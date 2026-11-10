"""Exercise public CLI/configuration boundaries without signing or image builds."""
from contextlib import contextmanager, redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import yaml

from naos_image_generator import __version__, cli, common, config, pipeline
from naos_image_generator.common import BuildError


def fixture_layout():
    parts = [('uboot', 8, 4), ('misc', 12, 4), ('boot_a', 16, 50),
             ('boot_b', 66, 50), ('system_a', 116, 100),
             ('system_b', 216, 100), ('userdata', 316, 32)]
    return dict(format=1, sector_size=512, compatible='fixture-board-v1',
                loader_copies=2, loader_offset=32768, loader_copy_size=524288,
                partitions=[dict(name=name, start_mib=start, size_mib=size,
                                 **({'initialize': 'initramfs'} if name == 'userdata' else {}))
                            for name, start, size in parts],
                environment=dict(partition='misc', image='environment.bin', size=32768,
                                 offsets=[1048576, 1114112]),
                misc_regions=[dict(name='system_key_import', offset=131072, size=65536),
                              dict(name='uboot_env_a', offset=1048576, size=65536),
                              dict(name='uboot_env_b', offset=1114112, size=65536)])


@contextmanager
def working_directory(path):
    previous = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


class CliTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.config_dir = self.root / 'config'
        self.config_dir.mkdir()
        self.command_dir = self.root / 'command'
        self.command_dir.mkdir()
        self.input_dir = self.root / 'export'
        self.input_dir.mkdir()
        self.addCleanup(common.set_tool_environment, {})

    def bundle(self, production=False, **defaults):
        flags = dict(secure_boot=production, system_encryption=production,
                     data_encryption=production, ota=False, sbom=production)
        flags.update(defaults)
        profile = 'production' if production else 'development'
        manifest = dict(defaults=flags, version='2.0-export', build_id='export-build',
                        source_date_epoch=1700000000)
        return SimpleNamespace(root=self.input_dir, machine='fixture-board', profile=profile,
                               layout=fixture_layout(), manifest=manifest,
                               bootloader={'capabilities': {'otp_key_hash_programming': True}},
                               summary=lambda: dict(machine='fixture-board', profile=profile))

    def write_yaml(self, values, name='generator.yml'):
        filename = self.config_dir / name
        filename.write_text(yaml.safe_dump(values))
        return filename

    def write_fixture(self, relative, content=b'public test fixture\n'):
        filename = self.config_dir / relative
        filename.parent.mkdir(parents=True, exist_ok=True)
        filename.write_bytes(content)
        return filename

    def keys(self):
        # File existence is all settings() examines; no real signing keys exist here.
        for name in ('secure.key', 'secure.crt', 'secure.pub', 'ota.key', 'ota.crt'):
            self.write_fixture('keys/' + name)
        self.write_fixture('keys/system.key', b'0123456789abcdef' * 4)
        return dict(secure_boot=dict(key='keys/secure.key', certificate='keys/secure.crt',
                                     public_key='keys/secure.pub'),
                    ota=dict(key='keys/ota.key', certificate='keys/ota.crt'),
                    system='keys/system.key')

    def main(self, argv):
        output, error = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(error), \
                patch.object(cli, 'prepare_environment', return_value=None), \
                patch.object(cli, 'prepare_toolset', return_value=None):
            status = cli.main(argv)
        return status, output.getvalue(), error.getvalue()

    def test_inspect_dispatches_only_to_bundle_and_version_exits_successfully(self):
        bundle = self.bundle()
        with patch.object(cli, 'Bundle', return_value=bundle) as constructor, \
                patch.object(cli, 'prepare_tools') as tools, patch.object(cli, 'build') as build:
            status, output, error = self.main(['inspect', str(self.input_dir)])
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(output), bundle.summary())
        self.assertEqual(error, '')
        constructor.assert_called_once_with(self.input_dir)
        tools.assert_not_called()
        build.assert_not_called()
        output = io.StringIO()
        with redirect_stdout(output), self.assertRaises(SystemExit) as result:
            cli.main(['--version'])
        self.assertEqual(result.exception.code, 0)
        self.assertEqual(output.getvalue().strip(), __version__)

    def test_build_flags_override_yaml_and_all_paths_keep_their_own_base(self):
        bundle = self.bundle(production=True)
        layout = fixture_layout()
        self.write_fixture('custom-layout.json', json.dumps(layout).encode())
        self.write_fixture('trust/ota.pem')
        self.write_fixture('trust/ssh.pub')
        values = dict(input='../yaml-input', output='../yaml-output', version='yaml-version',
                      build_id='yaml-build', epoch=100, processors=2,
                      ota=False, sbom=False, burn_key_hash=False,
                      partitions=dict(boot_mib=32, system_mib=64), layout='custom-layout.json',
                      overlays=['overlays/one', 'overlays/two'], remove=['etc/obsolete'],
                      additional_sbom=['sbom/business.json'], tools_dir='yaml-tools',
                      tools={'mkimage': 'tools/mkimage'}, keys=self.keys(),
                      ota_certificate='trust/ota.pem', ssh_ca='trust/ssh.pub')
        self.write_yaml(values)
        host_tools = {'mkimage': Path('/fixture/mkimage')}
        manifest = dict(version='cli-version', files={'firmware.img': {}}, ota=True, sbom={'files': 1})
        with working_directory(self.command_dir), \
                patch.object(cli, 'Bundle', return_value=bundle) as constructor, \
                patch.object(cli, 'prepare_tools', return_value=host_tools) as prepare, \
                patch.object(cli, 'build', return_value=manifest) as build:
            status, output, error = self.main([
                'build', 'cli-input', '-c', '../config/generator.yml', '-o', 'cli-output', '--force',
                '--ota', '--sbom', '--burn-key-hash', '--firmware-version', 'cli-version',
                '--build-id', 'cli-build', '--epoch', '777', '--processors', '3',
                '--boot-mib', '60', '--system-mib', '120', '--tools-dir', 'cli-tools'])
        self.assertEqual((status, error), (0, ''))
        constructor.assert_called_once_with(self.command_dir / 'cli-input')
        options = prepare.call_args.args[0]
        self.assertEqual({k: options[k] for k in ('version', 'build_id', 'epoch', 'processors')},
                         dict(version='cli-version', build_id='cli-build', epoch=777, processors=3))
        self.assertTrue(all(options[name] for name in ('ota', 'sbom', 'burn_key_hash')))
        self.assertEqual(options['toolset'], self.command_dir / 'cli-tools')
        self.assertEqual(options['tool_overrides'], {'mkimage': self.config_dir / 'tools/mkimage'})
        self.assertEqual(options['overlays'], [self.config_dir / 'overlays/one', self.config_dir / 'overlays/two'])
        self.assertEqual(options['additional_sbom'], [self.config_dir / 'sbom/business.json'])
        self.assertEqual(options['remove'], ['etc/obsolete'])
        self.assertEqual(options['ssh_ca'], self.config_dir / 'trust/ssh.pub')
        self.assertEqual(options['ota_certificate'], self.config_dir / 'trust/ota.pem')
        self.assertEqual(options['signing']['public_key'], self.config_dir / 'keys/secure.pub')
        self.assertEqual(options['system_key_file'], self.config_dir / 'keys/system.key')
        self.assertEqual(options['ota_signing']['key'], self.config_dir / 'keys/ota.key')
        self.assertEqual([p['start_mib'] for p in options['layout']['partitions']],
                         [8, 12, 16, 76, 136, 256, 376])
        self.assertEqual([p['size_mib'] for p in options['layout']['partitions']],
                         [4, 4, 60, 60, 120, 120, 32])
        build.assert_called_once_with(bundle, options, host_tools,
                                      self.command_dir / 'cli-output', force=True)
        self.assertEqual(json.loads(output)['output'], str(self.command_dir / 'cli-output'))

    def test_negative_flags_override_yaml_and_yaml_input_output_are_relative_to_yaml(self):
        bundle = self.bundle(production=True)
        filename = self.write_yaml(dict(input='../yaml-input', output='../yaml-output',
                                        ota=True, sbom=True, burn_key_hash=True, keys=self.keys()))
        result = dict(version='2.0-export', files={}, ota=False, sbom=None)
        with working_directory(self.command_dir), \
                patch.object(cli, 'Bundle', return_value=bundle) as constructor, \
                patch.object(cli, 'prepare_tools', return_value={}), \
                patch.object(cli, 'build', return_value=result) as build:
            status, _, error = self.main(['build', '--config', str(filename),
                                          '--no-ota', '--no-sbom', '--no-burn-key-hash'])
        self.assertEqual((status, error), (0, ''))
        constructor.assert_called_once_with(self.root / 'yaml-input')
        options = build.call_args.args[1]
        self.assertFalse(any(options[k] for k in ('ota', 'sbom', 'burn_key_hash')))
        self.assertIsNone(options['ota_signing'])
        self.assertEqual(build.call_args.args[3], self.root / 'yaml-output')
        self.assertEqual(build.call_args.kwargs, {'force': False})

    def test_check_inherits_yaml_and_export_booleans_without_building(self):
        bundle = self.bundle(ota=False, sbom=True)
        filename = self.write_yaml(dict(input='../export', ota=True,
                                        keys={'ota': self.keys()['ota']}))
        with patch.object(cli, 'Bundle', return_value=bundle), \
                patch.object(cli, 'prepare_tools', return_value={'sqfstar': 'fixture', 'mkimage': 'fixture'}) as prepare, \
                patch.object(cli, 'build') as build:
            status, output, error = self.main(['check', '--config', str(filename)])
        self.assertEqual((status, error), (0, ''))
        self.assertEqual(json.loads(output), dict(status='ok', machine='fixture-board',
                         profile='development', ota=True, sbom=True, burn_key_hash=False,
                         tools=['mkimage', 'sqfstar']))
        self.assertEqual(prepare.call_args.args[0]['ota_certificate'], self.config_dir / 'keys/ota.crt')
        build.assert_not_called()
        options = pipeline.settings(self.bundle(), {}, self.config_dir,
                                    {'ota': None, 'sbom': None, 'burn_key_hash': None})
        self.assertFalse(any(options[k] for k in ('ota', 'sbom', 'burn_key_hash')))

    def test_unknown_or_mistyped_yaml_is_rejected_before_any_input_or_tool_work(self):
        cases = [dict(unknown_option=True), dict(ota='true'), dict(sbom=1),
                 dict(burn_key_hash=0), dict(overlays='overlay'), dict(remove={}),
                 dict(additional_sbom='business.json'), ['not', 'a', 'mapping']]
        for values in cases:
            with self.subTest(values=values):
                filename = self.write_yaml(values)
                with patch.object(cli, 'Bundle') as bundle, patch.object(cli, 'prepare_tools') as prepare:
                    status, output, error = self.main(['check', '--config', str(filename)])
                self.assertEqual(status, 1)
                self.assertEqual(output, '')
                self.assertIn('naos-image-generator:', error)
                bundle.assert_not_called()
                prepare.assert_not_called()

    def test_missing_requested_keys_fail_without_reading_or_building(self):
        cases = [(self.bundle(production=True), {}, 'Secure boot'),
                 (self.bundle(ota=True), {}, 'OTA'),
                 (self.bundle(system_encryption=True), {}, 'configuration path'),
                 (self.bundle(system_encryption=True), {'keys': {'system': 'missing-system.key'}},
                  'Missing System encryption key'),
                 (self.bundle(), {'keys': {'unexpected': 'key'}}, 'Unknown key configuration')]
        for bundle, values, diagnostic in cases:
            with self.subTest(diagnostic=diagnostic):
                filename = self.write_yaml(dict(input='../export', **values))
                with patch.object(cli, 'Bundle', return_value=bundle), \
                        patch.object(cli, 'prepare_tools') as prepare, patch.object(cli, 'build') as build, \
                        patch.object(pipeline, '_system_key') as read_key:
                    status, output, error = self.main(['check', '--config', str(filename)])
                self.assertEqual((status, output), (1, ''))
                self.assertIn(diagnostic, error)
                prepare.assert_not_called()
                build.assert_not_called()
                read_key.assert_not_called()

    def test_path_environment_expansion_uses_yaml_directory_and_rejects_undefined_variables(self):
        with patch.dict(os.environ, {'NAOS_FIXTURE_DIRECTORY': 'fixture-keys', 'HOME': str(self.root / 'home')}):
            self.assertEqual(config.path('$NAOS_FIXTURE_DIRECTORY/ota.pem', self.config_dir),
                             self.config_dir / 'fixture-keys/ota.pem')
            self.assertEqual(config.path('~/ota.pem', self.config_dir), self.root / 'home/ota.pem')
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(BuildError):
            config.path('$NAOS_UNDEFINED_FIXTURE/key', self.config_dir)
        with patch.dict(os.environ, {'SOURCE_DATE_EPOCH': '123456'}):
            inherited = pipeline.settings(self.bundle(), {}, self.config_dir)
            configured = pipeline.settings(self.bundle(), {'epoch': 456789}, self.config_dir)
        self.assertEqual(inherited['epoch'], 123456)
        self.assertEqual(configured['epoch'], 456789)

    def test_force_refuses_unmarked_existing_outputs_and_preserves_all_data(self):
        destination = self.root / 'existing-output'
        destination.mkdir()
        user_file = destination / 'irreplaceable.txt'
        user_file.write_bytes(b'user data must remain unchanged\n')
        markers = [None, {'generator': 'another-program', 'schema_version': 1},
                   {'generator': 'naos-image-generator', 'schema_version': 2}]
        for marker in markers:
            manifest = destination / 'manifest.json'
            if marker is not None:
                manifest.write_text(json.dumps(marker))
            elif manifest.exists():
                manifest.unlink()
            before = {p.name: p.read_bytes() for p in destination.iterdir()}
            with self.subTest(marker=marker), \
                    patch('naos_image_generator.filesystems.prepare_rootfs') as prepare, \
                    self.assertRaisesRegex(BuildError, 'only replaces an earlier generator output'):
                pipeline.build(self.bundle(), {}, {}, destination, force=True)
            self.assertEqual({p.name: p.read_bytes() for p in destination.iterdir()}, before)
            prepare.assert_not_called()
        # A valid marker still requires an explicit --force.
        (destination / 'manifest.json').write_text(json.dumps(
            {'generator': 'naos-image-generator', 'schema_version': 1}))
        with self.assertRaises(BuildError):
            pipeline.build(self.bundle(), {}, {}, destination)
        self.assertEqual(user_file.read_bytes(), b'user data must remain unchanged\n')

    def test_failed_force_build_keeps_previous_marked_output_and_cleans_staging(self):
        destination = self.root / 'previous-output'
        destination.mkdir()
        manifest = b'{"generator":"naos-image-generator","schema_version":1}\n'
        (destination / 'manifest.json').write_bytes(manifest)
        (destination / 'previous.img').write_bytes(b'previous working firmware')
        before = {p.name: p.read_bytes() for p in destination.iterdir()}
        bundle = self.bundle()
        options = pipeline.settings(bundle, {}, self.config_dir)
        with patch('naos_image_generator.filesystems.prepare_rootfs', side_effect=BuildError('fixture failure')), \
                self.assertRaisesRegex(BuildError, 'fixture failure'):
            pipeline.build(bundle, options, {}, destination, force=True)
        self.assertEqual({p.name: p.read_bytes() for p in destination.iterdir()}, before)
        self.assertEqual(list(self.root.glob('.naos-*')), [])
        self.assertEqual(list(self.root.glob('.previous-output-old-*')), [])

    def test_input_and_output_parent_relationship_is_rejected_before_build_work(self):
        bundle = self.bundle()
        for destination in (bundle.root, bundle.root / 'nested-output', self.root):
            with self.subTest(destination=destination), \
                    patch('naos_image_generator.filesystems.prepare_rootfs') as prepare, \
                    self.assertRaisesRegex(BuildError, 'must be separate'):
                pipeline.build(bundle, {}, {}, destination, force=True)
            prepare.assert_not_called()

    def test_tool_environment_wins_for_loader_paths_while_caller_epoch_still_applies(self):
        tool_path = str(self.root / 'selected-toolset/bin') + os.pathsep + '/usr/bin'
        tool_libraries = str(self.root / 'selected-toolset/lib')
        common.set_tool_environment({'PATH': tool_path, 'LD_LIBRARY_PATH': tool_libraries,
                                     'FIXTURE_VALUE': 'toolset-default'})
        caller = dict(os.environ, PATH='/caller/bin', LD_LIBRARY_PATH='/caller/lib',
                      SOURCE_DATE_EPOCH='987654', FIXTURE_VALUE='caller-override')
        code = ('import json, os; print(json.dumps({name: os.environ[name] for name in '
                '("PATH", "LD_LIBRARY_PATH", "SOURCE_DATE_EPOCH", "FIXTURE_VALUE")}))')
        with patch.dict(os.environ, {'SOURCE_DATE_EPOCH': '123456'}):
            result = json.loads(common.run([sys.executable, '-c', code], env=caller))
        self.assertEqual(result, dict(PATH=tool_path, LD_LIBRARY_PATH=tool_libraries,
                                     SOURCE_DATE_EPOCH='987654', FIXTURE_VALUE='caller-override'))

    def test_tools_import_resolves_sources_relative_to_its_yaml_and_output_to_cwd(self):
        filename = self.write_yaml(dict(executables={'mkimage': 'bin/mkimage'},
                                        library_dirs=['vendor/lib']), 'tools.yml')
        with working_directory(self.command_dir), \
                patch.object(cli, 'import_toolset', return_value={'tools': ['mkimage']}) as importer:
            status, output, error = self.main(['tools', 'import', '--config', str(filename), '-o', 'tool-output'])
        self.assertEqual((status, error), (0, ''))
        importer.assert_called_once_with({'mkimage': self.config_dir / 'bin/mkimage'}, Path('tool-output'),
                                         library_dirs=[self.config_dir / 'vendor/lib'], target_assets={})
        self.assertEqual(json.loads(output), {'tools': ['mkimage']})

    def test_tools_import_resolves_target_runtime_assets_relative_to_yaml(self):
        filename = self.write_yaml(dict(executables={'apk':'bin/apk'}, targets={
            'aarch64':dict(fakeroot_apk='target/fakeroot.apk',ownership_library='target/ownership.so')}), 'tools.yml')
        with patch.object(cli,'import_toolset',return_value={'tools':[]}) as importer:
            status,_,error = self.main(['tools','import','-c',str(filename)])
        self.assertEqual((status,error),(0,''))
        self.assertEqual(importer.call_args.kwargs['target_assets'],{'aarch64':dict(
            fakeroot_apk=self.config_dir/'target/fakeroot.apk',ownership_library=self.config_dir/'target/ownership.so')})


if __name__ == '__main__':
    unittest.main()
