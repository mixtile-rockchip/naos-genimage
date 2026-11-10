"""OTA-only publication must not create a disk image or factory key records."""
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from naos_image_generator import cli, config, pipeline
import test_cli_repository
import test_pipeline


class OtaOnlyTests(unittest.TestCase):
    def setUp(self):
        # Reuse the tiny, real tar-editing fixture without inheriting its tests.
        self.fixture = test_pipeline.PipelineTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        self.names = ('naos-bundle-fixture-board-2.0-final.raucb',
                      'naos-bootloader-bundle-fixture-board-2.0-final.raucb')

    def bundles(self, captures):
        def build(output, work, metadata, contract, tools, signing, system_file, *args, **kwargs):
            output = Path(output)
            self.assertTrue(Path(system_file).is_file())
            self.assertTrue((output/'boot.img').is_file())
            captures['payload_directory'] = output
            captures['ota_metadata'] = dict(metadata)
            for name in self.names:
                (output/name).write_bytes(('signed fixture '+name).encode())
            return {name: {'signature_verified': True, 'payload_verified': True}
                    for name in self.names}
        return build

    def prepare(self, stack, captures):
        bundle = self.fixture.mock_image_build(stack, captures)
        misc = stack.enter_context(patch.object(pipeline, 'make_misc'))
        factory = stack.enter_context(patch.object(pipeline, 'assemble_factory'))
        key_import = stack.enter_context(patch('naos_image_generator.filesystems.make_import_record'))
        stack.enter_context(patch('naos_image_generator.ota.build_bundles', side_effect=self.bundles(captures)))
        return bundle, misc, factory, key_import

    def assert_manifest_files(self, output, manifest):
        actual = {path.name for path in output.iterdir() if path.name != 'manifest.json'}
        self.assertEqual(set(manifest['files']), actual)
        for name, record in manifest['files'].items():
            data = (output/name).read_bytes()
            self.assertEqual(record['sha256'], hashlib.sha256(data).hexdigest())
            self.assertEqual(record['size'], len(data))

    def test_only_both_signed_bundles_are_published_without_factory_or_misc(self):
        captures = {}
        output = self.root/'updates'
        with ExitStack() as stack:
            bundle, misc, factory, key_import = self.prepare(stack, captures)
            result = pipeline.build(bundle, self.fixture.options(ota=True, ota_only=True),
                                    {'sqfstar': 'fixture'}, output)
            misc.assert_not_called()
            factory.assert_not_called()
            key_import.assert_not_called()
        self.assertEqual({path.name for path in output.iterdir()}, {*self.names, 'manifest.json'})
        self.assertTrue(result['ota'] and result['ota_only'])
        self.assert_manifest_files(output, result)
        self.assertFalse(captures['payload_directory'].exists())
        self.assertEqual(list(self.root.glob('.naos-*')), [])

    def test_encrypted_updates_keep_payloads_and_key_import_out_of_final_sbom(self):
        captures = {}
        output = self.root/'production-updates'
        key = self.fixture.file('system.key', b'0123456789abcdef'*4)

        def encrypt(source, destination, key_hex):
            self.assertEqual(key_hex, key.read_bytes())
            destination.write_bytes(b'encrypted system payload fixture')
            return {'cipher': 'fixture'}

        def sbom(inputs, destination, rootfs, initramfs, artifacts, metadata, **kwargs):
            self.assertEqual(set(artifacts), {*self.names, 'rootfs.inventory.json', 'initramfs.inventory.json'})
            self.assert_manifest_files(destination, {'files': artifacts})
            captures['sbom_artifacts'] = set(artifacts)
            (destination/'final.spdx.json').write_text('{"spdxVersion":"SPDX-2.3"}\n')
            return {'file': 'final.spdx.json', 'format': 'SPDX-2.3'}

        with ExitStack() as stack:
            bundle, misc, factory, key_import = self.prepare(stack, captures)
            stack.enter_context(patch('naos_image_generator.filesystems.encrypt_system', side_effect=encrypt))
            stack.enter_context(patch('naos_image_generator.sbom.render_sbom', side_effect=sbom))
            options = self.fixture.options(ota=True, ota_only=True, sbom=True,
                                           system_key_file=key, system_encryption=True)
            result = pipeline.build(bundle, options, {'sqfstar': 'fixture'}, output)
            misc.assert_not_called()
            factory.assert_not_called()
            key_import.assert_not_called()
        forbidden = {'misc.img', 'system.img', 'system.squashfs', 'boot.img', 'uboot.img',
                     'idblock.bin', 'uboot-slot.img', 'idblock-slot.img', 'MiniLoaderAll.bin'}
        self.assertFalse(forbidden & set(result['files']))
        self.assertTrue(result['sbom'])
        self.assert_manifest_files(output, result)
        for path in output.iterdir():
            self.assertNotIn(key.read_bytes(), path.read_bytes())
        self.assertEqual(list(self.root.glob('.naos-*')), [])


class OtaOnlyCliTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_cli_repository.RepositoryCliTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.conventional_keys()

    def run_build(self, *arguments):
        fixture = self.fixture
        package = fixture.package()
        manifest = {'version': package.version, 'files': {}, 'ota': True, 'ota_only': '--ota-only' in arguments,
                    'sbom': None}
        with test_cli_repository.cwd(fixture.root), patch.object(cli, 'Repository') as factory, \
                patch.object(cli, 'Bundle', return_value=fixture.bundle()), \
                patch.object(cli, 'prepare_tools', return_value={}) as tools, \
                patch.object(cli, 'build', return_value=manifest) as build:
            factory.return_value.list_packages.return_value = [package]
            factory.return_value.acquire.return_value = fixture.source
            status, output, error = fixture.main(['build', '--image', package.name,
                '--image-version', package.version, '--apk', str(fixture.apk), *arguments])
        return status, output, error, tools, build

    def test_cli_ota_only_enables_signing_and_uses_separate_default_output(self):
        status, output, error, tools, build = self.run_build('--ota-only')
        self.assertEqual(status, 0, error)
        options = tools.call_args.args[0]
        self.assertTrue(options['ota'] and options['ota_only'])
        self.assertEqual(options['ota_signing']['key'], self.fixture.root/'key/ota/signing.key.pem')
        self.assertEqual(build.call_args.args[3],
                         self.fixture.root/'output/fixture-board/development/1.0.0-updates')
        self.assertTrue(json.loads(output)['ota'])

    def test_explicit_output_is_preserved_and_ordinary_ota_still_builds_factory(self):
        selected = self.fixture.root/'chosen'
        status, _, error, tools, build = self.run_build('--ota-only', '-o', str(selected))
        self.assertEqual(status, 0, error)
        self.assertEqual(build.call_args.args[3], selected)
        status, _, error, tools, build = self.run_build('--ota')
        self.assertEqual(status, 0, error)
        self.assertTrue(tools.call_args.args[0]['ota'])
        self.assertFalse(tools.call_args.args[0].get('ota_only', False))
        self.assertEqual(build.call_args.args[3],
                         self.fixture.root/'output/fixture-board/development/1.0.0')

    def test_explicit_no_ota_cannot_be_combined_with_ota_only(self):
        status, output, error, tools, build = self.run_build('--ota-only', '--no-ota')
        self.assertNotEqual(status, 0)
        self.assertEqual(output, '')
        tools.assert_not_called()
        build.assert_not_called()

    def test_yaml_ota_only_preserves_its_output_and_requires_boolean(self):
        fixture = self.fixture
        filename = fixture.yaml({'input': str(fixture.source), 'output': '../yaml-updates',
                                 'ota': False, 'ota_only': True,
                                 'keys': {'ota': {'key': str(fixture.root/'key/ota/signing.key.pem'),
                                                  'certificate': str(fixture.root/'key/ota/signing.cert.pem')}}})
        with test_cli_repository.cwd(fixture.root), patch.object(cli, 'Repository') as factory, \
                patch.object(cli, 'Bundle', return_value=fixture.bundle()), \
                patch.object(cli, 'prepare_tools', return_value={}) as tools, \
                patch.object(cli, 'build', return_value={'version': '1.0.0', 'files': {}, 'ota': True,
                                                      'ota_only': True, 'sbom': None}) as build:
            status, _, error = fixture.main(['build', '--config', str(filename)])
        self.assertEqual(status, 0, error)
        factory.assert_not_called()
        self.assertTrue(tools.call_args.args[0]['ota'] and tools.call_args.args[0]['ota_only'])
        self.assertEqual(build.call_args.args[3], fixture.root/'yaml-updates')
        for value in ('true', 1, []):
            filename = fixture.yaml({'ota_only': value})
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'ota_only'):
                config.load(filename)


if __name__ == '__main__':
    unittest.main()
