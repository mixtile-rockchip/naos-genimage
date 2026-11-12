"""Regression tests for preflight checks and final-output publication."""
from contextlib import ExitStack
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from naos_image_generator import common, config, pipeline
from naos_image_generator.common import BuildError


class PipelineTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.addCleanup(common.set_tool_environment, {})

    def file(self, name, content=b'public fixture'):
        filename = self.root / name
        filename.parent.mkdir(parents=True, exist_ok=True)
        filename.write_bytes(content)
        return filename

    def options(self, **overrides):
        result = dict(system_key_file=None, overlays=[], remove=[], additional_sbom=[],
                      secure_boot=False, system_encryption=False, data_encryption=False,
                      ota=False, sbom=False, burn_key_hash=False,
                      signing=None, ota_signing=None, ota_certificate=None, ssh_ca=None,
                      toolset=None, tool_overrides={}, machine='fixture-board', profile='development',
                      version='2.0-final', build_id='final-build', compatible='fixture-v1',
                      epoch=123456, generator_version='fixture', processors=1, layout={})
        result.update(overrides)
        return result

    def test_validate_inputs_accepts_valid_edits_and_does_not_return_key_material(self):
        key = self.file('system.key', b'0123456789abcdef' * 4)
        overlay = self.root / 'overlay'
        overlay.mkdir()
        additional = self.file('business.json', b'{"name":"business fixture"}\n')
        options = self.options(system_key_file=key, overlays=[overlay],
                               remove=['etc/old-config', 'usr/bin/obsolete'], additional_sbom=[additional])
        before = key.read_bytes()
        self.assertIsNone(pipeline.validate_inputs(options))
        self.assertEqual(key.read_bytes(), before)
        self.assertEqual(options['system_key_file'], key)
        self.assertNotIn('key_hex', options)

    def test_preflight_rejects_invalid_system_key_before_any_tool_lookup(self):
        for data in (b'', b'a' * 63, b'a' * 65, b'A' * 64, b'a' * 64 + b'\n', b'g' * 64):
            with self.subTest(length=len(data), character=data[:1]):
                key = self.file('system.key', data)
                with patch('naos_image_generator.tools.resolve_tools') as resolve, \
                        self.assertRaisesRegex(BuildError, '64 lowercase hexadecimal'):
                    pipeline.prepare_tools(self.options(system_key_file=key))
                resolve.assert_not_called()

    def test_validate_inputs_rejects_missing_overlays_unsafe_removals_and_bad_sbom(self):
        plain_file = self.file('ordinary-file')
        for overlay in (self.root / 'missing-overlay', plain_file):
            with self.subTest(overlay=overlay), self.assertRaisesRegex(BuildError, 'overlay directory'):
                pipeline.validate_inputs(self.options(overlays=[overlay]))
        for removal in ('/etc/passwd', '../outside', 'etc/../../outside', '.', ''):
            with self.subTest(removal=removal), self.assertRaises(BuildError):
                pipeline.validate_inputs(self.options(remove=[removal]))
        for content in (b'[]', b'false', b'0', b'null', b'"text"', b'{broken json'):
            filename = self.file('business.json', content)
            with self.subTest(sbom=content), self.assertRaises(BuildError):
                pipeline.validate_inputs(self.options(additional_sbom=[filename]))
        with self.assertRaises(BuildError):
            pipeline.validate_inputs(self.options(additional_sbom=[self.root / 'missing.json']))

    def test_empty_yaml_is_supported_but_false_zero_and_empty_list_are_not_mappings(self):
        filename = self.root / 'generator.yml'
        for content in ('', '# An intentionally empty config\n', '{}\n', 'null\n'):
            with self.subTest(content=content):
                filename.write_text(content)
                self.assertEqual(config.load(filename), ({}, self.root))
        for content in ('[]\n', 'false\n', '0\n', '""\n'):
            with self.subTest(content=content):
                filename.write_text(content)
                with self.assertRaisesRegex(BuildError, 'configuration option'):
                    config.load(filename)

    def test_default_toolset_works_from_cwd_after_independent_install_and_requires_dtc(self):
        toolset = self.root / '.tools'
        (toolset / 'bin').mkdir(parents=True)
        (toolset / 'lib').mkdir()
        selected = {'mkimage': toolset / 'bin/mkimage', 'sqfstar': toolset / 'bin/sqfstar',
                    'boot_merger': toolset / 'bin/boot_merger', 'dtc': toolset / 'bin/dtc'}
        # Simulate a wheel installed elsewhere; no source checkout .tools exists.
        installed_module = self.root / 'venv/lib/python3.11/site-packages/naos_image_generator/pipeline.py'
        with patch.object(pipeline, '__file__', str(installed_module)), \
                patch.object(pipeline.Path, 'cwd', return_value=self.root), \
                patch('naos_image_generator.tools.resolve_tools', return_value=selected) as resolve:
            self.assertEqual(pipeline.prepare_tools(self.options()), selected)
        resolve.assert_called_once_with({}, {'mkimage', 'sqfstar', 'boot_merger', 'dtc'}, toolset)
        environment = common.process_environment({'PATH': '/caller/path', 'LD_LIBRARY_PATH': '/caller/lib',
                                                  'SOURCE_DATE_EPOCH': '555'})
        self.assertTrue(environment['PATH'].startswith(str(toolset / 'bin') + ':'))
        self.assertTrue(environment['LD_LIBRARY_PATH'].startswith(str(toolset / 'lib')))
        self.assertEqual(environment['SOURCE_DATE_EPOCH'], '555')

    def mock_image_build(self, stack, captures):
        """Real tar editing, mocked host tools/storage; all output files are tiny."""
        source = self.root / 'export'
        source.mkdir()
        (source / 'export.json').write_text('{"schema_version":1}\n')
        with tarfile.open(source / 'rootfs.tar.gz', 'w:gz') as archive:
            for name, data in (
                    ('lib/apk/db/installed', b'P:fixture\nV:1.0-r0\nA:aarch64\nL:MIT\n\n'),
                    ('usr/lib/naos/version.json', b'{"version":"old","build_id":"old"}\n')):
                info = tarfile.TarInfo(name)
                info.size, info.mode = len(data), 0o644
                archive.addfile(info, io.BytesIO(data))
        for name in ('initramfs.cpio.gz', 'Image', 'fixture-board.dtb', 'resource.img', 'naos-uboot-env.bin'):
            (source / name).write_bytes(b'fixture')
        bundle = SimpleNamespace(root=source, machine='fixture-board', profile='development', bootloader={},
                                 manifest={'ota': {'compatible': 'fixture-v1'}},
                                 file=lambda name: source / name)

        def ramdisk(original, destination, **kwargs):
            destination.write_bytes(b'finalized ramdisk fixture')
            return {'files': []}

        def squashfs(archive_path, destination, tool, **kwargs):
            with tarfile.open(archive_path) as archive:
                captures['version'] = json.load(archive.extractfile('usr/lib/naos/version.json'))
                captures['apk_database'] = archive.extractfile('lib/apk/db/installed').read()
            destination.write_bytes(b'hsqs' + bytes(92))

        def firmware(bundle_root, work, output, *args):
            captures['os_inputs'] = args[3]
            for name in ('boot.img', 'uboot.img', 'idblock.bin'):
                (output / name).write_bytes(b'fixture ' + name.encode())
            return {}

        def misc(layout, environment, destination, import_record=None):
            destination.write_bytes(b'blank misc fixture')

        def factory(layout, payloads, destination):
            destination.write_bytes(b'complete firmware fixture')
            return {}

        def ota(output, work, metadata, *args, **kwargs):
            captures['ota_metadata'] = metadata.copy()
            (output / 'system.raucb').write_bytes(b'signed bundle fixture')
            return {'system': 'system.raucb'}

        stack.enter_context(patch('naos_image_generator.filesystems.prepare_initramfs', side_effect=ramdisk))
        stack.enter_context(patch('naos_image_generator.filesystems.make_squashfs', side_effect=squashfs))
        stack.enter_context(patch('naos_image_generator.bootloader.build_bootloader', side_effect=firmware))
        stack.enter_context(patch('naos_image_generator.ota.build_bundles', side_effect=ota))
        stack.enter_context(patch.object(pipeline, 'make_misc', side_effect=misc))
        stack.enter_context(patch.object(pipeline, 'assemble_factory', side_effect=factory))
        return bundle

    def test_final_rootfs_manifest_and_ota_use_the_same_requested_release_metadata(self):
        captures = {}
        output = self.root / 'output'
        with ExitStack() as stack:
            bundle = self.mock_image_build(stack, captures)
            result = pipeline.build(bundle, self.options(ota=True), {'sqfstar': 'fixture'}, output)
        saved = json.loads((output / 'manifest.json').read_text())
        self.assertEqual(saved, result)
        for field, value in (('version', '2.0-final'), ('build_id', 'final-build'), ('machine', 'fixture-board')):
            self.assertEqual(captures['version'][field], value)
            self.assertEqual(captures['ota_metadata'][field], value)
            self.assertEqual(saved[field], value)
        self.assertEqual(captures['version']['layout_compatible'], saved['compatible'])
        self.assertEqual(captures['apk_database'], b'P:fixture\nV:1.0-r0\nA:aarch64\nL:MIT\n\n')
        self.assertTrue(saved['ota'])
        for name, record in saved['files'].items():
            self.assertEqual(record['sha256'], hashlib.sha256((output / name).read_bytes()).hexdigest())
        self.assertEqual(list(self.root.glob('.naos-*')), [])

    def test_custom_board_updates_runtime_machine_and_preserves_base_compatibility(self):
        captures = {}
        output = self.root/'vision-output'
        custom = self.file('board/vision1.dtb')
        prepared = self.file('prepared/fixture-board.dtb',b'new device tree')
        resource = self.file('prepared/resource.img',b'new resource image')
        info = dict(name='vision1',filename='vision1.dtb',model='vision1',original_name='fixture-board.dtb')
        with ExitStack() as stack:
            bundle = self.mock_image_build(stack,captures)
            replace = stack.enter_context(patch('naos_image_generator.boards.prepare',return_value=(prepared,resource,info)))
            result = pipeline.build(bundle,self.options(dtb=custom,board_name='vision1',ota=True),{'sqfstar':'fixture'},output)
        self.assertTrue((output/'vision1.img').is_file())
        self.assertEqual(result['board'],'vision1')
        self.assertEqual(result['machine'],'fixture-board')
        self.assertEqual(result['compatible'],'fixture-v1')
        self.assertEqual(result['device_tree'],info)
        self.assertEqual(captures['version']['board'],'vision1')
        self.assertEqual(captures['version']['machine'],'vision1')
        self.assertEqual(captures['version']['layout_compatible'],'fixture-v1')
        self.assertEqual(captures['os_inputs']['dtb'],prepared)
        self.assertEqual(captures['os_inputs']['resource'],resource)
        self.assertEqual(captures['ota_metadata']['board'],'vision1')
        self.assertEqual(captures['ota_metadata']['machine'],'fixture-board')
        self.assertEqual(captures['ota_metadata']['compatible'],'fixture-v1')
        self.assertEqual(replace.call_args.args[:3],(bundle.root,'fixture-board',custom))

    def test_final_publish_failure_restores_marked_output_and_cleans_both_staging_dirs(self):
        output = self.root / 'output'
        output.mkdir()
        (output / 'manifest.json').write_text('{"generator":"naos-image-generator","schema_version":1}\n')
        (output / 'working-firmware.img').write_bytes(b'previous known good firmware')
        before = {p.name: p.read_bytes() for p in output.iterdir()}
        original_rename = Path.rename

        def failing_publish(source, target):
            if source.name.startswith('.naos-images-') and Path(target) == output:
                raise OSError('fixture publication failure')
            return original_rename(source, target)

        with ExitStack() as stack:
            bundle = self.mock_image_build(stack, {})
            stack.enter_context(patch.object(Path, 'rename', failing_publish))
            with self.assertRaisesRegex(OSError, 'fixture publication failure'):
                pipeline.build(bundle, self.options(), {'sqfstar': 'fixture'}, output, force=True)
        self.assertEqual({p.name: p.read_bytes() for p in output.iterdir()}, before)
        self.assertEqual(list(self.root.glob('.naos-*')), [])
        self.assertEqual(list(self.root.glob('.output-old-*')), [])


if __name__ == '__main__':
    unittest.main()
