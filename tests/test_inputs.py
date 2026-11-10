"""Validate portable-export structure and compiled partition payload roles."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from naos_image_generator.common import BuildError
from naos_image_generator.inputs import Bundle
from naos_image_generator.pipeline import settings


def layout_fixture(encrypted=False):
    names = [('uboot', 8, 4, 'uboot.img'), ('misc', 12, 4, None),
             ('boot_a', 16, 50, 'boot.img'), ('boot_b', 66, 50, 'boot.img'),
             ('system_a', 116, 100, 'system.img' if encrypted else 'system.squashfs'),
             ('system_b', 216, 100, 'system.img' if encrypted else 'system.squashfs'),
             ('userdata', 316, 32, None)]
    return dict(format=1, sector_size=512, compatible='fixture-board-v1',
                loader_copies=2, loader_offset=32768, loader_copy_size=524288,
                partitions=[dict(name=name, start_mib=start, size_mib=size,
                                 **({'payload': payload} if payload else {}),
                                 **({'initialize': 'initramfs'} if name == 'userdata' else {}))
                            for name, start, size, payload in names],
                environment=dict(partition='misc', image='naos-uboot-env.bin', size=32768,
                                 offsets=[1048576, 1114112]),
                misc_regions=[dict(name='system_key_import', offset=131072, size=65536),
                              dict(name='uboot_env_a', offset=1048576, size=65536),
                              dict(name='uboot_env_b', offset=1114112, size=65536)])


class InputTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.export = self.root / 'export'
        self.export.mkdir()
        self.layout = layout_fixture()
        self.bootloader = dict(machine='fixture-board', profile='development',
                               capabilities={'otp_key_hash_programming': True})
        self.manifest = dict(schema_version=1,
                             stage='before-filesystem-compression-encryption-and-signing',
                             machine='fixture-board', profile='development', version='2.0', build_id='fixture-build',
                             source_date_epoch=1700000000, kernel_release='6.12.69',
                             bootloader='bootloader/bootloader.json',
                             defaults=dict(secure_boot=False, system_encryption=False, data_encryption=False,
                                           ota=False, sbom=False),
                             ota={'compatible': 'fixture-board-v1'},
                             initramfs={'needs_finalization': False}, input_files={})
        for name in ('rootfs.tar.gz', 'Image', 'fixture-board.dtb', 'initramfs.cpio.gz',
                     'resource.img', 'naos-uboot-env.bin'):
            self.input_file(name, b'public input fixture')
        self.input_file('partition-layout.json', json.dumps(self.layout).encode())
        self.input_file('bootloader/bootloader.json', json.dumps(self.bootloader).encode())
        self.write_manifest()

    def input_file(self, name, data):
        filename = self.export / name
        filename.parent.mkdir(parents=True, exist_ok=True)
        filename.write_bytes(data)
        self.manifest['input_files'][name] = dict(size=len(data), sha256=hashlib.sha256(data).hexdigest())

    def write_manifest(self, value=None):
        (self.export / 'export.json').write_text(json.dumps(self.manifest if value is None else value))

    def test_valid_export_verifies_records_and_describes_its_original_identity(self):
        bundle = Bundle(self.export)
        summary = bundle.summary()
        self.assertEqual(summary['machine'], 'fixture-board')
        self.assertEqual(summary['profile'], 'development')
        self.assertEqual(summary['kernel_release'], '6.12.69')
        self.assertEqual(summary['files'], 9)
        self.assertEqual(summary['partitions'][2], dict(name='boot_a', start_mib=16, size_mib=50))
        self.assertEqual(bundle.file('Image').read_bytes(), b'public input fixture')

    def test_export_and_nested_manifest_mappings_reject_non_objects(self):
        malformed = ([], 'text', 0, False)
        for value in (*malformed, None):
            with self.subTest(export=value):
                (self.export / 'export.json').write_text(json.dumps(value))
                with self.assertRaisesRegex(BuildError, 'Export manifest.*JSON object'):
                    Bundle(self.export)
        for field in ('defaults', 'ota', 'initramfs', 'input_files'):
            for value in (*malformed, None):
                with self.subTest(field=field, value=value):
                    manifest = copy.deepcopy(self.manifest)
                    manifest[field] = value
                    self.write_manifest(manifest)
                    with self.assertRaises(BuildError):
                        Bundle(self.export)

    def test_each_input_record_layout_and_bootloader_must_be_an_object(self):
        for value in ([], 'text', 0, False, None):
            with self.subTest(record=value):
                manifest = copy.deepcopy(self.manifest)
                manifest['input_files']['Image'] = value
                self.write_manifest(manifest)
                with self.assertRaisesRegex(BuildError, 'input record.*JSON object'):
                    Bundle(self.export)
        for filename, original, diagnostic in (
                ('partition-layout.json', self.layout, 'Partition layout'),
                ('bootloader/bootloader.json', self.bootloader, 'Bootloader metadata')):
            for value in ([], 'text', 0, False, None):
                with self.subTest(filename=filename, value=value):
                    self.input_file(filename, json.dumps(value).encode())
                    self.write_manifest()
                    with self.assertRaisesRegex(BuildError, diagnostic + '.*JSON object'):
                        Bundle(self.export)
            self.input_file(filename, json.dumps(original).encode())

    def test_missing_roles_bad_checksums_and_mistyped_finalization_fail_clearly(self):
        for mutation in (
                lambda data: data.pop('bootloader'),
                lambda data: data['input_files'].pop('Image'),
                lambda data: data['input_files']['Image'].update(sha256='0' * 64),
                lambda data: data['input_files']['Image'].update(size=True),
                lambda data: data['initramfs'].update(needs_finalization='false'),
                lambda data: data['ota'].pop('compatible')):
            manifest = copy.deepcopy(self.manifest)
            mutation(manifest)
            self.write_manifest(manifest)
            with self.assertRaises(BuildError):
                Bundle(self.export)

    def test_custom_layout_may_resize_ab_but_cannot_replace_any_payload_role(self):
        bundle = Bundle(self.export)
        config = dict(partitions={'boot_mib': 64, 'system_mib': 128})
        resized = settings(bundle, config, self.root)
        self.assertEqual([p['size_mib'] for p in resized['layout']['partitions']],
                         [4, 4, 64, 64, 128, 128, 32])
        custom = self.root / 'layout.json'
        for index, new_payload in ((0, 'other-uboot.img'), (1, 'misc.img'), (2, 'other-fit.img'),
                                   (4, 'system.img'), (6, 'preformatted-userdata.img')):
            with self.subTest(partition=self.layout['partitions'][index]['name']):
                changed = copy.deepcopy(self.layout)
                changed['partitions'][index]['payload'] = new_payload
                custom.write_text(json.dumps(changed))
                with self.assertRaisesRegex(BuildError, 'payload roles differ'):
                    settings(bundle, {'layout': str(custom)}, self.root)

    def test_development_layout_cannot_silently_select_plain_system_for_encrypted_export(self):
        # Only the fixture's system feature is enabled: no signing keys are read.
        self.manifest['defaults']['system_encryption'] = True
        self.manifest['initramfs']['needs_finalization'] = True
        self.layout = layout_fixture(encrypted=True)
        self.input_file('partition-layout.json', json.dumps(self.layout).encode())
        self.write_manifest()
        bundle = Bundle(self.export)
        custom = self.root / 'development-layout.json'
        custom.write_text(json.dumps(layout_fixture(encrypted=False)))
        with self.assertRaisesRegex(BuildError, 'payload roles differ'):
            settings(bundle, {'layout': str(custom)}, self.root)


if __name__ == '__main__':
    unittest.main()
