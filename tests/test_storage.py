"""Check the on-disk storage format independently of the writer's helpers."""
import copy
import hashlib
import struct
from pathlib import Path
import tempfile
import unittest
import uuid
import zlib

from naos_image_generator.common import BuildError
from naos_image_generator.filesystems import make_import_record
from naos_image_generator import storage


MIB = 1024 * 1024
SECTOR = 512
DISK_UUID = 'd84ad0a9-5bf0-5d39-87b3-75140c17a6d0'
PART_UUIDS = (
    '95a18b39-fbe0-5fa5-935c-948240212276',
    '3f51c73f-0a4a-514e-8929-48e5534845c9',
    '1759b220-661e-55c4-ab83-e8acf69a4626',
    'd4fc1945-6fbc-5fec-a7f4-3d539cdece97',
    '77ca43d9-93a1-5878-b95e-88b865e6b83c',
    '52401164-153b-5a3d-aa0e-234411251b27',
    '3c1511e5-f1cc-5d37-a6cc-fd64617bf0d6',
)


def base_layout():
    """Public layout contract; tests do not depend on a parent checkout/export."""
    return {
        'format': 1, 'compatible': 'naos-mixtile-core3588e-v2-nano-v1',
        'sector_size': SECTOR, 'loader_offset': 32768,
        'loader_copies': 2, 'loader_copy_size': 524288,
        'partitions': [
            dict(name='uboot', start_mib=8, size_mib=4, payload='uboot.img'),
            dict(name='misc', start_mib=12, size_mib=4),
            dict(name='boot_a', start_mib=16, size_mib=50, payload='boot.img'),
            dict(name='boot_b', start_mib=66, size_mib=50, payload='boot.img'),
            dict(name='system_a', start_mib=116, size_mib=100, payload='system.squashfs'),
            dict(name='system_b', start_mib=216, size_mib=100, payload='system.squashfs'),
            dict(name='userdata', start_mib=316, size_mib=32,
                 grow=True, filesystem='f2fs', initialize='initramfs'),
        ],
        'environment': dict(partition='misc', image='naos-uboot-env.bin',
                            size=32768, offsets=[1048576, 1114112]),
        'misc_regions': [
            dict(name=name, offset=offset, size=65536)
            for name, offset in (
                ('bsp_reserved', 0), ('naos_control', 65536),
                ('system_key_import', 131072), ('data_key_blob_a', 196608),
                ('data_key_blob_b', 262144), ('uboot_env_a', 1048576),
                ('uboot_env_b', 1114112))],
    }


def read_at(stream, offset, length):
    stream.seek(offset)
    return stream.read(length)


class StorageTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.base = base_layout()
        self.layout = storage.resolve_layout(self.base)

    def file(self, name, data):
        path = self.root / name
        path.write_bytes(data)
        return path

    def header(self, stream, lba):
        block = read_at(stream, lba * SECTOR, SECTOR)
        fields = struct.unpack('<8sIIIIQQQQ16sQIII', block[:92])
        self.assertEqual(fields[:3], (b'EFI PART', 0x10000, 92))
        self.assertEqual(fields[4], 0)
        self.assertEqual(block[92:], bytes(SECTOR - 92))
        crc_input = block[:16] + bytes(4) + block[20:92]
        self.assertEqual(fields[3], zlib.crc32(crc_input))
        self.assertEqual(uuid.UUID(bytes_le=fields[9]), uuid.UUID(DISK_UUID))
        self.assertEqual(fields[11:13], (128, 128))
        table = read_at(stream, fields[10] * SECTOR, fields[11] * fields[12])
        self.assertEqual(fields[13], zlib.crc32(table))
        return fields, table

    def test_default_geometry_and_stable_uuids_do_not_modify_input(self):
        original = copy.deepcopy(self.base)
        layout = storage.resolve_layout(self.base)
        self.assertEqual(self.base, original)
        self.assertEqual(layout['gpt']['disk_guid'], DISK_UUID)
        self.assertEqual([p['uuid'] for p in layout['partitions']], list(PART_UUIDS))
        self.assertEqual(layout['gpt']['image_size_bytes'], 349 * MIB)
        self.assertEqual(layout['gpt']['last_usable_lba'], 714718)
        layout['partitions'][0]['size_mib'] = 1000
        self.assertEqual(self.base, original)

    def test_ab_size_overrides_reflow_all_following_partitions_and_preserve_identity(self):
        layout = storage.resolve_layout(self.base, {'boot_mib': 64, 'system_mib': 128})
        self.assertEqual([p['start_mib'] for p in layout['partitions']],
                         [8, 12, 16, 80, 144, 272, 400])
        self.assertEqual([p['size_mib'] for p in layout['partitions']],
                         [4, 4, 64, 64, 128, 128, 32])
        self.assertEqual(layout['gpt']['image_size_bytes'], 433 * MIB)
        self.assertEqual(layout['gpt']['disk_guid'], DISK_UUID)
        self.assertEqual([p['uuid'] for p in layout['partitions']], list(PART_UUIDS))
        self.assertEqual(layout['loader_offset'], 32768)
        self.assertEqual(layout['environment'], self.base['environment'])
        self.assertEqual(self.base['partitions'][3]['start_mib'], 66)

    def test_invalid_partition_sizes_order_overlap_and_identity_are_rejected(self):
        mutations = {
            'overlap': lambda x: x['partitions'][3].update(start_mib=65),
            'zero capacity': lambda x: x['partitions'][2].update(size_mib=0),
            'negative capacity': lambda x: x['partitions'][2].update(size_mib=-1),
            'floating start': lambda x: x['partitions'][2].update(start_mib=16.0),
            'boolean capacity': lambda x: x['partitions'][2].update(size_mib=True),
            'unequal AB': lambda x: x['partitions'][2].update(size_mib=49),
            'changed uboot': lambda x: x['partitions'][0].update(start_mib=7),
            'changed misc': lambda x: x['partitions'][1].update(size_mib=3),
            'changed partition UUID': lambda x: x['partitions'][4].update(uuid=str(uuid.UUID(int=1))),
            'changed compatibility': lambda x: x.update(compatible='new-layout'),
            'changed userdata initializer': lambda x: x['partitions'][-1].update(initialize='generator'),
            'missing partition': lambda x: x['partitions'].pop(),
            'changed order': lambda x: x['partitions'].reverse(),
            'wrong sector size': lambda x: x.update(sector_size=4096),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                layout = copy.deepcopy(self.base)
                mutate(layout)
                with self.assertRaises(BuildError):
                    storage.resolve_layout(self.base, layout=layout)
        for overrides in ({'boot_mib': 0}, {'system_mib': -1}, {'boot_mib': True},
                          {'system_mib': 2.0}, {'userdata_mib': 128}):
            with self.subTest(overrides=overrides), self.assertRaises(BuildError):
                storage.resolve_layout(self.base, overrides)

    def test_loader_geometry_cannot_overlap_gpt_or_partitions_or_change_contract(self):
        for changes in ({'loader_copies': 1}, {'loader_offset': 512},
                        {'loader_offset': 32769}, {'loader_offset': 65536},
                        {'loader_copy_size': 0}, {'loader_copy_size': 1025},
                        {'loader_copy_size': 4 * MIB}, {'loader_copy_size': 262144},
                        {'loader_offset': 32768.0}, {'loader_copy_size': 524288.0}):
            with self.subTest(changes=changes):
                layout = copy.deepcopy(self.base)
                layout.update(changes)
                with self.assertRaises(BuildError):
                    storage.resolve_layout(self.base, layout=layout)

    def test_misc_compiled_offsets_cannot_move_disappear_overlap_or_exceed_partition(self):
        mutations = {
            'moved import': lambda x: x['misc_regions'][2].update(offset=524288),
            'removed import': lambda x: x['misc_regions'].pop(2),
            'renamed control': lambda x: x['misc_regions'][1].update(name='other'),
            'changed import size': lambda x: x['misc_regions'][2].update(size=32768),
            'overlap': lambda x: x['misc_regions'][3].update(offset=131072),
            'out of bounds': lambda x: x['misc_regions'][-1].update(offset=4 * MIB),
            'duplicate name': lambda x: x['misc_regions'][-1].update(name='uboot_env_a'),
            'changed environment': lambda x: x['environment']['offsets'].__setitem__(0, 65536),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                layout = copy.deepcopy(self.base)
                mutate(layout)
                with self.assertRaises(BuildError):
                    storage.resolve_layout(self.base, layout=layout)

    def test_production_misc_regions_and_reordered_region_list_are_supported(self):
        production = copy.deepcopy(self.base)
        production['misc_regions'].extend([
            dict(name='system_key_blob_a', offset=327680, size=65536),
            dict(name='system_key_blob_b', offset=393216, size=65536),
        ])
        layout = copy.deepcopy(production)
        layout['misc_regions'].reverse()
        resolved = storage.resolve_layout(production, layout=layout)
        self.assertEqual({p['name']: p['offset'] for p in resolved['misc_regions']}
                         ['system_key_blob_b'], 393216)

    def test_primary_backup_gpt_crc_guid_entries_and_protective_mbr(self):
        image = self.root / 'gpt.img'
        with image.open('w+b') as stream:
            offsets = storage.write_gpt(stream, self.layout)
            self.assertEqual(image.stat().st_size, 349 * MIB)
            sectors = image.stat().st_size // SECTOR
            mbr = read_at(stream, 0, SECTOR)
            self.assertEqual(mbr[510:], b'\x55\xaa')
            self.assertEqual(mbr[:446], bytes(446))
            self.assertEqual(mbr[462:510], bytes(48))
            protective = struct.unpack('<B3sB3sII', mbr[446:462])
            self.assertEqual(protective[0], 0)
            self.assertEqual(protective[2], 0xee)
            self.assertEqual(protective[4:], (1, sectors - 1))
            primary, primary_table = self.header(stream, 1)
            backup, backup_table = self.header(stream, sectors - 1)
            self.assertEqual(primary[5:9], (1, sectors - 1, 34, sectors - 34))
            self.assertEqual(backup[5:9], (sectors - 1, 1, 34, sectors - 34))
            self.assertEqual(primary[10], 2)
            self.assertEqual(backup[10], sectors - 33)
            self.assertEqual(primary_table, backup_table)
            self.assertEqual(primary_table[7 * 128:], bytes(121 * 128))
            for index, expected in enumerate(self.layout['partitions']):
                fields = struct.unpack('<16s16sQQQ72s', primary_table[index * 128:(index + 1) * 128])
                self.assertEqual(uuid.UUID(bytes_le=fields[0]),
                                 uuid.UUID('0fc63daf-8483-4772-8e79-3d69d8477de4'))
                self.assertEqual(str(uuid.UUID(bytes_le=fields[1])), PART_UUIDS[index])
                self.assertEqual(fields[2], expected['start_mib'] * MIB // SECTOR)
                self.assertEqual(fields[3] + 1, (expected['start_mib'] + expected['size_mib']) * MIB // SECTOR)
                self.assertEqual(fields[4], 0)
                self.assertEqual(fields[5].decode('utf-16-le').rstrip('\0'), expected['name'])
                self.assertEqual(offsets[expected['name']],
                                 (expected['start_mib'] * MIB, expected['size_mib'] * MIB))

    def test_misc_writes_only_environment_and_import_at_compiled_relative_offsets(self):
        environment = bytes(range(256)) * 128
        env_file = self.file('environment.bin', environment)
        destination = self.root / 'misc.img'
        # Fixed public fixture, not a deployment key.
        key = b'0123456789abcdef' * 4
        record = make_import_record(key)
        header = (b'NAOS-SYSTEM-KEY\nversion=2\nkey=' + key + b'\n').ljust(256, b' ')
        self.assertEqual(record[:256], header)
        self.assertEqual(record[256:320], hashlib.sha256(header).hexdigest().encode())
        self.assertEqual(record[320:], bytes(65536 - 320))
        storage.make_misc(self.layout, env_file, destination, record)
        expected = bytearray(4 * MIB)
        expected[131072:196608] = record
        expected[1048576:1081344] = environment
        expected[1114112:1146880] = environment
        self.assertEqual(destination.read_bytes(), expected)
        # Development images leave the factory import, blobs, and recovery state blank.
        storage.make_misc(self.layout, env_file, destination)
        expected[131072:196608] = bytes(65536)
        self.assertEqual(destination.read_bytes(), expected)

    def test_misc_rejects_wrong_environment_and_import_lengths(self):
        for size in (32767, 32769):
            env = self.file('bad-environment.bin', bytes(size))
            with self.subTest(environment_size=size), self.assertRaises(BuildError):
                storage.make_misc(self.layout, env, self.root / 'misc.img')
        env = self.file('environment.bin', bytes(32768))
        for size in (65535, 65537):
            with self.subTest(import_size=size), self.assertRaises(BuildError):
                storage.make_misc(self.layout, env, self.root / 'misc.img', bytes(size))

    def test_factory_writes_two_idblocks_and_both_ab_payloads_without_userdata_format(self):
        idblock = b'IDBlock public fixture\0' * 5959
        uboot_copy = (b'U-Boot copy\0' * (2 * MIB // 12 + 1))[:2 * MIB]
        payloads = {
            'idblock.bin': self.file('idblock.bin', idblock),
            'uboot.img': self.file('uboot.img', uboot_copy * 2),
            'misc.img': self.file('misc.img', b'MISC' + bytes(4 * MIB - 4)),
            'boot.img': self.file('boot.img', b'FIT fixture' * 300),
            'system.squashfs': self.file('system.squashfs', b'SquashFS fixture' * 500),
        }
        output = self.root / 'factory.img'
        offsets = storage.assemble_factory(self.layout, payloads, output)
        self.assertEqual(output.stat().st_size, 349 * MIB)
        with output.open('rb') as stream:
            for offset in (32768, 557056):
                self.assertEqual(read_at(stream, offset, len(idblock)), idblock)
                self.assertEqual(read_at(stream, offset + len(idblock), 524288 - len(idblock)),
                                 bytes(524288 - len(idblock)))
            self.assertEqual(read_at(stream, 8 * MIB, 2 * MIB), uboot_copy)
            self.assertEqual(read_at(stream, 10 * MIB, 2 * MIB), uboot_copy)
            for name, payload in (('misc', 'misc.img'), ('boot_a', 'boot.img'),
                                  ('boot_b', 'boot.img'), ('system_a', 'system.squashfs'),
                                  ('system_b', 'system.squashfs')):
                start, capacity = offsets[name]
                data = payloads[payload].read_bytes()
                self.assertEqual(read_at(stream, start, len(data)), data)
                if len(data) < capacity:
                    self.assertEqual(read_at(stream, start + len(data), 512), bytes(512))
            self.assertEqual(read_at(stream, offsets['userdata'][0], offsets['userdata'][1]), bytes(32 * MIB))
            self.header(stream, 1)
            self.header(stream, output.stat().st_size // SECTOR - 1)

    def test_oversized_payload_is_rejected_before_overwriting_adjacent_bytes(self):
        destination = self.file('bounded.img', b'L' * 1024 + b'S' * 1024 + b'R' * 1024)
        oversized = self.file('oversized.bin', b'X' * 1025)
        with destination.open('r+b') as stream, self.assertRaises(BuildError):
            storage._copy(stream, oversized, 1024, 1024)
        self.assertEqual(destination.read_bytes(), b'L' * 1024 + b'S' * 1024 + b'R' * 1024)
        exact = self.file('exact.bin', b'E' * 1024)
        with destination.open('r+b') as stream:
            storage._copy(stream, exact, 1024, 1024)
        self.assertEqual(destination.read_bytes(), b'L' * 1024 + b'E' * 1024 + b'R' * 1024)

    def test_factory_rejects_idblock_and_partition_payload_overflow(self):
        # Sparse fixtures exercise real capacities without generating large data.
        for payload, size in (('idblock.bin', 524289), ('boot.img', 50 * MIB + 1),
                              ('system.squashfs', 100 * MIB + 1)):
            with self.subTest(payload=payload):
                payloads = {name: self.file(name, b'fixture') for name in
                            ('idblock.bin', 'uboot.img', 'misc.img', 'boot.img', 'system.squashfs')}
                with payloads[payload].open('wb') as stream:
                    stream.truncate(size)
                with self.assertRaises(BuildError):
                    storage.assemble_factory(self.layout, payloads, self.root / 'factory.img')


if __name__ == '__main__':
    unittest.main()
