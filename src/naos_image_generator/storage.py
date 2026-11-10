# SPDX-License-Identifier: MIT
"""Validate NAOS storage geometry and assemble ordinary GPT image files."""
import copy
from pathlib import Path
import shutil
import struct
import uuid
import zlib

from .common import BuildError, require

MIB = 1024 * 1024
SECTOR = 512
TYPE_GUID = uuid.UUID('0fc63daf-8483-4772-8e79-3d69d8477de4')


def resolve_layout(base, overrides=None, layout=None):
    result = copy.deepcopy(layout or base)
    require(result.get('format') == 1 and result.get('sector_size') == SECTOR,
            'Unsupported partition layout')
    require(result['compatible'] == base['compatible'], 'Changing the device storage identity requires a migration')
    parts = result['partitions']
    expected = ['uboot','misc','boot_a','boot_b','system_a','system_b','userdata']
    require([p['name'] for p in parts] == expected, 'Unexpected NAOS partition order')
    for index in (0, 1):
        for field in ('start_mib', 'size_mib'):
            require(parts[index][field] == base['partitions'][index][field],
                    'The compiled bootloader and misc geometry must remain unchanged')
    overrides = overrides or {}
    require(set(overrides) <= {'boot_mib', 'system_mib'}, 'Unknown partition size option')
    for key, value in overrides.items():
        require(type(value) is int and value > 0, 'Partition sizes must be positive integer MiB values')
        names = ('boot_a','boot_b') if key == 'boot_mib' else ('system_a','system_b')
        for part in parts:
            if part['name'] in names:
                part['size_mib'] = value
    if overrides:
        start = parts[1]['start_mib'] + parts[1]['size_mib']
        for part in parts[2:]:
            part['start_mib'] = start
            start += part['size_mib']
    end = 34 * SECTOR
    disk_guid = uuid.uuid5(uuid.NAMESPACE_URL, result['compatible'])
    for part in parts:
        start, size = part['start_mib'], part['size_mib']
        require(type(start) is int and type(size) is int and size > 0 and start * MIB >= end,
                'Partitions overlap or have invalid capacities: ' + part['name'])
        require(len(part['name'].encode('utf-16-le')) <= 72, 'GPT name is too long')
        end = (start + size) * MIB
        expected_uuid = str(uuid.uuid5(disk_guid, part['name']))
        require(part.get('uuid', expected_uuid) == expected_uuid, 'Partition UUID differs from the compiled storage contract')
        part.update(uuid=expected_uuid, type_guid=str(TYPE_GUID), attributes=0)
    for first, second in ((2,3),(4,5)):
        require(parts[first]['size_mib'] == parts[second]['size_mib'], 'A/B capacities must match')
    require(parts[-1].get('initialize') == 'initramfs', 'Userdata must be initialized by the initramfs')
    require(all(type(result[field]) is int for field in ('loader_copies', 'loader_offset', 'loader_copy_size'))
            and result['loader_copies'] == 2 and result['loader_offset'] >= 34 * SECTOR
            and result['loader_offset'] % SECTOR == 0 and result['loader_copy_size'] % SECTOR == 0
            and result['loader_copy_size'] > 0
            and result['loader_offset'] + result['loader_copies'] * result['loader_copy_size'] <= parts[0]['start_mib'] * MIB,
            'Invalid redundant IDBlock layout')
    require(result['loader_offset'] == base['loader_offset']
            and result['loader_copy_size'] == base['loader_copy_size'], 'IDBlock offsets differ from the target update configuration')
    previous, names = 0, set()
    for region in sorted(result['misc_regions'], key=lambda r:r['offset']):
        require(region['name'] not in names and type(region['offset']) is int and type(region['size']) is int
                and region['offset'] >= previous and region['size'] > 0, 'Invalid misc regions')
        names.add(region['name'])
        previous = region['offset'] + region['size']
    require(previous <= parts[1]['size_mib'] * MIB, 'Misc region exceeds its partition')
    # The initramfs and security tools use these compiled offsets. Reflowing A/B
    # partitions must not silently move their recovery/key records within misc.
    region_contract = lambda regions: {(r['name'], r['offset'], r['size']) for r in regions}
    require(region_contract(result['misc_regions']) == region_contract(base['misc_regions']),
            'Misc regions differ from the compiled recovery and security tools')
    require(result['environment'] == base['environment'], 'Initial environment layout differs from the compiled bootloader')
    size = ((end + 34 * SECTOR + MIB - 1) // MIB) * MIB
    count = size // SECTOR
    result['gpt'] = dict(disk_guid=str(disk_guid), entry_count=128, entry_size=128,
        image_size_bytes=size, first_usable_lba=34, last_usable_lba=count-34,
        primary_header_lba=1, primary_entries_lba=2,
        backup_header_lba=count-1, backup_entries_lba=count-33,
        partition_type_guid=str(TYPE_GUID), protective_mbr=True)
    return result


def _header(current, backup, last, disk_guid, table_lba, table_crc):
    data = struct.pack('<8sIIIIQQQQ16sQIII', b'EFI PART', 0x10000, 92, 0, 0,
        current, backup, 34, last, disk_guid.bytes_le, table_lba, 128, 128, table_crc)
    data = data[:16] + struct.pack('<I', zlib.crc32(data)) + data[20:]
    return data.ljust(SECTOR, b'\0')


def write_gpt(stream, layout):
    size = layout['gpt']['image_size_bytes']
    sectors = size // SECTOR
    disk_guid = uuid.UUID(layout['gpt']['disk_guid'])
    table = bytearray(128 * 128)
    offsets = {}
    for index, part in enumerate(layout['partitions']):
        start, capacity = part['start_mib'] * MIB, part['size_mib'] * MIB
        entry = struct.pack('<16s16sQQQ72s', uuid.UUID(part['type_guid']).bytes_le,
            uuid.UUID(part['uuid']).bytes_le, start//SECTOR, (start+capacity)//SECTOR-1,
            part['attributes'], part['name'].encode('utf-16-le').ljust(72,b'\0'))
        table[index*128:(index+1)*128] = entry
        offsets[part['name']] = (start,capacity)
    stream.truncate(size)
    mbr = bytearray(SECTOR)
    mbr[446:462] = struct.pack('<B3sB3sII',0,b'\0\2\0',0xee,b'\xff\xff\xff',1,min(sectors-1,0xffffffff))
    mbr[510:] = b'\x55\xaa'
    stream.seek(0)
    stream.write(mbr)
    crc = zlib.crc32(table)
    for current,backup,table_lba in ((1,sectors-1,2),(sectors-1,1,sectors-33)):
        stream.seek(table_lba*SECTOR)
        stream.write(table)
        stream.seek(current*SECTOR)
        stream.write(_header(current,backup,sectors-34,disk_guid,table_lba,crc))
    return offsets


def _copy(stream, source, offset, capacity):
    source = Path(source)
    require(source.is_file() and source.stat().st_size <= capacity,
            f'{source.name} exceeds its {capacity // MIB} MiB capacity')
    stream.seek(offset)
    with source.open('rb') as payload:
        shutil.copyfileobj(payload,stream,1024*1024)


def make_misc(layout, environment, destination, import_record=None):
    part = next(p for p in layout['partitions'] if p['name']=='misc')
    capacity = part['size_mib'] * MIB
    settings = layout['environment']
    require(Path(environment).stat().st_size == settings['size'], 'Unexpected initial environment size')
    with Path(destination).open('w+b') as stream:
        stream.truncate(capacity)
        for offset in settings['offsets']:
            require(offset >= 0 and offset + settings['size'] <= capacity, 'Environment exceeds misc')
            _copy(stream,environment,offset,settings['size'])
        if import_record is not None:
            region = next(p for p in layout['misc_regions'] if p['name']=='system_key_import')
            require(len(import_record)==region['size'], 'Unexpected factory key import size')
            stream.seek(region['offset'])
            stream.write(import_record)


def assemble_factory(layout, payloads, output):
    """All destinations are regular output files; this never opens /dev devices."""
    with Path(output).open('w+b') as stream:
        offsets = write_gpt(stream,layout)
        for index in range(layout['loader_copies']):
            _copy(stream,payloads['idblock.bin'],layout['loader_offset']+index*layout['loader_copy_size'],layout['loader_copy_size'])
        for part in layout['partitions']:
            name = part['name']
            if name == 'userdata':
                continue
            payload = payloads['misc.img'] if name=='misc' else payloads[part['payload']]
            start,capacity = offsets[name]
            _copy(stream,payload,start,capacity)
    return offsets
