# SPDX-License-Identifier: MIT
"""Read and verify the portable Yocto export, without importing Yocto."""
from pathlib import Path
import re

from .common import input_file, read_json, require, sha256


def label(value, name):
    require(isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+-]*', value),
            'Invalid ' + name)
    return value


class Bundle:
    def __init__(self, directory):
        self.root = Path(directory).resolve()
        require(self.root.is_dir(), 'Input directory does not exist')
        self.manifest = read_json(self.root / 'export.json')
        data = self.manifest
        require(isinstance(data, dict), 'Export manifest must be a JSON object')
        require(data.get('schema_version') == 1, 'Unsupported export schema')
        require(data.get('stage') == 'before-filesystem-compression-encryption-and-signing',
                'Expected early image-generator inputs')
        self.machine = label(data.get('machine'), 'machine')
        self.profile = label(data.get('profile'), 'profile')
        require(self.profile in ('development','production'), 'Unsupported export profile')
        label(data.get('version'), 'firmware version')
        label(data.get('build_id'), 'build ID')
        for name in ('defaults', 'ota', 'initramfs'):
            require(isinstance(data.get(name), dict), 'Export ' + name + ' must be a JSON object')
        records = data.get('input_files')
        require(isinstance(records, dict) and records, 'Export has no input manifest')
        for name, record in records.items():
            require(isinstance(record, dict), 'Export input record must be a JSON object: ' + name)
            path = input_file(self.root, name)
            require(not path.is_symlink() and type(record.get('size')) is int
                    and path.stat().st_size == record['size']
                    and re.fullmatch(r'[0-9a-f]{64}', str(record.get('sha256','')))
                    and sha256(path) == record['sha256'], 'Export input checksum mismatch: ' + name)
        bootloader_file = data.get('bootloader')
        require(isinstance(bootloader_file, str) and bootloader_file, 'Export has no bootloader metadata path')
        for name in ('rootfs.tar.gz','Image',self.machine+'.dtb','initramfs.cpio.gz',
                     'resource.img','partition-layout.json','naos-uboot-env.bin',bootloader_file):
            require(name in records, 'Missing export role: ' + name)
        self.layout = read_json(self.file('partition-layout.json'))
        require(isinstance(self.layout, dict), 'Partition layout must be a JSON object')
        label(self.layout.get('compatible'), 'storage compatibility identifier')
        self.bootloader = read_json(self.file(bootloader_file))
        require(isinstance(self.bootloader, dict), 'Bootloader metadata must be a JSON object')
        require(self.bootloader.get('machine') == self.machine
                and self.bootloader.get('profile') == self.profile, 'Bootloader belongs to another export')
        require(data['ota'].get('compatible') == self.layout['compatible'], 'OTA and disk compatibility identifiers differ')
        for key in ('secure_boot','system_encryption','data_encryption','ota','sbom'):
            require(type(data['defaults'].get(key)) is bool, 'Invalid default feature flag: ' + key)
        require(type(data['initramfs'].get('needs_finalization')) is bool
                and data['initramfs']['needs_finalization'] == data['defaults']['system_encryption'],
                'Initramfs and system encryption flags differ')

    def file(self, name):
        require(name in self.manifest['input_files'], 'Unlisted export input: ' + name)
        return input_file(self.root, name)

    def summary(self):
        return dict(machine=self.machine,profile=self.profile,version=self.manifest['version'],
            build_id=self.manifest['build_id'],kernel_release=self.manifest['kernel_release'],
            files=len(self.manifest['input_files'])+1,defaults=self.manifest['defaults'],
            capabilities=self.bootloader['capabilities'],
            partitions=[{k:p[k] for k in ('name','start_mib','size_mib')} for p in self.layout['partitions']])
