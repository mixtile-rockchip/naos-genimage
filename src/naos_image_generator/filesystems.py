# SPDX-License-Identifier: MIT
"""Edit target filesystem archives without extracting them on the host."""
from __future__ import annotations

import base64
import binascii
import copy
import configparser
from dataclasses import dataclass
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import struct
import subprocess
import tarfile
import tempfile
import zlib

from .common import process_environment


class FilesystemError(ValueError):
    """A filesystem input or generated archive failed validation."""


_DATABASE = "lib/apk/db/installed"
_VERSION = "usr/lib/naos/version.json"
_BOOT_CONFIRM = "etc/init.d/naos-boot-confirm"
_CORE_CONFIG = "etc/naos-core/device.ini"
_CONTAINER_MANIFEST = re.compile(r"var/lib/naos/containers/([A-Za-z0-9][A-Za-z0-9_.-]{0,127})/manifest\.yml")
_BOOT_MACHINE_CHECK = re.compile(
    rb"(^[ \t]*![ \t]+grep[ \t]+-q[ \t]+"
    + re.escape(b"'\"machine\"[[:space:]]*:[[:space:]]*\"")
    + rb")([^'\"\r\n]+)("
    + re.escape(b"\"'")
    + rb"[ \t]+/run/naos/lower/usr/lib/naos/version\.json[ \t]+\|\|[ \t]*(?:\\)?[ \t]*$)",
    re.MULTILINE)
_FINGERPRINT = "usr/lib/naos/system-key.sha256"
_METADATA = frozenset(("etc/alpine-release", "etc/os-release", "usr/lib/os-release", _VERSION))
_MODULE = re.compile(r"\.ko(?:\.(?:xz|gz|zst))?$")
_CHUNK = 1024 * 1024
_MAX_CPIO_BYTES = 512 * 1024 * 1024


def _require(value, message):
    if not value:
        raise FilesystemError(message)


def _path(value, *, root=False):
    _require(isinstance(value, str) and value and "\0" not in value and "\\" not in value
             and not value.startswith("/") and ".." not in value.split("/"),
             "Expected a safe target-relative archive path")
    result = str(PurePosixPath(value))
    _require(root or result != ".", "An individual file cannot be the target root")
    return result


def _epoch(value):
    _require(type(value) is int and 0 <= value <= 0xffffffff, "Invalid reproducible filesystem epoch")
    return value


def _file_digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _key_bytes(key_hex):
    if isinstance(key_hex, str):
        key_hex = key_hex.encode("ascii")
    _require(isinstance(key_hex, bytes) and re.fullmatch(rb"[0-9a-f]{64}", key_hex),
             "System key must be exactly 64 lowercase hexadecimal ASCII bytes without newline")
    return key_hex, bytes.fromhex(key_hex.decode("ascii"))


def _checksum(value):
    if value is None:
        return None
    if value.startswith("Q1"):
        try:
            digest = base64.b64decode(value[2:], validate=True)
        except (ValueError, binascii.Error) as error:
            raise FilesystemError("Invalid APK file checksum") from error
        _require(len(digest) == 20, "Invalid APK SHA1 length")
        return {"algorithm": "SHA1", "value": digest.hex(), "encoded": value}
    return {"algorithm": None, "value": None, "encoded": value}


def _apk_database(text):
    packages, identities = [], set()
    for paragraph in text.split("\n\n"):
        fields, files, depends, directory, current = {}, [], [], None, None
        for line in paragraph.splitlines():
            if not line:
                continue
            _require(":" in line, "Malformed APK installed database")
            field, value = line.split(":", 1)
            if field in {"P", "V", "A", "L", "o", "U", "c", "C"}:
                _require(field not in fields, "Duplicate APK package field")
                fields[field] = value
            elif field == "D":
                depends.extend(value.split())
            elif field == "F":
                directory, current = _path(value or '.', root=True), None
            elif field == "R":
                _require(directory is not None, "APK file lacks its directory")
                name = _path(str(PurePosixPath(directory) / _path(value)))
                _require(not any(item['path'] == name for item in files), "Duplicate APK package file")
                current = {"path": name, "apk_original_checksum": None}
                files.append(current)
            elif field == "Z":
                _require(current is not None and current['apk_original_checksum'] is None,
                         "Invalid APK file checksum field")
                current['apk_original_checksum'] = _checksum(value)
        if not fields:
            continue
        _require(fields.get('P') and fields.get('V'), "APK package lacks name or version")
        identity = fields['P'], fields['V'], fields.get('A', '')
        _require(identity not in identities, "Duplicate APK package identity")
        identities.add(identity)
        packages.append({
            "name": fields['P'], "version": fields['V'], "architecture": fields.get('A', ''),
            "license": fields.get('L', ''), "origin": fields.get('o', ''), "homepage": fields.get('U', ''),
            "aports_commit": fields.get('c', ''), "depends": depends,
            "apk_control_checksum": fields.get('C'), "archive": None,
            "files": sorted(files, key=lambda item: item['path']),
        })
    return sorted(packages, key=lambda item: (item['name'], item['version'], item['architecture']))


def _tar_kind(member):
    for check, kind in ((member.isfile, 'regular'), (member.islnk, 'hardlink'),
                        (member.issym, 'symlink'), (member.isdir, 'directory'),
                        (member.ischr, 'character-device'), (member.isblk, 'block-device'),
                        (member.isfifo, 'fifo')):
        if check():
            return kind
    raise FilesystemError('Unsupported target tar entry')


def _resolve_links(entries):
    for name, entry in entries.items():
        if entry['kind'] != 'hardlink':
            continue
        visiting, target = {name}, entry['link_target']
        while entries.get(target, {}).get('kind') == 'hardlink':
            _require(target not in visiting, 'Cyclic target hardlink')
            visiting.add(target)
            target = entries[target]['link_target']
        final = entries.get(target)
        _require(final is not None and final['kind'] == 'regular', 'Missing or non-regular hardlink target')
        for field in ('sha256', 'sha1', 'size'):
            entry[field] = final[field]


def _inventory(entries, metadata=None, packages=None, snapshot='final-rootfs-before-encryption'):
    files = [entries[name] for name in sorted(entries)]
    packages = packages or []
    owned = set()
    for package in packages:
        for record in package['files']:
            name, checksum = record['path'], record.get('apk_original_checksum')
            owned.add(name)
            entry = entries.get(name)
            record.update(kind=entry['kind'] if entry else None, sha256=entry['sha256'] if entry else None)
            if entry is None:
                record['status'] = 'missing'
            elif not checksum or checksum.get('algorithm') != 'SHA1' or not entry.get('sha1'):
                record['status'] = 'unverified'
            else:
                record['status'] = 'unchanged' if checksum['value'] == entry['sha1'] else 'modified'
    result = {
        'schema_version': 1, 'snapshot': snapshot, 'metadata': metadata or {},
        'packages': packages, 'files': files,
        'unowned_files': [item['path'] for item in files
                          if item['kind'] in {'regular', 'hardlink', 'symlink'} and item['path'] not in owned],
        'kernel_modules': [item.copy() for item in files if _MODULE.search(item['path'])],
    }
    if _DATABASE in entries:
        result['apk_database'] = {'path': _DATABASE, 'sha256': entries[_DATABASE]['sha256']}
    return result


def collect_rootfs(tar_path):
    """Hash the final tar, preserving APK ownership and original APK checksums."""
    entries, captured = {}, {}
    with tarfile.open(tar_path, 'r|*') as archive:
        for member in archive:
            kind = _tar_kind(member)
            name = _path(member.name, root=kind == 'directory')
            _require(name not in entries, 'Duplicate target tar entry')
            item = {'path': name, 'kind': kind, 'sha256': None, 'sha1': None, 'size': 0,
                    'mode': format(member.mode & 0o7777, '04o'), 'uid': member.uid,
                    'gid': member.gid, 'mtime': int(member.mtime)}
            if kind == 'regular':
                limit = 32 * _CHUNK if name == _DATABASE else 64 * 1024 if name in _METADATA else None
                _require(limit is None or member.size <= limit, 'Target metadata exceeds its size limit')
                content = bytearray() if limit is not None else None
                sha256, sha1, size = hashlib.sha256(), hashlib.sha1(usedforsecurity=False), 0
                source = archive.extractfile(member)
                _require(source is not None, 'Cannot read target tar file')
                with source:
                    while True:
                        block = source.read(_CHUNK)
                        if not block:
                            break
                        size += len(block)
                        sha256.update(block)
                        sha1.update(block)
                        if content is not None:
                            content.extend(block)
                _require(size == member.size, 'Truncated target tar file')
                item.update(sha256=sha256.hexdigest(), sha1=sha1.hexdigest(), size=size)
                if content is not None:
                    captured[name] = bytes(content).decode('utf-8')
            elif kind in {'hardlink', 'symlink'}:
                item['link_target'] = _path(member.linkname) if kind == 'hardlink' else member.linkname
            elif kind in {'character-device', 'block-device'}:
                item.update(device_major=member.devmajor, device_minor=member.devminor)
            entries[name] = item
    _resolve_links(entries)
    _require(_DATABASE in captured, 'Rootfs lacks its APK installed database')
    packages = _apk_database(captured[_DATABASE])
    return _inventory(entries, {name:captured[name] for name in sorted(_METADATA) if name in captured}, packages)


@dataclass
class CpioEntry:
    """One newc record. Payload bytes stay in memory, never become host nodes."""
    name: str
    ino: int
    mode: int
    uid: int = 0
    gid: int = 0
    nlink: int = 1
    mtime: int = 0
    devmajor: int = 0
    devminor: int = 0
    rdevmajor: int = 0
    rdevminor: int = 0
    data: bytes = b''
    magic: bytes = b'070701'


def _gzip_bytes(path):
    inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
    result = bytearray()
    with Path(path).open('rb') as source:
        while not inflater.eof:
            data = source.read(_CHUNK)
            _require(data, 'Truncated initramfs gzip member')
            while data and not inflater.eof:
                try:
                    result.extend(inflater.decompress(data, min(_CHUNK, _MAX_CPIO_BYTES - len(result) + 1)))
                except zlib.error as error:
                    raise FilesystemError('Invalid initramfs gzip member') from error
                _require(len(result) <= _MAX_CPIO_BYTES, 'Initramfs exceeds its uncompressed size limit')
                data = inflater.unconsumed_tail
            if inflater.eof:
                _require(not any(inflater.unused_data), 'Extra gzip member or nonzero initramfs trailing data')
        while True:
            data = source.read(_CHUNK)
            if not data:
                break
            _require(not any(data), 'Nonzero bytes after initramfs gzip member')
    return bytes(result)


def read_cpio(path):
    """Read exactly one gzip-compressed newc/CRC-newc archive."""
    content, offset, records, seen = _gzip_bytes(path), 0, [], set()
    kinds = {stat.S_IFREG, stat.S_IFDIR, stat.S_IFLNK, stat.S_IFCHR,
             stat.S_IFBLK, stat.S_IFIFO, stat.S_IFSOCK}
    def exact(size):
        nonlocal offset
        _require(size >= 0 and offset + size <= len(content), 'Truncated newc record')
        value = content[offset:offset + size]
        offset += size
        return value
    def padding(size):
        _require(not any(exact(size)), 'Nonzero newc alignment padding')
    while True:
        header = exact(110)
        magic = header[:6]
        _require(magic in (b'070701', b'070702') and re.fullmatch(rb'[0-9a-fA-F]{104}', header[6:]),
                 'Invalid newc header')
        (ino, mode, uid, gid, nlink, mtime, size, devmajor, devminor,
         rdevmajor, rdevminor, namesize, crc) = [int(header[i:i + 8], 16) for i in range(6, 110, 8)]
        _require(1 <= namesize <= _CHUNK and nlink >= 1, 'Invalid newc filename or link count')
        encoded = exact(namesize)
        _require(encoded.endswith(b'\0') and b'\0' not in encoded[:-1], 'Invalid newc filename terminator')
        name = encoded[:-1].decode('utf-8', 'surrogateescape')
        padding(-(110 + namesize) % 4)
        if name == 'TRAILER!!!':
            _require(size == 0 and crc == 0 and not any(content[offset:]), 'Invalid newc trailer or trailing archive')
            break
        kind = stat.S_IFMT(mode)
        _require(kind in kinds, 'Unsupported newc file type')
        name = _path(name, root=kind == stat.S_IFDIR)
        _require(name not in seen, 'Duplicate newc path')
        seen.add(name)
        _require(kind in (stat.S_IFREG, stat.S_IFLNK) or size == 0, 'Special newc entry has file data')
        data = exact(size)
        padding(-size % 4)
        _require(crc == ((sum(data) & 0xffffffff) if magic == b'070702' else 0), 'Invalid newc payload checksum')
        if kind == stat.S_IFLNK:
            _require(len(data) <= 64 * 1024 and b'\0' not in data, 'Invalid newc symlink')
        records.append(CpioEntry(name, ino, mode, uid, gid, nlink, mtime, devmajor, devminor,
                                 rdevmajor, rdevminor, data, magic))
    return records


def _cpio_inventory(records):
    entries, groups = {}, {}
    types = {stat.S_IFREG:'regular', stat.S_IFDIR:'directory', stat.S_IFLNK:'symlink',
             stat.S_IFCHR:'character-device', stat.S_IFBLK:'block-device', stat.S_IFIFO:'fifo', stat.S_IFSOCK:'socket'}
    for record in records:
        kind = types[stat.S_IFMT(record.mode)]
        item = dict(path=record.name, kind=kind, sha256=None, sha1=None, size=0,
                    mode=format(record.mode & 0o7777, '04o'), uid=record.uid, gid=record.gid,
                    mtime=record.mtime, nlink=record.nlink)
        if kind == 'regular':
            item.update(sha256=hashlib.sha256(record.data).hexdigest(),
                        sha1=hashlib.sha1(record.data, usedforsecurity=False).hexdigest(), size=len(record.data))
            if record.nlink > 1:
                groups.setdefault((record.devmajor, record.devminor, record.ino), []).append(record.name)
        elif kind == 'symlink':
            item['link_target'] = record.data.decode('utf-8', 'surrogateescape')
        elif kind in {'character-device', 'block-device'}:
            item.update(device_major=record.rdevmajor, device_minor=record.rdevminor)
        entries[record.name] = item
    for names in groups.values():
        payloads = [name for name in names if entries[name]['size']]
        target = min(payloads or names)
        for name in payloads:
            _require((entries[name]['sha256'], entries[name]['size']) ==
                     (entries[target]['sha256'], entries[target]['size']), 'Conflicting newc hardlink payloads')
        for name in names:
            if name != target:
                entries[name].update(kind='hardlink', link_target=target, sha256=entries[target]['sha256'],
                                     sha1=entries[target]['sha1'], size=entries[target]['size'])
    return _inventory(entries, snapshot='final-initramfs')


def collect_cpio(path):
    return _cpio_inventory(read_cpio(path))


def write_cpio(records, output, epoch):
    """Write deterministic newc/gzip while retaining target ownership and nodes."""
    epoch, output = _epoch(epoch), Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.initramfs-', dir=output.parent)
    try:
        with os.fdopen(fd, 'wb') as raw, gzip.GzipFile(fileobj=raw, mode='wb', filename='', mtime=epoch) as archive:
            offset = 0
            def emit(record):
                nonlocal offset
                name = record.name.encode('utf-8', 'surrogateescape') + b'\0'
                crc = sum(record.data) & 0xffffffff if record.magic == b'070702' else 0
                fields = (record.ino, record.mode, record.uid, record.gid, record.nlink, epoch, len(record.data),
                          record.devmajor, record.devminor, record.rdevmajor, record.rdevminor, len(name), crc)
                _require(all(type(v) is int and 0 <= v <= 0xffffffff for v in fields), 'newc metadata exceeds 32 bits')
                header = record.magic + b''.join(format(value, '08x').encode('ascii') for value in fields)
                name_pad, data_pad = -(110 + len(name)) % 4, -len(record.data) % 4
                archive.write(header + name + bytes(name_pad))
                archive.write(record.data)
                archive.write(bytes(data_pad))
                offset += 110 + len(name) + name_pad + len(record.data) + data_pad
            for record in records:
                emit(record)
            emit(CpioEntry('TRAILER!!!', 0, 0, mtime=epoch))
            archive.write(bytes(-offset % 512))
        os.replace(temporary, output)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def prepare_initramfs(source, output, key_hex=None, epoch=0):
    """Finalize the trusted system-key fingerprint without needing host root."""
    _require(Path(source).resolve() != Path(output).resolve(), 'Initramfs input and output must differ')
    records = read_cpio(source)
    before = _cpio_inventory(records)
    if key_hex is not None:
        key_hex, _ = _key_bytes(key_hex)
        next_inode = max((record.ino for record in records), default=0) + 1
        existing = {record.name:record for record in records}
        additions = []
        for parent in reversed(PurePosixPath(_FINGERPRINT).parents):
            name = str(parent)
            if name == '.':
                continue
            if name in existing:
                _require(stat.S_ISDIR(existing[name].mode), 'Fingerprint parent is not a directory')
            else:
                new = CpioEntry(name, next_inode, stat.S_IFDIR | 0o755, nlink=2, mtime=epoch)
                next_inode += 1
                existing[name] = new
                additions.append(new)
        value = hashlib.sha256(key_hex).hexdigest().encode('ascii') + b'\n'
        fingerprint = CpioEntry(_FINGERPRINT, next_inode, stat.S_IFREG | 0o644, mtime=epoch, data=value)
        records = [record for record in records if record.name != _FINGERPRINT]
        records.extend(additions + [fingerprint])
    write_cpio(records, output, epoch)
    after = collect_cpio(output)
    after['generator_changes'] = _changes(before, after)
    return after


@dataclass
class _TarEntry:
    info: tarfile.TarInfo
    source: object = None
    origin: str | None = None


def _changes(before, after):
    old = {item['path']:item for item in before['files']}
    new = {item['path']:item for item in after['files']}
    fields = ('kind', 'sha256', 'size', 'mode', 'uid', 'gid', 'link_target', 'device_major', 'device_minor')
    changed = []
    for name in sorted(set(old) | set(new)):
        left, right = old.get(name), new.get(name)
        if left is not None and right is not None and all(left.get(field) == right.get(field) for field in fields):
            continue
        action = 'added' if left is None else 'deleted' if right is None else 'modified'
        changed.append({'path':name, 'action':action,
                        'old_sha256':left.get('sha256') if left else None,
                        'new_sha256':right.get('sha256') if right else None})
    return changed


def _remove_tree(entries, name):
    for candidate in list(entries):
        if candidate == name or candidate.startswith(name + '/'):
            del entries[candidate]


def _put(entries, name, entry):
    if not entry.info.isdir():
        _remove_tree(entries, name)
    entries[name] = entry


def _add_overlay(entries, directory):
    directory = Path(directory)
    _require(directory.is_dir() and not directory.is_symlink(), 'Overlay must be an ordinary directory')
    hardlinks = {}
    for parent, directories, files in os.walk(directory, followlinks=False):
        directories.sort()
        files.sort()
        for filename in sorted(directories + files):
            source = Path(parent) / filename
            name = _path(source.relative_to(directory).as_posix())
            details = source.lstat()
            info = tarfile.TarInfo(name)
            previous = entries.get(name)
            info.uid = previous.info.uid if previous else 0
            info.gid = previous.info.gid if previous else 0
            info.mode = stat.S_IMODE(details.st_mode)
            content = None
            if stat.S_ISLNK(details.st_mode):
                info.type, info.linkname = tarfile.SYMTYPE, os.readlink(source)
            elif stat.S_ISDIR(details.st_mode):
                info.type = tarfile.DIRTYPE
            elif stat.S_ISREG(details.st_mode):
                identity = details.st_dev, details.st_ino
                link = hardlinks.get(identity) if details.st_nlink > 1 else None
                if link and (entries[link].info.uid, entries[link].info.gid) == (info.uid, info.gid):
                    info.type, info.linkname = tarfile.LNKTYPE, link
                else:
                    info.type, info.size, content = tarfile.REGTYPE, details.st_size, source
                    hardlinks[identity] = name
            elif stat.S_ISCHR(details.st_mode) or stat.S_ISBLK(details.st_mode):
                info.type = tarfile.CHRTYPE if stat.S_ISCHR(details.st_mode) else tarfile.BLKTYPE
                info.devmajor, info.devminor = os.major(details.st_rdev), os.minor(details.st_rdev)
            elif stat.S_ISFIFO(details.st_mode):
                info.type = tarfile.FIFOTYPE
            else:
                raise FilesystemError('Overlay contains an unsupported socket or special file')
            _put(entries, name, _TarEntry(info, content))


def _inline(entries, name, data, mode=0o644):
    info = tarfile.TarInfo(name)
    info.type, info.mode, info.size = tarfile.REGTYPE, mode, len(data)
    info.uid = info.gid = 0
    _put(entries, name, _TarEntry(info, data))


def _materialize_original_links(original, entries):
    """Retain surviving aliases if an overlay replaces or removes their inode."""
    groups = {}
    for name, member in original.items():
        if not member.islnk():
            continue
        seen, target = {name}, _path(member.linkname)
        while target in original and original[target].islnk():
            _require(target not in seen, 'Cyclic source tar hardlink')
            seen.add(target)
            target = _path(original[target].linkname)
        _require(target in original and original[target].isfile(), 'Missing source tar hardlink target')
        groups.setdefault(target, set()).update((name, target))
    for original_target, names in groups.items():
        survivors = sorted(name for name in names if name in entries and entries[name].origin == name)
        if not survivors:
            continue
        anchor = original_target if original_target in survivors else survivors[0]
        item = entries[anchor]
        item.info.type, item.info.linkname = tarfile.REGTYPE, ''
        item.info.size = original[original_target].size
        item.source = original[original_target]
        for name in survivors:
            if name != anchor:
                entries[name].info.type, entries[name].info.linkname = tarfile.LNKTYPE, anchor
                entries[name].info.size, entries[name].source = 0, None


def _directory_parents(entries):
    for name in list(entries):
        for parent in PurePosixPath(name).parents:
            path = str(parent)
            if path in entries:
                _require(entries[path].info.isdir(), 'Target file has a non-directory parent')
            else:
                info = tarfile.TarInfo(path)
                info.type, info.mode = tarfile.DIRTYPE, 0o755
                info.uid = info.gid = 0
                entries[path] = _TarEntry(info)
    if '.' not in entries:
        info = tarfile.TarInfo('.')
        info.type, info.mode = tarfile.DIRTYPE, 0o755
        entries['.'] = _TarEntry(info)
    _require(entries['.'].info.isdir(), 'Target root is not a directory')


def _entry_data(entry, archive):
    if isinstance(entry.source, bytes):
        return io.BytesIO(entry.source)
    if isinstance(entry.source, Path):
        fd = os.open(entry.source, os.O_RDONLY | os.O_NOFOLLOW)
        stream = os.fdopen(fd, 'rb')
        details = os.fstat(stream.fileno())
        if not stat.S_ISREG(details.st_mode) or details.st_size != entry.info.size:
            stream.close()
            raise FilesystemError('Overlay file changed during image generation')
        return stream
    _require(isinstance(entry.source, tarfile.TarInfo), 'Missing tar file payload source')
    stream = archive.extractfile(entry.source)
    _require(stream is not None, 'Cannot read source tar payload')
    return stream


def _old_inventory(bundle):
    path = bundle / 'sbom/inventory.json'
    if not path.is_file():
        return None
    value = json.loads(path.read_text())
    return value.get('rootfs', value)


def _sync_boot_confirmation(entries, archive, machine, previous_machine):
    """Keep the existing boot guard aligned with the generated product name."""
    entry = entries.get(_BOOT_CONFIRM)
    if entry is None:
        return
    _require(isinstance(machine, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+-]*', machine),
             'Invalid boot-confirmation machine identifier')
    if not entry.info.isfile() or entry.info.size > _CHUNK:
        _require(machine == previous_machine,
                 'Cannot synchronize the custom boot-confirmation script; '
                 'update etc/init.d/naos-boot-confirm for the selected board')
        return
    with _entry_data(entry, archive) as stream:
        script = stream.read()
    matches = list(_BOOT_MACHINE_CHECK.finditer(script))
    if len(matches) != 1 or not re.fullmatch(rb'[A-Za-z0-9][A-Za-z0-9._+-]*',
                                          matches[0].group(2).replace(rb'\.', b'.')):
        _require(machine == previous_machine,
                 'Cannot synchronize the custom boot-confirmation machine check; '
                 'update etc/init.d/naos-boot-confirm for the selected board')
        return
    # The existing guard uses grep BRE: dots need escaping, while an unescaped
    # plus is already literal. Never interpolate a board name as shell code.
    expected = machine.replace('.', r'\.').encode('ascii')
    match = matches[0]
    updated = script[:match.start(2)] + expected + script[match.end(2):]
    if updated != script:
        info = copy.copy(entry.info)
        info.size = len(updated)
        info.pax_headers = {key: value for key, value in info.pax_headers.items() if key != 'size'}
        _put(entries, _BOOT_CONFIRM, _TarEntry(info, updated))


def _imported_container_manifests(inventory, records):
    """Recognize container payloads owned by this invocation's local APKs."""
    identities = {(item['name'], item['version'], item['architecture']) for item in records}
    files = {item['path']: item for item in inventory['files']}
    candidates = set()
    for package in inventory['packages']:
        if (package['name'], package['version'], package['architecture']) not in identities:
            continue
        for item in package['files']:
            name = item['path']
            if not _CONTAINER_MANIFEST.fullmatch(name):
                continue
            rootfs = str(PurePosixPath(name).parent / 'rootfs')
            if files.get(name, {}).get('kind') == 'regular' and files.get(rootfs, {}).get('kind') == 'directory':
                candidates.add('/' + name)
    return sorted(candidates)


def _container_ini(text, manifest):
    """Edit only the manifest field, retaining comments and other settings."""
    newline = '\r\n' if '\r\n' in text else '\n'
    lines = text.splitlines(keepends=True)
    values, found = {'manifest': manifest}, set()
    active, end = False, None
    for index, line in enumerate(lines):
        section = re.fullmatch(r'[ \t]*\[([^]\r\n]+)\][ \t]*(?:[;#].*)?', line.rstrip('\r\n'))
        if section:
            if active:
                end = index
            active = section[1] == 'container'
            if active:
                end = len(lines)
            continue
        if active:
            match = re.fullmatch(r'([ \t]*)(manifest)([ \t]*=[ \t]*)(.*?)([ \t]+[;#].*|[;#].*|[ \t]*)',
                                 line.rstrip('\r\n'))
            if match:
                ending = line[len(line.rstrip('\r\n')):]
                lines[index] = match[1] + match[2] + match[3] + values[match[2]] + match[5] + ending
                found.add(match[2])
    if active:
        end = len(lines)
    if end is None:
        if lines and not lines[-1].endswith(('\n', '\r')):
            lines[-1] += newline
        if lines and lines[-1].strip():
            lines.append(newline)
        lines.append('[container]' + newline)
        end = len(lines)
    if end and not lines[end - 1].endswith(('\n', '\r')):
        lines[end - 1] += newline
    lines[end:end] = [key + '=' + value + newline for key, value in values.items() if key not in found]
    return ''.join(lines)


def _configure_imported_container(entries, archive, candidates):
    if not candidates:
        return
    entry = entries.get(_CORE_CONFIG)
    text = ''
    if entry is not None:
        _require(entry.info.isfile() and entry.info.size <= _CHUNK,
                 'Core device.ini must be a regular file of at most 1 MiB')
        try:
            with _entry_data(entry, archive) as stream:
                text = stream.read().decode('utf-8')
        except UnicodeDecodeError as error:
            raise FilesystemError('Core device.ini must use UTF-8') from error
    config = configparser.ConfigParser(interpolation=None, strict=False, inline_comment_prefixes=('#', ';'))
    config.optionxform = str
    try:
        config.read_string(text)
    except configparser.Error as error:
        raise FilesystemError('Cannot configure the preinstalled container: invalid Core device.ini') from error
    # Core treats DEFAULT as an unknown section rather than inherited values.
    config.defaults().clear()
    configured = config.get('container', 'manifest', fallback='/userdata/manifest.yml').strip()
    if len(configured) >= 2 and configured[0] in ('"', "'", '`') and configured[-1] == configured[0]:
        configured = configured[1:-1]
    if configured != '/userdata/manifest.yml':
        return
    _require(len(candidates) == 1,
             'Multiple container APKs were imported; set [container] manifest in '
             'files/etc/naos-core/device.ini to the desired container path. Imported manifests: ' + ', '.join(candidates))
    selected = candidates[0]
    name = selected.lstrip('/')
    rootfs = str(PurePosixPath(name).parent / 'rootfs')
    _require(name in entries and entries[name].info.isfile() and rootfs in entries and entries[rootfs].info.isdir(),
             'The selected preinstalled container requires a regular manifest.yml and adjacent rootfs: ' + selected)
    updated = _container_ini(text, selected).encode('utf-8')
    if entry is None:
        _inline(entries, _CORE_CONFIG, updated, mode=0o600)
    elif updated != text.encode('utf-8'):
        info = copy.copy(entry.info)
        info.size = len(updated)
        info.pax_headers = {key: value for key, value in info.pax_headers.items() if key != 'size'}
        _put(entries, _CORE_CONFIG, _TarEntry(info, updated))


def prepare_rootfs(bundle, work, overlays=(), remove=(), ota_certificate=None, ssh_ca=None,
                   metadata=None, epoch=0, source_archive=None, local_apks=()):
    """Merge edits into a tar, preserving target ownership, nodes and links.

    Overlay files use their source permission bits; existing target ownership
    is retained, and newly introduced paths are owned by root. Symlinks remain
    archive data and are never followed on the host.
    """
    bundle, work, epoch = Path(bundle), Path(work), _epoch(epoch)
    _require(not work.resolve().is_relative_to(bundle.resolve()), 'Rootfs work directory must be outside the input bundle')
    work.mkdir(parents=True, exist_ok=True)
    original_source = bundle / 'rootfs.tar.gz'
    _require(original_source.is_file(), 'Input bundle lacks rootfs.tar.gz')
    before = collect_rootfs(original_source)
    source = Path(source_archive) if source_archive is not None else original_source
    installed = collect_rootfs(source) if source_archive is not None else before
    container_manifests = _imported_container_manifests(installed, local_apks) if local_apks else ()
    del installed
    evidence = _old_inventory(bundle)
    if evidence:
        packages = {(p['name'], p['version'], p.get('architecture', '')):p for p in evidence.get('packages', [])}
        for package in before['packages']:
            original_package = packages.get((package['name'], package['version'], package.get('architecture', '')))
            if original_package:
                package['archive'] = original_package.get('archive')
    output = work / 'rootfs.tar.gz'
    _require(output.resolve() != source.resolve(), 'Rootfs input and output must differ')
    fd, temporary = tempfile.mkstemp(prefix='.rootfs-', dir=work)
    try:
        with tarfile.open(source, 'r:*') as archive:
            original, entries = {}, {}
            for member in archive:
                kind = _tar_kind(member)
                name = _path(member.name, root=kind == 'directory')
                _require(name not in original, 'Duplicate source tar path')
                original[name] = member
                entries[name] = _TarEntry(copy.copy(member), member if member.isfile() else None, name)
            for name in remove:
                _remove_tree(entries, _path(name))
            for directory in overlays:
                _add_overlay(entries, directory)
            _configure_imported_container(entries, archive, container_manifests)
            for name, certificate in (('etc/rauc/keyring.pem', ota_certificate),
                                      ('etc/ssh/ssh_ca_key.pub', ssh_ca)):
                if certificate is not None:
                    path = Path(certificate)
                    _require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= _CHUNK,
                             'Certificate must be a nonempty ordinary file')
                    _inline(entries, name, path.read_bytes())
            if metadata is not None:
                version = {}
                if _VERSION in entries:
                    _require(entries[_VERSION].info.isfile(), 'Version marker must be a regular file')
                    with _entry_data(entries[_VERSION], archive) as stream:
                        _require(entries[_VERSION].info.size <= 65536, 'Version marker exceeds size limit')
                        version = json.load(stream)
                    _require(isinstance(version, dict), 'Version marker is not a JSON object')
                previous_machine = version.get('machine')
                for field in ('machine', 'board', 'version', 'build_id', 'layout_compatible',
                              'secure_boot', 'system_encryption', 'data_encryption'):
                    value = metadata.get(field, metadata.get('defaults', {}).get(field))
                    if value is not None:
                        version[field] = value
                _inline(entries, _VERSION, (json.dumps(version, sort_keys=True, indent=2) + '\n').encode())
                if version.get('machine') is not None:
                    _sync_boot_confirmation(entries, archive, version['machine'], previous_machine)
            _materialize_original_links(original, entries)
            _directory_parents(entries)
            with (os.fdopen(fd, 'wb') as raw,
                  gzip.GzipFile(fileobj=raw, mode='wb', filename='', mtime=epoch) as gz,
                  tarfile.open(fileobj=gz, mode='w|', format=tarfile.PAX_FORMAT) as target):
                emitted, visiting = set(), set()
                def emit(name):
                    if name in emitted:
                        return
                    _require(name not in visiting, 'Cyclic output tar hardlink or parent')
                    visiting.add(name)
                    parent = str(PurePosixPath(name).parent)
                    if parent != name:
                        emit(parent)
                    entry = entries[name]
                    info = copy.copy(entry.info)
                    info.name, info.mtime = name, epoch
                    info.uname = info.gname = ''
                    info.pax_headers = {k:v for k,v in entry.info.pax_headers.items()
                                        if k not in {'mtime','atime','ctime','path','linkpath','uid','gid','uname','gname'}}
                    if info.islnk():
                        info.linkname = _path(info.linkname)
                        _require(info.linkname in entries and (entries[info.linkname].info.isfile()
                                 or entries[info.linkname].info.islnk()), 'Invalid output tar hardlink target')
                        emit(info.linkname)
                    if info.isfile():
                        with _entry_data(entry, archive) as stream:
                            target.addfile(info, stream)
                    else:
                        target.addfile(info)
                    emitted.add(name)
                    visiting.remove(name)
                for name in sorted(entries):
                    emit(name)
        os.replace(temporary, output)
    except BaseException:
        # os.fdopen may not yet have assumed ownership when a preflight fails.
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    result = collect_rootfs(output)
    old_packages = {(p['name'], p['version'], p.get('architecture', '')):p for p in before.get('packages', [])}
    for package in result['packages']:
        previous = old_packages.get((package['name'], package['version'], package.get('architecture', '')))
        if previous:
            package['archive'] = previous.get('archive')
    changes = _changes(before, result)
    statuses = {item['path']:item['action'] for item in changes}
    for package in result['packages']:
        for item in package['files']:
            item['generator_status'] = statuses.get(item['path'], 'unchanged')
    result['generator_changes'] = changes
    return output, result


def make_squashfs(tar_path, destination, tool, epoch=0, processors=4):
    """Feed the target tar to sqfstar; only the root inode is forced to root."""
    epoch, destination, tar_path = _epoch(epoch), Path(destination), Path(tar_path)
    _require(type(processors) is int and processors > 0, 'SquashFS processor count must be positive')
    _require(tar_path.resolve() != destination.resolve(), 'SquashFS source and destination must differ')
    _require(not destination.is_symlink(), 'SquashFS destination cannot be a symlink')
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.system-squashfs-', dir=destination.parent)
    os.close(fd)
    os.unlink(temporary)
    command = [str(tool), '-comp', 'zstd', '-processors', str(processors),
               '-mkfs-time', str(epoch), '-all-time', str(epoch),
               '-root-uid', '0', '-root-gid', '0', '-root-mode', '0755',
               '-no-progress', '-exit-on-error', temporary]
    environment = {name:value for name,value in process_environment().items() if name != 'SOURCE_DATE_EPOCH'}
    try:
        with gzip.open(tar_path, 'rb') as source, tempfile.TemporaryFile() as diagnostics:
            process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=diagnostics,
                                       stderr=diagnostics, env=environment)
            try:
                try:
                    shutil.copyfileobj(source, process.stdin, _CHUNK)
                except BrokenPipeError:
                    pass
                finally:
                    try:
                        process.stdin.close()
                    except BrokenPipeError:
                        pass
                status = process.wait()
            except BaseException:
                process.terminate()
                process.wait()
                raise
            diagnostics.seek(0)
            message = diagnostics.read().decode('utf-8', errors='replace')
            _require(status == 0 and not any(text in message for text in ('Could not resolve hardlink', 'FATAL ERROR')),
                     'SquashFS generation failed: ' + message[-4000:].strip())
        with open(temporary, 'rb') as stream:
            _require(stream.read(4) == b'hsqs' and Path(temporary).stat().st_size >= 96,
                     'SquashFS tool did not generate a valid filesystem')
        os.chmod(temporary, 0o644)
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def crypt_sectors(data, key, first_sector=0, *, decrypt=False):
    """The RK legacy aes-cbc-plain format restarts CBC for every 512-byte sector."""
    try:
        from Cryptodome.Cipher import AES
    except ImportError as error:
        raise FilesystemError('System encryption requires the pycryptodomex dependency') from error
    _require(len(key) == 32 and len(data) % 512 == 0 and type(first_sector) is int and first_sector >= 0,
             'Invalid sector encryption input')
    result = bytearray()
    for offset in range(0, len(data), 512):
        sector = first_sector + offset // 512
        iv = struct.pack('<I', sector & 0xffffffff) + bytes(12)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        block = data[offset:offset + 512]
        result.extend(cipher.decrypt(block) if decrypt else cipher.encrypt(block))
    return bytes(result)


def encrypt_system(source, destination, key_hex, alignment=4096):
    """Encrypt SquashFS and verify a full decrypt/readback before publishing it."""
    key_hex, key = _key_bytes(key_hex)
    source, destination = Path(source), Path(destination)
    _require(source.is_file() and not source.is_symlink(), 'System source must be an ordinary file')
    _require(not destination.is_symlink() and source.resolve() != destination.resolve(),
             'System cipher source and destination must be separate ordinary files')
    _require(type(alignment) is int and alignment > 0 and alignment % 512 == 0,
             'System cipher alignment must be a positive multiple of 512 bytes')
    length = source.stat().st_size
    _require(length >= 96, 'System source is too small to contain SquashFS')
    with source.open('rb') as stream:
        _require(stream.read(4) == b'hsqs', 'System source is not SquashFS')
    destination.parent.mkdir(parents=True, exist_ok=True)
    padded = (length + alignment - 1) // alignment * alignment
    expected = hashlib.sha256()
    fd, temporary = tempfile.mkstemp(prefix='.system-cipher-', dir=destination.parent)
    try:
        with source.open('rb') as plain, os.fdopen(fd, 'wb') as encrypted:
            for start in range(0, padded, _CHUNK):
                amount = min(_CHUNK, padded - start)
                meaningful = max(0, min(amount, length - start))
                data = plain.read(meaningful)
                _require(len(data) == meaningful, 'System source was truncated during encryption')
                expected.update(data)
                encrypted.write(crypt_sectors(data.ljust(amount, b'\0'), key, start // 512))
            _require(not plain.read(1), 'System source grew during encryption')
            encrypted.flush()
            os.fsync(encrypted.fileno())
        actual, cipher_hash = hashlib.sha256(), hashlib.sha256()
        with open(temporary, 'rb') as encrypted:
            for start in range(0, padded, _CHUNK):
                amount = min(_CHUNK, padded - start)
                data = encrypted.read(amount)
                _require(len(data) == amount, 'Encrypted system readback was truncated')
                cipher_hash.update(data)
                plain = crypt_sectors(data, key, start // 512, decrypt=True)
                meaningful = max(0, min(amount, length - start))
                actual.update(plain[:meaningful])
                _require(not any(plain[meaningful:]), 'Encrypted system padding failed readback')
            _require(not encrypted.read(1), 'Encrypted system has unexpected trailing data')
        _require(actual.digest() == expected.digest(), 'Encrypted system decrypt/readback differs from SquashFS')
        os.chmod(temporary, 0o644)
        os.replace(temporary, destination)
        return {'format':1, 'cipher':'aes-cbc-plain', 'key_bytes':32, 'sector_bytes':512,
                'iv_offset_sectors':0, 'data_offset_sectors':0, 'alignment_bytes':alignment,
                'key_storage':'misc-huk-blob', 'key_sha256':hashlib.sha256(key_hex).hexdigest(),
                'plain_bytes':length, 'encrypted_bytes':padded,
                'plaintext_sha256':expected.hexdigest(), 'ciphertext_sha256':cipher_hash.hexdigest()}
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def make_import_record(key_hex):
    """Build the bounded factory import; the caller controls its private output."""
    key_hex, _ = _key_bytes(key_hex)
    header = b'NAOS-SYSTEM-KEY\nversion=2\nkey=' + key_hex + b'\n'
    header = header.ljust(256, b' ')
    return (header + hashlib.sha256(header).hexdigest().encode('ascii') + bytes(192)).ljust(65536, b'\0')
