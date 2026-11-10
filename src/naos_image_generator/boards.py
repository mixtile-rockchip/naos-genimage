# SPDX-License-Identifier: MIT
"""Select carrier-board DTBs while retaining the compiled bootloader filenames."""
import hashlib
from pathlib import Path, PurePosixPath
import struct

from .bootloader import read_fdt
from .common import BuildError, require
from .inputs import label


_BLOCK = 512
_MAX_DTB = 8 * 1024 * 1024
_MAX_RESOURCE = 256 * 1024 * 1024


def discover(directory):
    """Return direct DTB files; an absent/empty board directory adds no menu."""
    directory = Path(directory)
    if not directory.exists():
        return ()
    require(directory.is_dir() and not directory.is_symlink(), 'Board directory must be an ordinary directory')
    result = tuple(sorted(directory.glob('*.dtb')))
    for filename in result:
        require(filename.is_file() and not filename.is_symlink(), 'Board DTB must be an ordinary file: '+filename.name)
        label(filename.stem, 'board device-tree name')
    return tuple(filename.resolve() for filename in result)


def describe(filename):
    filename = Path(filename)
    require(filename.is_file() and not filename.is_symlink() and 40 <= filename.stat().st_size <= _MAX_DTB,
            'Board DTB must be an ordinary device-tree file: '+filename.name)
    name = label(filename.stem, 'board device-tree name')
    try:
        nodes, data, _ = read_fdt(filename)
        model = nodes.get('/', {}).get('model', b'')
        require(model.endswith(b'\0') and model.count(b'\0') == 1, 'Board DTB lacks a valid root model')
        model = model[:-1].decode('utf-8')
        require(bool(model.strip()), 'Board DTB has an empty root model')
    except (UnicodeError, ValueError) as error:
        raise BuildError('Invalid board DTB: '+filename.name) from error
    return dict(name=name, filename=filename.name, model=model, sha256=hashlib.sha256(data).hexdigest(), size=len(data))


def _resource_entries(data):
    require(_BLOCK <= len(data) <= _MAX_RESOURCE and data[:4] == b'RSCE', 'Invalid Rockchip resource image')
    version, index_version = struct.unpack_from('<HH', data, 4)
    header_blocks, table_offset, entry_blocks = struct.unpack_from('<BBB', data, 8)
    count = struct.unpack_from('<I', data, 12)[0]
    require(version == index_version == 0 and header_blocks >= 1 and table_offset >= header_blocks
            and entry_blocks >= 1 and 0 < count <= 4096,
            'Unsupported Rockchip resource image layout')
    first_payload = (table_offset + count*entry_blocks)*_BLOCK
    require(first_payload <= len(data), 'Truncated Rockchip resource index')
    entries, names, ranges = [], set(), []
    for index in range(count):
        offset = (table_offset+index*entry_blocks)*_BLOCK
        raw = data[offset:offset+entry_blocks*_BLOCK]
        require(raw[:4] == b'ENTR', 'Invalid Rockchip resource entry')
        stop = raw.find(b'\0', 4, 224)
        require(stop > 4, 'Invalid Rockchip resource filename')
        try:
            name = raw[4:stop].decode('utf-8')
        except UnicodeError as error:
            raise BuildError('Invalid Rockchip resource filename') from error
        path = PurePosixPath(name)
        require(not path.is_absolute() and '..' not in path.parts and '\\' not in name
                and name not in names, 'Unsafe or duplicate Rockchip resource filename')
        names.add(name)
        hash_size, block, size = struct.unpack_from('<III', raw, 256)
        start, end = block*_BLOCK, block*_BLOCK+size
        require(hash_size in (0, 20, 32) and size > 0 and start >= first_payload and end <= len(data),
                'Rockchip resource payload is out of bounds')
        require(all(end <= left or start >= right for left,right in ranges),
                'Rockchip resource payloads overlap')
        ranges.append((start,end))
        content = data[start:end]
        if hash_size:
            digest = (hashlib.sha1(content, usedforsecurity=False).digest() if hash_size == 20
                      else hashlib.sha256(content).digest())
            require(raw[224:224+hash_size] == digest, 'Rockchip resource payload checksum mismatch: '+name)
        entries.append(dict(name=name, raw=raw, payload=content, hash_size=hash_size, index=offset))
    return first_payload, entries


def replace_resource(source, output, original_dtb, selected_dtb, original_name):
    """Replace the original DTB entry, preserving its name and all other assets."""
    source, output = Path(source), Path(output)
    require(output.resolve() not in {source.resolve(), Path(original_dtb).resolve(), Path(selected_dtb).resolve()}
            and not output.is_symlink(), 'Resource input and output must differ')
    require(source.is_file() and not source.is_symlink() and source.stat().st_size <= _MAX_RESOURCE,
            'Missing, nonordinary or oversized resource image')
    data = source.read_bytes()
    first_payload, entries = _resource_entries(data)
    original, replacement = Path(original_dtb).read_bytes(), Path(selected_dtb).read_bytes()
    # The SDK tool normally changes the first DTB's internal name to
    # rk-kernel.dtb. Preserve that actual name instead of using the new board.
    selected = [item for item in entries if item['name'] in (original_name, 'rk-kernel.dtb')
                or (item['name'].endswith('.dtb') and item['payload'] == original)]
    require(selected, 'Resource image contains no entry for the original kernel device tree')
    chosen = {item['name'] for item in selected}
    result = bytearray(data[:first_payload])
    for item in entries:
        payload = replacement if item['name'] in chosen else item['payload']
        raw = bytearray(item['raw'])
        block = len(result)//_BLOCK
        hash_size = item['hash_size']
        if hash_size:
            digest = (hashlib.sha1(payload, usedforsecurity=False).digest() if hash_size == 20
                      else hashlib.sha256(payload).digest())
            raw[224:256] = digest+bytes(32-len(digest))
        struct.pack_into('<III', raw, 256, hash_size, block, len(payload))
        result[item['index']:item['index']+len(raw)] = raw
        result.extend(payload)
        result.extend(bytes(-len(result)%_BLOCK))
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_bytes(result)
    _, final = _resource_entries(result)
    require([item['name'] for item in final] == [item['name'] for item in entries],
            'Resource image filenames changed unexpectedly')
    require(all(item['payload'] == (replacement if item['name'] in chosen else old['payload'])
                for item,old in zip(final,entries)), 'Rebuilt resource payload verification failed')
    return sorted(chosen)


def prepare(bundle_root, machine, selected_dtb, work):
    """Return overridden DTB/resource paths without modifying exported inputs."""
    root, work = Path(bundle_root), Path(work)
    original_name = label(machine, 'base machine')+'.dtb'
    original = root/original_name
    selected = Path(selected_dtb)
    info = describe(selected)
    require(original.is_file() and not original.is_symlink(), 'Original exported DTB is missing')
    nodes, _, _ = read_fdt(original)
    selected_nodes, content, _ = read_fdt(selected)
    require(len(content) == info['size'] and hashlib.sha256(content).hexdigest() == info['sha256'],
            'Board DTB changed during image generation')
    original_compatible = nodes.get('/',{}).get('compatible',b'').split(b'\0')
    if b'rockchip,rk3588' in original_compatible:
        require(b'rockchip,rk3588' in selected_nodes.get('/',{}).get('compatible',b'').split(b'\0'),
                'Board DTB must remain compatible with the RK3588 core module')
    directory = work/'board'
    require(not directory.resolve().is_relative_to(root.resolve()), 'Board work directory must be outside exported inputs')
    directory.mkdir(parents=True,exist_ok=True)
    dtb, resource = directory/original_name, directory/'resource.img'
    require(dtb.resolve() != selected.resolve() and not dtb.is_symlink(),
            'Selected board DTB must not be overwritten')
    dtb.write_bytes(content)
    entries = replace_resource(root/'resource.img',resource,original,dtb,original_name)
    info.update(original_name=original_name,resource_dtb_entries=entries,
                resource_sha256=hashlib.sha256(resource.read_bytes()).hexdigest())
    return dtb,resource,info
