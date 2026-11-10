# SPDX-License-Identifier: MIT
"""Build Rockchip boot firmware from compiled, key-independent inputs."""
from __future__ import annotations

import configparser
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import struct

from .common import BuildError, run


KEY_NODE = '/signature/key-dev'


def _require(condition, message):
    if not condition:
        raise BuildError(message)


def _sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def _record(path):
    return {'path': path.name, 'size': path.stat().st_size, 'sha256': _sha(path)}


def _inside(root, name):
    _require(isinstance(name, str) and name and '\\' not in name and '\0' not in name,
             'Invalid bootloader input filename')
    relative = PurePosixPath(name)
    _require(not relative.is_absolute() and '..' not in relative.parts and str(relative) != '.',
             'Bootloader input path escapes its directory')
    path = root / relative
    _require(path.is_file() and path.resolve().is_relative_to(root.resolve()),
             'Missing or escaping bootloader input: ' + name)
    return path


def _tool(tools, name):
    _require(name in tools, 'Required image-generation tool is not configured: ' + name)
    return str(tools[name])


def _invoke(tools, name, arguments, cwd, env):
    # Vendor signer output is deliberately not returned as a public report.
    try:
        return run([_tool(tools, name), *[str(value) for value in arguments]], cwd=cwd, env=env)
    except BuildError:
        raise BuildError('Boot firmware tool failed: ' + name) from None


def _private_signer(tools, work):
    """Keep the vendor signer's mutable settings private to this build."""
    directory = Path(work) / 'rk-signer'
    directory.mkdir(mode=0o700)
    executable = directory / 'rk_sign_tool'
    source = Path(_tool(tools, 'rk_sign_tool'))
    _require(source.is_file(), 'Rockchip signer must be an ordinary host file')
    shutil.copyfile(source, executable)
    executable.chmod(0o755)
    # Loader verification locates boot_merger next to rk_sign_tool.
    merger = directory / 'boot_merger'
    shutil.copyfile(_tool(tools, 'boot_merger'), merger)
    merger.chmod(0o755)
    # rk_sign_tool reads setting.ini beside its executable, then rewrites it
    # after cc/lk. Do not share state or import an SDK's selected key paths.
    values = {
        'support_chip': '3588', 'hard_sign_big_hash': '', 'hard_sign_litte_hash': '',
        'hard_sign_pss': '3588', 'new_crypto': '3588', 'new_idb': '3588',
        'sign_algo': '', 'sign_flag': '', 'sign_soft_version': '', 'sign_nonce': '',
        'sign_cert': '', 'select_chip': '', 'select_private_key': '',
        'select_public_key': '', 'exclude_boot_sign': '', 'sign_state': '',
        'sign_out': '', 'bin_root_dir': '', 'using_hsm': '', 'hsm_engine_id': '',
        'hsm_private_key_id': '', 'hsm_public_key_id': '',
    }
    settings = directory / 'setting.ini'
    settings.write_text('[System]\n' + ''.join(name + '=' + value + '\n' for name, value in values.items()))
    settings.chmod(0o600)
    return {**tools, 'rk_sign_tool': executable}


def read_fdt(path):
    """Read the bounded FDT structure, including FIT inline payloads."""
    raw = Path(path).read_bytes()
    _require(len(raw) >= 40, 'Truncated device tree')
    magic, total, offset, strings, _, version, _, _, string_size, structure_size = struct.unpack_from('>10I', raw)
    _require(magic == 0xD00DFEED and version >= 17 and 40 <= total <= len(raw)
             and offset + structure_size <= total and strings + string_size <= total,
             'Invalid device-tree header')
    position, end, stack, nodes = offset, offset + structure_size, [], {}
    while position + 4 <= end:
        token = struct.unpack_from('>I', raw, position)[0]
        position += 4
        if token == 1:
            stop = raw.find(b'\0', position, end)
            _require(stop >= 0, 'Unterminated device-tree node')
            name = raw[position:stop].decode('ascii')
            _require('/' not in name and (stack or name == ''), 'Invalid device-tree node name')
            stack.append(name)
            node = '/' + '/'.join(stack[1:])
            _require(node not in nodes, 'Duplicate device-tree node')
            nodes[node] = {}
            position = (stop + 4) & ~3
        elif token == 2:
            _require(stack, 'Unbalanced device tree')
            stack.pop()
        elif token == 3:
            _require(stack and position + 8 <= end, 'Truncated device-tree property')
            size, name_offset = struct.unpack_from('>II', raw, position)
            position += 8
            start = strings + name_offset
            stop = raw.find(b'\0', start, strings + string_size)
            _require(name_offset < string_size and stop >= 0 and position + size <= end,
                     'Invalid device-tree property')
            name = raw[start:stop].decode('ascii')
            properties = nodes['/' + '/'.join(stack[1:])]
            _require(name not in properties, 'Duplicate device-tree property')
            properties[name] = raw[position:position + size]
            position = (position + size + 3) & ~3
        elif token == 4:
            continue
        elif token == 9:
            _require(not stack, 'Unclosed device-tree node')
            return nodes, raw, total
        else:
            raise BuildError('Unsupported device-tree structure token')
    raise BuildError('Device tree has no end marker')


def _clean_dtb(path):
    nodes, _, _ = read_fdt(path)
    for node, properties in nodes.items():
        _require(not node.rsplit('/', 1)[-1].startswith('key-')
                 and not any(name.startswith('rsa,') or name == 'burn-key-hash' for name in properties),
                 'Exported control DTB already contains signing or OTP data')


def _key_identity(path):
    nodes, _, _ = read_fdt(path)
    key = nodes.get(KEY_NODE, {})
    bits = int.from_bytes(key.get('rsa,num-bits', b''), 'big')
    exponent = int.from_bytes(key.get('rsa,exponent', b''), 'big')
    modulus = key.get('rsa,modulus', b'')
    _require(bits == 2048 and exponent == 65537 and len(modulus) == 256 and modulus[0] & 0x80,
             'The selected tools did not inject the required RSA-2048 verification key')
    _require(key.get('required') == b'conf\0', 'FIT configuration signatures are not required')
    return bits, exponent, modulus


def _fit_hashes(path, expected):
    nodes, raw, total = read_fdt(path)
    result = {}
    for image, source in expected.items():
        node = '/images/' + image
        properties = nodes.get(node, {})
        if 'data' in properties:
            payload = properties['data']
        else:
            size = int.from_bytes(properties.get('data-size', b''), 'big')
            if 'data-position' in properties:
                position = int.from_bytes(properties['data-position'], 'big')
            elif 'data-offset' in properties:
                position = ((total + 3) & ~3) + int.from_bytes(properties['data-offset'], 'big')
            else:
                raise BuildError('FIT image has no payload: ' + image)
            _require(size > 0 and position + size <= len(raw), 'FIT payload is out of bounds: ' + image)
            payload = raw[position:position + size]
        checksum = hashlib.sha256(payload).digest()
        _require(len(payload) == source.stat().st_size and checksum.hex() == _sha(source),
                 'FIT data differs from the selected input: ' + image)
        hash_node = nodes.get(node + '/hash', {})
        _require(hash_node.get('algo') == b'sha256\0' and hash_node.get('value') == checksum,
                 'FIT payload hash verification failed: ' + image)
        result[image] = {'size': len(payload), 'sha256': checksum.hex()}
    return nodes, result


def _assert_signature_coverage(nodes, images):
    signature = nodes.get('/configurations/conf/signature', {})
    covered = {value.decode('ascii') for value in signature.get('hashed-nodes', b'').split(b'\0') if value}
    _require('/configurations/conf' in covered, 'FIT signature does not cover its configuration')
    for image in images:
        node = '/images/' + image
        _require(node in covered and node + '/hash' in covered,
                 'FIT signature does not cover image hash: ' + image)


def _assert_maximum_pss_encoding(encoded, bits):
    """Check RFC 8017 EMSA-PSS structure and the required maximum SHA256 salt.

    The FIT checker still verifies the signed message hash. This independent
    check enforces the salt policy even when that checker accepts any salt
    length, as OpenSSL's RSA_PSS_SALTLEN_AUTO does.
    """
    encoded_bits = bits - 1
    encoded_size = (encoded_bits + 7) // 8
    hash_size = hashlib.sha256().digest_size
    maximum = encoded_size - hash_size - 2
    _require(maximum >= 0 and len(encoded) == encoded_size,
             'FIT RSA-PSS encoded message has an invalid size')
    _require(encoded[-1] == 0xbc, 'FIT RSA-PSS trailer is invalid')
    masked, digest = encoded[:-hash_size - 1], encoded[-hash_size - 1:-1]
    unused = 8 * encoded_size - encoded_bits
    top_mask = 0xff >> unused
    _require(not masked[0] & ~top_mask, 'FIT RSA-PSS unused high bits are not zero')
    # MGF1(SHA256); its counter is a four-byte, big-endian integer.
    mask = b''.join(hashlib.sha256(digest + struct.pack('>I', counter)).digest()
                    for counter in range((len(masked) + hash_size - 1) // hash_size))
    database = bytearray(first ^ second for first, second in zip(masked, mask))
    database[0] &= top_mask
    delimiter = next((index for index, value in enumerate(database) if value), None)
    _require(delimiter is not None and database[delimiter] == 1,
             'FIT RSA-PSS data-block delimiter is invalid')
    salt_size = len(database) - delimiter - 1
    _require(salt_size == maximum,
             'FIT RSA-PSS salt length must be maximum (%d bytes), got %d' % (maximum, salt_size))
    return salt_size


def _assert_pss_signature(nodes, identity):
    """Recover the PSS encoding using only the injected RSA public key."""
    signature = nodes.get('/configurations/conf/signature', {})
    _require(signature.get('algo') == b'sha256,rsa2048\0'
             and signature.get('padding') == b'pss\0'
             and signature.get('key-name-hint') == b'dev\0',
             'FIT signature must use the selected RSA-2048/SHA256 PSS key')
    bits, exponent, modulus_bytes = identity
    modulus = int.from_bytes(modulus_bytes, 'big')
    _require(bits == 2048 and exponent == 65537 and len(modulus_bytes) == 256
             and modulus.bit_length() == bits and modulus & 1,
             'FIT RSA-PSS public key is invalid')
    value = signature.get('value', b'')
    _require(len(value) == (bits + 7) // 8, 'FIT RSA-PSS signature has an invalid size')
    representative = int.from_bytes(value, 'big')
    _require(representative < modulus, 'FIT RSA-PSS signature is outside the RSA modulus')
    encoded_size = (bits - 1 + 7) // 8
    encoded = pow(representative, exponent, modulus).to_bytes(encoded_size, 'big')
    salt_size = _assert_maximum_pss_encoding(encoded, bits)
    return {'algorithm': 'sha256,rsa2048', 'padding': 'pss',
            'pss_salt_length': 'maximum', 'pss_salt_bytes': salt_size}


def elf_load_segments(path):
    """Extract nonempty AArch64 ELF64 little-endian PT_LOAD file bytes."""
    content = Path(path).read_bytes()
    _require(len(content) >= 64 and content[:6] == b'\x7fELF\x02\x01', 'BL31 must be little-endian ELF64')
    fields = struct.unpack_from('<16sHHIQQQIHHHHHH', content)
    _require(fields[2] == 183, 'BL31 is not an AArch64 ELF')
    offset, stride, count = fields[5], fields[9], fields[10]
    _require(stride >= 56 and offset + stride * count <= len(content), 'Invalid BL31 program-header table')
    segments = {}
    for index in range(count):
        kind, _, start, _, address, size, _, _ = struct.unpack_from('<IIQQQQQQ', content, offset + index * stride)
        if kind != 1 or not size:
            continue
        _require(start + size <= len(content) and address not in segments, 'Invalid BL31 load segment')
        segments[address] = content[start:start + size]
    _require(segments, 'BL31 contains no loadable data')
    return segments


def _gzip(source, destination, epoch):
    with source.open('rb') as stream, destination.open('wb') as target:
        with gzip.GzipFile(fileobj=target, mode='wb', compresslevel=9, filename='', mtime=epoch) as compressed:
            shutil.copyfileobj(stream, compressed)


def _compressed(source, epoch):
    target = source.with_name(source.name + '.gz')
    _gzip(source, target, epoch)
    source.with_name(source.name + '.digest').write_bytes(bytes.fromhex(_sha(source)))
    return target


def _unsigned_its(text):
    """Remove only signature nodes from the SDK's simple generated ITS."""
    pattern = re.compile(r'\bsignature\s*\{[^{}]*\}\s*;', re.DOTALL)
    result = pattern.sub('', text)
    _require('signature' not in result, 'Unsupported nested signature node in unsigned ITS')
    return result


def _os_its(paths, layout, signed):
    loads = layout['fit']
    images, configuration, expected = [], [], {}
    for role, setting, image_type in (('kernel', 'kernel_load', 'kernel'),
                                      ('fdt', 'fdt_load', 'flat_dt'),
                                      ('ramdisk', 'ramdisk_load', 'ramdisk'),
                                      ('resource', None, 'multi')):
        if role not in paths:
            continue
        extra = ''
        if setting:
            value = loads[setting]
            value = int(value, 0) if isinstance(value, str) else value
            _require(type(value) is int and 0 < value <= 0xffffffff, 'Invalid OS FIT load address')
            extra += 'load = <0x%x>;' % value
            if role != 'fdt':
                extra += ' os = "linux";'
            if role == 'kernel':
                extra += ' entry = <0x%x>;' % value
        name = paths[role].relative_to(paths['work']).as_posix()
        images.append('%s { data = /incbin/("%s"); type = "%s"; arch = "arm64"; compression = "none"; %s hash { algo = "sha256"; }; };'
                      % (role, name, image_type, extra))
        configuration.append('%s = "%s";' % ('multi' if role == 'resource' else role, role))
        expected[role] = paths[role]
    signature = ''
    if signed:
        labels = ['kernel', 'fdt', 'ramdisk'] + (['multi'] if 'resource' in expected else [])
        signature = 'signature { algo = "sha256,rsa2048"; padding = "pss"; key-name-hint = "dev"; sign-images = %s; };' % ', '.join('"' + role + '"' for role in labels)
    text = '/dts-v1/; / { description = "NAOS OS FIT"; #address-cells = <1>; images { %s }; configurations { default = "conf"; conf { %s %s }; }; };\n' % ('\n'.join(images), '\n'.join(configuration), signature)
    return text, expected


def _stage_signing(signing, work):
    directory = work / 'keys'
    directory.mkdir(mode=0o700)
    for name, suffix in (('key', 'key'), ('certificate', 'crt'), ('public_key', 'pubkey')):
        _require(name in signing, 'Secure boot requires key, certificate and public_key paths')
        source = Path(signing[name]).resolve(strict=True)
        _require(source.is_file() and source.stat().st_size, 'Signing material must be an ordinary nonempty file')
        # Only the explicitly selected signer reads private key bytes.
        (directory / ('dev.' + suffix)).symlink_to(source)
    return directory


def _pad(source, destination, size):
    _require(0 < source.stat().st_size <= size, 'Bootloader payload exceeds its single-copy capacity')
    with source.open('rb') as stream, destination.open('wb') as target:
        shutil.copyfileobj(stream, target)
        target.truncate(size)


def _loader_configuration(text, artifacts):
    ini = configparser.ConfigParser(interpolation=None, strict=True)
    ini.optionxform = str
    try:
        ini.read_string(text)
        ddr = next(record['path'].removeprefix('rkbin/') for record in artifacts if record['role'] == 'ddr')
        usb = next(record['path'].removeprefix('rkbin/') for record in artifacts if record['role'] == 'usbplug')
        _require(ini.get('CHIP_NAME', 'NAME') == 'RK3588'
                 and ini.getint('CODE471_OPTION', 'NUM') == 1
                 and ini.getint('CODE472_OPTION', 'NUM') == 1
                 and ini.getint('LOADER_OPTION', 'NUM') == 2
                 and ini.get('CODE471_OPTION', 'Path1') == ddr
                 and ini.get('CODE472_OPTION', 'Path1') == usb
                 and ini.get('LOADER_OPTION', 'FlashData') == ddr
                 and ini.get('LOADER_OPTION', 'FlashBoot') == '@SPL_BINARY@'
                 and {ini.get('LOADER_OPTION', 'LOADER1'), ini.get('LOADER_OPTION', 'LOADER2')}
                     == {'FlashData', 'FlashBoot'}, 'Loader INI does not match the selected firmware')
        allowed = {'CHIP_NAME', 'VERSION', 'CODE471_OPTION', 'CODE472_OPTION', 'LOADER_OPTION',
                   'OUTPUT', 'SYSTEM', 'FLAG', 'BOOT1_PARAM'}
        _require(set(ini.sections()) <= allowed, 'Unsupported additional loader INI section')
        for section in ini.sections():
            for key in ini[section]:
                if 'PATH' in key.upper():
                    _require((section, key) in {('CODE471_OPTION', 'Path1'), ('CODE472_OPTION', 'Path1'), ('OUTPUT', 'PATH')},
                             'Unsupported loader file reference')
        name = ini.get('OUTPUT', 'PATH')
    except (configparser.Error, ValueError, StopIteration):
        raise BuildError('Invalid loader INI template') from None
    _require(Path(name).name == name and name.endswith('.bin') and '\\' not in name,
             'Unsafe loader output filename')
    return name


def build_bootloader(bundle_dir: Path, work: Path, output: Path, metadata: dict,
                     tools: dict, signing: dict | None, os_inputs: dict, epoch: int,
                     burn_key_hash: bool = False) -> dict:
    """Build OS FIT, U-Boot FIT, USB MiniLoader and raw IDBlock without flashing."""
    bundle_dir, work, output = Path(bundle_dir), Path(work), Path(output)
    source = bundle_dir / 'bootloader'
    _require(metadata.get('schema_version') == 1 and metadata.get('machine') == 'mixtile-core3588e-v2',
             'Unsupported bootloader export format or machine')
    _require(metadata.get('stage') == 'compiled-before-key-injection', 'Bootloader export is not a clean signing input')
    _require(type(epoch) is int and 0 <= epoch <= 0xffffffff, 'Invalid boot firmware epoch')
    signed = signing is not None
    capabilities = metadata['capabilities']
    if signed:
        _require(capabilities.get('fit_signature') and capabilities.get('spl_fit_signature'),
                 'The selected export was not compiled for secure boot')
        signature = metadata.get('signature', {})
        _require(signature.get('algorithm') == 'sha256,rsa2048'
                 and signature.get('padding') == 'pss'
                 and signature.get('pss_salt_length') == 'maximum',
                 'Secure boot export must require RSA-2048/SHA256 PSS with maximum salt')
    _require(not burn_key_hash or (signed and capabilities.get('otp_key_hash_programming')),
             'OTP programming requires a signed, OTP-capable SPL export')
    packing = metadata['packing']
    _require(packing.get('spl_separate_bss') and not packing.get('spl_padding_required')
             and not packing.get('tpl_required'), 'Unsupported SPL/TPL padding layout')
    bwork = work / 'bootloader'
    bwork.mkdir(parents=True, exist_ok=True, mode=0o700)
    _require(not any(bwork.iterdir()), 'Bootloader work directory must be empty')
    output.mkdir(parents=True, exist_ok=True)
    env = {'SOURCE_DATE_EPOCH': str(epoch)}
    artifacts = metadata['artifacts']
    by_role = {}
    for record in artifacts:
        path = _inside(source, record['path'])
        _require(path.stat().st_size == record['size'] and _sha(path) == record['sha256'],
                 'Bootloader input differs from its export metadata: ' + record['path'])
        _require(record['role'] not in by_role, 'Duplicate bootloader input role')
        by_role[record['role']] = path
    for role in ('uboot_nodtb', 'spl_nodtb', 'uboot_control_dtb', 'spl_control_dtb',
                 'ddr', 'usbplug', 'bl31', 'bl32', 'loader_config', 'uboot_fit_template'):
        _require(role in by_role, 'Missing bootloader role: ' + role)
    for role in ('uboot_control_dtb', 'spl_control_dtb'):
        _clean_dtb(by_role[role])
    (bwork / 'spl').mkdir()
    shutil.copyfile(by_role['uboot_nodtb'], bwork / 'u-boot-nodtb.bin')
    shutil.copyfile(by_role['spl_nodtb'], bwork / 'spl/u-boot-spl-nodtb.bin')
    shutil.copyfile(by_role['uboot_control_dtb'], bwork / 'u-boot.dtb')
    shutil.copyfile(by_role['spl_control_dtb'], bwork / 'spl/u-boot-spl.dtb')
    for record in artifacts:
        if record['role'] in ('ddr', 'usbplug', 'bl31', 'bl32'):
            target = bwork / record['path']
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(by_role[record['role']], target)
    segments = elf_load_segments(by_role['bl31'])
    expected_segments = packing['bl31_segments']
    _require(set(segments) == {record['address'] for record in expected_segments}, 'BL31 segment selection differs from the export')
    for record in expected_segments:
        data = segments[record['address']]
        name = record['prepared_path']
        _require(name == 'bl31_0x%08x.bin' % record['address'] and len(data) == record['size']
                 and hashlib.sha256(data).hexdigest() == record['sha256'], 'BL31 load segment differs from its build evidence')
        path = bwork / name
        path.write_bytes(data)
        if record['compression'] == 'gzip':
            _compressed(path, epoch)
        else:
            _require(record['compression'] == 'none', 'Unsupported BL31 compression')
    shutil.copyfile(by_role['bl32'], bwork / 'tee.bin')
    _require(packing['uboot_compression'] == packing['bl32_compression'] == 'gzip', 'Unsupported boot firmware compression')
    _compressed(bwork / 'u-boot-nodtb.bin', epoch)
    _compressed(bwork / 'tee.bin', epoch)

    os_dir = bwork / 'os'
    os_dir.mkdir()
    paths = {'work': bwork}
    for role, name in (('kernel', 'Image'), ('fdt', 'kernel.dtb'), ('ramdisk', 'initramfs.cpio.gz'), ('resource', 'resource.img')):
        original = os_inputs.get('dtb' if role == 'fdt' else role)
        if role == 'resource' and original is None:
            continue
        _require(original is not None and Path(original).is_file(), 'Missing finalized OS FIT input: ' + role)
        target = os_dir / name
        shutil.copyfile(original, target)
        paths[role] = target
    its, expected_os = _os_its(paths, os_inputs['layout'], signed)
    (bwork / 'boot.its').write_text(its)
    keys = _stage_signing(signing, bwork) if signed else None
    arguments = ['-f', 'boot.its']
    if signed:
        arguments += ['-k', 'keys', '-K', 'u-boot.dtb', '-r', '-E', '-p', '0x3000']
    arguments.append('boot.img')
    _invoke(tools, 'mkimage', arguments, bwork, env)
    os_nodes, os_payloads = _fit_hashes(bwork / 'boot.img', expected_os)
    identity = None
    os_signature, uboot_signature = None, None
    if signed:
        identity = _key_identity(bwork / 'u-boot.dtb')
        _assert_signature_coverage(os_nodes, expected_os)
        os_signature = _assert_pss_signature(os_nodes, identity)
        _invoke(tools, 'fit_check_sign', ['-f', 'boot.img', '-k', 'u-boot.dtb', '-c', 'conf'], bwork, env)

    uboot_its = by_role['uboot_fit_template'].read_text()
    if not signed:
        uboot_its = _unsigned_its(uboot_its)
    references = re.findall(r'/incbin/\(\s*"([^"\n]+)"\s*\)', uboot_its)
    _require(references, 'U-Boot ITS has no inputs')
    for name in references:
        _inside(bwork, name)
    (bwork / 'u-boot.its').write_text(uboot_its)
    arguments = ['-f', 'u-boot.its', '-E', '-p', hex(packing['fit_external_data_offset']), '-v', '0']
    if signed:
        arguments += ['-k', 'keys', '-K', 'spl/u-boot-spl.dtb', '-r']
    arguments.append('uboot.itb')
    _invoke(tools, 'mkimage', arguments, bwork, env)
    expected_uboot = {}
    # Match each image node to its relative /incbin/ source before signing.
    for match in re.finditer(r'([A-Za-z0-9_-]+)\s*\{\s*description\s*=.*?data\s*=\s*/incbin/\("([^"]+)"\)', uboot_its, re.DOTALL):
        expected_uboot[match.group(1)] = _inside(bwork, match.group(2))
    _require({'uboot', 'atf-1', 'atf-2', 'atf-3', 'optee', 'fdt'} == set(expected_uboot),
             'Unsupported U-Boot FIT image selection')
    uboot_nodes, uboot_payloads = _fit_hashes(bwork / 'uboot.itb', expected_uboot)
    if signed:
        _require(_key_identity(bwork / 'spl/u-boot-spl.dtb') == identity, 'SPL and U-Boot verification keys differ')
        _assert_signature_coverage(uboot_nodes, expected_uboot)
        uboot_signature = _assert_pss_signature(uboot_nodes, identity)
        _invoke(tools, 'fit_check_sign', ['-f', 'uboot.itb', '-k', 'spl/u-boot-spl.dtb', '-s'], bwork, env)
        if burn_key_hash:
            _invoke(tools, 'fdtput', ['-t', 'x', 'spl/u-boot-spl.dtb', KEY_NODE, 'burn-key-hash', '1'], bwork, env)
        if capabilities.get('spl_fit_hardware_crypto'):
            # RK3588 uses hardware RSA v2: keep np, clear unused c/r-squared.
            _invoke(tools, 'fdtput', ['-t', 'x', 'spl/u-boot-spl.dtb', KEY_NODE, 'rsa,r-squared', '0'], bwork, env)
            _invoke(tools, 'fdtput', ['-t', 'x', 'spl/u-boot-spl.dtb', KEY_NODE, 'rsa,c', '0'], bwork, env)
            _invoke(tools, 'fdtput', ['-r', 'spl/u-boot-spl.dtb', KEY_NODE + '/hash@c'], bwork, env)
    final_nodes, _, _ = read_fdt(bwork / 'spl/u-boot-spl.dtb')
    burn = final_nodes.get(KEY_NODE, {}).get('burn-key-hash')
    _require((burn == struct.pack('>I', 1)) if burn_key_hash else burn is None,
             'SPL OTP programming flag differs from the requested setting')
    spl = bwork / 'spl/u-boot-spl.bin'
    spl.write_bytes((bwork / 'spl/u-boot-spl-nodtb.bin').read_bytes() + (bwork / 'spl/u-boot-spl.dtb').read_bytes())
    _require(spl.stat().st_size <= packing['spl_max_size'], 'Repacked SPL exceeds its compiled size limit')
    rkbin = bwork / 'rkbin'
    (rkbin / 'tmp').mkdir()
    shutil.copyfile(spl, rkbin / 'tmp/u-boot-spl.bin')
    loader_text = by_role['loader_config'].read_text()
    _require(loader_text.count('@SPL_BINARY@') == 1, 'Loader template must have one SPL placeholder')
    loader_name = _loader_configuration(loader_text, artifacts)
    loader_text = loader_text.replace('@SPL_BINARY@', 'tmp/u-boot-spl.bin')
    loader_ini = rkbin / 'MINIALL.ini'
    loader_ini.write_text(loader_text)
    _invoke(tools, 'boot_merger', ['MINIALL.ini'], rkbin, env)
    loader = rkbin / loader_name
    _require(loader.is_file() and loader.stat().st_size, 'Rockchip boot_merger did not create a USB loader')
    shutil.copyfile(loader, bwork / 'MiniLoaderAll.bin')
    ddr_record = next(record for record in artifacts if record['role'] == 'ddr')
    _invoke(tools, 'mkimage', ['-n', 'rk3588', '-T', 'rksd', '-d', ddr_record['path'] + ':spl/u-boot-spl.bin', 'idblock.bin'], bwork, env)
    if signed:
        signer_tools = _private_signer(tools, bwork)
        for arguments in (['cc', '--chip', '3588'],
                          ['lk', '--key', 'keys/dev.key', '--pubkey', 'keys/dev.pubkey'],
                          ['sl', '--loader', 'MiniLoaderAll.bin'], ['vl', '--loader', 'MiniLoaderAll.bin'],
                          ['sb', '--idb', 'idblock.bin'], ['vb', '--idb', 'idblock.bin']):
            try:
                _invoke(signer_tools, 'rk_sign_tool', arguments, bwork, env)
            finally:
                (Path(signer_tools['rk_sign_tool']).parent / 'setting.ini').chmod(0o600)
    _pad(bwork / 'uboot.itb', bwork / 'uboot-slot.img', packing['uboot_fit_copy_size'])
    with (bwork / 'uboot.img').open('wb') as target:
        for _ in range(packing['uboot_fit_copies']):
            with (bwork / 'uboot-slot.img').open('rb') as stream:
                shutil.copyfileobj(stream, target)
    _pad(bwork / 'idblock.bin', bwork / 'idblock-slot.img', packing['idblock_copy_stride'])
    files = {}
    for name in ('boot.img', 'uboot.img', 'idblock.bin', 'MiniLoaderAll.bin', 'uboot-slot.img', 'idblock-slot.img'):
        target = output / name
        shutil.copyfile(bwork / name, target)
        files[name] = _record(target)
    os_verification = {'schema_version': 1, 'signed': signed, 'payloads': os_payloads,
                       'fit_sha256': files['boot.img']['sha256'], 'hardware_tested': False}
    if identity:
        os_verification['public_key'] = {'bits': identity[0], 'exponent': identity[1],
                                         'rsa_modulus_sha256': hashlib.sha256(identity[2]).hexdigest()}
        os_verification['signature'] = os_signature
    loader_verification = {'schema_version': 1, 'signed': signed, 'machine': metadata['machine'],
        'profile': metadata['profile'], 'source_revisions': metadata['source_revisions'],
        'otp_burn_key_hash': burn_key_hash, 'host_programmed_otp': False,
        'uboot_payloads': uboot_payloads, 'artifacts': files.copy(), 'hardware_tested': False}
    if signed:
        loader_verification['uboot_signature'] = uboot_signature
    for name, value in (('boot-verification.json', os_verification), ('bootloader-verification.json', loader_verification)):
        (output / name).write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')
        files[name] = _record(output / name)
    return {'artifacts': files, 'os_fit': os_verification, 'bootloader': loader_verification}


def publish_efuse_artifacts(source: Path, output: Path, verification: dict, *, separate: bool) -> dict:
    """Publish explicitly named OTP-programming files without touching hardware."""
    source, output = Path(source), Path(output)
    _require(verification.get('signed') is True and verification.get('otp_burn_key_hash') is True,
             'eFuse artifacts require a verified signed SPL with OTP programming enabled')
    _require(verification.get('host_programmed_otp') is False,
             'Unexpected host OTP programming metadata')
    output.mkdir(parents=True, exist_ok=True)
    artifacts = {}
    for original, name in (('MiniLoaderAll.bin', 'loader-efuse.bin'), ('idblock.bin', 'idblock-efuse.bin')):
        src, target = source / original, output / name
        _require(src.is_file() and not src.is_symlink(), 'Missing verified eFuse artifact: ' + original)
        shutil.copyfile(src, target)
        artifacts[name] = _record(target)
    mode = 'separate-loader' if separate else 'embedded-image'
    report = dict(schema_version=1, mode=mode, signed=True, otp_burn_key_hash=True,
        normal_image_programs_otp=not separate, host_programmed_otp=False, hardware_tested=False,
        machine=verification['machine'], source_revisions=verification['source_revisions'],
        artifacts=artifacts)
    (output / 'efuse-verification.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    description = (
        'The normal firmware and update bundles do not request OTP programming.\n'
        'The two eFuse files are separate provisioning artifacts.\n'
        if separate else
        'The firmware and bootloader update bundle contain an OTP-programming SPL.\n'
        'Booting these artifacts can permanently enable secure boot.\n')
    (output / 'EFUSE-INSTRUCTIONS.txt').write_text(
        'WARNING: PERMANENT SECURE BOOT PROVISIONING\n\n'
        'RK3588 stores the secure boot public-key hash in OTP. Programming this\n'
        'information is irreversible. Use the intended signing key, retain its\n'
        'private key securely, and keep device power stable throughout provisioning.\n'
        'Future boot firmware must be signed by the matching trusted key.\n\n'
        + description + '\n'
        'loader-efuse.bin is a signed Rockchip MiniLoader container with DDR, SPL and\n'
        'USB download code. It is not a bare SPL binary. idblock-efuse.bin is the\n'
        'signed bootable IDBlock containing the OTP-programming SPL.\n\n'
        'Provide a matching signed U-Boot image on the device. OTP programming\n'
        'requires the programming SPL to actually boot and verify that U-Boot FIT.\n'
        'USB Download Boot alone is not proof that OTP was programmed. Check the\n'
        'serial output for successful RSA key-hash and secure-flag writes, then\n'
        'restart and verify that the intended signed firmware boots normally.\n'
        + ('After separate provisioning succeeds, restore the normal non-programming\n'
           'IDBlock/loader from the matching firmware before normal operation.\n' if separate else '')
        + '\nThe generator only creates files. No device OTP has been programmed by\n'
          'running this host command.\n')
    return report
