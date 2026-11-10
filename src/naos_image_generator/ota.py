# SPDX-License-Identifier: MIT
"""Create separate signed OS and bootloader RAUC bundles."""
import configparser
from pathlib import Path
import re
import shutil

from .common import BuildError, require, run, sha256


def _verify_extracted(directory, metadata, images, expected, bundle_format):
    """Validate content authenticated by RAUC's signature and verity checks."""
    manifest_file = directory / 'manifest.raucm'
    require(manifest_file.is_file() and not manifest_file.is_symlink()
            and manifest_file.stat().st_size <= 1024*1024,
            'Verified OTA content lacks an ordinary manifest')
    manifest = configparser.ConfigParser(interpolation=None)
    manifest.optionxform = str
    try:
        manifest.read_string(manifest_file.read_text(encoding='utf-8'))
    except (OSError, UnicodeError, configparser.Error) as error:
        raise BuildError('Cannot read the verified OTA manifest') from error
    require(manifest.has_section('update') and manifest.has_section('bundle'),
            'Verified OTA manifest lacks update or bundle metadata')
    for name, value in (('compatible', metadata['compatible']), ('version', metadata['version']),
                        ('build', metadata['build_id'])):
        require(manifest['update'].get(name) == value,
                'Verified OTA manifest differs from the requested ' + name)
    require(manifest['bundle'].get('format') == bundle_format,
            'Verified OTA bundle has an unexpected format')
    order = [name[6:] for name in manifest.sections() if name.startswith('image.')]
    require(order == [slot for slot, _ in images],
            'OTA bundle has unexpected images or installation order')
    require(set(manifest.sections()) == {'update', 'bundle'} | {'image.'+slot for slot,_ in images},
            'Verified OTA manifest contains unexpected sections')
    filenames = {'manifest.raucm'} | {filename for _, filename in images}
    require({item.name for item in directory.iterdir()} == filenames,
            'Verified OTA bundle contains unexpected files')
    verified_images = []
    for slot, filename in images:
        section = manifest['image.'+slot]
        require(section.get('filename') == filename and section.get('type') == 'raw',
                'Verified OTA image differs from the requested raw payload')
        digest, size = section.get('sha256', ''), section.get('size', '')
        require(re.fullmatch(r'[0-9a-f]{64}', digest) and re.fullmatch(r'[0-9]+', size),
                'Verified OTA manifest lacks an image SHA256 or size')
        payload = directory / filename
        require(payload.is_file() and not payload.is_symlink(),
                'Verified OTA image must be an ordinary file')
        actual = {'sha256': sha256(payload), 'size': payload.stat().st_size}
        require(actual == {'sha256': digest, 'size': int(size)} == expected[slot],
                'Verified OTA payload hash or size differs from its source')
        verified_images.append({slot:dict(filename=filename, type='raw', **actual)})
    return {'compatible': metadata['compatible'], 'version': metadata['version'],
            'build': metadata['build_id'], 'bundle_format': bundle_format,
            'signature_verified': True, 'payload_verified': True,
            'manifest_sha256': sha256(manifest_file), 'images': verified_images,
            'installation_order': order}


def build_bundles(output, work, metadata, contract, tools, signing, system_file, processors=4,trust_certificate=None):
    output, work = Path(output), Path(work)
    require(signing and signing.get('key') and signing.get('certificate'), 'OTA generation requires an OTA signing key and certificate')
    trust = Path(trust_certificate or signing['certificate'])
    require(trust.is_file(), 'OTA verification requires the device trust certificate')
    bundle_format = contract.get('bundle_format','verity')
    require(bundle_format == 'verity', 'OTA generation requires the verity bundle format')
    result = {}
    definitions = (
        ('naos-bundle', [('rootfs',Path(system_file).name),('boot','boot.img')]),
        ('naos-bootloader-bundle', [('uboot','uboot-slot.img'),('idb','idblock-slot.img')]),
    )
    for prefix,images in definitions:
        directory = work / prefix
        directory.mkdir(parents=True)
        manifest = configparser.ConfigParser(interpolation=None)
        manifest.optionxform = str
        manifest['update'] = {'compatible':metadata['compatible'],'version':metadata['version'],
            'build':metadata['build_id'], 'description':'NAOS bootloader update' if 'bootloader' in prefix else 'NAOS system update'}
        manifest['bundle'] = {'format':bundle_format}
        expected = {}
        for slot,filename in images:
            source = output / filename
            require(source.is_file(), 'Missing OTA payload: ' + filename)
            if slot in ('uboot','idb'):
                expected_size = 2*1024*1024 if slot=='uboot' else 512*1024
                require(source.stat().st_size == expected_size, 'Bootloader OTA payload must contain exactly one copy')
            shutil.copyfile(source,directory/filename)
            expected[slot] = {'sha256':sha256(source), 'size':source.stat().st_size}
            manifest['image.'+slot] = {'filename':filename,'type':'raw'}
        with (directory/'manifest.raucm').open('w') as stream:
            manifest.write(stream)
        filename = f"{prefix}-{metadata.get('board',metadata['machine'])}-{metadata['version']}.raucb"
        target = output / filename
        args = [tools['rauc'], '--cert='+str(signing['certificate']), '--key='+str(signing['key']),
            '--signing-keyring='+str(trust),
            '--mksquashfs-args=-comp zstd -processors '+str(processors), 'bundle', directory, target]
        run(args,env={'SOURCE_DATE_EPOCH':str(metadata['epoch'])})
        extracted = work / (prefix+'-verified')
        # RAUC extract verifies the CMS signature and the complete verity
        # payload before extraction. Its native build need not support JSON.
        run([tools['rauc'],'--keyring='+str(trust),'extract',target,extracted])
        decoded = _verify_extracted(extracted,metadata,images,expected,bundle_format)
        decoded['trust_certificate_sha256'] = sha256(trust)
        decoded['switch_system_slot'] = prefix == 'naos-bundle'
        result[filename] = decoded
    return result
