# SPDX-License-Identifier: MIT
"""Orchestrate the standalone generator without compiling target code."""
from contextlib import ExitStack
import hashlib
import logging
import os
from pathlib import Path
import shutil
import tempfile
import uuid

from . import __version__
from .common import BuildError,input_file,read_json,record,require,run,safe_relative,set_tool_environment,write_json
from .config import path
from .inputs import Bundle,label
from .storage import MIB,assemble_factory,make_misc,resolve_layout

LOG = logging.getLogger(__name__)


def _file(value,base,description,private=False):
    result = path(value,base)
    require(result.is_file(), 'Missing ' + description)
    return result


def _signing(value,base,description):
    require(isinstance(value,dict) and not (set(value)-{'key','certificate','public_key'}), 'Invalid ' + description + ' configuration')
    require('key' in value and 'certificate' in value, description + ' requires key and certificate paths')
    result = {'key':_file(value['key'],base,description+' private key',True),
              'certificate':_file(value['certificate'],base,description+' certificate')}
    if value.get('public_key'):
        result['public_key'] = _file(value['public_key'],base,description+' public key')
    return result


def _matching_certificate(signing,openssl):
    public = run([openssl,'pkey','-in',signing['key'],'-pubout']).strip()
    certificate = run([openssl,'x509','-in',signing['certificate'],'-pubkey','-noout']).strip()
    require(public == certificate, 'Signing certificate does not match its private key')


def settings(bundle,config,base,overrides=None):
    overrides = {k:v for k,v in (overrides or {}).items() if v is not None}
    def get(name,default=None):
        return overrides.get(name,config.get(name,default))
    data = bundle.manifest
    defaults = data['defaults']
    options = dict(machine=bundle.machine,profile=bundle.profile,
        version=label(get('version',data['version']),'firmware version'),
        build_id=label(get('build_id',data['build_id']),'build ID'),
        compatible=bundle.layout['compatible'],
        epoch=int(get('epoch',os.environ.get('SOURCE_DATE_EPOCH',data['source_date_epoch']))),
        generator_version=__version__,
        secure_boot=defaults['secure_boot'],system_encryption=defaults['system_encryption'],data_encryption=defaults['data_encryption'],
        ota=get('ota',defaults['ota']),ota_only=get('ota_only',False),sbom=get('sbom',defaults['sbom']),
        burn_key_hash=get('burn_key_hash',False),efuse_loader=get('efuse_loader',False),processors=get('processors',4))
    for name in ('ota','ota_only','sbom','burn_key_hash','efuse_loader'):
        require(type(options[name]) is bool, name + ' must be true or false')
    if options['ota_only']:
        require(overrides.get('ota') is not False, '--ota-only cannot be combined with --no-ota')
        options['ota'] = True
    require(type(options['processors']) is int and options['processors']>0, 'Processor count must be positive')
    require(0<=options['epoch']<=0xffffffff,'Invalid reproducible build epoch')
    require(not options['sbom'] or defaults['sbom'], 'The export has no SBOM evidence; rebuild it with NAOS_SBOM=1')
    _validate_efuse_mode(bundle,options)
    require(isinstance(config.get('partitions',{}),dict), 'partitions must be a mapping')
    require(isinstance(config.get('tools',{}),dict), 'tools must be a mapping')
    partitions = dict(config.get('partitions',{}))
    for key in ('boot_mib','system_mib'):
        if key in overrides:
            partitions[key] = overrides[key]
    layout_file = get('layout')
    custom_layout = read_json(path(layout_file,base)) if layout_file else None
    options['layout'] = resolve_layout(bundle.layout,partitions,custom_layout)
    require(all(part.get('payload') == compiled.get('payload')
                for part,compiled in zip(options['layout']['partitions'],bundle.layout['partitions'])),
            'Partition payload roles differ from the compiled export')
    options['overlays'] = [path(v,base) for v in config.get('overlays',[])]
    options['apks_dir'] = path(config['apks_dir'],base) if config.get('apks_dir') else None
    options['dtb'] = path(get('dtb'),base) if get('dtb') else None
    options['board_name'] = label(options['dtb'].stem,'board name') if options['dtb'] else None
    require(options['board_name'] not in {'boot','uboot','misc','system','uboot-slot','idblock-slot'},
            'Device-tree name conflicts with a firmware payload filename')
    options['remove'] = config.get('remove',[])
    options['additional_sbom'] = [path(v,base) for v in config.get('additional_sbom',[])]
    options['toolset'] = path(get('tools_dir'),base) if get('tools_dir') else None
    options['tool_overrides'] = {k:path(v,base) for k,v in config.get('tools',{}).items()}
    keys = config.get('keys',{})
    require(isinstance(keys,dict) and not(set(keys)-{'secure_boot','system','ota'}),'Unknown key configuration')
    options['signing'] = _signing(keys.get('secure_boot'),base,'Secure boot') if options['secure_boot'] else None
    options['ota_signing'] = _signing(keys.get('ota'),base,'OTA') if options['ota'] else None
    options['system_key_file'] = _file(keys.get('system'),base,'System encryption key',True) if options['system_encryption'] else None
    options['ota_certificate'] = _file(config['ota_certificate'],base,'OTA trust certificate') if config.get('ota_certificate') else None
    if options['ota_signing'] and options['ota_certificate'] is None:
        options['ota_certificate'] = options['ota_signing']['certificate']
    options['ssh_ca'] = _file(config['ssh_ca'],base,'SSH CA public key') if config.get('ssh_ca') else None
    return options


def _validate_efuse_mode(bundle,options):
    burn, separate = options.get('burn_key_hash',False), options.get('efuse_loader',False)
    require(type(burn) is bool and type(separate) is bool, 'OTP programming options must be true or false')
    require(not (burn and separate), 'Choose either a separate eFuse loader or an OTP-programming image')
    require(not (burn or separate) or (bundle.profile == 'production' and options['secure_boot']
            and bundle.bootloader.get('capabilities',{}).get('otp_key_hash_programming')),
            'OTP programming requires a signed production SPL with OTP support')


def validate_inputs(options):
    from .local_apks import discover
    _system_key(options['system_key_file'])
    discover(options.get('apks_dir'))
    if options.get('dtb'):
        from .bootloader import read_fdt
        require(Path(options['dtb']).is_file(), 'Selected device tree does not exist')
        read_fdt(options['dtb'])
    for directory in options['overlays']:
        require(Path(directory).is_dir(), 'Rootfs overlay directory does not exist: '+str(directory))
    for name in options['remove']:
        safe_relative(name)
    for filename in options['additional_sbom']:
        require(isinstance(read_json(filename),dict), 'Additional SBOM component must be a JSON object')


def prepare_tools(options):
    from .local_apks import discover
    from .tools import resolve_tools,tool_environment
    validate_inputs(options)
    required = {'mkimage','boot_merger','sqfstar','dtc'}
    if discover(options.get('apks_dir')):
        required.add('apk')
    if options['secure_boot']:
        required |= {'fit_check_sign','rk_sign_tool','fdtput','openssl'}
    if options['ota']:
        required |= {'rauc','mksquashfs','unsquashfs','openssl'}
    if options['ota_certificate']:
        required.add('openssl')
    toolset = options['toolset']
    if toolset is None:
        for candidate in (Path.cwd()/'.tools',Path(__file__).resolve().parents[2]/'.tools'):
            if candidate.is_dir():
                toolset = candidate
                break
    tools = resolve_tools(options['tool_overrides'],required,toolset)
    set_tool_environment(tool_environment(toolset))
    if discover(options.get('apks_dir')):
        from .apk_runtime import resolve_runtime,preflight
        tools['apk_runtime'] = resolve_runtime(toolset,overrides=options['tool_overrides'])
        preflight(tools['apk_runtime'])
    for signing in (options['signing'],options['ota_signing']):
        if signing:
            _matching_certificate(signing,tools['openssl'])
    return tools


def _system_key(filename):
    import re
    if filename is None:
        return None
    require(not Path(filename).is_symlink(), 'System key must be an ordinary file')
    data = Path(filename).read_bytes()
    require(re.fullmatch(rb'[0-9a-f]{64}',data) is not None, 'System key must contain exactly 64 lowercase hexadecimal ASCII bytes without newline')
    return data


def build(bundle,options,tools,destination,force=False):
    from .bootloader import build_bootloader,publish_efuse_artifacts
    from .filesystems import prepare_rootfs,prepare_initramfs,make_squashfs,encrypt_system,make_import_record
    from .ota import build_bundles
    ota_only = options.get('ota_only',False)
    require(not ota_only or options['ota'], 'OTA-only generation requires OTA bundles')
    _validate_efuse_mode(bundle,options)
    destination = Path(destination).resolve()
    require(not destination.is_relative_to(bundle.root) and not bundle.root.is_relative_to(destination),
            'Output and input directories must be separate')
    if destination.exists():
        require(destination.is_dir(), 'Output must be a directory')
        if any(destination.iterdir()):
            prior = read_json(destination/'manifest.json') if force and (destination/'manifest.json').is_file() else {}
            require(force and prior.get('generator') == 'naos-image-generator' and prior.get('schema_version') == 1,
                    'Output already exists; --force only replaces an earlier generator output')
    destination.parent.mkdir(parents=True,exist_ok=True)
    metadata = {k:options[k] for k in ('machine','profile','version','build_id','compatible','epoch','generator_version',
                                     'secure_boot','system_encryption','data_encryption')}
    metadata['layout_compatible'] = metadata['compatible']
    if options.get('board_name'):
        metadata['board'] = options['board_name']
    with ExitStack() as stack:
        stage = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix='.naos-images-',dir=destination.parent)))
        work = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix='.naos-work-',dir=destination.parent)))
        payload_dir = work/'payloads' if ota_only else stage
        if ota_only:
            payload_dir.mkdir()
        selected_dtb,selected_resource,device_tree = None,None,None
        if options.get('dtb'):
            from .boards import prepare
            LOG.info('Replacing kernel and resource device trees for %s',options['board_name'])
            selected_dtb,selected_resource,device_tree = prepare(bundle.root,bundle.machine,options['dtb'],work)
        key_hex = _system_key(options['system_key_file'])
        signing = options['signing']
        if signing and 'public_key' not in signing:
            signing = dict(signing)
            signing['public_key'] = work/'dev.pubkey'
            run([tools['openssl'],'rsa','-in',signing['key'],'-RSAPublicKey_out','-out',signing['public_key']])
        LOG.info('Preparing rootfs and ramdisk')
        from .local_apks import discover, install
        local_packages = discover(options.get('apks_dir'))
        installed_rootfs, local_records, local_sboms = None, [], []
        if local_packages:
            installed_rootfs, local_records, local_sboms = install(bundle.file('rootfs.tar.gz'), local_packages, work,
                apk=tools['apk'], runtime=tools['apk_runtime'], epoch=options['epoch'])
        # Runtime identity follows the selected board; the input BSP identity
        # still governs bootloader files, update compatibility and SBOM evidence.
        rootfs_metadata = dict(metadata,machine=metadata.get('board',metadata['machine']))
        rootfs,root_inventory = prepare_rootfs(bundle.root,work,overlays=options['overlays'],remove=options['remove'],
            ota_certificate=options['ota_certificate'],ssh_ca=options['ssh_ca'],metadata=rootfs_metadata,epoch=options['epoch'],
            source_archive=installed_rootfs,local_apks=local_records)
        if local_records:
            root_inventory['local_apks'] = local_records
            root_inventory['additional_sbom'] = local_sboms
        ramdisk = work/'initramfs.cpio.gz'
        ramdisk_inventory = prepare_initramfs(bundle.file('initramfs.cpio.gz'),ramdisk,key_hex=key_hex,epoch=options['epoch'])
        LOG.info('Creating system filesystem')
        squashfs = (work if key_hex else payload_dir)/'system.squashfs'
        make_squashfs(rootfs,squashfs,tools['sqfstar'],epoch=options['epoch'],processors=options['processors'])
        if key_hex:
            system = payload_dir/'system.img'
            encryption = encrypt_system(squashfs,system,key_hex)
            write_json(payload_dir/'system-encryption.json',encryption)
        else:
            system = squashfs
        LOG.info('Creating OS FIT and boot firmware')
        os_inputs = {'kernel':bundle.file('Image'),'dtb':selected_dtb or bundle.file(bundle.machine+'.dtb'),'ramdisk':ramdisk,
                     'resource':selected_resource or bundle.file('resource.img'),'layout':options['layout']}
        firmware = build_bootloader(bundle.root,work,payload_dir,bundle.bootloader,tools,signing,
                                    os_inputs,options['epoch'],options['burn_key_hash'])
        layout = options['layout']
        factory = None
        if not ota_only:
            LOG.info('Assembling GPT factory image')
            make_misc(layout,bundle.file('naos-uboot-env.bin'),stage/'misc.img',make_import_record(key_hex) if key_hex else None)
            suffix = '-efuse' if options['burn_key_hash'] else ''
            factory_name = options['board_name'] if options.get('board_name') else f"naos-{bundle.machine}-{bundle.profile}-{metadata['version']}"
            factory = stage/f"{factory_name}{suffix}.img"
            payloads = {p.name:p for p in stage.iterdir() if p.is_file()}
            assemble_factory(layout,payloads,factory)
            write_json(stage/'partition-layout.json',layout)
        ota_info = {}
        if options['ota']:
            LOG.info('Creating signed system and bootloader OTA bundles')
            ota_info = build_bundles(payload_dir,work,metadata,bundle.manifest['ota'],tools,options['ota_signing'],system,
                                     options['processors'],trust_certificate=options['ota_certificate'])
            if options['burn_key_hash']:
                for filename in list(ota_info):
                    if filename.startswith('naos-bootloader-bundle-'):
                        marked = filename.removesuffix('.raucb')+'-efuse.raucb'
                        (payload_dir/filename).rename(payload_dir/marked)
                        ota_info[marked] = ota_info.pop(filename)
            if ota_only:
                for filename in ota_info:
                    (payload_dir/filename).rename(stage/filename)
        if options.get('efuse_loader'):
            LOG.info('Creating separate OTP-programming loader; normal firmware remains non-programming')
            efuse_work = work/'efuse'
            efuse_output = efuse_work/'payloads'
            special = build_bootloader(bundle.root,efuse_work,efuse_output,bundle.bootloader,tools,signing,
                                       os_inputs,options['epoch'],True)
            publish_efuse_artifacts(efuse_output,stage,special['bootloader'],separate=True)
        elif options['burn_key_hash']:
            publish_efuse_artifacts(payload_dir,stage,firmware['bootloader'],separate=False)
            loader = payload_dir/'MiniLoaderAll.bin'
            loader.unlink()
            verification = payload_dir/'bootloader-verification.json'
            if verification.is_file():
                report = read_json(verification)
                report['artifacts'].pop('MiniLoaderAll.bin',None)
                report['artifacts']['loader-efuse.bin'] = dict(path='loader-efuse.bin',**record(stage/'loader-efuse.bin'))
                write_json(verification,report)
        artifacts = {p.name:record(p,'factory_image' if p==factory else 'firmware_artifact')
                     for p in stage.iterdir() if p.is_file()}
        sbom_summary = None
        if options['sbom']:
            from .sbom import render_sbom
            LOG.info('Rendering final SPDX SBOM')
            write_json(stage/'rootfs.inventory.json',root_inventory)
            write_json(stage/'initramfs.inventory.json',ramdisk_inventory)
            artifacts.update({name:record(stage/name,'filesystem_inventory') for name in
                              ('rootfs.inventory.json','initramfs.inventory.json')})
            additions = [read_json(p) for p in options['additional_sbom']]
            sbom_summary = render_sbom(bundle.root,stage,root_inventory,ramdisk_inventory,artifacts,metadata,
                                       additional_components=additions)
        manifest = dict(schema_version=1,generator='naos-image-generator',generator_version=__version__,**{k:metadata[k] for k in
            ('machine','profile','version','build_id','compatible','epoch','secure_boot','system_encryption','data_encryption')},
            input_export_sha256=hashlib.sha256((bundle.root/'export.json').read_bytes()).hexdigest(),
            burn_key_hash=options['burn_key_hash'],efuse_loader=options.get('efuse_loader',False),
            ota=bool(ota_info),ota_only=ota_only,sbom=sbom_summary,
            files={p.name:record(p) for p in sorted(stage.iterdir()) if p.is_file()})
        if device_tree is not None:
            manifest.update(board=options['board_name'],device_tree=device_tree)
        write_json(stage/'manifest.json',manifest)
        backup = destination.with_name('.'+destination.name+'-old-'+uuid.uuid4().hex)
        if destination.exists():
            destination.rename(backup)
        try:
            stage.rename(destination)
        except BaseException:
            if backup.exists():
                backup.rename(destination)
            raise
        if backup.exists():
            shutil.rmtree(backup)
    return manifest
