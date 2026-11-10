# SPDX-License-Identifier: MIT
"""Command line interface for inspecting exports and building images."""
import argparse
import copy
import json
import logging
import os
from pathlib import Path
import shutil
import sys

import yaml

from . import __version__
from . import interactive as wizard
from .common import BuildError, require
from .config import load, path
from .inputs import Bundle
from .pipeline import build, prepare_tools, settings
from .repository import DEFAULT_REPOSITORY, Repository
from .tools import import_toolset
from .startup import check_environment
from .bundled_tools import require_toolset


def parser():
    result = argparse.ArgumentParser(description='Build NAOS firmware from exported image inputs.')
    result.add_argument('--version', action='version', version=__version__)
    commands = result.add_subparsers(dest='command', required=True)
    inspect = commands.add_parser('inspect', help='Verify and describe exported inputs')
    inspect.add_argument('input', type=Path)
    for name, description in (('check', 'Validate input, configuration, keys and host tools'),
                              ('build', 'Create factory firmware and optional OTA bundles')):
        command = commands.add_parser(name, help=description)
        command.add_argument('input', nargs='?', type=Path, help='Export directory (overrides YAML input)')
        command.add_argument('-c', '--config', type=Path, help='YAML configuration; relative paths use its directory')
        command.add_argument('--image', help='APK image package, such as mixtile-core3588e-v2-alpine-dev')
        command.add_argument('--image-version', help='Image package version, such as 1.0.0')
        command.add_argument('--repository', help='APK repository base URL (default: '+DEFAULT_REPOSITORY+')')
        command.add_argument('--apk', type=Path, help='APK client executable (or use .tools/bin/apk or PATH)')
        command.add_argument('--apk-key', type=Path, help='Pinned APK repository public key')
        command.add_argument('--apks-dir', type=Path, help='Local application APKs to install offline (default: apks/)')
        command.add_argument('--dtb', type=Path, help='Replacement board device tree; its filename names the generated image')
        command.add_argument('--cache-dir', type=Path, help='Downloaded package and export cache directory')
        command.add_argument('--ota', action=argparse.BooleanOptionalAction, default=None, help='Create both OTA bundles')
        command.add_argument('--ota-only', action=argparse.BooleanOptionalAction, default=None,
                             help='Create only system and bootloader OTA bundles, without a full firmware image')
        command.add_argument('--sbom', action=argparse.BooleanOptionalAction, default=None, help='Create final SPDX SBOM')
        command.add_argument('--burn-key-hash', action=argparse.BooleanOptionalAction, default=None,
                             help='Enable OTP public-key hash programming in generated SPL (default: disabled)')
        command.add_argument('--efuse-loader', action=argparse.BooleanOptionalAction, default=None,
                             help='Create a separate loader-efuse.bin while keeping normal firmware OTP programming disabled')
        command.add_argument('--firmware-version', dest='version')
        command.add_argument('--build-id')
        command.add_argument('--epoch', type=int)
        command.add_argument('--processors', type=int)
        command.add_argument('--boot-mib', type=int, help='Size of each boot A/B partition')
        command.add_argument('--system-mib', type=int, help='Size of each system A/B partition')
        command.add_argument('--tools-dir', type=Path)
        if name == 'build':
            command.add_argument('-o', '--output', type=Path, help='New output directory (overrides YAML output)')
            command.add_argument('--force', action='store_true', help='Replace an earlier generator output directory')
    tools = commands.add_parser('tools', help='Manage the generator host toolset')
    actions = tools.add_subparsers(dest='action', required=True)
    importer = actions.add_parser('import', help='Copy selected Linux host tools and their shared libraries')
    importer.add_argument('-c', '--config', required=True, type=Path,
                          help='YAML with executables mapping and optional library_dirs list')
    importer.add_argument('-o', '--output', type=Path, default=Path('.tools'))
    return result


def _import(args):
    filename = args.config.resolve()
    try:
        values = yaml.safe_load(filename.read_text())
    except (OSError, yaml.YAMLError) as error:
        raise BuildError('Cannot read tool import configuration') from error
    require(isinstance(values,dict) and not (set(values)-{'executables','library_dirs','targets'}),
            'Tool import configuration requires executables and optional library_dirs/targets')
    require(isinstance(values.get('executables'),dict) and values['executables'], 'executables must be a nonempty mapping')
    require(isinstance(values.get('library_dirs',[]),list), 'library_dirs must be a list')
    sources = {name:path(value,filename.parent) for name,value in values['executables'].items()}
    libraries = [path(value,filename.parent) for value in values.get('library_dirs',[])]
    targets = values.get('targets',{})
    require(isinstance(targets,dict) and all(isinstance(v,dict) for v in targets.values()),
            'targets must map architectures to runtime asset paths')
    targets = {architecture:{name:path(value,filename.parent) for name,value in assets.items()}
               for architecture,assets in targets.items()}
    result = import_toolset(sources,args.output,library_dirs=libraries,target_assets=targets)
    print(json.dumps(result, indent=2))


def _selected_path(args, config, name, base):
    value = getattr(args, name)
    if value is not None:
        return value.expanduser().resolve()
    return path(config[name], base) if config.get(name) else None


def _asset_root():
    for root in (Path.cwd(), Path(__file__).resolve().parents[2]):
        if (root / 'key').is_dir() or (root / '.tools').is_dir():
            return root
    return Path.cwd()


def _apk_executable(args, config, base):
    selected = _selected_path(args, config, 'apk', base)
    if selected is None:
        toolset = _selected_path(args, config, 'tools_dir', base)
        candidates = ((toolset / 'bin/apk',) if toolset is not None else
                      (Path.cwd() / '.tools/bin/apk', Path(__file__).resolve().parents[2] / '.tools/bin/apk'))
        selected = next((candidate for candidate in candidates if candidate.is_file()), None)
    if selected is None:
        program = shutil.which('apk')
        require(program, 'APK client is unavailable; install it in .tools/bin/apk or use --apk')
        selected = Path(program)
    require(selected.is_file() and os.access(selected, os.X_OK), 'APK client is not executable: '+str(selected))
    return selected


def prepare_environment():
    print('Checking environment...',file=sys.stderr,flush=True)
    result = check_environment()
    print('Environment ready: Python '+result['python']+', namespaces and ARM64 execution OK.',
          file=sys.stderr,flush=True)
    return result


def prepare_toolset(args, config, base):
    selected = _selected_path(args,config,'tools_dir',base)
    if selected is not None:
        return selected
    return require_toolset(_asset_root()/'.tools')


def _choose_package(packages, image, version):
    choices = [package for package in packages if (image is None or package.name == image)
               and (version is None or version in (package.version, package.apk_version))]
    require(choices, 'No image package matches the requested name and version')
    if image is not None and len(choices) == 1:
        return choices[0]
    require(sys.stdin.isatty(), 'Specify --image and --image-version when more than one image version matches')
    print('Available images:', file=sys.stderr)
    for number, package in enumerate(choices, 1):
        print(f'  {number}. {package.machine}  {package.profile}  {package.version}', file=sys.stderr)
    while True:
        print(f'Select image [1-{len(choices)}]: ', end='', file=sys.stderr, flush=True)
        value = sys.stdin.readline()
        require(value, 'No image selected')
        try:
            number = int(value.strip())
        except ValueError:
            number = 0
        if 1 <= number <= len(choices):
            return choices[number-1]
        print('Enter a number from the list.', file=sys.stderr)


def _repository(args, config, base):
    """Discover packages independently of downloading their image contents."""
    prepare_toolset(args,config,base)
    cache = _selected_path(args, config, 'cache_dir', base)
    if cache is None:
        cache = Path(os.environ.get('XDG_CACHE_HOME', str(Path.home() / '.cache'))) / 'naos-image-generator'
    key = _selected_path(args, config, 'apk_key', base)
    if key is None:
        local_key = _asset_root() / 'key/apk-repository/naos-apk.rsa.pub'
        if local_key.is_file():
            key = local_key
    return Repository(url=args.repository or config.get('repository', DEFAULT_REPOSITORY),
                      apk=_apk_executable(args,config,base), public_key=key, cache=cache)


def _source(args, config, base):
    image = args.image if args.image is not None else config.get('image')
    require(not (args.input is not None and args.image is not None),
            'Use either an export directory or --image')
    if args.input is not None:
        return args.input.resolve(), None
    if image is None and config.get('input'):
        return path(config['input'], base), None
    require(image is not None or sys.stdin.isatty(),
            'Specify --image for non-interactive use, or provide a local export directory')
    repository = _repository(args,config,base)
    version = args.image_version or config.get('image_version')
    package = _choose_package(repository.list_packages(),image,version)
    print(f'Using {package.name} version {package.version}', file=sys.stderr)
    return repository.acquire(package), package


def _remote_defaults(config):
    """Use the conventional release directory layout when no paths were given."""
    result = copy.deepcopy(config)
    root = _asset_root()
    toolset = root / '.tools'
    if toolset.is_dir():
        result.setdefault('tools_dir', str(toolset))
    if (root / 'files').is_dir():
        result.setdefault('overlays', [str(root / 'files')])
    keys = result.setdefault('keys', {})
    require(isinstance(keys,dict), 'Unknown key configuration')
    for name, directory, private, certificate in (
            ('secure_boot', 'secure-boot', 'dev.key', 'dev.crt'),
            ('ota', 'ota', 'signing.key.pem', 'signing.cert.pem')):
        key = root / 'key' / directory / private
        cert = root / 'key' / directory / certificate
        if key.is_file() and cert.is_file() and name not in keys:
            keys[name] = dict(key=str(key), certificate=str(cert))
            public = root / 'key' / directory / 'dev.pubkey'
            if name == 'secure_boot' and public.is_file():
                keys[name]['public_key'] = str(public)
    system = root / 'key/system-encryption/system.key'
    if system.is_file():
        keys.setdefault('system', str(system))
    ota = keys.get('ota')
    if isinstance(ota, dict) and ota.get('certificate'):
        result.setdefault('ota_certificate', ota['certificate'])
    ssh_ca = root / 'key/ssh-ca/ssh_ca_key.pub'
    if ssh_ca.is_file():
        result.setdefault('ssh_ca', str(ssh_ca))
    return result


def main(argv=None):
    arguments = parser()
    argv = list(sys.argv[1:] if argv is None else argv)
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    try:
        interactive = not argv
        if interactive:
            require(sys.stdin.isatty(),
                    'Interactive mode requires a terminal; use build/check/inspect with explicit arguments, or --help')
            prepare_environment()
        args = wizard.start(arguments,key_directory=_asset_root()/'key') if interactive else arguments.parse_args(argv)
        if args.command == 'tools':
            _import(args)
            return 0
        if args.command == 'inspect':
            print(json.dumps(Bundle(args.input).summary(),indent=2))
            return 0
        if not interactive:
            prepare_environment()
        config, base = load(args.config)
        local_apks = args.apks_dir.resolve() if args.apks_dir is not None else _asset_root()/'apks'
        if args.apks_dir is not None or ('apks_dir' not in config and local_apks.is_dir()):
            config['apks_dir'] = str(local_apks)
        output = None
        if interactive:
            repository = _repository(args,config,base)
            print('Loading available images...', file=sys.stderr, flush=True)
            package = wizard.choose_package(repository.list_packages(),profile=args.interactive_profile)
            wizard.configure(args,package)
            wizard.choose_device_tree(args,_asset_root()/'board',package.machine)
            if args.command == 'build':
                output_board = args.dtb.stem if args.dtb is not None else package.machine
                default_output = (Path.cwd() / 'output' / output_board / package.profile /
                                  (package.version + ('-updates' if args.ota_only else '')))
                output = wizard.output_directory(args,default_output)
            wizard.configure_efuse(args,package)
            wizard.confirm(args,package,output)
            print(f'Downloading Alpine {package.version} for {package.machine} ({package.profile})...',
                  file=sys.stderr, flush=True)
            source = repository.acquire(package)
        else:
            source, package = _source(args,config,base)
        if package is not None or interactive:
            config = _remote_defaults(config)
        bundle = Bundle(source)
        if package is None:
            prepare_toolset(args,config,base)
        overrides = {name:getattr(args,name) for name in ('ota','ota_only','sbom','burn_key_hash','efuse_loader','version','build_id',
                     'epoch','processors','boot_mib','system_mib','tools_dir','dtb')}
        if package is not None and overrides['version'] is None and 'version' not in config:
            overrides['version'] = package.version
        if overrides['tools_dir'] is not None:
            overrides['tools_dir'] = overrides['tools_dir'].resolve()
        if overrides['dtb'] is not None:
            overrides['dtb'] = overrides['dtb'].expanduser().resolve()
        from .local_apks import discover
        if config.get('apks_dir') and discover(path(config['apks_dir'],base)):
            # Share the explicit APK client selection with local package metadata inspection.
            tool_overrides = config.setdefault('tools', {})
            require(isinstance(tool_overrides, dict), 'tools must be a mapping')
            if args.apk is not None or 'apk' not in tool_overrides:
                tool_overrides['apk'] = str(_apk_executable(args, config, base))
        options = settings(bundle,config,base,overrides)
        if args.command == 'check':
            tools = prepare_tools(options)
            print(json.dumps({'status':'ok', 'machine':bundle.machine, 'profile':bundle.profile,
                              'ota':options['ota'], 'sbom':options['sbom'],
                              'burn_key_hash':options['burn_key_hash'], 'tools':sorted(tools)},indent=2))
            return 0
        if output is None:
            if args.output is not None:
                output = args.output.resolve()
            elif config.get('output'):
                output = path(config['output'],base)
            elif package is not None:
                output = Path.cwd() / 'output' / (options.get('board_name') or bundle.machine) / bundle.profile / (package.version + ('-updates' if options['ota_only'] else ''))
            else:
                output = path(None,base)
        tools = prepare_tools(options)
        manifest = build(bundle,options,tools,output,force=args.force)
        print(json.dumps({'output':str(output), 'machine':bundle.machine, 'profile':bundle.profile,
                          'version':manifest['version'], 'files':len(manifest['files']),
                          'ota':manifest['ota'], 'ota_only':manifest.get('ota_only',False),
                          'sbom':bool(manifest['sbom'])},indent=2))
        return 0
    except wizard.Cancelled:
        print('naos-image-generator: cancelled', file=sys.stderr)
        return 0
    except (BuildError, ValueError, OSError, KeyError) as error:
        print('naos-image-generator: '+str(error), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('naos-image-generator: cancelled', file=sys.stderr)
        return 130


if __name__ == '__main__':
    raise SystemExit(main())
