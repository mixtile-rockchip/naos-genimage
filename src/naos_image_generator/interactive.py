# SPDX-License-Identifier: MIT
"""Terminal selections for the no-argument entry point."""
from pathlib import Path
import os
import shlex
import sys

from .common import BuildError, read_json, require


DEFAULT_SYSTEM_MIB = 200


class Cancelled(Exception):
    pass


def answer(label, default=None):
    suffix = f' [{default}]' if default is not None else ''
    print(f'{label}{suffix}: ', end='', file=sys.stderr, flush=True)
    value = sys.stdin.readline()
    if not value or value.strip().lower() in ('q', 'quit'):
        raise Cancelled
    return value.strip() or (str(default) if default is not None else '')


def select(title, choices, default=0, single=False):
    require(choices, 'No available choices for '+title)
    if single and len(choices) == 1:
        print(f'{title}: {choices[0][0]}', file=sys.stderr)
        return choices[0][1]
    print(f'\n{title}:', file=sys.stderr)
    for number, (label, _) in enumerate(choices, 1):
        print(f'  {number}. {label}', file=sys.stderr)
    while True:
        value = answer('Select', default+1)
        if value.isdecimal() and 1 <= int(value) <= len(choices):
            return choices[int(value)-1][1]
        print('Enter a number from the list.', file=sys.stderr)


def yes(label, default=False):
    while True:
        value = answer(label+' (y/n)', 'y' if default else 'n').lower()
        if value in ('y', 'yes', 'n', 'no'):
            return value in ('y', 'yes')
        print('Enter y or n.', file=sys.stderr)


def positive(label, default):
    while True:
        value = answer(label, default)
        if value.isdecimal() and int(value) > 0:
            return int(value)
        print('Enter a positive integer.', file=sys.stderr)


def start(arguments, key_directory=None):
    require(sys.stdin.isatty(),
            'Interactive mode requires a terminal; use build/check/inspect with explicit arguments, or --help')
    print('NAOS Image Generator\nPress Enter for the displayed default, or q to cancel.', file=sys.stderr)
    directory = Path(key_directory) if key_directory is not None else Path('key').resolve()
    print(f'\nBefore continuing, confirm the required key files are prepared under: {directory}', file=sys.stderr)
    print('  Development: ota/signing.key.pem and ota/signing.cert.pem', file=sys.stderr)
    print('  Standard production setup: the OTA files above, plus:', file=sys.stderr)
    print('    secure-boot/dev.key, dev.crt and dev.pubkey', file=sys.stderr)
    print('    system-encryption/system.key', file=sys.stderr)
    print('    ssh-ca/ssh_ca_key.pub (public CA key only)', file=sys.stderr)
    print('The OTA private key signs update bundles; its certificate is trusted by the image.', file=sys.stderr)
    print('See README in each key directory for key-generation instructions.', file=sys.stderr)
    print(f'\nOptional system configuration replacements: {directory.parent / "files"}', file=sys.stderr)
    print('  Create directories and files using the same paths as on the device.', file=sys.stderr)
    print('  Example: files/etc/naos-core/device.ini -> /etc/naos-core/device.ini', file=sys.stderr)
    print('  Matching files are replaced; new files are added when generating the image.', file=sys.stderr)
    print(f'\nOptional local application APKs: {directory.parent / "apks"}', file=sys.stderr)
    print('  Place .apk files here to install them automatically into the image before files/ replacements.', file=sys.stderr)
    print('  Local APK signatures are not required; include any dependencies missing from the image.', file=sys.stderr)
    print('  Installation scripts and triggers run in a rootless target environment.', file=sys.stderr)
    print('  Optional /<package-name>.commands files run after all packages are installed.', file=sys.stderr)
    print('  Embedded SPDX 2.3 JSON is extracted from rootfs and merged when image SBOM is enabled.', file=sys.stderr)
    profile = select('Image type', [('Development', 'development'), ('Production', 'production')])
    action = select('What would you like to do?', [
        ('Full firmware image (.img)', 'factory'),
        ('Full firmware image + system and bootloader updates', 'ota'),
        ('System and bootloader updates', 'ota_only'),
        ('Check image generation requirements', 'check'),
        ('Exit', 'exit'),
    ])
    if action == 'exit':
        raise Cancelled
    command = ['check' if action == 'check' else 'build']
    args = arguments.parse_args(command)
    args.interactive_profile = profile
    if action != 'check':
        args.ota = action in ('ota', 'ota_only')
        args.ota_only = action == 'ota_only'
    return args


def choose_package(packages, image=None, version=None, profile=None):
    choices = [package for package in packages if (image is None or package.name == image)
               and (version is None or version in (package.version, package.apk_version))
               and (profile is None or package.profile == profile)]
    require(choices, 'No available '+profile+' image' if profile else 'No image package matches the requested name and version')
    machine = select('Board', [(name, name) for name in dict.fromkeys(p.machine for p in choices)], single=True)
    choices = [package for package in choices if package.machine == machine]
    if profile is None:
        profiles = [(name.title(), name) for name in ('development', 'production')
                    if any(package.profile == name for package in choices)]
        profile = select('Image type', profiles, single=True)
    return select('Image version', [('Alpine '+package.version, package) for package in choices if package.profile == profile])


def configure(args, package):
    """Collect choices from repository metadata without opening an image."""
    print(f'\nSelected image: {package.machine} / {package.profile} / Alpine {package.version}', file=sys.stderr)
    args.sbom = package.profile == 'production'
    if args.command == 'check':
        return
    if not args.ota_only:
        args.system_mib = DEFAULT_SYSTEM_MIB
        if not yes(f'Use default system A/B size ({DEFAULT_SYSTEM_MIB} MiB each)?', True):
            args.system_mib = positive('Each system slot (MiB)', DEFAULT_SYSTEM_MIB)
    if package.profile == 'production':
        args.sbom = yes('Generate SBOM?', True)
    else:
        print('SBOM: disabled for this image.', file=sys.stderr)


def choose_device_tree(args, directory, default_name):
    """Offer optional board DTBs before downloading the selected image."""
    from .boards import discover
    choices = discover(directory)
    if choices:
        args.dtb = select('Device tree', [(default_name,None)] +
                          [(candidate.stem,candidate) for candidate in choices])


def output_directory(args, default):
    while True:
        selected = Path(answer('Output directory', default)).expanduser().resolve()
        if selected.exists():
            if not selected.is_dir():
                print('Output must be a directory.', file=sys.stderr)
                continue
            if any(selected.iterdir()):
                marker = selected / 'manifest.json'
                if marker.is_file():
                    try:
                        prior = read_json(marker)
                    except BuildError:
                        prior = None
                    if isinstance(prior, dict) and prior.get('generator') == 'naos-image-generator' and prior.get('schema_version') == 1:
                        if yes('Replace the earlier generated output?'):
                            args.force = True
                            return selected
                        continue
                print('Directory is not empty; choose another output directory.', file=sys.stderr)
                continue
        return selected


def configure_efuse(args, package):
    """Keep irreversible provisioning opt-in, after the ordinary settings."""
    args.burn_key_hash = args.efuse_loader = False
    if package.profile != 'production' or args.command != 'build':
        return
    if not yes('Enable OTP/eFuse public-key Hash programming '
               '(irreversible; confirm you understand the risks; choose n for testing)?'):
        return
    mode = select('OTP/eFuse output', [
        ('Separate loader-efuse.bin; normal firmware does not program OTP/eFuse', 'separate'),
        ('Enable OTP/eFuse programming in the generated firmware', 'firmware'),
    ])
    print('\nWARNING: OTP/eFuse public-key Hash programming is permanent and cannot be undone.', file=sys.stderr)
    print('Check the secure-boot signing key before using these files. After programming,', file=sys.stderr)
    print('the device accepts only firmware signed with the matching key. Keep its private key safe.', file=sys.stderr)
    print('Keep device power stable. This generator only creates files; programming happens', file=sys.stderr)
    print('when the programming SPL boots and verifies the matching signed U-Boot.', file=sys.stderr)
    print('Downloading a USB Loader alone does not confirm that programming succeeded.', file=sys.stderr)
    if mode == 'separate':
        print('Programming Loader: loader-efuse.bin; programming IDBlock: idblock-efuse.bin.', file=sys.stderr)
        print('The normal firmware and its update bundles keep OTP/eFuse programming disabled.', file=sys.stderr)
    else:
        print('The generated firmware will contain the programming SPL.', file=sys.stderr)
        print('Use the efuse-marked files only for deliberate device provisioning.', file=sys.stderr)
    if not yes('Confirm permanent OTP/eFuse programming when this SPL runs?'):
        print('OTP/eFuse programming remains disabled.', file=sys.stderr)
        return
    args.efuse_loader = mode == 'separate'
    args.burn_key_hash = mode == 'firmware'


def _command_path(value):
    filename = Path(value).expanduser().resolve()
    try:
        return str(filename.relative_to(Path.cwd()))
    except ValueError:
        return str(filename)


def command_line(args, package, output=None, program=None):
    """Return a shell-quoted, non-interactive command for the chosen settings."""
    if program is None:
        entry = Path(__file__).resolve().parents[2]/'naos-image-generator.py'
        if entry.is_file():
            filename = _command_path(entry)
            if '/' not in filename:
                filename = './'+filename
            program = [filename] if os.access(entry,os.X_OK) else ['python3',filename]
        else:
            program = [sys.executable,'-m','naos_image_generator']
    command = [*program,args.command,'--image',package.name,'--image-version',package.version]
    for name,option in (
            ('config','--config'),('repository','--repository'),('apk','--apk'),
            ('apk_key','--apk-key'),('cache_dir','--cache-dir'),('apks_dir','--apks-dir'),
            ('tools_dir','--tools-dir'),('dtb','--dtb'),('version','--firmware-version'),
            ('build_id','--build-id'),('epoch','--epoch'),('processors','--processors'),
            ('boot_mib','--boot-mib'),('system_mib','--system-mib')):
        value = getattr(args,name,None)
        if value is not None:
            command += [option,_command_path(value) if isinstance(value,Path) else str(value)]
    for name in ('ota','ota_only','sbom','burn_key_hash','efuse_loader'):
        value = getattr(args,name,None)
        if value is not None:
            command.append('--'+('' if value else 'no-')+name.replace('_','-'))
    if args.command == 'build':
        require(output is not None, 'Repeat build command requires an output directory')
        # Repeating a completed build reuses the selected output directory.
        # The existing --force guard only replaces earlier generator outputs.
        command += ['--output',_command_path(output),'--force']
    return shlex.join(command)


def confirm(args, package, output=None):
    enabled = lambda value: 'enabled' if value else 'disabled'
    print('\nSummary:', file=sys.stderr)
    for label, value in (
        ('Board', args.dtb.stem if args.dtb is not None else package.machine),
        ('Device tree', args.dtb.stem if args.dtb is not None else package.machine),
        ('Image type', package.profile), ('Version', 'Alpine '+package.version),
        ('Generate', 'requirements check' if args.command == 'check' else
         'system and bootloader updates' if args.ota_only else 'full firmware image'),
        ('Output', output), ('OTA', 'system + bootloader' if args.ota else 'disabled'),
        ('SBOM', enabled(args.sbom)), ('OTP key hash programming', enabled(args.burn_key_hash)),
        ('Separate OTP/eFuse Loader', 'loader-efuse.bin' if args.efuse_loader else None),
    ):
        if value is not None:
            print(f'  {label}: {value}', file=sys.stderr)
    if args.ota_only:
        print('  Existing disk partitions: unchanged', file=sys.stderr)
    elif args.command == 'build':
        size = f'{args.system_mib if args.system_mib is not None else DEFAULT_SYSTEM_MIB} MiB'
        print(f'  Each system slot: {size}', file=sys.stderr)
    print('  Command: '+command_line(args,package,output),file=sys.stderr,flush=True)
    if not yes('Start generation?' if args.command == 'build' else 'Run checks?', True):
        raise Cancelled
