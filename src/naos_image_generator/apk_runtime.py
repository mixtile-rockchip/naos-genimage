# SPDX-License-Identifier: MIT
"""Resolve the isolated, unprivileged target environment for APK scripts."""
from pathlib import Path
import os
import platform
import shutil
import struct
import subprocess
import sys

from .common import BuildError, _diagnostic, process_environment, require
from .tools import resolve_tools


_ARCHITECTURES = {
    'aarch64': (2, 183, 'qemu-aarch64-static', 'qemu-aarch64'),
    'armv7': (1, 40, 'qemu-arm-static', 'qemu-arm'),
    'armhf': (1, 40, 'qemu-arm-static', 'qemu-arm'),
    'x86_64': (2, 62, 'qemu-x86_64-static', 'qemu-x86_64'),
}
_HOST_TOOLS = frozenset(('unshare', 'chroot', 'mount', 'umount', 'tar'))


def _ordinary_file(filename, description):
    filename = Path(filename).expanduser().absolute()
    require(filename.is_file() and not filename.is_symlink() and filename.stat().st_size > 0,
            'Missing ordinary '+description+': '+str(filename))
    return filename


def _target_library(filename, architecture):
    filename = _ordinary_file(filename, 'target ownership library')
    with filename.open('rb') as stream:
        header = stream.read(64)
    elf_class, machine, _, _ = _ARCHITECTURES[architecture]
    require(len(header) >= 52 and header[:4] == b'\x7fELF' and header[4] == elf_class
            and header[5] == 1 and struct.unpack_from('<HH', header, 16) == (3, machine),
            'Ownership library does not match target architecture '+architecture)
    return filename


def resolve_runtime(toolset=None, overrides=None, architecture='aarch64'):
    """Find host tools and target helpers; no download or host setup is performed.

    Explicit shared ``tools`` overrides may include the two data-file keys
    ``fakeroot_apk`` and ``ownership_library``, or optional executable ``qemu``.
    Other tool overrides belong to the main image pipeline and are ignored.
    """
    require(platform.system() == 'Linux', 'Local APK installation requires Linux user namespaces')
    require(architecture in _ARCHITECTURES, 'Unsupported target APK architecture: '+str(architecture))
    overrides = dict(overrides or {})
    if toolset is None:
        for candidate in (Path.cwd()/'.tools', Path(__file__).resolve().parents[2]/'.tools'):
            if candidate.is_dir():
                toolset = candidate
                break
    toolset = Path(toolset).expanduser().absolute() if toolset is not None else None
    target = (toolset if toolset is not None else Path.cwd()/'.tools')/'targets'/architecture
    runtime = resolve_tools({name:value for name,value in overrides.items() if name in _HOST_TOOLS},
                            _HOST_TOOLS, toolset)
    runtime['fakeroot_apk'] = _ordinary_file(overrides.get('fakeroot_apk', target/'fakeroot.apk'),
                                             'target fakeroot APK')
    runtime['ownership_library'] = _target_library(
        overrides.get('ownership_library', target/'libnaos-chown-compat.so'), architecture)
    qemu_name = _ARCHITECTURES[architecture][2]
    if 'qemu' in overrides:
        runtime['qemu'] = resolve_tools({qemu_name:overrides['qemu']}, [qemu_name])[qemu_name]
    else:
        bundled = toolset/'bin'/qemu_name if toolset is not None else None
        candidate = bundled if bundled is not None and os.path.lexists(bundled) else shutil.which(qemu_name)
        runtime['qemu'] = resolve_tools({qemu_name:candidate}, [qemu_name])[qemu_name] if candidate else None
    runtime.update(architecture=architecture, proc_mode='auto')
    return runtime


def _native_architecture(architecture):
    host = platform.machine().lower()
    return (host in ('aarch64', 'arm64') if architecture == 'aarch64' else
            host in ('armv7l', 'armv6l', 'arm') if architecture in ('armv7', 'armhf') else
            host in ('x86_64', 'amd64'))


def _binfmt(architecture, directory=Path('/proc/sys/fs/binfmt_misc')):
    """Require a persistent interpreter descriptor usable after entering chroot."""
    prefix = _ARCHITECTURES[architecture][3]
    try:
        if (directory/'status').read_text().strip() != 'enabled':
            return False
        for filename in directory.iterdir():
            if filename.name in ('register', 'status') or not filename.is_file():
                continue
            lines = filename.read_text().splitlines()
            interpreter = next((line.split(None, 1)[1] for line in lines
                                if line.startswith('interpreter ')), '')
            flags = next((line.split(':', 1)[1].strip() for line in lines
                          if line.startswith('flags:')), '')
            if (lines and lines[0] == 'enabled' and 'F' in flags
                    and (filename.name.startswith(prefix) or Path(interpreter).name.startswith(prefix))):
                return True
    except OSError:
        return False
    return False


def preflight(runtime):
    """Check normal-user namespace access and cross-architecture execution setup.

    No sudo, registration, persistent mounts or host configuration changes are
    attempted. The worker additionally probes the actual target executable.
    """
    architecture = runtime.get('architecture', 'aarch64')
    require(architecture in _ARCHITECTURES, 'Unsupported target APK architecture: '+str(architecture))
    _ordinary_file(runtime['fakeroot_apk'], 'target fakeroot APK')
    _target_library(runtime['ownership_library'], architecture)
    require(runtime.get('proc_mode', 'auto') in ('auto', 'private', 'bind'), 'Invalid namespace proc mode')
    command = [str(runtime['unshare']), '--user', '--map-root-user', '--mount', '--ipc',
               '--propagation', 'private', sys.executable, '-c',
               'import os; raise SystemExit(0 if os.geteuid() == 0 else 1)']
    try:
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env=process_environment(), timeout=15)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise BuildError('Cannot check unprivileged user namespaces: '+str(error)) from error
    require(result.returncode == 0,
            'Unprivileged user namespaces are unavailable; allow user/mount/IPC namespaces in the host or runner. '
            +_diagnostic(result.stderr))
    require(_native_architecture(architecture) or _binfmt(architecture),
            'Target '+architecture+' execution is unavailable; configure its QEMU/binfmt_misc handler with the F flag. '
            'The generator does not require sudo or change the host registration.')
