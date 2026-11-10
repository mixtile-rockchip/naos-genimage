# SPDX-License-Identifier: MIT
"""Check host capabilities before opening menus or generating images."""
from importlib import import_module
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import subprocess
import sys
import tempfile

from .common import BuildError, _diagnostic, require


_HOST_TOOLS = ('unshare', 'chroot', 'mount', 'umount', 'tar')
_PROBE_TIMEOUT = 15


def _environment():
    """Keep host probes independent of a selected toolset or target preload."""
    return {name:value for name,value in os.environ.items()
            if not name.startswith('LD_') and name not in ('PYTHONHOME', 'PYTHONPATH')}


def _probe(command, description):
    try:
        result = subprocess.run([str(value) for value in command], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=_environment(), timeout=_PROBE_TIMEOUT)
    except subprocess.TimeoutExpired as error:
        raise BuildError(description+' timed out') from error
    except OSError as error:
        raise BuildError(description+' failed: '+str(error)) from error
    require(result.returncode == 0, description+' failed: '+_diagnostic(result.stderr))


def _aarch64_exit_program():
    """A static ARM64 Linux exit(0) executable; no compiler or target libc needed."""
    address = 0x400000
    instructions = struct.pack('<III', 0xd2800000, 0xd2800ba8, 0xd4000001)
    size = 64+56+len(instructions)
    ident = b'\x7fELF\x02\x01\x01'+bytes(9)
    header = ident+struct.pack('<HHIQQQIHHHHHH', 2, 183, 1, address+120,
                              64, 0, 0, 64, 56, 1, 0, 0, 0)
    segment = struct.pack('<IIQQQQQQ', 1, 5, 0, address, address, size, size, 0x1000)
    return header+segment+instructions


def _check_aarch64():
    # A valid handler alone is insufficient: its registered interpreter may
    # be broken. Execute a harmless target program as well, without installing
    # packages, changing registrations or depending on the bundled toolset.
    try:
        with tempfile.TemporaryDirectory(prefix='naos-startup-aarch64-') as directory:
            program = Path(directory)/'check-aarch64'
            program.write_bytes(_aarch64_exit_program())
            program.chmod(0o700)
            _probe([program], 'ARM64 execution check; verify QEMU/binfmt and executable temporary storage')
    except OSError as error:
        raise BuildError('Cannot prepare the ARM64 execution check; verify writable temporary storage: '+str(error)) from error


def _python_dependencies():
    require(sys.version_info >= (3,11), 'Python 3.11 or newer is required')
    for module, description in (('yaml','PyYAML'),('Cryptodome.Cipher.AES','PyCryptodome')):
        try:
            import_module(module)
        except (ImportError,OSError) as error:
            raise BuildError('Missing Python dependency '+description+'. On Ubuntu, install '
                'python3-yaml and python3-pycryptodome before running the generator') from error


def entry_main(argv=None):
    """Report missing Python dependencies before importing the full CLI."""
    try:
        _python_dependencies()
        from .cli import main
        return main(argv)
    except BuildError as error:
        print('naos-image-generator: '+str(error),file=sys.stderr)
        return 1


def check_environment():
    """Return a brief host summary, or fail before any download or build work.

    This never invokes sudo, registers interpreters, creates persistent mounts
    or installs software. Bundled tools and target fakeroot assets are not
    needed for these checks.
    """
    _python_dependencies()
    require(platform.system() == 'Linux' and platform.machine().lower() in ('x86_64', 'amd64'),
            'The current generator toolset requires a Linux x86_64 host')
    libc, version = platform.libc_ver()
    match = re.fullmatch(r'(\d+)\.(\d+)(?:\.\d+)*', version)
    require(libc.lower() == 'glibc' and match is not None
            and tuple(map(int, match.groups())) >= (2, 38),
            'The current generator toolset requires glibc 2.38 or newer; Ubuntu 24.04 is supported')
    tools = {name:shutil.which(name) for name in _HOST_TOOLS}
    missing = [name for name,filename in tools.items() if filename is None]
    require(not missing, 'Missing host tools: '+', '.join(missing)+
            '. Install util-linux, coreutils and tar before running the generator')
    _probe([tools['unshare'], '--user', '--map-root-user', '--mount', '--ipc',
        '--propagation', 'private', sys.executable, '-c',
        'import os; raise SystemExit(0 if os.geteuid() == 0 else 1)'],
        'User namespace check; allow unprivileged user/mount/IPC namespaces on the host or runner')
    from .apk_runtime import _binfmt
    require(_binfmt('aarch64'), 'ARM64 QEMU/binfmt support is unavailable. Configure an enabled '
            'AArch64 binfmt_misc handler with the F flag before running the generator')
    _check_aarch64()
    return dict(python='.'.join(map(str, sys.version_info[:3])), host='linux-x86_64',
                glibc=version, namespaces=True, aarch64=True)
