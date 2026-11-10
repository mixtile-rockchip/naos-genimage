# SPDX-License-Identifier: MIT
"""Validate the host tools supplied with the project before using them."""
import os
from pathlib import Path, PurePosixPath
import re

from .common import BuildError, read_json, require, sha256


REQUIRED_TOOLS = frozenset(('apk', 'mkimage', 'boot_merger', 'sqfstar', 'dtc',
    'fdtget', 'fdtput', 'fit_check_sign', 'rk_sign_tool', 'openssl', 'rauc',
    'mksquashfs', 'unsquashfs'))
REQUIRED_ASSETS = frozenset(('targets/aarch64/fakeroot.apk',
                            'targets/aarch64/libnaos-chown-compat.so'))
_HELP = ' Obtain a complete copy of this project, including its .tools directory.'


def _relative(name):
    require(isinstance(name, str) and name and '\0' not in name and '\\' not in name,
            'Invalid bundled tool path')
    path = PurePosixPath(name)
    require(not path.is_absolute() and '..' not in path.parts and str(path) == name
            and name not in ('.', 'toolset.json'), 'Unsafe bundled tool path')
    return path


def validate_toolset(directory):
    """Check manifest records, executable tools and target helpers; return metadata."""
    root = Path(directory).expanduser().absolute()
    try:
        require(root.is_dir() and not root.is_symlink(), 'Bundled host tools directory is missing or unsafe')
        manifest_path = root / 'toolset.json'
        require(manifest_path.is_file() and not manifest_path.is_symlink()
                and manifest_path.stat().st_size <= 8 * 1024 * 1024,
                'Bundled host tools manifest is missing or unsafe')
        manifest = read_json(manifest_path)
        require(isinstance(manifest, dict) and manifest.get('schema_version') == 1
                and isinstance(manifest.get('host'), dict)
                and manifest['host'].get('os') == 'linux'
                and manifest['host'].get('architecture') == 'x86_64'
                and isinstance(manifest.get('files'), dict) and manifest['files']
                and isinstance(manifest.get('tools'), dict), 'Unsupported bundled host tools manifest')
        files = manifest['files']
        for name, record in files.items():
            relative = _relative(name)
            require(isinstance(record, dict) and record.get('path') == name
                    and type(record.get('size')) is int and record['size'] >= 0
                    and isinstance(record.get('sha256'), str)
                    and re.fullmatch(r'[0-9a-f]{64}', record['sha256']),
                    'Invalid bundled tool file record: ' + name)
            source = record.get('source')
            require(source is None or (isinstance(source, str) and source
                    and PurePosixPath(source).name == source and '\\' not in source),
                    'Nonportable bundled tool source filename: ' + name)
            for parent in relative.parents:
                candidate = root / parent
                require(candidate.is_dir() and not candidate.is_symlink(),
                        'Missing or unsafe bundled tool directory: ' + str(parent))
            filename = root / relative
            require(filename.is_file() and not filename.is_symlink(),
                    'Bundled tool file is missing or unsafe: ' + name)
            require(filename.stat().st_size == record['size'] and sha256(filename) == record['sha256'],
                    'Bundled tool file checksum mismatch: ' + name)
        for role in REQUIRED_TOOLS:
            name = 'bin/' + role
            require(manifest['tools'].get(role) == name and name in files,
                    'Required bundled host tool is missing: ' + role)
            require(os.access(root / name, os.X_OK), 'Bundled host tool is not executable: ' + role)
        for name in REQUIRED_ASSETS:
            require(name in files, 'Required bundled target helper is missing: ' + name)
        return manifest
    except (OSError, BuildError) as error:
        raise BuildError(str(error) + _HELP) from error


def require_toolset(directory):
    """Return the local bundled tool directory after validating it."""
    root = Path(directory).expanduser().absolute()
    validate_toolset(root)
    return root
