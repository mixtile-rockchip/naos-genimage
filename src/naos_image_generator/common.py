# SPDX-License-Identifier: MIT
"""Shared process and file helpers; no shell execution or device writes."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess


class BuildError(ValueError):
    pass


_TOOL_ENV = {}


def set_tool_environment(values):
    _TOOL_ENV.clear()
    _TOOL_ENV.update(values)


def require(condition, message):
    if not condition:
        raise BuildError(message)


def safe_relative(value):
    require(isinstance(value, str) and value and '\0' not in value and '\\' not in value,
            'Expected a relative path')
    path = PurePosixPath(value)
    require(not path.is_absolute() and '..' not in path.parts and str(path) != '.',
            'Path escapes the selected directory')
    return path


def input_file(root, name):
    path = Path(root) / safe_relative(name)
    require(path.is_file() and path.resolve().is_relative_to(Path(root).resolve()),
            'Missing or unsafe input: ' + name)
    return path


def sha256(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError, ValueError) as error:
        raise BuildError('Cannot read JSON file: ' + str(path)) from error


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + '\n', encoding='utf-8')


def record(path, role=None):
    path = Path(path)
    result = {'size': path.stat().st_size, 'sha256': sha256(path)}
    if role:
        result['role'] = role
    return result


def _diagnostic(data):
    value = data.decode(errors='replace') if isinstance(data, bytes) else str(data)
    value = re.sub(r'-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----',
                   '[private key omitted]', value, flags=re.DOTALL)
    value = re.sub(r'\b[0-9a-fA-F]{64,}\b', '[hex omitted]', value)
    return value[-3000:].strip()


def process_environment(env=None):
    values = {**os.environ, **_TOOL_ENV, **(env or {})}
    # Callers often pass a full environment when setting the build epoch.
    # Keep the selected toolset first for helper programs and shared libraries.
    for name in ('PATH', 'LD_LIBRARY_PATH'):
        if name in _TOOL_ENV:
            values[name] = _TOOL_ENV[name]
    return values


def run(command, cwd=None, env=None, timeout=900):
    """Return captured stdout. Signing-tool stdout is never logged on failure."""
    argv = [str(value) for value in command]
    values = process_environment(env)
    try:
        result = subprocess.run(argv, cwd=cwd, env=values, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    except FileNotFoundError as error:
        raise BuildError('Required tool is unavailable: ' + argv[0]) from error
    except subprocess.TimeoutExpired as error:
        raise BuildError('Tool timed out: ' + Path(argv[0]).name) from error
    if result.returncode:
        detail = _diagnostic(result.stderr)
        raise BuildError(f'{Path(argv[0]).name} failed (exit {result.returncode})' + (': ' + detail if detail else ''))
    return result.stdout.decode(errors='replace')
