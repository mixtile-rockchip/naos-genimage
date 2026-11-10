# SPDX-License-Identifier: MIT
"""Fetch signed image-input APKs without a package database or root privileges."""
from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import gzip
import hashlib
import io
import logging
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request

from .common import BuildError, process_environment, require, run, sha256
from .inputs import Bundle


DEFAULT_REPOSITORY = 'https://packages.naos.ai/repository'
PUBLIC_KEY_NAME = 'naos-apk.rsa.pub'
MAX_INDEX_BYTES = 16 * 1024**2
MAX_INDEX_CONTENT = 32 * 1024**2
MAX_APK_BYTES = 2 * 1024**3
MAX_EXPORT_BYTES = 8 * 1024**3
_PACKAGE = re.compile(r'(?P<machine>[a-z0-9][a-z0-9._+-]*)-alpine-(?P<profile>dev|prod)\Z')
_VERSION = re.compile(r'[0-9][A-Za-z0-9_.]*(?:-r[0-9]+)?\Z')
LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class Package:
    name: str
    apk_version: str
    version: str
    machine: str
    profile: str
    architecture: str

    @property
    def filename(self):
        return self.name + '-' + self.apk_version + '.apk'


def _package(name, version, architecture):
    match = _PACKAGE.fullmatch(name) if isinstance(name, str) else None
    require(match and isinstance(version, str) and _VERSION.fullmatch(version),
            'Invalid image package in repository index')
    require(architecture in ('x86_64', 'aarch64', 'noarch'), 'Unsupported package architecture')
    return Package(name, version, re.sub(r'-r0$', '', version), match['machine'],
                   'development' if match['profile'] == 'dev' else 'production', architecture)


def _download(url, destination, limit):
    class NoRedirects(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            raise BuildError('Unexpected repository redirect')

    request = urllib.request.Request(url, headers={'Cache-Control': 'no-cache'})
    try:
        with urllib.request.build_opener(NoRedirects()).open(request, timeout=60) as response, \
                Path(destination).open('xb') as output:
            total = 0
            while block := response.read(1024 * 1024):
                total += len(block)
                require(total <= limit, 'Repository response is too large')
                output.write(block)
            require(total > 0, 'Repository response is empty')
    except (urllib.error.URLError, OSError) as error:
        raise BuildError('Cannot download repository data: ' + url) from error


def _index_packages(filename):
    try:
        with gzip.open(filename, 'rb') as compressed:
            content = compressed.read(MAX_INDEX_CONTENT + 1)
        require(len(content) <= MAX_INDEX_CONTENT, 'Repository index is too large')
        with tarfile.open(fileobj=io.BytesIO(content), mode='r:', ignore_zeros=True) as archive:
            members = [member for member in archive if member.name == 'APKINDEX']
            require(len(members) == 1 and members[0].isfile()
                    and members[0].size <= MAX_INDEX_CONTENT, 'Invalid repository index archive')
            text = archive.extractfile(members[0]).read().decode('utf-8')
    except (OSError, EOFError, tarfile.TarError, UnicodeError) as error:
        raise BuildError('Cannot read repository index') from error
    packages, seen = [], set()
    for paragraph in text.strip().split('\n\n'):
        values = {}
        for line in paragraph.splitlines():
            require(len(line) >= 2 and line[1] == ':', 'Invalid repository index record')
            require(line[0] not in values, 'Duplicate repository index field')
            values[line[0]] = line[2:]
        if not _PACKAGE.fullmatch(values.get('P', '')):
            continue
        package = _package(values['P'], values.get('V'), values.get('A'))
        identity = (package.name, package.apk_version, package.architecture)
        require(identity not in seen, 'Duplicate image package in repository index')
        seen.add(identity)
        packages.append(package)
    return sorted(packages, key=lambda package: (package.machine, package.profile,
                  tuple(int(part) for part in re.findall(r'\d+', package.apk_version))), reverse=True)


def _extract(apk, destination, package):
    """Extract only ordinary export files; never execute package scripts."""
    prefix = PurePosixPath('usr/share/naos/image-inputs') / package.profile / package.machine
    seen, total, metadata = set(), 0, None
    try:
        # APK v2 concatenates independently compressed signature/control/data
        # members. GzipFile joins them; tarfile's r|gz stream reads only one.
        with gzip.open(apk, 'rb') as compressed, \
                tarfile.open(fileobj=compressed, mode='r|', ignore_zeros=True) as archive:
            for member in archive:
                require(isinstance(member.name, str) and '\\' not in member.name
                        and '\0' not in member.name, 'Unsafe APK member path')
                name = PurePosixPath(member.name)
                require(not name.is_absolute() and '..' not in name.parts, 'Unsafe APK member path')
                if str(name).startswith('.SIGN.'):
                    require(member.isfile() and member.size <= 16384, 'Invalid APK signature member')
                    continue
                if str(name) == '.PKGINFO':
                    require(metadata is None and member.isfile() and member.size <= 1024**2,
                            'Invalid APK package metadata')
                    metadata = {}
                    for line in archive.extractfile(member).read().decode('utf-8').splitlines():
                        field, separator, value = line.partition(' = ')
                        if separator and field in ('pkgname', 'pkgver', 'arch'):
                            require(field not in metadata, 'Duplicate APK package metadata')
                            metadata[field] = value
                    continue
                if name == prefix or name in prefix.parents:
                    require(member.isdir(), 'APK export parents must be directories')
                    continue
                require(name.is_relative_to(prefix), 'APK contains data outside its image export')
                relative = name.relative_to(prefix)
                require(str(relative) not in seen, 'Duplicate APK export file')
                seen.add(str(relative))
                target = destination / str(relative)
                require(member.isdir() or member.isfile(), 'APK export contains a link or special file')
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                total += member.size
                require(0 <= member.size <= MAX_APK_BYTES and total <= MAX_EXPORT_BYTES,
                        'APK export exceeds its size limit')
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open('xb') as output:
                    shutil.copyfileobj(archive.extractfile(member), output)
                require(target.stat().st_size == member.size, 'Truncated APK export file')
                target.chmod(0o644)
    except (OSError, EOFError, tarfile.TarError, UnicodeError) as error:
        raise BuildError('Cannot extract image-input APK') from error
    require(metadata and metadata.get('pkgname') == package.name
            and metadata.get('pkgver') == package.apk_version
            and metadata.get('arch') in (package.architecture, 'noarch'),
            'Downloaded APK identity differs from the selected image')
    _verified_export(destination, package)
    return destination


def _verified_export(destination, package):
    bundle = Bundle(destination)
    require(bundle.machine == package.machine and bundle.profile == package.profile,
            'Downloaded export belongs to another image')
    files = {path.relative_to(destination).as_posix() for path in destination.rglob('*') if path.is_file()}
    require(files == set(bundle.manifest['input_files']) | {'export.json'},
            'Downloaded export contains unlisted files')
    return bundle


class Repository:
    def __init__(self, url=DEFAULT_REPOSITORY, *, apk, public_key=None, cache=None):
        try:
            parts = urllib.parse.urlsplit(url)
            require(parts.scheme in ('http', 'https') and parts.hostname and not parts.username
                    and not parts.password and not parts.query and not parts.fragment,
                    'Expected an HTTP(S) repository URL without credentials')
        except ValueError as error:
            raise BuildError('Invalid repository URL') from error
        require(parts.scheme == 'https' or public_key is not None,
                'An HTTP repository requires an explicitly pinned public key')
        self.url = url.rstrip('/')
        self.apk = Path(apk).expanduser().absolute()
        require(self.apk.is_file() and os.access(self.apk, os.X_OK), 'The apk host tool is unavailable')
        self.public_key = Path(public_key).expanduser() if public_key is not None else None
        architecture = platform.machine().lower()
        self.architecture = {'amd64': 'x86_64', 'arm64': 'aarch64'}.get(architecture, architecture)
        require(self.architecture in ('x86_64', 'aarch64'), 'Unsupported APK client architecture')
        base = Path(cache).expanduser() if cache is not None else \
            Path(os.environ.get('XDG_CACHE_HOME', Path.home() / '.cache')) / 'naos-image-generator'
        self.root = base.absolute() / hashlib.sha256(self.url.encode()).hexdigest()[:16]
        require(not self.root.is_symlink(), 'Invalid repository cache directory')
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.keys = self.root / 'keys'
        self.keys.mkdir(exist_ok=True, mode=0o700)
        require(not self.keys.is_symlink(), 'Invalid repository key directory')

    @contextmanager
    def _lock(self):
        descriptor = os.open(self.root / '.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'r+') as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            yield

    def _apk(self, *arguments):
        env = {}
        if 'SSL_CERT_FILE' not in os.environ:
            certificate = Path('/etc/ssl/certs/ca-certificates.crt')
            if certificate.is_file():
                env['SSL_CERT_FILE'] = str(certificate)
        if 'fetch' in arguments:
            try:
                result = subprocess.run([str(self.apk), *map(str, arguments)],
                    env=process_environment(env), stdin=subprocess.DEVNULL,
                    stdout=sys.stderr, stderr=sys.stderr, timeout=900)
            except (OSError, subprocess.TimeoutExpired) as error:
                raise BuildError('Cannot complete the image download') from error
            require(result.returncode == 0, 'Image download failed')
            return ''
        return run([self.apk, *arguments], env=env)

    def _key(self):
        target = self.keys / PUBLIC_KEY_NAME
        if self.public_key is not None:
            require(self.public_key.is_file() and not self.public_key.is_symlink(),
                    'APK public key must be an ordinary file')
            require(0 < self.public_key.stat().st_size <= 16384, 'Invalid APK public key size')
            content = self.public_key.read_bytes()
        elif target.is_file() and not target.is_symlink():
            return
        else:
            origin = urllib.parse.urlsplit(self.url)
            url = urllib.parse.urlunsplit((origin.scheme, origin.netloc, '/keys/' + PUBLIC_KEY_NAME, '', ''))
            with tempfile.TemporaryDirectory(dir=self.root, prefix='.key-') as temporary:
                downloaded = Path(temporary) / PUBLIC_KEY_NAME
                _download(url, downloaded, 16384)
                content = downloaded.read_bytes()
        require(0 < len(content) <= 16384 and re.fullmatch(
            rb'-----BEGIN PUBLIC KEY-----\r?\n(?:[A-Za-z0-9+/=]+\r?\n)+-----END PUBLIC KEY-----\r?\n?', content),
            'Invalid APK public key')
        require(not target.is_symlink(), 'Invalid cached APK public key')
        target.write_bytes(content)
        target.chmod(0o644)

    def list_packages(self):
        with self._lock():
            self._key()
            with tempfile.TemporaryDirectory(dir=self.root, prefix='.index-') as temporary:
                directory = Path(temporary)
                signed = directory / 'APKINDEX.tar.gz'
                _download(self.url + '/' + self.architecture + '/APKINDEX.tar.gz', signed, MAX_INDEX_BYTES)
                self._apk('--keys-dir', self.keys, 'index', '--no-warnings', '--merge', '--index', signed,
                          '--output', directory / 'verified-index.tar.gz')
                return [package for package in _index_packages(signed)
                        if package.architecture in (self.architecture, 'noarch')]

    def acquire(self, package):
        require(isinstance(package, Package) and package == _package(package.name, package.apk_version,
                                                                  package.architecture), 'Invalid selected image package')
        require(package.architecture in (self.architecture, 'noarch'), 'Selected package has another architecture')
        with self._lock():
            self._key()
            with tempfile.TemporaryDirectory(dir=self.root, prefix='.fetch-') as temporary:
                directory = Path(temporary)
                self._apk('--keys-dir', self.keys, '--repositories-file', '/dev/null',
                          '--repository', self.url, '--arch', self.architecture, '--no-cache',
                          'fetch', '--recursive', '--output', directory,
                          package.name + '=' + package.apk_version)
                downloaded = directory / package.filename
                require(downloaded.is_file() and not downloaded.is_symlink()
                        and 0 < downloaded.stat().st_size <= MAX_APK_BYTES, 'apk did not download the selected image')
                LOG.info('Verifying image signature')
                self._apk('--keys-dir', self.keys, 'verify', downloaded)
                target = self.root / 'inputs' / sha256(downloaded)
                require(not target.parent.is_symlink(), 'Invalid cached export parent')
                target.parent.mkdir(exist_ok=True)
                require(not target.is_symlink(), 'Invalid cached export directory')
                if target.exists():
                    LOG.info('Checking cached image files')
                    _verified_export(target, package)
                    return target
                extracted = directory / 'export'
                extracted.mkdir()
                LOG.info('Unpacking and checking image files')
                _extract(downloaded, extracted, package)
                extracted.rename(target)
                return target
