"""Exercise signed-index gating and safe APK export acquisition without root."""
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from naos_image_generator.common import BuildError
from naos_image_generator import repository


PUBLIC = b'-----BEGIN PUBLIC KEY-----\nZmFrZQ==\n-----END PUBLIC KEY-----\n'
NAME = 'fixture-board-alpine-dev'
VERSION = '1.0.0-r0'
PREFIX = 'usr/share/naos/image-inputs/development/fixture-board/'


def tar_bytes(entries, end=True):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w') as archive:
        for name, data in entries:
            member = tarfile.TarInfo(name)
            if isinstance(data, tarfile.TarInfo):
                member.type, member.linkname = data.type, data.linkname
                archive.addfile(member)
            else:
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        size = archive.offset
    return stream.getvalue() if end else stream.getvalue()[:size]


def export_files():
    files = {name: b'opaque fixture data' for name in ('rootfs.tar.gz', 'Image', 'fixture-board.dtb',
             'initramfs.cpio.gz', 'resource.img', 'naos-uboot-env.bin')}
    files['partition-layout.json'] = json.dumps({'compatible': 'fixture-board-v1', 'partitions': []}).encode()
    files['bootloader/bootloader.json'] = json.dumps({'machine': 'fixture-board',
                                                   'profile': 'development', 'capabilities': {}}).encode()
    manifest = dict(schema_version=1, stage='before-filesystem-compression-encryption-and-signing',
        machine='fixture-board', profile='development', version='1.0.0', build_id='fixture',
        kernel_release='6.12.69', bootloader='bootloader/bootloader.json',
        defaults=dict(secure_boot=False, system_encryption=False, data_encryption=False, ota=False, sbom=False),
        ota={'compatible': 'fixture-board-v1'}, initramfs={'needs_finalization': False},
        input_files={name: dict(size=len(data), sha256=hashlib.sha256(data).hexdigest())
                     for name, data in files.items()})
    files['export.json'] = json.dumps(manifest).encode()
    return files


def apk_bytes(files=None, extra=(), package_name=NAME):
    control = f'pkgname = {package_name}\npkgver = {VERSION}\narch = x86_64\n'.encode()
    return (gzip.compress(tar_bytes([('.SIGN.RSA256.naos-apk.rsa.pub', b'x' * 512)], end=False), mtime=0)
            + gzip.compress(tar_bytes([('.PKGINFO', control)], end=False), mtime=0)
            + gzip.compress(tar_bytes([(PREFIX + name, data) for name, data in (files or export_files()).items()]
                                      + list(extra)), mtime=0))


def index_bytes(text=None):
    text = text if text is not None else f'P:{NAME}\nV:{VERSION}\nA:x86_64\nS:100\nC:Q1fixture\n'
    return (gzip.compress(tar_bytes([('.SIGN.RSA256.naos-apk.rsa.pub', b'x' * 512)], end=False), mtime=0)
            + gzip.compress(tar_bytes([('APKINDEX', text.encode())]), mtime=0))


class FakeRepository(repository.Repository):
    def __init__(self, root, **kwargs):
        self.calls = []
        self.payload = apk_bytes()
        self.fail_index = self.fail_verify = False
        executable = root / 'apk'
        executable.write_text('#!/bin/sh\nexit 0\n')
        executable.chmod(0o755)
        key = root / 'public-key'
        key.write_bytes(PUBLIC)
        super().__init__('https://packages.example/repository', apk=executable,
                         public_key=key, cache=root / 'cache', **kwargs)
        self.architecture = 'x86_64'

    def _apk(self, *arguments):
        args = [str(value) for value in arguments]
        self.calls.append(args)
        if 'index' in args and self.fail_index:
            raise BuildError('apk index signature failed')
        if 'verify' in args and self.fail_verify:
            raise BuildError('apk package signature failed')
        if 'fetch' in args:
            directory = Path(args[args.index('--output') + 1])
            (directory / (NAME + '-' + VERSION + '.apk')).write_bytes(self.payload)
        return ''


class RepositoryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.repo = FakeRepository(self.root)

    def download(self, url, destination, limit):
        content = PUBLIC if '/keys/' in url else index_bytes()
        self.assertLessEqual(len(content), limit)
        Path(destination).write_bytes(content)

    def packages(self):
        with patch.object(repository, '_download', side_effect=self.download):
            return self.repo.list_packages()

    def test_native_apk_verifies_index_before_list_and_hides_only_r0(self):
        package, = self.packages()
        self.assertEqual((package.name, package.version, package.apk_version, package.profile),
                         (NAME, '1.0.0', VERSION, 'development'))
        args, = self.repo.calls
        self.assertIn('index', args)
        self.assertIn('--keys-dir', args)
        self.assertIn('--merge', args)
        self.assertNotIn('--allow-untrusted', args)
        self.repo.fail_index = True
        with self.assertRaisesRegex(BuildError, 'index signature'):
            self.packages()
        self.assertEqual(repository._package(NAME, '1.0.0-r1', 'x86_64').version, '1.0.0-r1')

    def test_actual_concatenated_apk_export_extracts_verified_opaque_files(self):
        package, = self.packages()
        result = self.repo.acquire(package)
        self.assertEqual((result / 'rootfs.tar.gz').read_bytes(), b'opaque fixture data')
        self.assertEqual({path.relative_to(result).as_posix() for path in result.rglob('*') if path.is_file()},
                         set(export_files()))
        fetch = next(args for args in self.repo.calls if 'fetch' in args)
        self.assertEqual(fetch[-1], NAME + '=' + VERSION)
        self.assertIn('--recursive', fetch)
        self.assertIn('--no-cache', fetch)
        self.assertFalse(any('add' in args for args in self.repo.calls))
        self.assertTrue(any('verify' in args for args in self.repo.calls))

    def test_relative_cache_uses_absolute_paths_for_native_apk(self):
        repository_client = repository.Repository('https://packages.example/repository',
            apk=self.repo.apk, public_key=self.repo.public_key,
            cache=Path(os.path.relpath(self.root / 'relative-cache')))
        self.assertTrue(repository_client.root.is_absolute())
        self.assertTrue(repository_client.keys.is_absolute())

    def test_bad_apk_signature_stops_before_any_export_is_cached(self):
        package, = self.packages()
        self.repo.fail_verify = True
        with self.assertRaisesRegex(BuildError, 'package signature'):
            self.repo.acquire(package)
        self.assertEqual(list(self.repo.root.glob('inputs/*')), [])

    def test_changed_export_bytes_or_wrong_identity_cannot_be_published_to_cache(self):
        package, = self.packages()
        files = export_files()
        files['Image'] = b'changed'
        for payload in (apk_bytes(files), apk_bytes(package_name='another-board-alpine-dev')):
            self.repo.payload = payload
            with self.assertRaises(BuildError):
                self.repo.acquire(package)
            self.assertEqual(list(self.repo.root.glob('inputs/*')), [])

    def test_links_traversal_unrelated_payload_and_unlisted_files_are_rejected(self):
        package, = self.packages()
        link = tarfile.TarInfo('link')
        link.type, link.linkname = tarfile.SYMTYPE, '/etc/passwd'
        for name, value in ((PREFIX + 'link', link), (PREFIX + '../escape', b'bad'),
                            ('usr/bin/evil', b'bad'), (PREFIX + 'unlisted', b'bad')):
            self.repo.payload = apk_bytes(extra=[(name, value)])
            with self.subTest(name=name), self.assertRaises(BuildError):
                self.repo.acquire(package)

    def test_cached_export_is_revalidated_including_extra_files(self):
        package, = self.packages()
        result = self.repo.acquire(package)
        self.assertEqual(self.repo.acquire(package), result)
        (result / 'extra').write_bytes(b'unlisted')
        with self.assertRaisesRegex(BuildError, 'unlisted'):
            self.repo.acquire(package)

    def test_index_ignores_unrelated_packages_but_rejects_duplicate_image_versions(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'index'
            text = f'P:other\nV:1.0\nA:x86_64\n\nP:{NAME}\nV:{VERSION}\nA:x86_64\n'
            path.write_bytes(index_bytes(text))
            self.assertEqual(len(repository._index_packages(path)), 1)
            path.write_bytes(index_bytes(text + '\n' + text.split('\n\n')[1]))
            with self.assertRaisesRegex(BuildError, 'Duplicate image'):
                repository._index_packages(path)

    def test_https_bootstrap_gets_only_public_key_and_http_requires_pin(self):
        self.repo.public_key = None
        with patch.object(repository, '_download', side_effect=self.download) as download:
            self.repo.list_packages()
        self.assertEqual(download.call_args_list[0].args[0],
                         'https://packages.example/keys/naos-apk.rsa.pub')
        self.assertEqual((self.repo.keys / repository.PUBLIC_KEY_NAME).read_bytes(), PUBLIC)
        with self.assertRaisesRegex(BuildError, 'explicitly pinned'):
            repository.Repository('http://packages.example/repository', apk=self.repo.apk, cache=self.root / 'other')
        with self.assertRaises(BuildError):
            repository.Repository('https://user:password@packages.example/repository',
                                  apk=self.repo.apk, cache=self.root / 'other')

    def test_private_material_and_symlink_key_are_rejected(self):
        self.repo.public_key.write_bytes(b'-----BEGIN PRIVATE KEY-----\nZmFrZQ==\n-----END PRIVATE KEY-----\n')
        with self.assertRaisesRegex(BuildError, 'public key'):
            self.packages()
        self.repo.public_key.unlink()
        target = self.root / 'public-target'
        target.write_bytes(PUBLIC)
        self.repo.public_key.symlink_to(target)
        with self.assertRaisesRegex(BuildError, 'ordinary file'):
            self.packages()


if __name__ == '__main__':
    unittest.main()
