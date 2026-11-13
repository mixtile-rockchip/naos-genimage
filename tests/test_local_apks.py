"""Local application APK fixtures and installer regression tests."""
import base64
import gzip
import hashlib
import io
import os
import json
from pathlib import Path, PurePosixPath
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from naos_image_generator import local_apks
from naos_image_generator.common import BuildError


def make_apk(path, name='example', version='1.0-r0', architecture='aarch64',
             files=None, scripts=None, depends=(), triggers=()):
    """Write an unsigned APK v2 accepted by the native Alpine APK tools.

    File values may be bytes or (bytes, mode, uid, gid) tuples. Scripts use
    APK lifecycle names such as ``post-install`` and retain executable modes.
    """
    path = Path(path)
    files = files if files is not None else {'usr/share/example/data': b'example payload\n'}
    scripts = scripts or {}

    def archive(entries, *, end=True):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w', format=tarfile.PAX_FORMAT) as tar:
            for member, content in entries:
                tar.addfile(member, None if content is None else io.BytesIO(content))
            length = tar.offset
        return output.getvalue() if end else output.getvalue()[:length]

    def member(filename, content, *, mode=0o644, uid=0, gid=0):
        info = tarfile.TarInfo(filename)
        info.mode, info.uid, info.gid = mode, uid, gid
        info.size, info.mtime = len(content), 0
        return info, content

    entries, directories, installed_size = [], set(), 0
    for filename, contents in sorted(files.items()):
        content, mode, uid, gid = (contents, 0o644, 0, 0) if isinstance(contents, bytes) else contents
        for parent in reversed(PurePosixPath(filename).parents):
            directory = str(parent)
            if directory != '.' and directory not in directories:
                info = tarfile.TarInfo(directory)
                info.type, info.mode, info.uid, info.gid = tarfile.DIRTYPE, 0o755, 0, 0
                entries.append((info, None))
                directories.add(directory)
        info, content = member(filename, content, mode=mode, uid=uid, gid=gid)
        info.pax_headers['APK-TOOLS.checksum.SHA1'] = hashlib.sha1(content, usedforsecurity=False).hexdigest()
        entries.append((info, content))
        installed_size += ((len(content) + 4095) // 4096) * 4096
    payload = gzip.compress(archive(entries), mtime=0)
    metadata = [
        ('pkgname', name), ('pkgver', version), ('pkgdesc', 'Local APK fixture'),
        ('url', 'https://www.mixtile.com'), ('builddate', '0'),
        ('packager', 'NAOS tests'), ('size', str(installed_size)),
        ('arch', architecture), ('origin', name), ('license', 'MIT'),
        *[('depend', dependency) for dependency in depends],
        *[('triggers', trigger) for trigger in triggers],
        ('datahash', hashlib.sha256(payload).hexdigest()),
    ]
    control = [member('.PKGINFO', ''.join(f'{key} = {value}\n' for key, value in metadata).encode())]
    control += [member('.' + key, value, mode=0o755) for key, value in sorted(scripts.items())]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(gzip.compress(archive(control, end=False), mtime=0) + payload)
    return path


class ApkFixtureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.apk = Path(__file__).resolve().parents[1] / '.tools/bin/apk'
        if not self.apk.is_file():
            self.skipTest('The native APK toolset is not installed')

    def native(self, *arguments):
        return subprocess.run([str(self.apk), *map(str, arguments)],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def rootfs(self):
        base = make_apk(self.root / 'fixture-base.apk', name='fixture-base', files={
            'etc/apk/arch': b'aarch64\n',
            'etc/original.conf': (b'original configuration\n', 0o640, 0, 0),
            'home/naos/data': (b'owned by target user\n', 0o600, 1000, 1000),
        })
        directory = self.root / 'base-rootfs'
        directory.mkdir()
        flags = ['--usermode'] if os.geteuid() != 0 else []
        result = self.native('--root', directory, '--arch', 'aarch64', '--no-network',
                             '--repositories-file', '/dev/null', '--allow-untrusted',
                             'add', '--no-scripts', '--initdb', *flags, base)
        self.assertEqual(result.returncode, 0, result.stderr)
        (directory / 'dev').mkdir()
        os.link(directory / 'etc/original.conf', directory / 'etc/original-alias.conf')
        (directory / 'home/naos/runtime-link').symlink_to('/run/runtime-target')

        def metadata(info):
            info.name = str(PurePosixPath(info.name))
            info.uid = info.gid = 1000 if info.name == 'home/naos/data' else 0
            info.uname = info.gname = ''
            return info

        output = self.root / 'base-rootfs.tar.gz'
        with tarfile.open(output, 'w:gz') as archive:
            archive.add(directory, arcname='.', filter=metadata)
            device = tarfile.TarInfo('dev/console')
            device.type, device.mode, device.devmajor, device.devminor = tarfile.CHRTYPE, 0o600, 5, 1
            archive.addfile(device)
        return output

    @staticmethod
    def spdx(name='example'):
        return dict(spdxVersion='SPDX-2.3', SPDXID='SPDXRef-DOCUMENT',
                    documentNamespace='https://naos.ai/sbom/' + name + '-1.0',
                    name=name, dataLicense='CC0-1.0', documentDescribes=['SPDXRef-App'],
                    packages=[dict(SPDXID='SPDXRef-App', name=name, versionInfo='1.0-r0',
                                   downloadLocation='NOASSERTION', filesAnalyzed=False)])

    def test_native_index_and_verification_accept_unsigned_lifecycle_fixture(self):
        package = make_apk(self.root / 'example-1.0-r0.apk', depends=('busybox',),
                           scripts={'post-install': b'#!/bin/sh\nprintf installed > /fixture-installed\n'})
        verified = self.native('--allow-untrusted', 'verify', package)
        self.assertEqual(verified.returncode, 0, verified.stderr)
        index = self.root / 'APKINDEX.tar.gz'
        indexed = self.native('--allow-untrusted', 'index', '--no-warnings', '--output', index, package)
        self.assertEqual(indexed.returncode, 0, indexed.stderr)
        with tarfile.open(index) as archive:
            text = archive.extractfile('APKINDEX').read().decode()
        for expected in ('P:example\n', 'V:1.0-r0\n', 'A:aarch64\n', 'D:busybox\n'):
            self.assertIn(expected, text)

    def test_modified_data_is_rejected_even_when_signature_checks_are_disabled(self):
        package = make_apk(self.root / 'example-1.0-r0.apk')
        data = bytearray(package.read_bytes())
        data[-12] ^= 1
        package.write_bytes(data)
        verified = self.native('--allow-untrusted', 'verify', package)
        self.assertNotEqual(verified.returncode, 0)

    def test_native_install_records_the_correct_payload_checksum(self):
        content = b'owned local application data\n'
        package = make_apk(self.root / 'example-1.0-r0.apk',
                           files={'usr/share/example/data': (content, 0o640, 1000, 1000)})
        target = self.root / 'target'
        target.mkdir()
        flags = ['--usermode'] if os.geteuid() != 0 else []
        result = self.native('--root', target, '--arch', 'aarch64', '--no-network',
                             '--repositories-file', '/dev/null', '--allow-untrusted',
                             'add', '--no-scripts', '--initdb', *flags, package)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((target / 'usr/share/example/data').read_bytes(), content)
        self.assertEqual((target / 'usr/share/example/data').stat().st_mode & 0o777, 0o640)
        database = (target / 'lib/apk/db/installed').read_text()
        self.assertIn('P:example\nV:1.0-r0\nA:aarch64\n', database)
        expected = base64.b64encode(hashlib.sha1(content, usedforsecurity=False).digest()).decode()
        self.assertIn('R:data\na:1000:1000:640\nZ:Q1' + expected, database)

    def test_native_inspect_preserves_package_identity_archive_name_and_digest(self):
        package = make_apk(self.root / 'business-application.apk', name='custom-application',
                           version='2.5-r3', architecture='noarch')
        record, = local_apks.inspect([package], self.root, self.apk)
        self.assertRegex(record.pop('identity'), r'^[QX][0-9][A-Za-z0-9+/=]+$')
        self.assertEqual(record, dict(name='custom-application', version='2.5-r3',
                         architecture='noarch', filename='business-application.apk',
                         sha256=hashlib.sha256(package.read_bytes()).hexdigest()))

    def test_native_inspect_rejects_two_versions_of_the_same_local_package(self):
        first = make_apk(self.root / 'old.apk', name='business', version='1.0-r0')
        second = make_apk(self.root / 'new.apk', name='business', version='2.0-r0')
        with self.assertRaisesRegex(BuildError, 'only one local APK per package name: business'):
            local_apks.inspect([first, second], self.root, self.apk)

    def test_install_delegates_immutable_snapshots_and_sbom_to_rootless_worker(self):
        source = self.rootfs()
        source_digest = hashlib.sha256(source.read_bytes()).hexdigest()
        app = make_apk(self.root / 'business.apk', name='business',
                       scripts={'post-install': b'#!/bin/sh\naddgroup -S business\n'})
        original = app.read_bytes()
        runtime = {'architecture': 'aarch64', 'description': 'mocked namespace runtime'}
        document = self.spdx('business')
        evidence = [dict(path='sbom.spdx.json', document=document, extracted=True,
                         package=dict(name='business', version='1.0-r0'), sha256='a' * 64)]
        output = self.root / 'generated-rootfs.tar.gz'
        events = []

        def preflight(selected):
            self.assertIs(selected, runtime)
            events.append('preflight')

        def namespace(seed, packages, records, work, *, apk, runtime, epoch):
            events.append('namespace')
            self.assertEqual(seed, source)
            self.assertEqual(epoch, 123456)
            self.assertEqual(apk, self.apk)
            self.assertEqual(len(packages), 1)
            self.assertNotEqual(packages[0], app)
            self.assertEqual(packages[0].read_bytes(), original)
            public_record = dict(records[0])
            self.assertRegex(public_record.pop('identity'), r'^[QX][0-9][A-Za-z0-9+/=]+$')
            self.assertEqual([public_record], [dict(name='business', version='1.0-r0', architecture='aarch64',
                filename='business.apk', sha256=hashlib.sha256(original).hexdigest())])
            return output, evidence

        with patch('naos_image_generator.apk_runtime.preflight', side_effect=preflight), \
                patch('naos_image_generator.apk_namespace.run_install', side_effect=namespace):
            result, records, documents = local_apks.install(source, [app], self.root / 'work',
                                                         apk=self.apk, runtime=runtime, epoch=123456)
        self.assertEqual(events, ['preflight', 'namespace'])
        self.assertEqual(result, output)
        self.assertEqual(documents, evidence)
        self.assertEqual(records[0]['filename'], 'business.apk')
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), source_digest)
        self.assertEqual(app.read_bytes(), original)

    def test_install_resolves_runtime_for_the_rootfs_architecture(self):
        source = self.rootfs()
        app = make_apk(self.root / 'application.apk')
        runtime = {'architecture': 'aarch64'}
        output = self.root / 'generated-rootfs.tar.gz'
        with patch('naos_image_generator.apk_runtime.resolve_runtime', return_value=runtime) as resolve, \
                patch('naos_image_generator.apk_runtime.preflight') as preflight, \
                patch('naos_image_generator.apk_namespace.run_install', return_value=(output, [])) as worker:
            result, _, evidence = local_apks.install(source, [app], self.root / 'work', apk=self.apk)
        self.assertEqual(result, output)
        self.assertEqual(evidence, [])
        self.assertEqual(resolve.call_args.kwargs, {'architecture': 'aarch64'})
        preflight.assert_called_once_with(runtime)
        self.assertIs(worker.call_args.kwargs['runtime'], runtime)

    def test_install_fails_without_skipping_scripts_when_namespace_is_unavailable(self):
        source = self.rootfs()
        app = make_apk(self.root / 'application.apk')
        with patch('naos_image_generator.apk_runtime.preflight',
                   side_effect=BuildError('user namespaces unavailable')), \
                patch('naos_image_generator.apk_namespace.run_install') as worker:
            with self.assertRaisesRegex(BuildError, 'user namespaces unavailable'):
                local_apks.install(source, [app], self.root / 'work', apk=self.apk, runtime={})
        worker.assert_not_called()
        self.assertFalse((self.root / 'work/local-apks/rootfs').exists())

    def test_install_propagates_package_lifecycle_script_failures(self):
        source = self.rootfs()
        app = make_apk(self.root / 'application.apk',
                       scripts={'post-install': b'#!/bin/sh\nexit 31\n'})
        with patch('naos_image_generator.apk_runtime.preflight'), \
                patch('naos_image_generator.apk_namespace.run_install',
                      side_effect=BuildError('post-install failed with exit 31')):
            with self.assertRaisesRegex(BuildError, 'post-install failed with exit 31'):
                local_apks.install(source, [app], self.root / 'work', apk=self.apk, runtime={})

    def test_install_rejects_foreign_package_architecture_before_namespace_setup(self):
        source = self.rootfs()
        app = make_apk(self.root / 'application.apk', architecture='x86_64')
        with patch('naos_image_generator.apk_runtime.resolve_runtime') as resolve, \
                patch('naos_image_generator.apk_namespace.run_install') as worker:
            with self.assertRaisesRegex(BuildError, 'does not match the image'):
                local_apks.install(source, [app], self.root / 'work', apk=self.apk)
        resolve.assert_not_called()
        worker.assert_not_called()


class LocalApkTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def file(self, name, data=b'fixture'):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def test_discover_empty_or_absent_selection_and_sorted_local_packages(self):
        self.assertEqual(local_apks.discover(None), ())
        directory = self.root / 'apks'
        directory.mkdir()
        self.assertEqual(local_apks.discover(directory), ())
        self.file('apks/README', b'Local application packages')
        second = self.file('apks/z-last.apk')
        first = self.file('apks/a-first.apk')
        self.file('apks/nested/ignored.apk')
        self.assertEqual(local_apks.discover(directory), (first, second))

    def test_discover_rejects_symlink_directory_and_symlink_or_directory_packages(self):
        directory = self.root / 'apks'
        directory.mkdir()
        linked_directory = self.root / 'linked-apks'
        linked_directory.symlink_to(directory, target_is_directory=True)
        with self.assertRaisesRegex(BuildError, 'ordinary directory'):
            local_apks.discover(linked_directory)
        outside = self.file('outside.apk')
        linked_package = directory / 'linked.apk'
        linked_package.symlink_to(outside)
        with self.assertRaisesRegex(BuildError, 'ordinary file'):
            local_apks.discover(directory)
        linked_package.unlink()
        (directory / 'nested.apk').mkdir()
        with self.assertRaisesRegex(BuildError, 'ordinary file'):
            local_apks.discover(directory)

    def evidence(self, data, *, path='usr/share/business/sbom.spdx.json',
                 package='business', selected='business', remove=None):
        directory = self.root / 'rootfs'
        filename = self.file('rootfs/' + path, data)
        name = PurePosixPath(path)
        database = self.file('rootfs/lib/apk/db/installed',
                             f'P:{package}\nV:1.0-r0\nA:aarch64\nF:{name.parent}\nR:{name.name}\n\n'.encode())
        records = [dict(name=selected, version='1.0-r0')]
        result = local_apks._take_sboms(directory, records, remove=remove)
        if result:
            self.assertFalse(filename.exists())
            self.assertNotIn('R:' + name.name, database.read_text())
        return result

    def test_collects_only_selected_package_owned_spdx_and_hashes_original_bytes(self):
        document = dict(spdxVersion='SPDX-2.3', SPDXID='SPDXRef-DOCUMENT',
                        documentNamespace='https://naos.ai/sbom/business-1.0')
        data = json.dumps(document, indent=2).encode() + b'\n'
        record, = self.evidence(data)
        self.assertEqual(record, dict(path='usr/share/business/sbom.spdx.json', document=document,
                         sha256=hashlib.sha256(data).hexdigest(),
                         package=dict(name='business', version='1.0-r0'), extracted=True))
        self.assertEqual(self.evidence(data, selected='another-package'), [])
        self.assertEqual(self.evidence(data, path='usr/share/business/config.json'), [])
        self.assertEqual(len(self.evidence(data, path='usr/share/business/BUSINESS.SBOM.JSON')), 1)
        self.assertEqual(len(self.evidence(data, path='sbom.json')), 1)

    def test_normal_summary_is_extracted_without_being_treated_as_an_spdx_document(self):
        data = b'{"name":"business","version":"1.0","summary":"not SPDX"}\n'
        self.assertEqual(self.evidence(data, path='business.sbom.json'), [])
        self.assertFalse((self.root / 'rootfs/business.sbom.json').exists())
        self.assertNotIn('R:business.sbom.json', (self.root / 'rootfs/lib/apk/db/installed').read_text())

    def test_extraction_removes_files_through_the_target_fakeroot_callback(self):
        document = dict(spdxVersion='SPDX-2.3', SPDXID='SPDXRef-DOCUMENT',
                        documentNamespace='https://naos.ai/sbom/business-1.0')
        removed = []

        def remove(name):
            removed.append(name)
            (self.root / 'rootfs' / name).unlink()

        record, = self.evidence(json.dumps(document).encode(), path='sbom.json', remove=remove)
        self.assertEqual(removed, ['sbom.json'])
        self.assertEqual(record['document'], document)

    def test_installed_sbom_rejects_malformed_json_and_unsupported_spdx(self):
        with self.assertRaisesRegex(BuildError, 'Invalid JSON in installed APK SBOM'):
            self.evidence(b'{malformed json')
        for data in (b'[]', b'null', b'{"spdxVersion":"SPDX-3.0"}', b'{"bomFormat":"CycloneDX"}'):
            with self.subTest(data=data), self.assertRaisesRegex(BuildError, 'must use SPDX 2.3 JSON'):
                self.evidence(data)

if __name__ == '__main__':
    unittest.main()
