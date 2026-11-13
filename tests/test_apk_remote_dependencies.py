"""Exercise APK dependency solving and repository trust with real host tools.

Only a temporary loopback repository is used. Target scripts are disabled by
the adapter, so these checks need neither namespaces nor ARM64 execution.
"""
from functools import partial
import http.server
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import threading
import unittest

from naos_image_generator import apk_namespace as ns
from naos_image_generator import local_apks
from naos_image_generator.common import BuildError
from test_local_apks import make_apk


class NativeTarget:
    """Run the worker's APK command against an isolated host-side database."""

    def __init__(self, root, apk, env):
        self.root, self.apk, self.env = root, apk, env

    def run(self, command, **kwargs):
        if command[0] != '/sbin/apk':
            raise AssertionError('Unexpected target command: ' + repr(command))
        arguments = [str(self.apk), '--root', str(self.root), '--arch', 'aarch64',
                     '--usermode', '--no-scripts']
        for argument in command[1:]:
            value = str(argument)
            if value.startswith('/.naos-build/'):
                value = str(self.root / value.lstrip('/'))
            arguments.append(value)
        result = subprocess.run(arguments, env=self.env, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if result.returncode or re.search(r'(^|\n)ERROR:', result.stdout):
            raise BuildError('Native APK dependency installation failed: ' + result.stdout)
        return result.stdout.strip()


class RepositoryHandler(http.server.SimpleHTTPRequestHandler):
    def log_request(self, code='-', size='-'):
        self.server.requests.append((self.command, self.path, code))

    def log_message(self, *arguments):
        pass


class RemoteDependencyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.apk = Path(__file__).resolve().parents[1] / '.tools/bin/apk'
        cls.openssl = shutil.which('openssl')
        if not cls.apk.is_file() or not cls.openssl:
            raise unittest.SkipTest('Native APK tools and OpenSSL are required')
        temporary = tempfile.TemporaryDirectory(prefix='naos-apk-test-signing-')
        cls.addClassCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        cls.private = directory / 'repository.rsa'
        cls.public = directory / 'repository.rsa.pub'
        cls.other_private = directory / 'other.rsa'
        cls.other_public = directory / 'other.rsa.pub'
        for private, public in ((cls.private, cls.public),
                                (cls.other_private, cls.other_public)):
            subprocess.run([cls.openssl, 'genpkey', '-algorithm', 'RSA', '-pkeyopt',
                            'rsa_keygen_bits:2048', '-out', str(private)],
                           check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            private.chmod(0o600)
            subprocess.run([cls.openssl, 'pkey', '-in', str(private), '-pubout',
                            '-out', str(public)], check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='naos-apk-remote-test-')
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.root = self.work / 'rootfs'
        self.root.mkdir()
        self.helper = self.root / '.naos-build'
        self.helper.mkdir()
        self.inputs = self.work / 'local-apks'
        self.inputs.mkdir()
        self.repository = self.work / 'site/repository/aarch64'
        self.repository.mkdir(parents=True)
        self.env = ns._environment(1700000000)
        self.target = NativeTarget(self.root, self.apk, self.env)
        base = make_apk(self.work / 'fixture-base-1.0-r0.apk', name='fixture-base',
                        files={'etc/apk/arch': b'aarch64\n'})
        self.seed_installed(base)
        keys = self.root / 'etc/apk/keys'
        keys.mkdir(exist_ok=True)
        self.trust_key = keys / 'repository.rsa.pub'
        self.trust_key.write_bytes(self.public.read_bytes())
        handler = partial(RepositoryHandler, directory=str(self.work / 'site'))
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), handler)
        server.daemon_threads = True
        server.requests = []
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.stop_server, server, thread)
        self.server = server
        self.repositories = self.root / 'etc/apk/repositories'
        self.repositories.write_text(
            '# Fixture repository; read from the selected rootfs.\n'
            f'http://127.0.0.1:{server.server_port}/repository/aarch64/Packages.adb\n')
        self.source_bytes = {}

    @staticmethod
    def stop_server(server, thread):
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    def seed_installed(self, package):
        result = subprocess.run([
            str(self.apk), '--root', str(self.root), '--arch', 'aarch64',
            '--usermode', '--no-scripts', '--no-network', '--allow-untrusted',
            '--repositories-file', '/dev/null', 'add', '--initdb', str(package),
        ], env=self.env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertEqual(result.returncode, 0, result.stdout)

    def local(self, name='example-app', *, version='1.0-r0', depends=(), payload=b'local'):
        package = make_apk(self.inputs / f'{name}-{version}.apk', name=name,
                           version=version, depends=depends,
                           files={f'usr/share/{name}/origin': payload})
        self.source_bytes[package] = package.read_bytes()
        return package

    def remote(self, name='remote-dependency', *, version='1.0-r0', depends=(),
               architecture='aarch64', payload=b'remote'):
        return make_apk(self.repository / f'{name}-{version}.apk', name=name,
                        version=version, depends=depends, architecture=architecture,
                        files={f'usr/share/{name}/origin': payload})

    def publish(self, *packages):
        # v3 indexes authenticate even unsigned v2 fixture packages through
        # their recorded identities, as normal APK repository trust permits.
        result = subprocess.run([
            str(self.apk), '--allow-untrusted', '--no-network',
            '--sign-key', str(self.private), 'mkndx',
            '-o', 'Packages.adb', *[package.name for package in packages],
        ], cwd=self.repository, env=self.env, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertEqual(result.returncode, 0, result.stdout)
        return self.repository / 'Packages.adb'

    def install(self, *packages):
        repositories_before = self.repositories.read_bytes()
        keys_before = {path.name: path.read_bytes()
                       for path in (self.root / 'etc/apk/keys').iterdir()}
        indexes = self.work / 'local-indexes'
        indexes.mkdir()
        records = local_apks.inspect(packages, indexes, self.apk)
        self.assertTrue(all(record.get('identity') for record in records))
        constraints, temporary_key = ns.prepare_local_repository(
            self.root, self.helper, packages, records, apk=self.apk, env=self.env)
        try:
            ns._add(self.target, constraints)
        finally:
            Path(temporary_key).unlink(missing_ok=True)
            self.assertEqual(self.repositories.read_bytes(), repositories_before)
            self.assertEqual(
                {path.name: path.read_bytes()
                 for path in (self.root / 'etc/apk/keys').iterdir()}, keys_before)
            for path, original in self.source_bytes.items():
                self.assertEqual(path.read_bytes(), original, str(path))
            world = (self.root / 'etc/apk/world').read_text()
            self.assertNotIn('@', world)
            self.assertNotIn('/.naos-build/', world)

    def requested_packages(self):
        return [path for method, path, _ in self.server.requests
                if method == 'GET' and path.partition('?')[0].endswith('.apk')]

    def assert_installed(self, name, version='1.0-r0'):
        database = (self.root / 'lib/apk/db/installed').read_text()
        self.assertIn(f'P:{name}\nV:{version}\n', database)

    def test_unsigned_local_application_fetches_remote_and_recursive_dependencies(self):
        leaf = self.remote('remote-leaf', architecture='noarch')
        dependency = self.remote(version='2.0-r0', depends=('remote-leaf=1.0-r0',))
        self.publish(dependency, leaf)
        application = self.local(depends=('remote-dependency>=2.0',))
        self.install(application)
        self.assert_installed('example-app')
        self.assert_installed('remote-dependency', '2.0-r0')
        self.assert_installed('remote-leaf')
        self.assertEqual((self.root / 'usr/share/remote-leaf/origin').read_bytes(), b'remote')
        requests = self.requested_packages()
        self.assertTrue(any('remote-dependency-2.0-r0.apk' in path for path in requests))
        self.assertTrue(any('remote-leaf-1.0-r0.apk' in path for path in requests))

    def test_satisfied_installed_dependency_is_not_downloaded_again(self):
        dependency = self.remote(payload=b'already-installed')
        self.seed_installed(dependency)
        self.publish(dependency)
        application = self.local(depends=('remote-dependency>=1.0',))
        self.install(application)
        self.assert_installed('example-app')
        self.assertEqual(self.requested_packages(), [])
        self.assertEqual((self.root / 'usr/share/remote-dependency/origin').read_bytes(),
                         b'already-installed')

    def test_local_identity_wins_over_remote_package_with_same_name_and_version(self):
        remote = self.remote('example-app', payload=b'remote-collision')
        self.publish(remote)
        local = self.local(payload=b'original-local-package')
        self.install(local)
        self.assert_installed('example-app')
        self.assertEqual((self.root / 'usr/share/example-app/origin').read_bytes(),
                         b'original-local-package')
        self.assertEqual(self.requested_packages(), [])

    def test_local_dependency_identity_wins_over_newer_remote_version(self):
        remote = self.remote('example-library', version='2.0-r0',
                             payload=b'newer-remote-library')
        self.publish(remote)
        application = self.local(depends=('example-library>=1.0',))
        library = self.local('example-library', version='1.0-r0',
                             payload=b'requested-local-library')
        self.install(application, library)
        self.assert_installed('example-app')
        self.assert_installed('example-library', '1.0-r0')
        self.assertNotIn('P:example-library\nV:2.0-r0\n',
                         (self.root / 'lib/apk/db/installed').read_text())
        self.assertEqual((self.root / 'usr/share/example-library/origin').read_bytes(),
                         b'requested-local-library')
        self.assertEqual(self.requested_packages(), [])

    def test_repository_signed_with_untrusted_key_is_rejected(self):
        dependency = self.remote()
        self.publish(dependency)
        self.trust_key.write_bytes(self.other_public.read_bytes())
        with self.assertRaises(BuildError):
            self.install(self.local(depends=('remote-dependency',)))
        self.assertTrue(any('Packages.adb' in path for _, path, _ in self.server.requests))
        self.assertFalse((self.root / 'usr/share/remote-dependency/origin').exists())

    def test_tampered_signed_repository_index_is_rejected(self):
        dependency = self.remote()
        index = self.publish(dependency)
        damaged = bytearray(index.read_bytes())
        damaged[len(damaged) // 2] ^= 1
        index.write_bytes(damaged)
        with self.assertRaises(BuildError):
            self.install(self.local(depends=('remote-dependency',)))
        self.assertFalse((self.root / 'usr/share/remote-dependency/origin').exists())

    def test_replaced_remote_payload_does_not_match_signed_index(self):
        dependency = self.remote()
        self.publish(dependency)
        self.remote(payload=b'changed-after-index-was-signed')
        with self.assertRaises(BuildError):
            self.install(self.local(depends=('remote-dependency',)))
        self.assertTrue(self.requested_packages())
        self.assertFalse((self.root / 'usr/share/remote-dependency/origin').exists())

    def test_missing_remote_dependency_is_rejected(self):
        self.publish(self.remote('unrelated-package'))
        with self.assertRaises(BuildError):
            self.install(self.local(depends=('missing-dependency>=2.0',)))
        self.assertFalse((self.root / 'usr/share/example-app/origin').exists())

    def test_conflicting_local_dependency_constraints_are_rejected(self):
        self.publish(self.remote(version='1.0-r0'), self.remote(version='2.0-r0'))
        first = self.local('first-application', depends=('remote-dependency=1.0-r0',))
        second = self.local('second-application', depends=('remote-dependency=2.0-r0',))
        with self.assertRaises(BuildError):
            self.install(first, second)
        self.assertFalse((self.root / 'usr/share/first-application/origin').exists())
        self.assertFalse((self.root / 'usr/share/second-application/origin').exists())


if __name__ == '__main__':
    unittest.main()
