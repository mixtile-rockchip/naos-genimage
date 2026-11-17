"""Keep the default Core manifest aligned with explicitly imported container APKs."""
import configparser
import hashlib
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

from naos_image_generator import filesystems as fs


CONFIG = 'etc/naos-core/device.ini'
DEFAULT = b'# Product configuration\n[container]\nenabled=false # User choice\naddress=/var/run/naosd.sock\nmanifest=/userdata/manifest.yml ; Default business\n\n[http]\nenabled=true\nlisten=127.0.0.1:8890\n'


class ContainerPreinstallTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='naos-preinstalled-container-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.bundle = self.root / 'bundle'
        self.bundle.mkdir()
        self.source = self.root / 'installed.tar.gz'
        self.records = [self.record('business')]
        self.write_archive(self.bundle / 'rootfs.tar.gz', [])

    @staticmethod
    def record(name, version='1.0-r0'):
        return dict(name='naos-app-' + name, version=version, architecture='aarch64')

    @staticmethod
    def manifest(name):
        return f'/var/lib/naos/containers/{name}/manifest.yml'

    @classmethod
    def startup_config(cls, configuration=DEFAULT):
        return configuration.replace(b'/userdata/manifest.yml', cls.manifest('business').encode()).replace(
            b'enabled=false', b'enabled=true')

    def write_archive(self, target, containers, *, configuration=DEFAULT, ordinary=False, missing_rootfs=False):
        database = 'P:base\nV:1.0-r0\nA:aarch64\nL:MIT\n\n'
        files = {}
        if configuration is not None:
            files[CONFIG] = (configuration, 42, 43, 0o640)
        for name in containers:
            base = f'var/lib/naos/containers/{name}'
            database += f'P:naos-app-{name}\nV:1.0-r0\nA:aarch64\nL:custom\nF:{base}\nR:manifest.yml\n\n'
            files[base + '/manifest.yml'] = (f'version: "0.1"\nmeta:\n  id: {name}\n'.encode(), 0, 0, 0o644)
            if not missing_rootfs:
                files[base + '/rootfs'] = (None, 0, 0, 0o755)
        if ordinary:
            database += 'P:ordinary\nV:1.0-r0\nA:aarch64\nL:MIT\nF:usr/share/ordinary\nR:data\n\n'
            files['usr/share/ordinary/data'] = (b'ordinary application\n', 0, 0, 0o644)
        files['lib/apk/db/installed'] = (database.encode(), 0, 0, 0o644)
        with tarfile.open(target, 'w:gz') as archive:
            for name, (content, uid, gid, mode) in files.items():
                entry = tarfile.TarInfo(name)
                entry.uid, entry.gid, entry.mode = uid, gid, mode
                if content is None:
                    entry.type = tarfile.DIRTYPE
                    archive.addfile(entry)
                else:
                    entry.size = len(content)
                    archive.addfile(entry, io.BytesIO(content))

    def prepare(self, **kwargs):
        options = dict(source_archive=self.source, local_apks=self.records)
        options.update(kwargs)
        return fs.prepare_rootfs(self.bundle, self.root / 'work', **options)

    @staticmethod
    def read_config(output):
        with tarfile.open(output) as archive:
            return archive.extractfile(CONFIG).read(), archive.getmember(CONFIG)

    def test_default_overlay_is_updated_after_copy_without_changing_other_settings_or_sources(self):
        self.write_archive(self.source, ['business'])
        overlay = self.root / 'files'
        config = overlay / CONFIG
        config.parent.mkdir(parents=True)
        config.write_bytes(DEFAULT)
        config.chmod(0o600)
        hashes = {p: hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in (self.source, self.bundle / 'rootfs.tar.gz', config)}
        output, inventory = self.prepare(overlays=[overlay])
        text, entry = self.read_config(output)
        self.assertEqual(text, self.startup_config())
        self.assertEqual((entry.uid, entry.gid, entry.mode), (42, 43, 0o600))
        self.assertIn(CONFIG, [item['path'] for item in inventory['generator_changes']])
        for path, digest in hashes.items():
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)

    def test_ordinary_apk_does_not_select_an_already_installed_container(self):
        self.write_archive(self.source, ['business'], ordinary=True)
        records = [dict(name='ordinary', version='1.0-r0', architecture='aarch64')]
        output, _ = self.prepare(local_apks=records)
        self.assertEqual(self.read_config(output)[0], DEFAULT)

    def test_missing_or_different_import_identity_does_not_trigger_configuration(self):
        self.write_archive(self.source, ['business'])
        for index, records in enumerate(([], [self.record('business', '2.0-r0')],
                                         [dict(name='naos-app-business', version='1.0-r0', architecture='noarch')])):
            output, _ = fs.prepare_rootfs(self.bundle, self.root / f'work-{index}',
                source_archive=self.source, local_apks=records)
            self.assertEqual(self.read_config(output)[0], DEFAULT)

    def test_explicit_custom_manifest_and_empty_value_are_preserved_even_when_unrelated(self):
        for index, value in enumerate(('/userdata/custom/manifest.yml', self.manifest('another'), '')):
            configuration = DEFAULT.replace(b'/userdata/manifest.yml', value.encode())
            self.write_archive(self.source, ['business'], configuration=configuration)
            output, _ = fs.prepare_rootfs(self.bundle, self.root / f'custom-{index}',
                source_archive=self.source, local_apks=self.records)
            self.assertEqual(self.read_config(output)[0], configuration)

    def test_overlay_custom_manifest_takes_precedence(self):
        self.write_archive(self.source, ['business'])
        overlay = self.root / 'files'
        config = overlay / CONFIG
        config.parent.mkdir(parents=True)
        custom = DEFAULT.replace(b'/userdata/manifest.yml', b'/userdata/my-product/manifest.yml')
        config.write_bytes(custom)
        output, _ = self.prepare(overlays=[overlay])
        self.assertEqual(self.read_config(output)[0], custom)
        self.assertEqual(config.read_bytes(), custom)

    def test_multiple_imported_containers_require_a_nondefault_explicit_manifest(self):
        self.write_archive(self.source, ['business', 'other'])
        records = [self.record('business'), self.record('other')]
        with self.assertRaisesRegex(fs.FilesystemError, r'Multiple container APKs.*files/etc/naos-core/device.ini') as error:
            self.prepare(local_apks=records)
        self.assertIn(self.manifest('business'), str(error.exception))
        self.assertIn(self.manifest('other'), str(error.exception))
        self.assertFalse((self.root / 'work/rootfs.tar.gz').exists())
        self.assertEqual(list((self.root / 'work').glob('.rootfs-*')), [])

    def test_multiple_imports_preserve_any_explicit_custom_manifest(self):
        records = [self.record('business'), self.record('other')]
        for index, value in enumerate((self.manifest('other'), '/userdata/external/manifest.yml', '')):
            configuration = DEFAULT.replace(b'/userdata/manifest.yml', value.encode())
            self.write_archive(self.source, ['business', 'other'], configuration=configuration)
            output, _ = fs.prepare_rootfs(self.bundle, self.root / f'multiple-{index}',
                source_archive=self.source, local_apks=records)
            self.assertEqual(self.read_config(output)[0], configuration)

    def test_missing_manifest_uses_the_builtin_default_and_enables_container(self):
        configuration = b'[container]\n# Keep this setting\nenabled=false\n\n[http]\nenabled=true\n'
        self.write_archive(self.source, ['business'], configuration=configuration)
        output, _ = self.prepare()
        text, entry = self.read_config(output)
        parsed = configparser.ConfigParser()
        parsed.read_string(text.decode())
        self.assertEqual(parsed.get('container', 'manifest'), self.manifest('business'))
        self.assertEqual(parsed.get('container', 'enabled'), 'true')
        self.assertIn(b'# Keep this setting\n', text)
        self.assertEqual((entry.uid, entry.gid, entry.mode), (42, 43, 0o640))

    def test_missing_section_or_file_gets_the_startup_settings(self):
        for index, configuration in enumerate((b'# Existing file\n[http]\nenabled=true', None)):
            self.write_archive(self.source, ['business'], configuration=configuration)
            output, _ = fs.prepare_rootfs(self.bundle, self.root / f'no-section-{index}',
                source_archive=self.source, local_apks=self.records)
            text, entry = self.read_config(output)
            parsed = configparser.ConfigParser()
            parsed.read_string(text.decode())
            self.assertEqual(dict(parsed['container']), {'enabled': 'true', 'manifest': self.manifest('business')})
            if configuration is not None:
                self.assertTrue(text.startswith(configuration))
            else:
                self.assertEqual((entry.uid, entry.gid, entry.mode), (0, 0, 0o600))

    def test_incomplete_container_layout_is_not_recognized(self):
        self.write_archive(self.source, ['business'], missing_rootfs=True)
        output, _ = self.prepare()
        self.assertEqual(self.read_config(output)[0], DEFAULT)

    def test_selected_payload_removed_by_customization_is_rejected(self):
        self.write_archive(self.source, ['business'])
        with self.assertRaisesRegex(fs.FilesystemError, 'regular manifest.yml and adjacent rootfs'):
            self.prepare(remove=[self.manifest('business').lstrip('/')])

    def test_crlf_and_inline_comments_are_retained(self):
        configuration = DEFAULT.replace(b'\n', b'\r\n')
        self.write_archive(self.source, ['business'], configuration=configuration)
        output, _ = self.prepare()
        self.assertEqual(self.read_config(output)[0], self.startup_config(configuration))

    def test_quoted_default_path_is_updated(self):
        configuration = DEFAULT.replace(b'manifest=/userdata/manifest.yml', b'manifest="/userdata/manifest.yml"')
        self.write_archive(self.source, ['business'], configuration=configuration)
        output, _ = self.prepare()
        self.assertEqual(self.read_config(output)[0], self.startup_config())

    def test_unknown_section_and_case_distinct_key_do_not_supply_the_manifest_value(self):
        configuration = b'[DEFAULT]\nmanifest=/userdata/unrelated/manifest.yml\n[container]\nManifest=/userdata/also-unrelated/manifest.yml\nenabled=false\n'
        self.write_archive(self.source, ['business'], configuration=configuration)
        output, _ = self.prepare()
        text, _ = self.read_config(output)
        self.assertTrue(text.startswith(configuration.replace(b'enabled=false', b'enabled=true')))
        self.assertTrue(text.endswith(b'manifest=' + self.manifest('business').encode() + b'\n'))

    def test_missing_enabled_is_added_and_already_enabled_is_not_duplicated(self):
        for index, value in enumerate((None, 'true')):
            configuration = b'[container]\nmanifest=/userdata/manifest.yml\n'
            if value is not None:
                configuration += b'enabled=true\n'
            self.write_archive(self.source, ['business'], configuration=configuration)
            output, _ = fs.prepare_rootfs(self.bundle, self.root / f'enabled-{index}',
                source_archive=self.source, local_apks=self.records)
            text, _ = self.read_config(output)
            parsed = configparser.ConfigParser()
            parsed.read_string(text.decode())
            self.assertEqual(parsed.get('container', 'manifest'), self.manifest('business'))
            self.assertEqual(parsed.get('container', 'enabled'), 'true')
            self.assertEqual(text.count(b'enabled='), 1)


if __name__ == '__main__':
    unittest.main()
