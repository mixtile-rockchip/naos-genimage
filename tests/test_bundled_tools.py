"""Validate bundled host tools without executing their fixture payloads."""
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from naos_image_generator import bundled_tools
from naos_image_generator.common import BuildError


class BundledToolsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / '.tools'
        self.root.mkdir()
        self.records = {}
        names = {'bin/' + name for name in bundled_tools.REQUIRED_TOOLS}
        names.update(bundled_tools.REQUIRED_ASSETS)
        for name in sorted(names):
            filename = self.root / name
            filename.parent.mkdir(parents=True, exist_ok=True)
            data = ('fixture ' + name + '\n').encode()
            filename.write_bytes(data)
            filename.chmod(0o755 if name.startswith('bin/') else 0o644)
            self.records[name] = dict(path=name, size=len(data),
                                     sha256=hashlib.sha256(data).hexdigest(), source=filename.name)
        self.manifest = dict(schema_version=1, host=dict(os='linux', architecture='x86_64'),
                             files=self.records, tools={name:'bin/' + name
                             for name in bundled_tools.REQUIRED_TOOLS})
        self.write_manifest()

    def write_manifest(self):
        (self.root / 'toolset.json').write_text(json.dumps(self.manifest))

    def assert_invalid(self, expression=None):
        context = self.assertRaisesRegex(BuildError, expression) if expression else self.assertRaises(BuildError)
        with context as raised:
            bundled_tools.require_toolset(self.root)
        self.assertIn('including its .tools directory', str(raised.exception))

    def test_valid_tools_are_reused_without_changing_files(self):
        before = {p.relative_to(self.root):p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        self.assertEqual(bundled_tools.require_toolset(self.root), self.root)
        self.assertEqual(bundled_tools.validate_toolset(self.root), self.manifest)
        self.assertEqual(len(bundled_tools.REQUIRED_TOOLS), 13)
        self.assertIn('fdtget', bundled_tools.REQUIRED_TOOLS)
        self.assertEqual(before, {p.relative_to(self.root):p.read_bytes()
                                for p in self.root.rglob('*') if p.is_file()})

    def test_missing_directory_or_manifest_has_helpful_error(self):
        (self.root / 'toolset.json').unlink()
        self.assert_invalid('manifest')
        shutil.rmtree(self.root)
        self.assert_invalid('directory')

    def test_every_listed_file_is_checked(self):
        filename = self.root / 'extra-library.so'
        filename.write_bytes(b'library')
        self.records[filename.name] = dict(path=filename.name, size=7,
            sha256=hashlib.sha256(b'library').hexdigest())
        self.write_manifest()
        filename.write_bytes(b'changed')
        self.assert_invalid('checksum mismatch')

    def test_missing_or_changed_files_are_rejected(self):
        filename = self.root / 'bin/apk'
        contents = filename.read_bytes()
        filename.unlink()
        self.assert_invalid('missing or unsafe')
        filename.write_bytes(contents + b'extra byte')
        self.assert_invalid('checksum mismatch')

    def test_required_tools_and_assets_must_be_in_manifest(self):
        for name in ('bin/fdtget', *sorted(bundled_tools.REQUIRED_ASSETS)):
            record = self.records.pop(name)
            self.write_manifest()
            self.assert_invalid('missing')
            self.records[name] = record
        self.manifest['tools'].pop('apk')
        self.write_manifest()
        self.assert_invalid('missing: apk')

    def test_required_tools_are_executable(self):
        for role in sorted(bundled_tools.REQUIRED_TOOLS):
            filename = self.root / 'bin' / role
            filename.chmod(0o644)
            self.assert_invalid('not executable: ' + role)
            filename.chmod(0o755)

    def test_malformed_manifests_and_records_are_rejected(self):
        for value in (None, [], 'linux'):
            self.manifest['host'] = value
            self.write_manifest()
            self.assert_invalid('manifest')
        self.manifest['host'] = dict(os='linux', architecture='x86_64')
        self.records['bin/apk']['size'] = True
        self.write_manifest()
        self.assert_invalid('record')
        (self.root / 'toolset.json').write_text('{invalid')
        self.assert_invalid('JSON')

    def test_absolute_parent_and_unnormalized_paths_are_rejected(self):
        original = dict(self.records)
        for name in ('../outside', '/outside', 'bin/../outside', 'bin//apk', 'toolset.json'):
            self.manifest['files'] = {**original, name:dict(path=name, size=0, sha256='0'*64)}
            self.write_manifest()
            self.assert_invalid('tool path')

    def test_absolute_source_filename_is_rejected(self):
        self.records['bin/apk']['source'] = '/host/build/apk'
        self.write_manifest()
        self.assert_invalid('source filename')

    def test_file_and_parent_directory_symlinks_are_rejected(self):
        filename = self.root / 'bin/apk'
        filename.unlink()
        filename.symlink_to('dtc')
        self.assert_invalid('unsafe')
        filename.unlink()
        outside = self.root.parent / 'outside-bin'
        (self.root / 'bin').rename(outside)
        (self.root / 'bin').symlink_to(outside, target_is_directory=True)
        self.assert_invalid('unsafe')

    def test_toolset_root_symlink_is_rejected(self):
        actual = self.root.parent / 'actual-tools'
        self.root.rename(actual)
        self.root.symlink_to(actual, target_is_directory=True)
        self.assert_invalid('unsafe')


if __name__ == '__main__':
    unittest.main()
