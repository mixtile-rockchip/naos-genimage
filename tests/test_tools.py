import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from naos_image_generator.common import BuildError
from naos_image_generator import tools


class ToolResolutionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def executable(self, path):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#!/bin/sh\nexit 0\n")
        path.chmod(0o755)
        return path

    def test_resolution_priority_and_multicall_name(self):
        explicit = self.executable(self.root / "explicit" / "program")
        bundled = self.executable(self.root / "toolset" / "bin" / "program")
        host = self.executable(self.root / "host" / "program")
        alias = self.root / "toolset" / "bin" / "multicall"
        alias.symlink_to(bundled.name)
        with patch.dict(os.environ, {"PATH": str(host.parent)}):
            self.assertEqual(tools.resolve_tools({"program": explicit}, ["program"], bundled.parent.parent),
                             {"program": explicit})
            self.assertEqual(tools.resolve_tools({}, ["program"], bundled.parent.parent), {"program": bundled})
            self.assertEqual(tools.resolve_tools({}, ["program"]), {"program": host})
            self.assertEqual(tools.resolve_tools({}, ["multicall"], bundled.parent.parent)["multicall"], alias)

    def test_invalid_override_does_not_fall_back(self):
        with self.assertRaises(BuildError):
            tools.resolve_tools({"true": self.root / "missing"}, ["true"])
        with self.assertRaises(BuildError):
            tools.resolve_tools({}, ["../true"])

    def test_environment_is_local_and_has_no_empty_library_path(self):
        root = self.root / "toolset"
        (root / "bin").mkdir(parents=True)
        (root / "lib").mkdir()
        base = {"PATH": "/usr/bin", "HOME": "/example"}
        result = tools.tool_environment(root, base)
        self.assertEqual(result["PATH"], str(root / "bin") + ":/usr/bin")
        self.assertEqual(result["LD_LIBRARY_PATH"], str(root / "lib"))
        self.assertEqual(base, {"PATH": "/usr/bin", "HOME": "/example"})

    def test_portable_openssl_configuration_preserves_explicit_user_choice(self):
        root=self.root/'toolset'
        (root/'bin').mkdir(parents=True)
        configuration=root/'share/openssl/openssl.cnf'
        configuration.parent.mkdir(parents=True)
        configuration.write_text(tools._OPENSSL_CONFIG)
        base={'PATH':'/usr/bin'}
        self.assertEqual(tools.tool_environment(root,base)['OPENSSL_CONF'],str(configuration))
        self.assertNotIn('OPENSSL_CONF',base)
        explicit={'PATH':'/usr/bin','OPENSSL_CONF':'/custom/pkcs11.cnf'}
        self.assertEqual(tools.tool_environment(root,explicit)['OPENSSL_CONF'],'/custom/pkcs11.cnf')
        self.assertEqual(tools.tool_environment(None,base),base)


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64" and
                     all(shutil.which(name) for name in ("cc", "readelf", "patchelf", "ldconfig")),
                     "requires Linux x86_64 C compiler and ELF host tools")
class ToolImportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()

    def command(self, *args):
        return subprocess.run([str(arg) for arg in args], check=True, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE).stdout.decode()

    def fixture(self):
        (self.source / "leaf.c").write_text("int leaf(void) { return 42; }\n")
        (self.source / "middle.c").write_text("extern int leaf(void); int middle(void) { return leaf(); }\n")
        (self.source / "main.c").write_text(
            "#include <stdio.h>\nextern int middle(void); int main(void) { printf(\"%d\\n\", middle()); return 0; }\n")
        leaf = self.source / "libexample-leaf.so.1"
        middle = self.source / "libexample-middle.so.1"
        binary = self.source / "example"
        self.command("cc", "-shared", "-fPIC", self.source / "leaf.c", "-Wl,-soname,libexample-leaf.so.1", "-o", leaf)
        self.command("cc", "-shared", "-fPIC", self.source / "middle.c", leaf,
                     "-Wl,-soname,libexample-middle.so.1", "-Wl,-rpath," + str(self.source), "-o", middle)
        self.command("cc", self.source / "main.c", middle, "-Wl,-rpath," + str(self.source), "-o", binary)
        # Simulate native Yocto's absolute DT_NEEDED and uninheritable loader.
        self.command("patchelf", "--replace-needed", middle.name, middle, binary)
        self.command("patchelf", "--set-interpreter", "/missing/yocto/sysroot/ld-linux-x86-64.so.2", binary)
        return binary, middle, leaf

    def test_import_closes_dependencies_and_only_changes_copies(self):
        binary, middle, leaf = self.fixture()
        originals = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in (binary, middle, leaf)}
        destination = self.root / "imported"
        metadata = tools.import_toolset({"example": binary}, destination)
        self.assertEqual(self.command(destination / "bin" / "example"), "42\n")
        self.assertEqual(set(metadata["files"]), {"bin/example", "lib/" + middle.name, "lib/" + leaf.name})
        self.assertIn("libc.so.6", metadata["system_dependencies"])
        self.assertIsNotNone(metadata["host"]["minimum_glibc"])
        self.assertEqual(self.command("patchelf", "--print-rpath", destination / "bin" / "example").strip(), "$ORIGIN/../lib")
        self.assertEqual(self.command("patchelf", "--print-rpath", destination / "lib" / middle.name).strip(), "$ORIGIN")
        text = (destination / "toolset.json").read_text()
        self.assertNotIn(str(self.root), text)
        self.assertEqual(json.loads(text), metadata)
        for path, digest in originals.items():
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)

    def test_import_includes_target_runtime_assets_and_their_hashes(self):
        fakeroot = self.source/'fakeroot.apk'
        library = self.source/'libnaos-chown-compat.so'
        fakeroot.write_bytes(b'official target fakeroot APK fixture')
        library.write_bytes(b'target ownership helper fixture')
        destination = self.root/'with-target'
        metadata = tools.import_toolset({'true':Path(shutil.which('true'))},destination,
            target_assets={'aarch64':dict(fakeroot_apk=fakeroot,ownership_library=library)})
        for name,source in (('fakeroot.apk',fakeroot),('libnaos-chown-compat.so',library)):
            relative = 'targets/aarch64/'+name
            self.assertEqual((destination/relative).read_bytes(),source.read_bytes())
            self.assertEqual(metadata['files'][relative]['sha256'],hashlib.sha256(source.read_bytes()).hexdigest())
            self.assertEqual(metadata['files'][relative]['role'],'temporary-apk-install-helper')
        self.assertNotIn(str(self.root),json.dumps(metadata))

    def test_invalid_target_asset_configuration_fails_before_publication(self):
        for targets in ({'../outside':{}},{'aarch64':{'fakeroot_apk':self.source/'missing'}}):
            with self.subTest(targets=targets), self.assertRaises(BuildError):
                tools.import_toolset({'true':Path(shutil.which('true'))},self.root/'invalid',target_assets=targets)
            self.assertFalse((self.root/'invalid').exists())

    def test_explicit_library_directory_has_priority(self):
        binary, middle, leaf = self.fixture()
        alternate = self.root / "alternate"
        alternate.mkdir()
        (alternate / "leaf.c").write_text("int leaf(void) { return 99; }\n")
        self.command("cc", "-shared", "-fPIC", alternate / "leaf.c", "-Wl,-soname," + leaf.name,
                     "-o", alternate / leaf.name)
        destination = self.root / "imported"
        tools.import_toolset({"example": binary}, destination, [alternate])
        self.assertEqual(self.command(destination / "bin" / "example"), "99\n")

    def test_static_pie_is_copied_byte_exact_without_loader_patching(self):
        source = self.source / 'static-pie.c'
        source.write_text('#include <stdio.h>\nint main(void) { puts("static-pie"); return 0; }\n')
        executable = self.source / 'static-pie'
        try:
            self.command('cc', '-static-pie', source, '-o', executable)
        except subprocess.CalledProcessError:
            self.skipTest('host compiler has no static PIE runtime')
        info = tools._inspect(executable, Path(shutil.which('readelf')))
        self.assertTrue(info['dynamic'])
        self.assertEqual(info['needed'], [])
        self.assertIsNone(info['interpreter'])
        self.assertIsNone(info['soname'])
        original = executable.read_bytes()
        destination = self.root / 'static-toolset'
        with patch.object(tools, 'run', wraps=tools.run) as commands:
            metadata = tools.import_toolset({'apk': executable}, destination)
        self.assertFalse(any(Path(call.args[0][0]).name == 'patchelf'
                             for call in commands.call_args_list))
        self.assertEqual((destination / 'bin/apk').read_bytes(), original)
        self.assertEqual(self.command(destination / 'bin/apk'), 'static-pie\n')
        self.assertEqual(metadata['files']['bin/apk']['sha256'], hashlib.sha256(original).hexdigest())
        self.assertEqual(metadata['files']['bin/apk']['source_sha256'], metadata['files']['bin/apk']['sha256'])
        self.assertTrue(metadata['files']['bin/apk']['dynamic'])
        self.assertIsNone(metadata['host']['system_loader'])

    def test_nonempty_destination_is_untouched(self):
        destination = self.root / "imported"
        destination.mkdir()
        protected = destination / "keep"
        protected.write_bytes(b"unchanged")
        with self.assertRaises(BuildError):
            tools.import_toolset({"true": Path("/usr/bin/true")}, destination)
        self.assertEqual(protected.read_bytes(), b"unchanged")

    def test_importing_only_openssl_records_generated_public_configuration(self):
        # The importer's optional runtime data is selected by the declared
        # tool role. No certificate or private key is needed for this test.
        destination=self.root/'openssl-toolset'
        metadata=tools.import_toolset({'openssl':Path(shutil.which('true'))},destination)
        relative='share/openssl/openssl.cnf'
        configuration=destination/relative
        self.assertEqual(configuration.read_text(),tools._OPENSSL_CONFIG)
        self.assertEqual(metadata['files'][relative]['sha256'],hashlib.sha256(configuration.read_bytes()).hexdigest())
        self.assertTrue(metadata['files'][relative]['generated'])
        self.assertEqual(metadata['tools'],{'openssl':'bin/openssl'})

    def test_non_openssl_import_does_not_add_openssl_configuration(self):
        destination=self.root/'ordinary-toolset'
        metadata=tools.import_toolset({'true':Path(shutil.which('true'))},destination)
        self.assertFalse((destination/'share/openssl/openssl.cnf').exists())
        self.assertFalse(any(name.endswith('openssl.cnf') for name in metadata['files']))
        self.assertNotIn('OPENSSL_CONF',tools.tool_environment(destination,{'PATH':'/usr/bin'}))

    def test_non_elf_fails_without_publishing_destination(self):
        source = self.source / "script"
        source.write_text("#!/bin/sh\necho should-not-run\n")
        source.chmod(0o755)
        destination = self.root / "imported"
        with self.assertRaises(BuildError):
            tools.import_toolset({"script": source}, destination)
        self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
