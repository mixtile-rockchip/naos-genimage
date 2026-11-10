import os
from pathlib import Path
import struct
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from naos_image_generator import apk_runtime as runtime
from naos_image_generator.common import BuildError


class ApkRuntimeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.toolset = self.root/'tools'
        for name in runtime._HOST_TOOLS:
            self.executable(self.toolset/'bin'/name)
        self.target = self.toolset/'targets/aarch64'
        self.target.mkdir(parents=True)
        (self.target/'fakeroot.apk').write_bytes(b'official fakeroot APK fixture')
        self.library(self.target/'libnaos-chown-compat.so')

    def executable(self, path):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('#!/bin/sh\nexit 0\n')
        path.chmod(0o755)
        return path

    def library(self, path, machine=183, elf_class=2):
        header = bytearray(64)
        header[:6] = b'\x7fELF'+bytes((elf_class, 1))
        struct.pack_into('<HH', header, 16, 3, machine)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(header)
        return path

    def resolved(self, **kwargs):
        with patch.object(runtime.platform, 'system', return_value='Linux'):
            return runtime.resolve_runtime(self.toolset, **kwargs)

    def test_resolves_host_and_target_assets_without_yocto_paths(self):
        resolved = self.resolved()
        for name in runtime._HOST_TOOLS:
            self.assertEqual(resolved[name], self.toolset/'bin'/name)
        self.assertEqual(resolved['fakeroot_apk'], self.target/'fakeroot.apk')
        self.assertEqual(resolved['ownership_library'], self.target/'libnaos-chown-compat.so')
        self.assertEqual((resolved['architecture'], resolved['proc_mode']), ('aarch64', 'auto'))

    def test_overrides_are_honored_and_invalid_explicit_override_does_not_fall_back(self):
        unshare = self.executable(self.root/'custom/unshare')
        fakeroot = self.root/'custom/fakeroot.apk'
        fakeroot.write_bytes(b'custom target helper')
        library = self.library(self.root/'custom/ownership.so')
        qemu = self.executable(self.root/'custom/qemu')
        resolved = self.resolved(overrides=dict(unshare=unshare, fakeroot_apk=fakeroot,
            ownership_library=library, qemu=qemu, mkimage='/unused/main-pipeline-tool'))
        self.assertEqual(resolved['unshare'], unshare)
        self.assertEqual(resolved['fakeroot_apk'], fakeroot)
        self.assertEqual(resolved['ownership_library'], library)
        self.assertEqual(resolved['qemu'], qemu)
        with self.assertRaises(BuildError):
            self.resolved(overrides={'qemu':self.root/'missing'})

    def test_bundled_qemu_is_preferred_but_not_required_for_existing_binfmt(self):
        bundled = self.executable(self.toolset/'bin/qemu-aarch64-static')
        self.assertEqual(self.resolved()['qemu'], bundled)
        bundled.unlink()
        with patch.object(runtime.shutil, 'which', return_value=None):
            self.assertIsNone(self.resolved()['qemu'])

    def test_missing_or_symlink_target_assets_fail(self):
        fakeroot = self.target/'fakeroot.apk'
        fakeroot.unlink()
        with self.assertRaisesRegex(BuildError, 'target fakeroot APK'):
            self.resolved()
        backing = self.root/'fakeroot.apk'
        backing.write_bytes(b'APK')
        fakeroot.symlink_to(backing)
        with self.assertRaisesRegex(BuildError, 'target fakeroot APK'):
            self.resolved()

    def test_ownership_library_must_match_the_target_elf_architecture(self):
        self.library(self.target/'libnaos-chown-compat.so', machine=62)
        with self.assertRaisesRegex(BuildError, 'architecture aarch64'):
            self.resolved()
        self.library(self.target/'libnaos-chown-compat.so', elf_class=1)
        with self.assertRaisesRegex(BuildError, 'architecture aarch64'):
            self.resolved()

    def test_preflight_uses_unprivileged_namespaces_and_does_not_register_binfmt(self):
        resolved = self.resolved()
        with patch.object(runtime.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stderr=b'')) as run, \
                patch.object(runtime, '_native_architecture', return_value=False), \
                patch.object(runtime, '_binfmt', return_value=True):
            self.assertIsNone(runtime.preflight(resolved))
        command = run.call_args.args[0]
        self.assertIn('--user', command)
        self.assertIn('--map-root-user', command)
        self.assertIn('--mount', command)
        self.assertIn('--ipc', command)
        self.assertNotIn('sudo', command)
        self.assertNotIn('docker', command)

    def test_denied_namespaces_fail_with_a_host_configuration_message(self):
        resolved = self.resolved()
        with patch.object(runtime.subprocess, 'run', return_value=SimpleNamespace(returncode=1, stderr=b'Operation not permitted')), \
                self.assertRaisesRegex(BuildError, 'Unprivileged user namespaces are unavailable'):
            runtime.preflight(resolved)

    def test_namespace_timeout_is_reported_as_build_error(self):
        with patch.object(runtime.subprocess, 'run', side_effect=subprocess.TimeoutExpired('unshare', 15)), \
                self.assertRaisesRegex(BuildError, 'Cannot check unprivileged user namespaces'):
            runtime.preflight(self.resolved())

    def test_cross_architecture_requires_binfmt_but_native_execution_does_not(self):
        resolved = self.resolved()
        with patch.object(runtime.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stderr=b'')), \
                patch.object(runtime, '_native_architecture', return_value=False), \
                patch.object(runtime, '_binfmt', return_value=False), \
                self.assertRaisesRegex(BuildError, 'QEMU/binfmt_misc'):
            runtime.preflight(resolved)
        with patch.object(runtime.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stderr=b'')), \
                patch.object(runtime, '_native_architecture', return_value=True), \
                patch.object(runtime, '_binfmt') as binfmt:
            runtime.preflight(resolved)
            binfmt.assert_not_called()

    def test_binfmt_must_be_enabled_and_keep_interpreter_open_for_chroot(self):
        directory = self.root/'binfmt'
        directory.mkdir()
        status = directory/'status'
        status.write_text('enabled\n')
        handler = directory/'qemu-aarch64'
        handler.write_text('enabled\ninterpreter /usr/libexec/qemu-aarch64\nflags: POCF\n')
        self.assertTrue(runtime._binfmt('aarch64', directory))
        handler.write_text('enabled\ninterpreter /usr/libexec/qemu-aarch64\nflags: POC\n')
        self.assertFalse(runtime._binfmt('aarch64', directory))
        handler.write_text('disabled\ninterpreter /usr/libexec/qemu-aarch64\nflags: F\n')
        self.assertFalse(runtime._binfmt('aarch64', directory))
        status.write_text('disabled\n')
        handler.write_text('enabled\ninterpreter /usr/libexec/qemu-aarch64\nflags: F\n')
        self.assertFalse(runtime._binfmt('aarch64', directory))


if __name__ == '__main__':
    unittest.main()
