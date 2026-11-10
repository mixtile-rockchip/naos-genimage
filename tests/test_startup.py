"""Startup probes do not need the bundled image toolset or host changes."""
import os
from contextlib import ExitStack
from pathlib import Path
import struct
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from naos_image_generator import startup
from naos_image_generator.common import BuildError


class StartupEnvironmentTests(unittest.TestCase):
    def environment(self):
        stack = ExitStack()
        stack.enter_context(patch.object(startup.sys, 'version_info', (3, 12, 3)))
        stack.enter_context(patch.object(startup.platform, 'system', return_value='Linux'))
        stack.enter_context(patch.object(startup.platform, 'machine', return_value='x86_64'))
        stack.enter_context(patch.object(startup.platform, 'libc_ver', return_value=('glibc','2.39')))
        self.import_module = stack.enter_context(patch.object(startup, 'import_module'))
        self.which = stack.enter_context(patch.object(startup.shutil, 'which', side_effect=lambda name:'/usr/bin/'+name))
        self.binfmt = stack.enter_context(patch('naos_image_generator.apk_runtime._binfmt', return_value=True))
        self.run = stack.enter_context(patch.object(startup.subprocess, 'run',
            return_value=SimpleNamespace(returncode=0, stderr=b'', stdout=b'')))
        self.addCleanup(stack.close)
        return stack

    def test_valid_host_checks_namespace_and_executes_an_arm64_probe_without_toolset(self):
        self.environment()
        result = startup.check_environment()
        self.assertEqual(result, dict(python='3.12.3',host='linux-x86_64',glibc='2.39',namespaces=True,aarch64=True))
        self.assertEqual(self.run.call_count,2)
        namespace = self.run.call_args_list[0].args[0]
        for value in ('--user','--map-root-user','--mount','--ipc'):
            self.assertIn(value,namespace)
        self.assertNotIn('sudo',namespace)
        self.assertNotIn('docker',namespace)
        executable = Path(self.run.call_args_list[1].args[0][0])
        self.assertEqual(executable.name,'check-aarch64')
        self.assertFalse(executable.exists())
        self.binfmt.assert_called_once_with('aarch64')

    def test_old_python_fails_before_imports_or_host_commands(self):
        self.environment()
        with patch.object(startup.sys, 'version_info', (3,10,14)), \
                self.assertRaisesRegex(BuildError,'Python 3.11'):
            startup.check_environment()
        self.import_module.assert_not_called()
        self.run.assert_not_called()

    def test_only_linux_x86_64_hosts_are_supported(self):
        self.environment()
        for system, architecture in (('Darwin','x86_64'),('Linux','aarch64'),('Windows','AMD64')):
            with self.subTest(system=system,architecture=architecture), \
                    patch.object(startup.platform,'system',return_value=system), \
                    patch.object(startup.platform,'machine',return_value=architecture), \
                    self.assertRaisesRegex(BuildError,'Linux x86_64'):
                startup.check_environment()
        self.run.assert_not_called()

    def test_glibc_requirement_is_checked_before_using_bundled_tools(self):
        self.environment()
        for libc, version in (('glibc','2.37'),('musl','1.2.5'),('',''),('glibc','unrecognized')):
            with self.subTest(libc=libc,version=version), \
                    patch.object(startup.platform,'libc_ver',return_value=(libc,version)), \
                    self.assertRaisesRegex(BuildError,'glibc 2.38'):
                startup.check_environment()
        self.run.assert_not_called()

    def test_missing_python_dependencies_give_installation_guidance(self):
        self.environment()
        for missing in ('yaml','Cryptodome.Cipher.AES'):
            def load(name):
                if name==missing:
                    raise ModuleNotFoundError(name)
                return object()
            self.import_module.side_effect = load
            with self.subTest(module=missing),self.assertRaisesRegex(BuildError,'python3-yaml and python3-pycryptodome'):
                startup.check_environment()
        self.run.assert_not_called()

    def test_missing_host_tools_are_reported_together(self):
        self.environment()
        self.which.side_effect = lambda name:None if name in ('unshare','mount') else '/usr/bin/'+name
        with self.assertRaisesRegex(BuildError,'Missing host tools: unshare, mount'):
            startup.check_environment()
        self.run.assert_not_called()

    def test_denied_namespaces_stop_before_arm64_execution(self):
        self.environment()
        self.run.return_value = SimpleNamespace(returncode=1,stderr=b'Operation not permitted',stdout=b'')
        with self.assertRaisesRegex(BuildError,'User namespace check.*Operation not permitted'):
            startup.check_environment()
        self.assertEqual(self.run.call_count,1)
        self.binfmt.assert_not_called()

    def test_missing_or_unusable_binfmt_fails_before_executing_target(self):
        self.environment()
        self.binfmt.return_value = False
        with self.assertRaisesRegex(BuildError,'binfmt_misc handler with the F flag'):
            startup.check_environment()
        self.assertEqual(self.run.call_count,1)

    def test_registered_but_broken_qemu_is_detected(self):
        self.environment()
        self.run.side_effect = [SimpleNamespace(returncode=0,stderr=b'',stdout=b''),
                                OSError('Exec format error')]
        with self.assertRaisesRegex(BuildError,'ARM64 execution check.*Exec format error'):
            startup.check_environment()

    def test_namespace_and_qemu_timeouts_become_friendly_errors(self):
        self.environment()
        self.run.side_effect = subprocess.TimeoutExpired('unshare',15)
        with self.assertRaisesRegex(BuildError,'User namespace check.*timed out'):
            startup.check_environment()

    def test_unwritable_temporary_storage_is_reported_without_a_traceback(self):
        self.environment()
        with patch.object(startup.tempfile,'TemporaryDirectory',side_effect=PermissionError('denied')), \
                self.assertRaisesRegex(BuildError,'verify writable temporary storage'):
            startup.check_environment()

    def test_host_probes_do_not_inherit_target_preload_or_python_paths(self):
        self.environment()
        with patch.dict(os.environ, dict(LD_PRELOAD='/target/fakeroot.so',LD_LIBRARY_PATH='/target/lib',
                                        PYTHONPATH='/target/python',PYTHONHOME='/target/home',PATH='/usr/bin')):
            startup.check_environment()
        for call in self.run.call_args_list:
            env=call.kwargs['env']
            self.assertFalse(any(name.startswith('LD_') for name in env))
            self.assertNotIn('PYTHONHOME',env)
            self.assertNotIn('PYTHONPATH',env)
            self.assertEqual(env['PATH'],'/usr/bin')

    def test_arm64_probe_is_a_bounded_static_linux_executable(self):
        data=startup._aarch64_exit_program()
        self.assertEqual(data[:7],b'\x7fELF\x02\x01\x01')
        self.assertEqual(struct.unpack_from('<HH',data,16),(2,183))
        self.assertEqual(len(data),132)
        self.assertEqual(data[-12:],struct.pack('<III',0xd2800000,0xd2800ba8,0xd4000001))


if __name__ == '__main__':
    unittest.main()
