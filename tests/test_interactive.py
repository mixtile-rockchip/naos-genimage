"""Exercise terminal choices without downloading, signing or building images."""
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from naos_image_generator import __version__, cli, interactive
from naos_image_generator.common import BuildError
from test_cli import fixture_layout
from test_cli_repository import Terminal, cwd


class InterruptTerminal(Terminal):
    def readline(self, *args):
        raise KeyboardInterrupt


class InteractiveCliTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.source = self.root / 'downloaded-export'
        self.source.mkdir()
        apk = self.root / '.tools/bin/apk'
        apk.parent.mkdir(parents=True)
        apk.write_text('#!/bin/sh\nexit 0\n')
        apk.chmod(0o755)
        for name in ('secure-boot/dev.key', 'secure-boot/dev.crt', 'secure-boot/dev.pubkey',
                     'ota/signing.key.pem', 'ota/signing.cert.pem', 'ssh-ca/ssh_ca_key.pub'):
            path = self.root / 'key' / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('public test fixture\n')
        system_key = self.root / 'key/system-encryption/system.key'
        system_key.parent.mkdir(parents=True)
        system_key.write_bytes(b'0123456789abcdef' * 4)

    def package(self, profile='development', version='0.0.3', machine='fixture-board'):
        suffix = 'dev' if profile == 'development' else 'prod'
        return SimpleNamespace(name=machine+'-alpine-'+suffix, version=version,
                               apk_version=version+'-r0', machine=machine,
                               profile=profile, architecture='x86_64')

    def bundle(self, profile='development'):
        production = profile == 'production'
        return SimpleNamespace(root=self.source, machine='fixture-board', profile=profile,
            layout=fixture_layout(), bootloader={'capabilities': {'otp_key_hash_programming': True}},
            manifest={'version': 'export-version', 'build_id': 'export-build',
                      'source_date_epoch': 1700000000, 'defaults': {
                          'secure_boot': production, 'system_encryption': production,
                          'data_encryption': production, 'ota': False, 'sbom': production}},
            summary=lambda: {'machine': 'fixture-board', 'profile': profile})

    def run_wizard(self, replies, *, profile='development', packages=None, stdin=None):
        output, error = io.StringIO(), io.StringIO()
        stream = stdin if stdin is not None else Terminal(''.join(value+'\n' for value in replies))
        bundle = self.bundle(profile)
        events = []
        prompts = []
        real_answer, real_settings = interactive.answer, cli.settings

        def reply(label, default=None):
            prompts.append((label, default))
            value = real_answer(label, default)
            if label.startswith(('Start generation?', 'Run checks?')) and value.lower() in ('y', 'yes'):
                events.append('confirmed')
            return value

        def configured(*args, **kwargs):
            events.append('settings')
            return real_settings(*args, **kwargs)

        def generated(_bundle, options, _tools, _destination, **_kwargs):
            events.append('build')
            return {'version': options['version'], 'files': {}, 'ota': options['ota'],
                    'ota_only': options.get('ota_only', False),
                    'sbom': {'fixture': True} if options['sbom'] else None}

        with ExitStack() as stack:
            stack.enter_context(cwd(self.root))
            stack.enter_context(redirect_stdout(output))
            stack.enter_context(redirect_stderr(error))
            stack.enter_context(patch.object(cli.sys, 'stdin', stream))
            stack.enter_context(patch.object(interactive, 'answer', side_effect=reply))
            stack.enter_context(patch.object(cli, '_asset_root', return_value=self.root))
            stack.enter_context(patch.object(cli, 'prepare_environment', return_value=None))
            stack.enter_context(patch.object(cli, 'prepare_toolset', return_value=None))
            factory = stack.enter_context(patch.object(cli, 'Repository'))
            constructor = stack.enter_context(patch.object(cli, 'Bundle',
                side_effect=lambda *_: events.append('bundle') or bundle))
            settings = stack.enter_context(patch.object(cli, 'settings', side_effect=configured))
            tools = stack.enter_context(patch.object(cli, 'prepare_tools',
                side_effect=lambda *_: events.append('tools') or {}))
            build = stack.enter_context(patch.object(cli, 'build', side_effect=generated))
            repository = factory.return_value
            repository.list_packages.side_effect = lambda: events.append('index') or packages or [self.package(), self.package('production')]
            repository.acquire.side_effect = lambda _: events.append('acquire') or self.source
            status = cli.main([])
        return SimpleNamespace(status=status, output=output.getvalue(), error=error.getvalue(),
                               factory=factory, repository=repository, constructor=constructor,
                               settings=settings, tools=tools, build=build, events=events, prompts=prompts)

    def test_no_argument_defaults_select_development_and_latest_version(self):
        packages = [self.package('production'), self.package(), self.package(version='0.0.2')]
        result = self.run_wizard([''] * 6, packages=packages)
        self.assertEqual(result.status, 0, result.error)
        result.repository.list_packages.assert_called_once_with()
        result.repository.acquire.assert_called_once_with(packages[1])
        result.tools.assert_called_once()
        result.build.assert_called_once()
        options = result.build.call_args.args[1]
        self.assertEqual((options['profile'], options['version']), ('development', '0.0.3'))
        self.assertFalse(any(options[key] for key in ('ota', 'sbom', 'burn_key_hash', 'secure_boot')))
        self.assertEqual(result.build.call_args.args[3], self.root/'output/fixture-board/development/0.0.3')
        self.assertEqual(result.build.call_args.kwargs, {'force': False})
        self.assertEqual(json.loads(result.output)['version'], '0.0.3')
        self.assertIn('Image type:', result.error)
        self.assertIn('Summary:', result.error)
        self.assertIn('OTP key hash programming: disabled', result.error)
        self.assertNotIn('-r0', result.error)
        self.assertIn('Alpine 0.0.3', result.error)
        self.assertIn('Each system slot: 200 MiB', result.error)
        sizes = {part['name']: part['size_mib'] for part in options['layout']['partitions']}
        self.assertEqual((sizes['system_a'], sizes['system_b']), (200, 200))
        defaults = [(label, default) for label, default in result.prompts
                    if label.startswith('Use default system A/B size')]
        self.assertEqual(len(defaults), 1)
        self.assertIn('200 MiB each', defaults[0][0])
        self.assertEqual(defaults[0][1], 'y')
        self.assertFalse(any(label == 'Each system slot (MiB)' for label, _ in result.prompts))
        self.assertEqual(result.events, ['index', 'confirmed', 'acquire', 'bundle', 'settings', 'tools', 'build'])
        self.assertLess(result.error.index('Summary:'), result.error.index('Downloading Alpine'))

    def test_production_both_ota_custom_system_capacity_and_sbom(self):
        packages = [self.package('production'), self.package('production', '0.0.2'), self.package()]
        result = self.run_wizard(['2', '2', '2', 'n', '150', '', '', '', ''],
                                 profile='production', packages=packages)
        self.assertEqual(result.status, 0, result.error)
        result.repository.acquire.assert_called_once_with(packages[1])
        options = result.tools.call_args.args[0]
        self.assertTrue(all(options[key] for key in ('ota', 'sbom', 'secure_boot', 'system_encryption', 'data_encryption')))
        self.assertFalse(options['burn_key_hash'])
        sizes = {part['name']: part['size_mib'] for part in options['layout']['partitions']}
        self.assertEqual([sizes[key] for key in ('boot_a', 'boot_b', 'system_a', 'system_b')], [50, 50, 150, 150])
        self.assertEqual(options['version'], '0.0.2')
        self.assertEqual(options['ota_signing']['key'], self.root/'key/ota/signing.key.pem')
        self.assertTrue(json.loads(result.output)['sbom'])
        self.assertIn('OTA: system + bootloader', result.error)

    def test_public_wizard_chooses_image_type_first_and_uses_repository_directly(self):
        result = self.run_wizard([''] * 6)
        self.assertEqual(result.status, 0, result.error)
        result.factory.assert_called_once()
        result.repository.list_packages.assert_called_once_with()
        result.repository.acquire.assert_called_once()
        transcript = result.error
        self.assertLess(transcript.index('Image type:'), transcript.index('What would you like'))
        self.assertEqual(transcript.count('Image type:'), 2)  # First menu and final summary.
        for implementation_detail in ('Input source', 'Yocto', 'YAML', 'export'):
            self.assertNotIn(implementation_detail.lower(), transcript.lower())
        self.assertIn('Full firmware image (.img)', transcript)
        self.assertIn('Full firmware image + system and bootloader updates', transcript)
        self.assertIn('System and bootloader updates', transcript)

    def test_rejecting_default_capacity_prompts_for_a_value_with_200_mib_default(self):
        result = self.run_wizard(['', '', '', 'n', '', '', ''])
        self.assertEqual(result.status, 0, result.error)
        options = result.build.call_args.args[1]
        sizes = {part['name']: part['size_mib'] for part in options['layout']['partitions']}
        self.assertEqual((sizes['system_a'], sizes['system_b']), (200, 200))
        self.assertEqual((sizes['boot_a'], sizes['boot_b']), (50, 50))
        self.assertIn('200 MiB each', result.error)
        self.assertIn('Each system slot: 200 MiB', result.error)
        self.assertIn(('Each system slot (MiB)', 200), result.prompts)
        self.assertEqual(result.events, ['index', 'confirmed', 'acquire', 'bundle', 'settings', 'tools', 'build'])

    def test_accepting_default_capacity_skips_custom_value_input(self):
        result = self.run_wizard(['', '', '', 'y', '', ''])
        self.assertEqual(result.status, 0, result.error)
        sizes = {part['name']: part['size_mib'] for part in result.build.call_args.args[1]['layout']['partitions']}
        self.assertEqual((sizes['system_a'], sizes['system_b']), (200, 200))
        self.assertFalse(any(label == 'Each system slot (MiB)' for label, _ in result.prompts))
        self.assertEqual(result.events, ['index', 'confirmed', 'acquire', 'bundle', 'settings', 'tools', 'build'])

    def test_rejecting_default_capacity_applies_custom_value_to_both_system_slots(self):
        result = self.run_wizard(['', '', '', 'n', '150', '', ''])
        self.assertEqual(result.status, 0, result.error)
        sizes = {part['name']: part['size_mib'] for part in result.build.call_args.args[1]['layout']['partitions']}
        self.assertEqual((sizes['system_a'], sizes['system_b']), (150, 150))
        self.assertEqual((sizes['boot_a'], sizes['boot_b']), (50, 50))
        self.assertIn(('Each system slot (MiB)', 200), result.prompts)
        self.assertEqual(result.events, ['index', 'confirmed', 'acquire', 'bundle', 'settings', 'tools', 'build'])

    def test_updates_only_menu_keeps_profile_and_skips_partition_size_prompts(self):
        for profile, replies in (
                ('development', ['', '3', '', '', '']),
                ('production', ['2', '3', '', '', '', '', ''])):
            with self.subTest(profile=profile):
                result = self.run_wizard(replies, profile=profile)
                self.assertEqual(result.status, 0, result.error)
                result.build.assert_called_once()
                options = result.build.call_args.args[1]
                self.assertEqual(options['profile'], profile)
                self.assertTrue(options['ota'] and options['ota_only'])
                self.assertEqual(result.build.call_args.args[3],
                                 self.root/'output/fixture-board'/profile/'0.0.3-updates')
                self.assertNotIn('Use default system A/B size', result.error)
                self.assertNotIn('Each system slot', result.error)
                self.assertNotIn('Each boot slot', result.error)
                self.assertTrue(json.loads(result.output)['ota'])
                self.assertEqual(options['sbom'], profile == 'production')

    def test_check_action_uses_selected_image_and_never_builds(self):
        checked = self.run_wizard(['', '4', '', ''])
        self.assertEqual(checked.status, 0, checked.error)
        checked.repository.acquire.assert_called_once()
        checked.tools.assert_called_once()
        checked.build.assert_not_called()
        self.assertEqual(json.loads(checked.output)['status'], 'ok')
        for implementation_detail in ('Input source', 'Yocto', 'YAML', 'export'):
            self.assertNotIn(implementation_detail.lower(), checked.error.lower())

    def test_nonterminal_no_arguments_fails_before_any_repository_or_build(self):
        result = self.run_wizard([], stdin=io.StringIO())
        self.assertEqual((result.status, result.output), (1, ''))
        self.assertIn('Interactive mode requires a terminal', result.error)
        result.factory.assert_not_called()
        result.constructor.assert_not_called()
        result.tools.assert_not_called()
        result.build.assert_not_called()

    def test_quit_eof_and_final_decline_do_not_prepare_or_build(self):
        for replies in (['q'], ['', '5'], [], ['', '1', '', 'y', '', 'n']):
            with self.subTest(replies=replies):
                result = self.run_wizard(replies)
                self.assertEqual((result.status, result.output), (0, ''))
                self.assertIn('cancelled', result.error)
                result.repository.acquire.assert_not_called()
                result.constructor.assert_not_called()
                result.settings.assert_not_called()
                result.tools.assert_not_called()
                result.build.assert_not_called()
        # EOF at the final confirmation is cancellation, not default approval.
        result = self.run_wizard(['', '1', '', 'y', ''])
        self.assertEqual(result.status, 0, result.error)
        result.repository.acquire.assert_not_called()
        result.constructor.assert_not_called()
        result.settings.assert_not_called()
        result.tools.assert_not_called()
        result.build.assert_not_called()

    def test_production_updates_final_decline_never_downloads_or_validates(self):
        result = self.run_wizard(['2', '3', '', '', '', '', 'n'], profile='production')
        self.assertEqual(result.status, 0, result.error)
        result.repository.list_packages.assert_called_once()
        result.repository.acquire.assert_not_called()
        result.constructor.assert_not_called()
        result.settings.assert_not_called()
        result.tools.assert_not_called()
        result.build.assert_not_called()
        self.assertNotIn('Downloading Alpine', result.error)
        self.assertIn('Version: Alpine 0.0.3', result.error)

    def test_production_efuse_defaults_off_after_output_and_before_final_confirmation(self):
        result = self.run_wizard(['2', '1', '', 'y', '', '', '', ''], profile='production')
        self.assertEqual(result.status, 0, result.error)
        options = result.build.call_args.args[1]
        self.assertFalse(options['burn_key_hash'] or options['efuse_loader'])
        primary = [(label, default) for label, default in result.prompts if label.startswith('Enable OTP/eFuse')]
        self.assertEqual(len(primary), 1)
        self.assertEqual(primary[0][1], 'n')
        self.assertNotIn('WARNING:', result.error)
        self.assertNotIn('Confirm permanent OTP/eFuse', result.error)
        self.assertLess(result.error.index('Output directory'), result.error.index(primary[0][0]))
        self.assertLess(result.error.index(primary[0][0]), result.error.index('Summary:'))
        self.assertEqual(result.events, ['index', 'confirmed', 'acquire', 'bundle', 'settings', 'tools', 'build'])

    def test_production_efuse_output_modes_need_both_confirmations(self):
        for mode, separate in (('1', True), ('2', False)):
            with self.subTest(mode=mode):
                result = self.run_wizard(['2', '1', '', 'y', '', '', 'y', mode, 'y', ''], profile='production')
                self.assertEqual(result.status, 0, result.error)
                options = result.build.call_args.args[1]
                self.assertEqual(options['efuse_loader'], separate)
                self.assertEqual(options['burn_key_hash'], not separate)
                self.assertNotEqual(options['efuse_loader'], options['burn_key_hash'])
                secondary = [(label, default) for label, default in result.prompts
                             if label.startswith('Confirm permanent OTP/eFuse')]
                self.assertEqual(len(secondary), 1)
                self.assertEqual(secondary[0][1], 'n')
                transcript = result.error
                self.assertLess(transcript.index('WARNING:'), transcript.index(secondary[0][0]))
                self.assertLess(transcript.index(secondary[0][0]), transcript.index('Start generation?'))
                self.assertLess(transcript.index('Start generation?'), transcript.index('Downloading Alpine'))
                for warning in ('permanent', 'cannot be undone', 'matching key', 'power stable',
                                'SPL boots and verifies', 'USB Loader alone does not confirm'):
                    self.assertIn(warning, transcript)
                if separate:
                    self.assertIn('loader-efuse.bin', transcript)
                    self.assertIn('idblock-efuse.bin', transcript)
                    self.assertIn('normal firmware and its update bundles keep OTP/eFuse programming disabled', transcript)

    def test_production_efuse_secondary_default_no_keeps_both_flags_disabled(self):
        for mode in ('1', '2'):
            with self.subTest(mode=mode):
                result = self.run_wizard(['2', '1', '', 'y', '', '', 'y', mode, '', ''], profile='production')
                self.assertEqual(result.status, 0, result.error)
                options = result.build.call_args.args[1]
                self.assertFalse(options['efuse_loader'] or options['burn_key_hash'])
                self.assertIn('OTP/eFuse programming remains disabled.', result.error)

    def test_efuse_secondary_eof_and_final_decline_never_download_or_validate(self):
        for replies in (['2', '1', '', 'y', '', '', 'y', '1'],
                        ['2', '1', '', 'y', '', '', 'y', '2', 'y', 'n']):
            with self.subTest(replies=replies):
                result = self.run_wizard(replies, profile='production')
                self.assertEqual(result.status, 0, result.error)
                result.repository.acquire.assert_not_called()
                result.constructor.assert_not_called()
                result.settings.assert_not_called()
                result.tools.assert_not_called()
                result.build.assert_not_called()
                self.assertNotIn('Downloading Alpine', result.error)

    def test_development_and_requirement_checks_never_offer_efuse(self):
        for profile, replies in (('development', ['']*6),
                                 ('development', ['', '4', '', '']),
                                 ('production', ['2', '4', '', ''])):
            with self.subTest(profile=profile, replies=replies):
                result = self.run_wizard(replies, profile=profile)
                self.assertEqual(result.status, 0, result.error)
                self.assertFalse(any(label.startswith(('Enable OTP/eFuse', 'Confirm permanent OTP/eFuse'))
                                     for label, _ in result.prompts))
                self.assertNotIn('WARNING:', result.error)
                options = result.tools.call_args.args[0]
                self.assertFalse(options['efuse_loader'] or options['burn_key_hash'])

    def test_check_final_decline_never_downloads_or_validates(self):
        result = self.run_wizard(['', '4', '', 'n'])
        self.assertEqual(result.status, 0, result.error)
        result.repository.acquire.assert_not_called()
        result.constructor.assert_not_called()
        result.settings.assert_not_called()
        result.tools.assert_not_called()
        result.build.assert_not_called()

    def test_keyboard_interrupt_uses_cancel_exit_without_side_effects(self):
        result = self.run_wizard([], stdin=InterruptTerminal())
        self.assertEqual((result.status, result.output), (130, ''))
        result.factory.assert_not_called()
        result.tools.assert_not_called()
        result.build.assert_not_called()

    def test_invalid_menu_boolean_and_sizes_repeat_until_valid(self):
        replies = ['invalid', '9', '1', '', '', 'maybe', 'n', '0', '-4', 'bad', '150', '', '']
        result = self.run_wizard(replies)
        self.assertEqual(result.status, 0, result.error)
        self.assertGreaterEqual(result.error.count('Enter a number from the list.'), 2)
        self.assertIn('Enter y or n.', result.error)
        self.assertEqual(result.error.count('Enter a positive integer.'), 3)
        sizes = {part['name']: part['size_mib'] for part in result.tools.call_args.args[0]['layout']['partitions']}
        self.assertEqual((sizes['boot_a'], sizes['system_a']), (50, 150))

    def test_repository_choice_groups_board_profile_and_clean_version(self):
        packages = [self.package(machine='first-board'), self.package('production', machine='second-board'),
                    self.package('production', '0.0.2', machine='second-board'),
                    self.package(machine='second-board')]
        error = io.StringIO()
        with redirect_stderr(error), patch.object(interactive.sys, 'stdin', Terminal('2\n2\n2\n')):
            selected = interactive.choose_package(packages)
        self.assertIs(selected, packages[2])
        self.assertIn('Board:', error.getvalue())
        self.assertIn('Image type:', error.getvalue())
        self.assertIn('Image version:', error.getvalue())
        self.assertNotIn('-r0', error.getvalue())

    def test_selected_profile_is_filtered_without_another_type_prompt(self):
        packages = [self.package('production'), self.package(), self.package('production', '0.0.2')]
        error = io.StringIO()
        with redirect_stderr(error), patch.object(interactive.sys, 'stdin', Terminal('2\n')):
            selected = interactive.choose_package(packages, profile='production')
        self.assertIs(selected, packages[2])
        self.assertNotIn('Image type:', error.getvalue())
        with self.assertRaises(BuildError), redirect_stderr(io.StringIO()), \
                patch.object(interactive.sys, 'stdin', Terminal()):
            interactive.choose_package([self.package()], profile='production')

    def test_unrelated_output_is_preserved_and_only_prior_generator_can_replace(self):
        unrelated = self.root/'personal'
        unrelated.mkdir()
        personal = unrelated/'keep.txt'
        personal.write_text('keep me')
        earlier = self.root/'earlier'
        earlier.mkdir()
        (earlier/'manifest.json').write_text(json.dumps({'generator': 'naos-image-generator', 'schema_version': 1}))
        args = cli.parser().parse_args(['build'])
        error = io.StringIO()
        with redirect_stderr(error), patch.object(interactive.sys, 'stdin', Terminal(str(unrelated)+'\n'+str(earlier)+'\ny\n')):
            selected = interactive.output_directory(args, self.root/'default')
        self.assertEqual(selected, earlier)
        self.assertTrue(args.force)
        self.assertEqual(personal.read_text(), 'keep me')
        self.assertIn('Directory is not empty', error.getvalue())

    def test_prior_output_replacement_defaults_to_no(self):
        earlier = self.root/'earlier'
        earlier.mkdir()
        (earlier/'manifest.json').write_text(json.dumps({'generator': 'naos-image-generator', 'schema_version': 1}))
        fresh = self.root/'fresh'
        args = cli.parser().parse_args(['build'])
        with redirect_stderr(io.StringIO()), patch.object(interactive.sys, 'stdin', Terminal(str(earlier)+'\n\n'+str(fresh)+'\n')):
            selected = interactive.output_directory(args, earlier)
        self.assertEqual(selected, fresh)
        self.assertFalse(args.force)
        self.assertTrue((earlier/'manifest.json').is_file())

    def test_source_entry_is_executable_and_explicit_help_version_still_work(self):
        entry = Path(__file__).resolve().parents[1]/'naos-image-generator.py'
        self.assertTrue(entry.stat().st_mode & stat.S_IXUSR)
        self.assertTrue(os.access(entry, os.X_OK))
        for argument, expected in (('--help', 'Build NAOS firmware'), ('--version', __version__)):
            with self.subTest(argument=argument):
                result = subprocess.run([str(entry), argument], capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(expected, result.stdout)
                self.assertNotIn('What would you like', result.stderr)


if __name__ == '__main__':
    unittest.main()
