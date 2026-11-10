"""Printed commands reproduce wizard choices without another selection."""
from pathlib import Path
import shlex
from types import SimpleNamespace
import unittest

from naos_image_generator import cli, interactive
import test_interactive as interactive_tests


class RebuildCommandTests(unittest.TestCase):
    def setUp(self):
        self.fixture = interactive_tests.InteractiveCliTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def printed(self, result):
        self.assertEqual(result.status,0,result.error)
        lines = [line.lstrip() for line in result.error.splitlines() if line.lstrip().startswith('Command: ')]
        self.assertEqual(len(lines),1,result.error)
        tokens = shlex.split(lines[0].removeprefix('Command: '))
        return cli.parser().parse_args(tokens[1:])

    def test_default_build_command_repeats_image_options_and_can_replace_its_previous_output(self):
        result = self.fixture.run_wizard(['']*6)
        args = self.printed(result)
        self.assertEqual((args.command,args.image,args.image_version),
                         ('build','fixture-board-alpine-dev','0.0.3'))
        self.assertEqual(args.system_mib,200)
        self.assertFalse(any((args.ota,args.ota_only,args.sbom,args.burn_key_hash,args.efuse_loader)))
        self.assertIsNone(args.dtb)
        self.assertTrue(args.force)
        self.assertEqual(self.fixture.root/args.output,result.build.call_args.args[3])
        self.assertLess(result.error.index('Summary:'),result.error.index('Command: '))
        self.assertLess(result.error.index('Each system slot:'),result.error.index('Command: '))
        self.assertLess(result.error.index('Command: '),result.error.index('Start generation?'))
        self.assertLess(result.error.index('Command: '),result.error.index('Downloading Alpine'))
        self.assertNotIn('Command:',result.output)

    def test_production_build_command_repeats_ota_and_custom_capacity(self):
        result = self.fixture.run_wizard(['2','2','','n','150','','','',''],profile='production')
        args = self.printed(result)
        self.assertEqual(args.image,'fixture-board-alpine-prod')
        self.assertEqual(args.system_mib,150)
        self.assertTrue(args.ota and args.sbom)
        self.assertFalse(args.ota_only or args.burn_key_hash or args.efuse_loader)

    def test_updates_only_command_preserves_device_tree_and_has_no_capacity_prompt(self):
        dtb = self.fixture.root/'board/vision1.dtb'
        dtb.parent.mkdir()
        dtb.write_bytes(b'fixture; image constructor and tools are mocked')
        result = self.fixture.run_wizard(['','3','','2','',''])
        args = self.printed(result)
        self.assertTrue(args.ota and args.ota_only)
        self.assertEqual(self.fixture.root/args.dtb,dtb)
        self.assertIsNone(args.system_mib)

    def test_check_command_has_no_output_or_force_and_omits_unset_ota(self):
        result = self.fixture.run_wizard(['','4','',''])
        args = self.printed(result)
        self.assertEqual(args.command,'check')
        self.assertIsNone(args.ota)
        self.assertIsNone(args.ota_only)
        self.assertFalse(hasattr(args,'force'))

    def test_declining_confirmation_keeps_summary_command_without_downloading(self):
        result = self.fixture.run_wizard(['','','','','','n'])
        self.assertEqual(result.status,0,result.error)
        self.printed(result)
        self.assertLess(result.error.index('Command: '),result.error.index('Start generation?'))
        result.repository.acquire.assert_not_called()
        result.build.assert_not_called()

    def test_shell_metacharacters_and_optional_overrides_round_trip_without_execution(self):
        dtb = self.fixture.root/'board/vision 1;$(not-run).dtb'
        output = self.fixture.root/"output/firmware 'quoted' $value"
        args = cli.parser().parse_args(['build','--dtb',str(dtb),'--system-mib','150',
            '--boot-mib','50','--efuse-loader','--no-burn-key-hash','--sbom',
            '--ota','--no-ota-only','--build-id','custom-build','--epoch','123','--processors','2'])
        package = SimpleNamespace(name='fixture-board-alpine-prod',version='0.0.3')
        line = interactive.command_line(args,package,output,program=['./naos-image-generator.py'])
        parsed = cli.parser().parse_args(shlex.split(line)[1:])
        self.assertEqual(parsed.dtb,dtb)
        self.assertEqual(parsed.output,output)
        self.assertEqual((parsed.build_id,parsed.epoch,parsed.processors),('custom-build',123,2))
        self.assertEqual((parsed.system_mib,parsed.boot_mib),(150,50))
        self.assertTrue(parsed.efuse_loader and parsed.sbom and parsed.ota)
        self.assertFalse(parsed.burn_key_hash or parsed.ota_only)


if __name__ == '__main__':
    unittest.main()
