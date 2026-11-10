"""Optional board DTBs are selected before image acquisition."""
import unittest
from unittest.mock import patch

from naos_image_generator import cli, config
from naos_image_generator.common import BuildError
import test_bootloader as bootloader_tests
import test_interactive as interactive_tests
import test_cli_repository as repository_tests


class BoardWizardTests(unittest.TestCase):
    def setUp(self):
        self.fixture = interactive_tests.InteractiveCliTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def dtb(self, name='vision1'):
        filename = self.fixture.root/'board'/(name+'.dtb')
        filename.parent.mkdir(exist_ok=True)
        filename.write_bytes(bootloader_tests.fdt({'model':name.encode()+b'\0'}))
        return filename

    def test_absent_or_empty_board_directory_adds_no_prompt(self):
        for exists in (False,True):
            if exists:
                directory = self.fixture.root/'board'
                directory.mkdir()
                (directory/'README').write_text('Place device trees here.\n')
            with self.subTest(exists=exists):
                result = self.fixture.run_wizard(['']*6)
                self.assertEqual(result.status,0,result.error)
                self.assertNotIn('\nDevice tree:',result.error)
                self.assertEqual(result.build.call_args.args[3],
                    self.fixture.root/'output/fixture-board/development/0.0.3')

    def test_custom_dtb_changes_output_name_before_download(self):
        selected = self.dtb()
        result = self.fixture.run_wizard(['','','','','2','',''])
        self.assertEqual(result.status,0,result.error)
        self.assertIn('Device tree:',result.error)
        self.assertIn('  1. fixture-board\n',result.error)
        self.assertIn('  2. vision1\n',result.error)
        self.assertIn('  Device tree: vision1\n',result.error)
        self.assertIn('  Board: vision1\n',result.error)
        self.assertEqual(result.settings.call_args.args[3]['dtb'],selected)
        self.assertEqual(result.build.call_args.args[3],
            self.fixture.root/'output/vision1/development/0.0.3')
        self.assertEqual(result.events,
            ['index','confirmed','acquire','bundle','settings','tools','build'])
        self.assertLess(result.error.index('Device tree:'),result.error.index('Summary:'))
        self.assertLess(result.error.index('Summary:'),result.error.index('Downloading Alpine'))

    def test_original_dtb_remains_the_default_when_custom_files_exist(self):
        self.dtb()
        result = self.fixture.run_wizard(['']*7)
        self.assertEqual(result.status,0,result.error)
        self.assertIsNone(result.settings.call_args.args[3]['dtb'])
        self.assertEqual(result.build.call_args.args[3],
            self.fixture.root/'output/fixture-board/development/0.0.3')

    def test_cancel_at_dtb_selection_never_acquires_an_image(self):
        self.dtb()
        result = self.fixture.run_wizard(['','','','','q'])
        self.assertEqual(result.status,0,result.error)
        result.repository.acquire.assert_not_called()
        result.constructor.assert_not_called()
        result.tools.assert_not_called()
        result.build.assert_not_called()


class BoardExplicitCliTests(unittest.TestCase):
    def setUp(self):
        self.fixture = repository_tests.RepositoryCliTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def test_explicit_dtb_path_reaches_settings_without_a_selection_prompt(self):
        selected = self.fixture.root/'vision1.dtb'
        selected.write_bytes(bootloader_tests.fdt({'model':b'vision1\0'}))
        with patch.object(cli,'Bundle',return_value=self.fixture.bundle()), \
                patch.object(cli,'prepare_tools',return_value={}), \
                patch.object(cli,'settings',wraps=cli.settings) as settings:
            status,_,error = self.fixture.main(['check',str(self.fixture.source),'--dtb',str(selected)])
        self.assertEqual(status,0,error)
        self.assertEqual(settings.call_args.args[3]['dtb'],selected)
        self.assertNotIn('Device tree:',error)

    def test_yaml_dtb_paths_keep_the_configuration_file_base(self):
        filename = self.fixture.yaml({'dtb':'boards/vision1.dtb'})
        selected = filename.parent/'boards/vision1.dtb'
        selected.parent.mkdir()
        selected.write_bytes(bootloader_tests.fdt({'model':b'vision1\0'}))
        with patch.object(cli,'Bundle',return_value=self.fixture.bundle()), \
                patch.object(cli,'prepare_tools',return_value={}), \
                patch.object(cli,'settings',wraps=cli.settings) as settings:
            status,_,error = self.fixture.main(['check',str(self.fixture.source),'-c',str(filename)])
        self.assertEqual(status,0,error)
        self.assertEqual(settings.call_args.args[1]['dtb'],'boards/vision1.dtb')
        self.assertEqual(settings.call_args.args[2],filename.parent)

    def test_yaml_dtb_rejects_non_path_values(self):
        for value in (None,False,12,[],{}):
            with self.subTest(value=value):
                filename = self.fixture.yaml({'dtb':value})
                with self.assertRaisesRegex(BuildError,'dtb must be a nonempty string'):
                    config.load(filename)


if __name__ == '__main__':
    unittest.main()
