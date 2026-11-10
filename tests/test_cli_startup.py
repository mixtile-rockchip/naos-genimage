"""Startup requirements are checked before menus, downloads or image work."""
from contextlib import redirect_stderr, redirect_stdout
import io
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from naos_image_generator import cli
from naos_image_generator.common import BuildError
from test_cli_repository import Terminal


class CliStartupTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def invoke(self, arguments, stdin=None):
        output, error = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(error), \
                patch.object(cli.sys,'stdin',stdin if stdin is not None else io.StringIO()), \
                patch.object(cli,'_asset_root',return_value=self.root):
            status = cli.main(arguments)
        return status,output.getvalue(),error.getvalue()

    def test_interactive_environment_failure_precedes_menus_and_repository_access(self):
        with patch.object(cli,'prepare_environment',side_effect=BuildError('namespace unavailable')) as environment, \
                patch.object(cli,'prepare_toolset') as toolset, \
                patch.object(cli.wizard,'start') as menu, patch.object(cli,'Repository') as repository:
            status,output,error = self.invoke([],Terminal(''))
        self.assertEqual((status,output),(1,''))
        self.assertIn('namespace unavailable',error)
        environment.assert_called_once_with()
        menu.assert_not_called()
        toolset.assert_not_called()
        repository.assert_not_called()

    def test_environment_check_runs_before_first_interactive_menu(self):
        events = []
        def menu(*args,**kwargs):
            events.append('menu')
            raise cli.wizard.Cancelled
        with patch.object(cli,'prepare_environment',side_effect=lambda:events.append('environment')), \
                patch.object(cli,'prepare_toolset') as toolset, \
                patch.object(cli.wizard,'start',side_effect=menu):
            status,_,_ = self.invoke([],Terminal(''))
        self.assertEqual(status,0)
        self.assertEqual(events,['environment','menu'])
        toolset.assert_not_called()

    def test_explicit_build_and_check_fail_before_loading_source_or_tools(self):
        for command in ('build','check'):
            with self.subTest(command=command), \
                    patch.object(cli,'prepare_environment',side_effect=BuildError('QEMU unavailable')) as environment, \
                    patch.object(cli,'prepare_toolset') as toolset, \
                    patch.object(cli,'_source') as source:
                status,_,error = self.invoke([command,str(self.root/'input')])
            self.assertEqual(status,1)
            self.assertIn('QEMU unavailable',error)
            environment.assert_called_once_with()
            source.assert_not_called()
            toolset.assert_not_called()

    def test_help_and_version_have_no_environment_or_download_side_effects(self):
        for arguments in (['--help'],['build','--help'],['--version']):
            with self.subTest(arguments=arguments), \
                    patch.object(cli,'prepare_environment') as environment, \
                    patch.object(cli,'prepare_toolset') as toolset:
                with self.assertRaises(SystemExit) as stopped:
                    self.invoke(arguments)
            self.assertEqual(stopped.exception.code,0)
            environment.assert_not_called()
            toolset.assert_not_called()

    def test_inspect_and_tools_import_skip_build_startup_preparation(self):
        with patch.object(cli,'prepare_environment') as environment, \
                patch.object(cli,'prepare_toolset') as toolset, \
                patch.object(cli,'Bundle',return_value=SimpleNamespace(summary=lambda:{'fixture':True})), \
                patch.object(cli,'_import') as importer:
            self.assertEqual(self.invoke(['inspect',str(self.root/'input')])[0],0)
            self.assertEqual(self.invoke(['tools','import','-c',str(self.root/'tools.yml')])[0],0)
        importer.assert_called_once()
        environment.assert_not_called()
        toolset.assert_not_called()

    def test_nonterminal_interactive_call_fails_before_startup_or_menu(self):
        with patch.object(cli,'prepare_environment') as environment, \
                patch.object(cli,'prepare_toolset') as toolset, \
                patch.object(cli.wizard,'start') as menu:
            status,_,error = self.invoke([])
        self.assertEqual(status,1)
        self.assertIn('terminal',error)
        environment.assert_not_called()
        toolset.assert_not_called()
        menu.assert_not_called()

    def test_prepare_environment_reports_status_and_preserves_stdout(self):
        output,error = io.StringIO(),io.StringIO()
        expected = {'python':'3.12.3','namespaces':True,'arm64':True}
        with patch.object(cli,'check_environment',return_value=expected) as check, \
                redirect_stdout(output),redirect_stderr(error):
            self.assertEqual(cli.prepare_environment(),expected)
        check.assert_called_once_with()
        self.assertEqual(output.getvalue(),'')
        self.assertIn('Checking environment...',error.getvalue())
        self.assertIn('Environment ready:',error.getvalue())

    def test_default_toolset_is_selected_from_the_project_directory(self):
        args = cli.parser().parse_args(['check','input'])
        target = self.root/'.tools'
        with patch.object(cli,'_asset_root',return_value=self.root), \
                patch.object(cli,'require_toolset',return_value=target) as ensure:
            self.assertEqual(cli.prepare_toolset(args,{},self.root),target)
        ensure.assert_called_once_with(target)

    def test_explicit_cli_toolset_takes_priority_over_bundled_tools(self):
        selected = self.root/'custom-tools'
        selected.mkdir()
        args = cli.parser().parse_args(['check','input','--tools-dir',str(selected)])
        with patch.object(cli,'require_toolset') as ensure:
            self.assertEqual(cli.prepare_toolset(args,{'tools_dir':'ignored-yaml-tools'},self.root),selected)
        ensure.assert_not_called()

    def test_explicit_yaml_toolset_respects_its_base(self):
        base = self.root/'configuration'
        args = cli.parser().parse_args(['check','input'])
        with patch.object(cli,'require_toolset') as ensure:
            self.assertEqual(cli.prepare_toolset(args,{'tools_dir':'../custom-tools'},base),self.root/'custom-tools')
        ensure.assert_not_called()


if __name__ == '__main__':
    unittest.main()
