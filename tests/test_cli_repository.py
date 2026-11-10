"""Test remote-image selection and CLI dispatch without downloading or building."""
from contextlib import contextmanager, redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import yaml

from naos_image_generator import cli
from test_cli import fixture_layout


class Terminal(io.StringIO):
    def isatty(self):
        return True


@contextmanager
def cwd(directory):
    previous = Path.cwd()
    os.chdir(directory)
    try:
        yield
    finally:
        os.chdir(previous)


class RepositoryCliTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.apk = self.root / 'apk'
        self.apk.write_text('#!/bin/sh\nexit 0\n')
        self.apk.chmod(0o755)
        self.source = self.root / 'downloaded-export'
        self.source.mkdir()

    def package(self, profile='development', version='1.0.0'):
        suffix = 'dev' if profile == 'development' else 'prod'
        return SimpleNamespace(name='fixture-board-alpine-'+suffix, version=version,
                               apk_version=version+'-r0', machine='fixture-board',
                               profile=profile, architecture='x86_64')

    def bundle(self, profile='development'):
        production = profile == 'production'
        return SimpleNamespace(root=self.source, machine='fixture-board', profile=profile,
            layout=fixture_layout(), bootloader={'capabilities': {'otp_key_hash_programming':True}},
            manifest={'version':'old-export-version', 'build_id':'export-build',
                      'source_date_epoch':1700000000, 'defaults':dict(secure_boot=production,
                       system_encryption=production, data_encryption=production, ota=False, sbom=production)})

    def main(self, arguments, stdin=None):
        output, error = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(error), \
                patch.object(cli.sys, 'stdin', stdin or io.StringIO()), \
                patch.object(cli, '_asset_root', return_value=self.root), \
                patch.object(cli, 'prepare_environment', return_value=None), \
                patch.object(cli, 'prepare_toolset', return_value=None):
            status = cli.main(arguments)
        return status, output.getvalue(), error.getvalue()

    def yaml(self, values):
        directory = self.root / 'configuration'
        directory.mkdir(exist_ok=True)
        filename = directory / 'generator.yml'
        filename.write_text(yaml.safe_dump(values))
        return filename

    def conventional_keys(self):
        for name in ('secure-boot/dev.key', 'secure-boot/dev.crt', 'secure-boot/dev.pubkey',
                     'ota/signing.key.pem', 'ota/signing.cert.pem', 'ssh-ca/ssh_ca_key.pub',
                     'system-encryption/system.key'):
            filename = self.root / 'key' / name
            filename.parent.mkdir(parents=True,exist_ok=True)
            filename.write_text('public test fixture\n')
        (self.root / '.tools').mkdir()
        (self.root / 'files').mkdir()

    def test_missing_image_in_noninteractive_use_fails_before_repository_access(self):
        with patch.object(cli,'Repository') as repository, patch.object(cli,'Bundle') as bundle:
            status,output,error = self.main(['build'])
        self.assertEqual((status,output),(1,''))
        self.assertIn('Specify --image',error)
        repository.assert_not_called()
        bundle.assert_not_called()

    def test_local_input_never_opens_repository(self):
        with patch.object(cli,'Repository') as repository, \
                patch.object(cli,'Bundle',return_value=self.bundle()), \
                patch.object(cli,'prepare_tools',return_value={}):
            status,output,error = self.main(['check',str(self.source)])
        self.assertEqual((status,error),(0,''))
        self.assertEqual(json.loads(output)['status'],'ok')
        repository.assert_not_called()

    def test_image_overrides_yaml_input_and_respects_cli_and_yaml_path_bases(self):
        package = self.package()
        filename = self.yaml(dict(input='unused-local', apk='yaml-apk', apk_key='repo.pub',
                                  cache_dir='cache', repository='https://unused.example/repository'))
        with patch.object(cli,'Repository') as factory, \
                patch.object(cli,'Bundle',return_value=self.bundle()) as bundle, \
                patch.object(cli,'prepare_tools',return_value={}) as prepare:
            repository = factory.return_value
            repository.list_packages.return_value = [package]
            repository.acquire.return_value = self.source
            status,_,error = self.main(['check','-c',str(filename),'--image',package.name,
                '--image-version','1.0.0','--repository','https://packages.naos.ai/repository',
                '--apk',str(self.apk)])
        self.assertEqual(status,0,error)
        bundle.assert_called_once_with(self.source)
        factory.assert_called_once_with(url='https://packages.naos.ai/repository',apk=self.apk,
                                      public_key=filename.parent/'repo.pub',cache=filename.parent/'cache')
        repository.acquire.assert_called_once_with(package)
        self.assertEqual(prepare.call_args.args[0]['version'],'1.0.0')

    def test_explicit_local_input_and_remote_image_are_rejected_without_network(self):
        with patch.object(cli,'Repository') as factory:
            status,_,error = self.main(['check',str(self.source),'--image',self.package().name])
        self.assertEqual(status,1)
        self.assertIn('either an export directory or --image',error)
        factory.assert_not_called()

    def test_interactive_selection_uses_clean_versions_defaults_and_output(self):
        packages = [self.package(),self.package('production')]
        self.conventional_keys()
        with cwd(self.root), patch.object(cli,'Repository') as factory, \
                patch.object(cli,'Bundle',return_value=self.bundle('production')), \
                patch.object(cli,'prepare_tools',return_value={}) as prepare, \
                patch.object(cli,'build',return_value={'version':'1.0.0','files':{},'ota':False,'sbom':{}}) as build:
            factory.return_value.list_packages.return_value = packages
            factory.return_value.acquire.return_value = self.source
            status,output,error = self.main(['build','--apk',str(self.apk)], Terminal('invalid\n7\n2\n'))
        self.assertEqual(status,0,error)
        self.assertIn('Available images:',error)
        self.assertIn('fixture-board  production  1.0.0',error)
        self.assertNotIn('-r0',error)
        factory.return_value.acquire.assert_called_once_with(packages[1])
        options = prepare.call_args.args[0]
        self.assertEqual(options['signing']['key'],self.root/'key/secure-boot/dev.key')
        self.assertEqual(options['system_key_file'],self.root/'key/system-encryption/system.key')
        self.assertEqual(options['toolset'],self.root/'.tools')
        self.assertEqual(options['overlays'],[self.root/'files'])
        self.assertEqual(build.call_args.args[3],self.root/'output/fixture-board/production/1.0.0')
        self.assertEqual(json.loads(output)['version'],'1.0.0')

    def test_noninteractive_ambiguous_image_requires_a_version_without_fetching_apk(self):
        packages = [self.package(version='1.0.0'),self.package(version='1.1.0')]
        with patch.object(cli,'Repository') as factory:
            factory.return_value.list_packages.return_value = packages
            status,_,error = self.main(['check','--image',packages[0].name,'--apk',str(self.apk)])
        self.assertEqual(status,1)
        self.assertIn('--image-version',error)
        factory.return_value.acquire.assert_not_called()

    def test_replacement_ota_certificate_becomes_trust_unless_explicitly_overridden(self):
        self.conventional_keys()
        package = self.package()
        for explicit in (False, True):
            values = dict(image=package.name, image_version='1.0.0', apk=str(self.apk),
                          ota=True, keys={'ota': {'key':'replacement.key',
                                                'certificate':'replacement.crt'}})
            if explicit:
                values['ota_certificate'] = 'explicit-trust.crt'
            filename = self.yaml(values)
            for name in ('replacement.key', 'replacement.crt', 'explicit-trust.crt'):
                (filename.parent/name).write_text('public path-resolution fixture\n')
            with self.subTest(explicit=explicit), patch.object(cli,'Repository') as factory, \
                    patch.object(cli,'Bundle',return_value=self.bundle()), \
                    patch.object(cli,'prepare_tools',return_value={}) as prepare:
                factory.return_value.list_packages.return_value = [package]
                factory.return_value.acquire.return_value = self.source
                status,_,error = self.main(['check','-c',str(filename)])
            self.assertEqual(status,0,error)
            options = prepare.call_args.args[0]
            self.assertEqual(options['ota_signing']['certificate'],filename.parent/'replacement.crt')
            self.assertEqual(options['ota_certificate'],filename.parent/
                             ('explicit-trust.crt' if explicit else 'replacement.crt'))

    def test_firmware_version_override_wins_over_selected_package(self):
        package = self.package()
        filename = self.yaml({'image':package.name,'image_version':'1.0.0','apk':str(self.apk),
                              'version':'configured-firmware-version'})
        with patch.object(cli,'Repository') as factory, patch.object(cli,'Bundle',return_value=self.bundle()), \
                patch.object(cli,'prepare_tools',return_value={}) as prepare:
            factory.return_value.list_packages.return_value = [package]
            factory.return_value.acquire.return_value = self.source
            status,_,error = self.main(['check','-c',str(filename),'--firmware-version','explicit-version'])
        self.assertEqual(status,0,error)
        self.assertEqual(prepare.call_args.args[0]['version'],'explicit-version')

    def test_malformed_remote_configuration_is_rejected_before_network(self):
        for name in ('repository','image','image_version','apk','apk_key','cache_dir'):
            for value in (False,[],0,''):
                with self.subTest(name=name,value=value), patch.object(cli,'Repository') as factory:
                    filename = self.yaml({name:value})
                    status,_,error = self.main(['check','-c',str(filename)])
                    self.assertEqual(status,1)
                    self.assertIn(name+' must be a nonempty string',error)
                    factory.assert_not_called()


if __name__ == '__main__':
    unittest.main()
