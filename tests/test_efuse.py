"""OTP provisioning variants remain separate from ordinary firmware payloads."""
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from naos_image_generator import bootloader, config, pipeline
from naos_image_generator.common import BuildError, record, write_json
import test_cli
import test_pipeline


class EfuseSettingsTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_cli.CliTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def test_default_is_non_programming_and_each_mode_requires_production_support(self):
        fixture = self.fixture
        plain = pipeline.settings(fixture.bundle(), {}, fixture.config_dir)
        self.assertFalse(plain['burn_key_hash'] or plain['efuse_loader'])
        keys = fixture.keys()
        for flag in ('burn_key_hash','efuse_loader'):
            with self.subTest(flag=flag):
                selected = pipeline.settings(fixture.bundle(production=True), {'keys':keys, flag:True},
                                             fixture.config_dir)
                self.assertTrue(selected[flag])
                other = 'efuse_loader' if flag == 'burn_key_hash' else 'burn_key_hash'
                self.assertFalse(selected[other])
                with self.assertRaisesRegex(BuildError,'production SPL'):
                    pipeline.settings(fixture.bundle(), {flag:True}, fixture.config_dir)
                unsupported = fixture.bundle(production=True)
                unsupported.bootloader['capabilities']['otp_key_hash_programming'] = False
                with self.assertRaisesRegex(BuildError,'production SPL'):
                    pipeline.settings(unsupported, {'keys':keys, flag:True}, fixture.config_dir)

    def test_modes_are_exclusive_and_yaml_requires_a_boolean(self):
        fixture = self.fixture
        with self.assertRaisesRegex(BuildError,'either'):
            pipeline.settings(fixture.bundle(production=True),
                {'burn_key_hash':True,'efuse_loader':True},fixture.config_dir)
        for value in ('true',1,[]):
            filename = fixture.write_yaml({'efuse_loader':value})
            with self.subTest(value=value),self.assertRaisesRegex(BuildError,'efuse_loader'):
                config.load(filename)


class EfusePublicationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_pipeline.PipelineTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root

    def fixture_build(self, stack, captures):
        bundle = self.fixture.mock_image_build(stack,captures)
        bundle.profile = 'production'
        bundle.bootloader = {'capabilities':{'otp_key_hash_programming':True}}

        def firmware(bundle_root,work,output,metadata,tools,signing,os_inputs,epoch,burn=False):
            work,output = Path(work),Path(output)
            output.mkdir(parents=True,exist_ok=True)
            captures.setdefault('builds',[]).append((burn,work,output))
            value = b'programming-' if burn else b'normal-'
            files = {}
            for name in ('boot.img','uboot.img','idblock.bin','MiniLoaderAll.bin','uboot-slot.img','idblock-slot.img'):
                (output/name).write_bytes(value+name.encode())
                files[name] = dict(path=name,**record(output/name))
            verification = dict(schema_version=1,signed=True,otp_burn_key_hash=burn,
                host_programmed_otp=False,hardware_tested=False,machine='fixture-board',profile='production',
                source_revisions={'uboot':'fixture'},artifacts=files)
            write_json(output/'bootloader-verification.json',verification)
            return {'bootloader':verification}

        def factory(layout,payloads,destination):
            captures['factory_idblock'] = payloads['idblock.bin'].read_bytes()
            destination.write_bytes(b'factory-image-'+captures['factory_idblock'])

        def bundles(output,work,metadata,*args,**kwargs):
            output = Path(output)
            captures['ota_idblock'] = (output/'idblock-slot.img').read_bytes()
            result = {}
            for prefix in ('naos-bundle','naos-bootloader-bundle'):
                name = f'{prefix}-fixture-board-2.0-final.raucb'
                (output/name).write_bytes(captures['ota_idblock']+prefix.encode())
                result[name] = {'signature_verified':True,'payload_verified':True}
            return result

        stack.enter_context(patch.object(bootloader,'build_bootloader',side_effect=firmware))
        stack.enter_context(patch.object(pipeline,'assemble_factory',side_effect=factory))
        stack.enter_context(patch('naos_image_generator.ota.build_bundles',side_effect=bundles))
        return bundle

    def options(self,**extra):
        return self.fixture.options(profile='production',secure_boot=True,**extra)

    def assert_hashes(self,directory,manifest):
        self.assertEqual(set(manifest['files']),{p.name for p in directory.iterdir() if p.name!='manifest.json'})
        for name,item in manifest['files'].items():
            data = (directory/name).read_bytes()
            self.assertEqual((len(data),hashlib.sha256(data).hexdigest()),(item['size'],item['sha256']))

    def test_default_does_not_publish_or_build_a_provisioning_variant(self):
        captures = {}
        with ExitStack() as stack:
            bundle = self.fixture_build(stack,captures)
            result = pipeline.build(bundle,self.options(),{'sqfstar':'fixture'},self.root/'output')
        self.assertEqual([burn for burn,*_ in captures['builds']],[False])
        self.assertFalse(result['burn_key_hash'] or result['efuse_loader'])
        self.assertFalse(any('efuse' in name.lower() for name in result['files']))

    def test_separate_loader_never_enters_normal_factory_or_ota(self):
        captures = {}
        directory = self.root/'output'
        with ExitStack() as stack:
            bundle = self.fixture_build(stack,captures)
            result = pipeline.build(bundle,self.options(ota=True,efuse_loader=True),{'sqfstar':'fixture'},directory)
        self.assertEqual([burn for burn,*_ in captures['builds']],[False,True])
        self.assertNotEqual(captures['builds'][0][1],captures['builds'][1][1])
        self.assertTrue(captures['factory_idblock'].startswith(b'normal-'))
        self.assertTrue(captures['ota_idblock'].startswith(b'normal-'))
        self.assertTrue((directory/'MiniLoaderAll.bin').read_bytes().startswith(b'normal-'))
        self.assertTrue((directory/'loader-efuse.bin').read_bytes().startswith(b'programming-'))
        self.assertTrue((directory/'idblock-efuse.bin').read_bytes().startswith(b'programming-'))
        report = json.loads((directory/'efuse-verification.json').read_text())
        self.assertFalse(report['normal_image_programs_otp'] or report['host_programmed_otp'])
        self.assertEqual(set(report['artifacts']),{'loader-efuse.bin','idblock-efuse.bin'})
        for name,item in report['artifacts'].items():
            self.assertEqual(item['path'],name)
            self.assertEqual(item['sha256'],result['files'][name]['sha256'])
        self.assertFalse(result['burn_key_hash'])
        self.assertTrue(result['efuse_loader'])
        self.assertNotIn('spl-efuse.bin',result['files'])
        self.assert_hashes(directory,result)

    def test_embedded_burn_files_and_loader_bundle_are_explicitly_marked(self):
        captures = {}
        directory = self.root/'output'
        with ExitStack() as stack:
            bundle = self.fixture_build(stack,captures)
            result = pipeline.build(bundle,self.options(ota=True,burn_key_hash=True),{'sqfstar':'fixture'},directory)
        self.assertEqual([burn for burn,*_ in captures['builds']],[True])
        self.assertTrue(captures['factory_idblock'].startswith(b'programming-'))
        self.assertTrue(captures['ota_idblock'].startswith(b'programming-'))
        self.assertTrue((directory/'naos-fixture-board-production-2.0-final-efuse.img').is_file())
        self.assertTrue((directory/'naos-bootloader-bundle-fixture-board-2.0-final-efuse.raucb').is_file())
        self.assertTrue((directory/'naos-bundle-fixture-board-2.0-final.raucb').is_file())
        self.assertFalse((directory/'MiniLoaderAll.bin').exists())
        report = json.loads((directory/'bootloader-verification.json').read_text())
        self.assertNotIn('MiniLoaderAll.bin',report['artifacts'])
        self.assertEqual(report['artifacts']['loader-efuse.bin']['path'],'loader-efuse.bin')
        self.assertEqual(report['artifacts']['loader-efuse.bin']['sha256'],result['files']['loader-efuse.bin']['sha256'])
        self.assert_hashes(directory,result)

    def test_ota_only_separate_mode_keeps_factory_and_misc_absent_and_sbom_coherent(self):
        captures = {}
        directory = self.root/'updates'

        def sbom(inputs,destination,rootfs,initramfs,artifacts,metadata,**kwargs):
            self.assertIn('loader-efuse.bin',artifacts)
            self.assertIn('idblock-efuse.bin',artifacts)
            self.assertNotIn('misc.img',artifacts)
            self.assertNotIn('MiniLoaderAll.bin',artifacts)
            self.assertFalse(any(name.endswith('.img') for name in artifacts))
            self.assert_hashes(destination,{'files':artifacts})
            (destination/'final.spdx.json').write_text('{"spdxVersion":"SPDX-2.3"}\n')
            return {'file':'final.spdx.json'}

        with ExitStack() as stack:
            bundle = self.fixture_build(stack,captures)
            factory = stack.enter_context(patch.object(pipeline,'assemble_factory'))
            misc = stack.enter_context(patch.object(pipeline,'make_misc'))
            stack.enter_context(patch('naos_image_generator.sbom.render_sbom',side_effect=sbom))
            result = pipeline.build(bundle,self.options(ota=True,ota_only=True,sbom=True,efuse_loader=True),
                                    {'sqfstar':'fixture'},directory)
            factory.assert_not_called()
            misc.assert_not_called()
        self.assertTrue(result['ota_only'] and result['efuse_loader'])
        self.assertEqual(len(list(directory.glob('*.raucb'))),2)
        self.assert_hashes(directory,result)
        instructions = (directory/'EFUSE-INSTRUCTIONS.txt').read_text()
        self.assertIn('irreversible',instructions)
        self.assertIn('USB Download Boot alone is not proof',instructions)
        self.assertIn('restore the normal non-programming',instructions)
        self.assertNotIn(str(self.root),instructions)
        self.assertEqual(list(self.root.glob('.naos-*')),[])

    def test_failed_provisioning_does_not_replace_previous_generated_output(self):
        captures = {}
        directory = self.root/'output'
        directory.mkdir()
        (directory/'manifest.json').write_text('{"generator":"naos-image-generator","schema_version":1}\n')
        (directory/'keep.img').write_bytes(b'working-image')
        before = {p.name:p.read_bytes() for p in directory.iterdir()}
        with ExitStack() as stack:
            bundle = self.fixture_build(stack,captures)
            stack.enter_context(patch.object(bootloader,'publish_efuse_artifacts',side_effect=BuildError('provisioning failed')))
            with self.assertRaisesRegex(BuildError,'provisioning failed'):
                pipeline.build(bundle,self.options(efuse_loader=True),{'sqfstar':'fixture'},directory,force=True)
        self.assertEqual({p.name:p.read_bytes() for p in directory.iterdir()},before)
        self.assertEqual(list(self.root.glob('.naos-*')),[])


if __name__=='__main__':
    unittest.main()
