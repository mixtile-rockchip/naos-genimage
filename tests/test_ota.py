import configparser
import hashlib
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from naos_image_generator import common, ota
from naos_image_generator.common import BuildError
from naos_image_generator.tools import tool_environment


class OtaTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.metadata = dict(compatible='fixture-board-v1', version='2.0-test',
                             build_id='test-build', machine='fixture-board', epoch=1700000000)
        self.images = [('rootfs','system.img'),('boot','boot.img')]

    def extracted(self):
        directory = self.root / 'verified'
        directory.mkdir()
        parser = configparser.ConfigParser(interpolation=None)
        parser['update'] = {key:self.metadata[name] for key,name in
                            [('compatible','compatible'),('version','version'),('build','build_id')]}
        parser['bundle'] = {'format':'verity'}
        expected = {}
        for slot,filename in self.images:
            value = ('fixture-'+slot).encode()
            (directory/filename).write_bytes(value)
            expected[slot] = dict(sha256=hashlib.sha256(value).hexdigest(),size=len(value))
            parser['image.'+slot] = dict(filename=filename,type='raw',
                sha256=expected[slot]['sha256'],size=str(len(value)))
        self.write_manifest(directory,parser)
        return directory,parser,expected

    def write_manifest(self,directory,parser):
        with (directory/'manifest.raucm').open('w') as stream:
            parser.write(stream)

    def test_verified_manifest_records_order_and_checksums(self):
        directory,_,expected = self.extracted()
        result = ota._verify_extracted(directory,self.metadata,self.images,expected,'verity')
        self.assertEqual(result['installation_order'],['rootfs','boot'])
        self.assertEqual(result['images'][0]['rootfs']['sha256'],expected['rootfs']['sha256'])
        self.assertTrue(result['signature_verified'] and result['payload_verified'])

    def test_release_mismatch_or_reordered_images_is_rejected(self):
        directory,parser,expected = self.extracted()
        for key in ('compatible','version','build'):
            original = parser['update'][key]
            parser['update'][key] = 'other'
            self.write_manifest(directory,parser)
            with self.subTest(key=key),self.assertRaises(BuildError):
                ota._verify_extracted(directory,self.metadata,self.images,expected,'verity')
            parser['update'][key] = original
        boot = dict(parser['image.boot'])
        rootfs = dict(parser['image.rootfs'])
        parser.remove_section('image.boot');parser.remove_section('image.rootfs')
        parser['image.boot']=boot;parser['image.rootfs']=rootfs
        self.write_manifest(directory,parser)
        with self.assertRaisesRegex(BuildError,'order'):
            ota._verify_extracted(directory,self.metadata,self.images,expected,'verity')

    def test_modified_payload_cannot_match_only_its_edited_manifest(self):
        directory,parser,expected = self.extracted()
        value=b'changed boot'
        (directory/'boot.img').write_bytes(value)
        parser['image.boot']['sha256']=hashlib.sha256(value).hexdigest()
        parser['image.boot']['size']=str(len(value))
        self.write_manifest(directory,parser)
        with self.assertRaisesRegex(BuildError,'source'):
            ota._verify_extracted(directory,self.metadata,self.images,expected,'verity')

    def test_symlink_and_extra_files_are_rejected(self):
        directory,_,expected = self.extracted()
        extra=directory/'unexpected';extra.write_bytes(b'extra')
        with self.assertRaisesRegex(BuildError,'unexpected files'):
            ota._verify_extracted(directory,self.metadata,self.images,expected,'verity')
        extra.unlink()
        (directory/'boot.img').unlink()
        (directory/'boot.img').symlink_to(directory/'system.img')
        with self.assertRaisesRegex(BuildError,'ordinary file'):
            ota._verify_extracted(directory,self.metadata,self.images,expected,'verity')

    def test_multicopy_bootloader_payload_is_rejected_before_bundle(self):
        output,work=self.root/'output',self.root/'work'
        output.mkdir();work.mkdir()
        for filename,size in [('system.img',32),('boot.img',32),('uboot-slot.img',4*1024*1024),('idblock-slot.img',512*1024)]:
            with (output/filename).open('wb') as stream:stream.truncate(size)
        certificate=self.root/'trust.pem';certificate.write_text('certificate fixture')
        with patch.object(ota,'run') as run:
            # Stop the first system bundle after checking its inputs. This
            # test exercises the bootloader size check directly by allowing
            # the fake system extraction to populate authenticated content.
            def invoke(argv,**kwargs):
                if 'extract' in argv:
                    source=work/'naos-bundle';destination=Path(argv[-1])
                    shutil.copytree(source,destination)
                    parser=configparser.ConfigParser(interpolation=None)
                    parser.read(destination/'manifest.raucm')
                    for slot,filename in self.images:
                        value=(destination/filename).read_bytes()
                        parser['image.'+slot]['sha256']=hashlib.sha256(value).hexdigest()
                        parser['image.'+slot]['size']=str(len(value))
                    self.write_manifest(destination,parser)
                return ''
            run.side_effect=invoke
            with self.assertRaisesRegex(BuildError,'one copy'):
                ota.build_bundles(output,work,self.metadata,{}, {'rauc':'rauc'},
                    {'key':self.root/'private.key','certificate':certificate},output/'system.img')


_TOOLSET = Path(__file__).resolve().parents[1] / '.tools'


@unittest.skipUnless(all((_TOOLSET/'bin'/name).is_file() for name in ('rauc','openssl','mksquashfs','unsquashfs')),
                     'requires the imported native RAUC toolset')
class RealOtaTests(unittest.TestCase):
    def test_native_non_json_rauc_verifies_both_bundles_and_rejects_corruption(self):
        old_environment=dict(common._TOOL_ENV)
        common.set_tool_environment({})
        self.addCleanup(common.set_tool_environment,old_environment)
        with tempfile.TemporaryDirectory(prefix='naos-ota-test-') as temporary:
            root=Path(temporary);output=root/'output';work=root/'work';output.mkdir();work.mkdir()
            tools={name:_TOOLSET/'bin'/name for name in ('rauc','openssl')}
            for stem in ('signer','untrusted'):
                common.run([shutil.which('openssl'),'req','-config','/dev/null','-x509','-newkey','rsa:2048','-noenc',
                            '-keyout',root/(stem+'.key'),'-out',root/(stem+'.crt'),
                            '-days','1','-subj','/CN=NAOS OTA test '+stem,
                            '-addext','basicConstraints=critical,CA:TRUE'],env={'LD_LIBRARY_PATH':''})
                (root/(stem+'.key')).chmod(0o600)
            common.set_tool_environment(tool_environment(_TOOLSET))
            for filename,size in [('system.img',8192),('boot.img',8192),('uboot-slot.img',2*1024*1024),('idblock-slot.img',512*1024)]:
                with (output/filename).open('wb') as stream:
                    stream.write(os.urandom(min(size,16384)))
                    stream.truncate(size)
            metadata=dict(compatible='fixture-board-v1',version='2.0-test',build_id='test-build',machine='fixture-board',board='vision1',epoch=1700000000)
            result=ota.build_bundles(output,work,metadata,{'bundle_format':'verity'},tools,
                {'key':root/'signer.key','certificate':root/'signer.crt'},output/'system.img',1,
                trust_certificate=root/'signer.crt')
            self.assertEqual(len(result),2)
            for filename,verified in result.items():
                self.assertIn('-vision1-',filename)
                self.assertEqual(verified['compatible'],'fixture-board-v1')
                bootloader='bootloader' in filename
                self.assertEqual(verified['installation_order'],['uboot','idb'] if bootloader else ['rootfs','boot'])
                self.assertEqual(verified['switch_system_slot'],not bootloader)
                self.assertTrue(verified['signature_verified'] and verified['payload_verified'])
            bundle=output/next(name for name in result if 'bootloader' not in name)
            with self.assertRaises(BuildError):
                common.run([tools['rauc'],'--keyring='+str(root/'untrusted.crt'),'extract',bundle,root/'wrong-trust'])
            corrupted=root/'corrupted.raucb';shutil.copyfile(bundle,corrupted)
            with corrupted.open('r+b') as stream:
                stream.seek(4096);value=stream.read(1);stream.seek(4096);stream.write(bytes([value[0]^1]))
            with self.assertRaisesRegex(BuildError,'corrupted|verify|verification'):
                common.run([tools['rauc'],'--keyring='+str(root/'signer.crt'),'extract',corrupted,root/'corrupted'])


if __name__=='__main__':
    unittest.main()
