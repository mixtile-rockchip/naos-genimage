import base64
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import stat
import subprocess
import tarfile
import tempfile
import unittest

from naos_image_generator import filesystems as fs


KEY = b'0123456789abcdef' * 4


def make_tar(path):
    old = b'original configuration\n'
    check = base64.b64encode(hashlib.sha1(old, usedforsecurity=False).digest()).decode()
    database = ('P:sample\nV:1.0-r0\nA:aarch64\nL:MIT\nF:etc\n'
                'R:example.conf\nZ:Q1' + check + '\nR:alias.conf\nZ:Q1' + check + '\n\n').encode()
    version = json.dumps(dict(machine='test-board', version='old', build_id='old',
                              layout_compatible='test-layout', secure_boot=False,
                              system_encryption=False, data_encryption=False)).encode()
    with tarfile.open(path, 'w:gz') as archive:
        for name, uid, gid, mode in (('.',0,0,0o755), ('home/naos',1000,1000,0o700)):
            info = tarfile.TarInfo(name)
            info.type, info.uid, info.gid, info.mode = tarfile.DIRTYPE, uid, gid, mode
            archive.addfile(info)
        for name, data, uid, gid, mode in (
                ('lib/apk/db/installed',database,0,0,0o644),
                ('etc/example.conf',old,0,0,0o640),
                ('home/naos/data',b'owned by the target user',1000,1000,0o600),
                ('usr/lib/naos/version.json',version,0,0,0o644)):
            info = tarfile.TarInfo(name)
            info.size, info.uid, info.gid, info.mode = len(data), uid, gid, mode
            archive.addfile(info, io.BytesIO(data))
        link = tarfile.TarInfo('etc/alias.conf')
        link.type, link.linkname, link.mode = tarfile.LNKTYPE, 'etc/example.conf', 0o640
        archive.addfile(link)
        link = tarfile.TarInfo('etc/runtime-link')
        link.type, link.linkname = tarfile.SYMTYPE, '/run/../run/target'
        archive.addfile(link)
        device = tarfile.TarInfo('dev/console')
        device.type, device.devmajor, device.devminor, device.mode = tarfile.CHRTYPE, 5, 1, 0o600
        archive.addfile(device)
    return old


class FilesystemTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bundle = self.root / 'input'
        self.bundle.mkdir()
        self.old = make_tar(self.bundle / 'rootfs.tar.gz')
        self.original_hash = fs._file_digest(self.bundle / 'rootfs.tar.gz')

    def cpio(self):
        path = self.root / 'input.cpio.gz'
        records = [
            fs.CpioEntry('.',1,stat.S_IFDIR | 0o755,nlink=2),
            fs.CpioEntry('bin',2,stat.S_IFDIR | 0o755,nlink=2),
            fs.CpioEntry('dev',3,stat.S_IFDIR | 0o755,nlink=2),
            fs.CpioEntry('dev/console',4,stat.S_IFCHR | 0o600,rdevmajor=5,rdevminor=1),
            fs.CpioEntry('owned',5,stat.S_IFREG | 0o600,uid=1000,gid=1000,data=b'owner'),
            fs.CpioEntry('runtime-link',6,stat.S_IFLNK | 0o777,data=b'/run/target'),
            fs.CpioEntry('bin/alias',42,stat.S_IFREG | 0o755,nlink=2,devmajor=1,devminor=2),
            fs.CpioEntry('bin/program',42,stat.S_IFREG | 0o755,nlink=2,devmajor=1,devminor=2,
                         data=b'a program with a forward hardlink',magic=b'070702'),
        ]
        fs.write_cpio(records,path,111)
        return path

    def test_tar_preserves_target_metadata_and_hardlinks(self):
        output, inventory = fs.prepare_rootfs(self.bundle,self.root / 'work',epoch=222)
        entries = {item['path']:item for item in inventory['files']}
        self.assertEqual(entries['home/naos/data']['uid'],1000)
        self.assertEqual(entries['home/naos']['mode'],'0700')
        self.assertEqual(entries['dev/console']['device_major'],5)
        self.assertEqual(entries['dev/console']['device_minor'],1)
        self.assertEqual(entries['etc/runtime-link']['link_target'],'/run/../run/target')
        self.assertEqual(entries['etc/alias.conf']['kind'],'hardlink')
        self.assertEqual(entries['etc/alias.conf']['sha1'],hashlib.sha1(self.old,usedforsecurity=False).hexdigest())
        self.assertTrue(all(change['action'] == 'added' and entries[change['path']]['kind'] == 'directory'
                            for change in inventory['generator_changes']))
        self.assertEqual(fs._file_digest(self.bundle / 'rootfs.tar.gz'),self.original_hash)
        with tarfile.open(output) as archive:
            self.assertEqual(archive.getmember('home/naos/data').gid,1000)
            self.assertEqual(archive.getmember('home/naos/data').mtime,222)

    def test_overlay_updates_apk_status_and_breaks_only_replaced_hardlink(self):
        overlay = self.root / 'overlay'
        (overlay / 'etc').mkdir(parents=True)
        (overlay / 'etc/example.conf').write_bytes(b'custom configuration\n')
        (overlay / 'new-program').write_bytes(b'business executable')
        (overlay / 'new-program').chmod(0o755)
        (overlay / 'host-link').symlink_to('/this/is/data/not/a/host/read')
        output, inventory = fs.prepare_rootfs(self.bundle,self.root / 'work',overlays=[overlay],epoch=222)
        records = {item['path']:item for item in inventory['packages'][0]['files']}
        self.assertEqual(records['etc/example.conf']['status'],'modified')
        self.assertEqual(records['etc/example.conf']['generator_status'],'modified')
        self.assertEqual(records['etc/alias.conf']['status'],'unchanged')
        self.assertIn('new-program',inventory['unowned_files'])
        with tarfile.open(output) as archive:
            self.assertEqual(archive.extractfile('etc/alias.conf').read(),self.old)
            self.assertEqual(archive.getmember('host-link').linkname,'/this/is/data/not/a/host/read')

    def test_deleting_hardlink_target_keeps_surviving_alias_payload(self):
        output, inventory = fs.prepare_rootfs(self.bundle,self.root / 'work',remove=['etc/example.conf'],epoch=222)
        with tarfile.open(output) as archive:
            self.assertEqual(archive.extractfile('etc/alias.conf').read(),self.old)
            self.assertTrue(archive.getmember('etc/alias.conf').isfile())
        records = {item['path']:item for item in inventory['packages'][0]['files']}
        self.assertEqual(records['etc/example.conf']['status'],'missing')

    def test_certificates_version_and_overlay_ownership(self):
        certificate, ca = self.root / 'ota.pem',self.root / 'ssh.pub'
        certificate.write_bytes(b'public OTA certificate fixture\n')
        ca.write_bytes(b'public SSH CA fixture\n')
        overlay = self.root / 'overlay'
        (overlay / 'home/naos').mkdir(parents=True)
        (overlay / 'home/naos/data').write_bytes(b'custom target-owned data')
        metadata = dict(machine='new-board',version='2.0',build_id='ci-1',secure_boot=True)
        output, inventory = fs.prepare_rootfs(self.bundle,self.root / 'work',overlays=[overlay],
                    ota_certificate=certificate,ssh_ca=ca,metadata=metadata,epoch=222)
        with tarfile.open(output) as archive:
            self.assertEqual(archive.getmember('home/naos/data').uid,1000)
            self.assertEqual(archive.extractfile('etc/rauc/keyring.pem').read(),certificate.read_bytes())
            self.assertEqual(archive.getmember('etc/ssh/ssh_ca_key.pub').mode,0o644)
            version=json.load(archive.extractfile('usr/lib/naos/version.json'))
            self.assertEqual(version['version'],'2.0')
            self.assertEqual(version['layout_compatible'],'test-layout')
            self.assertTrue(version['secure_boot'])

    def test_unsafe_path_and_symlink_parent_are_rejected(self):
        overlay = self.root / 'overlay'
        (overlay / 'etc/runtime-link').mkdir(parents=True)
        (overlay / 'etc/runtime-link/file').write_bytes(b'safe replacement directory')
        # Replacing the symlink by a directory is safe; a descendant alone in a
        # malformed archive must never cause traversal on the host.
        fs.prepare_rootfs(self.bundle,self.root / 'safe',overlays=[overlay],epoch=222)
        with self.assertRaises(fs.FilesystemError):
            fs.prepare_rootfs(self.bundle,self.bundle / 'work',epoch=222)
        with self.assertRaises(fs.FilesystemError):
            fs.prepare_rootfs(self.bundle,self.root / 'bad',remove=['../outside'],epoch=222)

    def test_cpio_metadata_crc_hardlinks_and_key_fingerprint(self):
        source = self.cpio()
        old_hash = fs._file_digest(source)
        output = self.root / 'final.cpio.gz'
        inventory = fs.prepare_initramfs(source,output,KEY,epoch=222)
        entries = {item['path']:item for item in inventory['files']}
        records = {item.name:item for item in fs.read_cpio(output)}
        self.assertEqual(records['usr/lib/naos/system-key.sha256'].data,
                         hashlib.sha256(KEY).hexdigest().encode() + b'\n')
        self.assertNotEqual(hashlib.sha256(KEY).digest(),hashlib.sha256(bytes.fromhex(KEY.decode())).digest())
        self.assertEqual(entries['owned']['uid'],1000)
        self.assertEqual(entries['owned']['gid'],1000)
        self.assertEqual(entries['owned']['mtime'],222)
        self.assertEqual(entries['dev/console']['device_major'],5)
        self.assertEqual(entries['bin/alias']['kind'],'hardlink')
        self.assertEqual(entries['bin/alias']['sha256'],entries['bin/program']['sha256'])
        self.assertEqual(entries['runtime-link']['link_target'],'/run/target')
        self.assertEqual(fs._file_digest(source),old_hash)
        second = self.root / 'second.cpio.gz'
        fs.prepare_initramfs(source,second,KEY,epoch=222)
        self.assertEqual(output.read_bytes(),second.read_bytes())

    def test_concatenated_gzip_and_invalid_key_are_rejected(self):
        source = self.cpio()
        doubled = self.root / 'doubled.cpio.gz'
        doubled.write_bytes(source.read_bytes()+gzip.compress(b'unexpected archive'))
        with self.assertRaises(fs.FilesystemError):
            fs.read_cpio(doubled)
        with self.assertRaises(fs.FilesystemError):
            fs.prepare_initramfs(source,self.root / 'out',KEY+b'\n',epoch=222)
        with self.assertRaises(fs.FilesystemError):
            fs.prepare_initramfs(source,source,None,epoch=222)

    def test_factory_import_record_is_exact_protocol(self):
        record = fs.make_import_record(KEY)
        header = (b'NAOS-SYSTEM-KEY\nversion=2\nkey='+KEY+b'\n').ljust(256,b' ')
        self.assertEqual(len(record),65536)
        self.assertEqual(record[:256],header)
        self.assertEqual(record[256:320],hashlib.sha256(header).hexdigest().encode())
        self.assertFalse(any(record[320:]))

    @unittest.skipUnless(shutil.which('sqfstar') and shutil.which('unsquashfs'), 'SquashFS host tools not installed')
    def test_actual_squashfs_preserves_user_ownership(self):
        output,_ = fs.prepare_rootfs(self.bundle,self.root / 'work',epoch=222)
        image = self.root / 'system.squashfs'
        fs.make_squashfs(output,image,shutil.which('sqfstar'),epoch=222,processors=1)
        check = subprocess.run([shutil.which('unsquashfs'),'-cat',str(image),'etc/example.conf'],capture_output=True,check=True)
        self.assertEqual(check.stdout,self.old)
        listing = subprocess.run([shutil.which('unsquashfs'),'-lln',str(image)],capture_output=True,text=True,check=True).stdout
        self.assertRegex(listing,r'1000/1000\s+.*home/naos/data')

    @unittest.skipUnless(importlib.util.find_spec('Cryptodome'), 'Crypto dependency not installed')
    def test_sector_cipher_roundtrip_and_verified_output(self):
        source = self.root / 'system.squashfs'
        plaintext = b'hsqs'+bytes(range(256))*4
        source.write_bytes(plaintext)
        destination = self.root / 'system.img'
        metadata = fs.encrypt_system(source,destination,KEY)
        self.assertEqual(destination.stat().st_size,4096)
        decoded = fs.crypt_sectors(destination.read_bytes(),bytes.fromhex(KEY.decode()),decrypt=True)
        self.assertEqual(decoded[:len(plaintext)],plaintext)
        self.assertFalse(any(decoded[len(plaintext):]))
        self.assertEqual(metadata['key_sha256'],hashlib.sha256(KEY).hexdigest())
        # CBC must restart for each sector, rather than carrying the preceding
        # sector's ciphertext into the next sector.
        block = bytes(512)
        encrypted = fs.crypt_sectors(block*2,bytes.fromhex(KEY.decode()))
        self.assertNotEqual(encrypted[:512],encrypted[512:])
        self.assertEqual(encrypted[512:],fs.crypt_sectors(block,bytes.fromhex(KEY.decode()),first_sector=1))


if __name__ == '__main__':
    unittest.main()
