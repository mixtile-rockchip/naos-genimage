"""Namespace installation mechanics without requiring host privileges."""
import io
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

from naos_image_generator import apk_namespace as ns
from naos_image_generator.common import BuildError


class NamespaceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def seed(self, entries):
        output = self.root/'seed.tar.gz'
        with tarfile.open(output, 'w:gz') as archive:
            for name, kind, value in entries:
                info = tarfile.TarInfo(name)
                info.mode, info.uid, info.gid = 0o640, 1234, 5678
                info.type = kind
                if kind == tarfile.REGTYPE:
                    info.size = len(value)
                    archive.addfile(info, io.BytesIO(value))
                else:
                    if kind in (tarfile.LNKTYPE, tarfile.SYMTYPE):
                        info.linkname = value
                    archive.addfile(info)
        return output

    def runtime(self):
        return {name: '/usr/bin/'+name for name in ('unshare','chroot','mount','umount','tar')}

    def test_namespace_flags_and_clean_execution_environment(self):
        private = ns.namespace_command(self.runtime(), 'private')
        self.assertEqual(private[:7], ['/usr/bin/unshare','--user','--map-root-user','--mount',
                                      '--ipc','--propagation','private'])
        self.assertEqual(private[7:], ['--pid','--fork','--mount-proc'])
        self.assertNotIn('--mount-proc', ns.namespace_command(self.runtime(), 'bind'))
        with patch.dict(os.environ, {'LD_PRELOAD':'host.so','LD_LIBRARY_PATH':'/host/lib','SECRET':'host'}):
            environment = ns._environment(123)
        self.assertEqual(environment['SOURCE_DATE_EPOCH'], '123')
        self.assertNotIn('LD_PRELOAD', environment)
        self.assertNotIn('LD_LIBRARY_PATH', environment)
        self.assertNotIn('SECRET', environment)

    def test_bootstrap_preserves_links_without_mknod_or_chown(self):
        source = self.seed([('.',tarfile.DIRTYPE,None),('etc',tarfile.DIRTYPE,None),
                            ('etc/config',tarfile.REGTYPE,b'configuration'),
                            ('etc/hardlink',tarfile.LNKTYPE,'etc/config'),
                            ('etc/symlink',tarfile.SYMTYPE,'/run/config'),
                            ('dev/console',tarfile.CHRTYPE,None)])
        root = self.root/'target'
        root.mkdir()
        with patch.object(os,'mknod') as mknod, patch.object(os,'chown') as chown:
            ns.bootstrap(source, root)
        self.assertEqual((root/'etc/config').read_bytes(), b'configuration')
        self.assertEqual((root/'etc/config').stat().st_ino,(root/'etc/hardlink').stat().st_ino)
        self.assertEqual(os.readlink(root/'etc/symlink'),'/run/config')
        self.assertFalse((root/'dev/console').exists())
        mknod.assert_not_called()
        chown.assert_not_called()

    def test_bootstrap_rejects_reserved_paths_traversal_and_symlink_parents(self):
        cases = [([('../escape',tarfile.REGTYPE,b'data')], 'Unsafe'),
                 ([('.naos-build/helper',tarfile.REGTYPE,b'data')], 'reserved'),
                 ([('etc',tarfile.SYMTYPE,'/tmp'),('etc/file',tarfile.REGTYPE,b'data')], 'non-directory'),
                 ([('alias',tarfile.LNKTYPE,'missing')], 'hardlink')]
        for number,(entries,message) in enumerate(cases):
            with self.subTest(message=message):
                root = self.root/f'unsafe-{number}'
                root.mkdir()
                with self.assertRaisesRegex(BuildError,message):
                    ns.bootstrap(self.seed(entries),root)

    def test_archive_uses_script_ownership_mode_and_device_state(self):
        root=self.root/'target'
        (root/'home').mkdir(parents=True)
        payload=root/'home/data'
        payload.write_bytes(b'owned by script')
        console=root/'home/console'
        console.write_bytes(b'')
        (root/'home/alias').symlink_to('/run/target')
        metadata={}
        details=payload.lstat()
        metadata[(details.st_dev,details.st_ino)]={'uid':1234,'gid':5678,'mode':stat.S_IFREG|0o600}
        details=console.lstat()
        metadata[(details.st_dev,details.st_ino)]={'uid':0,'gid':0,'mode':stat.S_IFCHR|0o620,
                                                'rdev':os.makedev(5,1)}
        output=self.root/'output.tar.gz'
        ns.archive_rootfs(root,output,123,metadata)
        with tarfile.open(output) as archive:
            member=archive.getmember('home/data')
            self.assertEqual((member.uid,member.gid,member.mode,member.mtime),(1234,5678,0o600,123))
            member=archive.getmember('home/console')
            self.assertTrue(member.ischr())
            self.assertEqual((member.devmajor,member.devminor),(5,1))
            self.assertEqual(archive.getmember('home/alias').mode,0o777)

    def test_unchanged_pax_attributes_follow_hardlink_anchor_and_replacements_drop_them(self):
        source=self.root/'seed.tar.gz'
        capability='AQAAAgAAAAAAAAAAAAAAAAAAAAA='
        with tarfile.open(source,'w:gz',format=tarfile.PAX_FORMAT) as archive:
            original=tarfile.TarInfo('z-program')
            original.size,original.mode=8,0o755
            original.pax_headers={'SCHILY.xattr.security.capability':capability,
                                  'SCHILY.acl.access':'user::rwx,group::r-x,other::r-x',
                                  'mtime':'12.25'}
            archive.addfile(original,io.BytesIO(b'original'))
            alias=tarfile.TarInfo('a-program')
            alias.type,alias.linkname,alias.mode=tarfile.LNKTYPE,'z-program',0o755
            archive.addfile(alias)
        root=self.root/'target'
        root.mkdir()
        baseline=ns.bootstrap(source,root)
        output=self.root/'unchanged.tar.gz'
        ns.archive_rootfs(root,output,123,{},baseline)
        with tarfile.open(output) as archive:
            for name in ('a-program','z-program'):
                member=archive.getmember(name)
                self.assertEqual(member.pax_headers['SCHILY.xattr.security.capability'],capability)
                self.assertIn('SCHILY.acl.access',member.pax_headers)
                self.assertEqual(member.mtime,123)
                self.assertNotIn('mtime',member.pax_headers)
            self.assertTrue(archive.getmember('a-program').isfile())
            self.assertTrue(archive.getmember('z-program').islnk())
        (root/'z-program').write_bytes(b'replaced')
        changed=self.root/'changed.tar.gz'
        ns.archive_rootfs(root,changed,123,{},baseline)
        with tarfile.open(changed) as archive:
            for name in ('a-program','z-program'):
                self.assertNotIn('SCHILY.xattr.security.capability',archive.getmember(name).pax_headers)
                self.assertNotIn('SCHILY.acl.access',archive.getmember(name).pax_headers)

    def test_target_add_keeps_scripts_enabled_for_install_and_simulation(self):
        target=Mock()
        ns._add(target,['/.naos-build/packages/app.apk'])
        arguments=target.run.call_args.args[0]
        self.assertIn('--allow-untrusted',arguments)
        self.assertIn('--no-network',arguments)
        self.assertIn('--preserve-env',arguments)
        self.assertNotIn('--no-scripts',arguments)
        self.assertNotIn('--usermode',arguments)
        ns._add(target,['/.naos-build/packages/app.apk'],simulate=True)
        self.assertIn('--simulate',target.run.call_args.args[0])

    def test_launcher_reads_worker_result_and_reports_namespace_failures(self):
        work=self.root/'work'
        runtime={**self.runtime(),'proc_mode':'private'}
        source=self.root/'source.tar.gz'
        package=self.root/'app.apk'
        source.touch(); package.touch()
        def success(command,**kwargs):
            self.assertEqual(command[:7],ns.namespace_command(runtime,'private')[:7])
            job=json.loads((work/'namespace-job.json').read_text())
            Path(job['output']).write_bytes(b'archive')
            Path(job['result']).write_text('{"sboms":[]}')
            return Mock(wait=Mock(return_value=0))
        with patch.object(ns.subprocess,'Popen',side_effect=success):
            archive,sboms=ns.run_install(source,[package],[],work,runtime=runtime,epoch=123)
        self.assertEqual((archive.read_bytes(),sboms),(b'archive',[]))
        self.assertEqual((work/'namespace-job.json').stat().st_mode&0o777,0o600)
        with patch.object(ns.subprocess,'Popen',return_value=Mock(wait=Mock(return_value=1))):
            with self.assertRaisesRegex(BuildError,'user namespaces'):
                ns.run_install(source,[package],[],work,runtime=runtime,epoch=123)

    def test_launcher_timeout_terminates_the_worker_group(self):
        process=Mock(pid=4321)
        process.wait.side_effect=[subprocess.TimeoutExpired('unshare',900),0]
        with patch.object(ns.subprocess,'Popen',return_value=process),patch.object(ns.os,'killpg') as kill:
            with self.assertRaisesRegex(BuildError,'timed out'):
                ns.run_install(self.root/'source',[],[],self.root/'work',
                               runtime={**self.runtime(),'proc_mode':'bind'},epoch=0)
        kill.assert_called_once_with(4321,signal.SIGTERM)

    def command_root(self, name='app', contents=b'echo initialized\n'):
        root=self.root/'target'
        (root/'lib/apk/db').mkdir(parents=True)
        (root/(name+'.commands')).write_bytes(contents)
        database=root/'lib/apk/db/installed'
        database.write_text('P:'+name+'\nV:1-r0\nA:aarch64\nF:\nR:'+name+'.commands\n\n')
        return root,database,[{'name':name,'version':'1-r0'}]

    def test_package_commands_execute_inside_target_then_remove_file_and_db_record(self):
        root,database,records=self.command_root()
        calls=[]
        def execute(arguments,**kwargs):
            calls.append(arguments)
            if arguments[:2]==['/bin/rm','-f']:
                (root/arguments[-1].lstrip('/')).unlink()
        ns.run_package_commands(root,Mock(run=execute),records)
        self.assertEqual(calls[0],['/bin/sh','-e','/app.commands'])
        self.assertEqual(calls[1],['/bin/rm','-f','--','/app.commands'])
        self.assertFalse((root/'app.commands').exists())
        self.assertNotIn('R:app.commands',database.read_text())

    def test_package_commands_failures_are_not_suppressed(self):
        root,_,records=self.command_root()
        target=Mock()
        target.run.side_effect=BuildError('command exited with 29')
        with self.assertRaisesRegex(BuildError,'29'):
            ns.run_package_commands(root,target,records)
        self.assertEqual(target.run.call_count,1)

    def test_package_commands_reject_foreign_ownership_symlinks_and_large_files(self):
        for kind in ('foreign','symlink','large','hardlink'):
            with self.subTest(kind=kind):
                root,db,records=self.command_root(name='app-'+kind)
                filename=root/(records[0]['name']+'.commands')
                if kind=='foreign':
                    db.write_text(db.read_text().replace('R:app-foreign.commands','R:other.commands'))
                elif kind=='symlink':
                    filename.unlink();filename.symlink_to('/etc/hosts')
                elif kind=='large':
                    with filename.open('wb') as output:
                        output.truncate(1024*1024+1)
                else:
                    os.link(filename,root/'second-link')
                target=Mock()
                with self.assertRaises(BuildError):
                    ns.run_package_commands(root,target,records)
                target.run.assert_not_called()
                import shutil
                shutil.rmtree(root)


if __name__=='__main__':
    unittest.main()
