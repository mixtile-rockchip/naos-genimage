# SPDX-License-Identifier: MIT
"""Execute local APK lifecycle scripts in a rootless target namespace.

The target fakeroot daemon records ownership assigned by package scripts.
Namespace mounts and temporary helper files never enter the final rootfs.
"""
import argparse
import contextlib
import copy
import gzip
import hashlib
import json
import logging
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time

from .common import BuildError, _diagnostic, require

LOG = logging.getLogger(__name__)
_RUNTIME = {}


def namespace_command(runtime, mode):
    command = [str(runtime['unshare']), '--user', '--map-root-user', '--mount', '--ipc',
               '--propagation', 'private']
    if mode == 'private':
        command += ['--pid', '--fork', '--mount-proc']
    return command


def proc_mode(runtime):
    value = runtime.get('proc_mode', 'auto')
    if value == 'auto':
        value = 'bind' if any(Path(name).exists() for name in
                             ('/.dockerenv', '/run/.containerenv', '/run/systemd/container')) else 'private'
    require(value in ('private', 'bind'), 'Invalid APK namespace proc mode')
    return value


def _environment(epoch=None):
    # Host LD_PRELOAD/LD_LIBRARY_PATH must never leak into target processes.
    result = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'LANG': 'C', 'TZ': 'UTC'}
    if epoch is not None:
        result['SOURCE_DATE_EPOCH'] = str(epoch)
    return result


def run_install(source, staged_packages, records, work_dir, *, apk, runtime, epoch):
    """Invoke the namespace helper from an ordinary host-user process."""
    work = Path(work_dir).resolve()
    work.mkdir(mode=0o700, parents=True, exist_ok=True)
    mode = proc_mode(runtime)
    job = {'source': str(Path(source).resolve()), 'apk': str(Path(apk).resolve()),
           'packages': [str(Path(package).resolve()) for package in staged_packages],
           'records': records, 'epoch': epoch,
           'runtime': {name: str(value) if isinstance(value, Path) else value for name, value in runtime.items()},
           'proc_mode': mode, 'output': str(work/'rootfs.tar.gz'), 'result': str(work/'result.json')}
    job_path = work/'namespace-job.json'
    job_path.write_text(json.dumps(job)+'\n')
    job_path.chmod(0o600)
    environment = _environment(epoch)
    environment['PYTHONPATH'] = str(Path(__file__).resolve().parents[1])
    command = namespace_command(runtime, mode) + [sys.executable, '-m', __name__, '--worker', str(job_path)]
    LOG.info('Installing local APKs with lifecycle scripts in a rootless target namespace')
    with (work/'namespace.log').open('wb') as diagnostic:
        process = subprocess.Popen(command, env=environment, stdin=subprocess.DEVNULL,
                                   stdout=diagnostic, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            status = process.wait(timeout=900)
        except BaseException as error:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            if isinstance(error, subprocess.TimeoutExpired):
                raise BuildError('Rootless APK installation timed out') from error
            raise
    if status:
        detail = _diagnostic((work/'namespace.log').read_bytes())
        raise BuildError('Local APK installation failed: '+detail)
    result_path = Path(job['result'])
    require(result_path.is_file(), 'APK namespace helper produced no result')
    result = json.loads(result_path.read_text())
    require(Path(job['output']).is_file() and isinstance(result.get('sboms'), list),
            'APK namespace helper produced an invalid result')
    return Path(job['output']), result['sboms']


def run(command, *, env, input=None, reject_apk_errors=False, log_output=True, role=None):
    result = subprocess.run([str(item) for item in command], env=env, input=input,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, check=False)
    if log_output and result.stdout:
        print(result.stdout, end="", flush=True)
    if result.returncode:
        raise BuildError("Target command failed (exit " + str(result.returncode) + "): "
                         + (role or Path(str(command[0])).name) + ": " + _diagnostic(result.stdout))
    if reject_apk_errors and re.search(r"(^|\n)ERROR:|script exited with error|exited with error [0-9]+", result.stdout):
        raise BuildError("APK reported an installation or script error: " + _diagnostic(result.stdout))
    return result.stdout.strip()


class Target:
    def __init__(self, root, env):
        self.root, self.env, self.key, self.pid = root, env, None, None

    def run(self, command, **kwargs):
        prefix = [_RUNTIME["chroot"], self.root]
        if self.key:
            prefix += ["/usr/bin/env", "FAKEROOTKEY=" + self.key,
                       "LD_PRELOAD=/.naos-build/helper/usr/lib/libfakeroot.so:/.naos-build/libnaos-chown-compat.so"]
        return run(prefix + list(command), env=self.env, role=Path(str(command[0])).name, **kwargs)

    def start(self):
        pending = []
        # Defer Python's termination handler until the daemon PID is recorded.
        # Unlike blocking signals, this does not leave faked inheriting a
        # blocked SIGTERM when subprocess.run starts it.
        previous_handlers = {number: signal.signal(number, lambda signum, frame: pending.append(signum))
                             for number in (signal.SIGTERM, signal.SIGINT)}
        try:
            result = self.run(["/.naos-build/helper/usr/bin/faked", "--save-file", "/.naos-build/ownership.state"],
                              log_output=False)
            match = re.fullmatch(r"([0-9]+):([0-9]+)", result)
            if not match:
                raise RuntimeError("fakeroot daemon did not provide a key and PID")
            self.key, self.pid = match.group(1), int(match.group(2))
        finally:
            for number, handler in previous_handlers.items():
                signal.signal(number, handler)
        if pending:
            terminate(pending[0], None)

    def _running(self):
        # In private PID mode the daemon can become our adopted child. Reap it
        # if possible; in container mode it may instead belong to container init.
        try:
            if os.waitpid(self.pid, os.WNOHANG)[0]:
                return False
        except ChildProcessError:
            pass
        try:
            status = Path("/proc/%d/stat" % self.pid).read_text()
        except FileNotFoundError:
            return False
        return status.rsplit(")", 1)[1].split()[0] != "Z"

    def _wait_stopped(self, timeout):
        deadline = time.monotonic() + timeout
        while self._running():
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.05)
        return True

    def stop(self):
        if self.pid:
            # Synchronize the last metadata request before asking faked to save.
            error = None
            try:
                self.run(["/bin/ls", "-ldn", "/"])
            except (OSError, RuntimeError, BuildError) as failure:
                error = failure
            try:
                os.kill(self.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            if not self._wait_stopped(10):
                try:
                    os.kill(self.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                if not self._wait_stopped(2):
                    raise RuntimeError("cannot stop fakeroot daemon")
                if error is None:
                    error = RuntimeError("fakeroot daemon did not stop gracefully")
            self.pid = None
            self.key = None
            if error:
                raise error
            state = self.root / ".naos-build/ownership.state"
            if not state.is_file():
                raise RuntimeError("fakeroot did not save its ownership metadata")


def mount_rootfs(command, path, recursive, mounts, env):
    # A termination signal must not separate mounting from its cleanup record.
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT})
    try:
        run(command + [path], env=env)
        mounts.append((path, recursive))
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)


def unmount_rootfs(mounts, env):
    errors = []
    for path, recursive in reversed(mounts[:]):
        command = [_RUNTIME["umount"]]
        if recursive:
            # Detach the complete proc tree, including Docker's locked child
            # mounts. Unmounting each child would fail or remove protection.
            command.append("-l")
        try:
            run(command + [path], env=env)
        except (OSError, RuntimeError, BuildError) as error:
            errors.append(str(path) + ": " + str(error))
        else:
            mounts.remove((path, recursive))
    if errors:
        raise RuntimeError("cannot unmount rootfs: " + "; ".join(errors))


def cleanup_rootfs(target, mounts, workspace, env):
    errors = []
    previous_handlers = {number: signal.signal(number, signal.SIG_IGN)
                         for number in (signal.SIGTERM, signal.SIGINT)}
    try:
        if target and target.pid:
            try:
                target.stop()
            except Exception as error:
                errors.append("cannot stop fakeroot: " + str(error))
        try:
            unmount_rootfs(mounts, env)
        except Exception as error:
            errors.append(str(error))
        if mounts or (target and target.pid):
            errors.append("retained workspace with active mounts or daemon: " + str(workspace))
        else:
            try:
                shutil.rmtree(workspace)
            except OSError as error:
                errors.append("cannot remove workspace: " + str(error))
    finally:
        for number, handler in previous_handlers.items():
            signal.signal(number, handler)
    return errors


def terminate(signum, frame):
    raise SystemExit(128 + signum)


def read_ownership(path):
    ownership = {}
    for line in path.read_text().splitlines():
        fields = dict(item.split("=", 1) for item in line.split(","))
        ownership[(int(fields["dev"], 16), int(fields["ino"]))] = {
            "uid": int(fields["uid"]), "gid": int(fields["gid"]),
            "mode": int(fields["mode"], 8), "rdev": int(fields.get("rdev", "0"), 16)}
    return ownership


def _preserved_pax(name, info, path, baseline):
    if not baseline or name not in baseline['entries']:
        return {}
    original = baseline['entries'][name]
    if original.islnk():
        seen, anchor = {name}, _safe_name(original.linkname)
        while anchor in baseline['entries'] and baseline['entries'][anchor].islnk():
            require(anchor not in seen, 'Cyclic baseline hardlink metadata')
            seen.add(anchor)
            anchor = _safe_name(baseline['entries'][anchor].linkname)
        target = baseline['entries'][anchor]
        headers = {**target.pax_headers, **original.pax_headers}
        original = copy.copy(original)
        original.type, original.size = tarfile.REGTYPE, target.size
    else:
        headers = original.pax_headers
    headers = {key:value for key,value in headers.items() if key not in
               ('mtime','atime','ctime','path','linkpath','uid','gid','uname','gname')}
    if not headers:
        return {}
    regular = info.isfile() or info.islnk()
    same_kind = original.isfile() if regular else original.type == info.type
    if not same_kind or (original.uid, original.gid, original.mode) != (info.uid, info.gid, info.mode):
        return {}
    if regular:
        if original.size != path.stat().st_size:
            return {}
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as source:
            digest = hashlib.file_digest(source, 'sha256').hexdigest()
        if digest != baseline['digests'].get(name):
            return {}
    elif info.issym() and original.linkname != info.linkname:
        return {}
    elif info.ischr() or info.isblk():
        if (original.devmajor,original.devminor) != (info.devmajor,info.devminor):
            return {}
    return dict(headers)


def archive_rootfs(root, destination, epoch, ownership, baseline=None):
    paths = [root]
    for directory, directories, files in os.walk(root, followlinks=False):
        paths.extend(Path(directory) / name for name in directories + files)
    paths = sorted(set(paths), key=lambda path: path.relative_to(root).as_posix())
    with destination.open("wb") as output, gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=epoch) as compressed:
        with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as archive:
            for path in paths:
                name = "." if path == root else path.relative_to(root).as_posix()
                info = archive.gettarinfo(str(path), arcname=name)
                actual = path.lstat()
                fake = ownership.get((actual.st_dev, actual.st_ino), {})
                info.uid, info.gid = fake.get("uid", 0), fake.get("gid", 0)
                # Linux symlink permission bits are always 0777. A reused
                # inode in fakeroot can carry an irrelevant former file mode;
                # retain the actual symlink mode instead of serializing it.
                info.mode = stat.S_IMODE(actual.st_mode if info.issym() else fake.get("mode", actual.st_mode))
                info.uname = info.gname = ""
                info.mtime = epoch
                # Mounted build devices are empty placeholders after unmount.
                device = {"dev/null": (1, 3), "dev/zero": (1, 5),
                          "dev/random": (1, 8), "dev/urandom": (1, 9)}.get(path.relative_to(root).as_posix())
                if device:
                    info.type, info.size, info.mode = tarfile.CHRTYPE, 0, 0o666
                    info.devmajor, info.devminor = device
                elif not info.issym() and (stat.S_ISCHR(fake.get("mode", 0)) or stat.S_ISBLK(fake.get("mode", 0))):
                    info.type = tarfile.CHRTYPE if stat.S_ISCHR(fake["mode"]) else tarfile.BLKTYPE
                    info.size = 0
                    info.devmajor, info.devminor = os.major(fake["rdev"]), os.minor(fake["rdev"])
                info.pax_headers = _preserved_pax(path.relative_to(root).as_posix() if path != root else '.',
                                                  info, path, baseline)
                if info.isfile():
                    with path.open("rb") as stream:
                        archive.addfile(info, stream)
                else:
                    archive.addfile(info)


def _safe_name(value, *, root=False):
    require(isinstance(value, str) and value and not value.startswith('/')
            and '\\' not in value and '\0' not in value and '..' not in value.split('/'),
            'Unsafe APK seed archive path')
    result = str(PurePosixPath(value))
    require(root or result != '.', 'APK seed has an invalid individual file path')
    return result


def bootstrap(source, root):
    """Create executable seed files without privileged mknod or target chown.

    The full seed is re-extracted under target fakeroot later. Absolute target
    symlinks remain archive data and are created after regular payloads.
    """
    entries, digests = {}, {}
    with tarfile.open(source, 'r:*') as archive:
        for member in archive:
            name = _safe_name(member.name, root=member.isdir())
            require(name not in entries, 'Duplicate APK seed archive path')
            require(name != '.naos-build' and not name.startswith('.naos-build/'),
                    'APK seed contains the reserved build helper directory')
            require(member.isfile() or member.isdir() or member.islnk() or member.issym()
                    or member.ischr() or member.isblk() or member.isfifo(), 'Unsupported APK seed archive entry')
            member = copy.copy(member)
            member.pax_headers = dict(member.pax_headers)
            entries[name] = member
        for name in entries:
            for parent in PurePosixPath(name).parents:
                require(str(parent) not in entries or entries[str(parent)].isdir(),
                        'APK seed archive path has a non-directory parent')
                (root/str(parent)).mkdir(mode=0o755, parents=True, exist_ok=True)
        for name, member in entries.items():
            if member.isdir():
                (root/name).mkdir(mode=0o755, parents=True, exist_ok=True)
                (root/name).chmod((member.mode & 0o777) | 0o700)
        for name, member in entries.items():
            if member.isfile():
                stream = archive.extractfile(member)
                require(stream is not None, 'Missing APK seed file payload')
                digest = hashlib.sha256()
                with stream, (root/name).open('xb') as target:
                    while data := stream.read(1024*1024):
                        digest.update(data)
                        target.write(data)
                (root/name).chmod((member.mode & 0o777) | 0o600)
                digests[name] = digest.hexdigest()
        for name, member in entries.items():
            if member.islnk():
                target, visited = _safe_name(member.linkname), {name}
                while target in entries and entries[target].islnk():
                    require(target not in visited, 'Cyclic APK seed hardlink')
                    visited.add(target)
                    target = _safe_name(entries[target].linkname)
                require(target in entries and entries[target].isfile(), 'Invalid APK seed hardlink')
                os.link(root/target, root/name, follow_symlinks=False)
                digests[name] = digests[target]
            elif member.issym():
                os.symlink(member.linkname, root/name)
    return {'entries': entries, 'digests': digests}


def prepare_local_repository(root, helper, packages, records, *, apk, env):
    """Trust only the supplied local APKs without relaxing remote verification."""
    from Cryptodome.PublicKey import RSA

    require(len(packages) == len(records) and records, 'Local APK repository has no matching packages')
    directory = helper/'packages'
    directory.mkdir()
    archives, constraints = [], []
    for source, record in zip(packages, records):
        filename = _safe_name(record['name']+'-'+record['version']+'.apk')
        require('/' not in filename, 'Invalid local APK repository filename')
        identity = record.get('identity', '')
        require(re.fullmatch(r'[A-Za-z0-9+/=]{20,128}', identity) is not None,
                'Local APK lacks a valid package identity')
        destination = directory/filename
        shutil.copyfile(source, destination)
        archives.append(destination)
        constraints.append(record['name']+'><'+identity)

    keys = root/'etc/apk/keys'
    require(keys.is_dir() and keys.resolve().is_relative_to(root.resolve()),
            'Target APK keys directory is unavailable or unsafe')
    name = 'naos-build-'+os.urandom(16).hex()
    private = root.parent/(name+'.pem')
    public = keys/(name+'.pub')
    key = RSA.generate(2048)
    private_created = public_created = False
    try:
        with private.open('xb') as stream:
            private_created = True
            private.chmod(0o600)
            stream.write(key.export_key())
        with public.open('xb') as stream:
            public_created = True
            stream.write(key.public_key().export_key() + b'\n')
        public.chmod(0o644)
        # Only offline indexing of user-supplied APKs permits absent signatures.
        # Installation uses the temporary signed index and normal target trust.
        run([apk, '--allow-untrusted', '--no-network', '--sign-key', private,
             'mkndx', '--output', directory/'Packages.adb', *archives], env=env,
            role='local APK index')
    except BaseException:
        if public_created:
            public.unlink(missing_ok=True)
        raise
    finally:
        if private_created:
            private.unlink(missing_ok=True)
    return constraints, public


def mount_build_resolver(root, helper, mounts, env):
    """Use host DNS during installation, then restore the image's resolver."""
    destination = root/'etc/resolv.conf'
    backup = helper/'original-resolv.conf'
    require(Path('/etc/resolv.conf').is_file(), 'Host DNS resolver configuration is unavailable')
    if destination.exists() or destination.is_symlink():
        require(destination.is_file() or destination.is_symlink(), 'Invalid target DNS resolver configuration')
        destination.rename(backup)
    destination.touch(mode=0o644)
    mount_rootfs([_RUNTIME['mount'], '--bind', '/etc/resolv.conf'], destination, False, mounts, env)
    run([_RUNTIME['mount'], '-o', 'remount,bind,ro', destination], env=env)


def restore_image_resolver(root, helper):
    destination = root/'etc/resolv.conf'
    destination.unlink()
    backup = helper/'original-resolv.conf'
    if backup.exists() or backup.is_symlink():
        backup.rename(destination)


def _add(target, packages):
    # apk-tools otherwise sanitizes the environment of lifecycle scripts,
    # which would drop the target fakeroot preload and ownership daemon key.
    # Target.run supplies only the deliberately minimal build environment.
    command = ['/sbin/apk', '--preserve-env', '--no-cache', '--no-logfile',
               '--repository', '/.naos-build/packages/Packages.adb', 'add']
    return target.run(command + packages, reject_apk_errors=True)


def run_package_commands(root, target, records):
    """Execute only a package's own root-level commands file in the target."""
    from .filesystems import _apk_database
    from .local_apks import _remove_database_files

    database = root/'lib/apk/db/installed'
    packages = {(item['name'],item['version']): item
                for item in _apk_database(database.read_text())}
    removed = set()
    for record in records:
        name = _safe_name(record['name']+'.commands')
        require('/' not in name, 'Invalid local APK commands filename')
        package = packages.get((record['name'], record['version']))
        require(package is not None, 'Local APK commands package is not installed')
        owned = {item['path'] for item in package['files']}
        filename = root/name
        exists = filename.exists() or filename.is_symlink()
        if not exists and name not in owned:
            continue
        require(name in owned, 'Local APK commands file is not owned by its package: '+name)
        require(filename.is_file() and not filename.is_symlink() and filename.stat().st_nlink == 1
                and filename.stat().st_size <= 1024*1024,
                'Local APK commands must be an ordinary file of at most 1 MiB: '+name)
        target.run(['/bin/sh', '-e', '/'+name])
        target.run(['/bin/rm', '-f', '--', '/'+name], log_output=False)
        removed.add(name)
    if removed:
        _remove_database_files(database, removed)


def _worker(job):
    from .filesystems import _apk_database
    from .local_apks import _take_sboms

    require(os.geteuid() == 0, 'APK helper must run inside its mapped-root user namespace')
    _RUNTIME.clear()
    _RUNTIME.update(job['runtime'])
    epoch = job['epoch']
    require(type(epoch) is int and 0 <= epoch <= 0xffffffff, 'Invalid APK source date epoch')
    output = Path(job['output'])
    source = Path(job['source'])
    records = job['records']
    require(len(records) == len(job['packages']) and records, 'APK namespace job has no matching packages')
    env = _environment(epoch)
    workspace = Path(tempfile.mkdtemp(prefix='.apk-namespace-', dir=output.parent))
    mounts, target = [], None
    for number in (signal.SIGTERM, signal.SIGINT):
        signal.signal(number, terminate)
    try:
        root = workspace/'rootfs'
        root.mkdir()
        baseline = bootstrap(source, root)
        helper = root/'.naos-build'
        helper.mkdir()
        target = Target(root, env)
        shutil.copyfile(_RUNTIME['fakeroot_apk'], helper/'fakeroot.apk')
        # Build helper is official and verified independently of optional
        # signatures on user-supplied application APKs.
        target.run(['/sbin/apk', 'verify', '/.naos-build/fakeroot.apk'])
        (helper/'helper').mkdir()
        target.run(['/sbin/apk', 'extract', '--no-chown', '--destination',
                    '/.naos-build/helper', '/.naos-build/fakeroot.apk'])
        shutil.copyfile(_RUNTIME['ownership_library'], helper/'libnaos-chown-compat.so')
        shutil.copyfile(source, helper/'seed.tar.gz')
        devices = root/'dev'
        require(not devices.is_symlink() and (not devices.exists() or devices.is_dir()),
                'Unsafe APK seed device directory')
        devices.mkdir(exist_ok=True)
        for name in ('null', 'zero', 'random', 'urandom'):
            path = devices/name
            require(not path.is_symlink(), 'Unsafe APK seed device placeholder')
            path.parent.mkdir(exist_ok=True)
            path.touch(exist_ok=True)
            path.chmod(0o666)
            mount_rootfs([_RUNTIME['mount'], '--bind', '/dev/'+name], path, False, mounts, env)
        proc = root/'proc'
        require(not proc.is_symlink(), 'Unsafe APK seed proc directory')
        proc.mkdir(exist_ok=True)
        if job['proc_mode'] == 'bind':
            mount_rootfs([_RUNTIME['mount'], '--rbind', '/proc'], proc, True, mounts, env)
        else:
            mount_rootfs([_RUNTIME['mount'], '-t', 'proc', '-o', 'nosuid,nodev,noexec', 'proc'],
                         proc, False, mounts, env)
        target.start()
        excludes = [f'--exclude={prefix}dev/{name}' for name in ('null','zero','random','urandom')
                    for prefix in ('', './')]
        target.run(['/bin/tar', *excludes, '-xpf', '/.naos-build/seed.tar.gz', '-C', '/'])
        architecture = target.run(['/sbin/apk', '--print-arch'], log_output=False)
        require(all(record['architecture'] in (architecture, 'noarch') for record in records),
                'Local APK architecture does not match the image ('+architecture+')')
        packages, local_key = prepare_local_repository(root, helper, job['packages'], records,
                                                       apk=job['apk'], env=env)
        mount_build_resolver(root, helper, mounts, env)
        # Resolve all supplied identities in one transaction so dependency
        # scripts always see the requested local packages, including when a
        # remote repository offers the same name and version.
        _add(target, packages)
        sboms = _take_sboms(root, records,
            remove=lambda name: target.run(['/bin/rm', '--', '/'+name], log_output=False))
        local_key.unlink()
        run_package_commands(root, target, records)
        installed = {(p['name'],p['version']) for p in
                     _apk_database((root/'lib/apk/db/installed').read_text())}
        require(all((record['name'],record['version']) in installed for record in records),
                'A requested local APK version is absent from the final database')
        target.stop()
        ownership = read_ownership(helper/'ownership.state')
        unmount_rootfs(mounts, env)
        restore_image_resolver(root, helper)
        shutil.rmtree(helper)
        archive_rootfs(root, output, epoch, ownership, baseline)
        result = Path(job['result'])
        result.write_text(json.dumps({'sboms': sboms})+'\n')
    finally:
        original_error = sys.exc_info()[0] is not None
        errors = cleanup_rootfs(target, mounts, workspace, env)
        if errors:
            message = 'APK namespace cleanup failed: '+'; '.join(errors)
            if original_error:
                print(message, file=sys.stderr)
            else:
                raise BuildError(message)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        _worker(json.loads(args.worker.read_text()))
    except (BuildError, ValueError, OSError, RuntimeError) as error:
        print('APK namespace helper: '+str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
