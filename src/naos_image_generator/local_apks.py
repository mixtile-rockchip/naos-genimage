# SPDX-License-Identifier: MIT
"""Inspect local APKs and install them in a rootless target namespace."""
import gzip
import hashlib
import json
import logging
from pathlib import Path, PurePosixPath
import shutil
import tarfile

from .common import BuildError, require, run, sha256

LOG = logging.getLogger(__name__)


def discover(directory):
    if directory is None:
        return ()
    directory = Path(directory)
    require(directory.is_dir() and not directory.is_symlink(), 'Local APK directory must be an ordinary directory')
    packages = tuple(sorted(directory.glob('*.apk')))
    for package in packages:
        require(package.is_file() and not package.is_symlink(), 'Local APK must be an ordinary file: '+package.name)
    return packages


def inspect(packages, work, apk):
    """Use apk-tools to read both v2 and v3 metadata; local signatures are optional."""
    records, names = [], set()
    for number, package in enumerate(packages):
        index = Path(work) / f'local-{number}.index.tar.gz'
        run([apk, '--allow-untrusted', '--no-network', 'index', '--no-warnings',
             '--output', index, package])
        with gzip.open(index, 'rb') as source, tarfile.open(fileobj=source, mode='r|', ignore_zeros=True) as archive:
            content = [archive.extractfile(member).read().decode()
                       for member in archive if member.name == 'APKINDEX' and member.isfile()]
        require(len(content) == 1, 'Cannot read local APK metadata: '+package.name)
        entries = [dict(line.split(':', 1) for line in paragraph.splitlines() if ':' in line)
                   for paragraph in content[0].strip().split('\n\n') if paragraph.strip()]
        require(len(entries) == 1 and all(entries[0].get(field) for field in ('P', 'V', 'A')),
                'Invalid local APK metadata: '+package.name)
        fields = entries[0]
        require(fields['P'] not in names, 'Provide only one local APK per package name: '+fields['P'])
        names.add(fields['P'])
        records.append(dict(name=fields['P'], version=fields['V'], architecture=fields['A'],
                            filename=package.name, sha256=sha256(package)))
    return records


def _remove_database_files(database, removed):
    """Extracted supplier evidence is no longer an installed package payload."""
    result, directory, skip = [], '.', False
    for line in database.read_text().splitlines():
        if not line:
            skip = False
        elif line.startswith('F:'):
            directory, skip = line[2:] or '.', False
        elif line.startswith('R:'):
            skip = str(PurePosixPath(directory)/line[2:]) in removed
        if not skip:
            result.append(line)
    database.write_text('\n'.join(result)+'\n')


def _take_sboms(root, records, *, remove=None):
    from .filesystems import _apk_database
    database = root/'lib/apk/db/installed'
    identities = {(item['name'],item['version']) for item in records}
    evidence, removed = [], set()
    for package in _apk_database(database.read_text()):
        if (package['name'],package['version']) not in identities:
            continue
        for item in package['files']:
            name = item['path']
            lower = PurePosixPath(name).name.lower()
            if not (lower.endswith(('.spdx.json','.sbom.json')) or lower == 'sbom.json'):
                continue
            filename = root/name
            require(not filename.is_symlink() and filename.resolve().is_relative_to(root.resolve()),
                    'Unsafe installed APK SBOM: '+name)
            if not filename.exists():
                continue
            require(filename.is_file() and filename.stat().st_size <= 32*1024*1024,
                    'Invalid installed APK SBOM: '+name)
            data = filename.read_bytes()
            try:
                document = json.loads(data)
            except ValueError as error:
                raise BuildError('Invalid JSON in installed APK SBOM: '+name) from error
            if isinstance(document,dict) and document.get('spdxVersion') == 'SPDX-2.3':
                evidence.append(dict(path=name,document=document,sha256=hashlib.sha256(data).hexdigest(),
                    package=dict(name=package['name'],version=package['version']),extracted=True))
            else:
                require(not lower.endswith('.spdx.json') and
                        not (isinstance(document,dict) and 'spdxVersion' in document),
                        'Local APK SBOM must use SPDX 2.3 JSON: '+name)
            # Summary companions are removed too; the SPDX document carries
            # the dependency/license evidence used by the final merged SBOM.
            if remove is None:
                filename.unlink()
            else:
                remove(name)
            removed.add(name)
    if removed:
        _remove_database_files(database,removed)
    return evidence


def install(source, packages, work, *, apk, runtime=None, epoch=0):
    """Execute normal APK scripts and triggers without host root or Docker."""
    from .apk_namespace import run_install
    from .apk_runtime import resolve_runtime, preflight
    work = Path(work)/'local-apks'
    work.mkdir(mode=0o700,parents=True)
    staging = work/'packages'
    staging.mkdir(mode=0o700)
    copied = []
    for number, package in enumerate(packages):
        filename = staging/f'{number:04d}.apk'
        with Path(package).open('rb') as incoming, filename.open('xb') as outgoing:
            shutil.copyfileobj(incoming,outgoing)
        copied.append(filename)
    records = inspect(copied,work,apk)
    for record, original in zip(records,packages):
        record['filename'] = Path(original).name
    with tarfile.open(source,'r:*') as archive:
        architectures = [archive.extractfile(member).read().decode().strip()
                         for member in archive if member.name.removeprefix('./') == 'etc/apk/arch'
                         and member.isfile() and member.size <= 128]
    require(len(architectures) == 1, 'Rootfs lacks a valid /etc/apk/arch')
    architecture = architectures[0]
    require(all(record['architecture'] in (architecture,'noarch') for record in records),
            'Local APK architecture does not match the image ('+architecture+')')
    if runtime is None:
        candidate = Path(apk).resolve().parent.parent
        runtime = resolve_runtime(candidate if (candidate/'targets').is_dir() else None,
                                  architecture=architecture)
    require(runtime.get('architecture',architecture) == architecture,
            'APK runtime architecture does not match the image ('+architecture+')')
    preflight(runtime)
    LOG.info('Installing %d local APK(s) in a user namespace; scripts and triggers are enabled',len(packages))
    output,evidence = run_install(source,copied,records,work,runtime=runtime,epoch=epoch)
    return output,records,evidence
