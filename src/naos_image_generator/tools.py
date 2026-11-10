# SPDX-License-Identifier: MIT
"""Import explicitly selected host tools without modifying their sources.

Only readelf inspects input ELF files; the importer never executes an input
binary.  The first toolset format targets Linux x86_64 with the host glibc ABI.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import struct
import tempfile
from typing import Iterable

from .common import BuildError, run


_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+\-]*\Z")
_SYSTEM_ABI = re.compile(
    r"(?:ld-linux(?:-x86-64)?\.so(?:\.\d+)*|"
    r"lib(?:c|m|mvec|pthread|dl|rt|resolv|util|anl|BrokenLocale|thread_db|"
    r"nss_[A-Za-z0-9_-]+)\.so(?:\.\d+)*)\Z")
_OPENSSL_CONFIG = """# Portable configuration for the NAOS host signing tools.
openssl_conf = openssl_init

[openssl_init]
providers = providers

[providers]
default = default_provider

[default_provider]
activate = 1

[req]
distinguished_name = distinguished_name

[distinguished_name]
"""


def _require(value, message):
    if not value:
        raise BuildError(message)


def _name(value):
    _require(isinstance(value, str) and _NAME.fullmatch(value),
             "Invalid tool or library name")
    return value


def _file(path, executable=False):
    path = Path(path).expanduser().absolute()
    try:
        mode = path.stat().st_mode
    except OSError as error:
        raise BuildError("Missing tool or library: " + path.name) from error
    _require(stat.S_ISREG(mode), "Expected a regular file: " + path.name)
    if executable:
        _require(os.access(path, os.X_OK), "Tool is not executable: " + path.name)
    # Preserve argv[0] for multicall tools such as sqfstar -> mksquashfs.
    return path


def _sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def resolve_tools(overrides: dict[str, Path], names: Iterable[str],
                  toolset: Path | None = None) -> dict[str, Path]:
    """Resolve explicit overrides, then a toolset's bin directory, then PATH.

    A selected but invalid explicit override is an error, rather than silently
    falling back to another program.  Toolset entries have the same behavior.
    """
    result = {}
    toolset = Path(toolset).expanduser().absolute() if toolset is not None else None
    for item in names:
        name = _name(item)
        if name in overrides:
            candidate = overrides[name]
        else:
            bundled = toolset / "bin" / name if toolset is not None else None
            if bundled is not None and os.path.lexists(bundled):
                candidate = bundled
            else:
                candidate = shutil.which(name)
                _require(candidate, "Required host tool is unavailable: " + name)
        result[name] = _file(candidate, executable=True)
    return result


def tool_environment(toolset: Path | None, base: dict | None = None) -> dict[str, str]:
    """Return an environment for tool subprocesses; never change os.environ."""
    values = dict(os.environ if base is None else base)
    if toolset is not None:
        root = Path(toolset).expanduser().absolute()
        _require((root / "bin").is_dir(), "Toolset bin directory is missing")
        values["PATH"] = str(root / "bin") + os.pathsep + values.get("PATH", os.defpath)
        if (root / "lib").is_dir():
            previous = values.get("LD_LIBRARY_PATH", "")
            values["LD_LIBRARY_PATH"] = str(root / "lib") + (os.pathsep + previous if previous else "")
        configuration = root / "share/openssl/openssl.cnf"
        if configuration.is_file():
            values.setdefault("OPENSSL_CONF", str(configuration))
    return values


def _host_tool(name):
    value = shutil.which(name)
    if not value and name == "ldconfig":
        value = next((str(path) for path in (Path("/sbin/ldconfig"), Path("/usr/sbin/ldconfig"))
                      if path.is_file()), None)
    _require(value, "Tool import requires host " + name)
    return _file(value, executable=True)


def _inspect(path, readelf):
    with Path(path).open("rb") as stream:
        header = stream.read(64)
    _require(len(header) == 64 and header[:6] == b"\x7fELF\x02\x01",
             "Tool import supports ELF64 little-endian files only: " + path.name)
    elf_type, machine = struct.unpack_from("<HH", header, 16)
    _require(machine == 62 and elf_type in (2, 3),
             "Tool import supports Linux x86_64 executables and libraries only: " + path.name)
    env = {"LC_ALL": "C"}
    dynamic = run([readelf, "-dW", path], env=env)
    program = run([readelf, "-lW", path], env=env)
    versions = run([readelf, "-VW", path], env=env)
    needed = re.findall(r"\(NEEDED\)\s+Shared library: \[([^\]]+)\]", dynamic)
    paths = []
    for match in re.finditer(r"\((?:RUNPATH|RPATH)\)\s+Library (?:runpath|rpath): \[([^\]]*)\]", dynamic):
        paths.extend(match.group(1).split(":"))
    interpreter = re.search(r"\[Requesting program interpreter: ([^\]]+)\]", program)
    soname = re.search(r"\(SONAME\)\s+Library soname: \[([^\]]+)\]", dynamic)
    # Definitions exported by a library do not imply a runtime requirement.
    needs = versions.split("Version needs section", 1)[1] if "Version needs section" in versions else ""
    glibc = sorted(set(re.findall(r"\bGLIBC_(\d+(?:\.\d+)+)\b", needs)),
                   key=lambda version: tuple(map(int, version.split("."))))
    if "GLIBC_ABI_DT_RELR" in needs:
        glibc = sorted(set(glibc + ["2.36"]), key=lambda version: tuple(map(int, version.split("."))))
    return {"needed": needed, "runpath": paths,
            "interpreter": interpreter.group(1) if interpreter else None,
            "soname": soname.group(1) if soname else None,
            "dynamic": "Dynamic section at" in dynamic,
            "minimum_glibc": glibc[-1] if glibc else None}


def _cache(ldconfig):
    result = {}
    for line in run([ldconfig, "-p"], env={"LC_ALL": "C"}).splitlines():
        match = re.match(r"\s*(\S+)\s+\(([^)]*)\)\s+=>\s+(\S+)\s*$", line)
        if match and "x86-64" in match.group(2) and "x32" not in match.group(2):
            result.setdefault(match.group(1), []).append(Path(match.group(3)))
    return result


def _search_paths(source, raw_paths):
    result = []
    for raw in raw_paths:
        if not raw:
            continue  # Never search the importing process's working directory.
        origin = str(source.resolve().parent)
        value = raw.replace("${ORIGIN}", origin).replace("$ORIGIN", origin)
        if "$" in value:
            continue  # Unsupported loader substitutions cannot become host paths.
        path = Path(value)
        if path.is_absolute() and path.is_dir() and path not in result:
            result.append(path)
    return result


def _dependency(name, source, info, library_dirs, cache):
    basename = _name(Path(name).name)
    # Explicit directories can replace stale absolute Yocto DT_NEEDED entries.
    locations = [directory / basename for directory in library_dirs]
    locations.extend(directory / basename for directory in _search_paths(source, info["runpath"]))
    if Path(name).is_absolute():
        locations.append(Path(name))
    locations.extend(cache.get(basename, ()))
    for candidate in locations:
        if candidate.is_file():
            return _file(candidate)
    raise BuildError("Cannot resolve shared library " + basename + " required by " + source.name)


def _host_loader():
    for path in (Path("/lib64/ld-linux-x86-64.so.2"),
                 Path("/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2")):
        if path.is_file():
            return path
    raise BuildError("An x86_64 glibc host loader is required")


def import_toolset(sources: dict[str, Path], destination: Path,
                   library_dirs: Iterable[Path] = (), target_assets: dict | None = None) -> dict:
    """Copy trusted host tools and non-glibc DT_NEEDED libraries atomically.

    The destination must be absent or empty.  All patching applies to copies;
    input tools and libraries retain their original contents and permissions.
    The resulting metadata uses relative paths and source basenames only.
    """
    _require(platform.system() == "Linux" and platform.machine() in ("x86_64", "AMD64"),
             "Tool import currently requires a Linux x86_64 host")
    _require(isinstance(sources, dict) and sources, "No host tools were selected")
    selected = {_name(name): _file(path, executable=True) for name, path in sources.items()}
    assets = {}
    _require(isinstance(target_assets or {}, dict), 'targets must be a mapping')
    for architecture, values in (target_assets or {}).items():
        _require(architecture in ('aarch64','armv7','armhf','x86_64') and isinstance(values,dict)
                 and set(values) == {'fakeroot_apk','ownership_library'},
                 'Each target requires fakeroot_apk and ownership_library')
        for name, filename in (('fakeroot_apk','fakeroot.apk'),
                               ('ownership_library','libnaos-chown-compat.so')):
            assets['targets/'+architecture+'/'+filename] = (architecture,_file(values[name]))
    destination = Path(destination).expanduser().absolute()
    _require(not destination.is_symlink(), "Toolset destination must not be a symlink")
    _require(not destination.exists() or (destination.is_dir() and not any(destination.iterdir())),
             "Toolset destination must be absent or empty")
    directories = []
    for item in library_dirs:
        directory = Path(item).expanduser().absolute()
        _require(directory.is_dir(), "Shared-library directory is missing")
        if directory not in directories:
            directories.append(directory)
    readelf, patchelf, ldconfig = (_host_tool(name) for name in ("readelf", "patchelf", "ldconfig"))
    cache = _cache(ldconfig)
    inspected = {}

    def inspect(path):
        identity = path.resolve()
        if identity not in inspected:
            inspected[identity] = _inspect(path, readelf)
        return inspected[identity]

    # Build the complete dependency graph before copying or patching anything.
    graph = {}
    pending = [("bin/" + name, path) for name, path in sorted(selected.items())]
    system_dependencies = set()
    while pending:
        relative, source = pending.pop(0)
        source_hash = _sha256(source)
        if relative in graph:
            _require(graph[relative]["source_sha256"] == source_hash,
                     "Conflicting shared libraries: " + Path(relative).name)
            continue
        info = inspect(source)
        graph[relative] = {"source": source, "source_sha256": source_hash, "elf": info}
        for needed in info["needed"]:
            name = _name(Path(needed).name)
            if _SYSTEM_ABI.fullmatch(name):
                system_dependencies.add(name)
            else:
                pending.append(("lib/" + name, _dependency(needed, source, info, directories, cache)))

    loader = _host_loader() if any(item["elf"]["interpreter"] for item in graph.values()) else None
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix="." + destination.name + "-", dir=destination.parent))
    try:
        (staging / "bin").mkdir()
        (staging / "lib").mkdir()
        records = {}
        for relative, item in sorted(graph.items()):
            source, info = item["source"], item["elf"]
            target = staging / relative
            shutil.copyfile(source, target)
            target.chmod(0o755 if relative.startswith("bin/") else 0o644)
            # Static PIE executables also have a dynamic section for their own
            # relocations, but no loader or shared libraries to relocate.
            if info["needed"] or info["interpreter"] or info["soname"]:
                for needed in info["needed"]:
                    basename = Path(needed).name
                    if needed != basename:
                        run([patchelf, "--replace-needed", needed, basename, target])
                if info["soname"] and info["soname"] != Path(info["soname"]).name:
                    run([patchelf, "--set-soname", Path(info["soname"]).name, target])
                run([patchelf, "--set-rpath", "$ORIGIN/../lib" if relative.startswith("bin/") else "$ORIGIN", target])
                if info["interpreter"] and info["interpreter"] != str(loader):
                    run([patchelf, "--set-interpreter", loader, target])
                patched = _inspect(target, readelf)
                _require(patched["runpath"] == ["$ORIGIN/../lib" if relative.startswith("bin/") else "$ORIGIN"] and
                         all("/" not in name for name in patched["needed"]),
                         "Failed to remove host build paths from " + target.name)
            records[relative] = {"path": relative, "source": source.name,
                                 "source_sha256": item["source_sha256"],
                                 "sha256": _sha256(target), "size": target.stat().st_size,
                                 "architecture": "x86_64", "dynamic": info["dynamic"],
                                 "minimum_glibc": info["minimum_glibc"],
                                 "needed": sorted(Path(name).name for name in info["needed"])}
        if 'openssl' in selected:
            relative = 'share/openssl/openssl.cnf'
            configuration = staging / relative
            configuration.parent.mkdir(parents=True)
            configuration.write_text(_OPENSSL_CONFIG, encoding='utf-8')
            configuration.chmod(0o644)
            records[relative] = {'path':relative, 'generated':True,
                                 'sha256':_sha256(configuration), 'size':configuration.stat().st_size}
        for relative,(architecture,source) in sorted(assets.items()):
            target = staging/relative
            target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(source,target)
            target.chmod(0o644)
            records[relative] = dict(path=relative,source=source.name,architecture=architecture,
                source_sha256=_sha256(source),sha256=_sha256(target),size=target.stat().st_size,
                role='temporary-apk-install-helper')
        glibc = [item["elf"]["minimum_glibc"] for item in graph.values() if item["elf"]["minimum_glibc"]]
        minimum = max(glibc, key=lambda version: tuple(map(int, version.split(".")))) if glibc else None
        metadata = {"schema_version": 1, "host": {"os": "linux", "architecture": "x86_64",
                    "minimum_glibc": minimum, "system_loader": str(loader) if loader else None},
                    "tools": {name: "bin/" + name for name in sorted(selected)},
                    "files": records, "system_dependencies": sorted(system_dependencies)}
        (staging / "toolset.json").write_text(json.dumps(metadata, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        staging.replace(destination)
        return metadata
    finally:
        if staging.exists():
            shutil.rmtree(staging)
