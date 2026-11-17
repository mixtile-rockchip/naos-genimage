# SPDX-License-Identifier: MIT
"""Render a final SPDX 2.3 document from portable build evidence and new inventories.

This module has no BitBake or OpenEmbedded dependency. Supplier release evidence
is retained separately from delivered bytes so a local configuration change does
not silently rewrite a supplier's original checksum or dependency statement.
"""
from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import tempfile
from urllib.parse import quote, urlsplit


_HEX = re.compile(r"[0-9a-f]{64}")
_MODULE = re.compile(r"\.ko(?:\.(?:xz|gz|zst))?$")
_LICENSE_REF = re.compile(r"\bLicenseRef-[A-Za-z0-9.-]+\b")
_RELATIONS = frozenset(("DESCRIBES", "CONTAINS", "GENERATED_FROM", "GENERATES",
    "STATIC_LINK", "OTHER", "DISTRIBUTION_ARTIFACT", "BUILD_TOOL_OF", "DEPENDS_ON",
    "DESCRIBED_BY", "CONTAINED_BY", "DEPENDENCY_OF", "DEPENDENCY_MANIFEST_OF",
    "BUILD_DEPENDENCY_OF", "DEV_DEPENDENCY_OF", "OPTIONAL_DEPENDENCY_OF",
    "PROVIDED_DEPENDENCY_OF", "TEST_DEPENDENCY_OF", "RUNTIME_DEPENDENCY_OF",
    "EXAMPLE_OF", "DYNAMIC_LINK", "DATA_FILE_OF", "TEST_CASE_OF", "TEST_OF",
    "ANCESTOR_OF", "DESCENDANT_OF", "VARIANT_OF", "COPY_OF", "PATCH_FOR", "PATCH_APPLIED",
    "FILE_ADDED", "FILE_DELETED", "FILE_MODIFIED", "EXPANDED_FROM_ARCHIVE",
    "AMENDS", "PREREQUISITE_FOR", "HAS_PREREQUISITE", "REQUIREMENT_DESCRIPTION_FOR",
    "SPECIFICATION_FOR", "OPTIONAL_COMPONENT_OF", "METAFILE_OF", "PACKAGE_OF"))
_SPDX_ID = re.compile(r"SPDXRef-[A-Za-z0-9.-]+\Z")


def _canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _identity(kind, value):
    return "SPDXRef-" + kind + "-" + hashlib.sha256(_canonical(value).encode()).hexdigest()


def _path(value):
    if not isinstance(value, str) or not value or "\0" in value or "\\" in value:
        raise ValueError("Invalid SBOM relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or str(path) == ".":
        raise ValueError("SBOM path must be relative to its declared root")
    return str(path)


def _sha256(value):
    if not isinstance(value, str) or not _HEX.fullmatch(value):
        raise ValueError("SBOM evidence requires a lowercase SHA256 digest")
    return value


def _url(value):
    if not value or value in ("NONE", "NOASSERTION"):
        return "NOASSERTION"
    if not isinstance(value, str) or any(c.isspace() for c in value):
        raise ValueError("Invalid SBOM source URI")
    parsed = urlsplit(value)
    if not parsed.scheme or parsed.username or parsed.password:
        raise ValueError("SBOM source URI is relative or contains credentials")
    # BitBake file:// names identify local build inputs, not downloadable URLs.
    return "NOASSERTION" if parsed.scheme == "file" else value


def _expression(value):
    if not isinstance(value, str) or not value.strip() or value.upper() in (
            "NONE", "NOASSERTION", "CLOSED", "UNKNOWN"):
        return None
    tokens = re.findall(r"\(|\)|[A-Za-z0-9][A-Za-z0-9.+-]*", value)
    if "".join(tokens) != re.sub(r"\s+", "", value):
        return None
    cursor = 0

    def identifier():
        nonlocal cursor
        if cursor >= len(tokens) or tokens[cursor] in ("(", ")", "AND", "OR", "WITH"):
            raise ValueError
        cursor += 1

    def term():
        nonlocal cursor
        if cursor < len(tokens) and tokens[cursor] == "(":
            cursor += 1
            group()
            if cursor >= len(tokens) or tokens[cursor] != ")":
                raise ValueError
            cursor += 1
        else:
            identifier()
        if cursor < len(tokens) and tokens[cursor] == "WITH":
            cursor += 1
            identifier()

    def group():
        nonlocal cursor
        term()
        while cursor < len(tokens) and tokens[cursor] in ("AND", "OR"):
            cursor += 1
            term()
    try:
        group()
    except ValueError:
        return None
    return value.strip() if cursor == len(tokens) else None


def _file_map(inventory):
    result = {}
    for entry in inventory.get("files", []):
        if entry.get("path") == "." and entry.get("kind") == "directory":
            continue
        name = _path(entry.get("path"))
        if name in result:
            raise ValueError("Duplicate final inventory path: " + name)
        if entry.get("kind") in ("regular", "hardlink"):
            _sha256(entry.get("sha256"))
        result[name] = entry
    return result


def _same(first, second):
    fields = ("kind", "sha256", "size", "mode", "link_target", "device_major", "device_minor")
    return first is not None and second is not None and all(first.get(k) == second.get(k) for k in fields)


class _Document:
    def __init__(self):
        self.packages, self.files, self.relationships, self.licenses = {}, {}, set(), {}
        self.limitations, self.unknown_licenses = set(), []
        self.source_checksum_omissions = set()
        self.external_documents = {}
        self.supplier_packages = set()

    def license(self, expression, texts=None, *, owner=None, raw=None):
        parsed = _expression(expression)
        if parsed is None:
            if raw or expression:
                self.unknown_licenses.append({"owner": owner, "declaration": raw or expression})
            return "NOASSERTION"
        mapping = {}
        for name in sorted(set(_LICENSE_REF.findall(parsed))):
            text = (texts or {}).get(name)
            if not isinstance(text, str) or not text:
                self.unknown_licenses.append({"owner": owner, "declaration": parsed,
                                              "missing_license_text": name})
                return "NOASSERTION"
            key = name + "-" + hashlib.sha256(text.encode()).hexdigest()[:16]
            mapping[name] = key
            self.licenses[key] = {"licenseId": key, "extractedText": text,
                                  "name": name, "comment": "Supplier-provided license text; original identifier: " + name}
        return _LICENSE_REF.sub(lambda m:mapping[m.group()], parsed)

    def package(self, kind, identity, *, name, version=None, license_expression=None,
                license_texts=None, raw_license=None, source_info=None, comment=None,
                download=None, homepage=None, external_refs=None, checksums=None):
        identifier = _identity("package-" + kind, identity)
        value = {"SPDXID": identifier, "name": name, "downloadLocation": _url(download),
                 "filesAnalyzed": False, "licenseConcluded": "NOASSERTION",
                 "licenseDeclared": self.license(license_expression, license_texts,
                                                 owner=identifier, raw=raw_license),
                 "copyrightText": "NOASSERTION"}
        if version is not None:
            value["versionInfo"] = str(version)
        if source_info is not None:
            value["sourceInfo"] = _canonical(source_info) if not isinstance(source_info, str) else source_info
        if comment:
            value["comment"] = comment
        if homepage and _url(homepage) != "NOASSERTION":
            value["homepage"] = _url(homepage)
        if external_refs:
            value["externalRefs"] = copy.deepcopy(external_refs)
        if checksums:
            value["checksums"] = [{"algorithm": k, "checksumValue": v} for k, v in sorted(checksums.items())]
        previous = self.packages.setdefault(identifier, value)
        if previous != value:
            raise ValueError("Conflicting SPDX package identity: " + name)
        return identifier

    def file(self, scope, path, record, *, extra=None):
        """Describe bytes, never dereference a target filesystem symlink."""
        kind = record.get("kind", "regular")
        checksums = {}
        if kind in ("regular", "hardlink"):
            checksums["SHA256"] = _sha256(record.get("sha256"))
            if re.fullmatch(r"[0-9a-f]{40}", record.get("sha1") or ""):
                checksums["SHA1"] = record["sha1"]
        elif kind == "symlink":
            target = record.get("link_target")
            if not isinstance(target, str):
                raise ValueError("Symlink lacks target text: " + path)
            data = target.encode("utf-8", errors="surrogateescape")
            checksums = {"SHA256":hashlib.sha256(data).hexdigest(),
                         "SHA1":hashlib.sha1(data, usedforsecurity=False).hexdigest()}
        else:
            return None
        identifier = _identity("file-" + scope, [path, record, extra])
        display = "/" + path if scope == "rootfs" else "initramfs:/" + path if scope == "initramfs" else scope + ":/" + path
        details = {k:v for k, v in record.items() if k not in ("path", "sha256", "sha1")}
        if kind == "symlink":
            details["checksum_scope"] = "UTF-8 symlink target text, not the referenced file"
        if extra is not None:
            details["evidence"] = extra
        self.files[identifier] = {"SPDXID":identifier, "fileName":display,
            "checksums":[{"algorithm":k, "checksumValue":v} for k,v in sorted(checksums.items())],
            "licenseConcluded":"NOASSERTION", "licenseInfoInFiles":["NOASSERTION"],
            "copyrightText":"NOASSERTION", "comment":_canonical(details)}
        return identifier

    def relation(self, source, kind, target, comment=None):
        if source is None or target is None:
            return
        if kind not in _RELATIONS:
            kind, comment = "OTHER", ("Supplier relationship type was not mapped: " + kind + ". " + (comment or ""))
        self.relationships.add((source, kind, target, comment or ""))

    def verification_codes(self):
        contained = {}
        for source, kind, target, _ in self.relationships:
            if kind == "CONTAINS" and target in self.files:
                contained.setdefault(source, set()).add(target)
        for identifier, ids in contained.items():
            if identifier not in self.packages or identifier in self.supplier_packages:
                continue
            values = []
            for fid in ids:
                checksums = {v["algorithm"]:v["checksumValue"] for v in self.files[fid]["checksums"]}
                if "SHA1" not in checksums:
                    break
                values.append(checksums["SHA1"])
            else:
                self.packages[identifier].update(filesAnalyzed=True, licenseInfoFromFiles=["NOASSERTION"],
                    packageVerificationCode={"packageVerificationCodeValue":hashlib.sha1(
                        "".join(sorted(values)).encode(), usedforsecurity=False).hexdigest()})


def _source_packages(document, owner, sources):
    # Older exports copied a recipe's default SRC_URI archive checksum onto
    # every file:// entry. A patch/script cannot inherit the archive's digest.
    # Keep independently supplied local hashes and all remote pins unchanged.
    remote_hashes = {source.get("sha256") for source in sources or []
                     if urlsplit(source.get("uri") or "").scheme != "file" and source.get("sha256")}
    for source in sources or []:
        source = copy.deepcopy(source)
        uri = source.get("uri")
        if urlsplit(uri or "").scheme == "file" and source.get("sha256") in remote_hashes:
            source.pop("sha256")
            source["checksum_evidence"] = "No local checksum asserted: supplier repeated the remote archive checksum."
            document.source_checksum_omissions.add((owner, uri))
        identifier = document.package("source", source, name=uri or "Unspecified supplier source",
            version=source.get("revision"), download=uri, source_info=source,
            checksums={"SHA256":_sha256(source["sha256"])} if source.get("sha256") else None,
            comment="Build source evidence; this is not an asserted installed runtime package.")
        document.relation(owner, "GENERATED_FROM", identifier)


def _purl(value):
    return [{"referenceCategory":"PACKAGE-MANAGER", "referenceType":"purl", "referenceLocator":value}]


def _embedded_sbom(document, record, apk_nodes, final, file_nodes):
    """Import original APK SPDX evidence without asserting it describes edited bytes."""
    path, digest = _path(record["path"]), _sha256(record["sha256"])
    extracted = record.get("extracted", False)
    if type(extracted) is not bool:
        raise ValueError("Embedded APK SBOM extraction flag must be boolean")
    if (not extracted or path in final) and final.get(path, {}).get("sha256") != digest:
        raise ValueError("Embedded APK SBOM differs from final payload: " + path)
    supplier = record["document"]
    if not isinstance(supplier, dict) or supplier.get("spdxVersion") != "SPDX-2.3":
        raise ValueError("Embedded APK SBOM must be SPDX 2.3 JSON")
    namespace = _url(supplier.get("documentNamespace"))
    if namespace == "NOASSERTION" or not _SPDX_ID.fullmatch(supplier.get("SPDXID", "")):
        raise ValueError("Embedded APK SBOM lacks its document identity")
    owner = record["package"]
    installed = apk_nodes.get((owner.get("name"), owner.get("version")))
    if installed is None:
        raise ValueError("Embedded SBOM does not name an installed APK")
    context = {"document_namespace": namespace, "document_sha256": digest, "installed_path": path,
               "extracted_from_rootfs":extracted}
    evidence = document.package("apk-sbom", context, name=supplier.get("name", path),
        source_info=context, comment="Original supplier SBOM shipped by a local APK; supplier checksums describe its original payload.")
    document.relation(installed, "OTHER", evidence, "Supplier SBOM evidence embedded in this installed APK.")
    if extracted:
        original_file = document.file("apk-extracted-sbom", path, {"kind":"regular", "sha256":digest},
            extra={"role":"supplier SBOM extracted before final rootfs packaging"})
        document.relation(evidence, "GENERATED_FROM", original_file)
    else:
        document.relation(evidence, "CONTAINS", file_nodes.get(path))
    nodes, imported = {supplier["SPDXID"]:evidence}, []
    for field in ("packages", "files"):
        records = supplier.get(field, [])
        if not isinstance(records, list):
            raise ValueError("Embedded SBOM element collection must be a list")
        for value in records:
            old_id = value.get("SPDXID") if isinstance(value, dict) else None
            if not isinstance(old_id, str) or not _SPDX_ID.fullmatch(old_id) or old_id in nodes:
                raise ValueError("Invalid or duplicate embedded SBOM SPDX identifier")
            nodes[old_id] = _identity("apk-supplier", [context, old_id])
            imported.append((field, old_id, value))
    if supplier.get("snippets"):
        raise ValueError("Embedded APK SBOM snippets are not supported")
    external = {}
    for item in supplier.get("externalDocumentRefs", []):
        old_id = item.get("externalDocumentId", "")
        if not re.fullmatch(r"DocumentRef-[A-Za-z0-9.-]+", old_id) or old_id in external:
            raise ValueError("Invalid embedded SBOM external document identifier")
        reference = copy.deepcopy(item)
        reference["externalDocumentId"] = "DocumentRef-" + hashlib.sha256(_canonical([context, old_id]).encode()).hexdigest()
        reference["spdxDocument"] = _url(reference.get("spdxDocument"))
        checksum = reference.get("checksum", {})
        if reference["spdxDocument"] == "NOASSERTION" or not checksum.get("algorithm") or not checksum.get("checksumValue"):
            raise ValueError("Embedded SBOM external document lacks URI or checksum")
        external[old_id] = reference["externalDocumentId"]
        document.external_documents[reference["externalDocumentId"]] = reference

    def reference(value):
        if value in nodes:
            return nodes[value]
        if value in ("NONE", "NOASSERTION"):
            return value
        prefix, separator, target = value.partition(":") if isinstance(value, str) else ("", "", "")
        if separator and prefix in external and _SPDX_ID.fullmatch(target):
            return external[prefix] + ":" + target
        raise ValueError("Unresolved embedded SBOM relationship: " + str(value))

    texts = {}
    for item in supplier.get("hasExtractedLicensingInfos", []):
        name, text = item.get("licenseId"), item.get("extractedText")
        if not isinstance(name, str) or not _LICENSE_REF.fullmatch(name) or not isinstance(text, str) or not text:
            raise ValueError("Invalid embedded SBOM extracted license")
        if name in texts and texts[name] != text:
            raise ValueError("Conflicting embedded SBOM extracted license")
        texts[name] = text
    for field, old_id, original in imported:
        value = copy.deepcopy(original)
        value["SPDXID"] = nodes[old_id]
        for name in ("licenseDeclared", "licenseConcluded"):
            if name in value and value[name] not in ("NONE", "NOASSERTION"):
                value[name] = document.license(value[name], texts, owner=nodes[old_id])
        for name in ("licenseInfoFromFiles", "licenseInfoInFiles"):
            if name in value:
                value[name] = [v if v in ("NONE", "NOASSERTION") else document.license(v, texts, owner=nodes[old_id])
                               for v in value[name]]
        for name in ("hasFiles", "fileDependencies"):
            if name in value:
                value[name] = [reference(v) for v in value[name]]
        if field == "packages":
            if not isinstance(value.get("name"), str) or not value["name"]:
                raise ValueError("Embedded SBOM package lacks its name")
            value["downloadLocation"] = _url(value.get("downloadLocation"))
            value["sourceInfo"] = _canonical({**context, "supplier_spdx_id":old_id,
                                              "supplier_source_info":original.get("sourceInfo")})
            document.packages[nodes[old_id]] = value
            document.supplier_packages.add(nodes[old_id])
        else:
            if not isinstance(value.get("fileName"), str) or not value["fileName"] or not value.get("checksums"):
                raise ValueError("Embedded SBOM file lacks its name or checksums")
            value["fileName"] = "supplier-apk:/" + value["fileName"].lstrip("./")
            value["comment"] = _canonical({**context, "supplier_spdx_id":old_id,
                                          "supplier_comment":original.get("comment")})
            document.files[nodes[old_id]] = value
    described = set(supplier.get("documentDescribes", []))
    for relation in supplier.get("relationships", []):
        source, target = relation.get("spdxElementId"), relation.get("relatedSpdxElement")
        kind = relation.get("relationshipType")
        if not isinstance(kind, str) or not kind:
            raise ValueError("Embedded SBOM relationship lacks its type")
        document.relation(reference(source), kind, reference(target), relation.get("comment"))
        if source == supplier["SPDXID"] and kind == "DESCRIBES":
            described.add(target)
        if target == supplier["SPDXID"] and kind == "DESCRIBED_BY":
            described.add(source)
    package_ids = {old_id for field, old_id, _ in imported if field == "packages"}
    element_ids = {old_id for _, old_id, _ in imported}
    if not described and len(package_ids) == 1:
        described = package_ids
    for old_id in sorted(described):
        if old_id not in element_ids:
            raise ValueError("Embedded SBOM describes an absent element")
        document.relation(installed, "GENERATED_FROM", nodes[old_id],
                          "Supplier release evidence; final installed files are inventoried separately.")
    return len(imported)


def _release(document, delivered, component, final_files, file_nodes, owned_paths):
    release = component["release_sbom"]
    if release.get("schema_version") != 1 or release.get("spdx_version") != "SPDX-2.3":
        raise ValueError("Unsupported normalized supplier release SBOM")
    package_map = {v["spdx_id"]:v for v in release["packages"]}
    if len(package_map) != len(release["packages"]) or release["main_package"] not in package_map:
        raise ValueError("Invalid supplier release package identities")
    context = [component["recipe"], release["document_namespace"], release["document_sha256"]]
    nodes = {}
    for old_id, package in sorted(package_map.items()):
        nodes[old_id] = document.package("release-input", [context, old_id], name=package["name"],
            version=package.get("version"), license_expression=package.get("license_declared"),
            license_texts=release.get("license_texts", {}), download=package.get("download_location"),
            homepage=package.get("homepage"), external_refs=package.get("external_refs"),
            checksums=package.get("checksums"), source_info={"supplier_package":package,
                "release_document":release["document_namespace"], "release_document_sha256":release["document_sha256"]},
            comment="Original supplier release evidence. Its checksums are not rewritten after image customization.")
    main = release["main_package"]
    document.relation(delivered, "GENERATED_FROM", nodes[main])
    changed, binary_changed, verified = [], [], 0
    release_files = {}
    for record in release.get("files", []):
        old_id = record["spdx_id"]
        if old_id in nodes or old_id in release_files:
            raise ValueError("Duplicate supplier release SPDX identifier")
        original = document.file("supplier-release", _path(record["path"]),
            {"kind":"regular", "sha256":_sha256(record["sha256"])}, extra=context)
        release_files[old_id] = original
        installed = record.get("installed_path")
        if installed is None:
            continue
        installed = _path(installed)
        current = final_files.get(installed)
        if current is not None and current.get("sha256") == record["sha256"]:
            if record.get("installed_verified") is not True:
                raise ValueError("Supplier installed-file mapping was not verified")
            verified += 1
            if installed in owned_paths:
                document.relation(delivered, "CONTAINS", file_nodes.get(installed))
        else:
            changed.append(installed)
            if installed.startswith(("usr/bin/", "bin/", "usr/sbin/", "sbin/")) or ".so" in PurePosixPath(installed).name:
                binary_changed.append(installed)
            if installed in file_nodes:
                document.relation(file_nodes[installed], "GENERATED_FROM", original,
                                  "Supplier file was replaced or customized during image generation.")
    for relation in release.get("relationships", []):
        source = nodes.get(relation["source"]) or release_files.get(relation["source"])
        target = nodes.get(relation["target"]) or release_files.get(relation["target"])
        if source is None or target is None:
            # Normalization omits the supplier document, while retaining its hash.
            if relation["source"] == "SPDXRef-DOCUMENT":
                continue
            raise ValueError("Unresolved supplier release relationship")
        document.relation(source, relation["type"], target, relation.get("comment"))
    reached, pending = {main}, [main]
    while pending:
        current = pending.pop()
        for relation in release.get("relationships", []):
            if relation["source"] == current and relation["type"] == "STATIC_LINK":
                if relation["target"] not in package_map:
                    raise ValueError("Supplier static-link relation does not name a package")
                if relation["target"] not in reached:
                    reached.add(relation["target"])
                    pending.append(relation["target"])
    if binary_changed:
        document.limitations.add(component["recipe"] + " executable payload changed; supplier static dependencies are retained as input evidence, not asserted for the replacement binaries.")
    else:
        for identifier in sorted(reached - {main}):
            document.relation(delivered, "STATIC_LINK", nodes[identifier],
                              "Supplier dependency evidence applies to the verified, unchanged application binaries.")
    document.limitations.update(release.get("limitations", []))
    return {"verified_files":verified, "modified_files":changed,
            "static_dependencies":len(reached) - 1, "binary_changed":binary_changed}


def _write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2) + "\n").encode()
    with tempfile.NamedTemporaryFile(prefix="." + path.name + "-", dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(payload)
            stream.flush()
            os.fchmod(stream.fileno(), 0o644)
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
    return payload


def render_sbom(inputs: Path, output: Path, rootfs_inventory: dict, initramfs_inventory: dict,
                artifacts: dict, metadata: dict, *, additional_components: list[dict] | None = None) -> dict:
    """Write final SPDX/summary, using source evidence from an exported package.

    ``artifacts`` maps output-relative names to SHA256/size/role records. Extra
    components use the same normalized evidence schema as components.json;
    this preserves an extension point for separately supplied business SBOMs.
    """
    inputs, output = Path(inputs), Path(output)
    evidence_path = inputs / "sbom/components.json"
    if not evidence_path.is_file() or not (inputs / "sbom/inventory.json").is_file():
        raise ValueError("SBOM inputs were not exported; rebuild the input package with NAOS_SBOM=1")
    evidence = json.loads(evidence_path.read_text())
    baseline = json.loads((inputs / "sbom/inventory.json").read_text())
    if evidence.get("schema_version") != 1 or baseline.get("schema_version") != 1:
        raise ValueError("Unsupported portable SBOM evidence schema")
    for name in ("machine", "profile"):
        if evidence.get(name) != metadata.get(name):
            raise ValueError("SBOM evidence belongs to another " + name)
    machine, version, build_id = (str(metadata[k]) for k in ("machine", "version", "build_id"))
    epoch = int(metadata["epoch"])
    if epoch < 0:
        raise ValueError("Invalid SBOM creation epoch")
    if output.suffix != ".json":
        output /= "naos-" + str(metadata.get("board",machine)) + "-" + version + ".spdx.json"
    document = _Document()
    product = document.package("product", [machine, version, build_id], name="NAOS " + machine,
        version=version, source_info={k:metadata[k] for k in (
            "machine", "board", "profile", "version", "build_id", "compatible", "generator_version") if k in metadata},
        comment="Final generated firmware. File hashes describe the delivered filesystem before optional encryption.")
    document.relation("SPDXRef-DOCUMENT", "DESCRIBES", product)
    rootfs = document.package("filesystem", [machine, version], name="NAOS final root filesystem", version=version)
    document.relation(product, "CONTAINS", rootfs)
    artifact_nodes = {}
    for name, record in sorted(artifacts.items()):
        name = _path(name)
        if name == output.name:
            raise ValueError("An SBOM cannot include its own output checksum")
        if type(record.get("size")) is not int or record["size"] < 0:
            raise ValueError("Final artifact has an invalid size")
        artifact_nodes[name] = document.file("output", name, record, extra={"role":record.get("role")})
        document.relation(product, "DISTRIBUTION_ARTIFACT", artifact_nodes[name])
    if not artifact_nodes:
        raise ValueError("Final SBOM requires final image artifact checksums")
    for name in ("system.img", "system.squashfs"):
        document.relation(rootfs, "DISTRIBUTION_ARTIFACT", artifact_nodes.get(name))

    final = _file_map(rootfs_inventory)
    initial = _file_map(baseline["rootfs"])
    ramdisk = _file_map(initramfs_inventory)
    old_ramdisk = _file_map(baseline["initramfs"])
    root_nodes = {p:document.file("rootfs", p, r) for p,r in final.items()}
    ramdisk_nodes = {p:document.file("initramfs", p, r) for p,r in ramdisk.items()}
    for node in root_nodes.values():
        document.relation(rootfs, "CONTAINS", node)
    changes = {"rootfs":{p for p in set(initial) | set(final) if not _same(initial.get(p), final.get(p))},
               "initramfs":{p for p in set(old_ramdisk) | set(ramdisk) if not _same(old_ramdisk.get(p), ramdisk.get(p))}}
    for scope, inventory in (("rootfs", rootfs_inventory), ("initramfs", initramfs_inventory)):
        changes[scope].update(_path(record["path"]) for record in inventory.get("generator_changes", []))
        changes[scope] = sorted(changes[scope])
    custom = document.package("customizations", [machine, version, changes], name="NAOS image customizations",
        source_info=changes, comment="Generated fingerprints, replaced configuration/certificates and added business files; no license or unreported dependency is inferred.")
    if changes["rootfs"] or changes["initramfs"]:
        document.relation(product, "CONTAINS", custom)
    for scope, old, current, nodes in (("rootfs", initial, final, root_nodes),
                                       ("initramfs", old_ramdisk, ramdisk, ramdisk_nodes)):
        for path in changes[scope]:
            if path in nodes:
                document.relation(custom, "CONTAINS", nodes[path])
                document.relation(custom, "GENERATES", nodes[path])
            if path in old:
                previous = document.file("original-" + scope, path, old[path], extra={"role":"generator input"})
                document.relation(nodes.get(path), "GENERATED_FROM", previous)

    components = copy.deepcopy(evidence.get("components", [])) + copy.deepcopy(additional_components or [])
    identities = [(c.get("recipe"), c.get("name"), c.get("version")) for c in components]
    if len(set(identities)) != len(identities):
        raise ValueError("Duplicate SBOM component identity")
    # A more specific producer claim wins over an APK's original path record.
    # Modified baseline payloads belong to customization; separately supplied
    # business evidence may explicitly claim the newly installed files.
    extra_ids = {tuple(v) for v in identities[len(evidence.get('components', [])):]}
    owners = {}
    for component in components:
        identity = (component.get("recipe"), component.get("name"), component.get("version"))
        extra = identity in extra_ids
        if extra:
            for path, expected in component.get("payload_hashes", {}).items():
                if path not in final or final[path].get("sha256") != _sha256(expected):
                    raise ValueError("Additional component differs from final payload: " + path)
        prefixes = set(component.get("payload_paths", []))
        prefixes.update(v["path"] for v in component.get("modules", []))
        for prefix in prefixes:
            prefix = _path(prefix)
            score = len(PurePosixPath(prefix).parts)
            for path in final:
                if (path == prefix or path.startswith(prefix + "/")) and (extra or path not in changes["rootfs"]):
                    previous = owners.get(path)
                    if previous is None or score > previous[0]:
                        owners[path] = (score, identity)
                    elif score == previous[0] and identity != previous[1]:
                        raise ValueError("Ambiguous component ownership: " + path)
    component_nodes = {}
    claimed = set()
    static_dependencies, release_verified_files, release_components = 0, 0, 0
    module_paths, matched_modules, initramfs_packages = set(), set(), 0

    baseline_apks = {(p["name"], p["version"], p.get("architecture")):p
                     for p in baseline["rootfs"].get("packages", [])}
    apk_owned, apk_nodes, local_owned = set(), {}, set()
    local_archives = {(p["name"], p["version"]):p for p in rootfs_inventory.get("local_apks", [])}
    for package in rootfs_inventory.get("packages", []):
        key = (package["name"], package["version"], package.get("architecture"))
        original = baseline_apks.get(key, {})
        expression = package.get("license_expression", original.get("license_expression"))
        texts = package.get("license_texts", original.get("license_texts", {}))
        info = {k:package.get(k, original.get(k)) for k in (
            "origin", "aports_commit", "depends", "apk_control_checksum", "archive", "license")}
        local = local_archives.get(key[:2])
        if local:
            info["archive"] = {"name":_path(local["filename"]), "sha256":_sha256(local["sha256"])}
        info["file_records"] = package.get("files", [])
        node = document.package("apk", key, name=package["name"], version=package["version"],
            license_expression=expression, license_texts=texts, raw_license=package.get("license"),
            source_info=info, homepage=package.get("homepage"), external_refs=_purl(
                "pkg:apk/alpine/" + quote(package["name"], safe="") + "@" + quote(package["version"], safe="")
                + ("?arch=" + quote(package["architecture"], safe="") if package.get("architecture") else "")))
        if key[:2] in apk_nodes:
            raise ValueError("Ambiguous installed APK identity")
        apk_nodes[key[:2]] = node
        document.relation(rootfs, "CONTAINS", node)
        for record in package.get("files", []):
            path = _path(record["path"])
            if path in final:
                apk_owned.add(path)
                unchanged_local = local is not None and record.get("status") == "unchanged"
                if (path not in changes["rootfs"] or unchanged_local) and path not in owners:
                    document.relation(node, "CONTAINS", root_nodes.get(path))
                    if unchanged_local:
                        local_owned.add(path)
        archive = info.get("archive")
        if archive and archive.get("sha256"):
            source = document.file("apk-source", _path(archive["name"]), archive,
                                   extra={"role":"original APK archive, not final installed bytes"})
            document.relation(node, "GENERATED_FROM", source)

    embedded_sboms = rootfs_inventory.get("additional_sbom", [])
    if not isinstance(embedded_sboms, list):
        raise ValueError("Embedded APK SBOM evidence must be a list")
    embedded_elements = sum(_embedded_sbom(document, record, apk_nodes, final, root_nodes)
                            for record in embedded_sboms)

    for component in sorted(components, key=lambda c:_canonical([c.get("recipe"), c.get("name"), c.get("version")])):
        recipe = component.get("recipe", component.get("name"))
        if not recipe or recipe.endswith("-native") or component.get("is_native"):
            raise ValueError("Runtime SBOM cannot import a host/native component")
        node = document.package("component", [recipe, component.get("name"), component.get("version")],
            name=component.get("name", recipe), version=component.get("version"),
            license_expression=component.get("license_expression"), license_texts=component.get("license_texts"),
            raw_license=component.get("license"), homepage=component.get("homepage"),
            source_info={k:component[k] for k in ("recipe", "cve_product", "prebuilt", "build_evidence") if k in component})
        component_nodes[recipe] = node
        document.relation(product, "CONTAINS", node)
        _source_packages(document, node, component.get("sources"))
        identity = (component.get("recipe"), component.get("name"), component.get("version"))
        owned_paths = {path for path, (_, owner) in owners.items() if owner == identity}
        for path in owned_paths:
            document.relation(node, "CONTAINS", root_nodes.get(path))
            claimed.add(path)
        mismatches = [path for path, checksum in component.get("payload_hashes", {}).items()
                      if path not in final or final[path].get("sha256") != checksum]
        if mismatches:
            document.packages[node]["comment"] = _canonical({"generator_modified_or_removed_payloads":sorted(mismatches),
                "supplier_payload_hashes":component["payload_hashes"]})
        for artifact in component.get("artifacts", []):
            original = document.file("build-input", _path(artifact["path"]), artifact,
                                     extra={"role":"unsigned/unfinalized generator input"})
            document.relation(node, "GENERATED_FROM", original)
        configuration = component.get("configuration")
        if configuration:
            config_node = document.file("build-input", _path(configuration["file"]), configuration,
                                        extra={"role":"effective build configuration"})
            document.relation(node, "OTHER", config_node, "This exact configuration selected the compiled functionality.")
        for module in component.get("modules", []):
            path = _path(module["path"])
            module_paths.add(path)
            if path in final and final[path].get("sha256") == module["sha256"]:
                document.relation(node, "CONTAINS", root_nodes.get(path))
                claimed.add(path)
                matched_modules.add(path)
        for firmware in component.get("firmware_inputs", []):
            role = firmware["role"]
            record = document.package("firmware", [recipe, firmware], name="Rockchip " + role + " firmware",
                version=firmware.get("version"), source_info=firmware,
                license_expression=firmware.get("license_expression") or next((k for k in (
                    "LicenseRef-Rockchip-rkbin", "LicenseRef-ROCKCHIP") if k in component.get("license_texts", {})), None),
                license_texts=component.get("license_texts"),
                comment="Opaque vendor firmware; internal dependencies are not inferred.")
            original = document.file("build-input", _path(firmware.get("exported_path", firmware["path"])), firmware)
            document.relation(record, "CONTAINS", original)
            document.relation(node, "CONTAINS", record)
        spl = component.get("spl")
        if spl:
            if spl.get("source_built") is not True:
                raise ValueError("SPL metadata does not identify a source-built input")
            spl_node = document.package("spl", spl, name="U-Boot source-built SPL",
                version=component.get("version"), source_info=spl,
                license_expression=component.get("license_expression"), license_texts=component.get("license_texts"))
            document.relation(node, "CONTAINS", spl_node)
            document.relation(spl_node, "CONTAINS", document.file("build-input", _path(spl["path"]), spl))
        if "modules" in component:
            document.relation(artifact_nodes.get("boot.img"), "CONTAINS", node)
        if component.get("release_sbom"):
            report = _release(document, node, component, final, root_nodes, owned_paths)
            release_verified_files += report["verified_files"]
            static_dependencies += report["static_dependencies"]
            release_components += 1
        if "image_packages" in component:
            document.relation(artifact_nodes.get("boot.img"), "CONTAINS", node)
            for file_node in ramdisk_nodes.values():
                document.relation(node, "CONTAINS", file_node)
            for package in component["image_packages"]:
                package_node = document.package("initramfs-package", [recipe, package["name"], package["version"], package.get("architecture")],
                    name=package["name"], version=package["version"],
                    license_expression=package.get("license_expression"), license_texts=package.get("license_texts"),
                    raw_license=package.get("license"), homepage=package.get("homepage"),
                    source_info={k:package.get(k) for k in ("architecture", "source_recipe", "source_version", "cve_product")})
                document.relation(node, "CONTAINS", package_node)
                _source_packages(document, package_node, package.get("sources"))
                for path in package.get("files", []):
                    path = _path(path)
                    if path not in changes["initramfs"]:
                        document.relation(package_node, "CONTAINS", ramdisk_nodes.get(path))
                initramfs_packages += 1
    actual_modules = {p for p, entry in final.items() if _MODULE.search(p) and entry.get("kind") != "directory"}
    if actual_modules != matched_modules:
        document.limitations.add("Kernel module provenance is incomplete after customization: " +
            _canonical({"new_or_changed":sorted(actual_modules - matched_modules), "removed":sorted(module_paths - actual_modules)}))
    unowned = sorted(p for p, entry in final.items() if entry.get("kind") in ("regular", "hardlink", "symlink")
                     and p not in claimed and p not in apk_owned and p not in changes["rootfs"])
    if unowned:
        document.limitations.add(str(len(unowned)) + " final rootfs files have no asserted package owner.")
    added_business = [p for p in changes["rootfs"] if p not in initial and p in final]
    uncovered_business = [p for p in added_business if p not in local_owned
                          and (p not in owners or owners[p][1] not in extra_ids)]
    if uncovered_business:
        document.limitations.add("Added business files have no additional component SBOM; their bytes are inventoried without inventing license or static dependency statements.")
    if document.source_checksum_omissions:
        document.limitations.add(str(len(document.source_checksum_omissions)) +
            " local-source checksum assertions were omitted because the supplier export repeated a remote archive digest; source names remain inventoried, while remote archive hashes and Git revision pins are preserved.")
    document.limitations.add("Directories and special-file metadata remain in the final inventories; SPDX checksum File elements describe regular files, hardlinks and symlink target text.")
    document.verification_codes()
    known = set(document.packages) | set(document.files) | {"SPDXRef-DOCUMENT", "NONE", "NOASSERTION"}
    def resolved(identifier):
        prefix, _, target = identifier.partition(":")
        return identifier in known or (prefix in document.external_documents and _SPDX_ID.fullmatch(target))
    for source, _, target, _ in document.relationships:
        if not resolved(source) or not resolved(target):
            raise ValueError("Final SPDX document contains an unresolved relationship")
    value = {"spdxVersion":"SPDX-2.3", "dataLicense":"CC0-1.0", "SPDXID":"SPDXRef-DOCUMENT",
        "name":"NAOS " + machine + " " + version,
        "creationInfo":{"created":datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "creators":["Organization: NAOS", "Tool: naos-image-generator-" + str(metadata.get("generator_version", "unknown"))],
                        "licenseListVersion":str(evidence.get("license_list_version", "3.28.0"))},
        "packages":sorted(document.packages.values(), key=lambda v:v["SPDXID"]),
        "files":sorted(document.files.values(), key=lambda v:v["SPDXID"]),
        "relationships":[dict(spdxElementId=a, relationshipType=b, relatedSpdxElement=c,
                              **({"comment":d} if d else {})) for a,b,c,d in sorted(document.relationships)],
        "comment":_canonical({"scope":"Final generated image and actual final filesystem bytes",
            "limitations":sorted(document.limitations), "unowned_rootfs_paths":unowned,
            "unknown_license_declarations":document.unknown_licenses})}
    if document.licenses:
        value["hasExtractedLicensingInfos"] = sorted(document.licenses.values(), key=lambda v:v["licenseId"])
    if document.external_documents:
        value["externalDocumentRefs"] = sorted(document.external_documents.values(), key=lambda v:v["externalDocumentId"])
    value["documentNamespace"] = "https://spdx.org/spdxdocs/naos-image-" + hashlib.sha256(_canonical(value).encode()).hexdigest()
    payload = _write_json(output, value)
    summary_path = output.with_name(output.name.removesuffix(".spdx.json") + ".sbom.json")
    summary = {"schema_version":1, "format":"SPDX-2.3", "file":output.name,
        "sha256":hashlib.sha256(payload).hexdigest(), "size":len(payload), "summary_file":summary_path.name,
        "machine":machine, "profile":metadata["profile"], "version":version, "build_id":build_id,
        "packages":len(document.packages), "files":len(document.files), "relationships":len(document.relationships),
        "apk_packages":len(rootfs_inventory.get("packages", [])), "components":len(components),
        "kernel_modules":len(actual_modules), "matched_kernel_modules":len(matched_modules),
        "initramfs_packages":initramfs_packages, "final_rootfs_files":len(final), "final_initramfs_files":len(ramdisk),
        "release_sbom_components":release_components, "release_static_dependencies":static_dependencies,
        "release_verified_payload_files":release_verified_files, "changes":changes,
        "embedded_apk_sboms":len(embedded_sboms), "embedded_apk_sbom_elements":embedded_elements,
        "source_checksum_omissions":len(document.source_checksum_omissions),
        "unowned_rootfs_files":len(unowned), "unknown_license_declarations":len(document.unknown_licenses),
        "references_closed":True, "limitations":sorted(document.limitations)}
    _write_json(summary_path, summary)
    return summary
