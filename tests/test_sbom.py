import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from naos_image_generator.sbom import render_sbom


def file_record(path, data=b"data", **extra):
    return {"path":path, "kind":"regular", "sha256":hashlib.sha256(data).hexdigest(),
            "sha1":hashlib.sha1(data, usedforsecurity=False).hexdigest(), "size":len(data),
            "mode":"0644", "uid":0, "gid":0, **extra}


def component(name, paths=(), **extra):
    return {"schema_version":1, "name":name, "recipe":name, "version":"1.0",
            "license":"MIT", "license_expression":"MIT", "license_texts":{},
            "sources":[{"uri":"https://example.invalid/" + name + ".git", "revision":"abc123"}],
            "payload_paths":list(paths), **extra}


def release(name, files):
    records = [{"spdx_id":"SPDXRef-file-" + str(i), "path":path,
                "installed_path":path, "installed_verified":True, "sha256":record["sha256"]}
               for i, (path, record) in enumerate(sorted(files.items()))]
    return {"schema_version":1, "spdx_version":"SPDX-2.3", "archive_verified":True,
        "document_namespace":"https://example.invalid/releases/" + name,
        "document_sha256":hashlib.sha256(name.encode()).hexdigest(), "main_package":"SPDXRef-main",
        "packages":[{"spdx_id":"SPDXRef-main", "name":name, "version":"1.0",
                     "license_declared":"NOASSERTION", "download_location":"NOASSERTION"},
                    {"spdx_id":"SPDXRef-library", "name":name + "-static-library", "version":"2.0",
                     "license_declared":"BSD-3-Clause", "download_location":"NOASSERTION"}],
        "relationships":[{"source":"SPDXRef-main", "type":"STATIC_LINK", "target":"SPDXRef-library"},
            {"source":"SPDXRef-DOCUMENT", "type":"DESCRIBES", "target":"SPDXRef-main"}] +
            [{"source":"SPDXRef-main", "type":"CONTAINS", "target":r["spdx_id"]} for r in records],
        "files":records, "license_texts":{}, "limitations":[]}


class SBOMTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.inputs = self.directory / "inputs"
        (self.inputs / "sbom").mkdir(parents=True)
        files = [file_record(p, p.encode()) for p in (
            "etc/rauc/keyring.pem", "usr/bin/naos-core", "etc/naos-core/device.ini", "usr/bin/naos",
            "usr/bin/rauc", "usr/bin/rauc-hawkbit-updater", "lib/modules/test/driver.ko")]
        self.rootfs = {"schema_version":1, "files":files, "metadata":{},
            "packages":[{"name":"base", "version":"1", "architecture":"aarch64", "license":"Public-Domain",
                         "license_expression":None, "files":[{"path":v["path"], "sha256":v["sha256"],
                             "status":"unchanged"} for v in files]}]}
        self.ramdisk = {"schema_version":1, "files":[file_record("init"), file_record("usr/bin/helper")],
                        "packages":[], "metadata":{}}
        by_path = {v["path"]:v for v in files}
        core_files = {p:by_path[p] for p in ("usr/bin/naos-core", "etc/naos-core/device.ini")}
        container_files = {"usr/bin/naos":by_path["usr/bin/naos"]}
        self.components = [
            component("linux-naos-rockchip", ("lib/modules/test",), modules=[by_path["lib/modules/test/driver.ko"]]),
            component("u-boot-naos-rockchip", license_expression="GPL-2.0-only AND LicenseRef-vendor",
                      license_texts={"LicenseRef-vendor":"Vendor firmware notice"}, firmware_inputs=[{
                          "role":"ddr", "path":"bin/DDR.bin", "exported_path":"bootloader/bin/DDR.bin",
                          "version":"1.0", "sha256":hashlib.sha256(b"ddr").hexdigest(), "size":3}]),
            component("rauc", ("usr/bin/rauc",)),
            component("rauc-hawkbit-updater", ("usr/bin/rauc-hawkbit-updater",)),
            component("naos-core", core_files, payload_hashes={p:v["sha256"] for p,v in core_files.items()},
                      release_sbom=release("naos-core", core_files)),
            component("naos-container", container_files, release_sbom=release("naos-container", container_files)),
            component("naos-initramfs-encrypted", image_packages=[{
                "name":"busybox", "version":"1", "files":["init"], "source_recipe":"busybox",
                "sources":[], "license_expression":"GPL-2.0-only", "license_texts":{}}, {
                "name":"helper", "version":"1", "files":["usr/bin/helper"], "source_recipe":"helper",
                "sources":[], "license_expression":"MIT", "license_texts":{}}]),
        ]
        self.evidence = {"schema_version":1, "machine":"board", "profile":"production",
                         "license_list_version":"3.28.0", "components":self.components}
        self.baseline = {"schema_version":1, "rootfs":copy.deepcopy(self.rootfs),
                         "initramfs":copy.deepcopy(self.ramdisk)}
        self.write_inputs()
        self.artifacts = {"boot.img":{"sha256":hashlib.sha256(b"boot").hexdigest(), "size":4, "role":"boot"}}
        self.metadata = dict(machine="board", profile="production", version="2", build_id="ci-1",
                             epoch=1700000000, compatible="board-v1", generator_version="0.1")

    def write_inputs(self):
        (self.inputs / "sbom/components.json").write_text(json.dumps(self.evidence))
        (self.inputs / "sbom/inventory.json").write_text(json.dumps(self.baseline))

    def render(self, **extra):
        output = self.directory / "firmware.spdx.json"
        summary = render_sbom(self.inputs, output, self.rootfs, self.ramdisk, self.artifacts, self.metadata, **extra)
        document = json.loads(output.read_text())
        return summary, document

    def test_static_dependencies_licenses_and_closed_references(self):
        summary, doc = self.render()
        self.assertEqual(summary["format"], "SPDX-2.3")
        self.assertEqual(summary["release_static_dependencies"], 2)
        self.assertEqual(summary["kernel_modules"], 1)
        self.assertEqual(summary["initramfs_packages"], 2)
        self.assertTrue(doc["hasExtractedLicensingInfos"])
        ids = {p["SPDXID"] for key in ("packages", "files") for p in doc[key]} | {"SPDXRef-DOCUMENT"}
        self.assertTrue(all(r["spdxElementId"] in ids and r["relatedSpdxElement"] in ids for r in doc["relationships"]))
        base = next(p for p in doc["packages"] if p["name"] == "base")
        self.assertEqual(base["licenseDeclared"], "NOASSERTION")
        kernel = next(p for p in doc["packages"] if p["name"] == "linux-naos-rockchip")
        driver = next(f for f in doc["files"] if f["fileName"] == "/lib/modules/test/driver.ko")
        self.assertTrue(any(r["spdxElementId"] == kernel["SPDXID"] and r["relatedSpdxElement"] == driver["SPDXID"] for r in doc["relationships"]))
        self.assertFalse(any(r["spdxElementId"] == base["SPDXID"] and r["relatedSpdxElement"] == driver["SPDXID"] for r in doc["relationships"]))

    def test_configuration_changes_keep_original_release_checksums(self):
        path = "etc/naos-core/device.ini"
        original = next(v for v in self.rootfs["files"] if v["path"] == path)["sha256"]
        self.rootfs["files"] = [file_record(path, b"custom") if v["path"] == path else v for v in self.rootfs["files"]]
        summary, doc = self.render()
        self.assertIn(path, summary["changes"]["rootfs"])
        self.assertEqual(summary["release_verified_payload_files"], 2)
        original_files = [v for v in doc["files"] if v["fileName"].startswith("supplier-release:/") and v["fileName"].endswith(path)]
        self.assertTrue(any(any(c["checksumValue"] == original for c in f["checksums"]) for f in original_files))
        core = next(p for p in doc["packages"] if p["name"] == "naos-core" and p["SPDXID"].startswith("SPDXRef-package-component-"))
        self.assertTrue(any(r["spdxElementId"] == core["SPDXID"] and r["relationshipType"] == "STATIC_LINK" for r in doc["relationships"]))

    def test_replaced_binary_does_not_claim_old_runtime_dependencies(self):
        self.rootfs["files"] = [file_record("usr/bin/naos-core", b"replacement") if v["path"] == "usr/bin/naos-core" else v for v in self.rootfs["files"]]
        summary, doc = self.render()
        core = next(p for p in doc["packages"] if p["name"] == "naos-core" and p["SPDXID"].startswith("SPDXRef-package-component-"))
        self.assertFalse(any(r["spdxElementId"] == core["SPDXID"] and r["relationshipType"] == "STATIC_LINK" for r in doc["relationships"]))
        self.assertTrue(any("executable payload changed" in v for v in summary["limitations"]))
        self.assertTrue(any(r["relationshipType"] == "STATIC_LINK" for r in doc["relationships"]))

    def test_new_fingerprint_is_generator_owned(self):
        path = "usr/lib/naos/system-key.sha256"
        self.ramdisk["files"].append(file_record(path, b"example fingerprint\n"))
        summary, doc = self.render()
        self.assertIn(path, summary["changes"]["initramfs"])
        custom = next(p for p in doc["packages"] if p["name"] == "NAOS image customizations")
        fingerprint = next(f for f in doc["files"] if f["fileName"] == "initramfs:/" + path)
        self.assertTrue(any(r["spdxElementId"] == custom["SPDXID"] and r["relatedSpdxElement"] == fingerprint["SPDXID"] for r in doc["relationships"]))

    def test_package_verification_code_uses_actual_sha1(self):
        _, doc = self.render()
        rootfs = next(p for p in doc["packages"] if p["name"] == "NAOS final root filesystem")
        expected = hashlib.sha1("".join(sorted(v["sha1"] for v in self.rootfs["files"])).encode(), usedforsecurity=False).hexdigest()
        self.assertTrue(rootfs["filesAnalyzed"])
        self.assertEqual(rootfs["packageVerificationCode"]["packageVerificationCodeValue"], expected)

    def test_added_business_component_can_supply_its_own_evidence(self):
        record = file_record("opt/app/application", b"application")
        self.rootfs["files"].append(record)
        extra = component("business-app", (record["path"],), payload_hashes={record["path"]:record["sha256"]})
        _, doc = self.render(additional_components=[extra])
        business = next(p for p in doc["packages"] if p["name"] == "business-app")
        payload = next(f for f in doc["files"] if f["fileName"] == "/opt/app/application")
        self.assertTrue(any(r["spdxElementId"] == business["SPDXID"] and r["relatedSpdxElement"] == payload["SPDXID"] for r in doc["relationships"]))

    def embedded_apk(self, name="business", namespace="https://example.invalid/business/sbom"):
        package = {"SPDXID":"SPDXRef-main", "name":name, "versionInfo":"1.0",
                   "downloadLocation":"NOASSERTION", "filesAnalyzed":False,
                   "licenseConcluded":"NOASSERTION", "licenseDeclared":"LicenseRef-vendor",
                   "copyrightText":"NOASSERTION"}
        supplier = {"spdxVersion":"SPDX-2.3", "SPDXID":"SPDXRef-DOCUMENT", "name":name,
            "documentNamespace":namespace, "packages":[package, {**package,
                "SPDXID":"SPDXRef-library", "name":name+"-library", "licenseDeclared":"MIT"}],
            "files":[{"SPDXID":"SPDXRef-binary", "fileName":"usr/bin/"+name,
                "checksums":[{"algorithm":"SHA256", "checksumValue":hashlib.sha256(name.encode()).hexdigest()}],
                "licenseConcluded":"NOASSERTION", "licenseInfoInFiles":["LicenseRef-vendor"],
                "copyrightText":"NOASSERTION"}],
            "hasExtractedLicensingInfos":[{"licenseId":"LicenseRef-vendor", "extractedText":name+" license"}],
            "relationships":[{"spdxElementId":"SPDXRef-DOCUMENT", "relationshipType":"DESCRIBES", "relatedSpdxElement":"SPDXRef-main"},
                {"spdxElementId":"SPDXRef-main", "relationshipType":"RUNTIME_DEPENDENCY_OF", "relatedSpdxElement":"SPDXRef-library"},
                {"spdxElementId":"SPDXRef-main", "relationshipType":"CONTAINS", "relatedSpdxElement":"SPDXRef-binary"}]}
        payload = (json.dumps(supplier)+"\n").encode()
        path = "usr/share/"+name+"/sbom.spdx.json"
        installed = {"name":name, "version":"1.0-r0", "architecture":"aarch64", "license":"MIT",
            "files":[{"path":path, "sha256":hashlib.sha256(payload).hexdigest(), "status":"unchanged"}]}
        self.rootfs["packages"].append(installed)
        self.rootfs["files"].append(file_record(path, payload))
        record = {"path":path, "sha256":hashlib.sha256(payload).hexdigest(), "document":supplier,
                  "package":{"name":name, "version":"1.0-r0"}}
        self.rootfs.setdefault("additional_sbom", []).append(record)
        return record

    def test_embedded_apk_sbom_merges_namespaced_packages_files_and_licenses(self):
        record = self.embedded_apk()
        self.embedded_apk("other", "https://example.invalid/other/sbom")
        summary, doc = self.render()
        self.assertEqual(summary["embedded_apk_sboms"], 2)
        self.assertEqual(summary["embedded_apk_sbom_elements"], 6)
        supplier = [p for p in doc["packages"] if p["SPDXID"].startswith("SPDXRef-apk-supplier-")]
        self.assertEqual(len(supplier), 4)
        business = next(p for p in supplier if p["name"] == "business")
        other = next(p for p in supplier if p["name"] == "other")
        self.assertNotEqual(business["licenseDeclared"], other["licenseDeclared"])
        provenance = json.loads(business["sourceInfo"])
        self.assertEqual(provenance["document_namespace"], record["document"]["documentNamespace"])
        self.assertEqual(provenance["document_sha256"], record["sha256"])
        installed = next(p for p in doc["packages"] if p["name"] == "business" and p not in supplier)
        self.assertTrue(any(r["spdxElementId"] == installed["SPDXID"] and r["relationshipType"] == "GENERATED_FROM"
                            and r["relatedSpdxElement"] == business["SPDXID"] for r in doc["relationships"]))
        self.assertTrue(any(r["relationshipType"] == "RUNTIME_DEPENDENCY_OF" for r in doc["relationships"]))
        self.assertEqual(len([f for f in doc["files"] if f["fileName"].startswith("supplier-apk:/")]), 2)
        self.assertTrue(summary["references_closed"])

    def test_embedded_apk_sbom_original_file_hashes_survive_customization(self):
        record = self.embedded_apk()
        expected = record["document"]["files"][0]["checksums"][0]["checksumValue"]
        self.rootfs["files"].append(file_record("usr/bin/business", b"user replacement"))
        _, doc = self.render()
        supplier = next(f for f in doc["files"] if f["fileName"] == "supplier-apk:/usr/bin/business")
        current = next(f for f in doc["files"] if f["fileName"] == "/usr/bin/business")
        self.assertEqual(supplier["checksums"][0]["checksumValue"], expected)
        self.assertNotEqual(supplier["checksums"], current["checksums"])

    def test_file_only_embedded_apk_sbom_can_describe_its_checksummed_file(self):
        record = self.embedded_apk()
        supplier = record["document"]
        supplier["packages"] = []
        supplier["relationships"] = []
        supplier["documentDescribes"] = ["SPDXRef-binary"]
        expected = copy.deepcopy(supplier["files"][0]["checksums"])
        summary, document = self.render()
        imported = next(item for item in document["files"]
                        if item["fileName"] == "supplier-apk:/usr/bin/business")
        self.assertEqual(imported["checksums"], expected)
        self.assertEqual(summary["embedded_apk_sbom_elements"], 1)
        installed = next(item for item in document["packages"]
                         if item["name"] == "business" and item["SPDXID"].startswith("SPDXRef-package-apk-"))
        self.assertTrue(any(item["spdxElementId"] == installed["SPDXID"]
                            and item["relationshipType"] == "GENERATED_FROM"
                            and item["relatedSpdxElement"] == imported["SPDXID"]
                            for item in document["relationships"]))
        self.assertTrue(summary["references_closed"])

    def test_embedded_apk_sbom_document_describes_absent_element_is_rejected(self):
        record = self.embedded_apk()
        record["document"]["documentDescribes"] = ["SPDXRef-missing"]
        record["document"]["relationships"] = []
        with self.assertRaisesRegex(ValueError, "describes an absent element"):
            self.render()

    def test_embedded_apk_sbom_modified_document_is_rejected(self):
        record = self.embedded_apk()
        record["sha256"] = "0"*64
        with self.assertRaisesRegex(ValueError, "differs from final payload"):
            self.render()

    def test_extracted_root_apk_sbom_is_merged_without_retaining_it_in_rootfs(self):
        record = self.embedded_apk()
        self.rootfs["files"] = [f for f in self.rootfs["files"] if f["path"] != record["path"]]
        record.update(path="sbom.spdx.json", extracted=True)
        summary, document = self.render()
        self.assertEqual(summary["embedded_apk_sboms"], 1)
        package = next(p for p in document["packages"] if p["name"] == "business"
                       and p["SPDXID"].startswith("SPDXRef-apk-supplier-"))
        self.assertTrue(json.loads(package["sourceInfo"])["extracted_from_rootfs"])
        self.assertTrue(any(f["fileName"] == "apk-extracted-sbom:/sbom.spdx.json" for f in document["files"]))
        self.assertFalse(any(f["fileName"] == "/sbom.spdx.json" for f in document["files"]))

    def test_embedded_apk_sbom_unresolved_relationship_is_rejected(self):
        record = self.embedded_apk()
        record["document"]["relationships"][0]["relatedSpdxElement"] = "SPDXRef-missing"
        with self.assertRaisesRegex(ValueError, "Unresolved embedded SBOM"):
            self.render()

    def test_embedded_apk_sbom_external_document_reference_is_preserved(self):
        record = self.embedded_apk()
        record["document"]["externalDocumentRefs"] = [{"externalDocumentId":"DocumentRef-upstream",
            "spdxDocument":"https://example.invalid/upstream/sbom", "checksum":{"algorithm":"SHA256", "checksumValue":"a"*64}}]
        record["document"]["relationships"].append({"spdxElementId":"SPDXRef-main", "relationshipType":"DEPENDS_ON",
            "relatedSpdxElement":"DocumentRef-upstream:SPDXRef-main"})
        _, doc = self.render()
        self.assertEqual(len(doc["externalDocumentRefs"]), 1)
        prefix = doc["externalDocumentRefs"][0]["externalDocumentId"]
        self.assertTrue(any(r["relatedSpdxElement"] == prefix+":SPDXRef-main" for r in doc["relationships"]))

    def test_local_apk_archive_checksum_is_added_to_final_provenance(self):
        self.embedded_apk()
        self.rootfs["local_apks"] = [{"name":"business", "version":"1.0-r0", "architecture":"aarch64",
            "filename":"business-1.0-r0.apk", "sha256":"b"*64}]
        _, doc = self.render()
        archive = next(f for f in doc["files"] if f["fileName"] == "apk-source:/business-1.0-r0.apk")
        self.assertEqual(archive["checksums"], [{"algorithm":"SHA256", "checksumValue":"b"*64}])
        installed = next(p for p in doc["packages"] if p["name"] == "business" and p["SPDXID"].startswith("SPDXRef-package-apk-"))
        embedded = next(f for f in doc["files"] if f["fileName"] == "/usr/share/business/sbom.spdx.json")
        self.assertTrue(any(r["spdxElementId"] == installed["SPDXID"] and r["relationshipType"] == "CONTAINS"
                            and r["relatedSpdxElement"] == embedded["SPDXID"] for r in doc["relationships"]))

    def test_reproducible_document(self):
        first, _ = self.render()
        second, _ = self.render()
        self.assertEqual(first["sha256"], second["sha256"])

    def test_local_sources_do_not_inherit_a_remote_archive_checksum(self):
        archive_hash = hashlib.sha256(b"source archive").hexdigest()
        actual_local_hash = hashlib.sha256(b"local script").hexdigest()
        remote = {"uri":"https://example.invalid/source.tar.xz", "sha256":archive_hash}
        self.components[2]["sources"] = [
            {"uri":"file://local.patch", "sha256":archive_hash}, remote,
            {"uri":"file://verified-script", "sha256":actual_local_hash},
            {"uri":"https://example.invalid/source.git", "revision":"abcdef123456"}]
        self.components[-1]["image_packages"][0]["sources"] = [remote,
            {"uri":"file://initramfs.patch", "sha256":archive_hash}]
        self.write_inputs()
        summary, document = self.render()
        source = {p["name"]:p for p in document["packages"]
                  if p["SPDXID"].startswith("SPDXRef-package-source-")}
        for path in ("file://local.patch", "file://initramfs.patch"):
            self.assertNotIn("checksums", source[path])
            self.assertNotIn("sha256", json.loads(source[path]["sourceInfo"]))
        self.assertEqual(source[remote["uri"]]["checksums"],
                         [{"algorithm":"SHA256", "checksumValue":archive_hash}])
        self.assertEqual(source["file://verified-script"]["checksums"],
                         [{"algorithm":"SHA256", "checksumValue":actual_local_hash}])
        self.assertEqual(source["https://example.invalid/source.git"]["versionInfo"], "abcdef123456")
        self.assertEqual(summary["source_checksum_omissions"], 2)
        self.assertTrue(any("remote archive digest" in v for v in summary["limitations"]))

    def test_unsafe_artifact_path_is_rejected(self):
        self.artifacts["../escape.img"] = next(iter(self.artifacts.values()))
        with self.assertRaises(ValueError):
            self.render()

    def test_wrong_profile_evidence_is_rejected(self):
        self.metadata["profile"] = "development"
        with self.assertRaises(ValueError):
            self.render()


if __name__ == "__main__":
    unittest.main()
