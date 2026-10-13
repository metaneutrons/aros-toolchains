#!/usr/bin/env python3
"""Synthetic byte-boundary tests for sdk-owner-transport-v2.py only.

The retained signature bundle in these fixtures is deliberately fake. These
tests exercise transport joins and bytes, never Sigstore authentication.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
import warnings
import zipfile
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "sdk-owner-transport-v2.py"
SPEC = importlib.util.spec_from_file_location("sdk_owner_transport", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
transport = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(transport)
origin = transport.origin
stage = transport.stage

CONTEXT = {
    "repository": "example/project",
    "repository_id": 7890,
    "producer_commit": "a" * 40,
    "source_ref": "refs/heads/main",
    "workflow": ".github/workflows/toolchain.yml",
    "run_id": 123456,
    "run_attempt": 2,
}
SELECTION = {"role": "diagnostic", "group": "rv32", "host": "linux-x86_64",
             "profile": "release", "copy": "none"}
JOB = {"id": 90901, "name": "Retain SDK owners"}
ARTIFACT_ID = 667002
PROOF_ID = 667003
GROUP = "rv32"
PROFILE = "release"
HOST = "linux-x86_64"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def measurement(data: bytes) -> dict:
    return {"sha256": digest(data), "size": len(data)}


def sdk_identity(sdk_id: str) -> dict:
    return {
        "sdk_id": sdk_id,
        "version": "1.2.3",
        "target": {"target_triple": "i686-aros", "abi": {"stack": "m68k"}},
        "source": {"commit": "c" * 40, "git_tree": "d" * 40,
                   "content_sha256": "e" * 64, "contract_sha256": "f" * 64},
        "source_date_epoch": 1710000000,
    }


def product_members(sdk_id: str, family: str = "gnu") -> dict[str, bytes]:
    identity = sdk_identity(sdk_id)
    generation = {
        "schema": (stage.GNU_GENERATION_SCHEMA if family == "gnu"
                   else stage.LLVM_GENERATION_SCHEMA),
        "assurance": stage.GENERATION_ASSURANCE,
        "identity": identity,
        "source_profile": "aros-source-profile",
        "environment_sha256": "1" * 64,
        "compatibility_receipt_sha256": "2" * 64,
        "sdk_link_receipt_sha256": "3" * 64,
        "sdk_inventory_sha256": "4" * 64,
        "sdk_entries": 4,
    }
    if family == "llvm":
        generation["binding_sha256"] = "5" * 64

    archive_name = f"aros-sdk-{sdk_id}-1.2.3.tar.xz"
    archive = f"synthetic SDK archive bytes for {sdk_id}\n".encode()
    manifest = {"schema": stage.SDK_MANIFEST_SCHEMA, "identity": identity,
                "tree_sha256": "6" * 64, "files": []}
    ordinary_compatibility = {
        "native-compatibility.receipt.json": f'{{"sdk":"{sdk_id}"}}\n'.encode(),
        "standalone-object.o": f"synthetic object bytes for {sdk_id}".encode(),
    }
    compatibility_doc = {
        "schema": (stage.GNU_MEASUREMENT_SCHEMA if family == "gnu"
                   else stage.LLVM_MEASUREMENT_SCHEMA),
        "files": {name: measurement(raw) for name, raw in ordinary_compatibility.items()},
    }
    result = {
        "generation.json": stage.canonical_json(generation),
        "compatibility-inputs.json": stage.canonical_json({"sdk": sdk_id, "selected": "inputs"}),
        f"package/{archive_name}": archive,
        f"package/{archive_name}.manifest.json": stage.canonical_json(manifest),
        f"package/{archive_name}.sha256": f"{digest(archive)}  {archive_name}\n".encode(),
        "compatibility/compatibility-measurement.json": stage.canonical_json(compatibility_doc),
    }
    result.update({f"compatibility/{name}": raw for name, raw in ordinary_compatibility.items()})
    lane = {
        "schema": transport.OWNER_SCHEMA,
        "assurance": transport.OWNER_ASSURANCE,
        "sdk_id": sdk_id,
        "group_id": GROUP,
        "target_profile": PROFILE,
        "host": HOST,
        "files": {name: measurement(raw) for name, raw in sorted(result.items())},
    }
    result["sdk-lane.json"] = stage.canonical_json(lane)
    return {f"sdk-{sdk_id}/{name}": raw for name, raw in result.items()}


def zip_bytes(entries: list[tuple[str, bytes]]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries:
            info = zipfile.ZipInfo(name)
            info.compress_type = zipfile.ZIP_DEFLATED
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", message=r"Duplicate name:.*", category=UserWarning)
                archive.writestr(info, data)
    return buffer.getvalue()


def make_bundle(root: Path, *, sdk_ids: list[str] | None = None,
                family: str = "gnu", members: dict[str, bytes] | None = None,
                entries: list[tuple[str, bytes]] | None = None,
                selection: dict | None = None,
                signed_selection: dict | None = None,
                selected_job: dict | None = None,
                selected_context: dict | None = None,
                signed_context: dict | None = None,
                signed_files: dict | None = None) -> dict:
    sdk_ids = ["sdk-a"] if sdk_ids is None else list(sdk_ids)
    if members is None:
        members = {}
        for sdk_id in sdk_ids:
            members.update(product_members(sdk_id, family))
    archive_entries = list(members.items()) if entries is None else entries
    raw_zip = zip_bytes(archive_entries)
    root.mkdir(mode=0o700)
    os.chmod(root, 0o700)
    (root / "payload.zip").write_bytes(raw_zip)
    selected_lane = copy.deepcopy(SELECTION if selection is None else selection)
    selected = {
        "schema": origin.SELECTION_SCHEMA,
        "context": copy.deepcopy(CONTEXT if selected_context is None else selected_context),
        "selection": selected_lane,
        "job": copy.deepcopy(JOB if selected_job is None else selected_job),
        "artifact": {"id": ARTIFACT_ID, "name": "sdk-owner-payload",
                     "sha256": digest(raw_zip), "size_in_bytes": len(raw_zip)},
        "proof": {"id": PROOF_ID, "name": "sdk-owner-origin-proof",
                  "sha256": "b" * 64, "size_in_bytes": 123},
    }
    signed = {
        "schema": origin.SCHEMA,
        "context": copy.deepcopy(CONTEXT if signed_context is None else signed_context),
        "selection": copy.deepcopy(selected_lane if signed_selection is None else signed_selection),
        "job": {"id": JOB["id"], "check_run_id": 555001, "name": JOB["name"]},
        "artifact": copy.deepcopy(selected["artifact"]),
        "files": ({name: measurement(raw) for name, raw in members.items()}
                  if signed_files is None else copy.deepcopy(signed_files)),
    }
    if selected_job is not None:
        signed["job"]["id"] = selected_job["id"]
        signed["job"]["name"] = selected_job["name"]
    (root / "origin.json").write_bytes(origin.canonical(signed))
    # Synthetic bytes only: never an authenticated signature or Sigstore proof.
    (root / "origin.sigstore.json").write_bytes(b"synthetic signature bundle bytes; not authenticated\n")
    (root / "selection.json").write_bytes(origin.canonical(selected))
    for path in root.iterdir():
        os.chmod(path, 0o600)
    return {"root": root, "members": members, "raw_zip": raw_zip,
            "selection": selected, "signed": signed}


def rebind_members(bundle: dict, members: dict[str, bytes], *, entries: list[tuple[str, bytes]] | None = None,
                   signed_files: dict | None = None) -> None:
    raw_zip = zip_bytes(list(members.items()) if entries is None else entries)
    (bundle["root"] / "payload.zip").write_bytes(raw_zip)
    os.chmod(bundle["root"] / "payload.zip", 0o600)
    selected = copy.deepcopy(bundle["selection"])
    signed = copy.deepcopy(bundle["signed"])
    artifact = {"id": ARTIFACT_ID, "name": "sdk-owner-payload",
                "sha256": digest(raw_zip), "size_in_bytes": len(raw_zip)}
    selected["artifact"] = copy.deepcopy(artifact)
    signed["artifact"] = copy.deepcopy(artifact)
    signed["files"] = ({name: measurement(raw) for name, raw in members.items()}
                       if signed_files is None else copy.deepcopy(signed_files))
    (bundle["root"] / "selection.json").write_bytes(origin.canonical(selected))
    (bundle["root"] / "origin.json").write_bytes(origin.canonical(signed))
    os.chmod(bundle["root"] / "selection.json", 0o600)
    os.chmod(bundle["root"] / "origin.json", 0o600)
    bundle.update({"members": members, "raw_zip": raw_zip,
                   "selection": selected, "signed": signed})


class SdkOwnerTransportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="sdk-owner-transport-")
        self.base = Path(self.temporary.name).resolve()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def bundle(self, name: str = "retained", **kwargs) -> dict:
        return make_bundle(self.base / name, **kwargs)

    def output(self, name: str = "output") -> Path:
        return self.base / name

    def extract(self, bundle: dict, output: Path | None = None, *, sdk_ids: list[str] | None = None,
                group: str = GROUP, profile: str = PROFILE, host: str = HOST,
                compiler_family: str = "gnu", owner_role: str = "diagnostic") -> dict:
        return transport.extract(
            bundle["root"], self.output() if output is None else output,
            sdk_ids=["sdk-a"] if sdk_ids is None else sdk_ids,
            group=group, profile=profile, host=host, compiler_family=compiler_family,
            owner_role=owner_role,
        )

    def assert_rejected(self, bundle: dict, **kwargs: object) -> None:
        with self.assertRaises(origin.OriginError):
            self.extract(bundle, **kwargs)

    def test_extracts_gnu_and_llvm_products_and_verify_mode_is_identical(self) -> None:
        for family, sdk_ids in (("gnu", ["sdk-a"]), ("llvm", ["sdk-a", "sdk-b"])):
            with self.subTest(family=family, sdk_ids=sdk_ids):
                bundle = self.bundle(f"retained-{family}", sdk_ids=sdk_ids, family=family)
                output = self.output(f"output-{family}")
                extracted = self.extract(bundle, output, sdk_ids=sdk_ids, compiler_family=family)
                verified = transport.verify_output(
                    bundle["root"], output, sdk_ids=sdk_ids, group=GROUP, profile=PROFILE,
                    host=HOST, compiler_family=family)
                self.assertEqual(extracted, verified)
                self.assertEqual(extracted["schema"], "aros-sdk-owner-transport-v2")
                self.assertEqual(extracted["assurance"], "transport-byte-readback-only")
                self.assertNotIn("owner_role", extracted)
                self.assertEqual(extracted["raw_zip_sha256"], digest(bundle["raw_zip"]))
                self.assertEqual([item["sdk_id"] for item in extracted["sdk_generations"]], sdk_ids)
                for item in extracted["sdk_generations"]:
                    sdk_id = item["sdk_id"]
                    self.assertEqual(item["group_id"], GROUP)
                    self.assertEqual(item["target_profile"], PROFILE)
                    self.assertEqual(item["host"], HOST)
                    self.assertEqual(Path(item["package_dir"]), output / f"sdk-{sdk_id}/package")
                    self.assertTrue(item["compatibility"]["native_sdk_required"] is (family == "gnu"))
                    product = {name: data for name, data in bundle["members"].items()
                               if name.startswith(f"sdk-{sdk_id}/")}
                    for relative, data in product.items():
                        path = output / relative
                        self.assertEqual(path.read_bytes(), data)
                        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                    for directory in (output / f"sdk-{sdk_id}",
                                      output / f"sdk-{sdk_id}/package",
                                      output / f"sdk-{sdk_id}/compatibility"):
                        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)

    def test_cli_extract_and_verify_emit_identical_selection_json(self) -> None:
        sdk_ids = ["sdk-a", "sdk-b"]
        bundle = self.bundle(sdk_ids=sdk_ids, family="llvm")
        output = self.output()
        base = [sys.executable, str(SCRIPT), "--retained-dir", str(bundle["root"]),
                "--sdk-ids", json.dumps(sdk_ids), "--group", GROUP,
                "--profile", PROFILE, "--host", HOST, "--compiler-family", "llvm"]
        extracted = subprocess.run(base + ["--output-dir", str(output)],
                                   capture_output=True, text=True, check=False)
        self.assertEqual(extracted.returncode, 0, extracted.stderr)
        verified = subprocess.run(base + ["--verify-output-dir", str(output)],
                                  capture_output=True, text=True, check=False)
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assertEqual(json.loads(extracted.stdout), json.loads(verified.stdout))
        self.assertEqual(extracted.stdout, verified.stdout)
        self.assertNotIn("owner_role", json.loads(extracted.stdout))

        invalid = subprocess.run(base + ["--output-dir", str(output),
                                         "--verify-output-dir", str(output)],
                                 capture_output=True, text=True, check=False)
        self.assertNotEqual(invalid.returncode, 0)
        self.assertEqual(invalid.stdout, "")

        sdk_bundle = self.bundle(
            "sdk-role-cli",
            sdk_ids=["sdk-a", "sdk-b"], family="llvm",
            selection={"role": "sdk", "group": GROUP, "host": HOST,
                       "profile": PROFILE, "copy": "none"},
        )
        sdk_output = self.output("sdk-role-cli-output")
        sdk_base = [sys.executable, str(SCRIPT), "--retained-dir", str(sdk_bundle["root"]),
                    "--sdk-ids", json.dumps(["sdk-a", "sdk-b"]), "--group", GROUP,
                    "--profile", PROFILE, "--host", HOST, "--compiler-family", "llvm",
                    "--owner-role", "sdk"]
        sdk_extracted = subprocess.run(sdk_base + ["--output-dir", str(sdk_output)],
                                       capture_output=True, text=True, check=False)
        self.assertEqual(sdk_extracted.returncode, 0, sdk_extracted.stderr)
        sdk_verified = subprocess.run(sdk_base + ["--verify-output-dir", str(sdk_output)],
                                      capture_output=True, text=True, check=False)
        self.assertEqual(sdk_verified.returncode, 0, sdk_verified.stderr)
        self.assertEqual(json.loads(sdk_extracted.stdout), json.loads(sdk_verified.stdout))
        self.assertEqual(json.loads(sdk_extracted.stdout)["owner_role"], "sdk")

    def test_sdk_owner_role_is_explicit_and_bound_through_extract_and_verify(self) -> None:
        lane = {"role": "sdk", "group": GROUP, "host": HOST,
                "profile": PROFILE, "copy": "none"}
        bundle = self.bundle("sdk-role-api", selection=lane, signed_selection=lane)
        output = self.output("sdk-role-api-output")
        extracted = self.extract(bundle, output, owner_role="sdk")
        verified = transport.verify_output(
            bundle["root"], output, sdk_ids=["sdk-a"], group=GROUP, profile=PROFILE,
            host=HOST, compiler_family="gnu", owner_role="sdk")
        self.assertEqual(extracted, verified)
        self.assertEqual(extracted["owner_role"], "sdk")

    def test_owner_role_mismatches_reject_before_output_creation(self) -> None:
        sdk_lane = {"role": "sdk", "group": GROUP, "host": HOST,
                    "profile": PROFILE, "copy": "none"}
        sdk_bundle = self.bundle("sdk-role-default-diagnostic", selection=sdk_lane,
                                 signed_selection=sdk_lane)
        sdk_output = self.output("sdk-role-default-diagnostic-output")
        self.assert_rejected(sdk_bundle, output=sdk_output)
        self.assertFalse(sdk_output.exists())

        diagnostic_bundle = self.bundle("diagnostic-role-sdk-request")
        diagnostic_output = self.output("diagnostic-role-sdk-request-output")
        self.assert_rejected(diagnostic_bundle, output=diagnostic_output, owner_role="sdk")
        self.assertFalse(diagnostic_output.exists())

    def test_independent_sdk_set_and_family_are_enforced(self) -> None:
        bundle = self.bundle(sdk_ids=["sdk-a", "sdk-b"])
        for selection in (["sdk-a"], ["sdk-a", "sdk-b", "sdk-c"]):
            with self.subTest(selection=selection):
                self.assert_rejected(bundle, sdk_ids=selection)
        for invalid in (["sdk-b", "sdk-a"], ["sdk-a", "sdk-a"], ["../escape"],
                        ["."], [".."], ["SDK-A"], ["a" * 97], [],
                        [f"sdk-{index:02d}" for index in range(33)]):
            with self.subTest(invalid=invalid):
                self.assert_rejected(bundle, sdk_ids=invalid)
        self.assert_rejected(bundle, compiler_family="llvm")

    def test_independent_group_profile_host_and_product_tuple_are_enforced(self) -> None:
        bundle = self.bundle()
        for key, value in (("group", "other"), ("profile", "debug"),
                           ("host", "linux-aarch64")):
            with self.subTest(key=key):
                self.assert_rejected(bundle, **{key: value})

        for key, value in (("group_id", "other"), ("target_profile", "debug"),
                           ("host", "linux-aarch64"), ("sdk_id", "sdk-b")):
            with self.subTest(marker=key):
                bundle = self.bundle("marker-" + key.replace("_", "-"))
                members = dict(bundle["members"])
                lane_path = "sdk-sdk-a/sdk-lane.json"
                lane = json.loads(members[lane_path])
                lane[key] = value
                members[lane_path] = stage.canonical_json(lane)
                rebind_members(bundle, members)
                self.assert_rejected(bundle)

    def test_diagnostic_selector_and_shared_identity_joins_are_required(self) -> None:
        for index, lane in enumerate((
            {"role": "build", "group": GROUP, "host": HOST, "profile": PROFILE, "copy": "a"},
            {"role": "diagnostic", "group": GROUP, "host": HOST, "profile": PROFILE, "copy": "a"},
            {"role": "comparison", "group": GROUP, "host": HOST, "profile": PROFILE, "copy": "none"},
        )):
            with self.subTest(lane=lane):
                bundle = self.bundle(f"wrong-lane-{index}", selection=lane, signed_selection=lane)
                self.assert_rejected(bundle)

        bundle = self.bundle("job-join")
        selected = copy.deepcopy(bundle["selection"])
        selected["job"]["id"] += 1
        (bundle["root"] / "selection.json").write_bytes(origin.canonical(selected))
        self.assert_rejected(bundle)

        bundle = self.bundle("context-join")
        selected = copy.deepcopy(bundle["selection"])
        selected["context"]["run_attempt"] += 1
        (bundle["root"] / "selection.json").write_bytes(origin.canonical(selected))
        self.assert_rejected(bundle)

        for index, key in enumerate(("group", "host", "profile")):
            bundle = self.bundle(f"selector-join-{index}")
            selected = copy.deepcopy(bundle["selection"])
            signed = copy.deepcopy(bundle["signed"])
            replacement = {"group": "other", "host": "linux-aarch64", "profile": "debug"}[key]
            selected["selection"][key] = replacement
            signed["selection"][key] = replacement
            (bundle["root"] / "selection.json").write_bytes(origin.canonical(selected))
            (bundle["root"] / "origin.json").write_bytes(origin.canonical(signed))
            self.assert_rejected(bundle)

    def test_generation_manifest_and_measurement_schema_and_identity_are_enforced(self) -> None:
        bundle = self.bundle()
        members = dict(bundle["members"])
        generation_path = "sdk-sdk-a/generation.json"
        generation = json.loads(members[generation_path])
        generation["schema"] = stage.LLVM_GENERATION_SCHEMA
        members[generation_path] = stage.canonical_json(generation)
        rebind_members(bundle, members)
        self.assert_rejected(bundle)

        bundle = self.bundle("manifest-id")
        members = dict(bundle["members"])
        manifest_path = "sdk-sdk-a/package/aros-sdk-sdk-a-1.2.3.tar.xz.manifest.json"
        manifest = json.loads(members[manifest_path])
        manifest["identity"]["sdk_id"] = "sdk-b"
        members[manifest_path] = stage.canonical_json(manifest)
        rebind_members(bundle, members)
        self.assert_rejected(bundle)

        bundle = self.bundle("measurement-schema", family="gnu")
        members = dict(bundle["members"])
        measurement_path = "sdk-sdk-a/compatibility/compatibility-measurement.json"
        document = json.loads(members[measurement_path])
        document["schema"] = stage.LLVM_MEASUREMENT_SCHEMA
        members[measurement_path] = stage.canonical_json(document)
        rebind_members(bundle, members)
        self.assert_rejected(bundle)

        bundle = self.bundle("measurement-hash")
        members = dict(bundle["members"])
        measurement_path = "sdk-sdk-a/compatibility/compatibility-measurement.json"
        document = json.loads(members[measurement_path])
        document["files"]["standalone-object.o"]["sha256"] = "0" * 64
        members[measurement_path] = stage.canonical_json(document)
        rebind_members(bundle, members)
        self.assert_rejected(bundle)

    def test_signed_closure_rejects_extra_missing_swap_case_alias_and_traversal(self) -> None:
        bundle = self.bundle(sdk_ids=["sdk-a", "sdk-b"])
        self.assert_rejected(bundle, sdk_ids=["sdk-a"])

        members = dict(bundle["members"])
        members["sdk-sdk-a/compatibility/unselected.bin"] = b"extra"
        bundle = self.bundle("extra", sdk_ids=["sdk-a"])
        rebind_members(bundle, members)
        self.assert_rejected(bundle)

        bundle = self.bundle("traversal")
        members = dict(bundle["members"])
        members["sdk-sdk-a/../escape"] = b"traversal"
        rebind_members(bundle, members)
        self.assert_rejected(bundle)

        bundle = self.bundle("case-alias")
        members = dict(bundle["members"])
        members["sdk-sdk-a/compatibility/Native-Compatibility.receipt.json"] = b"alias"
        rebind_members(bundle, members)
        self.assert_rejected(bundle)

        bundle = self.bundle("unselected-zip")
        entries = list(bundle["members"].items()) + [("sdk-sdk-a/unselected.bin", b"extra")]
        rebind_members(bundle, dict(bundle["members"]), entries=entries)
        self.assert_rejected(bundle)

        bundle = self.bundle("missing-lane-file")
        members = dict(bundle["members"])
        del members["sdk-sdk-a/generation.json"]
        rebind_members(bundle, members)
        self.assert_rejected(bundle)

    def test_corrupt_zip_and_metadata_join_fail_after_rebinding_the_zip_digest(self) -> None:
        bundle = self.bundle()
        raw = bytearray(bundle["raw_zip"])
        raw[-8] ^= 0x40
        (bundle["root"] / "payload.zip").write_bytes(raw)
        os.chmod(bundle["root"] / "payload.zip", 0o600)
        selected = copy.deepcopy(bundle["selection"])
        signed = copy.deepcopy(bundle["signed"])
        artifact = {"id": ARTIFACT_ID, "name": "sdk-owner-payload",
                    "sha256": digest(raw), "size_in_bytes": len(raw)}
        selected["artifact"] = copy.deepcopy(artifact)
        signed["artifact"] = copy.deepcopy(artifact)
        (bundle["root"] / "selection.json").write_bytes(origin.canonical(selected))
        (bundle["root"] / "origin.json").write_bytes(origin.canonical(signed))
        self.assert_rejected(bundle)

        bundle = self.bundle("bad-signed-join")
        selected = copy.deepcopy(bundle["selection"])
        selected["selection"]["host"] = "linux-aarch64"
        (bundle["root"] / "selection.json").write_bytes(origin.canonical(selected))
        self.assert_rejected(bundle)

    def test_metadata_size_cap_is_enforced_after_zip_byte_verification(self) -> None:
        bundle = self.bundle()
        members = dict(bundle["members"])
        path = "sdk-sdk-a/compatibility/compatibility-measurement.json"
        members[path] = b"x" * 257
        rebind_members(bundle, members)
        with mock.patch.object(transport, "MAX_METADATA", 256):
            self.assert_rejected(bundle)

    def test_ordinary_compatibility_suffixes_do_not_make_files_metadata(self) -> None:
        for index, suffix in enumerate(("sha256", "manifest.json")):
            with self.subTest(suffix=suffix):
                bundle = self.bundle(f"ordinary-suffix-{index}")
                members = dict(bundle["members"])
                prefix = "sdk-sdk-a/"
                relative = f"large.{suffix}"
                raw = b"x" * 4097
                members[f"{prefix}compatibility/{relative}"] = raw
                measurement_path = prefix + "compatibility/compatibility-measurement.json"
                document = json.loads(members[measurement_path])
                document["files"][relative] = measurement(raw)
                members[measurement_path] = stage.canonical_json(document)
                lane_path = prefix + "sdk-lane.json"
                lane = json.loads(members[lane_path])
                lane["files"] = {name[len(prefix):]: measurement(data)
                                 for name, data in members.items() if name != lane_path}
                members[lane_path] = stage.canonical_json(lane)
                rebind_members(bundle, members)
                output = self.output(f"ordinary-suffix-output-{index}")
                with mock.patch.object(transport, "MAX_METADATA", 4096):
                    self.extract(bundle, output)
                    transport.verify_output(bundle["root"], output, sdk_ids=["sdk-a"],
                                            group=GROUP, profile=PROFILE, host=HOST,
                                            compiler_family="gnu")
                self.assertEqual((output / prefix / "compatibility" / relative).read_bytes(), raw)

    def test_retained_root_link_file_link_and_unexpected_member_are_rejected(self) -> None:
        bundle = self.bundle()
        alias = self.base / "retained-alias"
        alias.symlink_to(bundle["root"], target_is_directory=True)
        with self.assertRaises(origin.OriginError):
            transport.extract(alias, self.output(), sdk_ids=["sdk-a"], group=GROUP,
                              profile=PROFILE, host=HOST, compiler_family="gnu")

        bundle = self.bundle("hardlink-input")
        os.link(bundle["root"] / "payload.zip", self.base / "payload-hardlink")
        self.assert_rejected(bundle)

        bundle = self.bundle("symlink-input")
        metadata = bundle["root"] / "origin.sigstore.json"
        external = self.base / "external-signature.json"
        external.write_bytes(metadata.read_bytes())
        metadata.unlink()
        metadata.symlink_to(external)
        self.assert_rejected(bundle)

        bundle = self.bundle("extra-retained")
        (bundle["root"] / "unexpected.json").write_bytes(b"extra")
        os.chmod(bundle["root"] / "unexpected.json", 0o600)
        self.assert_rejected(bundle)

    def test_verify_output_is_read_only_and_rejects_output_aliases(self) -> None:
        bundle = self.bundle()
        output = self.output()
        self.extract(bundle, output)
        snapshot = {path.relative_to(output).as_posix(): (path.read_bytes() if path.is_file() else None,
                                                          path.stat().st_mode,
                                                          path.stat().st_mtime_ns)
                    for path in sorted(output.rglob("*"))}
        verified = transport.verify_output(
            bundle["root"], output, sdk_ids=["sdk-a"], group=GROUP, profile=PROFILE,
            host=HOST, compiler_family="gnu")
        self.assertEqual(verified["raw_zip_sha256"], digest(bundle["raw_zip"]))
        after = {path.relative_to(output).as_posix(): (path.read_bytes() if path.is_file() else None,
                                                        path.stat().st_mode,
                                                        path.stat().st_mtime_ns)
                 for path in sorted(output.rglob("*"))}
        self.assertEqual(snapshot, after)

        hardlink = self.base / "output-hardlink"
        os.link(output / "sdk-sdk-a/generation.json", hardlink)
        with self.assertRaises(origin.OriginError):
            transport.verify_output(bundle["root"], output, sdk_ids=["sdk-a"], group=GROUP,
                                     profile=PROFILE, host=HOST, compiler_family="gnu")
        hardlink.unlink()
        generation = output / "sdk-sdk-a/generation.json"
        original = generation.read_bytes()
        generation.write_bytes(original + b"changed\n")
        corrupted = generation.read_bytes()
        with self.assertRaises(origin.OriginError):
            transport.verify_output(bundle["root"], output, sdk_ids=["sdk-a"], group=GROUP,
                                     profile=PROFILE, host=HOST, compiler_family="gnu")
        self.assertEqual(generation.read_bytes(), corrupted)
        generation.write_bytes(original)
        (output / "unexpected").write_text("case/closure alias\n")
        with self.assertRaises(origin.OriginError):
            transport.verify_output(bundle["root"], output, sdk_ids=["sdk-a"], group=GROUP,
                                     profile=PROFILE, host=HOST, compiler_family="gnu")
        (output / "unexpected").unlink()

        generation.unlink()
        external = self.base / "external-generation.json"
        external.write_bytes(original)
        generation.symlink_to(external)
        with self.assertRaises(origin.OriginError):
            transport.verify_output(bundle["root"], output, sdk_ids=["sdk-a"], group=GROUP,
                                     profile=PROFILE, host=HOST, compiler_family="gnu")

        bundle = self.bundle("output-overlap")
        output_in_retained = bundle["root"] / "child"
        with self.assertRaises(origin.OriginError):
            self.extract(bundle, output_in_retained)

    def test_reused_output_preserves_sentinel_and_failed_output_is_left_for_inspection(self) -> None:
        bundle = self.bundle()
        reused = self.output()
        reused.mkdir()
        sentinel = reused / "outside-sentinel.txt"
        sentinel.write_text("preserve me\n")
        with self.assertRaises(origin.OriginError):
            self.extract(bundle, reused)
        self.assertEqual(sentinel.read_text(), "preserve me\n")

        bundle = self.bundle("partial-retained")
        output = self.output("partial-output")
        outside = self.base / "outside.txt"
        outside.write_text("preserve outside user data\n")
        original = transport.native._write_member
        calls = 0

        def fail_after_one(*args: object, **kwargs: object) -> dict:
            nonlocal calls
            calls += 1
            result = original(*args, **kwargs)
            if calls == 1:
                raise OSError("synthetic partial extraction failure")
            return result

        with mock.patch.object(transport.native, "_write_member", side_effect=fail_after_one):
            with self.assertRaises(origin.OriginError):
                self.extract(bundle, output)
        self.assertTrue(output.is_dir())
        self.assertTrue(any(path.is_file() for path in output.rglob("*")))
        self.assertEqual(outside.read_text(), "preserve outside user data\n")

    def test_retained_change_during_write_is_rejected_without_cleaning_partial_output(self) -> None:
        bundle = self.bundle()
        output = self.output()
        original = transport.native._write_member
        changed = False

        def mutate_retained(*args: object, **kwargs: object) -> dict:
            nonlocal changed
            result = original(*args, **kwargs)
            if not changed:
                path = bundle["root"] / "origin.sigstore.json"
                path.write_bytes(b"changed signature bundle bytes\n")
                os.chmod(path, 0o600)
                changed = True
            return result

        with mock.patch.object(transport.native, "_write_member", side_effect=mutate_retained):
            with self.assertRaises(origin.OriginError):
                self.extract(bundle, output)
        self.assertTrue(changed)
        self.assertTrue(output.is_dir())
        self.assertTrue(any(path.is_file() for path in output.rglob("*")))


if __name__ == "__main__":
    unittest.main(verbosity=2)
