#!/usr/bin/env python3
"""Synthetic byte-boundary tests for native-lane-transport.py only."""

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


SCRIPT = Path(__file__).resolve().parents[1] / "native-lane-transport.py"
SPEC = importlib.util.spec_from_file_location("native_lane_transport", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
transport = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(transport)
origin = transport.origin

CONTEXT = {
    "repository": "example/project",
    "repository_id": 7890,
    "producer_commit": "a" * 40,
    "source_ref": "refs/heads/main",
    "workflow": ".github/workflows/toolchain.yml",
    "run_id": 123456,
    "run_attempt": 2,
}
LANE = {"role": "build", "group": "rv32", "host": "linux",
        "profile": "release", "copy": "a"}
JOB = {"id": 90901, "name": "Build toolchain"}
ARTIFACT_ID = 667002
PROOF_ID = 667003
ARCHIVE = "aros-rv32-toolchain.tar.xz"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def measurement(data: bytes) -> dict:
    return {"sha256": digest(data), "size": len(data)}


def lane_members() -> dict[str, bytes]:
    result = {
        "evidence/build-result.json": b"synthetic build-result evidence\n",
        "evidence/environment.json": b"synthetic environment evidence\n",
        "evidence/environment-result.json": b"synthetic environment result\n",
        "evidence/package-result.json": b"synthetic package result\n",
        "evidence/package-verify.json": b"synthetic package readback\n",
        "evidence/measurement.json": b"synthetic portable measurement\n",
        f"package/{ARCHIVE}": b"synthetic tar.xz bytes, not a native archive\n",
    }
    package = f"package/{ARCHIVE}"
    result[package + ".manifest.json"] = b"synthetic manifest\n"
    result[package + ".sha256"] = b"synthetic checksum\n"
    result[package + ".spdx.json"] = b"synthetic SPDX evidence\n"
    return result


def zip_bytes(entries: list[tuple[str, bytes, int | None, int | None]]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data, mode, compression in entries:
            info = zipfile.ZipInfo(name)
            info.compress_type = zipfile.ZIP_DEFLATED if compression is None else compression
            if mode is not None:
                info.create_system = 3
                info.external_attr = mode << 16
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", message=r"Duplicate name:.*", category=UserWarning)
                archive.writestr(info, data)
    return buffer.getvalue()


def encrypted_flagged_zip(raw: bytes) -> bytes:
    """Set the encryption bit in both ZIP header forms without encrypting data."""
    changed = bytearray(raw)
    locations = ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8))
    count = 0
    for signature, offset in locations:
        position = 0
        while True:
            position = changed.find(signature, position)
            if position < 0:
                break
            flag_position = position + offset
            flags = int.from_bytes(changed[flag_position:flag_position + 2], "little")
            changed[flag_position:flag_position + 2] = (flags | 1).to_bytes(2, "little")
            count += 1
            position += len(signature)
    if count != 20:
        raise AssertionError(f"expected 20 ZIP local/central headers, found {count}")
    return bytes(changed)


def entries_for(members: dict[str, bytes]) -> list[tuple[str, bytes, int | None, int | None]]:
    return [(name, value, None, None) for name, value in members.items()]


def make_bundle(root: Path, *, entries: list[tuple[str, bytes, int | None, int | None]] | None = None,
                member_data: dict[str, bytes] | None = None,
                inventory: dict | None = None, selected_lane: dict | None = None,
                origin_lane: dict | None = None, selected_job: dict | None = None,
                origin_job: dict | None = None, origin_context: dict | None = None,
                selected_context: dict | None = None) -> dict:
    root.mkdir(mode=0o700)
    os.chmod(root, 0o700)
    members = lane_members() if member_data is None else member_data
    archive_entries = entries_for(members) if entries is None else entries
    raw_zip = zip_bytes(archive_entries)
    (root / "payload.zip").write_bytes(raw_zip)
    selection = {
        "schema": origin.SELECTION_SCHEMA,
        "context": copy.deepcopy(CONTEXT if selected_context is None else selected_context),
        "selection": copy.deepcopy(LANE if selected_lane is None else selected_lane),
        "job": copy.deepcopy(JOB if selected_job is None else selected_job),
        "artifact": {
            "id": ARTIFACT_ID,
            "name": "toolchain-build",
            "sha256": digest(raw_zip),
            "size_in_bytes": len(raw_zip),
        },
        "proof": {"id": PROOF_ID, "name": "toolchain-origin-proof",
                  "sha256": "b" * 64, "size_in_bytes": 123},
    }
    inventory_files = {name: measurement(data) for name, data in members.items()}
    signed = {
        "schema": origin.SCHEMA,
        "context": copy.deepcopy(CONTEXT if origin_context is None else origin_context),
        "selection": copy.deepcopy(LANE if origin_lane is None else origin_lane),
        "job": {"id": JOB["id"], "check_run_id": 555001, "name": JOB["name"]},
        "artifact": copy.deepcopy(selection["artifact"]),
        "files": copy.deepcopy(inventory_files if inventory is None else inventory),
    }
    if origin_job is not None:
        signed["job"] = copy.deepcopy(origin_job)
    if selected_job is not None and origin_job is None:
        signed["job"]["id"] = selected_job["id"]
        signed["job"]["name"] = selected_job["name"]
    (root / "origin.json").write_bytes(origin.canonical(signed))
    (root / "origin.sigstore.json").write_bytes(b"synthetic signature bundle bytes; not authenticated\n")
    (root / "selection.json").write_bytes(origin.canonical(selection))
    for path in root.iterdir():
        os.chmod(path, 0o600)
    return {"root": root, "members": members, "raw_zip": raw_zip,
            "selection": selection, "signed": signed, "inventory": inventory_files}


class NativeLaneTransportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="native-lane-transport-")
        self.base = Path(self.temporary.name).resolve()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def bundle(self, name: str = "retained", **kwargs) -> dict:
        return make_bundle(self.base / name, **kwargs)

    def test_shared_identity_join_requires_an_explicit_diagnostic_role(self) -> None:
        lane = {**LANE, "role": "diagnostic", "copy": "none"}
        bundle = self.bundle(selected_lane=lane, origin_lane=lane)
        selected = (bundle["root"] / "selection.json").read_bytes()
        signed = (bundle["root"] / "origin.json").read_bytes()
        with self.assertRaisesRegex(origin.OriginError, "selected transport role"):
            transport._validate_identity(selected, signed)
        observed, record, artifact = transport._validate_identity(
            selected, signed, required_role="diagnostic")
        self.assertEqual(observed["selection"], lane)
        self.assertEqual(record["selection"], lane)
        self.assertEqual(artifact["id"], ARTIFACT_ID)
        with self.assertRaisesRegex(origin.OriginError, "unsupported retained transport role"):
            transport._validate_identity(selected, signed, required_role="compatibility")
        # The native public extractor stays closed to diagnostic payloads.
        with self.assertRaisesRegex(origin.OriginError, "selected transport role"):
            transport.extract(bundle["root"], self.base / "must-not-extract")
        self.assertFalse((self.base / "must-not-extract").exists())

    def output(self, name: str = "output") -> Path:
        return self.base / name

    def test_sdk_identity_requires_explicit_role_and_cannot_enter_compiler_extractor(self) -> None:
        lane = {**LANE, "role": "sdk", "copy": "none"}
        bundle = self.bundle(selected_lane=lane, origin_lane=lane)
        selected = (bundle["root"] / "selection.json").read_bytes()
        signed = (bundle["root"] / "origin.json").read_bytes()
        observed, _, _ = transport._validate_identity(selected, signed, required_role="sdk")
        self.assertEqual(observed["selection"], lane)
        for role in ("build", "diagnostic"):
            with self.subTest(role=role), self.assertRaisesRegex(
                    origin.OriginError, "selected transport role"):
                transport._validate_identity(selected, signed, required_role=role)
        output = self.output()
        with self.assertRaisesRegex(origin.OriginError, "selected transport role"):
            transport.extract(bundle["root"], output)
        self.assertFalse(output.exists())

    def assert_rejected(self, bundle: dict, *, output: Path | None = None) -> None:
        with self.assertRaises(origin.OriginError):
            transport.extract(bundle["root"], self.output() if output is None else output)

    def assert_rejected_reason(self, bundle: dict, reason: str,
                               *, output: Path | None = None) -> None:
        with self.assertRaises(origin.OriginError) as caught:
            transport.extract(bundle["root"], self.output() if output is None else output)
        self.assertEqual(str(caught.exception), reason)

    def rewrite_selection_and_origin(self, bundle: dict, *, selected: dict | None = None,
                                     signed: dict | None = None) -> None:
        selected_record = copy.deepcopy(bundle["selection"] if selected is None else selected)
        signed_record = copy.deepcopy(bundle["signed"] if signed is None else signed)
        (bundle["root"] / "selection.json").write_bytes(origin.canonical(selected_record))
        (bundle["root"] / "origin.json").write_bytes(origin.canonical(signed_record))
        os.chmod(bundle["root"] / "selection.json", 0o600)
        os.chmod(bundle["root"] / "origin.json", 0o600)

    def bind_payload_zip(self, bundle: dict, raw: bytes, *, declared_size: int | None = None) -> None:
        (bundle["root"] / "payload.zip").write_bytes(raw)
        os.chmod(bundle["root"] / "payload.zip", 0o600)
        selected = copy.deepcopy(bundle["selection"])
        signed = copy.deepcopy(bundle["signed"])
        for identity in (selected["artifact"], signed["artifact"]):
            identity["sha256"] = digest(raw)
            identity["size_in_bytes"] = len(raw) if declared_size is None else declared_size
        self.rewrite_selection_and_origin(bundle, selected=selected, signed=signed)

    def test_stream_extracts_closed_inventory_and_verify_mode_is_byte_identical(self) -> None:
        bundle = self.bundle()
        output = self.output()
        extracted = transport.extract(bundle["root"], output)
        verified = transport.verify_output(bundle["root"], output)
        self.assertEqual(extracted, verified)
        self.assertEqual(extracted["schema"], "aros-toolchain-native-lane-transport-v2")
        self.assertEqual(extracted["assurance"], "transport-byte-readback-only")
        self.assertEqual(set(extracted["output_files"]), set(bundle["members"]))
        self.assertEqual(Path(extracted["package_dir"]), output / "package")
        self.assertEqual(Path(extracted["measurement"]), output / "evidence/measurement.json")
        self.assertEqual(Path(extracted["environment"]), output / "evidence/environment.json")
        self.assertEqual(extracted["raw_zip_sha256"], digest(bundle["raw_zip"]))
        for relative, data in bundle["members"].items():
            path = output / relative
            self.assertEqual(path.read_bytes(), data)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((output / "package").stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((output / "evidence").stat().st_mode), 0o700)

    def test_cli_extract_and_verify_modes_emit_identical_json(self) -> None:
        bundle = self.bundle()
        output = self.output()
        base = [sys.executable, str(SCRIPT), "--retained-dir", str(bundle["root"])]
        extracted = subprocess.run(base + ["--output-dir", str(output)],
                                   capture_output=True, text=True, check=False)
        self.assertEqual(extracted.returncode, 0, extracted.stderr)
        verified = subprocess.run(base + ["--verify-output-dir", str(output)],
                                  capture_output=True, text=True, check=False)
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assertEqual(json.loads(extracted.stdout), json.loads(verified.stdout))
        self.assertEqual(extracted.stdout, verified.stdout)

        invalid = subprocess.run(base + ["--output-dir", str(output),
                                         "--verify-output-dir", str(output)],
                                 capture_output=True, text=True, check=False)
        self.assertNotEqual(invalid.returncode, 0)
        self.assertEqual(invalid.stdout, "")

    def test_signed_inventory_missing_or_extra_file_is_rejected(self) -> None:
        bundle = self.bundle()
        del bundle["signed"]["files"]["evidence/environment.json"]
        (bundle["root"] / "origin.json").write_bytes(origin.canonical(bundle["signed"]))
        self.assert_rejected(bundle)

        extra_inventory = dict(bundle["inventory"])
        extra_inventory["evidence/unselected.json"] = measurement(b"extra")
        bundle = self.bundle("extra-inventory", inventory=extra_inventory)
        self.assert_rejected(bundle)

    def test_measurements_are_validated_before_zip_open_and_metadata_is_capped(self) -> None:
        bundle = self.bundle()
        signed = copy.deepcopy(bundle["signed"])
        signed["files"]["evidence/environment.json"]["size"] = origin.MAX_METADATA + 1
        self.rewrite_selection_and_origin(bundle, signed=signed)
        with mock.patch.object(origin, "verify_zip") as verify_zip:
            self.assert_rejected_reason(bundle, "signed native metadata member exceeds 16 MiB limit")
            verify_zip.assert_not_called()

        for index, invalid in enumerate(({"sha256": "A" * 64, "size": 1},
                                         {"sha256": "a" * 64, "size": True},
                                         {"sha256": "a" * 63, "size": 1})):
            with self.subTest(measurement=invalid):
                bundle = self.bundle("bad-measurement-" + str(index))
                signed = copy.deepcopy(bundle["signed"])
                signed["files"]["evidence/environment.json"] = invalid
                self.rewrite_selection_and_origin(bundle, signed=signed)
                with mock.patch.object(origin, "verify_zip") as verify_zip:
                    self.assert_rejected_reason(bundle, "signed native file measurement is invalid")
                    verify_zip.assert_not_called()

    def test_raw_zip_and_aggregate_file_size_limits_have_closed_reasons(self) -> None:
        bundle = self.bundle("raw-zip-limit")
        file_total = sum(entry["size"] for entry in bundle["inventory"].values())
        raw_limit = file_total + 1
        self.assertGreater(len(bundle["raw_zip"]), raw_limit)
        self.bind_payload_zip(bundle, bundle["raw_zip"], declared_size=raw_limit)
        with mock.patch.object(origin, "MAX_PAYLOAD", raw_limit):
            self.assert_rejected_reason(bundle, "input is not a bounded singly linked regular file")

        enlarged = lane_members()
        enlarged["evidence/environment.json"] = b"e" * 2500
        enlarged["evidence/environment-result.json"] = b"r" * 2500
        bundle = self.bundle("aggregate-files", member_data=enlarged)
        aggregate_limit = 4096
        self.assertLess(len(bundle["raw_zip"]), aggregate_limit)
        self.assertGreater(sum(entry["size"] for entry in bundle["inventory"].values()), aggregate_limit)
        with mock.patch.object(origin, "MAX_PAYLOAD", aggregate_limit):
            self.assert_rejected_reason(
                bundle, "signed native file inventory exceeds aggregate payload byte limit")

    def test_zip_extra_member_and_retained_extra_file_are_rejected(self) -> None:
        members = lane_members()
        entries = entries_for(members)
        entries.append(("evidence/unselected.json", b"extra", None, None))
        bundle = self.bundle("zip-extra", entries=entries)
        self.assert_rejected(bundle)

        bundle = self.bundle("retained-extra")
        extra = bundle["root"] / "unexpected.json"
        extra.write_bytes(b"extra")
        self.assert_rejected(bundle)

    def test_changed_selection_and_origin_identity_joins_are_rejected(self) -> None:
        bundle = self.bundle()
        selected = copy.deepcopy(bundle["selection"])
        selected["selection"]["group"] = "other"
        self.rewrite_selection_and_origin(bundle, selected=selected)
        self.assert_rejected(bundle)

        bundle = self.bundle("job-join")
        selected = copy.deepcopy(bundle["selection"])
        selected["job"]["id"] += 1
        self.rewrite_selection_and_origin(bundle, selected=selected)
        self.assert_rejected(bundle)

        bundle = self.bundle("context-join")
        selected = copy.deepcopy(bundle["selection"])
        selected["context"]["run_attempt"] += 1
        self.rewrite_selection_and_origin(bundle, selected=selected)
        self.assert_rejected(bundle)

    def test_origin_check_run_id_is_required_and_canonical(self) -> None:
        bundle = self.bundle()
        signed = copy.deepcopy(bundle["signed"])
        signed["job"]["check_run_id"] = True
        self.rewrite_selection_and_origin(bundle, signed=signed)
        self.assert_rejected(bundle)

    def test_only_native_build_copies_are_admitted_by_transport_shape(self) -> None:
        for index, lane in enumerate((
            {"role": "comparison", "group": "rv32", "host": "linux",
             "profile": "release", "copy": "none"},
            {"role": "build", "group": "rv32", "host": "linux",
             "profile": "release", "copy": "none"},
            {"role": "build", "group": "rv32", "host": "linux",
             "profile": "release", "copy": "c"},
        )):
            with self.subTest(lane=lane):
                bundle = self.bundle("wrong-lane-" + str(index))
                self.rewrite_selection_and_origin(bundle, selected={**bundle["selection"],
                                                                      "selection": lane},
                                                   signed={**bundle["signed"], "selection": lane})
                self.assert_rejected(bundle)

    def test_corrupted_payload_bytes_fail_member_readback_after_archive_rebind(self) -> None:
        bundle = self.bundle()
        modified = dict(bundle["members"])
        modified["evidence/build-result.json"] = b"different synthetic evidence\n"
        raw_zip = zip_bytes(entries_for(modified))
        (bundle["root"] / "payload.zip").write_bytes(raw_zip)
        selection = copy.deepcopy(bundle["selection"])
        selection["artifact"]["sha256"] = digest(raw_zip)
        selection["artifact"]["size_in_bytes"] = len(raw_zip)
        signed = copy.deepcopy(bundle["signed"])
        signed["artifact"] = copy.deepcopy(selection["artifact"])
        self.rewrite_selection_and_origin(bundle, selected=selection, signed=signed)
        self.assert_rejected(bundle)

    def test_zip_traversal_duplicate_case_alias_link_and_compression_are_rejected(self) -> None:
        base = lane_members()
        cases = {
            "traversal": [("../outside", b"x", None, None), *entries_for(dict(list(base.items())[1:]))],
            "case-alias": [("Evidence/environment.json", base["evidence/environment.json"], None, None),
                           *entries_for({name: value for name, value in base.items()
                                         if name != "evidence/environment.json"})],
            "link": [(name, data, (stat.S_IFLNK | 0o777) if name == "evidence/build-result.json" else None, None)
                     for name, data in base.items()],
            "unsupported-compression": [(name, data, None,
                                           zipfile.ZIP_BZIP2 if name == "evidence/build-result.json" else None)
                                          for name, data in base.items()],
        }
        duplicate = entries_for(base)
        duplicate[1] = (duplicate[0][0], duplicate[1][1], None, None)
        cases["duplicate"] = duplicate
        for label, entries in cases.items():
            with self.subTest(case=label):
                bundle = self.bundle(label, entries=entries)
                self.assert_rejected(bundle)

        bundle = self.bundle("encrypted-flag")
        self.bind_payload_zip(bundle, encrypted_flagged_zip(bundle["raw_zip"]))
        self.assert_rejected_reason(bundle, "ZIP member is not an ordinary unencrypted file")

    def test_corrupt_missing_extra_and_linked_extracted_output_are_rejected(self) -> None:
        for label in ("corrupt", "missing", "extra", "link"):
            with self.subTest(output=label):
                bundle = self.bundle("retained-" + label)
                output = self.output("output-" + label)
                transport.extract(bundle["root"], output)
                target = output / "evidence/build-result.json"
                if label == "corrupt":
                    target.write_bytes(b"changed")
                elif label == "missing":
                    target.unlink()
                elif label == "extra":
                    (output / "evidence/extra.json").write_bytes(b"extra")
                else:
                    target.unlink()
                    target.symlink_to(output / "evidence/environment.json")
                with self.assertRaises(origin.OriginError):
                    transport.verify_output(bundle["root"], output)

    def test_existing_output_is_preserved(self) -> None:
        bundle = self.bundle()
        output = self.output()
        output.mkdir()
        os.chmod(output, 0o700)
        sentinel = output / "keep.txt"
        sentinel.write_bytes(b"untouched")
        os.chmod(sentinel, 0o600)
        before = (output.stat().st_ino, output.stat().st_mtime_ns, output.stat().st_mode,
                  sentinel.stat().st_ino, sentinel.stat().st_size, sentinel.stat().st_mtime_ns,
                  sentinel.stat().st_mode, sentinel.read_bytes())
        self.assert_rejected_reason(bundle, "output directory must be fresh", output=output)
        self.assertEqual(sentinel.read_bytes(), b"untouched")
        self.assertEqual(set(path.name for path in output.iterdir()), {"keep.txt"})
        after = (output.stat().st_ino, output.stat().st_mtime_ns, output.stat().st_mode,
                 sentinel.stat().st_ino, sentinel.stat().st_size, sentinel.stat().st_mtime_ns,
                 sentinel.stat().st_mode, sentinel.read_bytes())
        self.assertEqual(after, before)

    def test_verify_mode_does_not_modify_existing_output(self) -> None:
        bundle = self.bundle()
        output = self.output()
        transport.extract(bundle["root"], output)

        def snapshot() -> dict[str, tuple]:
            paths = [output, *output.rglob("*")]
            result = {}
            for path in paths:
                current = path.lstat()
                item = (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns,
                        current.st_ctime_ns, current.st_uid, stat.S_IMODE(current.st_mode))
                if stat.S_ISREG(current.st_mode):
                    item += (path.read_bytes(),)
                result[path.relative_to(output.parent).as_posix()] = item
            return result

        before = snapshot()
        transport.verify_output(bundle["root"], output)
        self.assertEqual(snapshot(), before)

    def test_partial_extraction_failure_removes_only_created_output(self) -> None:
        bundle = self.bundle()
        output = self.output()
        writer = transport._write_member
        count = 0

        def fail_after_one(*args, **kwargs):
            nonlocal count
            result = writer(*args, **kwargs)
            count += 1
            if count == 1:
                raise RuntimeError("synthetic extraction stop")
            return result

        with mock.patch.object(transport, "_write_member", side_effect=fail_after_one):
            with self.assertRaises(origin.OriginError):
                transport.extract(bundle["root"], output)
        self.assertFalse(output.exists())
        self.assertEqual(set(path.name for path in bundle["root"].iterdir()),
                         {"payload.zip", "origin.json", "origin.sigstore.json", "selection.json"})

    def test_symlinked_retained_metadata_is_rejected(self) -> None:
        bundle = self.bundle()
        path = bundle["root"] / "origin.sigstore.json"
        raw = path.read_bytes()
        path.unlink()
        outside = self.base / "bundle-bytes"
        outside.write_bytes(raw)
        path.symlink_to(outside)
        with self.assertRaises(origin.OriginError):
            transport.extract(bundle["root"], self.output())

    def test_hardlinked_retained_and_extracted_inputs_are_rejected(self) -> None:
        bundle = self.bundle("hardlinked-retained")
        outside = self.base / "retained-hardlink"
        os.link(bundle["root"] / "origin.sigstore.json", outside)
        self.assert_rejected_reason(bundle, "input is not a bounded singly linked regular file")

        bundle = self.bundle("hardlinked-extracted")
        output = self.output("hardlinked-output")
        transport.extract(bundle["root"], output)
        outside_output = self.base / "extracted-hardlink"
        os.link(output / "evidence/build-result.json", outside_output)
        with self.assertRaises(origin.OriginError) as caught:
            transport.verify_output(bundle["root"], output)
        self.assertEqual(str(caught.exception),
                         "verification output member must be an owner-only ordinary file")

    def test_linked_output_parent_is_rejected_before_output_creation(self) -> None:
        bundle = self.bundle()
        real_parent = self.base / "real-output-parent"
        real_parent.mkdir()
        linked_parent = self.base / "linked-output-parent"
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        output = linked_parent / "result"
        self.assert_rejected_reason(
            bundle, "output parent must be an existing canonical directory", output=output)
        self.assertFalse((real_parent / "result").exists())


if __name__ == "__main__":
    unittest.main()
