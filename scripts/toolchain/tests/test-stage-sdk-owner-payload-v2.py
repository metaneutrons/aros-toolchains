#!/usr/bin/env python3
"""Synthetic bounded tests for SDK owner-payload staging."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "stage-sdk-owner-payload-v2.py"
SPEC = importlib.util.spec_from_file_location("stage_sdk_owner_payload_v2", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
stager = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stager)


SDK_ID = "core-sdk"
GROUP = "gnu-group"
PROFILE = "pc-x86_64"
HOST = "linux-x86_64"
def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"


def measure(raw: bytes) -> dict:
    return {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}


def identity(sdk_id: str = SDK_ID, version: str = "1.2.3") -> dict:
    return {
        "sdk_id": sdk_id,
        "version": version,
        "target": {"target_triple": "i386-aros", "abi": {"target_triple": "i386-aros"}},
        "source": {
            "commit": "a" * 40,
            "git_tree": "b" * 40,
            "content_sha256": "c" * 64,
            "contract_sha256": "d" * 64,
        },
        "source_date_epoch": 1730000000,
    }


class Fixture:
    def __init__(self, root: Path, family: str = "gnu", sdk_id: str = SDK_ID):
        self.root = root
        self.sdk_id = sdk_id
        self.asset = f"aros-sdk-{sdk_id}-1.2.3.tar.xz"
        self.operation = root / "operation"
        self.output = root / "output"
        self.operation.mkdir()
        (self.operation / "package").mkdir()
        (self.operation / "local-evidence").mkdir()
        evidence = self.operation / "local-evidence" / "evidence"
        evidence.mkdir()
        selected_identity = identity(sdk_id)
        archive = b"synthetic bounded SDK archive bytes\n"
        archive_sha = hashlib.sha256(archive).hexdigest()
        (self.operation / "package" / self.asset).write_bytes(archive)
        manifest = {
            "schema": "aros-sdk-manifest-v2",
            "identity": selected_identity,
            "tree_sha256": "e" * 64,
            "files": [
                {"path": "bin", "mode": "0755", "type": "directory"},
                {"path": "bin/aros", "mode": "0755", "type": "file",
                 "sha256": "e" * 64, "size": 123},
            ],
        }
        (self.operation / "package" / f"{self.asset}.manifest.json").write_bytes(canonical(manifest))
        (self.operation / "package" / f"{self.asset}.sha256").write_bytes(
            f"{archive_sha}  {self.asset}\n".encode())
        generation = {
            "schema": ("aros-sdk-generation-record-v1" if family == "gnu"
                       else "aros-llvm-sdk-generation-record-v1"),
            "assurance": "local-generation-binding-not-release-admission",
            "identity": selected_identity,
            "source_profile": "aros-source-profile",
            "environment_sha256": "f" * 64,
            "compatibility_receipt_sha256": "1" * 64,
            "sdk_link_receipt_sha256": "2" * 64,
            "sdk_inventory_sha256": "3" * 64,
            "sdk_entries": 4,
        }
        if family == "llvm":
            generation["binding_sha256"] = "4" * 64
        (self.operation / "generation.json").write_bytes(canonical(generation))
        (self.operation / "local-evidence" / "inputs.json").write_bytes(b'{"selected":"inputs"}\n')
        # Real SDK operations contain unrelated build trees, reports, results,
        # and lock files. Selection must not enumerate or stage these siblings.
        (self.operation / "result.json").write_text("{}\n")
        (self.operation / ".aros-lock-sdk-export").write_text("lock\n")
        for name in ("engine-work", "first", "second", "reports", "cmake", "upstream-build"):
            (self.operation / name).mkdir()
        (self.operation / "engine-work" / "unportable name").write_text("not selected\n")
        (self.operation / "local-evidence" / ".aros-lock-export").write_text("lock\n")
        (self.operation / "ignored-symlink").symlink_to(self.root, target_is_directory=True)
        os.mkfifo(self.operation / "ignored-fifo")
        members = {
            "native-compatibility.receipt.json": b'{"receipt":"synthetic"}\n',
            "standalone-object.o": b"bounded synthetic object bytes",
        }
        for name, raw in members.items():
            (evidence / name).write_bytes(raw)
        measurement_schema = ("aros-toolchain-compatibility-measurement-v3" if family == "gnu"
                              else "aros-toolchain-compatibility-measurement-v4")
        measurement_doc = {"schema": measurement_schema,
                           "files": {name: measure(raw) for name, raw in members.items()}}
        (evidence / "compatibility-measurement.json").write_bytes(canonical(measurement_doc))
        self.family = family


class StageSdkOwnerPayloadTests(unittest.TestCase):
    def make_fixture(self, family: str = "gnu", sdk_id: str = SDK_ID) -> Fixture:
        temporary = tempfile.TemporaryDirectory(prefix="aros-sdk-owner-payload-test-")
        self.addCleanup(temporary.cleanup)
        return Fixture(Path(temporary.name).resolve(), family, sdk_id)

    def stage(self, fixture: Fixture, *, sdk_id: str | None = None, group: str = GROUP,
              profile: str = PROFILE, host: str = HOST, operation_dir: Path | None = None,
              output_dir: Path | None = None) -> dict:
        return stager.stage(operation_dir or fixture.operation, output_dir or fixture.output,
                            sdk_id=sdk_id or fixture.sdk_id, group=group, profile=profile, host=host)

    def rejects_before_output(self, fixture: Fixture, **kwargs: object) -> None:
        with self.assertRaises((stager.StageError, stager._ORIGIN.OriginError)):
            self.stage(fixture, **kwargs)
        output = kwargs.get("output_dir", fixture.output)
        self.assertFalse(Path(output).exists(), "preflight rejection created an output")

    def test_stages_positive_gnu_and_llvm_closures(self) -> None:
        for family in ("gnu", "llvm"):
            with self.subTest(family=family):
                fixture = self.make_fixture(family)
                result = self.stage(fixture)
                lane = json.loads((fixture.output / "sdk-lane.json").read_bytes())
                self.assertEqual(lane["schema"], "aros-sdk-owner-payload-v2")
                self.assertEqual(lane["assurance"], "staging-byte-consistency-only")
                self.assertEqual(
                    {key: lane[key] for key in ("sdk_id", "group_id", "target_profile", "host")},
                    {"sdk_id": SDK_ID, "group_id": GROUP, "target_profile": PROFILE, "host": HOST},
                )
                self.assertEqual(lane["files"], result["files"])
                self.assertNotIn("sdk-lane.json", lane["files"])
                self.assertEqual(
                    set(lane["files"]),
                    {
                        "generation.json",
                        f"package/{fixture.asset}",
                        f"package/{fixture.asset}.manifest.json",
                        f"package/{fixture.asset}.sha256",
                        "compatibility-inputs.json",
                        "compatibility/compatibility-measurement.json",
                        "compatibility/native-compatibility.receipt.json",
                        "compatibility/standalone-object.o",
                    },
                )
                self.assertEqual(
                    (fixture.output / "compatibility-inputs.json").read_bytes(),
                    (fixture.operation / "local-evidence" / "inputs.json").read_bytes(),
                )
                self.assertEqual(
                    {path.name for path in fixture.output.iterdir()},
                    {"generation.json", "package", "compatibility-inputs.json",
                     "compatibility", "sdk-lane.json"},
                )
                self.assertEqual(stat.S_IMODE(fixture.output.stat().st_mode), 0o700)
                for path in fixture.output.rglob("*"):
                    if path.is_dir():
                        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
                    else:
                        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_rejects_wrong_evidence_hash_without_creating_output(self) -> None:
        fixture = self.make_fixture()
        path = fixture.operation / "local-evidence" / "evidence" / "compatibility-measurement.json"
        document = json.loads(path.read_bytes())
        document["files"]["standalone-object.o"]["sha256"] = "0" * 64
        path.write_bytes(canonical(document))
        self.rejects_before_output(fixture)

    def test_rejects_missing_and_extra_evidence_files(self) -> None:
        fixture = self.make_fixture()
        (fixture.operation / "local-evidence" / "evidence" / "standalone-object.o").unlink()
        self.rejects_before_output(fixture)

        fixture = self.make_fixture()
        (fixture.operation / "local-evidence" / "evidence" / "extra.bin").write_bytes(b"extra")
        self.rejects_before_output(fixture)

    def test_rejects_missing_compatibility_manifest_and_package_manifest(self) -> None:
        fixture = self.make_fixture()
        (fixture.operation / "local-evidence" / "evidence" / "compatibility-measurement.json").unlink()
        self.rejects_before_output(fixture)

        fixture = self.make_fixture()
        (fixture.operation / "package" / f"{fixture.asset}.manifest.json").unlink()
        self.rejects_before_output(fixture)

    def test_rejects_mismatched_generation_package_identity(self) -> None:
        fixture = self.make_fixture()
        path = fixture.operation / "generation.json"
        record = json.loads(path.read_bytes())
        record["identity"]["version"] = "9.8.7"
        path.write_bytes(canonical(record))
        self.rejects_before_output(fixture)

    def test_rejects_compiler_only_measurement_v2(self) -> None:
        fixture = self.make_fixture()
        path = fixture.operation / "local-evidence" / "evidence" / "compatibility-measurement.json"
        document = json.loads(path.read_bytes())
        document["schema"] = "aros-toolchain-compatibility-measurement-v2"
        path.write_bytes(canonical(document))
        self.rejects_before_output(fixture)

    def test_rejects_symlinked_file_and_symlinked_ancestor(self) -> None:
        fixture = self.make_fixture()
        evidence_file = fixture.operation / "local-evidence" / "evidence" / "standalone-object.o"
        external = fixture.root / "external.bin"
        external.write_bytes(evidence_file.read_bytes())
        evidence_file.unlink()
        evidence_file.symlink_to(external)
        self.rejects_before_output(fixture)

        fixture = self.make_fixture()
        alias = fixture.root / "linked-parent"
        alias.symlink_to(fixture.root, target_is_directory=True)
        self.rejects_before_output(fixture, operation_dir=alias / "operation")

    def test_rejects_hardlink_and_casefold_path_aliases(self) -> None:
        fixture = self.make_fixture()
        evidence_file = fixture.operation / "local-evidence" / "evidence" / "standalone-object.o"
        os.link(evidence_file, fixture.root / "hardlink-alias")
        self.rejects_before_output(fixture)

        fixture = self.make_fixture()
        evidence = fixture.operation / "local-evidence" / "evidence"
        extra = b"casefold collision"
        (evidence / "Native-Compatibility.receipt.json").write_bytes(extra)
        measurement_path = evidence / "compatibility-measurement.json"
        document = json.loads(measurement_path.read_bytes())
        document["files"]["Native-Compatibility.receipt.json"] = measure(extra)
        measurement_path.write_bytes(canonical(document))
        self.rejects_before_output(fixture)

    def test_rejects_path_alias_overlap_and_reused_output(self) -> None:
        fixture = self.make_fixture()
        aliased = fixture.root / "missing" / ".." / "operation"
        self.rejects_before_output(fixture, operation_dir=aliased)

        fixture = self.make_fixture()
        overlapping = fixture.operation / "staged"
        self.rejects_before_output(fixture, output_dir=overlapping)

        fixture = self.make_fixture()
        fixture.output.mkdir()
        with self.assertRaises((stager.StageError, stager._ORIGIN.OriginError)):
            self.stage(fixture)
        self.assertTrue(fixture.output.is_dir())
        self.assertEqual(list(fixture.output.iterdir()), [])

    def test_rejects_malformed_tuple_and_duplicate_json(self) -> None:
        fixture = self.make_fixture()
        self.rejects_before_output(fixture, group="../escape")

        fixture = self.make_fixture()
        path = fixture.operation / "generation.json"
        original = path.read_bytes()
        path.write_bytes(original.replace(b'"schema":', b'"schema":"aros-sdk-generation-record-v1","schema":', 1))
        self.rejects_before_output(fixture)

    def test_accepts_native_sdk_plus_id_and_real_manifest_vector_shape(self) -> None:
        fixture = self.make_fixture(sdk_id="sdk+preview")
        fixture.output = fixture.root / "sdk+preview"
        result = self.stage(fixture)
        self.assertEqual(result["selection"]["sdk_id"], "sdk+preview")
        self.assertTrue((fixture.output / "package" / fixture.asset).is_file())
        manifest = json.loads((fixture.output / "package" / f"{fixture.asset}.manifest.json").read_bytes())
        self.assertIsInstance(manifest["files"], list)
        self.assertEqual(manifest["files"][0], {"path": "bin", "mode": "0755", "type": "directory"})

    def test_rejects_dict_shaped_sdk_manifest_files(self) -> None:
        fixture = self.make_fixture()
        path = fixture.operation / "package" / f"{fixture.asset}.manifest.json"
        document = json.loads(path.read_bytes())
        document["files"] = {}
        path.write_bytes(canonical(document))
        self.rejects_before_output(fixture)

    def test_streams_ordinary_compatibility_evidence_without_materializing_it(self) -> None:
        fixture = self.make_fixture()
        original = stager.read_bounded
        materialized = []

        def observed(path: Path, limit: int, label: str) -> tuple[dict, bytes]:
            materialized.append(path)
            return original(path, limit, label)

        with patch.object(stager, "read_bounded", side_effect=observed):
            self.stage(fixture)
        ordinary_evidence = fixture.operation / "local-evidence" / "evidence" / "standalone-object.o"
        self.assertNotIn(ordinary_evidence, materialized)


if __name__ == "__main__":
    unittest.main(verbosity=2)
