"""Synthetic CLI and filesystem counterprobes for native-owner payload staging."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts/toolchain/stage-native-owner-payload-v2.py"
SPEC = importlib.util.spec_from_file_location("stage_native_owner_payload_v2", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
stager = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stager)
native = stager._NATIVE

ARCHIVE_NAME = "aros-rv32-linux-x86_64.tar.xz"
LOCK_NAME = ".aros-lock-e46ccf7835b00c92-0000000000000000"
ERROR = "native owner-payload staging rejected; no authority was created\n"


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"


class Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.source = root / "payload"
        self.evidence = self.source / "evidence"
        self.package = self.source / "package"
        self.output = root / "transport-payload"
        self.evidence.mkdir(parents=True)
        self.package.mkdir()
        self.archive = b"synthetic package archive bytes\n"
        self.measurement = b'{"schema":"synthetic-measurement-v1","files":[]}\n'
        (self.package / ARCHIVE_NAME).write_bytes(self.archive)
        (self.package / f"{ARCHIVE_NAME}.manifest.json").write_bytes(b"synthetic manifest\n")
        (self.package / f"{ARCHIVE_NAME}.sha256").write_bytes(
            f"{digest(self.archive)}  {ARCHIVE_NAME}\n".encode()
        )
        (self.package / f"{ARCHIVE_NAME}.spdx.json").write_bytes(b"synthetic SPDX record\n")
        for relative in sorted(native.EVIDENCE_NAMES):
            name = relative.split("/", 1)[1]
            path = self.evidence / name
            if name == "measurement.json":
                path.write_bytes(self.measurement)
            elif name == "package-result.json":
                self.write_package_result()
            else:
                path.write_bytes(f"synthetic {name}\n".encode())

    def result(self, **overrides: object) -> dict[str, object]:
        archive_path = self.package / ARCHIVE_NAME
        result: dict[str, object] = {
            "schema": "aros-toolchain-producer-stage-v1",
            "operation": "package",
            "package_dir": str(self.package),
            "archive": str(archive_path),
            "manifest": str(archive_path) + ".manifest.json",
            "checksum": str(archive_path) + ".sha256",
            "sbom": str(archive_path) + ".spdx.json",
            "sha256": digest(self.archive),
            "size": len(self.archive),
            "finished_candidate": {
                "portable_measurement": self.measurement.decode("utf-8"),
                "portable_measurement_sha256": digest(self.measurement),
            },
        }
        result.update(overrides)
        return result

    def write_package_result(self, **overrides: object) -> None:
        (self.evidence / "package-result.json").write_bytes(canonical(self.result(**overrides)))

    def add_lock(self, name: str = LOCK_NAME, raw: bytes = b"") -> Path:
        path = self.source / name
        path.write_bytes(raw)
        return path


class StageNativeOwnerPayloadTests(unittest.TestCase):
    def fixture(self) -> Fixture:
        temporary = tempfile.TemporaryDirectory(prefix="aros-native-owner-payload-test-")
        self.addCleanup(temporary.cleanup)
        return Fixture(Path(temporary.name).resolve())

    def rejects_before_output(self, fixture: Fixture) -> None:
        with self.assertRaises(stager.StageError):
            stager.stage(fixture.source, fixture.output)
        self.assertFalse(fixture.output.exists(), "preflight rejection created staged output")

    def test_stages_exact_ten_files_without_lockfiles(self) -> None:
        fixture = self.fixture()
        result = stager.stage(fixture.source, fixture.output)
        self.assertEqual(result["schema"], "aros-native-owner-payload-v2")
        self.assertEqual(result["assurance"], "staging-byte-consistency-only")
        self.assertEqual(set(result["files"]), native.EVIDENCE_NAMES | {
            f"package/{ARCHIVE_NAME}", f"package/{ARCHIVE_NAME}.manifest.json",
            f"package/{ARCHIVE_NAME}.sha256", f"package/{ARCHIVE_NAME}.spdx.json",
        })
        self.assertEqual({entry.name for entry in fixture.output.iterdir()}, {"evidence", "package"})
        self.assertEqual(stat.S_IMODE(fixture.output.stat().st_mode), 0o700)
        for relative in result["files"]:
            staged = fixture.output / relative
            source = fixture.source / relative
            self.assertEqual(staged.read_bytes(), source.read_bytes())
            self.assertEqual(stat.S_IMODE(staged.stat().st_mode), 0o600)

    def test_valid_persistent_root_locks_are_unchanged_and_not_copied(self) -> None:
        fixture = self.fixture()
        lock_a = fixture.add_lock()
        lock_b = fixture.add_lock(".aros-lock-0123456789abcdef-0000000000000000")
        before = {path.name: (path.read_bytes(), stager._fingerprint(path.stat()))
                  for path in (lock_a, lock_b)}
        result = stager.stage(fixture.source, fixture.output)
        self.assertEqual(len(result["files"]), 10)
        self.assertEqual({entry.name for entry in fixture.output.iterdir()}, {"evidence", "package"})
        for path in (lock_a, lock_b):
            self.assertEqual((path.read_bytes(), stager._fingerprint(path.stat())), before[path.name])

    def test_native_cli_returns_staging_only_json(self) -> None:
        fixture = self.fixture()
        result = subprocess.run(
            [sys.executable, "-B", str(SCRIPT), "--source-dir", str(fixture.source),
             "--output-dir", str(fixture.output)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        response = json.loads(result.stdout)
        self.assertEqual(response["assurance"], "staging-byte-consistency-only")
        self.assertEqual(len(response["files"]), 10)

    def test_unknown_and_malformed_root_entries_are_rejected(self) -> None:
        fixture = self.fixture()
        (fixture.source / "unexpected").write_bytes(b"not part of the closure")
        self.rejects_before_output(fixture)

        fixture = self.fixture()
        fixture.add_lock(".aros-lock-not-canonical-0000000000000000")
        self.rejects_before_output(fixture)

        fixture = self.fixture()
        (fixture.source / "other-directory").mkdir()
        self.rejects_before_output(fixture)

    def test_nonzero_symlinked_and_hardlinked_advisory_locks_are_rejected(self) -> None:
        fixture = self.fixture()
        fixture.add_lock(raw=b"not empty")
        self.rejects_before_output(fixture)

        fixture = self.fixture()
        lock = fixture.source / LOCK_NAME
        lock.symlink_to(fixture.source / "evidence/package-result.json")
        self.rejects_before_output(fixture)

        fixture = self.fixture()
        lock = fixture.add_lock()
        os.link(lock, fixture.root / "lock-hardlink")
        self.rejects_before_output(fixture)

    def test_missing_and_extra_evidence_or_package_members_are_rejected(self) -> None:
        fixture = self.fixture()
        (fixture.evidence / "build-result.json").unlink()
        self.rejects_before_output(fixture)

        fixture = self.fixture()
        (fixture.evidence / "extra.bin").write_bytes(b"extra")
        self.rejects_before_output(fixture)

        fixture = self.fixture()
        (fixture.package / f"{ARCHIVE_NAME}.spdx.json").unlink()
        self.rejects_before_output(fixture)

        fixture = self.fixture()
        (fixture.package / "second.tar.xz").write_bytes(b"second archive")
        self.rejects_before_output(fixture)

    def test_linked_and_hardlinked_payload_files_are_rejected(self) -> None:
        fixture = self.fixture()
        source = fixture.evidence / "build-result.json"
        external = fixture.root / "external-evidence"
        external.write_bytes(source.read_bytes())
        source.unlink()
        source.symlink_to(external)
        self.rejects_before_output(fixture)

        fixture = self.fixture()
        source = fixture.package / f"{ARCHIVE_NAME}.manifest.json"
        os.link(source, fixture.root / "manifest-hardlink")
        self.rejects_before_output(fixture)

    def test_package_result_requires_schema_operation_and_duplicate_free_json(self) -> None:
        for raw in (
            b"not JSON\n",
            b'{"schema":"aros-toolchain-producer-stage-v1","schema":"duplicate"}\n',
        ):
            fixture = self.fixture()
            (fixture.evidence / "package-result.json").write_bytes(raw)
            self.rejects_before_output(fixture)

        fixture = self.fixture()
        fixture.write_package_result(schema="unexpected-schema")
        self.rejects_before_output(fixture)
        fixture = self.fixture()
        fixture.write_package_result(operation="verify-package")
        self.rejects_before_output(fixture)

    def test_package_result_binds_original_directory_archive_and_sidecar_paths(self) -> None:
        for key, wrong in (
            ("package_dir", "/tmp/other/package"),
            ("archive", "/tmp/other/archive.tar.xz"),
            ("manifest", "/tmp/other/manifest.json"),
            ("checksum", "/tmp/other/archive.sha256"),
            ("sbom", "/tmp/other/archive.spdx.json"),
        ):
            with self.subTest(key=key):
                fixture = self.fixture()
                fixture.write_package_result(**{key: wrong})
                self.rejects_before_output(fixture)

    def test_package_result_archive_digest_size_and_measurement_are_joined(self) -> None:
        fixture = self.fixture()
        fixture.write_package_result(sha256="0" * 64)
        self.rejects_before_output(fixture)

        fixture = self.fixture()
        fixture.write_package_result(size=len(fixture.archive) + 1)
        self.rejects_before_output(fixture)

        fixture = self.fixture()
        fixture.write_package_result(finished_candidate={
            "portable_measurement": "{}\n",
            "portable_measurement_sha256": digest(b"{}\n"),
        })
        self.rejects_before_output(fixture)

        fixture = self.fixture()
        (fixture.evidence / "measurement.json").write_bytes(b"corrupted measurement\n")
        self.rejects_before_output(fixture)

    def test_oversized_package_result_is_rejected(self) -> None:
        fixture = self.fixture()
        (fixture.evidence / "package-result.json").write_bytes(b" " * (stager.MAX_METADATA + 1))
        self.rejects_before_output(fixture)

    def test_wrong_archive_name_closure_is_rejected(self) -> None:
        fixture = self.fixture()
        archive = fixture.package / ARCHIVE_NAME
        renamed = fixture.package / "other.tar.xz"
        archive.rename(renamed)
        fixture.write_package_result(
            archive=str(renamed), manifest=str(renamed) + ".manifest.json",
            checksum=str(renamed) + ".sha256", sbom=str(renamed) + ".spdx.json",
        )
        self.rejects_before_output(fixture)

    def test_occupied_output_sentinel_is_preserved(self) -> None:
        fixture = self.fixture()
        fixture.output.mkdir()
        sentinel = fixture.output / "keep.txt"
        sentinel.write_bytes(b"caller data\n")
        with self.assertRaises(stager.StageError):
            stager.stage(fixture.source, fixture.output)
        self.assertEqual(sentinel.read_bytes(), b"caller data\n")
        self.assertEqual({entry.name for entry in fixture.output.iterdir()}, {"keep.txt"})

    def test_corrupted_staging_copy_is_rejected_on_readback(self) -> None:
        fixture = self.fixture()
        original = stager._STAGE._copy_source

        def corrupt_copy(source: Path, destination: Path, expected: dict, limit: int) -> dict:
            result = original(source, destination, expected, limit)
            if destination.name == "build-result.json":
                destination.write_bytes(destination.read_bytes() + b"corruption")
            return result

        with mock.patch.object(stager._STAGE, "_copy_source", side_effect=corrupt_copy):
            with self.assertRaises(stager.StageError):
                stager.stage(fixture.source, fixture.output)

    def test_source_change_during_copy_is_rejected_after_copy(self) -> None:
        fixture = self.fixture()
        original = stager._STAGE._copy_source
        changed = False

        def mutate_source(source: Path, destination: Path, expected: dict, limit: int) -> dict:
            nonlocal changed
            result = original(source, destination, expected, limit)
            if not changed:
                changed = True
                victim = fixture.evidence / "build-result.json"
                victim.write_bytes(victim.read_bytes() + b"changed during copy\n")
            return result

        with mock.patch.object(stager._STAGE, "_copy_source", side_effect=mutate_source):
            with self.assertRaises(stager.StageError):
                stager.stage(fixture.source, fixture.output)

    def test_advisory_lock_identity_change_during_copy_is_rejected(self) -> None:
        fixture = self.fixture()
        lock = fixture.add_lock()
        os.chmod(lock, 0o600)
        original = stager._STAGE._copy_source
        changed = False

        def mutate_lock(source: Path, destination: Path, expected: dict, limit: int) -> dict:
            nonlocal changed
            result = original(source, destination, expected, limit)
            if not changed:
                changed = True
                os.chmod(lock, 0o640)
            return result

        with mock.patch.object(stager._STAGE, "_copy_source", side_effect=mutate_lock):
            with self.assertRaises(stager.StageError):
                stager.stage(fixture.source, fixture.output)

    def test_source_directory_identity_change_during_copy_is_rejected(self) -> None:
        fixture = self.fixture()
        original = stager._STAGE._copy_source
        changed = False

        def mutate_directory(source: Path, destination: Path, expected: dict, limit: int) -> dict:
            nonlocal changed
            result = original(source, destination, expected, limit)
            if not changed:
                changed = True
                os.chmod(fixture.evidence, 0o700)
            return result

        with mock.patch.object(stager._STAGE, "_copy_source", side_effect=mutate_directory):
            with self.assertRaises(stager.StageError):
                stager.stage(fixture.source, fixture.output)


if __name__ == "__main__":
    unittest.main()
