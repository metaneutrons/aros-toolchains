#!/usr/bin/env python3
"""Focused offline tests for the inactive start transport sealer."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock


SOURCE_ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = SOURCE_ROOT / "scripts/toolchain/seal-compiler-sdk-start-v2.py"
SPEC = importlib.util.spec_from_file_location("seal_compiler_sdk_start_v2", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
sealer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sealer)
START_TEST_MODULE_PATH = SOURCE_ROOT / "scripts/toolchain/tests/test-compiler-sdk-release-start-v2.py"
START_TEST_SPEC = importlib.util.spec_from_file_location(
    "compiler_sdk_release_start_fixtures_for_sealer", START_TEST_MODULE_PATH)
assert START_TEST_SPEC is not None and START_TEST_SPEC.loader is not None
start_tests = importlib.util.module_from_spec(START_TEST_SPEC)
START_TEST_SPEC.loader.exec_module(start_tests)
start_reader = start_tests.start

RECORD_BYTES = b'{"schema":"synthetic-start-record-v2","fixture":true}\n'
BUNDLE_BYTES = b'{"mediaType":"application/vnd.dev.sigstore.bundle+json;version=0.1"}\n'
ERRORS = (sealer.SealError, sealer.RECORD.AdapterError,
          sealer.ADMISSION.AdmissionError, OSError)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


class SealFixture:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="start-transport-sealer.")
        self.root = Path(self.temporary.name).resolve()
        self.source = self.root / "source"
        self.source.mkdir(mode=0o700)
        self.record = self.source / sealer.RECORD_BASENAME
        self.bundle = self.source / "signature-input.json"
        self.record.write_bytes(RECORD_BYTES)
        self.bundle.write_bytes(BUNDLE_BYTES)
        self.output = self.root / "retained"

    def close(self) -> None:
        self.temporary.cleanup()

    def seal(self, *, record: Path | None = None, bundle: Path | None = None,
             expected: str | None = None, output: Path | None = None) -> dict[str, str]:
        return sealer.seal_start_transport(
            record or self.record,
            bundle or self.bundle,
            expected if expected is not None else sha256(RECORD_BYTES),
            output or self.output,
        )


class SealStartTransportTests(unittest.TestCase):
    def fixture(self) -> SealFixture:
        value = SealFixture()
        self.addCleanup(value.close)
        return value

    def assert_rejected(self, fixture: SealFixture, **kwargs) -> Exception:
        with self.assertRaises(ERRORS) as raised:
            fixture.seal(**kwargs)
        return raised.exception

    def test_copies_exact_bytes_to_fixed_subject_names_and_preserves_sources(self) -> None:
        fixture = self.fixture()
        record_identity = (fixture.record.stat().st_dev, fixture.record.stat().st_ino)
        bundle_identity = (fixture.bundle.stat().st_dev, fixture.bundle.stat().st_ino)

        result = fixture.seal()

        retained_record = fixture.output / sealer.RECORD_BASENAME
        retained_bundle = fixture.output / sealer.BUNDLE_BASENAME
        self.assertEqual(result, {
            "record_path": str(retained_record),
            "bundle_path": str(retained_bundle),
            "record_sha256": sha256(RECORD_BYTES),
            "bundle_sha256": sha256(BUNDLE_BYTES),
        })
        self.assertEqual(retained_record.read_bytes(), RECORD_BYTES)
        self.assertEqual(retained_bundle.read_bytes(), BUNDLE_BYTES)
        self.assertEqual(fixture.record.read_bytes(), RECORD_BYTES)
        self.assertEqual(fixture.bundle.read_bytes(), BUNDLE_BYTES)
        self.assertEqual((fixture.record.stat().st_dev, fixture.record.stat().st_ino), record_identity)
        self.assertEqual((fixture.bundle.stat().st_dev, fixture.bundle.stat().st_ino), bundle_identity)
        self.assertEqual(stat.S_IMODE(fixture.output.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(retained_record.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(retained_bundle.stat().st_mode), 0o600)
        self.assertNotEqual(retained_record.stat().st_ino, fixture.record.stat().st_ino)
        self.assertNotEqual(retained_bundle.stat().st_ino, fixture.bundle.stat().st_ino)

    def test_private_output_parent_is_accepted_and_shared_parent_is_rejected_early(self) -> None:
        private = self.fixture()
        self.assertEqual(stat.S_IMODE(private.root.stat().st_mode) & 0o077, 0)
        private.seal()
        self.assertTrue(private.output.is_dir())

        shared = self.fixture()
        shared.root.chmod(0o750)
        with self.assertRaisesRegex(sealer.SealError, "private output parent grants group or other access"):
            shared.seal()
        self.assertFalse(shared.output.exists())
        self.assertEqual(shared.record.read_bytes(), RECORD_BYTES)
        self.assertEqual(shared.bundle.read_bytes(), BUNDLE_BYTES)

    def test_limits_and_retained_subject_basename_match_the_existing_reader(self) -> None:
        self.assertEqual(sealer.MAX_RECORD, start_reader.MAX_RECORD)
        self.assertEqual(sealer.MAX_BUNDLE, start_reader.MAX_BUNDLE)
        self.assertEqual(sealer.RECORD_BASENAME, "compiler-sdk-release-start-v2.json")
        with tempfile.TemporaryDirectory(prefix="start-transport-reader-compat.") as directory:
            root = Path(directory).resolve()
            reader_fixture = start_tests.StartFixture(root)
            selected_record = root / sealer.RECORD_BASENAME
            os.replace(reader_fixture.record_path, selected_record)
            reader_fixture.record_path = selected_record
            retained = sealer.seal_start_transport(
                selected_record, reader_fixture.bundle_path,
                sha256(reader_fixture.record_bytes), root / "retained",
            )
            reader_fixture.record_path = Path(retained["record_path"])
            reader_fixture.bundle_path = Path(retained["bundle_path"])
            subject_name = Path(retained["record_path"]).name
            reader_fixture.signature = start_tests.attestation(
                reader_fixture.record_bytes, subject_name=subject_name)

            self.assertEqual(subject_name, sealer.RECORD_BASENAME)
            self.assertEqual(reader_fixture.verify(), reader_fixture.record)

    def test_wrong_expected_digest_and_wrong_record_basename_create_no_output(self) -> None:
        fixture = self.fixture()
        self.assert_rejected(fixture, expected="0" * 64)
        self.assertFalse(fixture.output.exists())

        wrong_name = fixture.source / "other-start.json"
        wrong_name.write_bytes(RECORD_BYTES)
        self.assert_rejected(fixture, record=wrong_name)
        self.assertFalse(fixture.output.exists())

    def test_invalid_linked_inputs_and_linked_parents_are_rejected(self) -> None:
        fixture = self.fixture()
        saved_record = fixture.root / "saved-original-record"
        os.replace(fixture.record, saved_record)
        fixture.record.symlink_to(saved_record)
        with self.assertRaisesRegex(
                sealer.RECORD.AdapterError,
                "signed start record path has a symlink or noncanonical component"):
            fixture.seal()
        self.assertTrue(fixture.record.is_symlink())
        self.assertEqual(saved_record.read_bytes(), RECORD_BYTES)
        self.assertFalse(fixture.output.exists())

        fixture = self.fixture()
        hardlink = fixture.source / "record-hardlink.json"
        os.link(fixture.record, hardlink)
        with self.assertRaisesRegex(
                sealer.RECORD.AdapterError,
                "signed start record is not an owned, singly linked regular file"):
            fixture.seal()
        self.assertFalse(fixture.output.exists())
        self.assertEqual(fixture.record.read_bytes(), RECORD_BYTES)
        hardlink.unlink()

        fixture = self.fixture()
        saved_bundle = fixture.root / "saved-original-bundle"
        os.replace(fixture.bundle, saved_bundle)
        fixture.bundle.symlink_to(saved_bundle)
        with self.assertRaisesRegex(
                sealer.RECORD.AdapterError,
                "start signature bundle path has a symlink or noncanonical component"):
            fixture.seal()
        self.assertTrue(fixture.bundle.is_symlink())
        self.assertEqual(saved_bundle.read_bytes(), BUNDLE_BYTES)
        self.assertEqual(fixture.record.read_bytes(), RECORD_BYTES)
        self.assertFalse(fixture.output.exists())

        fixture = self.fixture()
        bundle_hardlink = fixture.source / "bundle-hardlink.json"
        os.link(fixture.bundle, bundle_hardlink)
        with self.assertRaisesRegex(
                sealer.RECORD.AdapterError,
                "start signature bundle is not an owned, singly linked regular file"):
            fixture.seal()
        self.assertEqual(fixture.bundle.read_bytes(), BUNDLE_BYTES)
        self.assertFalse(fixture.output.exists())
        bundle_hardlink.unlink()

        fixture = self.fixture()
        real_parent = fixture.root / "real-source"
        real_parent.mkdir()
        (real_parent / sealer.RECORD_BASENAME).write_bytes(RECORD_BYTES)
        (real_parent / "signature-input.json").write_bytes(BUNDLE_BYTES)
        linked_parent = fixture.root / "linked-source"
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        self.assert_rejected(
            fixture,
            record=linked_parent / sealer.RECORD_BASENAME,
            bundle=linked_parent / "signature-input.json",
        )
        self.assertFalse(fixture.output.exists())

        linked_output_parent = fixture.root / "linked-output-parent"
        linked_output_parent.symlink_to(fixture.root, target_is_directory=True)
        linked_output = linked_output_parent / "new-retained"
        self.assert_rejected(fixture, output=linked_output)
        self.assertFalse((fixture.root / "new-retained").exists())

    def test_empty_and_oversized_record_or_bundle_are_rejected_before_output(self) -> None:
        for label in ("empty-record", "empty-bundle", "large-record", "large-bundle"):
            with self.subTest(label=label):
                fixture = self.fixture()
                if label == "empty-record":
                    fixture.record.write_bytes(b"")
                elif label == "empty-bundle":
                    fixture.bundle.write_bytes(b"")
                elif label == "large-record":
                    fixture.record.write_bytes(b"r" * (sealer.MAX_RECORD + 1))
                else:
                    fixture.bundle.write_bytes(b"b" * (sealer.MAX_BUNDLE + 1))
                self.assert_rejected(fixture)
                self.assertFalse(fixture.output.exists())

    def test_occupied_output_directory_file_and_symlink_are_preserved(self) -> None:
        for label in ("directory", "file", "symlink"):
            with self.subTest(label=label):
                fixture = self.fixture()
                if label == "directory":
                    fixture.output.mkdir()
                    sentinel = fixture.output / "keep.txt"
                    sentinel.write_bytes(b"existing output")
                    before = sentinel.read_bytes()
                elif label == "file":
                    fixture.output.write_bytes(b"existing output file")
                    before = fixture.output.read_bytes()
                else:
                    target = fixture.root / "output-target"
                    target.mkdir()
                    sentinel = target / "keep.txt"
                    sentinel.write_bytes(b"existing linked output")
                    fixture.output.symlink_to(target, target_is_directory=True)
                    before = sentinel.read_bytes()
                self.assert_rejected(fixture)
                if label == "directory":
                    self.assertEqual(sentinel.read_bytes(), before)
                    self.assertEqual({item.name for item in fixture.output.iterdir()}, {"keep.txt"})
                elif label == "file":
                    self.assertEqual(fixture.output.read_bytes(), before)
                else:
                    self.assertTrue(fixture.output.is_symlink())
                    self.assertEqual(sentinel.read_bytes(), before)

    def test_source_replacement_during_capture_is_detected_before_output_creation(self) -> None:
        fixture = self.fixture()
        original_read_owned = sealer.RECORD._read_owned
        swapped = False

        def read_owned(path: Path, limit: int, label: str, **kwargs):
            nonlocal swapped
            result = original_read_owned(path, limit, label, **kwargs)
            if path == fixture.record and not swapped:
                swapped = True
                saved = fixture.root / "captured-original-record"
                os.replace(fixture.record, saved)
                fixture.record.write_bytes(b"replacement record bytes\n")
                self.assertEqual(saved.read_bytes(), RECORD_BYTES)
            return result

        with mock.patch.object(sealer.RECORD, "_read_owned", side_effect=read_owned):
            self.assert_rejected(fixture)
        self.assertTrue(swapped)
        self.assertFalse(fixture.output.exists())

    def test_source_replacement_during_write_is_detected_and_partial_output_is_unusable(self) -> None:
        fixture = self.fixture()
        original_write = sealer._write_retained_file
        changed = False

        def write_then_replace(directory_fd: int, name: str, raw: bytes, label: str):
            nonlocal changed
            result = original_write(directory_fd, name, raw, label)
            if not changed:
                changed = True
                replacement = fixture.root / "replacement-bundle"
                replacement.write_bytes(b"changed while retaining\n")
                os.replace(replacement, fixture.bundle)
            return result

        with mock.patch.object(sealer, "_write_retained_file", side_effect=write_then_replace):
            self.assert_rejected(fixture)
        self.assertTrue(changed)
        self.assertTrue(fixture.output.is_dir())
        self.assertEqual((fixture.output / sealer.RECORD_BASENAME).read_bytes(), RECORD_BYTES)
        self.assertEqual((fixture.output / sealer.BUNDLE_BASENAME).read_bytes(), BUNDLE_BYTES)
        self.assertEqual(fixture.bundle.read_bytes(), b"changed while retaining\n")

    def test_output_content_tampering_is_detected_at_readback(self) -> None:
        fixture = self.fixture()
        original_read_owned = sealer.RECORD._read_owned
        tampered = False
        retained_record = fixture.output / sealer.RECORD_BASENAME

        def read_owned(path: Path, limit: int, label: str, **kwargs):
            nonlocal tampered
            if path == retained_record and not tampered:
                tampered = True
                path.write_bytes(b"tampered output bytes\n")
            return original_read_owned(path, limit, label, **kwargs)

        with mock.patch.object(sealer.RECORD, "_read_owned", side_effect=read_owned):
            self.assert_rejected(fixture)
        self.assertTrue(tampered)
        self.assertTrue(fixture.output.is_dir())
        self.assertEqual(retained_record.read_bytes(), b"tampered output bytes\n")
        self.assertEqual(fixture.bundle.read_bytes(), BUNDLE_BYTES)

    def test_regular_output_replacement_after_read_capture_is_detected(self) -> None:
        fixture = self.fixture()
        original_read_owned = sealer.RECORD._read_owned
        swapped = False
        retained_record = fixture.output / sealer.RECORD_BASENAME

        def read_then_swap(path: Path, limit: int, label: str, **kwargs):
            nonlocal swapped
            result = original_read_owned(path, limit, label, **kwargs)
            if path == retained_record and not swapped:
                swapped = True
                replacement = fixture.root / "replacement-retained-record"
                replacement.write_bytes(b"different regular 0600 file\n")
                replacement.chmod(0o600)
                os.replace(replacement, retained_record)
            return result

        with mock.patch.object(sealer.RECORD, "_read_owned", side_effect=read_then_swap):
            with self.assertRaisesRegex(
                    sealer.SealError,
                    "retained signed start record output identity or permissions changed after readback"):
                fixture.seal()
        self.assertTrue(swapped)
        self.assertEqual(retained_record.read_bytes(), b"different regular 0600 file\n")
        self.assertEqual(stat.S_IMODE(retained_record.stat().st_mode), 0o600)
        self.assertEqual(fixture.record.read_bytes(), RECORD_BYTES)
        self.assertEqual(fixture.bundle.read_bytes(), BUNDLE_BYTES)

    def test_replaced_output_directory_is_rejected_even_if_replacement_has_matching_bytes(self) -> None:
        fixture = self.fixture()
        original_write = sealer._write_retained_file
        replaced = False
        displaced = fixture.root / "displaced-retained"

        def write_then_replace_directory(directory_fd: int, name: str, raw: bytes, label: str):
            nonlocal replaced
            result = original_write(directory_fd, name, raw, label)
            if not replaced:
                replaced = True
                os.rename(fixture.output, displaced)
                fixture.output.mkdir(mode=0o700)
                copied = fixture.output / sealer.RECORD_BASENAME
                copied.write_bytes(RECORD_BYTES)
                copied.chmod(0o600)
            return result

        with mock.patch.object(sealer, "_write_retained_file", side_effect=write_then_replace_directory):
            self.assert_rejected(fixture)
        self.assertTrue(replaced)
        self.assertTrue(fixture.output.is_dir())
        self.assertEqual((fixture.output / sealer.RECORD_BASENAME).read_bytes(), RECORD_BYTES)
        self.assertTrue((displaced / sealer.RECORD_BASENAME).is_file())

    def test_substituted_directory_before_open_is_not_chmodded_or_written(self) -> None:
        fixture = self.fixture()
        original_open = os.open
        substituted = False
        displaced = fixture.root / "created-output-directory"

        def open_after_substitution(path, *args, **kwargs):
            nonlocal substituted
            if os.fspath(path) == fixture.output.name and kwargs.get("dir_fd") is not None \
                    and not substituted:
                substituted = True
                os.rename(fixture.output, displaced)
                fixture.output.mkdir(mode=0o700)
                fixture.output.chmod(0o755)
            return original_open(path, *args, **kwargs)

        with mock.patch.object(sealer.os, "open", side_effect=open_after_substitution):
            self.assert_rejected(fixture)
        self.assertTrue(substituted)
        self.assertTrue(fixture.output.is_dir())
        self.assertEqual(stat.S_IMODE(fixture.output.stat().st_mode), 0o755)
        self.assertEqual(list(fixture.output.iterdir()), [])
        self.assertTrue(displaced.is_dir())
        self.assertEqual(stat.S_IMODE(displaced.stat().st_mode), 0o700)
        self.assertEqual(list(displaced.iterdir()), [])


class SealStartTransportCliTests(unittest.TestCase):
    def fixture(self) -> SealFixture:
        value = SealFixture()
        self.addCleanup(value.close)
        return value

    @staticmethod
    def arguments(fixture: SealFixture) -> list[str]:
        return [
            "--record", str(fixture.record),
            "--bundle", str(fixture.bundle),
            "--expected-record-sha256", sha256(RECORD_BYTES),
            "--output-directory", str(fixture.output),
        ]

    def test_cli_requires_full_option_names_and_reports_generic_failure(self) -> None:
        fixture = self.fixture()
        abbreviated_args = self.arguments(fixture)
        abbreviated_args[0:0] = ["--rec", str(fixture.record)]
        abbreviated_stderr = io.StringIO()
        with redirect_stderr(abbreviated_stderr), self.assertRaises(SystemExit) as abbreviated:
            sealer.main(abbreviated_args)
        self.assertEqual(abbreviated.exception.code, 2)
        self.assertIn("unrecognized arguments: --rec", abbreviated_stderr.getvalue())
        with self.assertRaises(SystemExit) as missing:
            sealer.main([])
        self.assertEqual(missing.exception.code, 2)

        arguments = self.arguments(fixture)
        arguments[arguments.index("--expected-record-sha256") + 1] = "not-a-digest"
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = sealer.main(arguments)
        self.assertEqual(result, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(),
                         "start transport sealing failed; any created output is unusable and must not be retried\n")
        self.assertFalse(fixture.output.exists())

    def test_cli_success_describes_copy_without_claiming_authentication(self) -> None:
        fixture = self.fixture()
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = sealer.main(self.arguments(fixture))
        self.assertEqual(result, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertIn("no bundle verification or start authentication performed", stdout.getvalue())
        self.assertTrue(fixture.output.is_dir())


if __name__ == "__main__":
    unittest.main(verbosity=2)
