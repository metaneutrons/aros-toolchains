#!/usr/bin/env python3
"""Offline tests for inactive authenticated-claim retention CLI behavior."""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock


SOURCE_ROOT = Path(__file__).resolve().parents[3]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


boundary_tests = load_module(
    "authenticated_claim_cli_boundary_fixtures_v2",
    SOURCE_ROOT / "scripts/toolchain/tests/test-compiler-sdk-authenticated-claim-v2.py",
)
cli = load_module(
    "authenticated_claim_cli_v2",
    SOURCE_ROOT / "scripts/toolchain/compiler-sdk-authenticated-claim-v2.py",
)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


class CliHarness:
    def __init__(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.add_cleanup = self.temporary.cleanup
        self.root = Path(self.temporary.name).resolve()
        self.boundary = boundary_tests.BoundaryHarness(self.root)
        self.context_path = self.root / "source-context.json"
        self.context_raw = (cli.START.ADMISSION.canonical_json(self.boundary.source) + "\n").encode()
        self.context_path.write_bytes(self.context_raw)
        self.claim_output = self.root / cli.CLAIM.CLAIM_NAME
        self.receipt_output = self.root / "retained-receipt.json"

    def argv(self, **overrides: object) -> list[str]:
        values = {
            "record": self.boundary.fixture.record_path,
            "bundle": self.boundary.fixture.bundle_path,
            "source-context": self.context_path,
            "expected-record-sha256": sha256(self.boundary.selected_record),
            "expected-bundle-sha256": sha256(self.boundary.selected_bundle),
            "runtime-lock": self.boundary.fixture.runtime_lock_path,
            "runtime-directory": self.boundary.fixture.runtime_directory,
            "runtime-interface": self.boundary.fixture.runtime_interface_path,
            "runtime-host": self.boundary.fixture.runtime_host,
            "claim-output": self.claim_output,
            "output": self.receipt_output,
        }
        values.update(overrides)
        result = []
        for key, value in values.items():
            result.extend((f"--{key}", str(value)))
        return result

    def expected_receipt_bytes(self) -> bytes:
        receipt = {
            "schema": "aros-toolchains-authenticated-claim-upload-v2",
            "assurance": "authenticated-claim-upload-only-not-native-dispatch",
            "dispatcher": self.boundary.identity,
            "claim": {
                "id": 70001,
                "name": cli.CLAIM.CLAIM_NAME,
                "size": len(self.boundary.claim_raw),
                "sha256": sha256(self.boundary.claim_raw),
            },
        }
        return (cli.START.ADMISSION.canonical_json(receipt) + "\n").encode("ascii")

    @contextlib.contextmanager
    def patched_boundaries(self):
        harness = self.boundary
        with mock.patch.object(cli.AUTH, "authenticate_dispatcher",
                               side_effect=harness.authenticate) as auth_mock, \
                mock.patch.object(cli.START, "verify_start",
                                  side_effect=harness.verify_start) as verify_mock, \
                mock.patch.object(cli.CLAIM, "claim_bytes",
                                  side_effect=harness.encode_claim) as claim_mock, \
                mock.patch.object(cli.UPLOAD, "upload_claim_once",
                                  side_effect=harness.upload_once) as upload_mock, \
                mock.patch.object(cli.START.ADMISSION, "api",
                                  side_effect=AssertionError("unexpected provider API")) as api_mock, \
                mock.patch.object(cli.START.ADMISSION, "git",
                                  side_effect=AssertionError("unexpected provider Git")) as git_mock, \
                mock.patch.object(cli.START, "bounded_gh",
                                  side_effect=AssertionError("unexpected signature command")) as signature_mock, \
                mock.patch.object(cli.UPLOAD, "gh_response",
                                  side_effect=AssertionError("unexpected upload transport")) as transport_mock:
            yield (auth_mock, verify_mock, claim_mock, upload_mock,
                   api_mock, git_mock, signature_mock, transport_mock)

    def invoke(self, argv: list[str] | None = None) -> tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, {"GH_HOST": "github.com", "GH_TOKEN": "fixture-job-token"}), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = cli.main(self.argv() if argv is None else argv)
        return result, stdout.getvalue(), stderr.getvalue()

    def assert_no_outputs(self, *, allow_claim: bool = False,
                          allow_receipt: bool = False) -> None:
        if not allow_claim:
            self.assertFalse(self.claim_output.exists())
        if not allow_receipt:
            self.assertFalse(self.receipt_output.exists())

    def assertFalse(self, condition: bool) -> None:
        if condition:
            raise AssertionError("unexpected output file")


class AuthenticatedClaimCliTests(unittest.TestCase):
    def harness(self) -> CliHarness:
        result = CliHarness()
        self.addCleanup(result.add_cleanup)
        return result

    def test_success_retains_exact_uploaded_subject_and_canonical_receipt(self) -> None:
        harness = self.harness()
        with harness.patched_boundaries() as mocks:
            auth_mock, verify_mock, claim_mock, upload_mock = mocks[:4]
            code, stdout, stderr = harness.invoke()

        self.assertEqual(code, 0, stderr)
        self.assertEqual(stderr, "")
        self.assertIn("no dispatch or activation", stdout)
        self.assertEqual(auth_mock.call_count, 2)
        self.assertEqual(verify_mock.call_count, 2)
        claim_mock.assert_called_once()
        upload_mock.assert_called_once()
        self.assertEqual(harness.claim_output.read_bytes(), harness.boundary.claim_raw)
        self.assertEqual(harness.receipt_output.read_bytes(), harness.expected_receipt_bytes())
        self.assertEqual(stat.S_IMODE(harness.claim_output.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(harness.receipt_output.stat().st_mode), 0o600)
        self.assertEqual(harness.boundary.upload_arguments[0], harness.claim_output.read_bytes())

    def _assert_preflight_rejected(self, harness: CliHarness, argv: list[str] | None = None,
                                   *, host: str = "github.com", token: str | None = "fixture-job-token",
                                   sentinel_path: Path | None = None,
                                   sentinel: bytes | None = None) -> None:
        environment = {"GH_HOST": host}
        if token is not None:
            environment["GH_TOKEN"] = token
        with mock.patch.dict(os.environ, environment):
            if token is None:
                os.environ.pop("GH_TOKEN", None)
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                with harness.patched_boundaries() as mocks:
                    code = cli.main(harness.argv() if argv is None else argv)
        self.assertEqual(code, 1)
        for provider_mock in mocks:
            provider_mock.assert_not_called()
        if sentinel_path is not None:
            self.assertEqual(sentinel_path.read_bytes(), sentinel)

    def test_pins_context_and_output_preflight_fail_without_provider_or_overwrite(self) -> None:
        cases = ("wrong record pin", "uppercase bundle pin", "duplicate context key",
                 "malformed context", "deep context", "oversized context",
                 "occupied claim output", "occupied receipt output", "aliased outputs",
                 "wrong claim basename", "broad output parent")
        for case in cases:
            with self.subTest(case=case):
                harness = self.harness()
                argv = harness.argv()
                sentinel_path = None
                sentinel = None
                if case == "wrong record pin":
                    argv = harness.argv(**{"expected-record-sha256": "0" * 64})
                elif case == "uppercase bundle pin":
                    argv = harness.argv(**{"expected-bundle-sha256": "A" * 64})
                elif case == "duplicate context key":
                    harness.context_path.write_bytes(b'{"repository":"one","repository":"two"}')
                elif case == "malformed context":
                    harness.context_path.write_bytes(b"{")
                elif case == "deep context":
                    harness.context_path.write_bytes(b"[" * 1500 + b"]" * 1500)
                elif case == "oversized context":
                    harness.context_path.write_bytes(b" " * (cli.START.MAX_RECORD + 1))
                elif case in ("occupied claim output", "occupied receipt output"):
                    sentinel = b"keep this existing file exactly\n"
                    sentinel_path = (harness.claim_output if case == "occupied claim output"
                                     else harness.receipt_output)
                    sentinel_path.write_bytes(sentinel)
                elif case == "aliased outputs":
                    alias = f"{harness.claim_output.parent}/./{harness.claim_output.name}"
                    argv = harness.argv(output=alias)
                elif case == "wrong claim basename":
                    argv = harness.argv(**{"claim-output": harness.root / "claim.json"})
                else:
                    harness.root.chmod(0o755)

                self._assert_preflight_rejected(
                    harness, argv, sentinel_path=sentinel_path, sentinel=sentinel)
                harness.assert_no_outputs(
                    allow_claim=sentinel_path == harness.claim_output,
                    allow_receipt=sentinel_path == harness.receipt_output)

    def test_host_and_job_token_are_required_before_provider(self) -> None:
        for host, token in (("api.github.com", "fixture-job-token"),
                            ("github.com", None), ("github.com", "")):
            with self.subTest(host=host, token="missing" if token is None else "present"):
                harness = self.harness()
                self._assert_preflight_rejected(harness, host=host, token=token)
                harness.assert_no_outputs()

    def test_argument_abbreviations_are_rejected_before_provider(self) -> None:
        harness = self.harness()
        argv = harness.argv()
        pin_selector = argv.index("--expected-record-sha256")
        argv[pin_selector] = "--expected-record-sh"
        with mock.patch.dict(os.environ, {"GH_HOST": "github.com", "GH_TOKEN": "fixture-job-token"}), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            with harness.patched_boundaries() as mocks:
                with self.assertRaises(SystemExit) as error:
                    cli.main(argv)
        self.assertEqual(error.exception.code, 2)
        for provider_mock in mocks:
            provider_mock.assert_not_called()
        harness.assert_no_outputs()

    def test_drift_after_upload_fails_before_any_local_output(self) -> None:
        for changed in ("record", "bundle", "context"):
            with self.subTest(changed=changed):
                harness = self.harness()
                original_upload = harness.boundary.upload_once

                def upload_then_change(*args, **kwargs):
                    asset = original_upload(*args, **kwargs)
                    path = {
                        "record": harness.boundary.fixture.record_path,
                        "bundle": harness.boundary.fixture.bundle_path,
                        "context": harness.context_path,
                    }[changed]
                    path.write_bytes(path.read_bytes() + b" ")
                    return asset

                with harness.patched_boundaries() as mocks:
                    upload_mock = mocks[3]
                    upload_mock.side_effect = upload_then_change
                    code, _, _ = harness.invoke()
                self.assertEqual(code, 1)
                upload_mock.assert_called_once()
                harness.assert_no_outputs()

    def test_claim_readback_tampering_fails_before_receipt_output(self) -> None:
        harness = self.harness()
        real_write = cli.START.ADMISSION._write_exclusive

        def write_then_tamper(path: Path, content: bytes) -> None:
            real_write(path, content)
            if path == harness.claim_output:
                path.write_bytes(content + b"tampered")

        with harness.patched_boundaries() as mocks, \
                mock.patch.object(cli.START.ADMISSION, "_write_exclusive",
                                  side_effect=write_then_tamper):
            upload_mock = mocks[3]
            code, _, _ = harness.invoke()
        self.assertEqual(code, 1)
        upload_mock.assert_called_once()
        self.assertEqual(harness.claim_output.read_bytes(), harness.boundary.claim_raw + b"tampered")
        self.assertFalse(harness.receipt_output.exists())

    def test_uncertain_upload_is_called_once_and_creates_no_output(self) -> None:
        harness = self.harness()
        with harness.patched_boundaries() as mocks:
            upload_mock = mocks[3]
            upload_mock.side_effect = cli.START.StartError("synthetic uncertain upload")
            code, _, _ = harness.invoke()
        self.assertEqual(code, 1)
        upload_mock.assert_called_once()
        harness.assert_no_outputs()

    def test_uploaded_metadata_must_match_retained_claim(self) -> None:
        harness = self.harness()
        original_upload = harness.boundary.upload_once

        def bad_metadata(*args, **kwargs):
            asset = original_upload(*args, **kwargs)
            asset["sha256"] = "0" * 64
            return asset

        with harness.patched_boundaries() as mocks:
            upload_mock = mocks[3]
            upload_mock.side_effect = bad_metadata
            code, _, _ = harness.invoke()
        self.assertEqual(code, 1)
        upload_mock.assert_called_once()
        harness.assert_no_outputs()

    def test_late_receipt_write_failure_preserves_partial_outputs(self) -> None:
        harness = self.harness()
        real_write = cli.START.ADMISSION._write_exclusive
        partial_receipt = b'{"schema":"aros-toolchains'

        def fail_receipt_after_partial_write(path: Path, content: bytes) -> None:
            if path == harness.receipt_output:
                real_write(path, partial_receipt)
                raise OSError("synthetic late receipt write failure")
            real_write(path, content)

        with harness.patched_boundaries() as mocks, \
                mock.patch.object(cli.START.ADMISSION, "_write_exclusive",
                                  side_effect=fail_receipt_after_partial_write):
            upload_mock = mocks[3]
            code, _, _ = harness.invoke()
        self.assertEqual(code, 1)
        upload_mock.assert_called_once()
        self.assertEqual(harness.claim_output.read_bytes(), harness.boundary.claim_raw)
        self.assertEqual(harness.receipt_output.read_bytes(), partial_receipt)

    def test_final_claim_recheck_detects_receipt_writer_mutation(self) -> None:
        harness = self.harness()
        real_write = cli.START.ADMISSION._write_exclusive

        def write_receipt_then_mutate_claim(path: Path, content: bytes) -> None:
            real_write(path, content)
            if path == harness.receipt_output:
                harness.claim_output.write_bytes(harness.claim_output.read_bytes() + b"mutated")

        with harness.patched_boundaries() as mocks, \
                mock.patch.object(cli.START.ADMISSION, "_write_exclusive",
                                  side_effect=write_receipt_then_mutate_claim):
            code, stdout, stderr = harness.invoke()

        self.assertEqual(code, 1)
        self.assertEqual(stdout, "")
        self.assertIn("retention failed", stderr)
        self.assertEqual(harness.claim_output.read_bytes(), harness.boundary.claim_raw + b"mutated")
        self.assertEqual(harness.receipt_output.read_bytes(), harness.expected_receipt_bytes())
        auth_mock, verify_mock, claim_mock, upload_mock = mocks[:4]
        self.assertEqual(auth_mock.call_count, 2)
        self.assertEqual(verify_mock.call_count, 2)
        claim_mock.assert_called_once()
        upload_mock.assert_called_once()
        for provider_mock in mocks[4:]:
            provider_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
