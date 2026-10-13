#!/usr/bin/env python3
"""Offline tests for the authenticated-start to one-claim-upload boundary.

Provider, signature and upload boundaries are deterministic mocks. These tests
exercise local ordering and byte-selection joins; they do not prove live
provider behavior, signature authenticity or production eligibility.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import tempfile
import unittest
from contextlib import contextmanager
from unittest import mock


SOURCE_ROOT = Path(__file__).resolve().parents[3]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


start_fixtures = load_module(
    "compiler_sdk_release_start_claim_fixture_v2",
    SOURCE_ROOT / "scripts/toolchain/tests/test-compiler-sdk-release-start-v2.py",
)
boundary = load_module(
    "compiler_sdk_authenticated_claim_v2",
    SOURCE_ROOT / "scripts/toolchain/compiler-sdk-authenticated-claim-v2.py",
)

AUTH = boundary.AUTH
START = boundary.START
UPLOAD = boundary.UPLOAD
CLAIM = boundary.CLAIM
FAILURES = (START.StartError, START.ADMISSION.AdmissionError, START.ORIGIN.OriginError,
            OSError, ValueError)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def dispatcher_identity(source: dict) -> dict:
    context = {
        "repository": source["repository"],
        "repository_id": source["repository_id"],
        "producer_commit": "9" * 40,
        "source_ref": start_fixtures.MAIN,
        "workflow": CLAIM.WORKFLOW,
        "run_id": source["run_id"] + 1,
        "run_attempt": 1,
    }
    return {
        "schema": AUTH.SCHEMA,
        "assurance": AUTH.ASSURANCE,
        "context": context,
        "job": {"id": start_fixtures.JOB_ID + 1,
                "check_run_id": start_fixtures.CHECK_RUN_ID + 1,
                "name": CLAIM.JOB},
        "event": "workflow_run",
        "trigger_context": copy.deepcopy(source),
    }


class BoundaryHarness:
    """Real bounded local bytes plus explicit mocks at external boundaries."""

    def __init__(self, root: Path):
        self.fixture = start_fixtures.StartFixture(root)
        self.source = copy.deepcopy(self.fixture.source)
        self.selected_record = self.fixture.record_bytes
        self.selected_bundle = self.fixture.bundle_bytes
        self.identity = dispatcher_identity(self.source)
        self.expected_candidate = {
            "tag": copy.deepcopy(self.fixture.record["tag"]),
            "draft": copy.deepcopy(self.fixture.record["draft"]),
        }
        self.observed_candidate = copy.deepcopy(self.expected_candidate)
        self.events: list[str] = []
        self.auth_calls = 0
        self.verify_calls = 0
        self.auth_failure_call: int | None = None
        self.verify_failure_call: int | None = None
        self.claim_failure = False
        self.identity_change_call: int | None = None
        self.source_mutation_auth_call: int | None = None
        self.source_mutation_verify_call: int | None = None
        self.candidate_mutation_verify_call: int | None = None
        self.bytes_mutation_verify_call: tuple[int, str] | None = None
        self.semantic_record_rewrite_on_auth = False
        self.changed_return_record_call: int | None = None
        self.source_mutation_after_claim = False
        self.claim_raw: bytes | None = None
        self.upload_arguments: tuple | None = None
        self.initial_source = copy.deepcopy(self.source)

    def _mutate_source(self, source: dict) -> None:
        source["producer_commit"] = "8" * 40

    def authenticate(self, source: dict) -> dict:
        self.auth_calls += 1
        call = self.auth_calls
        self.events.append(f"dispatcher-auth:{call}")
        if self.auth_failure_call == call:
            raise START.StartError("synthetic dispatcher authentication failure")
        if self.source_mutation_auth_call == call:
            self._mutate_source(source)
        if self.semantic_record_rewrite_on_auth and call == 1:
            # Same JSON value, different original bytes. The digest pins were
            # selected before dispatcher authentication and must reject this.
            parsed = json.loads(self.fixture.record_path.read_bytes())
            alternate = json.dumps(parsed, sort_keys=True, indent=2).encode("utf-8") + b"\n"
            if json.loads(alternate) != parsed or alternate == self.selected_record:
                raise AssertionError("semantic-byte fixture was not distinct and equivalent")
            self.fixture.record_path.write_bytes(alternate)
        if source != self.initial_source:
            raise START.StartError("source context changed before dispatcher recheck")
        identity = copy.deepcopy(self.identity)
        if self.identity_change_call == call:
            identity["context"]["run_id"] += 1
        return identity

    def verify_start(self, record_path: Path, bundle_path: Path, source: dict, **selection) -> dict:
        self.verify_calls += 1
        call = self.verify_calls
        self.events.append(f"start-verify:{call}")
        expected_selection = {
            "runtime_lock": self.fixture.runtime_lock_path,
            "runtime_directory": self.fixture.runtime_directory,
            "runtime_interface": self.fixture.runtime_interface_path,
            "runtime_host": self.fixture.runtime_host,
            "expected_record_sha256": sha256(self.selected_record),
            "expected_bundle_sha256": sha256(self.selected_bundle),
        }
        if (record_path != self.fixture.record_path or bundle_path != self.fixture.bundle_path
                or selection != expected_selection):
            raise AssertionError("start verifier did not receive exact paired pins and runtime selectors")
        if self.verify_failure_call == call:
            raise START.StartError("synthetic signed-start verification failure")

        raw = START.ADMISSION.read_regular_file(record_path, "mock selected start", START.MAX_RECORD)
        bundle = START.ADMISSION.read_regular_file(bundle_path, "mock selected bundle", START.MAX_BUNDLE)
        if sha256(raw) != selection["expected_record_sha256"]:
            raise START.StartError("selected start record differs from the exact digest pin")
        if sha256(bundle) != selection["expected_bundle_sha256"]:
            raise START.StartError("selected start bundle differs from the exact digest pin")

        parsed = START.ADMISSION.parse_json(raw, "mock selected start", maximum=START.MAX_RECORD)
        verified = START.validate_start(parsed, source)
        if self.observed_candidate != self.expected_candidate:
            raise START.StartError("mock provider candidate changed during start verification")

        if self.source_mutation_verify_call == call:
            self._mutate_source(source)
        if self.candidate_mutation_verify_call == call:
            self.observed_candidate["draft"]["id"] += 1
        if self.bytes_mutation_verify_call == (call, "record"):
            record_path.write_bytes(record_path.read_bytes() + b" ")
        elif self.bytes_mutation_verify_call == (call, "bundle"):
            bundle_path.write_bytes(bundle_path.read_bytes() + b" ")

        final_record = START.ADMISSION.read_regular_file(
            record_path, "mock selected start", START.MAX_RECORD)
        final_bundle = START.ADMISSION.read_regular_file(
            bundle_path, "mock selected bundle", START.MAX_BUNDLE)
        if final_record != raw or final_bundle != bundle:
            raise START.StartError("selected start bytes changed during verification")
        if source != self.initial_source:
            raise START.StartError("source context changed during start verification")
        if self.observed_candidate != self.expected_candidate:
            raise START.StartError("mock provider candidate changed during start verification")

        if self.changed_return_record_call == call:
            changed = copy.deepcopy(verified)
            changed["draft"]["id"] += 1
            return changed
        return verified

    def encode_claim(self, record_bytes: bytes, bundle_bytes: bytes, **selection) -> bytes:
        self.events.append("claim-encode")
        if self.claim_failure:
            raise START.StartError("synthetic claim encoding failure")
        if record_bytes != self.selected_record or bundle_bytes != self.selected_bundle:
            raise AssertionError("claim encoder did not receive the original selected bytes")
        expected_selection = {
            "source_context": self.initial_source,
            "dispatcher_context": self.identity["context"],
            "dispatcher_job": self.identity["job"],
            "dispatcher_event": self.identity["event"],
            "trigger_context": self.identity["trigger_context"],
        }
        if selection != expected_selection:
            raise AssertionError("claim encoder did not receive the authenticated identity joins")
        self.claim_raw = real_claim_bytes(record_bytes, bundle_bytes, **selection)
        if self.source_mutation_after_claim:
            self._mutate_source(self.source)
        return self.claim_raw

    def upload_once(self, claim: bytes, record_bytes: bytes, bundle_bytes: bytes, **selection) -> dict:
        self.events.append("upload-once")
        self.upload_arguments = (claim, record_bytes, bundle_bytes, copy.deepcopy(selection))
        return {"id": 70001, "name": CLAIM.CLAIM_NAME, "size": len(claim),
                "sha256": sha256(claim)}


real_claim_bytes = CLAIM.claim_bytes


class AuthenticatedClaimBoundaryTests(unittest.TestCase):
    def harness(self) -> BoundaryHarness:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return BoundaryHarness(Path(temporary.name))

    @contextmanager
    def patched_boundaries(self, harness: BoundaryHarness):
        with mock.patch.object(AUTH, "authenticate_dispatcher", side_effect=harness.authenticate) as auth_mock, \
                mock.patch.object(START, "verify_start", side_effect=harness.verify_start) as verify_mock, \
                mock.patch.object(CLAIM, "claim_bytes", side_effect=harness.encode_claim) as claim_mock, \
                mock.patch.object(UPLOAD, "upload_claim_once", side_effect=harness.upload_once) as upload_mock, \
                mock.patch.object(START.ADMISSION, "api", side_effect=AssertionError("unexpected provider API")), \
                mock.patch.object(START.ADMISSION, "git", side_effect=AssertionError("unexpected provider Git")), \
                mock.patch.object(START, "bounded_gh", side_effect=AssertionError("unexpected signature command")), \
                mock.patch.object(UPLOAD, "gh_response", side_effect=AssertionError("unexpected upload transport")):
            yield auth_mock, verify_mock, claim_mock, upload_mock

    def invoke(self, harness: BoundaryHarness) -> dict:
        return boundary.authenticate_and_upload(
            harness.fixture.record_path,
            harness.fixture.bundle_path,
            harness.source,
            runtime_lock=harness.fixture.runtime_lock_path,
            runtime_directory=harness.fixture.runtime_directory,
            runtime_interface=harness.fixture.runtime_interface_path,
            runtime_host=harness.fixture.runtime_host,
        )

    def assert_no_upload(self, upload_mock) -> None:
        upload_mock.assert_not_called()

    def test_success_authenticates_in_order_and_uploads_only_one_claim(self) -> None:
        harness = self.harness()
        self.assertTrue(stat.S_ISREG(harness.fixture.record_path.stat().st_mode))
        self.assertTrue(stat.S_ISREG(harness.fixture.bundle_path.stat().st_mode))
        self.assertEqual(harness.fixture.record_path.read_bytes(), harness.selected_record)
        self.assertEqual(harness.fixture.bundle_path.read_bytes(), harness.selected_bundle)

        with self.patched_boundaries(harness) as (_, verify_mock, claim_mock, upload_mock):
            result = self.invoke(harness)

        self.assertEqual(harness.events, [
            "dispatcher-auth:1", "start-verify:1", "claim-encode",
            "dispatcher-auth:2", "start-verify:2", "upload-once",
        ])
        self.assertEqual(len(harness.events), 6)
        self.assertEqual(verify_mock.call_count, 2)
        self.assertEqual(claim_mock.call_count, 1)
        upload_mock.assert_called_once()
        self.assertEqual(result["assurance"],
                         "authenticated-claim-upload-only-not-native-dispatch")
        self.assertEqual(result["claim"]["name"], CLAIM.CLAIM_NAME)
        self.assertEqual(result["claim"], {
            "id": 70001, "name": CLAIM.CLAIM_NAME, "size": len(harness.claim_raw),
            "sha256": sha256(harness.claim_raw),
        })
        self.assertEqual(harness.upload_arguments[0], harness.claim_raw)
        self.assertEqual(harness.upload_arguments[1:3],
                         (harness.selected_record, harness.selected_bundle))
        self.assertEqual(harness.events[-1], "upload-once")
        self.assertNotIn("native-dispatch", harness.events)

        expected_pins = {
            "expected_record_sha256": sha256(harness.selected_record),
            "expected_bundle_sha256": sha256(harness.selected_bundle),
        }
        expected_runtime = {
            "runtime_lock": harness.fixture.runtime_lock_path,
            "runtime_directory": harness.fixture.runtime_directory,
            "runtime_interface": harness.fixture.runtime_interface_path,
            "runtime_host": harness.fixture.runtime_host,
        }
        for call in verify_mock.call_args_list:
            self.assertEqual(call.args[:2],
                             (harness.fixture.record_path, harness.fixture.bundle_path))
            self.assertEqual(call.kwargs, {**expected_runtime, **expected_pins})

    def test_failure_at_each_preupload_gate_never_calls_upload(self) -> None:
        cases = {
            "initial dispatcher authentication": ("auth", 1, 1, 0),
            "initial signed-start verification": ("verify", 1, 1, 1),
            "selected record join": ("returned record", 1, 1, 1),
            "claim encoding": ("claim", 1, 1, 1),
            "dispatcher identity recheck": ("identity recheck", 2, 2, 1),
            "signed-start recheck": ("verify recheck", 2, 2, 2),
        }
        for label, (failure, expected_auth_calls, configured_call, verify_calls) in cases.items():
            with self.subTest(gate=label):
                harness = self.harness()
                if failure == "auth":
                    harness.auth_failure_call = configured_call
                elif failure == "verify":
                    harness.verify_failure_call = configured_call
                elif failure == "returned record":
                    harness.changed_return_record_call = configured_call
                elif failure == "claim":
                    harness.claim_failure = True
                elif failure == "identity recheck":
                    harness.identity_change_call = 2
                else:
                    harness.verify_failure_call = 2

                with self.patched_boundaries(harness) as (auth_mock, verify_mock, claim_mock, upload_mock):
                    with self.assertRaises(FAILURES):
                        self.invoke(harness)

                self.assert_no_upload(upload_mock)
                self.assertEqual(auth_mock.call_count, expected_auth_calls)
                self.assertEqual(verify_mock.call_count, verify_calls)
                if failure in ("auth", "verify", "returned record"):
                    claim_mock.assert_not_called()
                if failure in ("claim", "identity recheck", "verify recheck"):
                    self.assertLess(harness.events.index("claim-encode"),
                                    len(harness.events))

    def test_semantically_equal_record_with_different_raw_bytes_fails_its_pin(self) -> None:
        harness = self.harness()
        harness.semantic_record_rewrite_on_auth = True
        with self.patched_boundaries(harness) as (_, verify_mock, claim_mock, upload_mock):
            with self.assertRaisesRegex(START.StartError, "exact digest pin"):
                self.invoke(harness)
        self.assert_no_upload(upload_mock)
        self.assertEqual(verify_mock.call_count, 1)
        claim_mock.assert_not_called()

    def test_source_candidate_and_byte_changes_during_each_start_verification_fail(self) -> None:
        cases = [
            ("source", 1, None), ("source", 2, None),
            ("candidate", 1, None), ("candidate", 2, None),
            ("record-bytes", 1, "record"), ("record-bytes", 2, "record"),
            ("bundle-bytes", 1, "bundle"), ("bundle-bytes", 2, "bundle"),
        ]
        for kind, verify_call, file_kind in cases:
            with self.subTest(kind=kind, verify_call=verify_call):
                harness = self.harness()
                if kind == "source":
                    harness.source_mutation_verify_call = verify_call
                elif kind == "candidate":
                    harness.candidate_mutation_verify_call = verify_call
                else:
                    harness.bytes_mutation_verify_call = (verify_call, file_kind)

                with self.patched_boundaries(harness) as (_, verify_mock, claim_mock, upload_mock):
                    with self.assertRaises(FAILURES):
                        self.invoke(harness)

                self.assert_no_upload(upload_mock)
                self.assertEqual(verify_mock.call_count, verify_call)
                if verify_call == 1:
                    claim_mock.assert_not_called()
                else:
                    claim_mock.assert_called_once()

    def test_source_change_at_dispatcher_recheck_and_own_identity_change_fail(self) -> None:
        cases = ("source changed after claim encoding", "own dispatcher identity changed")
        for case in cases:
            with self.subTest(case=case):
                harness = self.harness()
                if case == "source changed after claim encoding":
                    harness.source_mutation_after_claim = True
                else:
                    harness.identity_change_call = 2

                with self.patched_boundaries(harness) as (auth_mock, verify_mock, claim_mock, upload_mock):
                    with self.assertRaises(FAILURES):
                        self.invoke(harness)

                self.assert_no_upload(upload_mock)
                self.assertEqual(auth_mock.call_count, 2)
                self.assertEqual(verify_mock.call_count, 1)
                claim_mock.assert_called_once()


if __name__ == "__main__":
    unittest.main(verbosity=2)
