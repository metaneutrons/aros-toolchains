#!/usr/bin/env python3
"""Offline composition tests for candidate-only native-start authentication.

The real candidate wrapper, dispatcher-claim signature gate, post-claim start
reader, claim codec, and local file reader execute. Provider observations,
Sigstore command results, runtime verification, and the numeric GitHub GET are
bounded fixtures. These tests establish no live provider or native-run
qualification.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
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


# Reuse only the original start test's synthetic record/provider helpers.
# Never call its verify method: that would patch a different module instance.
DATA = load_module(
    "native_candidate_start_test_data_v2",
    SOURCE_ROOT / "scripts/toolchain/tests/test-compiler-sdk-release-start-v2.py",
)
NATIVE = load_module(
    "authenticate_compiler_sdk_native_candidate_v2",
    SOURCE_ROOT / "scripts/toolchain/authenticate-compiler-sdk-native-candidate-v2.py",
)
START = NATIVE.START
CLAIM = NATIVE.CLAIM
UPLOAD = NATIVE.POST.UPLOAD
ADMISSION = START.ADMISSION
ORIGIN = START.ORIGIN

REPOSITORY = DATA.REPOSITORY
CLAIM_SIGNATURE = "dispatcher claim signature authentication"
START_SIGNATURE = "start signature authentication"
ASSET_ID = 887766
FIXED_ENV = {
    "GH_HOST": "github.com",
    "GH_TOKEN": "synthetic-job-token",
    "GITHUB_TOKEN": "alternate-token-fixture",
    "GH_AUTH_TOKEN": "alternate-auth-fixture",
    "GH_ENTERPRISE_TOKEN": "enterprise-token-fixture",
    "GITHUB_ENTERPRISE_TOKEN": "enterprise-fallback-fixture",
    "GOVERNANCE_TOKEN": "governance-token-fixture",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "oidc-token-fixture",
    "ACTIONS_ID_TOKEN_REQUEST_URL": "https://oidc.invalid/token",
}
ERRORS = (START.StartError, ADMISSION.AdmissionError, ORIGIN.OriginError, OSError)
RECEIPT_NAME = ".aros-tools-runtime-receipt-v1.json"


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def included(body: bytes) -> bytes:
    return b"HTTP/2 200 Fixture\r\nContent-Type: application/octet-stream\r\n\r\n" + body


class NativeCandidateFixture:
    """Canonical synthetic start and claim with all external edges bounded."""

    def __init__(self, root: Path):
        self.root = root.resolve()
        self.start = DATA.StartFixture(self.root)
        self.source_context = copy.deepcopy(self.start.source)
        self.dispatcher_context = DATA.context(
            workflow=CLAIM.WORKFLOW,
            run_id=DATA.RUN_ID + 100,
        )
        self.dispatcher_provider_context = copy.deepcopy(self.dispatcher_context)
        self.dispatcher_job = {
            "id": DATA.JOB_ID + 100,
            "check_run_id": DATA.CHECK_RUN_ID + 100,
            "name": CLAIM.JOB,
        }
        self.dispatcher_job_provider = DATA.provider_job(
            self.dispatcher_context,
            job_id=self.dispatcher_job["id"],
            check_id=self.dispatcher_job["check_run_id"],
            name=CLAIM.JOB,
        )
        self.dispatcher_run = DATA.provider_run(self.dispatcher_context)
        self.record_raw = self.start.record_bytes
        self.start_bundle = self.start.bundle_bytes
        self.claim_raw = CLAIM.claim_bytes(
            self.record_raw,
            self.start_bundle,
            source_context=self.source_context,
            dispatcher_context=self.dispatcher_context,
            dispatcher_job=self.dispatcher_job,
            dispatcher_event="workflow_run",
            trigger_context=self.source_context,
        )
        self.claim_bundle = b"synthetic dispatcher signature bundle; verifier is mocked\n"
        self.record_path = self.start.record_path
        self.start_bundle_path = self.start.bundle_path
        self.claim_path = self.root / CLAIM.CLAIM_NAME
        self.claim_bundle_path = self.root / "dispatcher.sigstore.json"
        self.claim_path.write_bytes(self.claim_raw)
        self.claim_bundle_path.write_bytes(self.claim_bundle)

        self.asset_id = ASSET_ID
        self.release_path = f"repos/{REPOSITORY}/releases/{DATA.DRAFT_ID}"
        self.tag_lookup_path = f"repos/{REPOSITORY}/releases/tags/{DATA.TAG_NAME}"
        self.start.provider[f"repos/{REPOSITORY}"]["private"] = True
        self.start.provider[f"repos/{REPOSITORY}"]["visibility"] = "private"
        self.start.source_job = DATA.provider_job(self.source_context)
        self.source_job_provider = copy.deepcopy(self.start.source_job)
        self.dispatcher_latest_attempt = 1
        self.probe: str | None = None
        self.late_input_change: str | None = None
        self.late_final_start_change: str | None = None
        self.late_context_change: str | None = None

        self.api_calls: list[str] = []
        self.origin_calls: list[tuple[list[str], str]] = []
        self.signature_purposes: list[str] = []
        self.dispatcher_signature_calls = 0
        self.start_signature_calls = 0
        self.transport_calls: list[tuple[list[str], dict]] = []
        self.asset_reads = 0
        self.runtime_calls = []
        self.git_calls: list[tuple[str, ...]] = []

    @property
    def dispatcher_attempt_path(self) -> str:
        return (f"repos/{REPOSITORY}/actions/runs/"
                f"{self.dispatcher_provider_context['run_id']}/attempts/1")

    @property
    def dispatcher_latest_path(self) -> str:
        return f"repos/{REPOSITORY}/actions/runs/{self.dispatcher_provider_context['run_id']}"

    def selected_inputs(self) -> tuple[tuple[str, Path, bytes, int], ...]:
        return (
            ("record_path", self.record_path, self.record_raw, START.MAX_RECORD),
            ("start_bundle_path", self.start_bundle_path, self.start_bundle, START.MAX_BUNDLE),
            ("claim_path", self.claim_path, self.claim_raw, START.MAX_RECORD),
            ("claim_bundle_path", self.claim_bundle_path, self.claim_bundle, START.MAX_BUNDLE),
        )

    def input_path(self, field: str) -> Path:
        return dict((name, path) for name, path, _, _ in self.selected_inputs())[field]

    def input_bytes(self, field: str) -> bytes:
        return dict((name, raw) for name, _, raw, _ in self.selected_inputs())[field]

    def pins(self) -> dict[str, str]:
        return {
            "expected_record_sha256": sha256(self.record_raw),
            "expected_start_bundle_sha256": sha256(self.start_bundle),
            "expected_claim_sha256": sha256(self.claim_raw),
            "expected_claim_bundle_sha256": sha256(self.claim_bundle),
        }

    def call(self, *, environment: dict[str, str] | None = None, **overrides) -> dict:
        arguments = {
            "record_path": self.record_path,
            "start_bundle_path": self.start_bundle_path,
            "claim_path": self.claim_path,
            "claim_bundle_path": self.claim_bundle_path,
            "source_context": self.source_context,
            "dispatcher_context": self.dispatcher_context,
            "dispatcher_job": self.dispatcher_job,
            **self.pins(),
            "expected_claim_asset_id": self.asset_id,
            "runtime_lock": self.start.runtime_lock_path,
            "runtime_directory": self.start.runtime_directory,
            "runtime_interface": self.start.runtime_interface_path,
            "runtime_host": self.start.runtime_host,
        }
        arguments.update(overrides)

        with mock.patch.dict(os.environ, FIXED_ENV if environment is None else environment, clear=True), \
                mock.patch.object(ADMISSION, "api", side_effect=self.api), \
                mock.patch.object(ADMISSION, "git", side_effect=self.git), \
                mock.patch.object(ADMISSION, "_bounded_subprocess",
                                  side_effect=self.bounded_subprocess), \
                mock.patch.object(ORIGIN, "gh_json", side_effect=self.origin), \
                mock.patch.object(START, "bounded_gh", side_effect=self.signature), \
                mock.patch.object(START, "verify_runtime_evidence") as runtime_evidence:
            try:
                return NATIVE.authenticate_candidate(**arguments)
            finally:
                self.runtime_calls = runtime_evidence.call_args_list

    def make_asset(self) -> dict:
        identifier = self.asset_id
        value = {
            "id": identifier,
            "name": CLAIM.CLAIM_NAME,
            "state": "uploaded",
            "content_type": "application/json",
            "size": len(self.claim_raw),
            "digest": f"sha256:{sha256(self.claim_raw)}",
            "url": f"https://api.github.com/repos/{REPOSITORY}/releases/assets/{identifier}",
        }
        if self.probe == "wrong_asset_id":
            value["id"] += 1
            value["url"] = f"https://api.github.com/repos/{REPOSITORY}/releases/assets/{value['id']}"
        elif self.probe == "wrong_asset_size":
            value["size"] += 1
        elif self.probe == "wrong_asset_digest":
            value["digest"] = "sha256:" + "0" * 64
        elif self.probe == "wrong_asset_name":
            value["name"] = "another-claim.json"
        return value

    def release(self) -> dict:
        assets = [] if self.probe == "empty_assets" else [self.make_asset()]
        if self.probe == "extra_asset":
            assets.append({"id": self.asset_id + 1, "name": "unexpected.json"})
        return {
            "id": DATA.DRAFT_ID,
            "tag_name": DATA.TAG_NAME,
            "target_commitish": DATA.COMMIT,
            "draft": True,
            "prerelease": False,
            "immutable": False,
            "assets": assets,
        }

    def api(self, path: str, **kwargs):
        if kwargs:
            raise AssertionError(f"provider observation attempted non-default API options: {kwargs!r}")
        self.api_calls.append(path)
        if path == self.dispatcher_attempt_path:
            value = copy.deepcopy(self.dispatcher_run)
            if self.probe == "dispatcher_failed_attempt":
                value["conclusion"] = "failure"
            return value
        if path == self.dispatcher_latest_path:
            value = copy.deepcopy(self.dispatcher_run)
            value["run_attempt"] = self.dispatcher_latest_attempt
            return value
        if path in (self.release_path, self.tag_lookup_path):
            return self.release()
        return self.start.run_api(path, **kwargs)

    def origin(self, arguments: list[str], purpose: str = "GitHub observation"):
        selected = list(arguments)
        self.origin_calls.append((selected, purpose))
        if selected[:1] != ["api"]:
            raise AssertionError(f"unexpected provider command: {selected!r}")
        if "--paginate" in selected:
            endpoint = selected[-1]
            if f"/runs/{self.source_context['run_id']}/" in endpoint:
                job = copy.deepcopy(self.source_job_provider)
                if self.probe == "source_failed_job":
                    job.update(status="completed", conclusion="failure")
            elif f"/runs/{self.dispatcher_provider_context['run_id']}/" in endpoint:
                job = copy.deepcopy(self.dispatcher_job_provider)
                if self.probe == "dispatcher_failed_job":
                    job.update(status="completed", conclusion="failure")
            else:
                raise AssertionError(f"unexpected jobs endpoint: {endpoint!r}")
            return [{"total_count": 1, "jobs": [job]}]
        if len(selected) == 2 and "/actions/runs/" in selected[1]:
            if f"/runs/{self.dispatcher_provider_context['run_id']}/" in selected[1]:
                return copy.deepcopy(self.dispatcher_run)
            if f"/runs/{self.source_context['run_id']}/" in selected[1]:
                return DATA.provider_run(self.source_context)
        raise AssertionError(f"unexpected origin selector: {selected!r} ({purpose})")

    def git(self, *arguments: str) -> bytes:
        self.git_calls.append(arguments)
        if len(arguments) != 2 or arguments[0] != "show":
            raise AssertionError(f"unexpected local Git selector: {arguments!r}")
        selected = arguments[1]
        prefix = f"{self.source_context['producer_commit']}:"
        if not selected.startswith(prefix):
            raise AssertionError(f"frozen input uses another producer commit: {selected!r}")
        path = selected[len(prefix):]
        if path not in self.start.blobs:
            raise AssertionError(f"unexpected frozen input path: {path!r}")
        return self.start.blobs[path]

    def signature(self, arguments: list[str], purpose: str = "start provider observation"):
        selected = list(arguments)
        self.signature_purposes.append(purpose)
        if selected[:2] != ["attestation", "verify"]:
            raise AssertionError(f"unexpected signature command: {selected!r}")

        if purpose == CLAIM_SIGNATURE:
            self.dispatcher_signature_calls += 1
            subject = Path(selected[2])
            bundle = Path(selected[4])
            if (subject.name != CLAIM.CLAIM_NAME or subject.read_bytes() != self.claim_raw
                    or bundle.read_bytes() != self.claim_bundle
                    or subject.stat().st_mode & 0o777 != 0o600
                    or bundle.stat().st_mode & 0o777 != 0o600):
                raise AssertionError("dispatcher verifier did not receive private selected claim bytes")
            expected = [
                "attestation", "verify", str(subject), "--bundle", str(bundle),
                "--hostname", "github.com", "--repo", REPOSITORY,
                "--signer-workflow", f"{REPOSITORY}/{CLAIM.WORKFLOW}",
                "--signer-digest", self.dispatcher_context["producer_commit"],
                "--source-digest", self.dispatcher_context["producer_commit"],
                "--source-ref", START.ADMISSION.MAIN_REF,
                "--deny-self-hosted-runners", "--format", "json",
            ]
            if selected != expected:
                raise AssertionError("dispatcher signature verifier arguments differ from the independent selection")
            invocation = (f"https://github.com/{REPOSITORY}/actions/runs/"
                          f"{self.dispatcher_context['run_id']}/attempts/1")
            result = DATA.attestation(
                self.claim_raw, invocation=invocation, subject_name=CLAIM.CLAIM_NAME,
            )
            verification = result[0]["verificationResult"]
            if self.probe == "dispatcher_signature_attempt":
                verification["signature"]["certificate"]["runInvocationURI"] += "/rerun"
            elif self.probe == "dispatcher_signature_subject":
                verification["statement"]["subject"][0]["name"] = "other-claim.json"
            elif self.probe == "dispatcher_signature_digest":
                verification["statement"]["subject"][0]["digest"]["sha256"] = "0" * 64
            if self.dispatcher_signature_calls == 2 and self.late_context_change is not None:
                self.change_selected_context()
            if self.dispatcher_signature_calls == 2 and self.late_final_start_change is not None:
                path = self.input_path(self.late_final_start_change)
                path.write_bytes(path.read_bytes() + b"late outer start-input change\n")
            return result

        if purpose == START_SIGNATURE:
            self.start_signature_calls += 1
            subject = Path(selected[2])
            bundle = Path(selected[4])
            if (subject.name != self.record_path.name or subject.read_bytes() != self.record_raw
                    or bundle.read_bytes() != self.start_bundle
                    or subject.stat().st_mode & 0o777 != 0o600
                    or bundle.stat().st_mode & 0o777 != 0o600):
                raise AssertionError("start verifier did not receive private selected record bytes")
            expected = [
                "attestation", "verify", str(subject), "--bundle", str(bundle),
                "--repo", REPOSITORY, "--signer-workflow", f"{REPOSITORY}/{START.WORKFLOW}",
                "--signer-digest", self.source_context["producer_commit"],
                "--source-digest", self.source_context["producer_commit"],
                "--source-ref", START.ADMISSION.MAIN_REF,
                "--deny-self-hosted-runners", "--format", "json",
            ]
            if selected != expected:
                raise AssertionError("start signature verifier arguments differ from the exact selection")
            result = DATA.attestation(self.record_raw, subject_name=self.record_path.name)
            verification = result[0]["verificationResult"]
            if self.probe == "start_signature_attempt":
                verification["signature"]["certificate"]["runInvocationURI"] += "/rerun"
            elif self.probe == "start_signature_subject":
                verification["statement"]["subject"][0]["name"] = "other-start.json"
            elif self.probe == "start_signature_digest":
                verification["statement"]["subject"][0]["digest"]["sha256"] = "0" * 64
            if self.probe == "dispatcher_rerun_after_start_gate":
                self.dispatcher_latest_attempt = 2
            return result

        raise AssertionError(f"unexpected signature purpose: {purpose!r}")

    def change_selected_context(self) -> None:
        if self.late_context_change == "source_context":
            self.source_context["producer_commit"] = "9" * 40
        elif self.late_context_change == "dispatcher_context":
            self.dispatcher_context["run_id"] += 1
        elif self.late_context_change == "dispatcher_job":
            self.dispatcher_job["id"] += 1
        else:
            raise AssertionError(f"unknown selected-context mutation: {self.late_context_change!r}")

    def bounded_subprocess(self, command: list[str], **kwargs):
        selected = list(command)
        options = copy.deepcopy(kwargs)
        self.transport_calls.append((selected, options))
        expected = [
            "gh", "api", f"repos/{REPOSITORY}/releases/assets/{self.asset_id}",
            "--method", "GET", "--include", "--hostname", "github.com",
            "-H", "Accept: application/octet-stream",
            "-H", "X-GitHub-Api-Version: 2022-11-28",
        ]
        if selected != expected:
            raise AssertionError("numeric claim readback differs from the exact fixed-host GET selector")
        environment = options["env"]
        if environment.get("GH_HOST") != "github.com" or environment.get("GH_TOKEN") != FIXED_ENV["GH_TOKEN"]:
            raise AssertionError("numeric claim GET did not use the fixed-host job token")
        if any(key in environment for key in (
                "GITHUB_TOKEN", "GH_AUTH_TOKEN", "GH_ENTERPRISE_TOKEN",
                "GITHUB_ENTERPRISE_TOKEN", "GOVERNANCE_TOKEN",
                "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL")):
            raise AssertionError("numeric claim GET retained an alternate credential or OIDC token")
        if (options["cwd"] is not None or options["timeout"] != ADMISSION.API_TIMEOUT_SECONDS
                or options["stdout_limit"] != START.MAX_RECORD + UPLOAD.MAX_HEADERS
                or options["stderr_limit"] != ADMISSION.MAX_API_STDERR_BYTES
                or options["label"] != "selected claim numeric readback"):
            raise AssertionError("numeric claim GET did not retain its bounded transport limits")

        self.asset_reads += 1
        body = self.claim_raw + b"changed" if self.probe == "numeric_wrong_bytes" else self.claim_raw
        response = included(body)
        if self.asset_reads == 2 and self.late_input_change is not None:
            path = self.input_path(self.late_input_change)
            path.write_bytes(path.read_bytes() + b"late selected-input change\n")
        return subprocess.CompletedProcess(selected, 0, response, b"")

    def assert_no_external_observation(self, testcase: unittest.TestCase) -> None:
        testcase.assertEqual(self.api_calls, [])
        testcase.assertEqual(self.origin_calls, [])
        testcase.assertEqual(self.signature_purposes, [])
        testcase.assertEqual(self.transport_calls, [])
        testcase.assertEqual(self.runtime_calls, [])

    def assert_boundary(self, testcase: unittest.TestCase, *, dispatcher_signatures: int,
                        start_signatures: int, numeric_reads: int, runtime_calls: int) -> None:
        testcase.assertEqual(self.signature_purposes.count(CLAIM_SIGNATURE), dispatcher_signatures)
        testcase.assertEqual(self.signature_purposes.count(START_SIGNATURE), start_signatures)
        testcase.assertEqual(self.asset_reads, numeric_reads)
        testcase.assertEqual(len(self.transport_calls), numeric_reads)
        testcase.assertEqual(len(self.runtime_calls), runtime_calls)


class NativeCandidateAuthenticationTests(unittest.TestCase):
    def fixture(self) -> NativeCandidateFixture:
        temporary = tempfile.TemporaryDirectory(prefix="aros-native-candidate-v2.")
        self.addCleanup(temporary.cleanup)
        return NativeCandidateFixture(Path(temporary.name).resolve())

    def assert_rejected(self, fixture: NativeCandidateFixture, pattern: str, **overrides) -> None:
        with self.assertRaises(ERRORS) as raised:
            fixture.call(**overrides)
        self.assertRegex(str(raised.exception), pattern)

    def test_positive_runs_both_real_gates_and_returns_the_closed_candidate_only_summary(self) -> None:
        fixture = self.fixture()
        result = fixture.call()
        self.assertEqual(result, {
            "schema": "aros-toolchains-native-candidate-authentication-v2",
            "assurance": "authenticated-candidate-only-not-native-dispatch-or-qualification",
            "authenticated_candidate_only": {
                "tag_name": DATA.TAG_NAME,
                "commit": DATA.COMMIT,
                "draft_id": DATA.DRAFT_ID,
                "claim_asset": {
                    "id": ASSET_ID,
                    "name": "compiler-sdk-dispatch-claim-v2.json",
                    "size": len(fixture.claim_raw),
                    "sha256": sha256(fixture.claim_raw),
                },
            },
            "limitations": [
                "does not authenticate the actual native workflow_dispatch event or OIDC identity",
                "does not establish a signed native dispatch-run binding",
                "does not provide durable exclusive claim consumption",
                "does not authorize dispatch or qualify a release",
            ],
        })
        self.assertEqual(set(result), {
            "schema", "assurance", "authenticated_candidate_only", "limitations",
        })
        self.assertEqual(set(result["authenticated_candidate_only"]), {
            "tag_name", "commit", "draft_id", "claim_asset",
        })
        self.assertEqual(set(result["authenticated_candidate_only"]["claim_asset"]), {
            "id", "name", "size", "sha256",
        })
        self.assertEqual(fixture.signature_purposes, [CLAIM_SIGNATURE, START_SIGNATURE, CLAIM_SIGNATURE])
        fixture.assert_boundary(
            self, dispatcher_signatures=2, start_signatures=1, numeric_reads=2, runtime_calls=2,
        )
        self.assertEqual(len(fixture.git_calls), len(fixture.start.record["admission"]["inputs"]))
        self.assertEqual(len([path for path in fixture.api_calls if "/releases/" in path]), 8)
        self.assertEqual(fixture.transport_calls[0][0], fixture.transport_calls[1][0])
        self.assertEqual(fixture.transport_calls[0][0][3:5], ["--method", "GET"])
        self.assertFalse(any(method in command for command, _ in fixture.transport_calls
                             for method in ("POST", "PATCH", "DELETE")))
        for _, path, _, maximum in fixture.selected_inputs():
            metadata = path.stat()
            self.assertTrue(path.is_file())
            self.assertEqual(metadata.st_nlink, 1)
            self.assertLessEqual(metadata.st_size, maximum)
        self.assertEqual(fixture.runtime_calls, [
            mock.call(
                fixture.start.record,
                lock_path=fixture.start.runtime_lock_path,
                directory=fixture.start.runtime_directory,
                interface_path=fixture.start.runtime_interface_path,
                host=fixture.start.runtime_host,
            ),
            mock.call(
                fixture.start.record,
                lock_path=fixture.start.runtime_lock_path,
                directory=fixture.start.runtime_directory,
                interface_path=fixture.start.runtime_interface_path,
                host=fixture.start.runtime_host,
            ),
        ])

    def test_each_independent_pin_and_canonical_start_encoding_is_checked_before_provider_calls(self) -> None:
        for field in (
                "expected_record_sha256", "expected_start_bundle_sha256",
                "expected_claim_sha256", "expected_claim_bundle_sha256"):
            with self.subTest(pin=field):
                fixture = self.fixture()
                self.assert_rejected(
                    fixture,
                    "candidate input differs from its independent byte selection",
                    **{field: "0" * 64},
                )
                fixture.assert_no_external_observation(self)

        fixture = self.fixture()
        noncanonical = (json.dumps(fixture.start.record, indent=2) + "\n").encode("ascii")
        fixture.record_path.write_bytes(noncanonical)
        self.assert_rejected(
            fixture,
            "selected start record is not canonical JSON",
            expected_record_sha256=sha256(noncanonical),
        )
        fixture.assert_no_external_observation(self)

    def test_fixed_host_token_and_exact_numeric_selection_reject_before_external_observation(self) -> None:
        environments = (
            {**FIXED_ENV, "GH_HOST": "github.example"},
            {key: value for key, value in FIXED_ENV.items() if key != "GH_HOST"},
            {key: value for key, value in FIXED_ENV.items() if key != "GH_TOKEN"},
            {**FIXED_ENV, "GH_TOKEN": ""},
            {**FIXED_ENV, "GH_TOKEN": "   "},
        )
        for environment in environments:
            with self.subTest(environment=environment):
                fixture = self.fixture()
                self.assert_rejected(
                    fixture, "native candidate requires the fixed-host job token",
                    environment=environment)
                fixture.assert_no_external_observation(self)
        for identifier in (None, 0, True, "887766", 887766.0, 2**54):
            with self.subTest(asset_id=identifier):
                fixture = self.fixture()
                with self.assertRaises(ERRORS):
                    fixture.call(expected_claim_asset_id=identifier)
                fixture.assert_no_external_observation(self)

    def test_all_four_captured_inputs_must_be_bounded_unlinked_regular_files(self) -> None:
        for field, maximum in (
                ("record_path", START.MAX_RECORD),
                ("start_bundle_path", START.MAX_BUNDLE),
                ("claim_path", START.MAX_RECORD),
                ("claim_bundle_path", START.MAX_BUNDLE)):
            with self.subTest(input=field, property="bounded"):
                fixture = self.fixture()
                fixture.input_path(field).write_bytes(b"x" * (maximum + 1))
                self.assert_rejected(fixture, "bounded, singly-linked regular file|metadata size limit")
                fixture.assert_no_external_observation(self)

            with self.subTest(input=field, property="symlink"):
                fixture = self.fixture()
                path = fixture.input_path(field)
                target = path.with_name(path.name + ".target")
                target.write_bytes(fixture.input_bytes(field))
                path.unlink()
                path.symlink_to(target)
                self.assert_rejected(fixture, "cannot be opened as a regular file")
                fixture.assert_no_external_observation(self)

            with self.subTest(input=field, property="hardlink"):
                fixture = self.fixture()
                path = fixture.input_path(field)
                os.link(path, path.with_name(path.name + ".hardlink"))
                self.assert_rejected(fixture, "bounded, singly-linked regular file")
                fixture.assert_no_external_observation(self)

    def test_all_metadata_signature_and_runtime_paths_must_be_distinct(self) -> None:
        cases = (
            ("record and start bundle", "captured metadata, signatures and runtime evidence must use separate paths",
             {"start_bundle_path": "record_path"}),
            ("record and claim", "captured metadata, signatures and runtime evidence must use separate paths",
             {"record_path": "claim_path"}),
            ("record and claim bundle", "captured metadata, signatures and runtime evidence must use separate paths",
             {"record_path": "claim_bundle_path"}),
            ("start and claim bundle", "captured metadata, signatures and runtime evidence must use separate paths",
             {"claim_bundle_path": "start_bundle_path"}),
            ("claim and claim bundle", "captured metadata, signatures and runtime evidence must use separate paths",
             {"claim_bundle_path": "claim_path"}),
            ("runtime lock and record", "captured metadata, signatures and runtime evidence must use separate paths",
             {"runtime_lock": "record_path"}),
            ("runtime interface and claim", "captured metadata, signatures and runtime evidence must use separate paths",
             {"runtime_interface": "claim_path"}),
            ("runtime lock and interface", "captured metadata, signatures and runtime evidence must use separate paths",
             {"runtime_lock": "runtime_interface_path"}),
        )
        for label, reason, selected in cases:
            with self.subTest(paths=label):
                fixture = self.fixture()
                replacements = {
                    "record_path": fixture.record_path,
                    "start_bundle_path": fixture.start_bundle_path,
                    "claim_path": fixture.claim_path,
                    "claim_bundle_path": fixture.claim_bundle_path,
                    "runtime_interface_path": fixture.start.runtime_interface_path,
                }
                overrides = {key: replacements[value] for key, value in selected.items()}
                self.assert_rejected(fixture, reason, **overrides)
                fixture.assert_no_external_observation(self)

        fixture = self.fixture()
        receipt_collision = fixture.root / RECEIPT_NAME
        receipt_collision.write_bytes(fixture.claim_bundle)
        self.assert_rejected(
            fixture,
            "captured metadata, signatures and runtime evidence must use separate paths",
            claim_bundle_path=receipt_collision,
            runtime_directory=fixture.root,
        )
        fixture.assert_no_external_observation(self)

    def test_claimed_release_requires_one_exact_asset_and_numeric_readback_of_its_bytes(self) -> None:
        cases = (
            ("empty_assets", "claimed start requires the exact private sole-claim candidate", 0),
            ("extra_asset", "claimed start requires the exact private sole-claim candidate", 0),
            ("wrong_asset_id", "candidate claim differs from the independent numeric selection", 0),
            ("wrong_asset_size", "claim asset identity, bytes or upload state differs", 0),
            ("wrong_asset_digest", "claim asset identity, bytes or upload state differs", 0),
            ("wrong_asset_name", "claim asset identity, bytes or upload state differs", 0),
            ("numeric_wrong_bytes", "selected claim numeric readback differs from the captured bytes", 1),
        )
        for probe, reason, reads in cases:
            with self.subTest(probe=probe):
                fixture = self.fixture()
                fixture.probe = probe
                self.assert_rejected(fixture, reason)
                fixture.assert_boundary(
                    self, dispatcher_signatures=1, start_signatures=1,
                    numeric_reads=reads, runtime_calls=1,
                )

    def test_failed_original_start_and_dispatcher_owners_stop_at_the_expected_gate(self) -> None:
        cases = (
            ("dispatcher_failed_attempt", "incomplete or unsuccessful", 0),
            ("dispatcher_failed_job", "owning job did not succeed", 0),
            ("source_failed_attempt", "incomplete or unsuccessful", 1),
            ("source_failed_job", "owning job did not succeed", 1),
        )
        for probe, reason, dispatcher_signatures in cases:
            with self.subTest(owner=probe):
                fixture = self.fixture()
                fixture.probe = probe
                if probe == "source_failed_attempt":
                    fixture.start.case = "failed_attempt"
                self.assert_rejected(fixture, reason)
                fixture.assert_boundary(
                    self, dispatcher_signatures=dispatcher_signatures, start_signatures=0,
                    numeric_reads=0, runtime_calls=0,
                )

    def test_both_original_signatures_reject_attempt_subject_and_digest_drift(self) -> None:
        cases = (
            ("dispatcher_signature_attempt", "another original attempt", 1, 0),
            ("dispatcher_signature_subject", "signature subject differs", 1, 0),
            ("dispatcher_signature_digest", "signature subject differs", 1, 0),
            ("start_signature_attempt", "another original run attempt", 1, 1),
            ("start_signature_subject", "start signature subject differs", 1, 1),
            ("start_signature_digest", "start signature subject differs", 1, 1),
        )
        for probe, reason, dispatcher_signatures, start_signatures in cases:
            with self.subTest(signature=probe):
                fixture = self.fixture()
                fixture.probe = probe
                self.assert_rejected(fixture, reason)
                fixture.assert_boundary(
                    self,
                    dispatcher_signatures=dispatcher_signatures,
                    start_signatures=start_signatures,
                    numeric_reads=0,
                    runtime_calls=0,
                )

    def test_dispatcher_rerun_during_start_gate_is_rejected_after_second_owner_observation(self) -> None:
        fixture = self.fixture()
        fixture.probe = "dispatcher_rerun_after_start_gate"
        self.assert_rejected(fixture, "start run was rerun, changed or did not complete successfully")
        fixture.assert_boundary(
            self, dispatcher_signatures=1, start_signatures=1, numeric_reads=2, runtime_calls=2,
        )
        self.assertEqual(fixture.api_calls.count(fixture.dispatcher_latest_path), 3)

    def test_late_change_to_each_of_the_four_selected_input_bytes_is_rejected(self) -> None:
        for field in ("record_path", "start_bundle_path", "claim_path", "claim_bundle_path"):
            with self.subTest(input=field):
                fixture = self.fixture()
                fixture.late_input_change = field
                if field == "claim_bundle_path":
                    reason = "dispatcher claim or signature differs from selected bytes"
                elif field in ("record_path", "start_bundle_path"):
                    reason = "start record or signature changed during authentication"
                else:
                    reason = "selected start, signature or claim changed during verification"
                self.assert_rejected(fixture, reason)
                fixture.assert_boundary(
                    self, dispatcher_signatures=1, start_signatures=1,
                    numeric_reads=2, runtime_calls=2,
                )
                self.assertNotEqual(fixture.input_path(field).read_bytes(), fixture.input_bytes(field))

    def test_start_inputs_changed_after_the_post_claim_gate_are_rejected_by_outer_readback(self) -> None:
        # The final dispatcher verifier consumes the captured start bytes, not
        # their original paths. Only the composition's final readback closes a
        # change to those paths during that final signature verification.
        for field in ("record_path", "start_bundle_path"):
            with self.subTest(input=field):
                fixture = self.fixture()
                fixture.late_final_start_change = field
                self.assert_rejected(
                    fixture, "candidate start, claim or signature changed during authentication")
                fixture.assert_boundary(
                    self, dispatcher_signatures=2, start_signatures=1,
                    numeric_reads=2, runtime_calls=2,
                )
                self.assertNotEqual(fixture.input_path(field).read_bytes(), fixture.input_bytes(field))

    def test_source_dispatcher_and_job_selections_are_rejoined_after_both_gates(self) -> None:
        cases = (
            ("source_context", "start record context differs from independent source selection"),
            ("dispatcher_context", "claim payload differs from the exact selected start and dispatcher"),
            ("dispatcher_job", "claim payload differs from the exact selected start and dispatcher"),
        )
        for selected, reason in cases:
            with self.subTest(selection=selected):
                fixture = self.fixture()
                fixture.late_context_change = selected
                self.assert_rejected(fixture, reason)
                self.assertEqual(
                    fixture.signature_purposes,
                    [CLAIM_SIGNATURE, START_SIGNATURE, CLAIM_SIGNATURE],
                )
                fixture.assert_boundary(
                    self, dispatcher_signatures=2, start_signatures=1,
                    numeric_reads=2, runtime_calls=2,
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
