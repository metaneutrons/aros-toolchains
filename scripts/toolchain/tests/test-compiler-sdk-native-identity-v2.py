#!/usr/bin/env python3
"""Offline tests for the inactive native execution identity gate.

The real identity, event, OIDC-claim, run-attempt, latest-run and job-join
helpers execute. Only the authenticated OIDC HTTPS issuer and fixed-host
provider GET boundary are deterministic fixtures. The claim and prior
candidate-authentication result are synthetic caller-authenticated inputs;
these tests establish no signature, live provider, or workflow qualification.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from urllib.parse import parse_qs, urlsplit
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


start_tests = load(
    "native_identity_start_fixtures_v2",
    ROOT / "scripts/toolchain/tests/test-compiler-sdk-release-start-v2.py",
)
identity = load(
    "compiler_sdk_native_identity_v2",
    ROOT / "scripts/toolchain/compiler-sdk-native-identity-v2.py",
)
START = identity.START
UPLOAD = identity.UPLOAD
CLAIM = identity.CLAIM
ORIGIN = identity.ORIGIN
AUTH = identity.AUTH
ERRORS = (START.StartError, ORIGIN.OriginError, START.ADMISSION.AdmissionError)


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


class OIDCResponse:
    def __init__(self, raw: bytes):
        self.raw = raw

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, limit: int) -> bytes:
        return self.raw[:limit]


class OIDCOpener:
    def __init__(self, harness):
        self.harness = harness

    def open(self, request, timeout: int):
        self.harness.oidc_requests.append((request, timeout))
        parsed = urlsplit(request.full_url)
        self.harness.oidc_query = parse_qs(parsed.query)
        self.harness.oidc_authorization = request.get_header("Authorization")
        claims = self.harness.oidc_claims()
        if self.harness.probe == "oidc_wrong_event":
            claims["event_name"] = "workflow_run"
        if self.harness.probe == "oidc_wrong_runner_environment":
            claims["runner_environment"] = "self-hosted"
        header = {"alg": "RS256", "typ": "JWT"}
        token = ".".join((b64url(json.dumps(header).encode()),
                          b64url(json.dumps(claims).encode()), "fixture-signature"))
        return OIDCResponse(json.dumps({"value": token}).encode())


class NativeIdentityFixture:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.record, self.source, _ = start_tests.record_fixture()
        self.tag = copy.deepcopy(self.record["tag"])
        self.draft = copy.deepcopy(self.record["draft"])
        self.dispatcher = {
            "repository": self.source["repository"],
            "repository_id": self.source["repository_id"],
            "producer_commit": "9" * 40,
            "source_ref": START.ADMISSION.MAIN_REF,
            "workflow": CLAIM.WORKFLOW,
            "run_id": self.source["run_id"] + 1,
            "run_attempt": 1,
        }
        self.dispatcher_job = {
            "id": start_tests.JOB_ID + 1,
            "check_run_id": start_tests.CHECK_RUN_ID + 1,
            "name": CLAIM.JOB,
        }
        self.bundle = b"synthetic start signature bundle\n"
        self.claim_raw = CLAIM.claim_bytes(
            (START.ADMISSION.canonical_json(self.record) + "\n").encode("ascii"),
            self.bundle,
            source_context=self.source,
            dispatcher_context=self.dispatcher,
            dispatcher_job=self.dispatcher_job,
            dispatcher_event="workflow_run",
            trigger_context=self.source,
        )
        self.claim = START.ADMISSION.parse_json(self.claim_raw, "fixture claim")
        self.native_context = {
            "repository": self.source["repository"],
            "repository_id": self.source["repository_id"],
            "producer_commit": self.tag["commit"],
            "source_ref": f'refs/tags/{self.tag["name"]}',
            "workflow": CLAIM.NATIVE_WORKFLOW,
            "run_id": self.source["run_id"] + 2,
            "run_attempt": 1,
        }
        asset_id = 887766
        self.candidate_authentication = {
            "schema": "aros-toolchains-native-candidate-authentication-v2",
            "assurance": "authenticated-candidate-only-not-native-dispatch-or-qualification",
            "authenticated_candidate_only": {
                "tag_name": self.tag["name"],
                "commit": self.tag["commit"],
                "draft_id": self.draft["id"],
                "claim_asset": {
                    "id": asset_id,
                    "name": CLAIM.CLAIM_NAME,
                    "size": len(self.claim_raw),
                    "sha256": sha256(self.claim_raw),
                },
            },
            "limitations": [
                "does not authenticate the actual native workflow_dispatch event or OIDC identity",
                "does not establish a signed native dispatch-run binding",
                "does not provide durable exclusive claim consumption",
                "does not authorize dispatch or qualify a release",
            ],
        }
        self.event_path = (self.root / "event.json").resolve()
        self.set_event()
        self.environment = {
            "GH_HOST": "github.com",
            "GH_TOKEN": "synthetic-job-token",
            "GITHUB_REPOSITORY": self.native_context["repository"],
            "GITHUB_REPOSITORY_ID": str(self.native_context["repository_id"]),
            "GITHUB_SHA": self.native_context["producer_commit"],
            "GITHUB_REF": self.native_context["source_ref"],
            "GITHUB_RUN_ID": str(self.native_context["run_id"]),
            "GITHUB_RUN_ATTEMPT": str(self.native_context["run_attempt"]),
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_EVENT_PATH": str(self.event_path),
            "GITHUB_WORKFLOW": identity.NATIVE_WORKFLOW_NAME,
            "ACTIONS_ID_TOKEN_REQUEST_URL": "https://oidc.actions.githubusercontent.com/",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "synthetic-oidc-request-token",
        }
        self.probe: str | None = None
        self.api_calls: list[str] = []
        self.metadata_calls: list[str] = []
        self.latest_calls = 0
        self.attempt_calls = 0
        self.jobs_calls = 0
        self.oidc_requests: list[tuple[object, int]] = []
        self.oidc_query: dict[str, list[str]] = {}
        self.oidc_authorization: str | None = None
        self.stack = None

    @property
    def repository(self) -> str:
        return self.source["repository"]

    @property
    def own_attempt(self) -> str:
        return (f'repos/{self.repository}/actions/runs/{self.native_context["run_id"]}'
                f'/attempts/{self.native_context["run_attempt"]}')

    @property
    def own_jobs(self) -> str:
        return self.own_attempt + "/jobs?per_page=100"

    def set_event(self, *, ref: str | None = None, repository: dict | None = None,
                  workflow: str | None = None) -> None:
        value = {
            "inputs": {},
            "ref": ref if ref is not None else f'refs/tags/{self.tag["name"]}',
            "repository": repository if repository is not None else {
                "id": self.source["repository_id"], "full_name": self.repository,
            },
            "sender": {"login": "fixture"},
            "workflow": workflow if workflow is not None else identity.NATIVE_WORKFLOW_NAME,
        }
        self.event_path.write_bytes((START.ADMISSION.canonical_json(value) + "\n").encode())

    def oidc_claims(self) -> dict:
        now = int(ORIGIN.time.time())
        context = self.native_context
        return {
            "iss": "https://token.actions.githubusercontent.com",
            "aud": ORIGIN.AUDIENCE,
            "event_name": "workflow_dispatch",
            "repository": context["repository"],
            "sha": context["producer_commit"],
            "ref": context["source_ref"],
            "workflow_ref": f'{context["repository"]}/{context["workflow"]}@{context["source_ref"]}',
            "workflow_sha": context["producer_commit"],
            "runner_environment": "github-hosted",
            "repository_id": context["repository_id"],
            "run_id": context["run_id"],
            "run_attempt": context["run_attempt"],
            "check_run_id": 555099,
            "iat": now,
            "nbf": now - 1,
            "exp": now + 600,
        }

    def provider_run(self, *, event: str = "workflow_dispatch", attempt: int | None = None) -> dict:
        context = self.native_context
        suffix = context["source_ref"].split("/", 2)[2]
        return {
            "id": context["run_id"],
            "run_attempt": context["run_attempt"] if attempt is None else attempt,
            "head_sha": context["producer_commit"],
            "head_branch": suffix,
            "path": f'{context["workflow"]}@{context["source_ref"]}',
            "head_repository": {"id": context["repository_id"], "full_name": context["repository"]},
            "event": event,
            "status": "in_progress",
            "conclusion": None,
        }

    def provider_job(self, *, name: str = identity.NATIVE_JOB,
                     labels: list[str] | None = None,
                     status: str = "in_progress", attempt: int = 1) -> dict:
        context = self.native_context
        return {
            "id": 90999,
            "check_run_url": f'https://api.github.com/repos/{context["repository"]}/check-runs/555099',
            "name": name,
            "head_sha": context["producer_commit"],
            "run_id": context["run_id"],
            "run_attempt": attempt,
            "labels": labels if labels is not None else ["ubuntu-24.04"],
            "status": status,
            "conclusion": None if status == "in_progress" else "failure",
        }

    def api(self, path: str, **kwargs):
        self.api_calls.append(path)
        if kwargs:
            raise AssertionError("unexpected provider metadata options")
        if path == f"repos/{self.repository}":
            return {"full_name": self.repository, "archived": False,
                    "disabled": False, "default_branch": "main"}
        latest_path = f'repos/{self.repository}/actions/runs/{self.native_context["run_id"]}'
        if path == latest_path:
            self.latest_calls += 1
            attempt = 2 if self.probe == "latest_rerun" and self.latest_calls >= 2 else 1
            status = "completed" if self.probe == "latest_completed" and self.latest_calls >= 2 else "in_progress"
            return {"id": self.native_context["run_id"], "run_attempt": attempt,
                    "head_sha": self.native_context["producer_commit"],
                    "status": status, "conclusion": None if status == "in_progress" else "success"}
        raise AssertionError(f"unexpected admission API endpoint: {path}")

    def fixed_metadata(self, path: str):
        self.metadata_calls.append(path)
        if path == self.own_attempt:
            self.attempt_calls += 1
            event = "push" if self.probe == "provider_wrong_event" else "workflow_dispatch"
            attempt = 2 if self.probe == "attempt_rerun" and self.attempt_calls >= 2 else 1
            return self.provider_run(event=event, attempt=attempt)
        if path.startswith(self.own_jobs + "&page="):
            self.jobs_calls += 1
            job = self.provider_job(
                name="Other job" if self.probe == "wrong_job_name" else identity.NATIVE_JOB,
                labels=["self-hosted", "ubuntu-24.04"] if self.probe == "wrong_runner" else None,
                status="completed" if self.probe == "job_completed" else "in_progress",
            )
            total = 2 if self.probe == "incomplete_jobs" else 1
            if self.probe == "event_file_drift" and self.jobs_calls == 1:
                self.event_path.write_bytes(self.event_path.read_bytes() + b" ")
            page = {"total_count": total, "jobs": [job]}
            if self.jobs_calls == 2 and self.probe == "event_path_env_drift":
                os.environ["GITHUB_EVENT_PATH"] = str(self.root / "alternate-event.json")
            if self.jobs_calls == 2 and self.probe == "workflow_display_name_drift":
                os.environ["GITHUB_WORKFLOW"] = "Changed native workflow name"
            return page
        raise AssertionError(f"unexpected fixed metadata path: {path}")

    def install(self):
        self.stack = mock.patch.dict(os.environ, self.environment, clear=True)
        self.stack.__enter__()
        self.stack2 = mock.patch.object(START.ADMISSION, "api", side_effect=self.api)
        self.stack2.__enter__()
        self.stack3 = mock.patch.object(UPLOAD, "fixed_metadata", side_effect=self.fixed_metadata)
        self.stack3.__enter__()
        self.stack4 = mock.patch.object(
            ORIGIN.urllib.request, "build_opener", side_effect=lambda *_args: OIDCOpener(self),
        )
        self.stack4.__enter__()

    def close(self):
        if self.stack4:
            self.stack4.__exit__(None, None, None)
            self.stack3.__exit__(None, None, None)
            self.stack2.__exit__(None, None, None)
            self.stack.__exit__(None, None, None)

    def authenticate(self):
        return identity.authenticate_native_execution(self.claim, self.candidate_authentication)


class NativeIdentityTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        fixture = NativeIdentityFixture(Path(temporary.name))
        fixture.install()
        self.addCleanup(fixture.close)
        return fixture

    def test_valid_candidate_tag_dispatch_is_identity_only(self):
        fixture = self.fixture()
        result = fixture.authenticate()
        self.assertEqual(result, {
            "schema": "aros-toolchains-native-execution-identity-v2",
            "assurance": "native-execution-identity-only-not-consumption-or-qualification",
            "event": "workflow_dispatch",
            "context": fixture.native_context,
            "job": {
                "id": 90999, "check_run_id": 555099, "name": "Authenticate and consume compiler and SDK candidate",
                "labels": ["ubuntu-24.04"],
            },
            "candidate_identity": {
                "tag_name": fixture.tag["name"], "commit": fixture.tag["commit"],
                "draft_id": fixture.draft["id"], "claim_asset_id": 887766,
            },
            "limitations": [
                "claim authenticity must be established independently by the original-dispatcher signature gate",
                "candidate authenticity must be established independently by the native-candidate gate",
                "does not authenticate a signed native dispatch-run binding",
                "does not provide durable exclusive claim consumption",
                "does not authorize fan-out, dispatch or release qualification",
            ],
        })
        self.assertNotIn("release_authority", result)
        self.assertEqual(fixture.oidc_query, {"audience": [ORIGIN.AUDIENCE]})
        self.assertEqual(fixture.oidc_authorization, "bearer synthetic-oidc-request-token")
        self.assertEqual(len(fixture.oidc_requests), 1)
        self.assertEqual(fixture.api_calls.count(f"repos/{fixture.repository}"), 2)
        self.assertEqual(fixture.latest_calls, 2)
        self.assertEqual(fixture.attempt_calls, 2)
        self.assertEqual(fixture.jobs_calls, 2)
        self.assertTrue(all("/attempts/1/jobs?per_page=100&page=1" in path
                            for path in fixture.metadata_calls if "/jobs?" in path))

    def test_rejects_wrong_runner_ref_sha_repository_attempt_and_event_before_oidc(self):
        cases = {
            "branch": {"GITHUB_REF": "refs/heads/main"},
            "wrong_sha": {"GITHUB_SHA": "8" * 40},
            "wrong_repository": {"GITHUB_REPOSITORY": "other/repository"},
            "wrong_repository_id": {"GITHUB_REPOSITORY_ID": "1234"},
            "attempt_two": {"GITHUB_RUN_ATTEMPT": "2"},
            "wrong_event": {"GITHUB_EVENT_NAME": "push"},
        }
        for name, values in cases.items():
            with self.subTest(name=name):
                fixture = self.fixture()
                os.environ.update(values)
                with self.assertRaises(ERRORS):
                    fixture.authenticate()
                self.assertEqual(fixture.oidc_requests, [])
                self.assertEqual(fixture.metadata_calls, [])

    def test_rejects_source_or_dispatcher_run_reuse(self):
        for reused in (start_tests.RUN_ID, start_tests.RUN_ID + 1):
            with self.subTest(reused=reused):
                fixture = self.fixture()
                os.environ["GITHUB_RUN_ID"] = str(reused)
                with self.assertRaises(ERRORS):
                    fixture.authenticate()
                self.assertEqual(fixture.oidc_requests, [])
                self.assertEqual(fixture.api_calls, [])

    def test_rejects_wrong_event_payload_ref_repository_and_workflow(self):
        cases = {
            "ref": {"ref": "refs/tags/v9.9.9"},
            "repository": {"repository": {"id": start_tests.REPOSITORY_ID + 1,
                                             "full_name": fixture_repo()}},
            "repository_bool_id": {"repository": {"id": True, "full_name": fixture_repo()}},
            "workflow": {"workflow": False},
        }
        for name, values in cases.items():
            with self.subTest(name=name):
                fixture = self.fixture()
                fixture.set_event(**values)
                with self.assertRaises(ERRORS):
                    fixture.authenticate()
                self.assertEqual(fixture.oidc_requests, [])
                self.assertEqual(fixture.api_calls, [])

    def test_payload_request_forms_do_not_replace_oidc_and_provider_workflow_identity(self):
        for ref in ("v1.2.3", "refs/tags/v1.2.3"):
            with self.subTest(ref=ref):
                fixture = self.fixture()
                fixture.set_event(ref=ref, workflow=CLAIM.NATIVE_WORKFLOW)
                result = fixture.authenticate()
                self.assertEqual(result["context"]["source_ref"], "refs/tags/v1.2.3")
                self.assertEqual(result["context"]["workflow"], CLAIM.NATIVE_WORKFLOW)
                self.assertEqual(len(fixture.oidc_requests), 1)

    def test_rejects_bad_oidc_provider_run_and_incomplete_or_wrong_job(self):
        cases = ("oidc_wrong_event", "provider_wrong_event", "attempt_rerun",
                 "incomplete_jobs", "wrong_job_name", "wrong_runner", "job_completed")
        for probe in cases:
            with self.subTest(probe=probe):
                fixture = self.fixture()
                fixture.probe = probe
                with self.assertRaises(ERRORS):
                    fixture.authenticate()
                if probe.startswith("oidc"):
                    self.assertEqual(fixture.metadata_calls, [])
                else:
                    self.assertGreaterEqual(len(fixture.metadata_calls), 1)

    def test_rejects_non_hosted_oidc_runner_even_when_provider_labels_are_plausible(self):
        fixture = self.fixture()
        fixture.probe = "oidc_wrong_runner_environment"
        self.assertEqual(fixture.provider_job()["labels"], ["ubuntu-24.04"])
        with self.assertRaisesRegex(ORIGIN.OriginError, "OIDC workflow/source/runner binding differs"):
            fixture.authenticate()
        self.assertEqual(len(fixture.oidc_requests), 1)
        self.assertEqual(fixture.metadata_calls, [])

    def test_rechecks_latest_run_and_event_file_after_provider_observation(self):
        for probe in ("latest_rerun", "latest_completed", "event_file_drift"):
            with self.subTest(probe=probe):
                fixture = self.fixture()
                fixture.probe = probe
                with self.assertRaises(ERRORS):
                    fixture.authenticate()
                if probe.startswith("latest"):
                    self.assertEqual(fixture.latest_calls, 2)
                else:
                    self.assertEqual(fixture.jobs_calls, 2)

    def test_rechecks_event_path_and_display_name_after_provider_observation(self):
        for probe in ("event_path_env_drift", "workflow_display_name_drift"):
            with self.subTest(probe=probe):
                fixture = self.fixture()
                fixture.probe = probe
                with self.assertRaisesRegex(START.StartError, "native runner environment changed"):
                    fixture.authenticate()
                self.assertEqual(fixture.jobs_calls, 2)

    def test_rejects_claim_or_candidate_projection_mismatch(self):
        cases = ("candidate_commit", "draft_id", "asset_id", "assurance",
                 "old_candidate_limitations")
        for probe in cases:
            with self.subTest(probe=probe):
                fixture = self.fixture()
                if probe == "candidate_commit":
                    fixture.candidate_authentication["authenticated_candidate_only"]["commit"] = "8" * 40
                elif probe == "draft_id":
                    fixture.candidate_authentication["authenticated_candidate_only"]["draft_id"] += 1
                elif probe == "asset_id":
                    fixture.candidate_authentication["authenticated_candidate_only"]["claim_asset"]["id"] = True
                elif probe == "assurance":
                    fixture.candidate_authentication["assurance"] = "structural-only"
                else:
                    fixture.candidate_authentication["limitations"] = [
                        "does not authenticate the actual native workflow_dispatch event or OIDC identity",
                        "does not provide durable exclusive claim consumption",
                        "does not authorize dispatch or qualify a release",
                    ]
                with self.assertRaises(ERRORS):
                    fixture.authenticate()
                self.assertEqual(fixture.api_calls, [])
                self.assertEqual(fixture.oidc_requests, [])

    def test_rejects_selected_ids_above_json_safe_integer_limit(self):
        too_large = 2**53
        cases = {
            "start_job_id": lambda fixture: fixture.claim["start"]["job"].__setitem__("id", too_large),
            "start_check_id": lambda fixture: fixture.claim["start"]["job"].__setitem__("check_run_id", too_large),
            "dispatcher_job_id": lambda fixture: fixture.claim["dispatcher"]["job"].__setitem__("id", too_large),
            "dispatcher_check_id": lambda fixture: fixture.claim["dispatcher"]["job"].__setitem__("check_run_id", too_large),
            "draft_id": lambda fixture: (
                fixture.claim["candidate"]["draft"].__setitem__("id", too_large),
                fixture.candidate_authentication["authenticated_candidate_only"].__setitem__("draft_id", too_large),
            ),
            "claim_asset_id": lambda fixture: fixture.candidate_authentication[
                "authenticated_candidate_only"]["claim_asset"].__setitem__("id", too_large),
        }
        for name, update in cases.items():
            with self.subTest(name=name):
                fixture = self.fixture()
                update(fixture)
                with self.assertRaisesRegex(ORIGIN.OriginError, "exact integer limit"):
                    fixture.authenticate()
                self.assertEqual(fixture.api_calls, [])
                self.assertEqual(fixture.oidc_requests, [])

    def test_requires_fixed_host_job_token(self):
        for key, value in (("GH_HOST", "github.example"), ("GH_TOKEN", ""),
                           ("GH_TOKEN", "   \t  ")):
            with self.subTest(key=key, value=value):
                fixture = self.fixture()
                os.environ[key] = value
                with self.assertRaises(ERRORS):
                    fixture.authenticate()
                self.assertEqual(fixture.api_calls, [])
                self.assertEqual(fixture.oidc_requests, [])

    def test_authentic_claim_and_candidate_results_cannot_be_mixed_by_tag_alone(self):
        for change in ("claim", "asset_hash", "asset_size"):
            with self.subTest(change=change):
                fixture = self.fixture()
                asset = fixture.candidate_authentication["authenticated_candidate_only"]["claim_asset"]
                if change == "claim":
                    fixture.claim["candidate"]["runtime"]["receipt_sha256"] = "e" * 64
                elif change == "asset_hash":
                    asset["sha256"] = "0" * 64
                else:
                    asset["size"] += 1
                with self.assertRaisesRegex(START.StartError, "prior authenticated asset"):
                    fixture.authenticate()
                self.assertEqual(fixture.api_calls, [])
                self.assertEqual(fixture.oidc_requests, [])


def fixture_repo() -> str:
    return "metaneutrons/aros-toolchains"


if __name__ == "__main__":
    unittest.main()
