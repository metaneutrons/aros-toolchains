#!/usr/bin/env python3
"""Offline tests for the inactive dispatcher identity authentication boundary.

Every provider and OIDC transport is replaced with a deterministic fixture.
These tests exercise local joins only; they do not prove live OIDC issuance,
workflow eligibility, provider permissions, or production behavior.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import os
from pathlib import Path
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


start_tests = load_module(
    "compiler_sdk_release_start_auth_fixture_v2",
    SOURCE_ROOT / "scripts/toolchain/tests/test-compiler-sdk-release-start-v2.py",
)
auth = load_module(
    "compiler_sdk_dispatcher_auth_v2",
    SOURCE_ROOT / "scripts/toolchain/compiler-sdk-dispatcher-auth-v2.py",
)

START = auth.START
ORIGIN = auth.ORIGIN
UPLOAD = auth.UPLOAD
CLAIM = auth.CLAIM
REPOSITORY = start_tests.REPOSITORY
MAIN = start_tests.MAIN
SOURCE_RUN_ID = start_tests.RUN_ID
OWN_RUN_ID = SOURCE_RUN_ID + 1
OWN_COMMIT = "9" * 40
OWN_JOB_ID = 90902
OWN_CHECK_ID = 555002
SOURCE_JOB_ID = start_tests.JOB_ID
SOURCE_CHECK_ID = start_tests.CHECK_RUN_ID
AUTH_ERRORS = (START.StartError, ORIGIN.OriginError, START.ADMISSION.AdmissionError)


def event_fixture(source: dict) -> dict:
    return {
        "action": "completed",
        "repository": {
            "id": source["repository_id"],
            "full_name": source["repository"],
        },
        "workflow_run": {
            "id": source["run_id"],
            "run_attempt": source["run_attempt"],
            "head_sha": source["producer_commit"],
            "head_branch": "main",
            "event": "workflow_run",
            "status": "completed",
            "conclusion": "success",
            "head_repository": {
                "id": source["repository_id"],
                "full_name": source["repository"],
            },
        },
    }


def provider_run(context: dict, *, event: str = "workflow_run",
                 status: str = "completed", conclusion: str | None = "success",
                 path: str | None = None, head_repository: dict | None = None,
                 head_branch: str = "main", head_sha: str | None = None,
                 run_attempt: int | None = None) -> dict:
    return {
        "id": context["run_id"],
        "run_attempt": context["run_attempt"] if run_attempt is None else run_attempt,
        "head_sha": context["producer_commit"] if head_sha is None else head_sha,
        "head_branch": head_branch,
        "path": (f'{context["workflow"]}@{context["source_ref"]}'
                 if path is None else path),
        "head_repository": (head_repository if head_repository is not None else {
            "id": context["repository_id"], "full_name": context["repository"],
        }),
        "event": event,
        "status": status,
        "conclusion": conclusion,
    }


def latest_run(context: dict, *, status: str, conclusion: str | None,
               run_attempt: int | None = None, head_sha: str | None = None) -> dict:
    return {
        "id": context["run_id"],
        "run_attempt": context["run_attempt"] if run_attempt is None else run_attempt,
        "head_sha": context["producer_commit"] if head_sha is None else head_sha,
        "status": status,
        "conclusion": conclusion,
    }


def owning_job(context: dict, *, job_id: int = OWN_JOB_ID,
               check_id: int = OWN_CHECK_ID, name: str = CLAIM.JOB,
               status: str = "in_progress", conclusion: str | None = None,
               run_attempt: int = 1) -> dict:
    return {
        "id": job_id,
        "check_run_url": (
            f'https://api.github.com/repos/{context["repository"]}/check-runs/{check_id}'
        ),
        "name": name,
        "head_sha": context["producer_commit"],
        "run_id": context["run_id"],
        "run_attempt": run_attempt,
        "status": status,
        "conclusion": conclusion,
    }


class AuthenticationHarness:
    """Real bounded event file plus mocked provider and OIDC boundaries."""

    def __init__(self, root: Path):
        self.root = root.resolve()
        self.source = start_tests.context()
        self.context = {
            "repository": self.source["repository"],
            "repository_id": self.source["repository_id"],
            # Dispatcher code runs on main independently of the producer commit.
            "producer_commit": OWN_COMMIT,
            "source_ref": MAIN,
            "workflow": CLAIM.WORKFLOW,
            "run_id": OWN_RUN_ID,
            "run_attempt": 1,
        }
        self.event_path = (self.root / "event.json").resolve()
        self.set_event(event_fixture(self.source))
        self.environment = {
            "GITHUB_REPOSITORY": self.context["repository"],
            "GITHUB_REPOSITORY_ID": str(self.context["repository_id"]),
            "GITHUB_SHA": self.context["producer_commit"],
            "GITHUB_REF": self.context["source_ref"],
            "GITHUB_RUN_ID": str(self.context["run_id"]),
            "GITHUB_RUN_ATTEMPT": str(self.context["run_attempt"]),
            "GITHUB_EVENT_NAME": "workflow_run",
            "GITHUB_EVENT_PATH": str(self.event_path),
        }
        self.api_calls: list[str] = []
        self.api_counts: dict[str, int] = {}
        self.metadata_calls: list[str] = []
        self.metadata_counts: dict[str, int] = {}
        self.oidc_calls: list[tuple[dict, str]] = []
        self.event_reads: list[tuple[Path, str, int]] = []
        self.api_hook = None
        self.metadata_hook = None
        self.oidc_hook = None
        self.upload_transport_mock = None
        self.upload_once_mock = None

    @property
    def event_bytes(self) -> bytes:
        return self.event_path.read_bytes()

    @property
    def own_attempt_path(self) -> str:
        return (f'repos/{REPOSITORY}/actions/runs/{self.context["run_id"]}'
                f'/attempts/{self.context["run_attempt"]}')

    @property
    def source_attempt_path(self) -> str:
        return (f'repos/{REPOSITORY}/actions/runs/{self.source["run_id"]}'
                f'/attempts/{self.source["run_attempt"]}')

    @property
    def own_jobs_path(self) -> str:
        return self.own_attempt_path + "/jobs?per_page=100"

    def set_event(self, value: dict | bytes) -> None:
        if isinstance(value, bytes):
            raw = value
        else:
            raw = START.ADMISSION.canonical_json(value).encode("utf-8") + b"\n"
        self.event_path.write_bytes(raw)

    def set_source_context(self, **changes: object) -> None:
        self.source.update(changes)

    def set_environment(self, **changes: str) -> None:
        self.environment.update(changes)

    def provider_api(self, path: str, **kwargs):
        self.api_calls.append(path)
        self.api_counts[path] = self.api_counts.get(path, 0) + 1
        if kwargs:
            raise AssertionError(f"unexpected provider API options: {kwargs!r}")

        repository_path = f"repos/{REPOSITORY}"
        if path == repository_path:
            value = {
                "full_name": REPOSITORY,
                "archived": False,
                "disabled": False,
                "default_branch": "main",
            }
        elif path == self.source_attempt_path:
            value = {"status": "completed", "conclusion": "success"}
        elif path == f"repos/{REPOSITORY}/actions/runs/{self.source['run_id']}":
            value = latest_run(self.source, status="completed", conclusion="success")
        elif path == f"repos/{REPOSITORY}/actions/runs/{self.context['run_id']}":
            value = latest_run(self.context, status="in_progress", conclusion=None)
        else:
            raise AssertionError(f"unexpected provider API endpoint: {path!r}")

        value = copy.deepcopy(value)
        if self.api_hook is not None:
            value = self.api_hook(path, self.api_counts[path], value)
        return value

    def provider_metadata(self, path: str):
        self.metadata_calls.append(path)
        self.metadata_counts[path] = self.metadata_counts.get(path, 0) + 1

        if path.startswith(self.own_jobs_path + "&page="):
            value = {"total_count": 1, "jobs": [owning_job(self.context)]}
        elif path == self.own_attempt_path:
            value = provider_run(self.context, status="in_progress", conclusion=None)
        elif path == self.source_attempt_path:
            value = provider_run(self.source)
        else:
            raise AssertionError(f"unexpected fixed-metadata path: {path!r}")

        value = copy.deepcopy(value)
        if self.metadata_hook is not None:
            value = self.metadata_hook(path, self.metadata_counts[path], value)
        return value

    def oidc_check_id(self, context: dict, *, expected_event: str) -> int:
        self.oidc_calls.append((copy.deepcopy(context), expected_event))
        if self.oidc_hook is not None:
            return self.oidc_hook(context, expected_event)
        return OWN_CHECK_ID

    def authenticate(self) -> dict:
        real_read = START.ADMISSION.read_regular_file

        def tracked_read(path: Path, label: str, maximum: int) -> bytes:
            self.event_reads.append((Path(path), label, maximum))
            return real_read(path, label, maximum)

        def forbidden_transport(*args, **kwargs):
            raise AssertionError("authentication attempted an upload or live provider transport")

        with mock.patch.dict(os.environ, self.environment, clear=True), \
                mock.patch.object(START.ADMISSION, "api", side_effect=self.provider_api), \
                mock.patch.object(START.ADMISSION, "read_regular_file", side_effect=tracked_read), \
                mock.patch.object(UPLOAD, "fixed_metadata", side_effect=self.provider_metadata), \
                mock.patch.object(ORIGIN, "owning_check_id", side_effect=self.oidc_check_id), \
                mock.patch.object(UPLOAD, "gh_response", side_effect=forbidden_transport) as transport, \
                mock.patch.object(UPLOAD, "upload_claim_once", side_effect=forbidden_transport) as upload:
            self.upload_transport_mock = transport
            self.upload_once_mock = upload
            result = auth.authenticate_dispatcher(self.source)
        return result

    def assert_no_upload_or_live_transport(self, testcase: unittest.TestCase) -> None:
        testcase.assertIsNotNone(self.upload_transport_mock)
        testcase.assertIsNotNone(self.upload_once_mock)
        testcase.assertEqual(self.upload_transport_mock.call_count, 0)
        testcase.assertEqual(self.upload_once_mock.call_count, 0)


class DispatcherAuthenticationTests(unittest.TestCase):
    def harness(self, root: str) -> AuthenticationHarness:
        return AuthenticationHarness(Path(root))

    def assert_rejected(self, harness: AuthenticationHarness) -> None:
        with self.assertRaises(AUTH_ERRORS):
            harness.authenticate()
        harness.assert_no_upload_or_live_transport(self)

    def test_positive_returns_only_closed_identity_assurance_after_rechecks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.harness(directory)
            self.assertTrue(fixture.event_path.is_absolute())
            self.assertEqual(fixture.event_path, fixture.event_path.resolve())
            self.assertNotEqual(fixture.context["producer_commit"], fixture.source["producer_commit"])

            result = fixture.authenticate()

        self.assertEqual(set(result), {
            "schema", "assurance", "context", "job", "event", "trigger_context",
        })
        self.assertEqual(result, {
            "schema": auth.SCHEMA,
            "assurance": auth.ASSURANCE,
            "context": fixture.context,
            "job": {"id": OWN_JOB_ID, "check_run_id": OWN_CHECK_ID, "name": CLAIM.JOB},
            "event": "workflow_run",
            "trigger_context": fixture.source,
        })
        self.assertEqual(set(result["context"]), {
            "repository", "repository_id", "producer_commit", "source_ref",
            "workflow", "run_id", "run_attempt",
        })
        self.assertEqual(fixture.oidc_calls, [(fixture.context, "workflow_run")])
        self.assertEqual(len(fixture.event_reads), 2)
        self.assertTrue(all(path == fixture.event_path for path, _, _ in fixture.event_reads))
        self.assertTrue(all(maximum == START.ADMISSION.MAX_EVENT_BYTES
                            for _, _, maximum in fixture.event_reads))
        self.assertEqual(fixture.metadata_counts[fixture.own_attempt_path], 2)
        self.assertEqual(fixture.metadata_counts[fixture.source_attempt_path], 2)
        self.assertEqual(fixture.metadata_counts[fixture.own_jobs_path + "&page=1"], 2)
        self.assertEqual(fixture.api_counts[
            f"repos/{REPOSITORY}/actions/runs/{fixture.context['run_id']}"], 2)
        self.assertEqual(fixture.api_counts[fixture.source_attempt_path], 2)
        fixture.assert_no_upload_or_live_transport(self)

    def test_rejects_malformed_causal_events_and_fork_identity(self) -> None:
        cases = {
            "wrong action": lambda value: value.update(action="requested"),
            "outer repository id": lambda value: value["repository"].update(id=123),
            "outer repository fork": lambda value: value["repository"].update(
                full_name="someone/aros-toolchains"),
            "source run id": lambda value: value["workflow_run"].update(id=SOURCE_RUN_ID + 10),
            "source attempt": lambda value: value["workflow_run"].update(run_attempt=2),
            "source head": lambda value: value["workflow_run"].update(head_sha="8" * 40),
            "source branch": lambda value: value["workflow_run"].update(head_branch="release"),
            "source event": lambda value: value["workflow_run"].update(event="push"),
            "source status": lambda value: value["workflow_run"].update(status="queued"),
            "source conclusion": lambda value: value["workflow_run"].update(conclusion="failure"),
            "head repository id": lambda value: value["workflow_run"]["head_repository"].update(id=123),
            "head repository fork": lambda value: value["workflow_run"]["head_repository"].update(
                full_name="someone/aros-toolchains"),
        }
        for label, mutate in cases.items():
            with self.subTest(case=label), tempfile.TemporaryDirectory() as directory:
                fixture = self.harness(directory)
                selected = event_fixture(fixture.source)
                mutate(selected)
                fixture.set_event(selected)
                self.assert_rejected(fixture)

    def test_boolean_provider_ids_are_not_accepted_as_integers(self) -> None:
        fields = (
            ("repository", "id"),
            ("workflow_run", "id"),
            ("workflow_run", "run_attempt"),
            ("workflow_run", "head_repository", "id"),
        )
        for path in fields:
            with self.subTest(path=path), tempfile.TemporaryDirectory() as directory:
                fixture = self.harness(directory)
                selected = event_fixture(fixture.source)
                target = selected
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = True
                fixture.set_event(selected)
                self.assert_rejected(fixture)

    def test_rejects_invalid_event_bytes_and_oversized_event(self) -> None:
        for raw in (b"{broken json", b'{"action":"completed","action":"completed"}'):
            with self.subTest(raw=raw), tempfile.TemporaryDirectory() as directory:
                fixture = self.harness(directory)
                fixture.set_event(raw)
                self.assert_rejected(fixture)

        with tempfile.TemporaryDirectory() as directory:
            fixture = self.harness(directory)
            fixture.set_event(b" " * (START.ADMISSION.MAX_EVENT_BYTES + 1))
            self.assert_rejected(fixture)

    def test_rejects_wrong_invocation_event_ref_run_or_source_workflow(self) -> None:
        env_cases = {
            "non-workflow-run trigger": {"GITHUB_EVENT_NAME": "push"},
            "non-main dispatcher": {"GITHUB_REF": "refs/heads/release"},
            "dispatcher rerun": {"GITHUB_RUN_ATTEMPT": "2"},
            "same run as source": {"GITHUB_RUN_ID": str(SOURCE_RUN_ID)},
            "different repository": {"GITHUB_REPOSITORY": "someone/aros-toolchains"},
        }
        for label, changes in env_cases.items():
            with self.subTest(case=label), tempfile.TemporaryDirectory() as directory:
                fixture = self.harness(directory)
                fixture.set_environment(**changes)
                self.assert_rejected(fixture)

        with tempfile.TemporaryDirectory() as directory:
            fixture = self.harness(directory)
            fixture.set_source_context(workflow=".github/workflows/other.yml")
            self.assert_rejected(fixture)

    def test_rejects_original_provider_workflow_mismatch_and_unhealthy_repository(self) -> None:
        cases = {
            "original run workflow differs": lambda path, count, value: {
                **value, "path": ".github/workflows/other.yml@refs/heads/main",
            } if path == fixture.source_attempt_path else value,
            "original run event differs": lambda path, count, value: {
                **value, "event": "push",
            } if path == fixture.source_attempt_path else value,
        }
        for label, hook in cases.items():
            with self.subTest(case=label), tempfile.TemporaryDirectory() as directory:
                fixture = self.harness(directory)
                fixture.metadata_hook = hook
                self.assert_rejected(fixture)

        for field, value in (("archived", True), ("disabled", True),
                             ("default_branch", "release"), ("full_name", "fork/repo")):
            with self.subTest(repository_field=field), tempfile.TemporaryDirectory() as directory:
                fixture = self.harness(directory)
                def change_repository(path, count, response, selected=field, changed=value):
                    if path == f"repos/{REPOSITORY}":
                        response[selected] = changed
                    return response
                fixture.api_hook = change_repository
                self.assert_rejected(fixture)

    def test_rejects_missing_oidc_selected_job_and_provider_failures(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.harness(directory)
            fixture.metadata_hook = lambda path, count, value: (
                {"total_count": 1, "jobs": [owning_job(fixture.context, check_id=OWN_CHECK_ID + 1)]}
                if path.startswith(fixture.own_jobs_path + "&page=") else value
            )
            self.assert_rejected(fixture)

        with tempfile.TemporaryDirectory() as directory:
            fixture = self.harness(directory)
            fixture.api_hook = lambda path, count, value: (
                {**value, "status": "failure", "conclusion": "failure"}
                if path == fixture.source_attempt_path else value
            )
            self.assert_rejected(fixture)

        with tempfile.TemporaryDirectory() as directory:
            fixture = self.harness(directory)
            fixture.metadata_hook = lambda path, count, value: (
                {"total_count": 1, "jobs": [owning_job(
                    fixture.context, status="completed", conclusion="failure")]}
                if path.startswith(fixture.own_jobs_path + "&page=") else value
            )
            self.assert_rejected(fixture)

    def test_rechecks_event_own_run_source_run_and_owning_job(self) -> None:
        cases = ("mutated event", "late dispatcher run", "late source run",
                 "late source provider event", "late dispatcher job")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                fixture = self.harness(directory)
                if case == "mutated event":
                    def mutate_event(context, expected_event):
                        fixture.event_path.write_bytes(fixture.event_bytes + b" ")
                        return OWN_CHECK_ID
                    fixture.oidc_hook = mutate_event
                elif case == "late dispatcher run":
                    def changed_dispatcher(path, count, value):
                        if path == f"repos/{REPOSITORY}/actions/runs/{fixture.context['run_id']}" \
                                and count == 2:
                            value["run_attempt"] = 2
                        return value
                    fixture.api_hook = changed_dispatcher
                elif case == "late source run":
                    def changed_source(path, count, value):
                        if path == fixture.source_attempt_path and count == 2:
                            value["status"] = "failure"
                            value["conclusion"] = "failure"
                        return value
                    fixture.api_hook = changed_source
                elif case == "late source provider event":
                    def changed_source_event(path, count, value):
                        if path == fixture.source_attempt_path and count == 2:
                            value["event"] = "push"
                        return value
                    fixture.metadata_hook = changed_source_event
                else:
                    def changed_job(path, count, value):
                        if path.startswith(fixture.own_jobs_path + "&page=") and count == 2:
                            value["jobs"][0]["id"] += 1
                        return value
                    fixture.metadata_hook = changed_job
                self.assert_rejected(fixture)
                if case == "mutated event":
                    self.assertEqual(len(fixture.event_reads), 2)


class ProviderJsonTests(unittest.TestCase):
    def pagination_path(self, run_id: int = OWN_RUN_ID, attempt: int = 1) -> str:
        return (f"repos/{REPOSITORY}/actions/runs/{run_id}/attempts/{attempt}"
                "/jobs?per_page=100")

    @staticmethod
    def job(identity: int) -> dict:
        return {"id": identity}

    def call_with_pages(self, path: str, pages: list[dict]) -> tuple[object, list[str]]:
        calls: list[str] = []

        def fixed_metadata(selected: str):
            calls.append(selected)
            page_number = int(selected.rsplit("=", 1)[1])
            if page_number > len(pages):
                raise AssertionError(f"unexpected extra provider page: {selected}")
            return copy.deepcopy(pages[page_number - 1])

        with mock.patch.object(UPLOAD, "fixed_metadata", side_effect=fixed_metadata):
            result = auth.provider_json(["api", "--paginate", "--slurp", path])
        return result, calls

    def assert_provider_rejected(self, arguments: list[str], *, should_not_call_metadata: bool = True) -> None:
        with mock.patch.object(UPLOAD, "fixed_metadata") as fixed:
            with self.assertRaises(AUTH_ERRORS):
                auth.provider_json(arguments)
        if should_not_call_metadata:
            fixed.assert_not_called()

    def test_manual_pagination_accepts_exactly_two_complete_pages(self) -> None:
        jobs = [self.job(identity) for identity in range(1, 102)]
        pages = [
            {"total_count": 101, "jobs": jobs[:100]},
            {"total_count": 101, "jobs": jobs[100:]},
        ]
        result, calls = self.call_with_pages(self.pagination_path(), pages)
        self.assertEqual(len(result), 2)
        self.assertEqual(calls, [
            self.pagination_path() + "&page=1",
            self.pagination_path() + "&page=2",
        ])
        self.assertEqual(result[0]["jobs"][0]["id"], 1)
        self.assertEqual(result[1]["jobs"][0]["id"], 101)

    def test_manual_pagination_rejects_changed_totals_duplicate_ids_and_empty_truncation(self) -> None:
        jobs = [self.job(identity) for identity in range(1, 101)]
        cases = {
            "changed totals": [
                {"total_count": 101, "jobs": jobs},
                {"total_count": 102, "jobs": [self.job(101)]},
            ],
            "duplicate job ids": [
                {"total_count": 101, "jobs": jobs},
                {"total_count": 101, "jobs": [self.job(1)]},
            ],
            "empty truncation": [{"total_count": 1, "jobs": []}],
        }
        for label, pages in cases.items():
            with self.subTest(case=label):
                calls: list[str] = []
                def fixed_metadata(selected: str):
                    calls.append(selected)
                    index = int(selected.rsplit("=", 1)[1]) - 1
                    return copy.deepcopy(pages[index])
                with mock.patch.object(UPLOAD, "fixed_metadata", side_effect=fixed_metadata):
                    with self.assertRaises(AUTH_ERRORS):
                        auth.provider_json(["api", "--paginate", "--slurp", self.pagination_path()])
                self.assertGreaterEqual(len(calls), 1)

    def test_manual_pagination_rejects_oversized_pages(self) -> None:
        page = {"total_count": 101, "jobs": [self.job(identity) for identity in range(1, 102)]}
        with mock.patch.object(UPLOAD, "fixed_metadata", return_value=page) as fixed:
            with self.assertRaises(AUTH_ERRORS):
                auth.provider_json(["api", "--paginate", "--slurp", self.pagination_path()])
        fixed.assert_called_once_with(self.pagination_path() + "&page=1")

    def test_provider_selectors_are_fixed_to_run_attempt_endpoints(self) -> None:
        other_repo = self.pagination_path().replace(REPOSITORY, "someone/project")
        for path in (
            other_repo,
            f"repos/{REPOSITORY}/releases/1",
            self.pagination_path(attempt=0),
            self.pagination_path().replace("/attempts/1/", "/attempts/01/"),
            self.pagination_path().replace("/attempts/1/", "/attempts/1/attempts/2/"),
        ):
            with self.subTest(path=path):
                self.assert_provider_rejected(["api", "--paginate", "--slurp", path])

        # Job enumeration must remain bound to one explicit run attempt.
        without_attempt = f"repos/{REPOSITORY}/actions/runs/{OWN_RUN_ID}/jobs?per_page=100"
        with mock.patch.object(UPLOAD, "fixed_metadata", return_value={
                "total_count": 1, "jobs": [self.job(1)]}) as fixed:
            with self.assertRaises(AUTH_ERRORS):
                auth.provider_json(["api", "--paginate", "--slurp", without_attempt])
        fixed.assert_not_called()

        direct_job_list = self.pagination_path()
        self.assert_provider_rejected(["api", direct_job_list])

    def test_provider_json_rejects_caller_supplied_input_flags(self) -> None:
        path = self.pagination_path()
        rejected = (
            ["api", path, "--method", "GET"],
            ["api", "--paginate", "--slurp", path, "--method", "POST"],
            ["api", "--paginate", "--slurp", path + "&page=2"],
            ["api", "--paginate", path],
            ["api", "--hostname", "github.example", path],
        )
        for arguments in rejected:
            with self.subTest(arguments=arguments):
                self.assert_provider_rejected(arguments)

    def test_direct_attempt_observation_uses_only_fixed_metadata_get(self) -> None:
        path = (f"repos/{REPOSITORY}/actions/runs/{OWN_RUN_ID}/attempts/1")
        expected = {"id": OWN_RUN_ID, "run_attempt": 1, "event": "workflow_run"}
        with mock.patch.object(UPLOAD, "fixed_metadata", return_value=expected) as fixed:
            self.assertEqual(auth.provider_json(["api", path]), expected)
        fixed.assert_called_once_with(path)


class ObserveDispatcherTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source = start_tests.context()
        self.context = {
            "repository": self.source["repository"],
            "repository_id": self.source["repository_id"],
            "producer_commit": OWN_COMMIT,
            "source_ref": MAIN,
            "workflow": CLAIM.WORKFLOW,
            "run_id": OWN_RUN_ID,
            "run_attempt": 1,
        }

    def test_observe_dispatcher_joins_exact_attempt_and_current_execution(self) -> None:
        provider_calls: list[list[str]] = []
        api_calls: list[str] = []

        def provider(arguments: list[str], purpose: str = "provider observation"):
            provider_calls.append(list(arguments))
            return provider_run(self.context, status="in_progress", conclusion=None)

        def api(path: str, **kwargs):
            api_calls.append(path)
            self.assertEqual(kwargs, {})
            return latest_run(self.context, status="in_progress", conclusion=None)

        with mock.patch.object(ORIGIN, "gh_json", side_effect=provider), \
                mock.patch.object(START.ADMISSION, "api", side_effect=api):
            auth.observe_dispatcher(self.context)

        self.assertEqual(provider_calls, [[
            "api", f"repos/{REPOSITORY}/actions/runs/{OWN_RUN_ID}/attempts/1",
        ]])
        self.assertEqual(api_calls, [f"repos/{REPOSITORY}/actions/runs/{OWN_RUN_ID}"])

    def test_observe_dispatcher_rejects_wrong_provider_event_and_latest_run_state(self) -> None:
        event_cases = (
            {"event": "push"},
            {"head_sha": "8" * 40},
            {"head_branch": "release"},
            {"path": ".github/workflows/other.yml@refs/heads/main"},
            {"head_repository": {"id": 1, "full_name": "fork/repo"}},
        )
        for changes in event_cases:
            with self.subTest(provider_event=changes):
                observed = provider_run(self.context, status="in_progress", conclusion=None)
                observed.update(changes)
                with mock.patch.object(ORIGIN, "gh_json", return_value=observed), \
                        mock.patch.object(START.ADMISSION, "api") as api:
                    with self.assertRaises(AUTH_ERRORS):
                        auth.observe_dispatcher(self.context)
                api.assert_not_called()

        latest_cases = (
            {"run_attempt": 2},
            {"head_sha": "8" * 40},
            {"status": "completed", "conclusion": "success"},
            {"status": "in_progress", "conclusion": "failure"},
        )
        for changes in latest_cases:
            with self.subTest(latest_run=changes):
                observed = latest_run(self.context, status="in_progress", conclusion=None)
                observed.update(changes)
                with mock.patch.object(ORIGIN, "gh_json", return_value=provider_run(
                        self.context, status="in_progress", conclusion=None)), \
                        mock.patch.object(START.ADMISSION, "api", return_value=observed):
                    with self.assertRaises(AUTH_ERRORS):
                        auth.observe_dispatcher(self.context)


if __name__ == "__main__":
    unittest.main(verbosity=2)
