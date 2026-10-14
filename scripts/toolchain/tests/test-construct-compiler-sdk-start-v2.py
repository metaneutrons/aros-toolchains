#!/usr/bin/env python3
"""Offline tests for the inactive protected-start record constructor.

Provider, OIDC, and publication boundaries are synthetic fixtures. Runtime
files use the bounded local fixture from the release-start tests; these tests
do not claim live provider authenticity or published-runtime authenticity.
"""

from __future__ import annotations

from collections import Counter
import copy
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import io
import json
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


release_tests = load_module(
    "compiler_sdk_release_start_test_fixtures_for_constructor",
    SOURCE_ROOT / "scripts/toolchain/tests/test-compiler-sdk-release-start-v2.py",
)
constructor = load_module(
    "construct_compiler_sdk_start_v2",
    SOURCE_ROOT / "scripts/toolchain/construct-compiler-sdk-start-v2.py",
)

START = constructor.START
ADMISSION = constructor.ADMISSION
ORIGIN = constructor.ORIGIN
RUNTIME = START.RUNTIME

REPOSITORY = release_tests.REPOSITORY
REPOSITORY_ID = release_tests.REPOSITORY_ID
COMMIT = release_tests.COMMIT
MAIN = release_tests.MAIN
WORKFLOW = START.WORKFLOW
RUN_ID = release_tests.RUN_ID
RUN_ATTEMPT = 1
JOB_ID = release_tests.JOB_ID
CHECK_RUN_ID = release_tests.CHECK_RUN_ID
CI_RUN_ID = 900
CI_ATTEMPT = 1
LOCK_PATH = release_tests.LOCK_PATH
CI_WORKFLOW = ADMISSION.CI_WORKFLOW
CI_WORKFLOW_NAME = ADMISSION.CI_WORKFLOW_NAME

ERRORS = (
    START.StartError,
    ADMISSION.AdmissionError,
    ORIGIN.OriginError,
    RUNTIME.RuntimeError,
    OSError,
)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def json_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"


class ConstructorFixture:
    """Synthetic provider and OIDC observations with real bounded local files."""

    def __init__(self, probe: str | None = None):
        self.temporary = tempfile.TemporaryDirectory(prefix="compiler-sdk-start-constructor.")
        self.root = Path(self.temporary.name).resolve()
        self.runtime = release_tests.RuntimeEvidenceFixture(self.root)
        self.record = copy.deepcopy(self.runtime.record)
        self.admission = copy.deepcopy(self.record["admission"])
        self.tag = copy.deepcopy(self.record["tag"])
        self.draft = copy.deepcopy(self.record["draft"])
        self.source = copy.deepcopy(self.record["context"])
        self.probe = probe

        self.event_path = self.root / "workflow-event.json"
        self.event_value = {
            "action": "completed",
            "repository": {"id": REPOSITORY_ID, "full_name": REPOSITORY},
            "workflow_run": {
                "id": CI_RUN_ID,
                "run_attempt": CI_ATTEMPT,
                "head_sha": COMMIT,
                "head_branch": "main",
                "head_repository": {"id": REPOSITORY_ID, "full_name": REPOSITORY},
                "event": "push",
                "name": CI_WORKFLOW_NAME,
                "path": CI_WORKFLOW,
                "status": "completed",
                "conclusion": "success",
            },
        }
        self.write_event()

        self.environment = {
            "GITHUB_REPOSITORY": REPOSITORY,
            "GITHUB_REPOSITORY_ID": str(REPOSITORY_ID),
            "GITHUB_SHA": COMMIT,
            "GITHUB_REF": MAIN,
            "GITHUB_RUN_ID": str(RUN_ID),
            "GITHUB_RUN_ATTEMPT": str(RUN_ATTEMPT),
            "GITHUB_EVENT_NAME": "workflow_run",
            "GITHUB_EVENT_PATH": str(self.event_path),
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
        }

        self.inputs = release_tests.input_bytes()
        self.inputs[LOCK_PATH] = self.runtime.lock_path.read_bytes()
        self.candidate_responses = release_tests.provider_responses(self.record)
        self.calls: dict[str, list] = {
            "api": [], "origin": [], "oidc": [], "git": [], "reads": [],
            "head": [], "clean": [], "main": [], "candidate": [], "runtime": [], "own_run": [],
        }
        self.counters: Counter[str] = Counter()
        self.blocked_calls: Counter[str] = Counter()
        self.cli_input_paths: dict[str, Path] | None = None

    def close(self) -> None:
        self.temporary.cleanup()

    def write_event(self) -> None:
        self.event_bytes = json_bytes(self.event_value)
        self.event_path.write_bytes(self.event_bytes)

    def environment_patch(self) -> dict[str, str]:
        return self.environment

    def snapshot(self) -> dict[str, bytes]:
        return {
            path.relative_to(self.root).as_posix(): path.read_bytes()
            for path in sorted(self.root.rglob("*")) if path.is_file()
        }

    def ci_run(self) -> dict:
        return {
            "id": CI_RUN_ID,
            "run_attempt": CI_ATTEMPT,
            "head_sha": COMMIT,
            "event": "push",
            "head_branch": "main",
            "head_repository": {"id": REPOSITORY_ID, "full_name": REPOSITORY},
            "name": CI_WORKFLOW_NAME,
            "path": CI_WORKFLOW,
            "status": "completed",
            "conclusion": "success",
        }

    def ci_job(self) -> dict:
        return {"id": 901, "name": ADMISSION.CI_JOB_NAME,
                "status": "completed", "conclusion": "success"}

    def ci_attempt(self) -> dict:
        return {
            "id": CI_RUN_ID,
            "run_attempt": CI_ATTEMPT,
            "head_sha": COMMIT,
            "event": "push",
            "head_branch": "main",
            "head_repository": {"id": REPOSITORY_ID, "full_name": REPOSITORY},
            "status": "completed",
            "conclusion": "success",
        }

    def own_provider_run(self) -> dict:
        value = release_tests.provider_run(self.source)
        value["status"] = "in_progress"
        value["conclusion"] = None
        if self.probe == "provider_event_wrong":
            value["event"] = "push"
        return value

    def source_job(self) -> dict:
        value = release_tests.provider_job(self.source, status="in_progress", conclusion=None)
        value["labels"] = ["ubuntu-24.04"]
        if self.probe == "job_labels_wrong":
            value["labels"] = ["self-hosted"]
        return value

    def api(self, path: str, **kwargs):
        if kwargs not in ({}, {"governance": False}):
            raise AssertionError(f"unexpected provider API options: {kwargs!r}")
        self.calls["api"].append((path, dict(kwargs)))

        if path == f"repos/{REPOSITORY}/branches/main":
            self.counters["main_api"] += 1
            sha = COMMIT
            if self.probe == "main_advanced" or (
                    self.probe == "late_main_advanced" and self.counters["main_api"] == 2):
                sha = "9" * 40
            return {"protected": True, "commit": {"sha": sha}}

        ci_listing = (
            f"repos/{REPOSITORY}/actions/workflows/ci.yml/runs?event=push&branch=main&head_sha={COMMIT}"
            "&per_page=100&page=1"
        )
        if path == ci_listing:
            self.counters["ci_list"] += 1
            value = self.ci_run()
            if self.probe == "ci_provider_commit_wrong":
                value["head_sha"] = "9" * 40
            if self.probe == "ci_provider_attempt_wrong":
                value["run_attempt"] = 2
            return {"workflow_runs": [value]}

        ci_latest = f"repos/{REPOSITORY}/actions/runs/{CI_RUN_ID}"
        if path == ci_latest:
            value = self.ci_run()
            if self.probe == "ci_latest_attempt_wrong":
                value["run_attempt"] = 2
            return value

        ci_attempt_path = f"repos/{REPOSITORY}/actions/runs/{CI_RUN_ID}/attempts/{CI_ATTEMPT}"
        if path == ci_attempt_path:
            self.counters["ci_attempt_api"] += 1
            value = self.ci_attempt()
            if self.probe == "late_ci_repo_id" and self.counters["ci_attempt_api"] == 4:
                value["head_repository"]["id"] = REPOSITORY_ID + 1
            return value

        ci_jobs = ci_attempt_path + "/jobs?per_page=100&page=1"
        if path == ci_jobs:
            return {"jobs": [self.ci_job()]}

        own_latest = f"repos/{REPOSITORY}/actions/runs/{RUN_ID}"
        if path == own_latest:
            self.counters["own_latest"] += 1
            value = {"id": RUN_ID, "run_attempt": 1, "head_sha": COMMIT,
                     "status": "in_progress", "conclusion": None}
            stale_call = 1 if self.probe == "stale_own_run" else 2
            if self.probe in {"stale_own_run", "late_stale_own_run"} and \
                    self.counters["own_latest"] == stale_call:
                value["run_attempt"] = 2
            return value

        if path == f"repos/{REPOSITORY}":
            value = copy.deepcopy(self.candidate_responses[path])
            if self.probe == "inactive_repository":
                value["archived"] = True
            return value

        if path in self.candidate_responses:
            value = copy.deepcopy(self.candidate_responses[path])
            if path.endswith(f"/releases/{self.draft['id']}"):
                self.counters["candidate_release"] += 1
                if self.probe == "late_candidate" and self.counters["candidate_release"] == 2:
                    value["draft"] = False
            return value

        raise AssertionError(f"unexpected mocked provider GET: {path}")

    def origin(self, arguments: list[str], purpose: str = "GitHub observation"):
        selected = list(arguments)
        self.calls["origin"].append((selected, purpose))
        attempt_path = f"repos/{REPOSITORY}/actions/runs/{RUN_ID}/attempts/{RUN_ATTEMPT}"
        if selected == ["api", attempt_path]:
            self.counters["own_provider_attempt"] += 1
            return copy.deepcopy(self.own_provider_run())

        if selected[:3] == ["api", "--paginate", "--slurp"] and len(selected) == 4:
            jobs_path = attempt_path + "/jobs?per_page=100"
            if selected[3] != jobs_path:
                raise AssertionError(f"unexpected mocked provider job selector: {selected[3]}")
            self.counters["source_jobs"] += 1
            value = self.source_job()
            if self.probe == "late_job_labels" and self.counters["source_jobs"] == 2:
                value["labels"] = ["ubuntu-22.04"]
            return [{"total_count": 1, "jobs": [value]}]

        raise AssertionError(f"unexpected mocked gh provider command: {selected!r}")

    def oidc_check_id(self, context: dict, *, expected_event: str) -> int:
        self.calls["oidc"].append((copy.deepcopy(context), expected_event))
        if context != self.source or expected_event != "workflow_run":
            raise AssertionError("constructor requested OIDC ownership for a different source")
        if self.probe == "wrong_oidc_check_id":
            return CHECK_RUN_ID + 1
        return CHECK_RUN_ID

    def git(self, *arguments: str) -> bytes:
        self.calls["git"].append(arguments)
        if len(arguments) != 2 or arguments[0] != "show":
            raise AssertionError(f"unexpected mocked Git selector: {arguments!r}")
        selected = arguments[1]
        prefix = f"{COMMIT}:"
        if not selected.startswith(prefix):
            raise AssertionError(f"frozen input was not selected from the admitted commit: {selected!r}")
        path = selected[len(prefix):]
        if path not in self.inputs:
            raise AssertionError(f"unexpected frozen input path: {path!r}")
        self.counters[f"git:{path}"] += 1
        if self.probe == "frozen_blob_wrong" and path == LOCK_PATH:
            return self.inputs[path] + b"changed"
        if self.probe == "late_frozen_blob" and path == LOCK_PATH and self.counters[f"git:{path}"] == 2:
            return self.inputs[path] + b"changed"
        return self.inputs[path]

    def load_head(self) -> str:
        if self.probe == "local_head_wrong" or (
                self.probe == "late_local_head_wrong" and len(self.calls["head"]) == 1):
            selected = "9" * 40
        else:
            selected = COMMIT
        self.calls["head"].append(selected)
        return selected

    def require_clean(self) -> None:
        if self.probe == "dirty_checkout" or (
                self.probe == "late_dirty_checkout" and len(self.calls["clean"]) == 1):
            raise ADMISSION.AdmissionError("tracked checkout differs from HEAD")
        self.calls["clean"].append(True)

    def blocked_boundary(self, name: str):
        def call(*_args, **_kwargs):
            self.blocked_calls[name] += 1
            raise AssertionError(f"constructor crossed forbidden {name} boundary")
        return call

    def cli_arguments(self, output: Path | None = None) -> list[str]:
        paths = {
            "admission": self.root / "admission.json",
            "tag": self.root / "tag.json",
            "draft": self.root / "draft.json",
        }
        for key, value in (("admission", self.admission), ("tag", self.tag), ("draft", self.draft)):
            with paths[key].open("xb") as handle:
                handle.write(json_bytes(value))
        self.cli_input_paths = paths
        destination = output or (self.root / "start.json")
        arguments = []
        for option, path in (("--admission", paths["admission"]), ("--tag", paths["tag"]),
                             ("--draft", paths["draft"]), ("--runtime-lock", self.runtime.lock_path),
                             ("--runtime-directory", self.runtime.directory),
                             ("--runtime-interface", self.runtime.interface_path), ("--output", destination)):
            arguments.extend((option, str(path)))
        return arguments

    def invoke(self, cli_args: list[str] | None = None):
        original_read = ADMISSION.read_regular_file

        def tracked_read(path: Path, label: str, maximum: int) -> bytes:
            self.calls["reads"].append((Path(path), label, maximum))
            raw = original_read(path, label, maximum)
            if (self.probe == "late_cli_input" and label == "start admission input"
                    and sum(item_label == label for _, item_label, _ in self.calls["reads"]) == 2):
                return raw + b" "
            if self.probe == "late_event" and label == "start trigger" and \
                    sum(item_label == "start trigger" for _, item_label, _ in self.calls["reads"]) == 2:
                return raw + b" "
            if self.probe == "late_runtime" and label == "start runtime evidence" and \
                    Path(path) == self.runtime.lock_path and \
                    sum(item_label == label and item_path == Path(path)
                        for item_path, item_label, _ in self.calls["reads"]) == 3:
                return raw + b" "
            return raw

        def observe_candidate(record: dict) -> None:
            self.calls["candidate"].append(copy.deepcopy(record))
            original_candidate(record)

        original_candidate = START.observe_candidate
        original_runtime = START.verify_runtime_evidence

        def verify_runtime(record: dict, **kwargs) -> None:
            self.calls["runtime"].append((copy.deepcopy(record), dict(kwargs)))
            original_runtime(record, **kwargs)

        original_own_run = constructor.own_run

        def own_run(context: dict) -> None:
            self.calls["own_run"].append(copy.deepcopy(context))
            original_own_run(context)

        def source_event(head: str):
            self.counters["event_context"] += 1
            return original_event_context(head)

        def require_main(head: str) -> bool:
            self.calls["main"].append(head)
            return original_require_main(head)

        original_event_context = ADMISSION._event_context
        original_require_main = ADMISSION.require_main
        patches = ExitStack()
        with patches:
            patches.enter_context(mock.patch.dict(os.environ, self.environment_patch(), clear=False))
            patches.enter_context(mock.patch.object(ADMISSION, "api", side_effect=self.api))
            patches.enter_context(mock.patch.object(ADMISSION, "git", side_effect=self.git))
            patches.enter_context(mock.patch.object(ADMISSION, "_load_head", side_effect=self.load_head))
            patches.enter_context(mock.patch.object(ADMISSION, "require_clean_tracked_checkout",
                                                     side_effect=self.require_clean))
            patches.enter_context(mock.patch.object(ADMISSION, "_event_context", side_effect=source_event))
            patches.enter_context(mock.patch.object(ADMISSION, "require_main", side_effect=require_main))
            patches.enter_context(mock.patch.object(ADMISSION, "read_regular_file", side_effect=tracked_read))
            patches.enter_context(mock.patch.object(ORIGIN, "gh_json", side_effect=self.origin))
            patches.enter_context(mock.patch.object(ORIGIN, "owning_check_id",
                                                     side_effect=self.oidc_check_id))
            patches.enter_context(mock.patch.object(constructor, "own_run", side_effect=own_run))
            patches.enter_context(mock.patch.object(START, "observe_candidate",
                                                     side_effect=observe_candidate))
            patches.enter_context(mock.patch.object(START, "verify_runtime_evidence",
                                                     side_effect=verify_runtime))

            for name in ("materialize", "download_asset", "verify_signature", "verify_attestation", "run"):
                patches.enter_context(mock.patch.object(RUNTIME, name,
                                                         side_effect=self.blocked_boundary(name)))
            patches.enter_context(mock.patch.object(START, "bounded_gh",
                                                     side_effect=self.blocked_boundary("signature verifier")))
            patches.enter_context(mock.patch.object(Path, "write_bytes",
                                                     side_effect=self.blocked_boundary("file write_bytes")))
            patches.enter_context(mock.patch.object(Path, "write_text",
                                                     side_effect=self.blocked_boundary("file write_text")))

            if cli_args is not None:
                stdout = io.StringIO()
                stderr = io.StringIO()
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    result = constructor.main(cli_args)
                return result, stdout.getvalue(), stderr.getvalue()
            return constructor.construct_start(
                self.admission, self.tag, self.draft, runtime_lock=self.runtime.lock_path,
                runtime_directory=self.runtime.directory, runtime_interface=self.runtime.interface_path,
            )

    def invoke_cli(self, output: Path | None = None):
        return self.invoke(self.cli_arguments(output))


class ConstructStartTests(unittest.TestCase):
    def fixture(self, probe: str | None = None) -> ConstructorFixture:
        value = ConstructorFixture(probe)
        self.addCleanup(value.close)
        return value

    def assert_rejected_without_side_effects(self, fixture: ConstructorFixture) -> Exception:
        before = fixture.snapshot()
        selected_inputs = (copy.deepcopy(fixture.admission), copy.deepcopy(fixture.tag),
                           copy.deepcopy(fixture.draft))
        with self.assertRaises(ERRORS) as raised:
            fixture.invoke()
        self.assertEqual(fixture.snapshot(), before, "constructor changed or created a local file")
        self.assertEqual((fixture.admission, fixture.tag, fixture.draft), selected_inputs,
                         "constructor mutated one of its retained inputs")
        self.assertNotIn("start.json", before)
        self.assertFalse(any(name.endswith(".sigstore.json") for name in before))
        self.assertTrue(all(count == 0 for count in fixture.blocked_calls.values()),
                        f"constructor crossed a forbidden boundary: {fixture.blocked_calls}")
        return raised.exception

    def test_constructs_an_unsigned_record_from_exact_provider_event_and_runtime_files(self) -> None:
        fixture = self.fixture()
        before = fixture.snapshot()
        result = fixture.invoke()

        self.assertEqual(fixture.snapshot(), before)
        self.assertEqual(result["schema"], START.SCHEMA)
        self.assertEqual(result["assurance"], START.ASSURANCE)
        self.assertEqual(result["context"], fixture.source)
        self.assertEqual(result["event"], "workflow_run")
        self.assertEqual(result["job"], {
            "id": JOB_ID, "check_run_id": CHECK_RUN_ID, "name": START.JOB,
        })
        self.assertEqual(result["admission"], fixture.admission)
        self.assertEqual(result["tag"], fixture.tag)
        self.assertEqual(result["draft"], fixture.draft)
        self.assertEqual(set(result), {
            "schema", "assurance", "context", "event", "job", "admission", "tag", "draft", "runtime",
        })

        manifest = json.loads((fixture.runtime.directory / ".aros-tools-runtime-manifest.json").read_bytes())
        executable = next(item for item in manifest["files"] if item["path"] == "bin/aros")
        self.assertEqual(result["runtime"], {
            "lock_sha256": sha256(fixture.runtime.lock_path.read_bytes()),
            "receipt_sha256": sha256(fixture.runtime.receipt_path.read_bytes()),
            "interface_sha256": sha256(fixture.runtime.interface_path.read_bytes()),
            "executable_sha256": executable["sha256"],
        })
        self.assertEqual(result["runtime"]["executable_sha256"],
                         sha256(fixture.runtime.executable_path.read_bytes()))
        self.assertNotIn("signature", result)
        self.assertNotIn("bundle", result)
        self.assertEqual(fixture.calls["oidc"], [(fixture.source, "workflow_run")])
        self.assertEqual(fixture.calls["own_run"], [fixture.source, fixture.source])
        self.assertEqual(fixture.counters["event_context"], 2)
        self.assertEqual(fixture.counters["ci_list"], 2)
        self.assertEqual(fixture.counters["ci_attempt_api"], 4)
        self.assertEqual(fixture.calls["main"], [COMMIT, COMMIT])
        self.assertEqual(fixture.calls["head"], [COMMIT, COMMIT])
        self.assertEqual(fixture.calls["clean"], [True, True])
        self.assertEqual(fixture.counters["own_latest"], 2)
        self.assertEqual(fixture.counters["own_provider_attempt"], 2)
        self.assertEqual(fixture.counters["source_jobs"], 2)
        self.assertEqual(len(fixture.calls["candidate"]), 2)
        self.assertEqual(fixture.counters["candidate_release"], 2)
        self.assertEqual(len(fixture.calls["runtime"]), 2)
        self.assertEqual(sum(label == "start trigger" for _, label, _ in fixture.calls["reads"]), 2)
        self.assertEqual(sum(label == "workflow_run event" for _, label, _ in fixture.calls["reads"]), 2)

        expected_git = [
            ("show", f"{COMMIT}:{path}")
            for _ in range(2) for path in fixture.admission["inputs"]
        ]
        self.assertEqual(fixture.calls["git"], expected_git)
        self.assertFalse(any(name.endswith("start.json") or name.endswith(".sigstore.json")
                             for name in fixture.snapshot()))
        self.assertTrue(all(count == 0 for count in fixture.blocked_calls.values()))

    def test_wrong_execution_context_host_and_trigger_are_rejected(self) -> None:
        probes = (
            ("workflow event", lambda fixture: fixture.environment.update(GITHUB_EVENT_NAME="push")),
            ("runner OS", lambda fixture: fixture.environment.update(RUNNER_OS="Windows")),
            ("runner architecture", lambda fixture: fixture.environment.update(RUNNER_ARCH="ARM64")),
            ("attempt", lambda fixture: fixture.environment.update(GITHUB_RUN_ATTEMPT="2")),
            ("repository", lambda fixture: fixture.environment.update(
                GITHUB_REPOSITORY="example/aros-toolchains")),
            ("repository ID", lambda fixture: fixture.environment.update(
                GITHUB_REPOSITORY_ID=str(REPOSITORY_ID + 1))),
            ("source ref", lambda fixture: fixture.environment.update(GITHUB_REF="refs/heads/release")),
            ("source commit", lambda fixture: fixture.environment.update(GITHUB_SHA="9" * 40)),
            ("trigger action", lambda fixture: fixture.event_value.update(action="requested")),
            ("trigger repository ID", lambda fixture: fixture.event_value["repository"].update(
                id=REPOSITORY_ID + 1)),
            ("head repository ID", lambda fixture: fixture.event_value["workflow_run"][
                "head_repository"].update(id=REPOSITORY_ID + 1)),
            ("head repository name", lambda fixture: fixture.event_value["workflow_run"][
                "head_repository"].update(full_name="example/aros-toolchains")),
            ("original CI event", lambda fixture: fixture.event_value["workflow_run"].update(
                event="workflow_dispatch")),
            ("original CI run ID", lambda fixture: fixture.event_value["workflow_run"].update(
                id=CI_RUN_ID + 1)),
            ("original CI commit", lambda fixture: fixture.event_value["workflow_run"].update(
                head_sha="9" * 40)),
            ("original CI attempt", lambda fixture: fixture.event_value["workflow_run"].update(
                run_attempt=2)),
            ("original CI branch", lambda fixture: fixture.event_value["workflow_run"].update(
                head_branch="release")),
            ("original CI workflow name", lambda fixture: fixture.event_value["workflow_run"].update(
                name="Other workflow")),
            ("original CI workflow path", lambda fixture: fixture.event_value["workflow_run"].update(
                path=".github/workflows/other.yml")),
            ("original CI conclusion", lambda fixture: fixture.event_value["workflow_run"].update(
                conclusion="failure")),
            ("original CI status", lambda fixture: fixture.event_value["workflow_run"].update(
                status="in_progress")),
        )
        for label, mutate in probes:
            with self.subTest(probe=label):
                fixture = self.fixture()
                mutate(fixture)
                fixture.write_event()
                self.assert_rejected_without_side_effects(fixture)

    def test_admission_requires_active_repo_original_ci_and_clean_frozen_main(self) -> None:
        for label, probe in (
            ("inactive repository", "inactive_repository"),
            ("CI provider commit", "ci_provider_commit_wrong"),
            ("CI provider attempt", "ci_provider_attempt_wrong"),
            ("latest CI attempt", "ci_latest_attempt_wrong"),
            ("advanced main", "main_advanced"),
            ("local HEAD", "local_head_wrong"),
            ("dirty tracked checkout", "dirty_checkout"),
            ("frozen input blob", "frozen_blob_wrong"),
        ):
            with self.subTest(probe=label):
                self.assert_rejected_without_side_effects(self.fixture(probe))


class ConstructStartCliTests(unittest.TestCase):
    def fixture(self, probe: str | None = None) -> ConstructorFixture:
        value = ConstructorFixture(probe)
        self.addCleanup(value.close)
        return value

    def assert_no_provider_calls(self, fixture: ConstructorFixture) -> None:
        for boundary in ("api", "origin", "oidc", "git"):
            self.assertEqual(fixture.calls[boundary], [], f"invalid CLI input reached {boundary}")

    def assert_rejected(self, fixture: ConstructorFixture, arguments: list[str], output: Path,
                        *, no_provider_calls: bool = False, output_should_exist: bool = False) -> None:
        before = fixture.snapshot()
        result, stdout, stderr = fixture.invoke(arguments)
        self.assertEqual(result, 1)
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "protected start construction rejected; output is not authorized\n")
        self.assertEqual(fixture.snapshot(), before, "failed CLI construction changed or created a file")
        self.assertEqual(output.exists() or output.is_symlink(), output_should_exist)
        self.assertTrue(all(count == 0 for count in fixture.blocked_calls.values()))
        if no_provider_calls:
            self.assert_no_provider_calls(fixture)

    @staticmethod
    def replace_argument(arguments: list[str], option: str, value: Path) -> list[str]:
        selected = list(arguments)
        index = selected.index(option)
        selected[index + 1] = str(value)
        return selected

    def test_cli_writes_a_canonical_unsigned_record_exclusively(self) -> None:
        fixture = self.fixture()
        arguments = fixture.cli_arguments()
        output = fixture.root / "start.json"
        before = fixture.snapshot()

        result, stdout, stderr = fixture.invoke(arguments)

        self.assertEqual(result, 0)
        self.assertEqual(stderr, "")
        self.assertIn("not release authority", stdout)
        raw = output.read_bytes()
        parsed = json.loads(raw)
        self.assertEqual(raw, json_bytes(parsed))
        self.assertEqual(parsed, fixture.calls["candidate"][0])
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        self.assertNotIn("signature", parsed)
        self.assertNotIn("bundle", parsed)
        self.assertEqual({key: value for key, value in fixture.snapshot().items()
                          if key != "start.json"}, before)
        self.assertEqual(fixture.calls["oidc"], [(fixture.source, "workflow_run")])

    def test_tampered_oversize_symlink_and_fifo_inputs_are_rejected_without_provider_calls(self) -> None:
        cases = ("tampered", "oversize", "symlink", "fifo")
        for case in cases:
            with self.subTest(case=case):
                fixture = self.fixture()
                arguments = fixture.cli_arguments()
                assert fixture.cli_input_paths is not None
                output = fixture.root / "start.json"
                if case == "tampered":
                    fixture.cli_input_paths["admission"].write_bytes(b'{"receipt":1,"receipt":2}\n')
                elif case == "oversize":
                    fixture.cli_input_paths["tag"].write_bytes(b" " * (START.MAX_RECORD + 1))
                elif case == "symlink":
                    link = fixture.root / "admission-link.json"
                    link.symlink_to(fixture.cli_input_paths["admission"])
                    arguments = self.replace_argument(arguments, "--admission", link)
                else:
                    fifo = fixture.root / "draft.fifo"
                    os.mkfifo(fifo)
                    arguments = self.replace_argument(arguments, "--draft", fifo)
                self.assert_rejected(fixture, arguments, output, no_provider_calls=True)

    def test_occupied_symlink_and_nested_symlink_outputs_are_rejected_before_provider_calls(self) -> None:
        for case in ("occupied", "symlink", "nested-link"):
            with self.subTest(case=case):
                fixture = self.fixture()
                output = fixture.root / "start.json"
                arguments = fixture.cli_arguments(output)
                if case == "occupied":
                    output.write_bytes(b"preserve me\n")
                elif case == "symlink":
                    target = fixture.root / "existing-target"
                    target.write_bytes(b"preserve target\n")
                    output.symlink_to(target)
                else:
                    real_parent = fixture.root / "real-parent"
                    real_parent.mkdir()
                    linked_parent = fixture.root / "linked-parent"
                    linked_parent.symlink_to(real_parent, target_is_directory=True)
                    output = linked_parent / "start.json"
                    arguments = self.replace_argument(arguments, "--output", output)
                self.assert_rejected(fixture, arguments, output, no_provider_calls=True,
                                     output_should_exist=case in {"occupied", "symlink"})
                if case == "symlink":
                    self.assertTrue(output.is_symlink())

    def test_late_input_change_and_construction_failure_write_no_output(self) -> None:
        fixture = self.fixture("late_cli_input")
        arguments = fixture.cli_arguments()
        output = fixture.root / "start.json"
        self.assert_rejected(fixture, arguments, output)

        failed = self.fixture("main_advanced")
        failed_arguments = failed.cli_arguments()
        failed_output = failed.root / "start.json"
        self.assert_rejected(failed, failed_arguments, failed_output)

    def test_output_sync_failure_is_rejected_without_claiming_output_absence(self) -> None:
        fixture = self.fixture()
        arguments = fixture.cli_arguments()
        output = fixture.root / "start.json"
        original_sync = os.fsync

        def fail_only_output_sync(descriptor: int) -> None:
            if output.exists() and os.fstat(descriptor).st_ino == output.stat().st_ino:
                raise OSError("synthetic sync failure")
            original_sync(descriptor)

        with mock.patch.object(ADMISSION.os, "fsync", side_effect=fail_only_output_sync):
            result, stdout, stderr = fixture.invoke(arguments)
        self.assertEqual(result, 1)
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "protected start construction rejected; output is not authorized\n")
        self.assertTrue(output.is_file())
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        self.assertTrue(all(count == 0 for count in fixture.blocked_calls.values()))


class ConstructStartBoundaryTests(unittest.TestCase):
    def fixture(self, probe: str | None = None) -> ConstructorFixture:
        value = ConstructorFixture(probe)
        self.addCleanup(value.close)
        return value

    def assert_rejected_without_side_effects(self, fixture: ConstructorFixture) -> Exception:
        before = fixture.snapshot()
        selected_inputs = (copy.deepcopy(fixture.admission), copy.deepcopy(fixture.tag),
                           copy.deepcopy(fixture.draft))
        with self.assertRaises(ERRORS) as raised:
            fixture.invoke()
        self.assertEqual(fixture.snapshot(), before, "constructor changed or created a local file")
        self.assertEqual((fixture.admission, fixture.tag, fixture.draft), selected_inputs,
                         "constructor mutated one of its retained inputs")
        self.assertNotIn("start.json", before)
        self.assertFalse(any(name.endswith(".sigstore.json") for name in before))
        self.assertTrue(all(count == 0 for count in fixture.blocked_calls.values()),
                        f"constructor crossed a forbidden boundary: {fixture.blocked_calls}")
        return raised.exception

    def test_own_run_oidc_selected_job_and_fixed_runner_label_are_required(self) -> None:
        for label, probe in (
            ("provider run event", "provider_event_wrong"),
            ("stale own run", "stale_own_run"),
            ("OIDC check ID", "wrong_oidc_check_id"),
            ("runner label", "job_labels_wrong"),
        ):
            with self.subTest(probe=label):
                self.assert_rejected_without_side_effects(self.fixture(probe))

    def test_late_runtime_candidate_source_job_run_and_event_changes_are_rejected(self) -> None:
        for label, probe in (
            ("runtime bytes", "late_runtime"),
            ("candidate metadata", "late_candidate"),
            ("frozen source blob", "late_frozen_blob"),
            ("local HEAD", "late_local_head_wrong"),
            ("main branch", "late_main_advanced"),
            ("tracked checkout", "late_dirty_checkout"),
            ("source CI repository ID", "late_ci_repo_id"),
            ("own run", "late_stale_own_run"),
            ("own job runner label", "late_job_labels"),
            ("trigger event bytes", "late_event"),
        ):
            with self.subTest(probe=label):
                self.assert_rejected_without_side_effects(self.fixture(probe))


if __name__ == "__main__":
    unittest.main()
