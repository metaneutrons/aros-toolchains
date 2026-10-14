#!/usr/bin/env python3
"""Offline candidate-controller contract tests.

The controller, admission, archive extraction and interface preflight are real.
GitHub, OIDC, signature/provenance verifier exits, and downloaded runtime bytes
are isolated fixtures. Passing tests do not claim live provider authenticity,
release qualification, or publication authority.
"""

from __future__ import annotations

from contextlib import ExitStack, redirect_stderr, redirect_stdout
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


admission_tests = load(
    "candidate_admission_test_fixtures",
    ROOT / "scripts/toolchain/tests/test-release-admission-v2.py",
)
controller = load(
    "create_compiler_sdk_candidate_v2",
    ROOT / "scripts/toolchain/create-compiler-sdk-candidate-v2.py",
)
ADMISSION = controller.ADMISSION
ORIGIN = controller.ORIGIN
RUNTIME = controller.RUNTIME
INTERFACE = controller.INTERFACE
REAL_API_GET = controller._api_get
REAL_API_POST = controller._api_post
REAL_BOUNDED_SUBPROCESS = ADMISSION._bounded_subprocess

REPOSITORY = ADMISSION.REPOSITORY
RUNTIME_REPOSITORY = ADMISSION.RUNTIME_REPOSITORY
START_RUN_ID = 712340
START_CHECK_ID = 712341
START_JOB_ID = 712342
DRAFT_ID = 712399
TAG_OBJECT = "d" * 40
TAG_EPOCH = 1_800_000_000
JOB_TOKEN = "synthetic-job-token"


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


class CandidateFixture:
    def __init__(self, *, probe: str | None = None):
        self.probe = probe
        requested_probe = probe
        self.probe = None
        self.provider = admission_tests.ReleaseAdmissionTests()
        self.provider.setUp()
        self.root = self.provider.base
        self.assets_dir = self.root / "asset-fixtures"
        self.assets_dir.mkdir(mode=0o700)
        self.mutations: list[tuple[str, dict]] = []
        self.api_calls: list[str] = []
        self.oidc_calls: list[tuple[dict, str]] = []
        self.verifier_calls: list[str] = []
        self.credentialless_calls: list[str] = []
        self.admission_calls = 0
        self.branch_reads = 0
        self.real_bounded = REAL_BOUNDED_SUBPROCESS
        self.real_api_get = REAL_API_GET
        self.real_api_post = REAL_API_POST
        self.late_ref_readback = False
        self._prepare_synthetic_lock()
        self.event_path = self.root / "candidate-workflow-event.json"
        self._write_start_event()
        self.environment = {
            "PATH": f"{self.provider.bin}:{os.environ.get('PATH', '')}",
            "GITHUB_REPOSITORY": REPOSITORY,
            "GITHUB_REPOSITORY_ID": "7890",
            "GITHUB_SHA": self.provider.head,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_RUN_ID": str(START_RUN_ID),
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_EVENT_NAME": "workflow_run",
            "GITHUB_EVENT_PATH": str(self.event_path),
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "GH_TOKEN": JOB_TOKEN,
            "GH_AUTH_TOKEN": "must-not-be-used",
            "GITHUB_TOKEN": "must-not-be-used",
            "GOVERNANCE_TOKEN": "must-not-be-used",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "must-not-be-used",
            "ACTIONS_ID_TOKEN_REQUEST_URL": "must-not-be-used",
            "RP_CREATED": "true",
            "RP_TAG": f"v{admission_tests.VERSION}",
            "RP_SHA": self.provider.head,
            "RP_VERSION": admission_tests.VERSION,
            "RP_ID": str(DRAFT_ID),
            "CANDIDATE_ASSET_FIXTURES": str(self.assets_dir),
            "CANDIDATE_JOB_TOKEN": JOB_TOKEN,
        }
        self.stack = ExitStack()
        self._patch_low_level_boundaries()
        receipt = ADMISSION.admission()
        if type(receipt) is not dict:
            raise AssertionError("synthetic full admission did not produce a receipt")
        self.receipt = receipt
        self.probe = requested_probe
        self.admission_path = self.root / "candidate-admission.json"
        self.admission_path.write_bytes(canonical(receipt))
        self.runtime_directory = self.root / "private-runtime"
        self.interface_path = self.root / "runtime-interface.json"
        self.tag_output = self.root / "candidate-tag.json"
        self.draft_output = self.root / "candidate-draft.json"
        self.tag_input = self.root / "candidate-tag-input.json"

    def close(self) -> None:
        self.stack.close()
        self.provider.tearDown()

    def _prepare_synthetic_lock(self) -> None:
        lock = copy.deepcopy(self.provider.lock)
        host = "linux-x86_64"
        entry = lock["hosts"][host]
        executable = self._interface_executable(lock["version"])
        payloads: dict[str, bytes] = {}
        files: dict[str, bytes] = {}
        for path in RUNTIME.EXPECTED_FILES:
            files[path] = executable if path == "bin/aros" else f"synthetic runtime file: {path}\n".encode()
        manifest_files = []
        for path, (mode, _) in sorted(RUNTIME.EXPECTED_FILES.items()):
            data = files[path]
            manifest_files.append({"path": path, "mode": mode, "sha256": sha(data), "size": len(data)})

        root_name = f"aros-tools-v{lock['version']}-{entry['target']}"
        archive_stream = io.BytesIO()
        with tarfile.open(fileobj=archive_stream, mode="w:gz") as archive:
            root_info = tarfile.TarInfo(root_name)
            root_info.type = tarfile.DIRTYPE
            root_info.mode = 0o755
            archive.addfile(root_info)
            bin_info = tarfile.TarInfo(f"{root_name}/bin")
            bin_info.type = tarfile.DIRTYPE
            bin_info.mode = 0o755
            archive.addfile(bin_info)
            for path, data in sorted(files.items()):
                member = tarfile.TarInfo(f"{root_name}/{path}")
                member.mode = int(RUNTIME.EXPECTED_FILES[path][0], 8)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        archive_raw = archive_stream.getvalue()
        entry["archive"]["size"] = len(archive_raw)
        entry["archive"]["sha256"] = sha(archive_raw)
        manifest = {
            "schema": 1, "package": "aros-tools", "version": lock["version"],
            "target": entry["target"], "source_commit": lock["source_commit"],
            "source_date_epoch": lock["source_date_epoch"],
            "archive": entry["archive"]["name"],
            "archive_sha256": entry["archive"]["sha256"],
            "archive_size": entry["archive"]["size"], "files": manifest_files,
        }
        manifest_raw = RUNTIME.canonical_json(manifest) + b"\n"
        entry["manifest"]["size"] = len(manifest_raw)
        entry["manifest"]["sha256"] = sha(manifest_raw)
        payloads[entry["archive"]["name"]] = archive_raw
        payloads[entry["manifest"]["name"]] = manifest_raw
        for field in ("archive_bundle", "manifest_bundle"):
            bundle = f"fixture signed bundle: {field}\n".encode()
            entry[field]["size"] = len(bundle)
            entry[field]["sha256"] = sha(bundle)
            payloads[entry[field]["name"]] = bundle
        for other_host, other_entry in lock["hosts"].items():
            if other_host == host:
                continue
            for field in ("archive", "manifest", "archive_bundle", "manifest_bundle"):
                asset = other_entry[field]
                data = f"locked fixture asset: {asset['name']}\n".encode()
                asset["size"] = len(data)
                asset["sha256"] = sha(data)
                payloads[asset["name"]] = data

        self.provider.lock = lock
        self.provider.selection = {"schema": "fixture", "tools_commit": lock["source_commit"]}
        self.provider._write_inputs()
        admission_tests._run_git(self.provider.repo, "add", ".")
        admission_tests._run_git(self.provider.repo, "commit", "-q", "--amend", "--no-edit")
        self.provider.head = admission_tests._run_git(self.provider.repo, "rev-parse", "HEAD")
        self.provider._build_scenario()
        self.provider._save_responses()
        # Rewrite event only after the final fixture commit is known.
        self.asset_ids = {}
        for item in self.provider.responses[admission_tests.RUNTIME_RELEASE_PATH]["assets"]:
            self.asset_ids[item["name"]] = item["id"]
        for name, data in payloads.items():
            (self.assets_dir / str(self.asset_ids[name])).write_bytes(data)
            (self.assets_dir / str(self.asset_ids[name])).chmod(0o600)
        fake_gh = self.provider.bin / "gh"
        fake_gh.write_text(
            "#!/usr/bin/env python3\n"
            "import os, sys\n"
            "from pathlib import Path\n"
            "args = sys.argv[1:]\n"
            "if os.environ.get('GH_HOST') != 'github.com' or "
            "os.environ.get('GH_TOKEN') != os.environ.get('CANDIDATE_JOB_TOKEN'):\n"
            "    raise SystemExit(80)\n"
            "if any(name in os.environ for name in ('GH_AUTH_TOKEN', 'GITHUB_TOKEN', "
            "'GOVERNANCE_TOKEN', 'ACTIONS_ID_TOKEN_REQUEST_TOKEN', "
            "'ACTIONS_ID_TOKEN_REQUEST_URL')):\n"
            "    raise SystemExit(82)\n"
            "if args[:2] != ['api', '--method'] or args[2] != 'GET' or "
            "'Accept: application/octet-stream' not in args:\n"
            "    raise SystemExit(81)\n"
            "endpoint = args[-1]\n"
            "asset_id = endpoint.rsplit('/', 1)[-1]\n"
            "sys.stdout.buffer.write(Path(os.environ['CANDIDATE_ASSET_FIXTURES'], asset_id).read_bytes())\n",
            encoding="utf-8",
        )
        fake_gh.chmod(0o755)

    @staticmethod
    def _interface_executable(version: str) -> bytes:
        options = sorted({option for _, required in INTERFACE.INTERFACES for option in required})
        option_text = " ".join(f"--{option}" for option in options)
        script = (
            "#!/bin/sh\n"
            'if [ "$1" = "--version" ]; then printf \'aros-tools %s\\n\' '
            f"'{version}'" "; exit 0; fi\n"
            f"printf '%s\\n' {option_text}\n"
        )
        return script.encode("utf-8")

    def _write_start_event(self) -> None:
        event = {
            "action": "completed",
            "repository": {"id": 7890, "full_name": REPOSITORY},
            "workflow_run": {
                "id": self.receipt_ci_id(), "run_attempt": 1,
                "name": ADMISSION.CI_WORKFLOW_NAME, "path": ADMISSION.CI_WORKFLOW,
                "event": "push", "head_branch": "main", "head_sha": self.provider.head,
                "head_repository": {"id": 7890, "full_name": REPOSITORY},
                "status": "completed", "conclusion": "success",
            },
        }
        self.event_path.write_bytes(canonical(event))

    def receipt_ci_id(self) -> int:
        return admission_tests.RUN_ID

    def _patch_low_level_boundaries(self) -> None:
        self.stack.enter_context(mock.patch.dict(os.environ, self.environment, clear=False))
        self.stack.enter_context(mock.patch.object(ADMISSION, "ROOT", self.provider.repo))
        self.stack.enter_context(mock.patch.object(ADMISSION, "api", side_effect=self.api))
        self.stack.enter_context(mock.patch.object(controller, "_api_get", side_effect=self.api))
        self.stack.enter_context(mock.patch.object(controller, "_api_post", side_effect=self.post))
        self.stack.enter_context(mock.patch.object(ORIGIN, "owning_check_id", side_effect=self.oidc))
        self.stack.enter_context(mock.patch.object(ADMISSION, "_bounded_subprocess",
                                                   side_effect=self.bounded_process))
        real_admission = ADMISSION.admission

        def track_admission(**kwargs):
            self.admission_calls += 1
            return real_admission(**kwargs)

        self.stack.enter_context(mock.patch.object(ADMISSION, "admission", side_effect=track_admission))

    def _route(self, path: str):
        base = path.split("?", 1)[0]
        response = self.provider.responses.get(path, self.provider.responses.get(base))
        if response is None:
            return None
        if isinstance(response, dict) and response.get("__http"):
            return response
        return copy.deepcopy(response)

    def api(self, path: str, *, allow_404: bool = False, governance: bool = False):
        self.api_calls.append(path)
        base = path.split("?", 1)[0]
        own_latest = f"repos/{REPOSITORY}/actions/runs/{START_RUN_ID}"
        own_attempt = own_latest + "/attempts/1"
        if path == own_attempt:
            return {
                "id": START_RUN_ID, "run_attempt": 1, "head_sha": self.provider.head,
                "head_branch": "main", "path": f"{controller.WORKFLOW}@refs/heads/main",
                "head_repository": {"id": 7890, "full_name": REPOSITORY},
                "event": "workflow_run", "status": "in_progress", "conclusion": None,
            }
        if path == own_latest:
            value = {"id": START_RUN_ID, "run_attempt": 1, "head_sha": self.provider.head,
                     "status": "in_progress", "conclusion": None}
            if self.probe == "own_rerun":
                value["run_attempt"] = 2
            return value
        own_jobs = f"repos/{REPOSITORY}/actions/runs/{START_RUN_ID}/attempts/1/jobs"
        if re.fullmatch(re.escape(own_jobs) + r"\?per_page=100&page=[1-9][0-9]*", path):
            return self.own_jobs_page(path)
        candidate_ref = f"repos/{REPOSITORY}/git/ref/tags/v{admission_tests.VERSION}"
        candidate_release = f"repos/{REPOSITORY}/releases/tags/v{admission_tests.VERSION}"
        if self.probe == "tag_ref_forbidden" and base == candidate_ref:
            route = {"__http": 403}
        elif self.probe == "release_tag_forbidden" and base == candidate_release:
            route = {"__http": 403}
        else:
            route = self._route(path)
        if route is None or isinstance(route, dict) and route.get("__http") == 404:
            if allow_404:
                return None
            raise controller.CandidateError("synthetic provider route unavailable")
        if isinstance(route, dict) and route.get("__http"):
            raise controller.CandidateError("synthetic provider HTTP failure")
        if self.probe == "inactive_repo" and path == admission_tests.REPOSITORY_PATH:
            route["archived"] = True
        if self.probe == "main_advanced" and path == admission_tests.BRANCH_PATH:
            route["commit"]["sha"] = "9" * 40
        pull_list = f"repos/{REPOSITORY}/commits/{self.provider.head}/pulls"
        if self.probe == "wrong_pending_label" and base == pull_list:
            route[0]["labels"] = [{"name": "autorelease: tagged"}]
        if self.probe == "pending_and_tagged" and base == pull_list:
            route[0]["labels"] = [
                {"name": "autorelease: pending"}, {"name": "autorelease: tagged"},
            ]
        if self.probe == "governance_changed" and base == admission_tests.RULESET_PATH:
            route["rules"] = [{"type": "update"}]
        if (self.probe == "governance_after_ref_readback" and self.late_ref_readback
                and base == admission_tests.RULESET_PATH):
            route["rules"] = [{"type": "update"}]
        if (self.probe == "pending_label_after_ref_readback" and self.late_ref_readback
                and base == pull_list):
            route[0]["labels"] = []
        if self.probe == "ci_failed" and base == admission_tests.RUN_PATH:
            route["status"] = "completed"
            route["conclusion"] = "failure"
        if (self.probe == "ci_failed_after_ref_readback" and self.late_ref_readback
                and base == admission_tests.RUN_PATH):
            route["status"] = "completed"
            route["conclusion"] = "failure"
        if (self.probe == "ci_rerun_after_ref_readback" and self.late_ref_readback
                and base == admission_tests.RUN_PATH):
            route["run_attempt"] = 2
        if base == admission_tests.BRANCH_PATH:
            self.branch_reads += 1
            late_kind = {
                "admission_before_post": "admission",
                "lock_before_post": "lock",
                "runtime_before_post": "runtime",
            }.get(self.probe)
            if (late_kind is not None and self.admission_calls >= 3 and len(self.api_calls) > 1
                    and self.api_calls[-2].split("?", 1)[0] == admission_tests.RELEASES_PATH):
                self._mutate_local(late_kind)
        if (self.probe in {"governance_after_ref_readback", "pending_label_after_ref_readback",
                           "ci_failed_after_ref_readback", "ci_rerun_after_ref_readback"}
                and base == f"repos/{REPOSITORY}/git/tags/{TAG_OBJECT}"):
            self.late_ref_readback = True
        return route

    def post(self, path: str, payload: dict):
        self.mutations.append((path, copy.deepcopy(payload)))
        if path.endswith("/git/tags"):
            if self.probe == "tag_unknown":
                return 202, {"message": "unknown"}
            tag_sha = TAG_OBJECT
            created = {
                "sha": tag_sha, "tag": payload["tag"], "message": payload["message"],
                "object": {"sha": payload["object"], "type": "commit", "url": "fixture"},
                "tagger": copy.deepcopy(payload["tagger"]),
            }
            self.provider.responses[f"repos/{REPOSITORY}/git/tags/{tag_sha}"] = created
            late_kind = {
                "admission_after_tag_object": "admission",
                "lock_after_tag_object": "lock",
                "runtime_after_tag_object": "runtime",
            }.get(self.probe)
            if late_kind is not None:
                self._mutate_local(late_kind)
            return 201, created
        if path.endswith("/git/refs"):
            if self.probe == "ref_unknown":
                return 200, {"ref": payload["ref"]}
            name = payload["ref"].removeprefix("refs/tags/")
            created = {"ref": payload["ref"], "object": {
                "sha": payload["sha"], "type": "tag",
                "url": f"https://api.github.com/repos/{REPOSITORY}/git/tags/{payload['sha']}",
            }}
            self.provider.responses[f"repos/{REPOSITORY}/git/ref/tags/{name}"] = created
            return 201, created
        raise AssertionError(f"unexpected fake mutation endpoint: {path}")

    def _mutate_local(self, kind: str) -> None:
        if kind == "admission":
            path = self.admission_path
        elif kind == "lock":
            path = self.provider.repo / "toolchains/aros-tools-runtime-v1.json"
        elif kind == "runtime":
            path = self.runtime_directory / "bin/aros"
        else:
            raise AssertionError(f"unknown synthetic mutation kind: {kind}")
        path.write_bytes(path.read_bytes() + b" ")

    def own_jobs_page(self, path: str) -> dict:
        page = int(path.rsplit("page=", 1)[1])
        selected = {
            "id": START_JOB_ID,
            "check_run_url": f"https://api.github.com/repos/{REPOSITORY}/check-runs/{START_CHECK_ID}",
            "name": controller.JOB, "head_sha": self.provider.head,
            "run_id": START_RUN_ID, "run_attempt": 1, "labels": ["ubuntu-24.04"],
            "status": "in_progress", "conclusion": None,
        }
        if self.probe == "incomplete_job_page":
            return {"total_count": 2, "jobs": [selected]}
        if self.probe == "duplicate_job_page":
            if page == 1:
                fillers = [{"id": START_JOB_ID + number + 1} for number in range(99)]
                return {"total_count": 101, "jobs": [selected, *fillers]}
            if page == 2:
                return {"total_count": 101, "jobs": [copy.deepcopy(selected)]}
            return {"total_count": 101, "jobs": []}
        return {"total_count": 1, "jobs": [selected]}

    def oidc(self, context: dict, *, expected_event: str) -> int:
        self.oidc_calls.append((copy.deepcopy(context), expected_event))
        if expected_event != "workflow_run" or context["run_id"] != START_RUN_ID:
            raise AssertionError("unexpected OIDC selector")
        return START_CHECK_ID

    def bounded_process(self, command: list[str], **kwargs):
        if command[0] == "git":
            self.assert_no_provider_token(kwargs["env"])
            self.credentialless_calls.append("git")
            return self.real_bounded(command, **kwargs)
        if command[0] == "gh" and command[1:4] == ["api", "--method", "POST"] and "graphql" in command:
            self.assert_job_transport(kwargs["env"])
            result = {
                "data": {"node": {
                    "__typename": "RepositoryRuleset",
                    "id": admission_tests.RULESET_NODE_ID,
                    "databaseId": admission_tests.RULESET_ID,
                    "bypassActors": {"totalCount": 0, "nodes": [],
                                     "pageInfo": {"hasNextPage": False}},
                }}
            }
            return subprocess.CompletedProcess(command, 0, json.dumps(result).encode(), b"")
        if command[0] == "gh" and command[1] == "api":
            self.assert_job_transport(kwargs["env"])
            path = command[-1]
            value = self.api(path)
            return subprocess.CompletedProcess(command, 0, json.dumps(value).encode(), b"")
        if command[0] == "gh" and command[1] == "attestation":
            self.assert_job_transport(kwargs["env"])
            self.verifier_calls.append("attestation")
            if self.probe == "bad_attestation":
                return subprocess.CompletedProcess(command, 1, b"", b"synthetic attestation rejection")
            return subprocess.CompletedProcess(command, 0, b"", b"")
        if command[0] == "cosign":
            self.assert_no_provider_token(kwargs["env"])
            self.credentialless_calls.append("cosign")
            self.verifier_calls.append("signature")
            if self.probe == "bad_signature":
                return subprocess.CompletedProcess(command, 1, b"", b"synthetic signature rejection")
            return subprocess.CompletedProcess(command, 0, b"", b"")
        raise AssertionError(f"unexpected bounded subprocess in fixture: {command!r}")

    @staticmethod
    def assert_job_transport(environment: dict[str, str]) -> None:
        if (environment.get("GH_TOKEN") != JOB_TOKEN or environment.get("GH_HOST") != "github.com"
                or "GH_AUTH_TOKEN" in environment or "GOVERNANCE_TOKEN" in environment
                or "GITHUB_TOKEN" in environment
                or "ACTIONS_ID_TOKEN_REQUEST_TOKEN" in environment
                or "ACTIONS_ID_TOKEN_REQUEST_URL" in environment):
            raise AssertionError("provider transport did not use only the fixed-host job token")

    @staticmethod
    def assert_no_provider_token(environment: dict[str, str]) -> None:
        if any(name in environment for name in
               ("GH_TOKEN", "GH_AUTH_TOKEN", "GITHUB_TOKEN", "GOVERNANCE_TOKEN",
                "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL")):
            raise AssertionError("non-provider child unexpectedly received a provider token")

    def cli_args(self, command: str, *, output: Path | None = None) -> list[str]:
        args = [command, "--admission", str(self.admission_path),
                "--runtime-lock", str(self.provider.repo / "toolchains/aros-tools-runtime-v1.json"),
                "--runtime-directory", str(self.runtime_directory),
                "--runtime-interface", str(self.interface_path),
                "--output", str(output or (self.tag_output if command == "create-tag" else self.draft_output))]
        if command == "bind-draft":
            args.extend(("--tag", str(self.tag_input)))
        return args

    def invoke(self, command: str, *, output: Path | None = None):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return controller.main(self.cli_args(command, output=output))

    def create_candidate_tag(self) -> dict:
        result = self.invoke("create-tag")
        if result != 0:
            raise AssertionError("synthetic candidate tag creation failed")
        value = json.loads(self.tag_output.read_bytes())
        self.environment.update({"RP_TAG": value["name"], "RP_SHA": value["commit"]})
        self.tag_input.write_bytes(canonical(value))
        return value

    def create_draft(self, tag: dict) -> None:
        release = {
            "id": DRAFT_ID, "tag_name": tag["name"], "target_commitish": tag["commit"],
            "draft": True, "prerelease": False, "immutable": False, "assets": [],
        }
        self.provider.responses[f"repos/{REPOSITORY}/releases/{DRAFT_ID}"] = copy.deepcopy(release)
        self.provider.responses[f"repos/{REPOSITORY}/releases/tags/{tag['name']}"] = copy.deepcopy(release)
        self.provider.responses[admission_tests.RELEASES_PATH] = [copy.deepcopy(release)]


class CandidateControllerTests(unittest.TestCase):
    def fixture(self, **kwargs) -> CandidateFixture:
        value = CandidateFixture(**kwargs)
        self.addCleanup(value.close)
        return value

    def test_create_tag_runs_fresh_admission_runtime_materialization_preflight_and_readback(self) -> None:
        fixture = self.fixture()
        result = fixture.invoke("create-tag")
        self.assertEqual(result, 0)
        record = json.loads(fixture.tag_output.read_bytes())
        self.assertEqual(record, {
            "name": fixture.receipt["tag"], "object": TAG_OBJECT,
            "commit": fixture.receipt["commit"], "epoch": record["epoch"],
        })
        self.assertEqual(fixture.mutations[0][0], f"repos/{REPOSITORY}/git/tags")
        self.assertEqual(fixture.mutations[1][0], f"repos/{REPOSITORY}/git/refs")
        self.assertEqual([call[0] for call in fixture.mutations], [
            f"repos/{REPOSITORY}/git/tags", f"repos/{REPOSITORY}/git/refs",
        ])
        self.assertEqual(stat.S_IMODE(fixture.tag_output.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(fixture.interface_path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(fixture.runtime_directory.stat().st_mode), 0o700)
        jobs_prefix = f"repos/{REPOSITORY}/actions/runs/{START_RUN_ID}/attempts/1/jobs?per_page=100&page="
        job_reads = [path for path in fixture.api_calls if path.startswith(jobs_prefix)]
        self.assertEqual(len(job_reads), 8)
        self.assertTrue(all(path.endswith("page=1") for path in job_reads))
        self.assertIn("signature", fixture.verifier_calls)
        self.assertIn("attestation", fixture.verifier_calls)
        # Four complete owning-job identity fences each independently read
        # the OIDC check id before and after selecting the job.
        self.assertEqual(len(fixture.oidc_calls), 8)
        self.assertTrue(all(event == "workflow_run" for _, event in fixture.oidc_calls))
        self.assertEqual(fixture.receipt["assurance"], "metadata-only")
        self.assertNotIn("release authority", fixture.tag_output.read_text(encoding="utf-8"))

    def test_bind_draft_observes_one_private_empty_draft_without_re_admission_or_mutation(self) -> None:
        fixture = self.fixture()
        tag = fixture.create_candidate_tag()
        fixture.create_draft(tag)
        before = len(fixture.mutations)
        admissions_before = fixture.admission_calls
        result = fixture.invoke("bind-draft")
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(fixture.draft_output.read_bytes()), {
            "id": DRAFT_ID, "tag_name": tag["name"], "target_commitish": tag["commit"],
        })
        self.assertEqual(len(fixture.mutations), before)
        self.assertEqual(fixture.admission_calls, admissions_before)
        self.assertEqual(stat.S_IMODE(fixture.draft_output.stat().st_mode), 0o600)

    def test_job_page_counterprobes_reject_incomplete_and_duplicate_provider_pages(self) -> None:
        for probe in ("incomplete_job_page", "duplicate_job_page"):
            with self.subTest(probe=probe):
                fixture = self.fixture(probe=probe)
                self.assertEqual(fixture.invoke("create-tag"), 1)
                self.assertEqual(fixture.mutations, [])
                self.assertFalse(fixture.tag_output.exists())
                job_pages = [path for path in fixture.api_calls
                             if "/attempts/1/jobs?per_page=100&page=" in path]
                self.assertTrue(any(path.endswith("page=1") for path in job_pages))
                if probe == "duplicate_job_page":
                    self.assertTrue(any(path.endswith("page=2") for path in job_pages))
                else:
                    self.assertFalse(any(path.endswith("page=2") for path in job_pages))

    def test_signature_and_attestation_failures_stop_before_tag_mutation(self) -> None:
        for probe, verifier in (("bad_signature", "signature"), ("bad_attestation", "attestation")):
            with self.subTest(probe=probe):
                fixture = self.fixture(probe=probe)
                self.assertEqual(fixture.invoke("create-tag"), 1)
                self.assertIn(verifier, fixture.verifier_calls)
                self.assertEqual(fixture.mutations, [])
                self.assertFalse(fixture.tag_output.exists())

        successful = self.fixture()
        self.assertEqual(successful.invoke("create-tag"), 0)
        self.assertIn("git", successful.credentialless_calls)
        self.assertIn("cosign", successful.credentialless_calls)

    def test_stale_governance_and_failed_ci_are_rejected_before_mutation(self) -> None:
        stale = self.fixture()
        receipt = json.loads(stale.admission_path.read_bytes())
        receipt["governance"]["checked_at"] = 1
        stale.admission_path.write_bytes(canonical(receipt))
        self.assertEqual(stale.invoke("create-tag"), 1)
        self.assertEqual(stale.mutations, [])
        self.assertFalse(stale.tag_output.exists())

        for probe in ("governance_changed", "ci_failed"):
            with self.subTest(probe=probe):
                fixture = self.fixture(probe=probe)
                self.assertEqual(fixture.invoke("create-tag"), 1)
                self.assertEqual(fixture.mutations, [])
                self.assertFalse(fixture.tag_output.exists())

    def test_invalid_trigger_context_and_privileged_absence_forbidden_fail_closed(self) -> None:
        fixture = self.fixture()
        before_api = len(fixture.api_calls)
        with mock.patch.dict(os.environ, {"GITHUB_EVENT_NAME": "push"}):
            self.assertEqual(fixture.invoke("create-tag"), 1)
        self.assertEqual(len(fixture.api_calls), before_api)
        self.assertEqual(fixture.mutations, [])
        self.assertFalse(fixture.tag_output.exists())

        for probe in ("tag_ref_forbidden", "release_tag_forbidden"):
            with self.subTest(probe=probe):
                forbidden = self.fixture(probe=probe)
                self.assertEqual(forbidden.invoke("create-tag"), 1)
                self.assertEqual(forbidden.mutations, [])
                self.assertFalse(forbidden.tag_output.exists())

        status_fixture = self.fixture()
        endpoint = f"repos/{REPOSITORY}/git/ref/tags/v{admission_tests.VERSION}"
        cases = ((b"provider response (HTTP 404)", None),
                 (b"provider response (HTTP 403)", controller.CandidateError),
                 (b"provider response (HTTP 404); conflict (HTTP 403)", controller.CandidateError))
        for stderr, expected_error in cases:
            command = ["gh", "api", "--method", "GET", endpoint]
            response = subprocess.CompletedProcess(command, 1, b"", stderr)
            with self.subTest(stderr=stderr):
                with mock.patch.object(ADMISSION, "_bounded_subprocess", return_value=response) as run:
                    if expected_error is None:
                        self.assertIsNone(status_fixture.real_api_get(endpoint, allow_404=True))
                    else:
                        with self.assertRaises(expected_error):
                            status_fixture.real_api_get(endpoint, allow_404=True)
                    run.assert_called_once()

    def test_late_input_and_runtime_changes_fail_before_first_tag_post(self) -> None:
        for kind in ("admission", "lock", "runtime"):
            with self.subTest(kind=kind):
                fixture = self.fixture(probe=f"{kind}_before_post")
                self.assertEqual(fixture.invoke("create-tag"), 1)
                self.assertEqual(fixture.mutations, [])
                self.assertFalse(fixture.tag_output.exists())

    def test_changes_after_tag_object_stop_without_ref_retry_or_authorized_output(self) -> None:
        for kind in ("admission", "lock", "runtime"):
            with self.subTest(kind=kind):
                fixture = self.fixture(probe=f"{kind}_after_tag_object")
                self.assertEqual(fixture.invoke("create-tag"), 1)
                self.assertEqual([path for path, _ in fixture.mutations],
                                 [f"repos/{REPOSITORY}/git/tags"])
                self.assertFalse(fixture.tag_output.exists())

    def test_source_policy_and_ci_drift_after_ref_readback_reject_handoff_without_retry(self) -> None:
        for probe in ("governance_after_ref_readback", "pending_label_after_ref_readback",
                      "ci_failed_after_ref_readback", "ci_rerun_after_ref_readback"):
            with self.subTest(probe=probe):
                fixture = self.fixture(probe=probe)
                self.assertEqual(fixture.invoke("create-tag"), 1)
                self.assertTrue(fixture.late_ref_readback)
                self.assertEqual([path for path, _ in fixture.mutations], [
                    f"repos/{REPOSITORY}/git/tags", f"repos/{REPOSITORY}/git/refs",
                ])
                self.assertFalse(fixture.tag_output.exists())

    def test_output_io_failure_never_emits_an_authorized_record(self) -> None:
        fixture = self.fixture()

        def partial_write(path: Path, content: bytes) -> None:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(content[:10])
                handle.flush()
                os.fsync(handle.fileno())
                raise OSError("synthetic output I/O failure")

        with mock.patch.object(ADMISSION, "_write_exclusive", side_effect=partial_write):
            self.assertEqual(fixture.invoke("create-tag"), 1)
        self.assertEqual([path for path, _ in fixture.mutations], [
            f"repos/{REPOSITORY}/git/tags", f"repos/{REPOSITORY}/git/refs",
        ])
        self.assertTrue(fixture.tag_output.exists())
        self.assertEqual(fixture.tag_output.read_bytes(), b'{"commit":')
        with self.assertRaises(json.JSONDecodeError):
            json.loads(fixture.tag_output.read_bytes())
        self.assertNotIn(b'"object":', fixture.tag_output.read_bytes())

    def test_invalid_outputs_and_linked_inputs_fail_before_provider_observations(self) -> None:
        for case in ("occupied", "output_symlink", "nested_output_link", "admission_symlink",
                     "lock_symlink", "fifo_admission", "oversize_admission"):
            with self.subTest(case=case):
                fixture = self.fixture()
                output = fixture.tag_output
                args = fixture.cli_args("create-tag")
                if case == "occupied":
                    output.write_bytes(b"keep")
                elif case == "output_symlink":
                    target = fixture.root / "target"
                    target.write_bytes(b"keep")
                    output.symlink_to(target)
                elif case == "nested_output_link":
                    actual = fixture.root / "real-parent"
                    actual.mkdir()
                    linked = fixture.root / "linked-parent"
                    linked.symlink_to(actual, target_is_directory=True)
                    output = linked / "tag.json"
                    index = args.index("--output")
                    args[index + 1] = str(output)
                elif case == "admission_symlink":
                    linked = fixture.root / "admission-link.json"
                    linked.symlink_to(fixture.admission_path)
                    index = args.index("--admission")
                    args[index + 1] = str(linked)
                elif case == "lock_symlink":
                    lock = fixture.root / "lock-link.json"
                    lock.symlink_to(fixture.provider.repo / "toolchains/aros-tools-runtime-v1.json")
                    index = args.index("--runtime-lock")
                    args[index + 1] = str(lock)
                elif case == "fifo_admission":
                    fifo = fixture.root / "admission.fifo"
                    os.mkfifo(fifo)
                    index = args.index("--admission")
                    args[index + 1] = str(fifo)
                else:
                    fixture.admission_path.write_bytes(b" " * (controller.MAX_RECORD + 1))
                before_calls = (len(fixture.api_calls), len(fixture.oidc_calls))
                with redirect_stderr(io.StringIO()):
                    stdout_result = controller.main(args)
                self.assertEqual(stdout_result, 1)
                self.assertEqual((len(fixture.api_calls), len(fixture.oidc_calls)), before_calls)
                self.assertEqual(fixture.mutations, [])
                if case == "occupied":
                    self.assertEqual(output.read_bytes(), b"keep")

    def test_stale_admission_main_or_own_job_rejects_before_any_candidate_mutation(self) -> None:
        for probe in ("inactive_repo", "main_advanced", "own_rerun", "wrong_pending_label",
                      "pending_and_tagged"):
            with self.subTest(probe=probe):
                fixture = self.fixture(probe=probe)
                result = fixture.invoke("create-tag")
                self.assertEqual(result, 1)
                self.assertEqual(fixture.mutations, [])
                self.assertFalse(fixture.tag_output.exists())

    def test_unknown_tag_or_ref_mutation_outcomes_stop_without_retry_or_binding(self) -> None:
        for probe, expected_calls in (("tag_unknown", 1), ("ref_unknown", 2)):
            with self.subTest(probe=probe):
                fixture = self.fixture(probe=probe)
                self.assertEqual(fixture.invoke("create-tag"), 1)
                self.assertEqual(len(fixture.mutations), expected_calls)
                self.assertFalse(fixture.tag_output.exists())

    def test_bind_draft_rejects_wrong_action_outputs_public_or_ambiguous_draft(self) -> None:
        for case in ("rp_created", "rp_id", "public", "prerelease", "immutable", "asset", "duplicate"):
            with self.subTest(case=case):
                fixture = self.fixture()
                tag = fixture.create_candidate_tag()
                fixture.create_draft(tag)
                if case == "rp_created":
                    with mock.patch.dict(os.environ, {"RP_CREATED": "false"}):
                        self.assertEqual(fixture.invoke("bind-draft"), 1)
                    self.assertFalse(fixture.draft_output.exists())
                    self.assertEqual(len(fixture.mutations), 2, "draft binding must never perform a mutation")
                    continue
                elif case == "rp_id":
                    with mock.patch.dict(os.environ, {"RP_ID": "01"}):
                        self.assertEqual(fixture.invoke("bind-draft"), 1)
                    self.assertFalse(fixture.draft_output.exists())
                    self.assertEqual(len(fixture.mutations), 2, "draft binding must never perform a mutation")
                    continue
                else:
                    route = f"repos/{REPOSITORY}/releases/{DRAFT_ID}"
                    by_tag = f"repos/{REPOSITORY}/releases/tags/{tag['name']}"
                    fixture.provider.responses[route][{
                        "public": "draft", "prerelease": "prerelease",
                        "immutable": "immutable", "asset": "assets",
                    }.get(case, "draft")] = {
                        "public": False, "prerelease": True, "immutable": True,
                        "asset": [{"id": 1}],
                    }.get(case, True)
                    fixture.provider.responses[by_tag] = copy.deepcopy(fixture.provider.responses[route])
                    listing = fixture.provider.responses[admission_tests.RELEASES_PATH]
                    if case == "duplicate":
                        listing.append(copy.deepcopy(listing[0]))
                self.assertEqual(fixture.invoke("bind-draft"), 1)
                self.assertFalse(fixture.draft_output.exists())
                self.assertEqual(len(fixture.mutations), 2, "draft binding must never perform a mutation")

    def test_live_http_wrapper_is_bounded_fixed_post_and_uses_only_job_token(self) -> None:
        fixture = self.fixture()
        calls = []

        def bounded(command, **kwargs):
            calls.append((list(command), kwargs["env"]))
            return subprocess.CompletedProcess(command, 0, b'{"ok":true}', b"")

        with mock.patch.object(ADMISSION, "_bounded_subprocess", side_effect=bounded):
            self.assertEqual(fixture.real_api_get(f"repos/{REPOSITORY}/releases"), {"ok": True})
        command, environment = calls[0]
        self.assertEqual(command[:3], ["gh", "api", "--method"])
        self.assertIn("GET", command)
        self.assertIn(f"X-GitHub-Api-Version: {controller.API_VERSION}", command)
        self.assertEqual(environment["GH_HOST"], "github.com")
        self.assertEqual(environment["GH_TOKEN"], JOB_TOKEN)
        self.assertNotIn("GH_AUTH_TOKEN", environment)
        self.assertNotIn("GITHUB_TOKEN", environment)
        self.assertNotIn("GOVERNANCE_TOKEN", environment)
        self.assertNotIn("ACTIONS_ID_TOKEN_REQUEST_TOKEN", environment)
        self.assertNotIn("ACTIONS_ID_TOKEN_REQUEST_URL", environment)

    def test_live_mutation_wrapper_posts_private_canonical_body_and_parses_http_headers(self) -> None:
        endpoint = f"repos/{REPOSITORY}/git/tags"
        payload = {"tag": f"v{admission_tests.VERSION}", "object": "a" * 40,
                   "message": "fixture annotated tag"}
        expected_body = (ADMISSION.canonical_json(payload) + "\n").encode("utf-8")
        for newline in (b"\r\n", b"\n"):
            with self.subTest(newline=newline):
                fixture = self.fixture()
                captured = []

                def bounded(command, **kwargs):
                    input_index = command.index("--input") + 1
                    request_path = Path(command[input_index])
                    captured.append({
                        "command": list(command),
                        "environment": dict(kwargs["env"]),
                        "body": request_path.read_bytes(),
                        "mode": stat.S_IMODE(request_path.stat().st_mode),
                    })
                    response = (b"HTTP/2 201 Created" + newline
                                + b"content-type: application/json" + newline * 2
                                + b'{"sha":"' + TAG_OBJECT.encode("ascii") + b'"}')
                    return subprocess.CompletedProcess(command, 0, response, b"")

                with mock.patch.object(ADMISSION, "_bounded_subprocess", side_effect=bounded):
                    self.assertEqual(fixture.real_api_post(endpoint, payload),
                                     (201, {"sha": TAG_OBJECT}))

                self.assertEqual(len(captured), 1)
                call = captured[0]
                command = call["command"]
                self.assertEqual(command[:5], ["gh", "api", "--include", "--method", "POST"])
                self.assertEqual(command[5:7], ["-H", f"X-GitHub-Api-Version: {controller.API_VERSION}"])
                self.assertEqual(command[7], "--input")
                self.assertEqual(command[-1], endpoint)
                self.assertEqual(call["body"], expected_body)
                self.assertEqual(call["mode"], 0o600)
                fixture.assert_job_transport(call["environment"])

    def test_live_mutation_wrapper_rejects_unknown_or_malformed_responses_without_retry(self) -> None:
        endpoint = f"repos/{REPOSITORY}/git/tags"
        payload = {"tag": f"v{admission_tests.VERSION}", "object": "a" * 40,
                   "message": "fixture annotated tag"}
        multiple_blocks = (
            b"HTTP/2 201 Created\r\ncontent-type: application/json\r\n\r\n{}\r\n"
            b"HTTP/2 201 Created\r\ncontent-type: application/json\r\n\r\n{}"
        )
        cases = (
            ("http_failure", subprocess.CompletedProcess([], 1, b"", b"private detail synthetic-secret")),
            ("timeout", "timeout"),
            ("malformed_headers", subprocess.CompletedProcess([], 0, b"not an HTTP response", b"")),
            ("missing_separator", subprocess.CompletedProcess(
                [], 0, b"HTTP/2 201 Created\r\ncontent-type: application/json\r\n{\"ok\":true}", b"")),
            ("multiple_blocks", subprocess.CompletedProcess([], 0, multiple_blocks, b"")),
        )
        for name, response in cases:
            with self.subTest(case=name):
                fixture = self.fixture()
                calls = []

                def bounded(command, **kwargs):
                    calls.append(list(command))
                    request_path = Path(command[command.index("--input") + 1])
                    self.assertEqual(stat.S_IMODE(request_path.stat().st_mode), 0o600)
                    self.assertEqual(request_path.read_bytes(),
                                     (ADMISSION.canonical_json(payload) + "\n").encode("utf-8"))
                    fixture.assert_job_transport(kwargs["env"])
                    if response == "timeout":
                        raise subprocess.TimeoutExpired(
                            command, kwargs["timeout"], stderr=b"synthetic-secret provider trace"
                        )
                    return subprocess.CompletedProcess(
                        command, response.returncode, response.stdout, response.stderr
                    )

                with mock.patch.object(ADMISSION, "_bounded_subprocess", side_effect=bounded):
                    with self.assertRaises(controller.CandidateError) as rejected:
                        fixture.real_api_post(endpoint, payload)
                self.assertEqual(len(calls), 1, "mutation boundary must never retry")
                self.assertNotIn("synthetic-secret", str(rejected.exception))
                self.assertNotIn("private detail", str(rejected.exception))


if __name__ == "__main__":
    unittest.main()
