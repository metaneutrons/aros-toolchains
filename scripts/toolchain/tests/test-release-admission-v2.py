#!/usr/bin/env python3
"""Offline contract tests for metadata-only Release Please admission."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


SOURCE_ROOT = Path(__file__).resolve().parents[3]
SCRIPT_SOURCE = SOURCE_ROOT / "scripts/toolchain/release-admission-v2.py"
RUNTIME_SOURCE = SOURCE_ROOT / "scripts/toolchain/materialize-aros-tools-runtime.py"
LOCK_SOURCE = SOURCE_ROOT / "toolchains/aros-tools-runtime-v1.json"
REPOSITORY = "metaneutrons/aros-toolchains"
RUNTIME_REPOSITORY = "metaneutrons/aros-tools"
BOT_LOGIN = "metaneutrons-release-please[bot]"
VERSION = "1.2.3"
TAG = f"v{VERSION}"
RUN_ID = 900
RUN_ATTEMPT = 1
PR_ID = 1100
PR_NUMBER = 11
RULESET_ID = 55
JOB_ID = 4400
GOV_TOKEN = "governance-secret-fixture"
JOB_TOKEN = "job-token-fixture"

BRANCH_PATH = f"repos/{REPOSITORY}/branches/main"
REPOSITORY_PATH = f"repos/{REPOSITORY}"
COMMIT_PULLS_PATH = ""
PR_FILES_PATH = f"repos/{REPOSITORY}/pulls/{PR_NUMBER}/files"
CLOSED_PULLS_PATH = f"repos/{REPOSITORY}/pulls"
RULESETS_PATH = f"repos/{REPOSITORY}/rulesets"
RULESET_PATH = f"{RULESETS_PATH}/{RULESET_ID}"
CI_RUNS_PATH = f"repos/{REPOSITORY}/actions/workflows/ci.yml/runs"
RUN_PATH = f"repos/{REPOSITORY}/actions/runs/{RUN_ID}"
ATTEMPT_PATH = f"{RUN_PATH}/attempts/{RUN_ATTEMPT}"
JOBS_PATH = f"{ATTEMPT_PATH}/jobs"
RELEASES_PATH = f"repos/{REPOSITORY}/releases"
RUNTIME_RELEASE_PATH = f"repos/{RUNTIME_REPOSITORY}/releases/397412413"
RUNTIME_TAG = "v0.3.12"
RUNTIME_REF_PATH = f"repos/{RUNTIME_REPOSITORY}/git/ref/tags/{RUNTIME_TAG}"
RUNTIME_TAG_OBJECT_PATH = f"repos/{RUNTIME_REPOSITORY}/git/tags/c3899780df174b644305cf00e17181514a1fc31b"
RUNTIME_COMMIT_PATH = f"repos/{RUNTIME_REPOSITORY}/git/commits/ff08ff9df3556113a1eafc9733c3eb0f9445007c"


FAKE_GH = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

args = sys.argv[1:]
if len(args) != 4 or args[:3] != ["api", "--method", "GET"]:
    print("unexpected fake gh command", file=sys.stderr)
    raise SystemExit(91)
endpoint = args[3]
base = endpoint.split("?", 1)[0]
is_ruleset = base.startswith("repos/metaneutrons/aros-toolchains/rulesets")
if "GOVERNANCE_TOKEN" in os.environ:
    print("governance credential leaked outside its adapter", file=sys.stderr)
    raise SystemExit(92)
token = os.environ.get("GH_TOKEN", "")
if token == os.environ.get("FAKE_GOV_TOKEN") and not is_ruleset:
    print("governance token used outside rulesets", file=sys.stderr)
    raise SystemExit(93)
if is_ruleset and token not in {os.environ.get("FAKE_GOV_TOKEN"), os.environ.get("FAKE_JOB_TOKEN")}:
    print("ruleset read lacks an allowed read token", file=sys.stderr)
    raise SystemExit(94)

log_path = Path(os.environ["FAKE_GH_LOG"])
with log_path.open("a", encoding="utf-8") as handle:
    handle.write(json.dumps({
        "endpoint": endpoint,
        "method": "GET",
        "credential": "governance" if token == os.environ.get("FAKE_GOV_TOKEN") else "job",
        "governance_env_present": "GOVERNANCE_TOKEN" in os.environ,
    }, sort_keys=True) + "\n")

configuration = json.loads(Path(os.environ["FAKE_GH_RESPONSES"]).read_text(encoding="utf-8"))
errors = configuration.get("errors", {})
error = errors.get(endpoint, errors.get(base))
if error is not None:
    if error == "transport":
        print("synthetic transport failure containing governance-secret-fixture", file=sys.stderr)
        raise SystemExit(2)
    status = int(error)
    print(f"synthetic provider body governance-secret-fixture (HTTP {status})", file=sys.stderr)
    raise SystemExit(1)

responses = configuration["responses"]
value = responses.get(endpoint, responses.get(base))
if isinstance(value, dict) and "__sequence" in value:
    sequence = value["__sequence"]
    value = sequence.pop(0)
    if not sequence:
        responses[endpoint if endpoint in responses else base] = value
    Path(os.environ["FAKE_GH_RESPONSES"]).write_text(json.dumps(configuration), encoding="utf-8")
if value is None:
    print("synthetic provider body governance-secret-fixture (HTTP 404)", file=sys.stderr)
    raise SystemExit(1)
if isinstance(value, dict) and "__http" in value:
    status = int(value["__http"])
    print(f"synthetic provider body governance-secret-fixture (HTTP {status})", file=sys.stderr)
    raise SystemExit(1)
if isinstance(value, dict) and "__raw_json" in value:
    sys.stdout.write(value["__raw_json"])
else:
    sys.stdout.write(json.dumps(value, separators=(",", ":")))
'''


def _run_git(root: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, check=False)
    if result.returncode:
        raise AssertionError(f"fixture Git command failed: {args!r}: {result.stderr}")
    return result.stdout.strip()


class ReleaseAdmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="release-admission-v2.")
        self.base = Path(self.temporary.name).resolve()
        self.repo = self.base / "fixture-repo"
        self.repo.mkdir()
        (self.repo / "scripts/toolchain").mkdir(parents=True)
        (self.repo / "toolchains").mkdir()
        (self.repo / ".github/workflows").mkdir(parents=True)
        shutil.copyfile(SCRIPT_SOURCE, self.repo / "scripts/toolchain/release-admission-v2.py")
        shutil.copyfile(RUNTIME_SOURCE, self.repo / "scripts/toolchain/materialize-aros-tools-runtime.py")

        self.lock = json.loads(LOCK_SOURCE.read_text(encoding="utf-8"))
        self.selection = {"schema": "fixture", "tools_commit": self.lock["source_commit"]}
        self._write_inputs()
        _run_git(self.repo, "init", "-q")
        _run_git(self.repo, "config", "user.name", "Admission Fixture")
        _run_git(self.repo, "config", "user.email", "admission@example.invalid")
        _run_git(self.repo, "add", ".")
        _run_git(self.repo, "commit", "-q", "-m", "fixture main merge")
        self.head = _run_git(self.repo, "rev-parse", "HEAD")

        self.bin = self.base / "bin"
        self.bin.mkdir()
        fake_gh = self.bin / "gh"
        fake_gh.write_text(FAKE_GH, encoding="utf-8")
        fake_gh.chmod(0o755)
        self.responses_path = self.base / "responses.json"
        self.log_path = self.base / "gh-log.jsonl"
        self.event_path = self.base / "workflow-event.json"
        self._build_scenario()
        self._save_responses()
        self.serial = 0

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_inputs(self) -> None:
        (self.repo / ".release-please-manifest.json").write_text(
            json.dumps({".": VERSION}, sort_keys=True) + "\n", encoding="utf-8"
        )
        (self.repo / "version.txt").write_text(VERSION + "\n", encoding="utf-8")
        (self.repo / "CHANGELOG.md").write_text(f"# Changelog\n\n## {VERSION}\n", encoding="utf-8")
        (self.repo / "toolchains/aros-tools-runtime-v1.json").write_text(
            json.dumps(self.lock, sort_keys=True) + "\n", encoding="utf-8"
        )
        (self.repo / "toolchains/compiler-sdk-ci-selection-v2.json").write_text(
            json.dumps(self.selection, sort_keys=True) + "\n", encoding="utf-8"
        )
        (self.repo / ".github/workflows/ci.yml").write_text(
            "name: Producer contracts\njobs:\n  contracts:\n", encoding="utf-8"
        )

    def _commit_file(self, relative: str, content: str) -> None:
        (self.repo / relative).write_text(content, encoding="utf-8")
        _run_git(self.repo, "add", relative)
        _run_git(self.repo, "commit", "-q", "--amend", "--no-edit")
        self.head = _run_git(self.repo, "rev-parse", "HEAD")
        self._refresh_head_bound_responses()
        self._save_responses()

    def _pull(self) -> dict[str, object]:
        return {
            "id": PR_ID,
            "number": PR_NUMBER,
            "state": "closed",
            "merged_at": "2026-10-13T10:00:00Z",
            "merge_commit_sha": self.head,
            "title": f"chore(main): release {VERSION}",
            "user": {"login": BOT_LOGIN},
            "base": {"ref": "main", "repo": {"full_name": REPOSITORY}},
            "head": {"ref": "release-please--branches--main", "repo": {"full_name": REPOSITORY}},
            "labels": [{"name": "autorelease: pending"}],
        }

    def _workflow_run(self) -> dict[str, object]:
        return {
            "id": RUN_ID,
            "run_attempt": RUN_ATTEMPT,
            "name": "Producer contracts",
            "path": ".github/workflows/ci.yml",
            "event": "push",
            "head_branch": "main",
            "head_sha": self.head,
            "head_repository": {"full_name": REPOSITORY},
            "status": "completed",
            "conclusion": "success",
        }

    def _build_scenario(self) -> None:
        asset_list = []
        next_asset_id = 3000
        for host in self.lock["hosts"].values():
            for field in ("archive", "manifest", "archive_bundle", "manifest_bundle"):
                asset = host[field]
                next_asset_id += 1
                asset_list.append({
                    "id": next_asset_id,
                    "name": asset["name"],
                    "size": asset["size"],
                    "digest": f"sha256:{asset['sha256']}",
                })
        for index in range(28):
            asset_list.append({
                "id": 5000 + index,
                "name": f"aros-tools-v0.3.12-platform-asset-{index + 1}.tar.gz",
                "size": 1024 + index,
                "digest": "sha256:" + f"{index + 1:064x}",
            })
        epoch = self.lock["source_date_epoch"]
        commit_date = datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        workflow_run = self._workflow_run()
        self.responses: dict[str, object] = {
            REPOSITORY_PATH: {
                "full_name": REPOSITORY,
                "archived": False,
                "disabled": False,
                "default_branch": "main",
            },
            BRANCH_PATH: {"protected": True, "commit": {"sha": self.head}},
            RULESETS_PATH: [{"id": RULESET_ID, "target": "tag", "enforcement": "active"}],
            RULESET_PATH: {
                "id": RULESET_ID,
                "target": "tag",
                "enforcement": "active",
                "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
                "rules": [{"type": "update"}, {"type": "deletion"}],
                "bypass_actors": [],
            },
            RUNTIME_RELEASE_PATH: {
                "id": self.lock["release_id"],
                "tag_name": self.lock["tag"],
                "draft": False,
                "prerelease": False,
                "immutable": True,
                "assets": asset_list,
            },
            RUNTIME_REF_PATH: {"ref": f"refs/tags/{RUNTIME_TAG}", "object": {
                "type": "tag", "sha": self.lock["tag_object"]}},
            RUNTIME_TAG_OBJECT_PATH: {
                "sha": self.lock["tag_object"],
                "tag": RUNTIME_TAG,
                "object": {"type": "commit", "sha": self.lock["source_commit"]},
            },
            RUNTIME_COMMIT_PATH: {
                "sha": self.lock["source_commit"],
                "tree": {"sha": self.lock["source_tree"]},
                "committer": {"date": commit_date},
            },
            PR_FILES_PATH: [
                {"filename": ".release-please-manifest.json", "status": "modified"},
                {"filename": "version.txt", "status": "modified"},
                {"filename": "CHANGELOG.md", "status": "modified"},
            ],
            CI_RUNS_PATH: {"total_count": 1, "workflow_runs": [workflow_run]},
            RUN_PATH: workflow_run,
            ATTEMPT_PATH: workflow_run,
            JOBS_PATH: {"total_count": 1, "jobs": [{
                "id": JOB_ID, "name": "contracts", "status": "completed", "conclusion": "success"
            }]},
            RELEASES_PATH: [],
        }
        self.responses[f"repos/{RUNTIME_REPOSITORY}/git/ref/tags/{TAG}"] = {
            "__http": 404,
        }
        self.responses[f"repos/{REPOSITORY}/commits/{self.head}/pulls"] = [self._pull()]
        self.responses[CLOSED_PULLS_PATH] = [self._pull()]
        self.errors: dict[str, object] = {}
        self._write_event(workflow_run)

    def _refresh_head_bound_responses(self) -> None:
        self.responses[BRANCH_PATH] = {"protected": True, "commit": {"sha": self.head}}
        self.responses[CI_RUNS_PATH] = {"total_count": 1, "workflow_runs": [self._workflow_run()]}
        self.responses[RUN_PATH] = self._workflow_run()
        self.responses[ATTEMPT_PATH] = self._workflow_run()
        self.responses[f"repos/{REPOSITORY}/commits/{self.head}/pulls"] = [self._pull()]
        self.responses[CLOSED_PULLS_PATH] = [self._pull()]
        self._write_event(self._workflow_run())

    def _write_event(self, workflow_run: dict[str, object]) -> None:
        self.event_path.write_text(json.dumps({"workflow_run": workflow_run}), encoding="utf-8")

    def _save_responses(self) -> None:
        self.responses_path.write_text(
            json.dumps({"responses": self.responses, "errors": self.errors}, sort_keys=True),
            encoding="utf-8",
        )

    def _environment(self, *, event: str = "workflow_run") -> dict[str, str]:
        environment = dict(os.environ)
        environment.update({
            "PATH": f"{self.bin}:{environment.get('PATH', '')}",
            "GITHUB_REPOSITORY": REPOSITORY,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_EVENT_NAME": event,
            "GITHUB_EVENT_PATH": str(self.event_path),
            "GH_TOKEN": JOB_TOKEN,
            "GOVERNANCE_TOKEN": GOV_TOKEN,
            "FAKE_GOV_TOKEN": GOV_TOKEN,
            "FAKE_JOB_TOKEN": JOB_TOKEN,
            "FAKE_GH_RESPONSES": str(self.responses_path),
            "FAKE_GH_LOG": str(self.log_path),
        })
        return environment

    def _run_admit(
        self,
        *,
        event: str = "workflow_run",
        output: Path | None = None,
        github_output: Path | None = None,
        environment: dict[str, str] | None = None,
    ) -> tuple[subprocess.CompletedProcess[str], Path, Path]:
        self.serial += 1
        if output is None:
            output = self.base / f"receipt-{self.serial}.json"
        if github_output is None:
            github_output = self.base / f"github-output-{self.serial}.txt"
            github_output.write_bytes(b"")
        run_environment = self._environment(event=event)
        if environment is not None:
            run_environment.update(environment)
        result = subprocess.run(
            [sys.executable, "-B", str(self.repo / "scripts/toolchain/release-admission-v2.py"),
             "admit", "--output", str(output), "--github-output", str(github_output)],
            cwd=self.repo,
            env=run_environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        return result, output, github_output

    def _run_recheck(self, admission: Path, output: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-B", str(self.repo / "scripts/toolchain/release-admission-v2.py"),
             "recheck", "--admission", str(admission), "--output", str(output)],
            cwd=self.repo,
            env=self._environment(event="workflow_dispatch"),
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )

    def _api_route(self, path: str, value: object) -> None:
        self.responses[path] = value
        self._save_responses()

    def _api_error(self, path: str, value: object) -> None:
        self.errors[path] = value
        self._save_responses()

    def _assert_rejected(self, result: subprocess.CompletedProcess[str]) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(result.stdout, "")
        self.assertIn("release admission failed:", result.stderr)
        self.assertNotIn(GOV_TOKEN, result.stderr)
        self.assertNotIn(JOB_TOKEN, result.stderr)

    def test_main_advance_during_admission_does_not_emit_a_stale_receipt(self) -> None:
        self._api_route(BRANCH_PATH, {"__sequence": [
            {"protected": True, "commit": {"sha": self.head}},
            {"protected": True, "commit": {"sha": "a" * 40}},
        ]})
        result, output, github_output = self._run_admit()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(output.exists())
        self.assertEqual(github_output.read_bytes(), b"ready=false\n")

    def test_staged_change_hidden_by_restored_worktree_is_rejected(self) -> None:
        selection_path = self.repo / "toolchains/compiler-sdk-ci-selection-v2.json"
        original = selection_path.read_bytes()
        selection_path.write_bytes(original + b"\n")
        _run_git(self.repo, "add", "toolchains/compiler-sdk-ci-selection-v2.json")
        selection_path.write_bytes(original)
        result, output, github_output = self._run_admit()
        self._assert_rejected(result)
        self.assertFalse(output.exists())
        self.assertEqual(github_output.read_bytes(), b"")

    def test_positive_admission_is_closed_metadata_receipt_and_only_get(self) -> None:
        result, output, github_output = self._run_admit()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(output.is_file())
        receipt = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(set(receipt), {
            "schema", "assurance", "repository", "commit", "version", "tag",
            "pull_request", "runs", "governance", "inputs", "release_absence",
        })
        self.assertEqual(receipt["repository"], REPOSITORY)
        self.assertEqual(receipt["commit"], self.head)
        self.assertEqual(receipt["version"], VERSION)
        self.assertEqual(receipt["tag"], TAG)
        self.assertEqual(receipt["pull_request"], PR_NUMBER)
        self.assertEqual(len(self.responses[RUNTIME_RELEASE_PATH]["assets"]), 40)
        self.assertEqual(receipt["runs"]["producer_contracts"], {"id": RUN_ID, "attempt": RUN_ATTEMPT})
        self.assertEqual(set(receipt["inputs"]), {
            ".release-please-manifest.json", "version.txt", "CHANGELOG.md",
            "toolchains/aros-tools-runtime-v1.json", "toolchains/compiler-sdk-ci-selection-v2.json",
            ".github/workflows/ci.yml", "scripts/toolchain/materialize-aros-tools-runtime.py",
        })
        self.assertEqual(receipt["release_absence"]["private_draft_absence"], "unproven")
        self.assertEqual(receipt["release_absence"]["required_start_recheck"]["permission"], "contents:write")
        output_lines = github_output.read_text(encoding="utf-8").splitlines()
        self.assertEqual(output_lines[0], "ready=true")
        self.assertEqual(json.loads(output_lines[1].removeprefix("admission=")), receipt)
        log = [json.loads(line) for line in self.log_path.read_text(encoding="utf-8").splitlines()]
        self.assertTrue(log)
        self.assertTrue(all(entry["method"] == "GET" for entry in log))
        self.assertTrue(all(not entry["governance_env_present"] for entry in log))
        self.assertTrue(all(
            entry["credential"] == ("governance" if "/rulesets" in entry["endpoint"] else "job")
            for entry in log
        ))
        self.assertFalse(any("releases/assets" in entry["endpoint"] for entry in log))

    def test_repository_root_allowlist_accepts_only_the_exact_root(self) -> None:
        probe = (
            "import json,runpy,sys; "
            "module=runpy.run_path(sys.argv[1],run_name='api_allowlist_probe'); "
            "print(json.dumps(module['api'](sys.argv[2])))"
        )
        script = str(self.repo / "scripts/toolchain/release-admission-v2.py")
        valid = subprocess.run(
            [sys.executable, "-B", "-c", probe, script, REPOSITORY_PATH],
            cwd=self.repo, env=self._environment(), capture_output=True, text=True, check=False, timeout=30,
        )
        self.assertEqual(valid.returncode, 0, valid.stderr)
        self.assertEqual(json.loads(valid.stdout)["full_name"], REPOSITORY)
        for endpoint in (
            f"{REPOSITORY_PATH}?per_page=100",
            f"{REPOSITORY_PATH}-extra",
            "repos/metaneutrons-extra/aros-toolchains",
        ):
            with self.subTest(endpoint=endpoint):
                invalid = subprocess.run(
                    [sys.executable, "-B", "-c", probe, script, endpoint],
                    cwd=self.repo, env=self._environment(), capture_output=True, text=True,
                    check=False, timeout=30,
                )
                self.assertNotEqual(invalid.returncode, 0)
        log = [json.loads(line) for line in self.log_path.read_text(encoding="utf-8").splitlines()]
        self.assertEqual([entry["endpoint"] for entry in log], [REPOSITORY_PATH])

    def test_repository_must_be_explicitly_active_and_match_identity(self) -> None:
        active = self.responses[REPOSITORY_PATH]
        assert isinstance(active, dict)
        cases = [
            ("archived", {**active, "archived": True}),
            ("disabled", {**active, "disabled": True}),
            ("missing archived", {key: value for key, value in active.items() if key != "archived"}),
            ("missing disabled", {key: value for key, value in active.items() if key != "disabled"}),
            ("malformed archived", {**active, "archived": "false"}),
            ("malformed disabled", {**active, "disabled": 0}),
            ("wrong repository", {**active, "full_name": "metaneutrons/aros-toolchains-extra"}),
            ("wrong default branch", {**active, "default_branch": "trunk"}),
        ]
        for label, metadata in cases:
            with self.subTest(label=label):
                self._api_route(REPOSITORY_PATH, metadata)
                result, output, github_output = self._run_admit()
                self._assert_rejected(result)
                self.assertFalse(output.exists())
                self.assertEqual(github_output.read_bytes(), b"")
                log = [json.loads(line) for line in self.log_path.read_text(encoding="utf-8").splitlines()]
                endpoints = [entry["endpoint"] for entry in log]
                self.assertIn(REPOSITORY_PATH, endpoints)
                self.assertNotIn(f"repos/{REPOSITORY}/git/ref/tags/{TAG}", endpoints)
                self.assertFalse(any(endpoint.startswith(RELEASES_PATH) for endpoint in endpoints))

    def test_repository_archived_during_absence_survey_is_rejected_before_output(self) -> None:
        active = self.responses[REPOSITORY_PATH]
        assert isinstance(active, dict)
        self._api_route(REPOSITORY_PATH, {"__sequence": [
            active,
            {**active, "archived": True},
        ]})
        result, output, github_output = self._run_admit()
        self._assert_rejected(result)
        self.assertFalse(output.exists())
        self.assertEqual(github_output.read_bytes(), b"")
        log = [json.loads(line) for line in self.log_path.read_text(encoding="utf-8").splitlines()]
        endpoints = [entry["endpoint"] for entry in log]
        self.assertEqual(endpoints.count(REPOSITORY_PATH), 2)
        tag_ref_path = f"repos/{REPOSITORY}/git/ref/tags/{TAG}"
        releases_page_path = RELEASES_PATH + "?per_page=100&page=1"
        self.assertLess(endpoints.index(REPOSITORY_PATH), endpoints.index(tag_ref_path))
        self.assertLess(endpoints.index(tag_ref_path), endpoints.index(releases_page_path))
        self.assertLess(endpoints.index(releases_page_path), len(endpoints) - 1)
        self.assertEqual(endpoints[-1], REPOSITORY_PATH)

    def test_repository_root_errors_never_mean_candidate_absence(self) -> None:
        for status in (404, 401, 403, 429):
            with self.subTest(status=status):
                self._api_error(REPOSITORY_PATH, status)
                result, output, github_output = self._run_admit()
                self._assert_rejected(result)
                self.assertFalse(output.exists())
                self.assertEqual(github_output.read_bytes(), b"")
                log = [json.loads(line) for line in self.log_path.read_text(encoding="utf-8").splitlines()]
                endpoints = [entry["endpoint"] for entry in log]
                self.assertIn(REPOSITORY_PATH, endpoints)
                self.assertNotIn(f"repos/{REPOSITORY}/git/ref/tags/{TAG}", endpoints)

    def test_recheck_repeats_metadata_gates_and_preserves_receipt(self) -> None:
        admitted, admission_path, _ = self._run_admit()
        self.assertEqual(admitted.returncode, 0, admitted.stderr)
        output = self.base / "rechecked.json"
        result = self._run_recheck(admission_path, output)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output.read_bytes(), admission_path.read_bytes())
        log = [json.loads(line) for line in self.log_path.read_text(encoding="utf-8").splitlines()]
        recheck_rules = [entry for entry in log if "/rulesets" in entry["endpoint"]][2:]
        self.assertTrue(recheck_rules)
        self.assertTrue(all(entry["credential"] == "job" for entry in recheck_rules))

    def test_stale_or_nonrelease_events_return_ready_false_without_receipt(self) -> None:
        self._write_event({**self._workflow_run(), "head_sha": "f" * 40})
        result, output, github_output = self._run_admit()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(output.exists())
        self.assertEqual(github_output.read_text(encoding="utf-8"), "ready=false\n")
        result, output, github_output = self._run_admit(event="pull_request")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(output.exists())
        self.assertEqual(github_output.read_text(encoding="utf-8"), "ready=false\n")

    def test_workflow_run_must_be_the_current_latest_attempt(self) -> None:
        self._write_event({**self._workflow_run(), "id": RUN_ID + 1})
        result, output, github_output = self._run_admit()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(output.exists())
        self.assertEqual(github_output.read_text(encoding="utf-8"), "ready=false\n")
        self._write_event({**self._workflow_run(), "path": ".github/workflows/other.yml"})
        result, output, github_output = self._run_admit()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(output.exists())
        self.assertEqual(github_output.read_text(encoding="utf-8"), "ready=false\n")

    def test_wrong_repository_or_non_main_dispatch_is_not_admitted(self) -> None:
        result, output, github_output = self._run_admit(event="workflow_dispatch")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(output.exists())
        env = self._environment(event="workflow_dispatch")
        env["GITHUB_REF"] = "refs/heads/feature"
        other_output = self.base / "other-receipt.json"
        other_github_output = self.base / "other-github-output.txt"
        other_github_output.write_bytes(b"")
        other = subprocess.run(
            [sys.executable, "-B", str(self.repo / "scripts/toolchain/release-admission-v2.py"),
             "admit", "--output", str(other_output), "--github-output", str(other_github_output)],
            cwd=self.repo, env=env, capture_output=True, text=True, check=False,
        )
        self.assertEqual(other.returncode, 0, other.stderr)
        self.assertFalse(other_output.exists())
        self.assertEqual(other_github_output.read_text(encoding="utf-8"), "ready=false\n")
        env = self._environment(event="workflow_dispatch")
        env["GITHUB_REPOSITORY"] = "someone-else/another-repository"
        other_repo_output = self.base / "wrong-repository-receipt.json"
        other_repo_github_output = self.base / "wrong-repository-github-output.txt"
        other_repo_github_output.write_bytes(b"")
        wrong_repo = subprocess.run(
            [sys.executable, "-B", str(self.repo / "scripts/toolchain/release-admission-v2.py"),
             "admit", "--output", str(other_repo_output), "--github-output", str(other_repo_github_output)],
            cwd=self.repo, env=env, capture_output=True, text=True, check=False,
        )
        self.assertEqual(wrong_repo.returncode, 0, wrong_repo.stderr)
        self.assertFalse(other_repo_output.exists())
        self.assertEqual(other_repo_github_output.read_text(encoding="utf-8"), "ready=false\n")
        self.assertTrue(output.exists())

    def test_main_must_be_protected_and_match_the_local_commit(self) -> None:
        self._api_route(BRANCH_PATH, {"protected": False, "commit": {"sha": self.head}})
        result, _, github_output = self._run_admit()
        self._assert_rejected(result)
        self.assertEqual(github_output.read_bytes(), b"")
        self._api_route(BRANCH_PATH, {"protected": True, "commit": {"sha": "f" * 40}})
        result, output, github_output = self._run_admit()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(output.exists())
        self.assertEqual(github_output.read_text(encoding="utf-8"), "ready=false\n")

    def test_ordinary_main_without_release_pr_skips_runtime_and_governance(self) -> None:
        selection = dict(self.selection)
        selection["tools_commit"] = "0" * 40
        self._commit_file("toolchains/compiler-sdk-ci-selection-v2.json",
                          json.dumps(selection, sort_keys=True) + "\n")
        self._api_route(f"repos/{REPOSITORY}/commits/{self.head}/pulls", [])
        environment = self._environment(event="workflow_dispatch")
        environment.pop("GOVERNANCE_TOKEN")
        result, output, github_output = self._run_admit(
            event="workflow_dispatch", environment=environment
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(output.exists())
        self.assertEqual(github_output.read_text(encoding="utf-8"), "ready=false\n")
        log = [json.loads(line) for line in self.log_path.read_text(encoding="utf-8").splitlines()]
        endpoints = [entry["endpoint"] for entry in log]
        self.assertEqual(endpoints, [
            f"repos/{REPOSITORY}/branches/main",
            f"repos/{REPOSITORY}/commits/{self.head}/pulls?per_page=100&page=1",
        ])

    def test_tracked_checkout_modifications_are_rejected_before_validation(self) -> None:
        for relative in (
            "scripts/toolchain/materialize-aros-tools-runtime.py",
            "toolchains/compiler-sdk-ci-selection-v2.json",
        ):
            with self.subTest(path=relative):
                path = self.repo / relative
                original = path.read_text(encoding="utf-8")
                path.write_text(original + "\n# local tracked modification\n", encoding="utf-8")
                result, output, github_output = self._run_admit()
                self._assert_rejected(result)
                self.assertIn("tracked checkout differs from HEAD", result.stderr)
                self.assertFalse(output.exists())
                self.assertEqual(github_output.read_bytes(), b"")
                path.write_text(original, encoding="utf-8")

    def test_release_pr_must_be_exact_unique_app_authored_and_pending(self) -> None:
        with self.subTest("wrong author"):
            self._api_route(f"repos/{REPOSITORY}/commits/{self.head}/pulls", [{
                **self._pull(), "user": {"login": "untrusted-user"},
            }])
            result, _, _ = self._run_admit()
            self._assert_rejected(result)
            self._api_route(f"repos/{REPOSITORY}/commits/{self.head}/pulls", [self._pull()])
        with self.subTest("wrong file set"):
            self._api_route(PR_FILES_PATH, [
                {"filename": ".release-please-manifest.json", "status": "modified"},
                {"filename": "version.txt", "status": "modified"},
                {"filename": "README.md", "status": "modified"},
            ])
            result, _, _ = self._run_admit()
            self._assert_rejected(result)
            self._api_route(PR_FILES_PATH, [
                {"filename": ".release-please-manifest.json", "status": "modified"},
                {"filename": "version.txt", "status": "modified"},
                {"filename": "CHANGELOG.md", "status": "modified"},
            ])
        with self.subTest("wrong status"):
            self._api_route(PR_FILES_PATH, [
                {"filename": ".release-please-manifest.json", "status": "modified"},
                {"filename": "version.txt", "status": "added"},
                {"filename": "CHANGELOG.md", "status": "modified"},
            ])
            result, _, _ = self._run_admit()
            self._assert_rejected(result)
            self._api_route(PR_FILES_PATH, [
                {"filename": ".release-please-manifest.json", "status": "modified"},
                {"filename": "version.txt", "status": "modified"},
                {"filename": "CHANGELOG.md", "status": "modified"},
            ])
        with self.subTest("retired label"):
            self._api_route(f"repos/{REPOSITORY}/commits/{self.head}/pulls", [{
                **self._pull(), "labels": [{"name": "autorelease: triggered"}],
            }])
            result, output, github_output = self._run_admit()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(output.exists())
            self.assertEqual(github_output.read_text(encoding="utf-8"), "ready=false\n")
        with self.subTest("ambiguous merge"):
            second = self._pull()
            second.update({"id": PR_ID + 1, "number": PR_NUMBER + 1})
            self._api_route(f"repos/{REPOSITORY}/commits/{self.head}/pulls", [self._pull(), second])
            result, _, _ = self._run_admit()
            self._assert_rejected(result)
        with self.subTest("other merged pending release"):
            other = self._pull()
            other.update({"id": PR_ID + 2, "number": PR_NUMBER + 2, "merge_commit_sha": "e" * 40})
            self._api_route(CLOSED_PULLS_PATH, [self._pull(), other])
            result, _, _ = self._run_admit()
            self._assert_rejected(result)

    def test_runtime_lock_and_public_release_metadata_must_match(self) -> None:
        selection = dict(self.selection)
        selection["tools_commit"] = "0" * 40
        self.selection = selection
        self._commit_file("toolchains/compiler-sdk-ci-selection-v2.json",
                          json.dumps(self.selection, sort_keys=True) + "\n")
        result, _, github_output = self._run_admit()
        self._assert_rejected(result)
        self.assertEqual(github_output.read_bytes(), b"")

    def test_runtime_asset_tag_tree_and_epoch_drift_are_rejected(self) -> None:
        valid_release = self.responses[RUNTIME_RELEASE_PATH]
        assert isinstance(valid_release, dict)
        cases = (
            ("asset digest", RUNTIME_RELEASE_PATH, {**valid_release, "assets": [
                {**valid_release["assets"][0], "digest": "sha256:" + "0" * 64},
                *valid_release["assets"][1:],
            ]}),
            ("locked asset size", RUNTIME_RELEASE_PATH, {**valid_release, "assets": [
                {**valid_release["assets"][0], "size": valid_release["assets"][0]["size"] + 1},
                *valid_release["assets"][1:],
            ]}),
            ("runtime immutable flag", RUNTIME_RELEASE_PATH, {**valid_release, "immutable": False}),
            ("runtime tag object", RUNTIME_REF_PATH, {
                "ref": f"refs/tags/{RUNTIME_TAG}", "object": {"type": "tag", "sha": "0" * 40},
            }),
            ("annotated tag target", RUNTIME_TAG_OBJECT_PATH, {
                "sha": self.lock["tag_object"], "tag": RUNTIME_TAG,
                "object": {"type": "commit", "sha": "0" * 40},
            }),
            ("source tree", RUNTIME_COMMIT_PATH, {
                "sha": self.lock["source_commit"], "tree": {"sha": "0" * 40},
                "committer": {"date": "2026-10-01T00:00:00Z"},
            }),
            ("source epoch", RUNTIME_COMMIT_PATH, {
                "sha": self.lock["source_commit"], "tree": {"sha": self.lock["source_tree"]},
                "committer": {"date": "2026-10-01T00:00:00Z"},
            }),
        )
        for label, path, value in cases:
            with self.subTest(label=label):
                original = self.responses[path]
                self._api_route(path, value)
                result, _, _ = self._run_admit()
                self._assert_rejected(result)
                self._api_route(path, original)

    def test_all_assets_are_unique_but_only_the_twelve_locked_assets_are_selected(self) -> None:
        valid_release = self.responses[RUNTIME_RELEASE_PATH]
        assert isinstance(valid_release, dict)
        assets = valid_release["assets"]
        with self.subTest("duplicate provider ID on an unrelated asset"):
            duplicate_id = {**assets[-1], "id": assets[0]["id"], "name": "extra-duplicate-id.tar.gz"}
            self._api_route(RUNTIME_RELEASE_PATH, {**valid_release, "assets": [*assets, duplicate_id]})
            result, _, _ = self._run_admit()
            self._assert_rejected(result)
        with self.subTest("duplicate provider name"):
            duplicate_name = {**assets[-1], "id": 99999, "name": assets[0]["name"]}
            self._api_route(RUNTIME_RELEASE_PATH, {**valid_release, "assets": [*assets, duplicate_name]})
            result, _, _ = self._run_admit()
            self._assert_rejected(result)
        with self.subTest("missing locked asset"):
            self._api_route(RUNTIME_RELEASE_PATH, {**valid_release, "assets": assets[1:]})
            result, _, _ = self._run_admit()
            self._assert_rejected(result)
        self._api_route(RUNTIME_RELEASE_PATH, valid_release)

    def test_governance_requires_explicit_empty_bypass_and_exact_scope(self) -> None:
        ruleset = dict(self.responses[RULESET_PATH])
        ruleset.pop("bypass_actors")
        self._api_route(RULESET_PATH, ruleset)
        result, _, github_output = self._run_admit()
        self._assert_rejected(result)
        self.assertEqual(github_output.read_bytes(), b"")
        ruleset["bypass_actors"] = []
        ruleset["conditions"] = {"ref_name": {"include": ["refs/tags/*"], "exclude": []}}
        self._api_route(RULESET_PATH, ruleset)
        result, _, _ = self._run_admit()
        self._assert_rejected(result)

    def test_governance_receipt_expiry_and_public_policy_drift_block_recheck(self) -> None:
        admitted, admission_path, _ = self._run_admit()
        self.assertEqual(admitted.returncode, 0, admitted.stderr)
        original = json.loads(admission_path.read_text(encoding="utf-8"))
        expired = dict(original)
        expired["governance"] = {**original["governance"], "checked_at": 1}
        expired_path = self.base / "expired-admission.json"
        expired_path.write_text(json.dumps(expired), encoding="utf-8")
        expired_output = self.base / "expired-output.json"
        result = self._run_recheck(expired_path, expired_output)
        self._assert_rejected(result)
        self.assertFalse(expired_output.exists())

        changed = dict(self.responses[RULESET_PATH])
        changed["rules"] = [*changed["rules"], {"type": "required_signatures"}]
        self._api_route(RULESET_PATH, changed)
        changed_output = self.base / "changed-output.json"
        result = self._run_recheck(admission_path, changed_output)
        self._assert_rejected(result)
        self.assertFalse(changed_output.exists())

        omitted = dict(self.responses[RULESET_PATH])
        omitted.pop("bypass_actors")
        self._api_route(RULESET_PATH, omitted)
        omitted_output = self.base / "omitted-bypass-recheck.json"
        result = self._run_recheck(admission_path, omitted_output)
        self._assert_rejected(result)
        self.assertFalse(omitted_output.exists())

    def test_ci_must_use_explicit_latest_successful_attempt_and_contract_job(self) -> None:
        with self.subTest("run detail attempt drift"):
            self._api_route(RUN_PATH, {**self._workflow_run(), "run_attempt": RUN_ATTEMPT + 1})
            result, _, _ = self._run_admit()
            self._assert_rejected(result)
        self._api_route(RUN_PATH, self._workflow_run())
        with self.subTest("attempt endpoint drift"):
            self._api_route(ATTEMPT_PATH, {**self._workflow_run(), "run_attempt": RUN_ATTEMPT + 1})
            result, _, _ = self._run_admit()
            self._assert_rejected(result)
        self._api_route(ATTEMPT_PATH, self._workflow_run())
        with self.subTest("missing contracts job"):
            self._api_route(JOBS_PATH, {"jobs": [{
                "id": JOB_ID, "name": "other", "status": "completed", "conclusion": "success",
            }]})
            result, _, _ = self._run_admit()
            self._assert_rejected(result)
        with self.subTest("duplicate contracts job"):
            self._api_route(JOBS_PATH, {"jobs": [
                {"id": JOB_ID, "name": "contracts", "status": "completed", "conclusion": "success"},
                {"id": JOB_ID + 1, "name": "contracts", "status": "completed", "conclusion": "success"},
            ]})
            result, _, _ = self._run_admit()
            self._assert_rejected(result)
        with self.subTest("other failed job"):
            self._api_route(JOBS_PATH, {"jobs": [
                {"id": JOB_ID, "name": "contracts", "status": "completed", "conclusion": "success"},
                {"id": JOB_ID + 1, "name": "optional", "status": "completed", "conclusion": "failure"},
            ]})
            result, _, _ = self._run_admit()
            self._assert_rejected(result)
        with self.subTest("duplicate job id"):
            self._api_route(JOBS_PATH, {"jobs": [
                {"id": JOB_ID, "name": "contracts", "status": "completed", "conclusion": "success"},
                {"id": JOB_ID, "name": "other", "status": "completed", "conclusion": "skipped"},
            ]})
            result, _, _ = self._run_admit()
            self._assert_rejected(result)

    def test_only_real_404_means_candidate_tag_absent(self) -> None:
        path = f"repos/{REPOSITORY}/git/ref/tags/{TAG}"
        for status in (401, 403, 429):
            with self.subTest(status=status):
                self._api_error(path, status)
                result, output, github_output = self._run_admit()
                self._assert_rejected(result)
                self.assertFalse(output.exists())
                self.assertEqual(github_output.read_bytes(), b"")
                self.assertNotIn("governance-secret-fixture", result.stderr)
        self._api_error(path, "transport")
        result, output, github_output = self._run_admit()
        self._assert_rejected(result)
        self.assertFalse(output.exists())
        self.assertEqual(github_output.read_bytes(), b"")

    def test_api_metadata_response_is_bounded_before_json_decode(self) -> None:
        self._api_route(BRANCH_PATH, "x" * (8 * 1024 * 1024 + 1))
        result, output, github_output = self._run_admit()
        self._assert_rejected(result)
        self.assertIn("exceeded its output limit", result.stderr)
        self.assertFalse(output.exists())
        self.assertEqual(github_output.read_bytes(), b"")

    def test_existing_tag_or_release_is_consumed_and_never_revived(self) -> None:
        tag_ref = f"repos/{REPOSITORY}/git/ref/tags/{TAG}"
        self._api_route(tag_ref, {"ref": f"refs/tags/{TAG}", "object": {"type": "tag", "sha": "a" * 40}})
        result, output, github_output = self._run_admit()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(output.exists())
        self.assertEqual(github_output.read_text(encoding="utf-8"), "ready=false\n")
        self.responses.pop(tag_ref)
        self._api_route(RELEASES_PATH, [{"id": 700, "tag_name": TAG, "draft": True}])
        result, output, github_output = self._run_admit()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(output.exists())
        self.assertEqual(github_output.read_text(encoding="utf-8"), "ready=false\n")

    def test_duplicate_ids_and_duplicate_json_keys_are_rejected(self) -> None:
        pulls_path = f"repos/{REPOSITORY}/commits/{self.head}/pulls"
        self._api_route(pulls_path, [self._pull(), self._pull()])
        result, _, _ = self._run_admit()
        self._assert_rejected(result)
        self.responses[pulls_path] = {"__raw_json": '[{"id":1100,"id":1101}]'}
        self._save_responses()
        result, _, _ = self._run_admit()
        self._assert_rejected(result)

    def test_failed_admission_and_exclusive_output_preserve_sentinels(self) -> None:
        tag_ref = f"repos/{REPOSITORY}/git/ref/tags/{TAG}"
        self._api_error(tag_ref, 403)
        sentinel_output = self.base / "sentinel-receipt.json"
        sentinel_output.write_text("receipt sentinel\n", encoding="utf-8")
        github_output = self.base / "sentinel-github-output.txt"
        github_output.write_text("workflow sentinel\n", encoding="utf-8")
        result, _, _ = self._run_admit(output=sentinel_output, github_output=github_output)
        self._assert_rejected(result)
        self.assertEqual(sentinel_output.read_text(encoding="utf-8"), "receipt sentinel\n")
        self.assertEqual(github_output.read_text(encoding="utf-8"), "workflow sentinel\n")
        self._api_error(tag_ref, None)
        result, _, _ = self._run_admit(output=sentinel_output, github_output=github_output)
        self._assert_rejected(result)
        self.assertEqual(sentinel_output.read_text(encoding="utf-8"), "receipt sentinel\n")
        self.assertEqual(github_output.read_text(encoding="utf-8"), "workflow sentinel\n")
        self._api_error(REPOSITORY_PATH, 404)
        result, _, _ = self._run_admit(output=sentinel_output, github_output=github_output)
        self._assert_rejected(result)
        self.assertEqual(sentinel_output.read_text(encoding="utf-8"), "receipt sentinel\n")
        self.assertEqual(github_output.read_text(encoding="utf-8"), "workflow sentinel\n")

    def test_event_saved_receipt_and_github_output_reject_links_and_oversize_files(self) -> None:
        target_output = self.base / "target-output.txt"
        target_output.write_text("untouched\n", encoding="utf-8")
        event_symlink = self.base / "event-symlink.json"
        event_symlink.symlink_to(self.event_path)
        result, output, github_output = self._run_admit(
            environment={"GITHUB_EVENT_PATH": str(event_symlink)}
        )
        self._assert_rejected(result)
        self.assertFalse(output.exists())
        self.assertEqual(github_output.read_bytes(), b"")

        event_hardlink = self.base / "event-hardlink.json"
        os.link(self.event_path, event_hardlink)
        result, output, github_output = self._run_admit(
            environment={"GITHUB_EVENT_PATH": str(event_hardlink)}
        )
        self._assert_rejected(result)
        self.assertFalse(output.exists())
        self.assertEqual(github_output.read_bytes(), b"")
        event_hardlink.unlink()

        oversized_event = self.base / "oversized-event.json"
        oversized_event.write_bytes(b"x" * (1024 * 1024 + 1))
        result, output, github_output = self._run_admit(
            environment={"GITHUB_EVENT_PATH": str(oversized_event)}
        )
        self._assert_rejected(result)
        self.assertFalse(output.exists())
        self.assertEqual(github_output.read_bytes(), b"")
        self.assertEqual(target_output.read_text(encoding="utf-8"), "untouched\n")

        admitted, admission_path, _ = self._run_admit()
        self.assertEqual(admitted.returncode, 0, admitted.stderr)
        receipt_symlink = self.base / "receipt-symlink.json"
        receipt_symlink.symlink_to(admission_path)
        symlink_output = self.base / "symlink-recheck.json"
        result = self._run_recheck(receipt_symlink, symlink_output)
        self._assert_rejected(result)
        self.assertFalse(symlink_output.exists())

        receipt_hardlink = self.base / "receipt-hardlink.json"
        os.link(admission_path, receipt_hardlink)
        hardlink_output = self.base / "hardlink-recheck.json"
        result = self._run_recheck(receipt_hardlink, hardlink_output)
        self._assert_rejected(result)
        self.assertFalse(hardlink_output.exists())

        oversized_receipt = self.base / "oversized-receipt.json"
        oversized_receipt.write_bytes(b"x" * (64 * 1024 + 1))
        oversized_output = self.base / "oversized-recheck.json"
        result = self._run_recheck(oversized_receipt, oversized_output)
        self._assert_rejected(result)
        self.assertFalse(oversized_output.exists())

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX FIFO support")
    def test_fifo_event_and_receipt_fail_without_waiting_for_a_writer(self) -> None:
        event_fifo = self.base / "event-fifo"
        os.mkfifo(event_fifo)
        result, output, github_output = self._run_admit(
            environment={"GITHUB_EVENT_PATH": str(event_fifo)}
        )
        self._assert_rejected(result)
        self.assertFalse(output.exists())
        self.assertEqual(github_output.read_bytes(), b"")

        receipt_fifo = self.base / "receipt-fifo"
        os.mkfifo(receipt_fifo)
        recheck_output = self.base / "fifo-recheck.json"
        result = self._run_recheck(receipt_fifo, recheck_output)
        self._assert_rejected(result)
        self.assertFalse(recheck_output.exists())

        # Exercise the actual open/append path, not only the earlier lstat
        # preflight: a regular output could be replaced with a FIFO later.
        github_fifo = self.base / "github-output-fifo"
        os.mkfifo(github_fifo)
        result = subprocess.run(
            [sys.executable, "-B", "-c",
             "import runpy,sys; from pathlib import Path; "
             "module=runpy.run_path(sys.argv[1],run_name='fifo_append_probe'); "
             "module['_append_github_output'](Path(sys.argv[2]),receipt=None)",
             str(self.repo / "scripts/toolchain/release-admission-v2.py"), str(github_fifo)],
            cwd=self.repo, capture_output=True, text=True, check=False, timeout=30,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertIn("GitHub output could not be appended", result.stderr)

    def test_linked_github_output_and_parent_directory_are_rejected_without_writes(self) -> None:
        target = self.base / "github-target.txt"
        target.write_text("preserve github target\n", encoding="utf-8")
        github_symlink = self.base / "github-symlink.txt"
        github_symlink.symlink_to(target)
        receipt = self.base / "linked-output-receipt.json"
        result, _, _ = self._run_admit(github_output=github_symlink)
        self._assert_rejected(result)
        self.assertFalse(receipt.exists())
        self.assertEqual(target.read_text(encoding="utf-8"), "preserve github target\n")

        github_hardlink = self.base / "github-hardlink.txt"
        os.link(target, github_hardlink)
        result, _, _ = self._run_admit(github_output=github_hardlink)
        self._assert_rejected(result)
        self.assertFalse(receipt.exists())
        self.assertEqual(target.read_text(encoding="utf-8"), "preserve github target\n")

        real_directory = self.base / "real-output-dir"
        real_directory.mkdir()
        linked_directory = self.base / "linked-output-dir"
        linked_directory.symlink_to(real_directory, target_is_directory=True)
        github_output = self.base / "safe-github-output.txt"
        github_output.write_bytes(b"unchanged\n")
        linked_receipt = linked_directory / "receipt.json"
        result, _, _ = self._run_admit(output=linked_receipt, github_output=github_output)
        self._assert_rejected(result)
        self.assertFalse((real_directory / "receipt.json").exists())
        self.assertEqual(github_output.read_bytes(), b"unchanged\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
