#!/usr/bin/env python3
"""Offline tests for provider-metadata owner artifact selection only."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "select-owner-artifacts-v2.py"
SPEC = importlib.util.spec_from_file_location("select_owner_artifacts_v2", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
selector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(selector)
origin = selector.artifact_origin


REPOSITORY = "example/project"
REPOSITORY_ID = 7890
COMMIT = "a" * 40
RUN_ID = 123456
RUN_ATTEMPT = 2
JOB_ID = 90901
CHECK_ID = 555001
JOB_NAME = "Build toolchain"
PAYLOAD_ID = 667002
PROOF_ID = 667003
PAYLOAD_NAME = "toolchain-build"
PROOF_NAME = "toolchain-origin-proof"
PAYLOAD_DIGEST = "b" * 64
PROOF_DIGEST = "c" * 64
SOURCE_CONTEXT = {
    "repository": REPOSITORY,
    "repository_id": REPOSITORY_ID,
    "producer_commit": COMMIT,
    "source_ref": "refs/heads/main",
    "workflow": ".github/workflows/toolchain.yml",
    "run_id": RUN_ID,
    "run_attempt": RUN_ATTEMPT,
}
LANE = {"role": "build", "group": "rv32", "host": "linux",
        "profile": "release", "copy": "a"}


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode() + b"\n"


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def job() -> dict:
    return {
        "id": JOB_ID,
        "check_run_url": f"https://api.github.com/repos/{REPOSITORY}/check-runs/{CHECK_ID}",
        "name": JOB_NAME,
        "head_sha": COMMIT,
        "run_id": RUN_ID,
        "run_attempt": RUN_ATTEMPT,
        "status": "completed",
        "conclusion": "success",
    }


def jobs_page() -> list[dict]:
    return [{"total_count": 1, "jobs": [job()]}]


def provider_artifact(identity: int, name: str, digest: str, *,
                      context: dict | None = None, expired: bool = False,
                      size: int = 2048) -> dict:
    ctx = SOURCE_CONTEXT if context is None else context
    return {
        "id": identity,
        "name": name,
        "digest": f"sha256:{digest}",
        "expired": expired,
        "size_in_bytes": size,
        "workflow_run": {
            "id": ctx["run_id"],
            "head_sha": ctx["producer_commit"],
            "repository_id": ctx["repository_id"],
            "head_repository_id": ctx["repository_id"],
        },
    }


def artifacts_page(*, payload: dict | None = None, proof: dict | None = None,
                   extras: list[dict] | None = None, total: int | None = None) -> list[dict]:
    selected = [payload or provider_artifact(PAYLOAD_ID, PAYLOAD_NAME, PAYLOAD_DIGEST),
                proof or provider_artifact(PROOF_ID, PROOF_NAME, PROOF_DIGEST)]
    selected.extend(extras or [])
    return [{"total_count": len(selected) if total is None else total,
             "artifacts": selected}]


class SelectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="select-owner-artifacts-v2-")
        self.root = Path(self.temporary.name).resolve()
        self.context_path = self.root / "source-context.json"
        self.context_bytes = canonical(SOURCE_CONTEXT)
        self.context_path.write_bytes(self.context_bytes)
        self.api_calls: list[tuple[list[str], str]] = []
        self.jobs = jobs_page()
        self.artifacts = artifacts_page()

        def fake_gh(arguments: list[str], purpose: str = "GitHub observation") -> object:
            command = list(arguments)
            self.api_calls.append((command, purpose))
            if command[-1].endswith("/jobs?per_page=100"):
                return self.jobs
            if command[-1].endswith("/artifacts?per_page=100"):
                return self.artifacts
            raise AssertionError("unexpected provider request")

        self.fake_gh = fake_gh
        self.patch = mock.patch.object(origin, "gh_json", side_effect=fake_gh)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.addCleanup(self.temporary.cleanup)

    def args(self, **overrides: object) -> object:
        values = {
            "source_context": self.context_path,
            "source_context_sha256": sha256(self.context_bytes),
            "job_name": JOB_NAME,
            "payload_name": PAYLOAD_NAME,
            "proof_name": PROOF_NAME,
            **LANE,
        }
        values.update(overrides)
        return selector.parser().parse_args(sum(([f"--{key.replace('_', '-')}", str(value)]
                                                for key, value in values.items()), []))

    def test_direct_good_selection_is_exact_metadata_shape(self) -> None:
        result = selector.select_owner_artifacts(self.args())
        self.assertEqual(set(result), {"schema", "context", "selection", "job", "artifact", "proof"})
        self.assertEqual(result, {
            "schema": origin.SELECTION_SCHEMA,
            "context": SOURCE_CONTEXT,
            "selection": LANE,
            "job": {"id": JOB_ID, "name": JOB_NAME},
            "artifact": {"id": PAYLOAD_ID, "name": PAYLOAD_NAME,
                         "sha256": PAYLOAD_DIGEST, "size_in_bytes": 2048},
            "proof": {"id": PROOF_ID, "name": PROOF_NAME,
                      "sha256": PROOF_DIGEST, "size_in_bytes": 2048},
        })
        self.assertEqual(origin.source_selection(result, SOURCE_CONTEXT, same_attempt=True), result)
        self.assertEqual([call[0][-1] for call in self.api_calls], [
            f"repos/{REPOSITORY}/actions/runs/{RUN_ID}/attempts/{RUN_ATTEMPT}/jobs?per_page=100",
            f"repos/{REPOSITORY}/actions/runs/{RUN_ID}/artifacts?per_page=100",
        ])

    def test_expected_artifact_name_mismatch_is_rejected(self) -> None:
        with self.assertRaises(origin.OriginError):
            selector.select_owner_artifacts(self.args(payload_name="different-payload"))

    def test_duplicate_requested_artifact_name_is_rejected(self) -> None:
        duplicate = provider_artifact(667004, PAYLOAD_NAME, "d" * 64)
        self.artifacts = artifacts_page(extras=[duplicate])
        with self.assertRaises(origin.OriginError):
            selector.select_owner_artifacts(self.args())

    def test_incomplete_artifact_pages_are_rejected(self) -> None:
        self.artifacts = artifacts_page(total=3)
        with self.assertRaises(origin.OriginError):
            selector.select_owner_artifacts(self.args())

    def test_failed_job_is_rejected(self) -> None:
        failed = job()
        failed["conclusion"] = "failure"
        self.jobs = [{"total_count": 1, "jobs": [failed]}]
        with self.assertRaises(origin.OriginError):
            selector.select_owner_artifacts(self.args())

    def test_wrong_run_artifact_is_rejected(self) -> None:
        wrong = dict(SOURCE_CONTEXT, run_id=RUN_ID + 1)
        self.artifacts = artifacts_page(payload=provider_artifact(
            PAYLOAD_ID, PAYLOAD_NAME, PAYLOAD_DIGEST, context=wrong))
        with self.assertRaises(origin.OriginError):
            selector.select_owner_artifacts(self.args())

    def test_expired_artifact_is_rejected(self) -> None:
        self.artifacts = artifacts_page(payload=provider_artifact(
            PAYLOAD_ID, PAYLOAD_NAME, PAYLOAD_DIGEST, expired=True))
        with self.assertRaises(origin.OriginError):
            selector.select_owner_artifacts(self.args())

    def test_proof_size_limit_is_enforced(self) -> None:
        self.artifacts = artifacts_page(proof=provider_artifact(
            PROOF_ID, PROOF_NAME, PROOF_DIGEST, size=2 * origin.MAX_METADATA + 1))
        with self.assertRaises(origin.OriginError):
            selector.select_owner_artifacts(self.args())

    def test_context_change_during_provider_read_is_rejected(self) -> None:
        def mutate_after_jobs(arguments: list[str], purpose: str = "GitHub observation") -> object:
            self.api_calls.append((list(arguments), purpose))
            if arguments[-1].endswith("/jobs?per_page=100"):
                self.context_path.write_bytes(canonical(dict(SOURCE_CONTEXT, run_attempt=RUN_ATTEMPT + 1)))
                return self.jobs
            return self.artifacts

        with mock.patch.object(origin, "gh_json", side_effect=mutate_after_jobs):
            with self.assertRaises(origin.OriginError):
                selector.select_owner_artifacts(self.args())

    def test_bad_selectors_and_context_digest_make_no_api_calls(self) -> None:
        for overrides in (
            {"source_context_sha256": "0" * 64},
            {"payload_name": "../payload"},
            {"payload_name": PAYLOAD_NAME, "proof_name": PAYLOAD_NAME},
            {"role": "unknown"},
            {"copy": "none"},
            {"job_name": ""},
            {"job_name": "line one\nline two"},
        ):
            with self.subTest(overrides=overrides):
                self.api_calls.clear()
                with self.assertRaises(origin.OriginError):
                    selector.select_owner_artifacts(self.args(**overrides))
                self.assertEqual(self.api_calls, [])

    def test_cli_fake_gh_outputs_only_canonical_selection_and_fetches_metadata(self) -> None:
        fake_bin = self.root / "bin"
        fake_bin.mkdir()
        fake_gh = fake_bin / "gh"
        fake_gh.write_text(FAKE_GH, encoding="utf-8")
        fake_gh.chmod(0o755)
        request_log = self.root / "gh-requests.jsonl"
        env = os.environ.copy()
        env.update({
            "PATH": f"{fake_bin}{os.pathsep}{env.get('PATH', '')}",
            "FAKE_GH_REQUEST_LOG": str(request_log),
        })
        command = [sys.executable, str(SCRIPT),
                   "--source-context", str(self.context_path),
                   "--source-context-sha256", sha256(self.context_bytes),
                   "--job-name", JOB_NAME,
                   "--payload-name", PAYLOAD_NAME,
                   "--proof-name", PROOF_NAME,
                   "--role", LANE["role"], "--group", LANE["group"],
                   "--host", LANE["host"], "--profile", LANE["profile"],
                   "--copy", LANE["copy"]]
        result = subprocess.run(command, capture_output=True, text=True,
                                check=False, env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        expected = {
            "schema": origin.SELECTION_SCHEMA,
            "context": SOURCE_CONTEXT,
            "selection": LANE,
            "job": {"id": JOB_ID, "name": JOB_NAME},
            "artifact": {"id": PAYLOAD_ID, "name": PAYLOAD_NAME,
                         "sha256": PAYLOAD_DIGEST, "size_in_bytes": 2048},
            "proof": {"id": PROOF_ID, "name": PROOF_NAME,
                      "sha256": PROOF_DIGEST, "size_in_bytes": 2048},
        }
        self.assertEqual(result.stdout.encode(), canonical(expected))
        self.assertEqual(result.stderr, "")
        requests = request_log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(requests, [
            f"api --paginate --slurp repos/{REPOSITORY}/actions/runs/{RUN_ID}/attempts/{RUN_ATTEMPT}/jobs?per_page=100",
            f"api --paginate --slurp repos/{REPOSITORY}/actions/runs/{RUN_ID}/artifacts?per_page=100",
        ])

    def test_cli_bad_or_duplicate_selector_does_not_invoke_fake_gh(self) -> None:
        fake_bin = self.root / "bin-empty"
        fake_bin.mkdir()
        fake_gh = fake_bin / "gh"
        fake_gh.write_text(FAKE_GH, encoding="utf-8")
        fake_gh.chmod(0o755)
        request_log = self.root / "empty-gh-requests.jsonl"
        env = os.environ.copy()
        env.update({"PATH": f"{fake_bin}{os.pathsep}{env.get('PATH', '')}",
                    "FAKE_GH_REQUEST_LOG": str(request_log)})
        command = [sys.executable, str(SCRIPT),
                   "--source-context", str(self.context_path),
                   "--source-context-sha256", sha256(self.context_bytes),
                   "--job-name", JOB_NAME,
                   "--payload-name", PAYLOAD_NAME,
                   "--proof-name", PROOF_NAME,
                   "--role", LANE["role"], "--group", LANE["group"],
                   "--host", LANE["host"], "--profile", LANE["profile"],
                   "--copy", LANE["copy"]]
        probes = [("bad-digest", command[:]),
                  ("duplicate-flag", command + ["--role", LANE["role"]])]
        for label, probe in probes:
            with self.subTest(probe=label):
                if label == "bad-digest":
                    probe[probe.index("--source-context-sha256") + 1] = "0" * 64
                self.assertFalse(request_log.exists())
                result = subprocess.run(probe, capture_output=True, text=True,
                                        check=False, env=env)
                self.assertNotEqual(result.returncode, 0)
        self.assertFalse(request_log.exists())


FAKE_GH = f'''#!/bin/sh
printf '%s\\n' "$*" >> "$FAKE_GH_REQUEST_LOG"
case "$*" in
  *'/jobs?per_page=100') printf '%s\\n' '{json.dumps(jobs_page(), separators=(",", ":"))}' ;;
  *'/artifacts?per_page=100') printf '%s\\n' '{json.dumps(artifacts_page(), separators=(",", ":"))}' ;;
  *) printf '%s\\n' 'synthetic provider body must not be emitted' >&2; exit 17 ;;
esac
'''


if __name__ == "__main__":
    unittest.main()
