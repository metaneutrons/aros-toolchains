#!/usr/bin/env python3
"""CLI tests for V2 compiler/SDK route selection.

Git identity checks use small local repositories and real annotated/lightweight
tags. GitHub CLI calls are intercepted by a fixture executable; these tests do
not establish anything about the state of a real GitHub repository.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


TOOLCHAIN = Path(__file__).resolve().parents[1]
SCRIPT = TOOLCHAIN / "select-compiler-sdk-route-v2.py"
TAGGER_EPOCH = "1700000000"
SENTINEL = b"pre-existing workflow output\n"


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8") + b"\n"


class RouteFixture:
    """Tiny, self-contained Git producer/tools repositories and a fake gh."""

    def __init__(self, *, version: str = "1.2.3", tag_name: str = "v1.2.3",
                 annotated: bool = True, tag_target: str = "head") -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="compiler-sdk-route-")
        self.root = Path(self.temp.name)
        self.producer = self.root / "producer"
        self.tools = self.root / "tools"
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.producer.mkdir()
        self.tools.mkdir()
        self.gh_log = self.root / "gh-calls.jsonl"
        self.gh_log.write_bytes(b"")
        self.selection = self.root / "selection.json"
        self.runtime_lock = self.root / "runtime-lock.json"
        self.output = self.root / "github-output"
        self.output.write_bytes(SENTINEL)
        self.repository = "example/compiler-sdk"
        self.event = "push"
        self.ref_type = "tag"
        self.source_ref = f"refs/tags/{tag_name}"
        self.run_attempt = "1"
        self.mode = ""
        self.scope = ""
        self.group = ""

        self._git(self.producer, "init", "--quiet", "--initial-branch=main")
        self._git(self.producer, "config", "user.name", "Route Fixture")
        self._git(self.producer, "config", "user.email", "route-fixture@example.invalid")
        (self.producer / "version.txt").write_text(version + "\n", encoding="utf-8")
        self._git(self.producer, "add", "version.txt")
        self._git(self.producer, "commit", "--quiet", "-m", "record release version")
        self.version_commit = self._git(self.producer, "rev-parse", "HEAD")
        (self.producer / "fixture.txt").write_text("small local producer fixture\n", encoding="utf-8")
        self._git(self.producer, "add", "fixture.txt")
        self._git(self.producer, "commit", "--quiet", "-m", "complete producer fixture")
        self.producer_commit = self._git(self.producer, "rev-parse", "HEAD")
        (self.producer / "main-only.txt").write_text("protected main descendant\n", encoding="utf-8")
        self._git(self.producer, "add", "main-only.txt")
        self._git(self.producer, "commit", "--quiet", "-m", "advance protected main")
        self.main_commit = self._git(self.producer, "rev-parse", "HEAD")
        self._git(self.producer, "checkout", "--quiet", "--detach", self.producer_commit)

        self._git(self.tools, "init", "--quiet", "--initial-branch=main")
        self._git(self.tools, "config", "user.name", "Route Fixture")
        self._git(self.tools, "config", "user.email", "route-fixture@example.invalid")
        (self.tools / "tools.txt").write_text("published tools fixture\n", encoding="utf-8")
        self._git(self.tools, "add", "tools.txt")
        self._git(self.tools, "commit", "--quiet", "-m", "record tools commit")
        self.tools_commit = self._git(self.tools, "rev-parse", "HEAD")

        tag_env = os.environ.copy()
        tag_env["GIT_COMMITTER_DATE"] = f"{TAGGER_EPOCH} +0000"
        target = self.producer_commit if tag_target == "head" else self.version_commit
        if annotated:
            self._git(self.producer, "tag", "-a", "-m", "fixture product tag", tag_name,
                      target, env=tag_env)
        else:
            self._git(self.producer, "tag", tag_name, target, env=tag_env)
        self.tag_object = self._git(self.producer, "rev-parse", f"refs/tags/{tag_name}^{{tag}}") \
            if annotated else ""

        self.selection_value = {
            "schema": "aros-compiler-sdk-ci-selection-v2",
            "source_commit": self.producer_commit,
            "tools_commit": self.tools_commit,
        }
        self.runtime_value = {
            "schema": "aros-tools-runtime-v1",
            "source_commit": self.tools_commit,
        }
        self.write_inputs()
        self.set_remote_responses()
        self._install_gh()

    def close(self) -> None:
        self.temp.cleanup()

    @staticmethod
    def _git(repo: Path, *args: str, env: dict[str, str] | None = None) -> str:
        command_env = os.environ.copy()
        command_env["GIT_CONFIG_NOSYSTEM"] = "1"
        command_env["GIT_TERMINAL_PROMPT"] = "0"
        if env:
            command_env.update(env)
        result = subprocess.run(["git", "-C", str(repo), *args], check=True,
                                capture_output=True, text=True, env=command_env)
        return result.stdout.strip()

    def write_inputs(self) -> None:
        self.selection.write_bytes(canonical(self.selection_value))
        self.runtime_lock.write_bytes(canonical(self.runtime_value))

    def set_remote_responses(self, *, ref: dict | None = None, tag: dict | None = None,
                             main: dict | None = None, compare: dict | None = None) -> None:
        ref_value = ref or {
            "ref": self.source_ref,
            "object": {"type": "tag", "sha": self.tag_object},
        }
        tag_value = tag or {
            "sha": self.tag_object,
            "object": {"type": "commit", "sha": self.producer_commit},
        }
        main_value = main or {"protected": True, "commit": {"sha": self.main_commit}}
        compare_value = compare or {
            "base_commit": {"sha": self.producer_commit},
            "merge_base_commit": {"sha": self.producer_commit},
            "status": "ahead",
        }
        self.remote_ref_json = canonical(ref_value).decode("utf-8")
        self.remote_tag_json = canonical(tag_value).decode("utf-8")
        self.remote_main_json = canonical(main_value).decode("utf-8")
        self.remote_compare_json = canonical(compare_value).decode("utf-8")
        self.remote_ref_raw: str | None = None
        self.remote_tag_raw: str | None = None

    def _install_gh(self) -> None:
        gh = self.bin / "gh"
        gh.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, sys\n"
            "args = sys.argv[1:]\n"
            "with open(os.environ['GH_ROUTE_LOG'], 'a', encoding='utf-8') as log:\n"
            "    log.write(json.dumps(args) + '\\n')\n"
            "endpoint = args[-1] if args else ''\n"
            "if '--include' in args:\n"
            "    response = os.environ.get('GH_ROUTE_RELEASE', '404')\n"
            "    if response == 'transport':\n"
            "        print('fixture transport failure', file=sys.stderr)\n"
            "        sys.exit(7)\n"
            "    statuses = response.split(',')\n"
            "    for status in statuses:\n"
            "        print(f'HTTP/2 {status} Fixture response')\n"
            "        print()\n"
            "        print('{\"id\":42}')\n"
            "    sys.exit(0 if statuses[-1] == '200' else 1)\n"
            "if '/git/ref/tags/' in endpoint:\n"
            "    raw = os.environ.get('GH_ROUTE_REF_RAW')\n"
            "    print(raw if raw is not None else os.environ['GH_ROUTE_REF_JSON'])\n"
            "    sys.exit(0)\n"
            "if '/git/tags/' in endpoint:\n"
            "    raw = os.environ.get('GH_ROUTE_TAG_RAW')\n"
            "    print(raw if raw is not None else os.environ['GH_ROUTE_TAG_JSON'])\n"
            "    sys.exit(0)\n"
            "if endpoint.endswith('/branches/main'):\n"
            "    print(os.environ['GH_ROUTE_MAIN_JSON'])\n"
            "    sys.exit(0)\n"
            "if '/compare/' in endpoint:\n"
            "    print(os.environ['GH_ROUTE_COMPARE_JSON'])\n"
            "    sys.exit(0)\n"
            "print('unexpected fixture gh endpoint: ' + endpoint, file=sys.stderr)\n"
            "sys.exit(9)\n",
            encoding="utf-8",
        )
        gh.chmod(0o755)

    def gh_calls(self) -> list[list[str]]:
        if not self.gh_log.read_bytes():
            return []
        return [json.loads(line) for line in self.gh_log.read_text(encoding="utf-8").splitlines()]

    def run(self, *, env_overrides: dict[str, str] | None = None,
            **overrides: str) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["PATH"] = str(self.bin) + os.pathsep + env.get("PATH", "")
        env["GH_ROUTE_LOG"] = str(self.gh_log)
        env["GH_ROUTE_REF_JSON"] = self.remote_ref_json
        env["GH_ROUTE_TAG_JSON"] = self.remote_tag_json
        env["GH_ROUTE_MAIN_JSON"] = self.remote_main_json
        env["GH_ROUTE_COMPARE_JSON"] = self.remote_compare_json
        if self.remote_ref_raw is not None:
            env["GH_ROUTE_REF_RAW"] = self.remote_ref_raw
        else:
            env.pop("GH_ROUTE_REF_RAW", None)
        if self.remote_tag_raw is not None:
            env["GH_ROUTE_TAG_RAW"] = self.remote_tag_raw
        else:
            env.pop("GH_ROUTE_TAG_RAW", None)
        env.setdefault("GH_ROUTE_RELEASE", "404")
        if env_overrides:
            env.update(env_overrides)
        args = {
            "event": self.event,
            "ref_type": self.ref_type,
            "source_ref": self.source_ref,
            "repository": self.repository,
            "producer_commit": self.producer_commit,
            "run_attempt": self.run_attempt,
            "producer_dir": str(self.producer),
            "selection": str(self.selection),
            "runtime_lock": str(self.runtime_lock),
            "github_output": str(self.output),
            "mode": self.mode,
            "scope": self.scope,
            "group": self.group,
        }
        args.update(overrides)
        cli = [sys.executable, str(SCRIPT)]
        for name, value in args.items():
            if value is None:
                continue
            cli.extend((f"--{name.replace('_', '-')}", str(value)))
        return subprocess.run(cli, capture_output=True, text=True, env=env, timeout=60)

    def outputs(self) -> dict[str, str]:
        lines = self.output.read_text(encoding="utf-8").splitlines()[1:]
        return dict(line.split("=", 1) for line in lines)


class CompilerSdkRouteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = RouteFixture()

    def tearDown(self) -> None:
        self.fixture.close()

    def assert_rejected(self, result: subprocess.CompletedProcess[str], *, gh_calls: int | None = None) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.fixture.output.read_bytes(), SENTINEL)
        if gh_calls is not None:
            self.assertEqual(len(self.fixture.gh_calls()), gh_calls)

    def test_canonical_stable_and_rc_tags_select_released_full_routes(self) -> None:
        self.assertEqual(self.fixture.producer_commit,
                         self.fixture._git(self.fixture.producer, "rev-parse", "HEAD"))
        expected_keys = {
            "source_commit", "tools_commit", "release_id", "prerelease", "tag_object",
            "tag_epoch", "event", "scope", "full_qualification", "runtime_kind", "full_matrix",
        }
        self.assertEqual(self.fixture.run().returncode, 0)
        stable = self.fixture.outputs()
        self.assertEqual(set(stable), expected_keys)
        self.assertEqual(stable, {
            "source_commit": self.fixture.producer_commit,
            "tools_commit": self.fixture.tools_commit,
            "release_id": "v1.2.3",
            "prerelease": "false",
            "tag_object": self.fixture.tag_object,
            "tag_epoch": TAGGER_EPOCH,
            "event": "push",
            "scope": "full",
            "full_qualification": "false",
            "runtime_kind": "released",
            "full_matrix": "true",
        })
        self.assertEqual(len(self.fixture.gh_calls()), 5)
        self.assertTrue(self.fixture.gh_calls()[2][-1].endswith("/branches/main"))
        self.assertTrue(self.fixture.gh_calls()[3][-1].endswith(
            f"/compare/{self.fixture.producer_commit}...{self.fixture.main_commit}"))

        rc = RouteFixture(version="1.2.3", tag_name="v1.2.3-rc.2")
        try:
            result = rc.run()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(rc.outputs(), {
                "source_commit": rc.producer_commit,
                "tools_commit": rc.tools_commit,
                "release_id": "v1.2.3-rc.2",
                "prerelease": "true",
                "tag_object": rc.tag_object,
                "tag_epoch": TAGGER_EPOCH,
                "event": "push",
                "scope": "full",
                "full_qualification": "false",
                "runtime_kind": "released",
                "full_matrix": "true",
            })
            self.assertEqual(len(rc.gh_calls()), 5)
        finally:
            rc.close()

    def test_branch_small_and_full_routes_remain_development_with_stable_diagnostic_id(self) -> None:
        self.fixture.event = "workflow_dispatch"
        self.fixture.ref_type = "branch"
        self.fixture.source_ref = "refs/heads/feature/diagnostic"
        self.fixture.mode = "qualify-v2"
        self.fixture.scope = "linux-x86_64"
        self.fixture.group = "i686-aros"
        small_result = self.fixture.run()
        self.assertEqual(small_result.returncode, 0, small_result.stderr)
        small = self.fixture.outputs()
        self.assertEqual(small["runtime_kind"], "development")
        self.assertEqual(small["full_qualification"], "false")
        self.assertEqual(small["full_matrix"], "false")
        self.assertEqual(small["scope"], "linux-x86_64")
        self.assertEqual(small["release_id"], f"toolchain-dev-{self.fixture.producer_commit[:12]}")
        self.assertEqual(self.fixture.gh_calls(), [])

        self.fixture.mode = "qualify-v2-full"
        self.fixture.scope = "full"
        self.fixture.group = ""
        self.fixture.output.write_bytes(SENTINEL)
        full_result = self.fixture.run()
        self.assertEqual(full_result.returncode, 0, full_result.stderr)
        full = self.fixture.outputs()
        self.assertEqual(full["runtime_kind"], "development")
        self.assertEqual(full["full_qualification"], "true")
        self.assertEqual(full["full_matrix"], "true")
        self.assertEqual(full["scope"], "full")
        self.assertEqual(full["release_id"], small["release_id"])
        self.assertEqual(self.fixture.gh_calls(), [])

    def test_runtime_tools_mismatch_is_rejected_before_gh(self) -> None:
        self.fixture.runtime_value["source_commit"] = "f" * 40
        self.fixture.write_inputs()
        self.assert_rejected(self.fixture.run(), gh_calls=0)

    def test_push_attempt_must_be_first_and_attempt_must_be_a_positive_integer(self) -> None:
        for attempt in ("2", "0", "-1", "not-an-integer", None):
            with self.subTest(attempt=attempt):
                self.fixture.output.write_bytes(SENTINEL)
                self.fixture.gh_log.write_bytes(b"")
                self.assert_rejected(self.fixture.run(run_attempt=attempt), gh_calls=0)

    def test_wrong_event_checkout_is_rejected_before_gh(self) -> None:
        self.assert_rejected(self.fixture.run(producer_commit=self.fixture.version_commit), gh_calls=0)

    def test_dirty_producer_checkout_is_rejected_before_gh(self) -> None:
        (self.fixture.producer / "unexpected.txt").write_text("untracked\n", encoding="utf-8")
        self.assert_rejected(self.fixture.run(), gh_calls=0)

    def test_tag_version_must_match_committed_version_before_gh(self) -> None:
        invalid = RouteFixture(version="1.2.3", tag_name="v1.2.4")
        try:
            self.assert_rejected(invalid.run(), gh_calls=0)
        finally:
            invalid.close()

    def test_tag_must_peel_to_event_commit_before_gh(self) -> None:
        mispeeled = RouteFixture(version="1.2.3", tag_name="v1.2.3", tag_target="version")
        try:
            self.assert_rejected(mispeeled.run(), gh_calls=0)
        finally:
            mispeeled.close()

    def test_aliased_annotated_tag_name_is_rejected_before_gh(self) -> None:
        alias_ref = "refs/tags/v1.2.3-rc.1"
        RouteFixture._git(self.fixture.producer, "update-ref", alias_ref, self.fixture.tag_object)
        self.fixture.source_ref = alias_ref
        self.assert_rejected(self.fixture.run(), gh_calls=0)

    def test_lightweight_tag_is_counted_and_rejected_before_gh(self) -> None:
        lightweight = RouteFixture(annotated=False)
        try:
            self.assert_rejected(lightweight.run(), gh_calls=0)
        finally:
            lightweight.close()

    def test_remote_tag_ref_and_tag_object_must_match_local_identity(self) -> None:
        wrong_ref = {
            "ref": "refs/tags/v9.9.9",
            "object": {"type": "tag", "sha": self.fixture.tag_object},
        }
        self.fixture.set_remote_responses(ref=wrong_ref)
        self.assert_rejected(self.fixture.run(), gh_calls=1)

        self.fixture.gh_log.write_bytes(b"")
        wrong_object = {
            "ref": self.fixture.source_ref,
            "object": {"type": "commit", "sha": self.fixture.producer_commit},
        }
        self.fixture.set_remote_responses(ref=wrong_object)
        self.assert_rejected(self.fixture.run(), gh_calls=1)

        self.fixture.gh_log.write_bytes(b"")
        wrong_object_sha = {
            "ref": self.fixture.source_ref,
            "object": {"type": "tag", "sha": "a" * 40},
        }
        self.fixture.set_remote_responses(ref=wrong_object_sha)
        self.assert_rejected(self.fixture.run(), gh_calls=1)

    def test_remote_annotated_tag_must_directly_select_event_commit(self) -> None:
        self.fixture.set_remote_responses(tag={
            "sha": self.fixture.tag_object,
            "object": {"type": "commit", "sha": self.fixture.version_commit},
        })
        self.assert_rejected(self.fixture.run(), gh_calls=2)

    def test_tag_commit_must_be_in_protected_main_history(self) -> None:
        bad_cases = (
            ("unprotected", {"protected": False, "commit": {"sha": self.fixture.main_commit}}, None, 3),
            ("invalid-main-sha", {"protected": True, "commit": {"sha": "not-a-sha"}}, None, 3),
            ("unrelated-base", None, {
                "base_commit": {"sha": self.fixture.producer_commit},
                "merge_base_commit": {"sha": self.fixture.version_commit},
                "status": "ahead",
            }, 4),
            ("wrong-base", None, {
                "base_commit": {"sha": self.fixture.version_commit},
                "merge_base_commit": {"sha": self.fixture.producer_commit},
                "status": "ahead",
            }, 4),
            ("diverged-tag-commit", None, {
                "base_commit": {"sha": self.fixture.producer_commit},
                "merge_base_commit": {"sha": self.fixture.producer_commit},
                "status": "diverged",
            }, 4),
        )
        for label, main, compare, expected_calls in bad_cases:
            with self.subTest(case=label):
                self.fixture.gh_log.write_bytes(b"")
                self.fixture.output.write_bytes(SENTINEL)
                self.fixture.set_remote_responses(main=main, compare=compare)
                self.assert_rejected(self.fixture.run(), gh_calls=expected_calls)

    def test_release_must_be_proven_absent_by_one_exact_404(self) -> None:
        for response, expected_calls in (("200", 5), ("401", 5), ("403", 5),
                                         ("429", 5), ("transport", 5), ("404,200", 5)):
            with self.subTest(response=response):
                self.fixture.gh_log.write_bytes(b"")
                self.fixture.output.write_bytes(SENTINEL)
                result = self.fixture.run(env_overrides={"GH_ROUTE_RELEASE": response})
                self.assert_rejected(result, gh_calls=expected_calls)
        self.fixture.gh_log.write_bytes(b"")
        self.fixture.output.write_bytes(SENTINEL)
        result = self.fixture.run(env_overrides={"GH_ROUTE_RELEASE": "404"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.fixture.outputs()["release_id"], "v1.2.3")
        self.assertEqual(len(self.fixture.gh_calls()), 5)

    def test_noncanonical_semver_and_invalid_tag_ref_are_rejected_before_gh(self) -> None:
        bad_semver = RouteFixture(version="1.2.3", tag_name="v01.2.3")
        try:
            self.assert_rejected(bad_semver.run(), gh_calls=0)
        finally:
            bad_semver.close()
        self.assert_rejected(self.fixture.run(ref_type="branch", source_ref="refs/heads/main"),
                             gh_calls=0)

    def test_tag_route_rejects_diagnostic_mode_scope_or_group_before_gh(self) -> None:
        for overrides in ({"mode": "qualify-v2"}, {"scope": "linux-x86_64"},
                          {"group": "i686-aros"}):
            with self.subTest(overrides=overrides):
                self.fixture.output.write_bytes(SENTINEL)
                self.fixture.gh_log.write_bytes(b"")
                self.assert_rejected(self.fixture.run(**overrides), gh_calls=0)

    def test_duplicate_selection_json_is_rejected_before_gh(self) -> None:
        self.fixture.selection.write_bytes(
            ("{\"schema\":\"aros-compiler-sdk-ci-selection-v2\","
             f"\"source_commit\":\"{self.fixture.producer_commit}\","
             f"\"source_commit\":\"{self.fixture.producer_commit}\","
             f"\"tools_commit\":\"{self.fixture.tools_commit}\"}}\n").encode("utf-8")
        )
        self.assert_rejected(self.fixture.run(), gh_calls=0)

    def test_duplicate_github_identity_json_is_rejected_without_output_mutation(self) -> None:
        self.fixture.remote_ref_raw = (
            f'{{"ref":"{self.fixture.source_ref}","ref":"{self.fixture.source_ref}",'
            f'"object":{{"type":"tag","sha":"{self.fixture.tag_object}"}}}}'
        )
        self.assert_rejected(self.fixture.run(), gh_calls=1)


if __name__ == "__main__":
    unittest.main()
