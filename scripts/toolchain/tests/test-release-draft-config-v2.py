#!/usr/bin/env python3
"""Offline contract tests for the inactive Release Please draft adapter."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest


SOURCE_ROOT = Path(__file__).resolve().parents[3]
SCRIPT_SOURCE = SOURCE_ROOT / "scripts/toolchain/prepare-release-draft-config-v2.py"
PRIVATE_MARKER = "fixture-config-must-not-be-printed"
MAX_CONFIG_BYTES = 256 * 1024
DRAFT_CONFIG_PATH = "toolchains/release-please-draft-config-v2.json"


def _run_git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=root, capture_output=True, text=True, check=False
    )
    if result.returncode:
        raise AssertionError(f"fixture Git command failed: {args!r}: {result.stderr}")
    return result.stdout.strip()


class ReleaseDraftConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="release-draft-config-v2.")
        self.base = Path(self.temporary.name).resolve()
        self.repo = self.base / "fixture-repo"
        (self.repo / "scripts/toolchain").mkdir(parents=True)
        (self.repo / "toolchains").mkdir()
        shutil.copyfile(SCRIPT_SOURCE, self.repo / "scripts/toolchain/prepare-release-draft-config-v2.py")

        self.config = {
            "$schema": "https://example.invalid/release-please-config.json",
            "release-type": "simple",
            "include-component-in-tag": False,
            "include-v-in-tag": True,
            "initial-version": "0.1.0",
            "skip-github-release": True,
            "bump-minor-pre-major": True,
            "bump-patch-for-minor-pre-major": False,
            "review-marker": PRIVATE_MARKER,
            "packages": {
                ".": {
                    "package-name": "fixture-package-name",
                    "changelog-path": "fixture/CHANGELOG.md",
                    "extra-reviewed-setting": {"keep": [1, "two", False]},
                }
            },
        }

        _run_git(self.repo, "init", "-q")
        _run_git(self.repo, "config", "user.name", "Draft Config Fixture")
        _run_git(self.repo, "config", "user.email", "draft-config@example.invalid")
        self._write_committed_config(json.dumps(self.config, sort_keys=True) + "\n", initial=True)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_committed_config(
        self,
        raw: str | bytes,
        *,
        initial: bool = False,
        draft_raw: str | bytes | None = None,
        update_draft: bool = True,
    ) -> None:
        content = raw.encode("utf-8") if isinstance(raw, str) else raw
        (self.repo / "release-please-config.json").write_bytes(content)
        draft_content: bytes | None = None
        if draft_raw is not None:
            draft_content = draft_raw.encode("utf-8") if isinstance(draft_raw, str) else draft_raw
        elif update_draft:
            try:
                source = json.loads(content)
                if isinstance(source, dict):
                    source["skip-github-release"] = False
                    source["draft"] = True
                    source["force-tag-creation"] = False
                    draft_content = (json.dumps(source, sort_keys=True) + "\n").encode("utf-8")
            except (UnicodeDecodeError, json.JSONDecodeError):
                pass
        if draft_content is not None:
            (self.repo / DRAFT_CONFIG_PATH).write_bytes(draft_content)
        _run_git(self.repo, "add", "release-please-config.json")
        if draft_content is not None:
            _run_git(self.repo, "add", DRAFT_CONFIG_PATH)
        if initial:
            _run_git(self.repo, "commit", "-q", "-m", "fixture config")
        else:
            _run_git(self.repo, "commit", "-q", "--amend", "--no-edit")

    def _remove_committed_draft_config(self) -> None:
        _run_git(self.repo, "rm", "-q", DRAFT_CONFIG_PATH)
        _run_git(self.repo, "commit", "-q", "--amend", "--no-edit")

    def _run(self, output: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(self.repo / "scripts/toolchain/prepare-release-draft-config-v2.py"),
                "--output",
                str(output),
            ],
            cwd=self.repo,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )

    def _assert_failure_without_output(self, output: Path) -> subprocess.CompletedProcess[str]:
        result = self._run(output)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertNotIn(PRIVATE_MARKER, result.stdout)
        self.assertNotIn(PRIVATE_MARKER, result.stderr)
        return result

    def test_valid_committed_config_preserves_strategy_and_package(self) -> None:
        output = self.base / "draft-config.json"
        result = self._run(output)

        self.assertEqual(result.returncode, 0, result.stderr)
        expected = copy.deepcopy(self.config)
        expected["skip-github-release"] = False
        expected["draft"] = True
        expected["force-tag-creation"] = False
        self.assertEqual(json.loads(output.read_text(encoding="utf-8")), expected)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        self.assertNotIn(PRIVATE_MARKER, result.stdout)
        self.assertNotIn(PRIVATE_MARKER, result.stderr)
        self.assertLess(len(result.stdout), 100)

    def test_dirty_worktree_config_is_not_used(self) -> None:
        committed = copy.deepcopy(self.config)
        worktree = copy.deepcopy(self.config)
        worktree["packages"]["unexpected"] = {}
        worktree["review-marker"] = "dirty-worktree-marker"
        dirty_draft = copy.deepcopy(committed)
        dirty_draft["review-marker"] = "dirty-draft-marker"
        dirty_draft["skip-github-release"] = False
        dirty_draft["draft"] = True
        dirty_draft["force-tag-creation"] = False
        (self.repo / "release-please-config.json").write_text(
            json.dumps(worktree), encoding="utf-8"
        )
        (self.repo / DRAFT_CONFIG_PATH).write_text(
            json.dumps(dirty_draft), encoding="utf-8"
        )

        output = self.base / "from-head.json"
        result = self._run(output)

        self.assertEqual(result.returncode, 0, result.stderr)
        committed["skip-github-release"] = False
        committed["draft"] = True
        committed["force-tag-creation"] = False
        self.assertEqual(json.loads(output.read_text(encoding="utf-8")), committed)
        self.assertEqual(
            json.loads((self.repo / "release-please-config.json").read_text(encoding="utf-8")),
            worktree,
        )
        self.assertEqual(
            json.loads((self.repo / DRAFT_CONFIG_PATH).read_text(encoding="utf-8")),
            dirty_draft,
        )
        self.assertNotIn("dirty-worktree-marker", result.stdout + result.stderr)
        self.assertNotIn("dirty-draft-marker", result.stdout + result.stderr)

    def test_allowed_existing_draft_and_force_values_are_idempotent(self) -> None:
        config = copy.deepcopy(self.config)
        config["draft"] = True
        config["force-tag-creation"] = False
        self._write_committed_config(json.dumps(config))

        output = self.base / "idempotent.json"
        result = self._run(output)

        self.assertEqual(result.returncode, 0, result.stderr)
        config["skip-github-release"] = False
        self.assertEqual(json.loads(output.read_text(encoding="utf-8")), config)

    def test_invalid_committed_configurations_fail_closed(self) -> None:
        missing_skip = copy.deepcopy(self.config)
        del missing_skip["skip-github-release"]
        disabled_skip = copy.deepcopy(self.config)
        disabled_skip["skip-github-release"] = False
        non_boolean_skip = copy.deepcopy(self.config)
        non_boolean_skip["skip-github-release"] = 1
        extra_package = copy.deepcopy(self.config)
        extra_package["packages"]["another-package"] = {}
        package_not_object = copy.deepcopy(self.config)
        package_not_object["packages"]["."] = []
        nested_package_override = copy.deepcopy(self.config)
        nested_package_override["packages"]["."]["extra-reviewed-setting"]["future"] = {
            "draft": True
        }
        draft_conflict = copy.deepcopy(self.config)
        draft_conflict["draft"] = False
        force_conflict = copy.deepcopy(self.config)
        force_conflict["force-tag-creation"] = True

        cases: list[tuple[str, str | bytes]] = [
            (
                "duplicate key",
                '{"skip-github-release":true,"skip-github-release":true,"packages":{".":{}}}',
            ),
            ("malformed JSON", "{not-json"),
            ("non-object root", "[]"),
            ("missing skip flag", json.dumps(missing_skip)),
            ("disabled skip flag", json.dumps(disabled_skip)),
            ("non-boolean skip flag", json.dumps(non_boolean_skip)),
            ("extra package", json.dumps(extra_package)),
            ("package is not an object", json.dumps(package_not_object)),
            ("nested package override", json.dumps(nested_package_override)),
            ("conflicting root draft", json.dumps(draft_conflict)),
            ("conflicting root force-tag", json.dumps(force_conflict)),
            ("non-finite number", json.dumps(self.config)[:-1] + ',"invalid":NaN}'),
            ("overflowing exponent", json.dumps(self.config)[:-1] + ',"invalid":1e9999}'),
            ("oversized configuration", b" " * (MAX_CONFIG_BYTES + 1)),
        ]
        for key in ("skip-github-release", "draft", "force-tag-creation"):
            for value in (True, False):
                package_override = copy.deepcopy(self.config)
                package_override["packages"]["."][key] = value
                cases.append((f"package override {key}={value}", json.dumps(package_override)))

        for name, raw in cases:
            with self.subTest(name=name):
                self._write_committed_config(raw)
                output = self.base / f"invalid-{name.replace(' ', '-')}.json"
                self._assert_failure_without_output(output)
                self.assertFalse(os.path.lexists(output), f"unexpected output at {output}")

    def test_original_json_depth_is_checked_before_derivation(self) -> None:
        for depth, accepted in ((10, True), (80, False)):
            with self.subTest(depth=depth):
                nested = "leaf"
                for _ in range(depth):
                    nested = {"child": nested}
                config = copy.deepcopy(self.config)
                config["packages"]["."]["reviewed-depth"] = nested
                self._write_committed_config(json.dumps(config))
                output = self.base / f"source-depth-{depth}.json"
                result = self._run(output)
                if accepted:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(
                        json.loads(output.read_text())["packages"]["."]["reviewed-depth"],
                        nested,
                    )
                else:
                    self.assertEqual(result.returncode, 1)
                    self.assertIn(
                        "committed Release Please configuration is invalid JSON",
                        result.stderr,
                    )
                    self.assertNotIn("Traceback", result.stderr)
                    self.assertNotIn(PRIVATE_MARKER, result.stdout + result.stderr)
                    self.assertFalse(os.path.lexists(output))

    def test_missing_committed_draft_config_fails_before_output(self) -> None:
        self._remove_committed_draft_config()
        output = self.base / "missing-draft-config.json"

        self._assert_failure_without_output(output)
        self.assertFalse(os.path.lexists(output))

    def test_committed_draft_config_must_be_strict_and_exact(self) -> None:
        expected = copy.deepcopy(self.config)
        expected["skip-github-release"] = False
        expected["draft"] = True
        expected["force-tag-creation"] = False

        extra = copy.deepcopy(expected)
        extra["extra-setting"] = "not-in-source"
        stale = copy.deepcopy(expected)
        stale["initial-version"] = "9.9.9"
        strategy_drift = copy.deepcopy(expected)
        strategy_drift["release-type"] = "node"
        package_drift = copy.deepcopy(expected)
        package_drift["packages"]["."]["package-name"] = "other-package"
        integer_float_drift = copy.deepcopy(expected)
        integer_float_drift["packages"]["."]["extra-reviewed-setting"] = {
            "keep": [1.0, "two", False]
        }

        cases: list[tuple[str, str | bytes]] = [
            ("duplicate key", '{"draft":true,"draft":true}'),
            ("non-finite constant", '{"invalid":NaN}'),
            ("overflowing exponent", '{"invalid":1e9999}'),
            ("non-object root", "[]"),
            ("invalid UTF-8", b"\xff"),
            ("too deeply nested", "{" + '"x":' * 66 + "0" + "}" * 66),
            ("oversized draft", b" " * (MAX_CONFIG_BYTES + 1)),
            ("extra field", json.dumps(extra)),
            ("stale source value", json.dumps(stale)),
            ("strategy drift", json.dumps(strategy_drift)),
            ("package drift", json.dumps(package_drift)),
            ("integer-float alias", json.dumps(integer_float_drift)),
        ]
        for key, alias in (
            ("skip-github-release", 0),
            ("draft", 1),
            ("force-tag-creation", 0),
        ):
            numeric_alias = copy.deepcopy(expected)
            numeric_alias[key] = alias
            cases.append((f"numeric boolean alias {key}", json.dumps(numeric_alias)))
        for key, value in (
            ("skip-github-release", True),
            ("draft", False),
            ("force-tag-creation", True),
        ):
            toggle_drift = copy.deepcopy(expected)
            toggle_drift[key] = value
            cases.append((f"toggle drift {key}", json.dumps(toggle_drift)))

        for name, raw_draft in cases:
            with self.subTest(name=name):
                self._write_committed_config(
                    json.dumps(self.config, sort_keys=True), draft_raw=raw_draft
                )
                output = self.base / f"invalid-draft-{name.replace(' ', '-')}.json"
                self._assert_failure_without_output(output)
                self.assertFalse(os.path.lexists(output), f"unexpected output at {output}")

    def test_source_change_with_old_derived_blob_fails_before_output(self) -> None:
        changed_source = copy.deepcopy(self.config)
        changed_source["initial-version"] = "0.2.0"
        self._write_committed_config(
            json.dumps(changed_source, sort_keys=True), update_draft=False
        )
        output = self.base / "stale-after-source-change.json"

        self._assert_failure_without_output(output)
        self.assertFalse(os.path.lexists(output))

    def test_existing_output_is_never_overwritten(self) -> None:
        output = self.base / "existing.json"
        output.write_bytes(b"sentinel-existing\n")

        self._assert_failure_without_output(output)
        self.assertEqual(output.read_bytes(), b"sentinel-existing\n")

    def test_output_destination_is_preflighted_before_config_read(self) -> None:
        self._write_committed_config("{malformed")
        output = self.base / "existing-before-config.json"
        output.write_bytes(b"sentinel-preflight\n")

        result = self._assert_failure_without_output(output)

        self.assertIn("output already exists", result.stderr)
        self.assertEqual(output.read_bytes(), b"sentinel-preflight\n")

    def test_symlink_output_is_not_followed_or_modified(self) -> None:
        sentinel = self.base / "sentinel.json"
        sentinel.write_bytes(b"sentinel-symlink\n")
        output = self.base / "linked-output.json"
        output.symlink_to(sentinel)

        self._assert_failure_without_output(output)
        self.assertTrue(output.is_symlink())
        self.assertEqual(sentinel.read_bytes(), b"sentinel-symlink\n")

    def test_fifo_output_is_rejected_without_blocking_or_replacement(self) -> None:
        output = self.base / "output.fifo"
        os.mkfifo(output)

        self._assert_failure_without_output(output)
        self.assertTrue(stat.S_ISFIFO(output.lstat().st_mode))

    def test_hardlinked_output_is_not_modified(self) -> None:
        sentinel = self.base / "hardlink-sentinel.json"
        output = self.base / "hardlinked-output.json"
        sentinel.write_bytes(b"sentinel-hardlink\n")
        os.link(sentinel, output)

        self._assert_failure_without_output(output)
        self.assertEqual(output.stat().st_nlink, 2)
        self.assertEqual(output.read_bytes(), b"sentinel-hardlink\n")
        self.assertEqual(sentinel.read_bytes(), b"sentinel-hardlink\n")

    def test_symlinked_parent_is_rejected_without_writing_through_it(self) -> None:
        real_parent = self.base / "real-parent"
        real_parent.mkdir()
        sentinel = real_parent / "sentinel.txt"
        sentinel.write_bytes(b"sentinel-parent\n")
        linked_parent = self.base / "linked-parent"
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        output = linked_parent / "generated.json"

        self._assert_failure_without_output(output)
        self.assertTrue(linked_parent.is_symlink())
        self.assertEqual(sentinel.read_bytes(), b"sentinel-parent\n")
        self.assertFalse((real_parent / "generated.json").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
