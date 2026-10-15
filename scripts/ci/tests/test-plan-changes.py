#!/usr/bin/env python3
"""Tests for the conservative CI change planner."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PLANNER = Path(__file__).resolve().parents[1] / "plan-changes.py"


class GitFixture:
    def __init__(self, root: Path):
        self.root = root
        self._git("init", "--quiet")
        self._git("config", "user.name", "Planner Test")
        self._git("config", "user.email", "planner@example.invalid")
        self.write("README.md", "initial documentation\n")
        self.base = self.commit("base")

    def _git(self, *args: str) -> str:
        result = subprocess.run(
            ["git", *args],
            cwd=self.root,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return result.stdout.strip()

    def write(self, relative_path: str, content: str) -> None:
        path = self.root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def commit(self, message: str) -> str:
        self._git("add", "--all")
        self._git("commit", "--quiet", "-m", message)
        return self._git("rev-parse", "HEAD")


class PlanChangesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.fixture = GitFixture(self.repo)

    def invoke(
        self,
        *,
        event: str = "pull_request",
        base: str | None = None,
        head: str | None = None,
        repository_dir: Path | None = None,
        github_output: Path | None = None,
    ) -> dict[str, str]:
        command = [
            sys.executable,
            str(PLANNER),
            "--event",
            event,
            "--repository-dir",
            str(repository_dir or self.repo),
        ]
        if base is not None:
            command.append(f"--base={base}")
        if head is not None:
            command.append(f"--head={head}")
        if github_output is not None:
            command.extend(["--github-output", str(github_output)])
        result = subprocess.run(command, check=True, text=True, capture_output=True)
        return json.loads(result.stdout)

    def test_readme_only_modification_selects_markdown_scope(self) -> None:
        self.fixture.write("README.md", "updated documentation\n")
        head = self.fixture.commit("update README")

        result = self.invoke(base=self.fixture.base, head=head)

        self.assertEqual(result, {"scope": "markdown", "reason": "markdown_only"})

    def test_valid_full_base_and_head_shas_are_accepted(self) -> None:
        self.fixture.write("README.md", "updated documentation\n")
        head = self.fixture.commit("update README")
        self.assertRegex(self.fixture.base, r"^[0-9a-f]{40}$")
        self.assertRegex(head, r"^[0-9a-f]{40}$")

        result = self.invoke(base=self.fixture.base, head=head)

        self.assertEqual(result["scope"], "markdown")

    def test_script_workflow_and_input_changes_select_full_scope(self) -> None:
        paths = (
            "scripts/ci/check-toolchain.py",
            ".github/workflows/build.yml",
            "toolchain.toml",
        )
        for path in paths:
            with self.subTest(path=path):
                self.fixture.write(path, "changed\n")
                head = self.fixture.commit(f"change {path}")
                result = self.invoke(base=self.fixture.base, head=head)
                self.assertEqual(result["scope"], "full")

    def test_mixed_readme_and_other_changes_select_full_scope(self) -> None:
        self.fixture.write("README.md", "updated documentation\n")
        self.fixture.write("config.toml", "changed\n")
        head = self.fixture.commit("mixed change")

        self.assertEqual(self.invoke(base=self.fixture.base, head=head)["scope"], "full")

    def test_unknown_path_selects_full_scope(self) -> None:
        self.fixture.write("unclassified.data", "changed\n")
        head = self.fixture.commit("add unknown input")

        self.assertEqual(self.invoke(base=self.fixture.base, head=head)["scope"], "full")

    def test_nested_markdown_addition_and_modification_select_markdown_scope(self) -> None:
        self.fixture.write("docs/nested/guide.md", "new guide\n")
        head = self.fixture.commit("add nested Markdown")

        self.assertEqual(self.invoke(base=self.fixture.base, head=head)["scope"], "markdown")

        self.fixture.write("docs/nested/guide.md", "updated guide\n")
        head = self.fixture.commit("update nested Markdown")
        self.assertEqual(self.invoke(base=self.fixture.base, head=head)["scope"], "markdown")

    def test_markdown_deletion_selects_markdown_scope(self) -> None:
        self.fixture.write("docs/guide.md", "guide\n")
        base = self.fixture.commit("add guide")
        (self.repo / "docs/guide.md").unlink()
        head = self.fixture.commit("delete guide")

        self.assertEqual(self.invoke(base=base, head=head)["scope"], "markdown")

    def test_empty_diff_selects_full_scope(self) -> None:
        head = self.fixture._git("rev-parse", "HEAD")

        result = self.invoke(base=self.fixture.base, head=head)

        self.assertEqual(result["scope"], "full")
        self.assertEqual(result["reason"], "identical_refs")

    def test_nonempty_refs_with_empty_tree_diff_select_full_scope(self) -> None:
        self.fixture._git("commit", "--allow-empty", "--quiet", "-m", "empty commit")
        head = self.fixture._git("rev-parse", "HEAD")

        result = self.invoke(base=self.fixture.base, head=head)

        self.assertEqual(result, {"scope": "full", "reason": "empty_diff"})

    def test_markdown_to_markdown_rename_selects_markdown_scope(self) -> None:
        self.fixture.write("guide.md", "guide\n")
        self.fixture.commit("add guide")
        (self.repo / "guide.md").rename(self.repo / "renamed.md")
        head = self.fixture.commit("rename guide")

        self.assertEqual(self.invoke(base=self.fixture.base, head=head)["scope"], "markdown")

    def test_markdown_to_non_markdown_rename_selects_full_scope(self) -> None:
        (self.repo / "README.md").rename(self.repo / "README.txt")
        head = self.fixture.commit("rename README to text")

        self.assertEqual(self.invoke(base=self.fixture.base, head=head)["scope"], "full")

    def test_code_to_markdown_rename_selects_full_scope(self) -> None:
        self.fixture.write("source.c", "int main(void) { return 0; }\n")
        base = self.fixture.commit("add source")
        (self.repo / "source.c").rename(self.repo / "source.md")
        head = self.fixture.commit("rename source to Markdown")

        self.assertEqual(self.invoke(base=base, head=head)["scope"], "full")

    def test_symlink_change_selects_full_scope(self) -> None:
        (self.repo / "README.md").unlink()
        os.symlink("target.txt", self.repo / "README.md")
        head = self.fixture.commit("replace README with symlink")

        self.assertEqual(self.invoke(base=self.fixture.base, head=head)["scope"], "full")

    def test_executable_mode_change_selects_full_scope(self) -> None:
        self.fixture.write("README.md", "updated documentation\n")
        (self.repo / "README.md").chmod(0o755)
        head = self.fixture.commit("make README executable")

        result = self.invoke(base=self.fixture.base, head=head)

        self.assertEqual(result["scope"], "full")
        self.assertEqual(result["reason"], "mode_change")

    def test_unusual_paths_select_full_scope(self) -> None:
        for path in ("line\nbreak.txt", "überblick.txt"):
            with self.subTest(path=path):
                self.fixture.write(path, "changed\n")
                head = self.fixture.commit(f"add {path}")
                result = self.invoke(base=self.fixture.base, head=head)
                self.assertEqual(result["scope"], "full")
                self.assertEqual(result["reason"], "unsafe_path")

    def test_malformed_and_missing_refs_select_full_scope(self) -> None:
        valid_head = self.fixture._git("rev-parse", "HEAD")
        cases = (
            ("pull_request", "A" * 40, valid_head),
            ("pull_request", "0" * 39, valid_head),
            ("pull_request", "--all", valid_head),
            ("pull_request", None, valid_head),
            ("pull_request", self.fixture.base, None),
        )
        for event, base, head in cases:
            with self.subTest(base=base, head=head):
                self.assertEqual(
                    self.invoke(event=event, base=base, head=head)["scope"], "full"
                )

    def test_non_pull_request_event_selects_full_scope(self) -> None:
        head = self.fixture._git("rev-parse", "HEAD")

        result = self.invoke(event="push", base=self.fixture.base, head=head)

        self.assertEqual(result, {"scope": "full", "reason": "event_not_pull_request"})

    def test_git_failure_selects_full_scope(self) -> None:
        invalid_repository = self.root / "not-a-repository"
        invalid_repository.mkdir()
        head = "1" * 40

        result = self.invoke(
            base=self.fixture.base, head=head, repository_dir=invalid_repository
        )

        self.assertEqual(result, {"scope": "full", "reason": "git_error"})

    def test_github_output_contains_only_fixed_scope_and_reason(self) -> None:
        self.fixture.write("README.md", "updated documentation\n")
        head = self.fixture.commit("update README")
        output = self.root / "github-output.txt"

        self.invoke(base=self.fixture.base, head=head, github_output=output)

        self.assertEqual(output.read_text(encoding="ascii"), "scope=markdown\nreason=markdown_only\n")


if __name__ == "__main__":
    unittest.main()
