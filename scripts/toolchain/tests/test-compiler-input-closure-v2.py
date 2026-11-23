"""Contract tests for the deny-by-default compiler input closure."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "compiler-input-closure-v2.py"
SPEC = importlib.util.spec_from_file_location("closure", SCRIPT)
closure = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(closure)
SOURCE_ROOT = SCRIPT.parents[2]

CLASSIFICATION = {
    "schema": "aros-compiler-input-classification-v2",
    "sdk_only": [
        {"path": ".github/workflows/toolchain-sdk-v2.yml", "kind": "file",
         "reason": "SDK qualification workflow."},
        {"path": "docs", "kind": "directory", "reason": "Narrative documentation."},
    ],
}
FILES = {
    ".github/workflows/toolchain-compilers-v2.yml": "compiler workflow\n",
    ".github/workflows/toolchain-sdk-v2.yml": "sdk workflow\n",
    ".github/actions/build-native-lane-v2/action.yml": "action\n",
    "docs/README.md": "docs index\n",
    "docs/plans/plan.md": "plan\n",
    "scripts/toolchain/build-lane-v2.sh": "#!/bin/sh\n",
    "toolchains/gnu-16.2.0.sources.json": "{}\n",
    "toolchains/compiler-sdk-ci-selection-v2.json": "{\"pin\": 1}\n",
}


class Repository:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "Closure Test")
        self.git("config", "commit.gpgsign", "false")
        for path, text in FILES.items():
            self.write(path, text)
        self.write_classification(CLASSIFICATION)

    def git(self, *arguments: str) -> str:
        return subprocess.run(["git", "-C", str(self.root), *arguments], check=True,
                              capture_output=True, text=True).stdout

    def write(self, path: str, text: str) -> None:
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)

    def write_classification(self, document: object) -> None:
        self.write(closure.CLASSIFICATION_PATH, json.dumps(document, indent=2) + "\n")

    def commit(self, message: str = "change") -> str:
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", message)
        return self.git("rev-parse", "HEAD").strip()

    def digest(self, commit: str) -> str:
        return closure.closure(str(self.root), commit)["closure_sha256"]


class ClosureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="closure-")
        self.repo = Repository(Path(self.temporary.name))
        self.base = self.repo.commit("base")
        self.base_digest = self.repo.digest(self.base)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def assert_changed(self, path: str, text: str = "changed\n") -> None:
        self.repo.write(path, text)
        self.assertNotEqual(self.repo.digest(self.repo.commit()), self.base_digest, path)

    def assert_rejected(self, message: str) -> None:
        commit = self.repo.commit()
        with self.assertRaisesRegex(closure.ClosureError, message):
            closure.closure(str(self.repo.root), commit)

    def test_sdk_only_changes_keep_the_digest(self) -> None:
        self.repo.write(".github/workflows/toolchain-sdk-v2.yml", "fixed sdk workflow\n")
        self.repo.write("docs/plans/plan.md", "revised plan\n")
        self.repo.write("docs/new/notes.md", "new notes\n")
        result = closure.closure(str(self.repo.root), self.repo.commit())
        self.assertEqual(result["closure_sha256"], self.base_digest)
        self.assertEqual(result["excluded_count"], 4)

    def test_every_other_change_changes_the_digest(self) -> None:
        for path in (".github/workflows/toolchain-compilers-v2.yml",
                     ".github/actions/build-native-lane-v2/action.yml",
                     "scripts/toolchain/build-lane-v2.sh",
                     "toolchains/gnu-16.2.0.sources.json",
                     "toolchains/compiler-sdk-ci-selection-v2.json"):
            with self.subTest(path=path):
                self.assert_changed(path, f"changed {path}\n")

    def test_a_new_unclassified_file_changes_the_digest(self) -> None:
        self.assert_changed("scripts/toolchain/new-helper.py", "print()\n")

    def test_a_classification_change_changes_the_digest(self) -> None:
        document = json.loads(json.dumps(CLASSIFICATION))
        document["sdk_only"][1]["reason"] = "Reworded reason."
        self.repo.write_classification(document)
        self.assertNotEqual(self.repo.digest(self.repo.commit()), self.base_digest)

    def test_moves_across_the_boundary_change_the_digest(self) -> None:
        self.repo.git("mv", "docs/plans/plan.md", "toolchains/plan.md")
        self.assertNotEqual(self.repo.digest(self.repo.commit()), self.base_digest)
        self.repo.git("mv", "toolchains/plan.md", "docs/plans/plan.md")
        self.assertEqual(self.repo.digest(self.repo.commit()), self.base_digest)
        self.repo.git("mv", "toolchains/gnu-16.2.0.sources.json", "docs/gnu.json")
        self.assertNotEqual(self.repo.digest(self.repo.commit()), self.base_digest)

    def test_an_emptied_sdk_only_directory_is_a_stale_entry(self) -> None:
        self.repo.git("rm", "-q", "-r", "docs")
        self.assert_rejected("does not exist as a directory")

    def test_an_executable_mode_change_changes_the_digest(self) -> None:
        os.chmod(self.repo.root / "scripts/toolchain/build-lane-v2.sh", 0o755)
        self.assertNotEqual(self.repo.digest(self.repo.commit()), self.base_digest)

    def test_the_closure_is_read_from_the_commit_not_the_working_tree(self) -> None:
        self.repo.write("toolchains/gnu-16.2.0.sources.json", "uncommitted\n")
        self.assertEqual(self.repo.digest(self.base), self.base_digest)

    def test_protected_inputs_cannot_be_excluded(self) -> None:
        for entry in (
            {"path": closure.CLASSIFICATION_PATH, "kind": "file", "reason": "x"},
            {"path": ".github/workflows/toolchain-compilers-v2.yml", "kind": "file", "reason": "x"},
            {"path": ".github", "kind": "directory", "reason": "x"},
            {"path": "toolchains", "kind": "directory", "reason": "x"},
        ):
            with self.subTest(entry=entry["path"]):
                self.repo.write_classification({**CLASSIFICATION, "sdk_only": [entry]})
                self.assert_rejected("protected compiler input")

    def test_invalid_classifications_are_rejected(self) -> None:
        sdk = CLASSIFICATION["sdk_only"]
        cases = {
            "unexpected or missing keys": {**CLASSIFICATION, "extra": True},
            "schema differs": {**CLASSIFICATION, "schema": "other"},
            "needs a reason": {**CLASSIFICATION, "sdk_only": [{**sdk[1], "reason": ""}]},
            "kind must be": {**CLASSIFICATION, "sdk_only": [{**sdk[1], "kind": "glob"}]},
            "not canonical": {**CLASSIFICATION, "sdk_only": [{**sdk[1], "path": "docs/../toolchains"}]},
            "does not exist as a file": {**CLASSIFICATION, "sdk_only": [
                {"path": "docs/missing.md", "kind": "file", "reason": "stale"}]},
            "does not exist as a directory": {**CLASSIFICATION, "sdk_only": [
                {"path": "docs/plans/plan.md", "kind": "directory", "reason": "wrong kind"}]},
            "lists a path twice": {**CLASSIFICATION, "sdk_only": [sdk[1], sdk[1]]},
            "must be sorted": {**CLASSIFICATION, "sdk_only": [sdk[1], sdk[0]]},
            "overlap": {**CLASSIFICATION, "sdk_only": [
                sdk[1], {"path": "docs/plans/plan.md", "kind": "file", "reason": "overlap"}]},
        }
        for message, document in cases.items():
            with self.subTest(message=message):
                self.repo.write_classification(document)
                self.assert_rejected(message)

    def test_duplicate_json_keys_are_rejected(self) -> None:
        self.repo.write(closure.CLASSIFICATION_PATH,
                        '{"schema": "aros-compiler-input-classification-v2", "sdk_only": [], "sdk_only": []}\n')
        self.assert_rejected("repeats a JSON key")

    def test_a_missing_classification_is_rejected(self) -> None:
        self.repo.git("rm", "-q", closure.CLASSIFICATION_PATH)
        self.assert_rejected("no compiler input classification")

    def test_only_full_commit_ids_are_accepted(self) -> None:
        for value in (self.base[:12], "HEAD", "main", self.base.upper()):
            with self.subTest(value=value):
                with self.assertRaisesRegex(closure.ClosureError, "full lowercase object ID"):
                    closure.closure(str(self.repo.root), value)
        tree = self.repo.git("rev-parse", f"{self.base}^{{tree}}").strip()
        with self.assertRaises(closure.ClosureError):
            closure.closure(str(self.repo.root), tree)

    def test_cli_reports_json_and_failures(self) -> None:
        ok = subprocess.run(["python3", "-B", str(SCRIPT), "--repository-dir", str(self.repo.root),
                             "--commit", self.base], capture_output=True, text=True, check=False)
        self.assertEqual(ok.returncode, 0, ok.stderr)
        self.assertEqual(json.loads(ok.stdout)["closure_sha256"], self.base_digest)
        bad = subprocess.run(["python3", "-B", str(SCRIPT), "--repository-dir", str(self.repo.root),
                              "--commit", "0" * 40], capture_output=True, text=True, check=False)
        self.assertEqual(bad.returncode, 2)
        self.assertIn("compiler input closure failed", bad.stderr)
        self.assertEqual(bad.stdout, "")


class RepositoryClassificationTests(unittest.TestCase):
    """The committed classification of this repository must validate."""

    def test_this_repository_classification_validates(self) -> None:
        head = subprocess.run(["git", "-C", str(SOURCE_ROOT), "rev-parse", "HEAD"],
                              capture_output=True, text=True, check=False)
        if head.returncode != 0:
            self.skipTest("source root is not a Git checkout")
        result = closure.closure(str(SOURCE_ROOT), head.stdout.strip())
        self.assertGreater(result["included_count"], 0)


if __name__ == "__main__":
    unittest.main()
