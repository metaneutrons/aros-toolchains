#!/usr/bin/env python3
"""Fail-closed tests for the V2 runtime CLI interface preflight."""

from __future__ import annotations

import hashlib
import ast
import importlib.util
import json
import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts/toolchain/check-v2-runtime-interface.py"
SPEC = importlib.util.spec_from_file_location("v2_runtime_interface", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC is not None and SPEC.loader is not None
SPEC.loader.exec_module(MODULE)
RECORD_SPEC = importlib.util.spec_from_file_location(
    "record_complete_qualification_v2",
    ROOT / "scripts/toolchain/record-complete-qualification-v2.py",
)
RECORD_MODULE = importlib.util.module_from_spec(RECORD_SPEC)
assert RECORD_SPEC is not None and RECORD_SPEC.loader is not None
RECORD_SPEC.loader.exec_module(RECORD_MODULE)

FAKE_EXECUTABLE = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys
import time

config = json.loads(os.environ["PREFLIGHT_FAKE_CONFIG"])
arguments = sys.argv[1:]
if config.get("marker"):
    Path(config["marker"]).write_text("called", encoding="utf-8")
blocked_environment = {
    "GOVERNANCE_TOKEN", "GH_TOKEN", "GITHUB_TOKEN", "GH_AUTH_TOKEN",
    "GH_ENTERPRISE_TOKEN", "LD_PRELOAD", "LD_LIBRARY_PATH",
}
if any(name in os.environ for name in blocked_environment) \
        or any(name.startswith(("DYLD_", "LD_")) for name in os.environ):
    print("PRIVATE_CHILD_ENV_VALUE", file=sys.stderr)
    raise SystemExit(31)
if arguments == ["--version"]:
    if config.get("sleep_version"):
        time.sleep(5)
    if config.get("mutate_path"):
        with open(config["mutate_path"], "ab") as handle:
            handle.write(b"changed")
    if config.get("stderr_secret"):
        print("PRIVATE_STDERR_SECRET_VALUE", file=sys.stderr)
    if config.get("oversized_version"):
        os.write(1, b"x" * (2 * 1024 * 1024))
        raise SystemExit(0)
    print(config.get("version_output", "aros " + config["version"]))
    raise SystemExit(0)
if arguments and arguments[-1] == "--help":
    command = " ".join(arguments[:-1])
    if config.get("stderr_secret_command") == command:
        print("PRIVATE_STDERR_SECRET_VALUE", file=sys.stderr)
    if command not in config["interfaces"]:
        raise SystemExit(2)
    if config.get("oversized_command") == command:
        os.write(1, b"x" * (2 * 1024 * 1024))
        raise SystemExit(0)
    print("Options:")
    for option in config["interfaces"][command]:
        print("  --" + option + " <VALUE>")
    if config.get("create_output_on_command") == command:
        Path(config["output_path"]).write_bytes(b"race sentinel\n")
    if config.get("replace_output_parent_on_command") == command:
        old_parent = Path(config["output_parent"])
        moved_parent = Path(config["moved_parent"])
        old_parent.rename(moved_parent)
        old_parent.mkdir()
        Path(config["replacement_sentinel"]).write_bytes(b"replacement parent sentinel\n")
    raise SystemExit(0)
print("unsupported selector", file=sys.stderr)
raise SystemExit(2)
'''


def interface_map() -> dict[str, list[str]]:
    return {
        " ".join(command): list(options)
        for command, options in MODULE.INTERFACES
    }


def interface_options(command: tuple[str, ...]) -> set[str]:
    return set(dict(MODULE.INTERFACES)[command])


def caller_options(text: str, start: str, end: str) -> set[str]:
    start_at = text.index(start)
    end_at = text.index(end, start_at)
    snippet = text[start_at:end_at]
    return set(re.findall(r"--([A-Za-z0-9][A-Za-z0-9-]*)", snippet))


def python_argv_options(path: Path, assigned_name: str) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(target, ast.Name) and target.id == assigned_name for target in node.targets):
            continue
        lists = [item for item in ast.walk(node.value) if isinstance(item, ast.List)]
        if not lists:
            continue
        return {
            item.value[2:]
            for item in ast.walk(lists[0])
            if isinstance(item, ast.Constant) and isinstance(item.value, str)
            and item.value.startswith("--")
        }
    raise AssertionError(f"no argv list assigned to {assigned_name} in {path}")


class RuntimeInterfacePreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.executable = self.root / "aros"
        self.executable.write_text(FAKE_EXECUTABLE, encoding="utf-8")
        self.executable.chmod(0o700)
        self.output = self.root / "receipt.json"
        self.version = "0.3.19"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def config(self, **updates: object) -> dict:
        value = {"version": self.version, "interfaces": interface_map()}
        value.update(updates)
        return value

    def digest(self) -> str:
        return hashlib.sha256(self.executable.read_bytes()).hexdigest()

    def run_preflight(self, config: dict, *, expected_sha: str | None = None,
                      expected_version: str | None = None, timeout: float | None = None) -> dict:
        with patch.dict(os.environ, {"PREFLIGHT_FAKE_CONFIG": json.dumps(config)}, clear=False):
            options = {
                "aros": str(self.executable),
                "aros_sha256": expected_sha or self.digest(),
                "expected_version": expected_version or self.version,
                "output": str(self.output),
            }
            if timeout is not None:
                options["command_timeout"] = timeout
            return MODULE.preflight(**options)

    def assert_failure(self, config: dict, *, expected_sha: str | None = None,
                       expected_version: str | None = None, timeout: float | None = None) -> str:
        with self.assertRaises(MODULE.PreflightError) as raised:
            self.run_preflight(
                config,
                expected_sha=expected_sha,
                expected_version=expected_version,
                timeout=timeout,
            )
        self.assertFalse(self.output.exists(), "failed preflight left a receipt behind")
        return str(raised.exception)

    def test_complete_synthetic_interface_writes_an_interface_only_receipt(self) -> None:
        config = self.config()
        with patch.dict(
            os.environ,
            {
                "PREFLIGHT_FAKE_CONFIG": json.dumps(config),
                "GOVERNANCE_TOKEN": "DO_NOT_PASS_TO_THE_CHILD",
                "GH_TOKEN": "GH_TOKEN_SECRET_FIXTURE",
                "GITHUB_TOKEN": "GITHUB_TOKEN_SECRET_FIXTURE",
                "GH_AUTH_TOKEN": "GH_AUTH_TOKEN_SECRET_FIXTURE",
                "GH_ENTERPRISE_TOKEN": "GH_ENTERPRISE_TOKEN_SECRET_FIXTURE",
                "LD_PRELOAD": "DO_NOT_LOAD_THIS_LIBRARY",
                "LD_LIBRARY_PATH": "DO_NOT_LOAD_FROM_THIS_DIRECTORY",
                "DYLD_INSERT_LIBRARIES": "DO_NOT_INJECT_THIS_LIBRARY",
                "DYLD_LIBRARY_PATH": "DO_NOT_LOAD_FROM_THIS_DIRECTORY",
            },
            clear=False,
        ):
            receipt = MODULE.preflight(
                aros=str(self.executable),
                aros_sha256=self.digest(),
                expected_version=self.version,
                output=str(self.output),
            )
        written = json.loads(self.output.read_text(encoding="utf-8"))
        self.assertEqual(receipt, written)
        self.assertEqual(receipt["assurance"], "interface-only-exact-selected-binary")
        self.assertEqual(receipt["runtime"]["sha256"], self.digest())
        self.assertEqual(receipt["runtime"]["version"], self.version)
        self.assertEqual(len(receipt["checks"]), len(MODULE.INTERFACES) + 1)
        serialized = json.dumps(receipt)
        for secret_fixture in (
            "DO_NOT_PASS_TO_THE_CHILD", "GH_TOKEN_SECRET_FIXTURE",
            "GITHUB_TOKEN_SECRET_FIXTURE", "GH_AUTH_TOKEN_SECRET_FIXTURE",
            "GH_ENTERPRISE_TOKEN_SECRET_FIXTURE",
        ):
            self.assertNotIn(secret_fixture, serialized)
        verify_package = next(
            item for item in receipt["checks"]
            if item["kind"] == "command-interface"
            and item["checked_selectors"].get("command")
            == ["toolchain", "producer", "verify-package"]
        )
        self.assertTrue(
            {
                "package-measurement",
                "package-measurement-sha256",
                "executor-contract-sha256",
                "executor-binary-sha256",
            }.issubset(set(verify_package["checked_selectors"]["required_options"]))
        )
        self.assertNotIn("tools_commit", receipt)
        self.assertTrue(all(item["result"] == "passed" for item in receipt["checks"]))

    def test_wrong_digest_is_rejected_before_any_execution(self) -> None:
        marker = self.root / "execution-marker"
        message = self.assert_failure(
            self.config(marker=str(marker)), expected_sha="0" * 64
        )
        self.assertIn("SHA-256", message)
        self.assertFalse(marker.exists())

    def test_wrong_version_does_not_create_receipt(self) -> None:
        message = self.assert_failure(
            self.config(), expected_version="0.3.20"
        )
        self.assertIn("version differs", message)

    def test_missing_command_and_required_flag_fail_closed(self) -> None:
        missing_method = self.config()
        del missing_method["interfaces"]["toolchain producer release-plan"]
        self.assertIn("command failed", self.assert_failure(missing_method))

        missing_flag = self.config()
        missing_flag["interfaces"]["toolchain producer verify-package"].remove("package-measurement")
        self.assertIn("lacks required options", self.assert_failure(missing_flag))

    def test_command_timeout_is_bounded_and_leaves_no_receipt(self) -> None:
        message = self.assert_failure(self.config(sleep_version=True), timeout=0.15)
        self.assertIn("time limit", message)

    def test_oversized_stdout_is_rejected_without_retaining_its_body(self) -> None:
        target = "sdk verify-source"
        message = self.assert_failure(self.config(oversized_command=target))
        self.assertIn("output limit", message)
        self.assertNotIn("xxxx", message)

    def test_stderr_secret_is_suppressed_and_fails_closed(self) -> None:
        message = self.assert_failure(self.config(stderr_secret=True))
        self.assertIn("stderr", message)
        self.assertNotIn("PRIVATE_STDERR_SECRET_VALUE", message)

    def test_linked_executable_and_linked_parent_are_rejected(self) -> None:
        linked = self.root / "linked-aros"
        linked.symlink_to(self.executable)
        with self.assertRaises(MODULE.PreflightError):
            MODULE.preflight(
                aros=str(linked), aros_sha256=self.digest(),
                expected_version=self.version, output=str(self.output),
            )
        self.assertFalse(self.output.exists())

        linked_parent = self.root / "linked-parent"
        linked_parent.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(MODULE.PreflightError):
            MODULE.preflight(
                aros=str(linked_parent / "aros"), aros_sha256=self.digest(),
                expected_version=self.version, output=str(self.output),
            )
        self.assertFalse(self.output.exists())

    def test_reused_and_linked_receipt_outputs_preserve_the_sentinel(self) -> None:
        sentinel = b"sentinel receipt\n"
        self.output.write_bytes(sentinel)
        with self.assertRaises(MODULE.PreflightError):
            self.run_preflight(self.config())
        self.assertEqual(self.output.read_bytes(), sentinel)

        self.output.unlink()
        target = self.root / "receipt-target"
        target.write_bytes(sentinel)
        self.output.symlink_to(target)
        with self.assertRaises(MODULE.PreflightError):
            self.run_preflight(self.config())
        self.assertTrue(self.output.is_symlink())
        self.assertEqual(target.read_bytes(), sentinel)

    def test_output_race_preserves_the_exclusive_creation_sentinel(self) -> None:
        final_command = " ".join(MODULE.INTERFACES[-1][0])
        config = self.config(
            create_output_on_command=final_command,
            output_path=str(self.output),
        )
        with patch.dict(os.environ, {"PREFLIGHT_FAKE_CONFIG": json.dumps(config)}, clear=False):
            with self.assertRaises(MODULE.PreflightError) as raised:
                MODULE.preflight(
                    aros=str(self.executable), aros_sha256=self.digest(),
                    expected_version=self.version, output=str(self.output),
                )
        self.assertIn("appeared", str(raised.exception))
        self.assertEqual(self.output.read_bytes(), b"race sentinel\n")

    def test_output_parent_replacement_does_not_redirect_or_overwrite_receipt(self) -> None:
        parent = self.root / "receipt-parent"
        parent.mkdir()
        moved_parent = self.root / "receipt-parent-moved"
        output = parent / "receipt.json"
        sentinel = parent / "replacement-sentinel"
        final_command = " ".join(MODULE.INTERFACES[-1][0])
        config = self.config(
            replace_output_parent_on_command=final_command,
            output_parent=str(parent),
            moved_parent=str(moved_parent),
            replacement_sentinel=str(sentinel),
        )
        with patch.dict(os.environ, {"PREFLIGHT_FAKE_CONFIG": json.dumps(config)}, clear=False):
            with self.assertRaises(MODULE.PreflightError) as raised:
                MODULE.preflight(
                    aros=str(self.executable), aros_sha256=self.digest(),
                    expected_version=self.version, output=str(output),
                )
        self.assertIn("parent identity changed", str(raised.exception))
        self.assertEqual(sentinel.read_bytes(), b"replacement parent sentinel\n")
        self.assertFalse(output.exists())
        self.assertFalse((moved_parent / output.name).exists())

    def test_v2_qualification_argv_and_actual_shell_callers_are_covered(self) -> None:
        record_state = {
            "runtime": "/tmp/aros",
            "source_run": {
                "repository": "owner/repo", "workflow": ".github/workflows/release.yml",
                "run_id": 1, "run_attempt": 1, "source_tag": "v1.2.3",
                "tag_object": "a" * 40, "producer_commit": "b" * 40,
            },
            "forbidden_prefixes": ["/tmp/forbidden"],
            "release_dir": Path("/tmp/release"), "inputs_sha256": "a" * 64,
            "index_sha256": "b" * 64, "selection_path": Path("/tmp/selection.json"),
            "selection_sha256": "c" * 64, "subject_path": Path("/tmp/subject.json"),
            "subject_sha256": "d" * 64, "attestation_repository": "owner/repo",
            "attestation_workflow": ".github/workflows/release.yml",
            "attestation_signer": "owner", "created_at": "2026-01-01T00:00:00Z",
            "expires_at": "2026-01-02T00:00:00Z",
        }
        record_argv = RECORD_MODULE._record_argv(None, record_state, Path("/tmp/evidence.json"))
        record_command = ("toolchain", "producer", "record-qualification")
        record_options = {item[2:] for item in record_argv if item.startswith("--")}
        self.assertEqual(interface_options(record_command), record_options)

        verify_state = dict(record_state)
        verify_state["summary"] = {
            "bindings": {"release_id": "v1.2.3", "base_url": "https://example.invalid/v1.2.3"}
        }
        verify_argv = RECORD_MODULE._verify_argv(
            verify_state, Path("/tmp/evidence.json"), "e" * 64,
            Path("/tmp/policy.json"), "f" * 64,
        )
        verify_command = ("toolchain", "producer", "verify-qualification")
        verify_options = {item[2:] for item in verify_argv if item.startswith("--")}
        self.assertEqual(interface_options(verify_command), verify_options)

        qualifier = (ROOT / "scripts/toolchain/qualify-compiler-sdk-lane-v2.sh").read_text()
        workflow = (ROOT / ".github/workflows/toolchain-release.yml").read_text()
        qualifier_calls = (
            (("toolchain", "producer", "compare"), qualifier,
             '"$aros" toolchain producer compare',
             '"$aros" toolchain producer materialize-engine-free-source'),
            (("toolchain", "producer", "compatibility-host-tools"), qualifier,
             '"$aros" toolchain producer compatibility-host-tools', "while IFS= read -r role"),
            (("sdk", "build"), qualifier,
             'if "$aros" sdk build', '> "$operation/result.json"; then'),
        )
        for command, source, start, end in qualifier_calls:
            observed = caller_options(source, start, end)
            if command == ("sdk", "build"):
                self.assertIn("host_tools+=(--host-tool", source)
                observed.add("host-tool")
            self.assertEqual(interface_options(command), observed,
                            "V2 qualifier caller drifted from the declared interface: " + " ".join(command))
        prepare = ROOT / "scripts/toolchain/prepare-compiler-sdk-inputs-v2.py"
        recipe_call_options = python_argv_options(prepare, "command")
        recipe_command = ("toolchain", "producer", "recipe")
        self.assertEqual(interface_options(recipe_command), recipe_call_options)
        materialize_call_options = python_argv_options(prepare, "materialize_result")
        qualifier_materialize_options = caller_options(
            qualifier, '"$aros" toolchain producer materialize-engine-free-source', "host_tools=()"
        )
        self.assertEqual(
            interface_options(("toolchain", "producer", "materialize-engine-free-source")),
            materialize_call_options | qualifier_materialize_options,
        )
        release_evidence_options = caller_options(
            workflow,
            'toolchain producer verify-release-evidence', '> "$final_evidence"',
        )
        self.assertEqual(
            interface_options(("toolchain", "producer", "verify-release-evidence")),
            release_evidence_options,
        )
        final_index_options = caller_options(
            workflow, 'toolchain producer index', '> "$final_index"',
        )
        self.assertEqual(
            interface_options(("toolchain", "producer", "index")),
            final_index_options,
        )

    def test_executable_mutation_during_version_call_is_rejected(self) -> None:
        original = self.executable.read_bytes()
        message = self.assert_failure(self.config(mutate_path=str(self.executable)))
        self.assertIn("identity changed", message)
        self.assertNotEqual(self.executable.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
