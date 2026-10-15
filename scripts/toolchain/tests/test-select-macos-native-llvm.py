#!/usr/bin/env python3
"""Exercise macOS native LLVM selection and its V2 workflow bindings."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
HELPER = ROOT / "scripts/toolchain/select-macos-native-llvm.sh"
POLICY_PATH = ROOT / "scripts/toolchain/tests/test-compiler-sdk-workflow-v2.py"
SPEC = importlib.util.spec_from_file_location("compiler_sdk_workflow_policy", POLICY_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load workflow policy module: {POLICY_PATH}")
POLICY = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = POLICY
SPEC.loader.exec_module(POLICY)

SELECTOR_NAME = "Select installed macOS LLVM tools"
SELECTOR_CALL = "bash scripts/toolchain/select-macos-native-llvm.sh"
NATIVE_RUST_ACTION = "uses: ./.github/actions/select-native-rust-toolchain"
NATIVE_RUST_STEP = "      - id: rust\n"
JOBS = {
    "v2-build": "Install native compiler prerequisites",
    "v2-sdk": "Install native SDK consumer prerequisites",
    "v2-qualify": "Install compiler and SDK consumer prerequisites",
}


class MacOSNativeLLVMHelperTests(unittest.TestCase):
    def run_helper(
        self,
        *,
        brew_prefix: str | None = None,
        brew_status: int = 0,
        runner_os: str = "macOS",
        github_path_value: str | None = "present",
        missing_tools: set[str] | None = None,
        nonexecutable_tools: set[str] | None = None,
        failing_tools: set[str] | None = None,
        prefix_has_bin: bool = True,
    ) -> tuple[subprocess.CompletedProcess[str], bytes | None, bytes, list[str]]:
        missing_tools = missing_tools or set()
        nonexecutable_tools = nonexecutable_tools or set()
        failing_tools = failing_tools or set()

        with tempfile.TemporaryDirectory(prefix="macos-native-llvm-test-") as temporary:
            base = Path(temporary)
            prefix = base / "homebrew" / "opt" / "llvm"
            bin_dir = prefix / "bin"
            if prefix_has_bin:
                bin_dir.mkdir(parents=True)
            else:
                prefix.mkdir(parents=True)

            fake_bin = base / "fake-bin"
            fake_bin.mkdir()
            brew = fake_bin / "brew"
            brew.write_text(
                "#!/bin/sh\n"
                "[ \"$#\" -eq 2 ] && [ \"$1\" = --prefix ] && [ \"$2\" = llvm ] || exit 91\n"
                "[ \"${FAKE_BREW_STATUS:-0}\" -eq 0 ] || exit \"$FAKE_BREW_STATUS\"\n"
                "printf '%s' \"$FAKE_BREW_PREFIX\"\n",
                encoding="utf-8",
            )
            brew.chmod(0o700)

            log_path = base / "llvm-invocations.log"
            for tool in ("llvm-ar", "llvm-ranlib"):
                if tool in missing_tools or not bin_dir.is_dir():
                    continue
                failure = 23 if tool in failing_tools else 0
                executable = bin_dir / tool
                executable.write_text(
                    "#!/bin/sh\n"
                    f"printf '%s %s\\n' '{tool}' \"$*\" >> \"$FAKE_LLVM_LOG\"\n"
                    "[ \"$#\" -eq 1 ] && [ \"$1\" = --version ] || exit 92\n"
                    f"printf '%s\\n' '{tool} fixture version'\n"
                    f"exit {failure}\n",
                    encoding="utf-8",
                )
                executable.chmod(0o600 if tool in nonexecutable_tools else 0o700)

            github_path = base / "github-path"
            github_path.write_bytes(b"before/path\n")
            initial_contents = github_path.read_bytes()
            env = {
                "PATH": f"{fake_bin}:/usr/bin:/bin",
                "FAKE_BREW_PREFIX": brew_prefix if brew_prefix is not None else str(prefix),
                "FAKE_BREW_STATUS": str(brew_status),
                "FAKE_LLVM_LOG": str(log_path),
                "RUNNER_OS": runner_os,
            }
            if github_path_value == "present":
                env["GITHUB_PATH"] = str(github_path)
            elif github_path_value is not None:
                env["GITHUB_PATH"] = github_path_value

            result = subprocess.run(
                ["bash", str(HELPER)],
                cwd=ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )
            invocations = log_path.read_text(encoding="utf-8").splitlines() if log_path.exists() else []
            path_contents = github_path.read_bytes() if github_path.exists() else None
            return result, path_contents, initial_contents, invocations

    def assert_failed_without_publication(
        self, *, expected_code: int = 1, expected_message: str = "", **options: object
    ) -> None:
        result, path_contents, initial_contents, _ = self.run_helper(**options)
        self.assertEqual(result.returncode, expected_code, result.stdout + result.stderr)
        if expected_message:
            self.assertIn(expected_message, result.stderr)
        self.assertEqual(path_contents, initial_contents)

    def test_publishes_only_after_both_tools_pass_version_probe(self) -> None:
        result, path_contents, initial_contents, invocations = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(invocations, ["llvm-ar --version", "llvm-ranlib --version"])
        self.assertEqual(result.stdout.splitlines(), ["llvm-ar fixture version", "llvm-ranlib fixture version"])
        self.assertIsNotNone(path_contents)
        self.assertTrue(path_contents.startswith(initial_contents))
        self.assertTrue(path_contents.endswith(b"/homebrew/opt/llvm/bin\n"))

    def test_rejects_each_missing_or_nonexecutable_tool_without_publication(self) -> None:
        for tool in ("llvm-ar", "llvm-ranlib"):
            with self.subTest(missing=tool):
                self.assert_failed_without_publication(
                    missing_tools={tool}, expected_message=f"missing executable {tool}"
                )
            with self.subTest(nonexecutable=tool):
                self.assert_failed_without_publication(
                    nonexecutable_tools={tool}, expected_message=f"missing executable {tool}"
                )

    def test_rejects_version_failure_from_each_tool_without_publication(self) -> None:
        for tool in ("llvm-ar", "llvm-ranlib"):
            with self.subTest(tool=tool):
                self.assert_failed_without_publication(failing_tools={tool}, expected_code=23)

    def test_rejects_brew_failure_and_invalid_prefixes_without_publication(self) -> None:
        with self.subTest(reason="brew failure"):
            self.assert_failed_without_publication(brew_status=19, expected_code=19)
        with self.subTest(reason="relative prefix"):
            self.assert_failed_without_publication(brew_prefix="relative/llvm")
        with self.subTest(reason="multiline prefix"):
            self.assert_failed_without_publication(brew_prefix="/valid/llvm\n/extra")
        with self.subTest(reason="carriage return prefix"):
            self.assert_failed_without_publication(brew_prefix="/valid/llvm\r/extra")
        with self.subTest(reason="missing bin directory"):
            self.assert_failed_without_publication(prefix_has_bin=False)

    def test_rejects_nonmac_runner_and_missing_github_path_without_publication(self) -> None:
        with self.subTest(reason="non-macOS runner"):
            self.assert_failed_without_publication(runner_os="Linux")
        with self.subTest(reason="missing GITHUB_PATH"):
            self.assert_failed_without_publication(github_path_value=None)
        with self.subTest(reason="empty GITHUB_PATH"):
            self.assert_failed_without_publication(github_path_value="")


def replace_job(workflow: str, name: str, replacement: str) -> str:
    original = POLICY.workflow_job(workflow, name)
    start = workflow.index(original)
    return workflow[:start] + replacement + workflow[start + len(original) :]


def validate_macos_llvm_workflow(documents: object) -> None:
    workflow = documents.text(POLICY.WORKFLOW)
    for name, installer_name in JOBS.items():
        job = POLICY.workflow_job(workflow, name)
        POLICY.require(
            job.count(f"name: {SELECTOR_NAME}\n") == 1,
            f"{name} must contain exactly one macOS LLVM selector step",
        )
        installer = POLICY.workflow_step(job, installer_name)
        selector = POLICY.workflow_step(job, SELECTOR_NAME)
        POLICY.require(
            "install-build-prerequisites.sh" in installer,
            f"{name} source prerequisite installer is missing",
        )
        POLICY.require(
            re.search(r"(?m)^        if: runner\.os == 'macOS'\s*$", selector) is not None,
            f"{name} macOS LLVM selector must be conditional on the macOS runner",
        )
        POLICY.require(
            selector.count(SELECTOR_CALL) == 1,
            f"{name} must invoke the macOS LLVM selector exactly once",
        )
        POLICY.require(
            job.count(NATIVE_RUST_ACTION) == 1,
            f"{name} must contain exactly one native Rust toolchain action",
        )
        installer_start = job.index(f"      - name: {installer_name}\n")
        selector_start = job.index(f"      - name: {SELECTOR_NAME}\n")
        native_action_start = job.index(NATIVE_RUST_ACTION)
        POLICY.require(
            installer_start < selector_start < native_action_start,
            f"{name} must select macOS LLVM after source installation and before native toolchain setup",
        )


class MacOSNativeLLVMWorkflowTests(unittest.TestCase):
    def new_documents(self, workflow: str | None = None) -> object:
        documents = POLICY.Documents()
        if workflow is not None:
            documents.set_text(POLICY.WORKFLOW, workflow)
        return documents

    def test_current_v2_jobs_bind_mac_llvm_between_install_and_native_setup(self) -> None:
        validate_macos_llvm_workflow(self.new_documents())

    def test_rejects_removed_late_or_unconditional_selector_steps(self) -> None:
        baseline = self.new_documents().text(POLICY.WORKFLOW)
        for name in JOBS:
            original_job = POLICY.workflow_job(baseline, name)
            selector = POLICY.workflow_step(original_job, SELECTOR_NAME)

            with self.subTest(job=name, mutation="removed"):
                mutated = replace_job(baseline, name, original_job.replace(selector, "", 1))
                with self.assertRaises(POLICY.PolicyViolation):
                    validate_macos_llvm_workflow(self.new_documents(mutated))

            with self.subTest(job=name, mutation="late"):
                without_selector = original_job.replace(selector, "", 1)
                native_step_start = without_selector.index(NATIVE_RUST_STEP)
                native_end_match = re.search(
                    r"(?m)^      - ",
                    without_selector[native_step_start + len(NATIVE_RUST_STEP) :],
                )
                native_end = (
                    native_step_start + len(NATIVE_RUST_STEP) + native_end_match.start()
                    if native_end_match is not None
                    else len(without_selector)
                )
                late_job = without_selector[:native_end] + selector + without_selector[native_end:]
                mutated = replace_job(baseline, name, late_job)
                with self.assertRaises(POLICY.PolicyViolation):
                    validate_macos_llvm_workflow(self.new_documents(mutated))

            with self.subTest(job=name, mutation="unconditional"):
                unconditional = selector.replace("        if: runner.os == 'macOS'\n", "", 1)
                mutated = replace_job(
                    baseline,
                    name,
                    original_job.replace(selector, unconditional, 1),
                )
                with self.assertRaises(POLICY.PolicyViolation):
                    validate_macos_llvm_workflow(self.new_documents(mutated))


if __name__ == "__main__":
    unittest.main()
