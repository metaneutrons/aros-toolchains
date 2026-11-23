"""Contract tests for the split compiler qualification workflows (M2).

The checks read the workflow text the same way the producer contracts do.
Each rule has a counterprobe that mutates the real text and must fail.
"""

from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[3]
COMPILERS = ROOT / ".github/workflows/toolchain-compilers-v2.yml"
INPUTS = ROOT / ".github/workflows/toolchain-v2-inputs.yml"
MANIFEST_ACTION = ROOT / ".github/actions/retain-compiler-manifest-v2/action.yml"
COMPILER_WORKFLOW = ".github/workflows/toolchain-compilers-v2.yml"
PINNED_USE = re.compile(r"uses: (?:\./[A-Za-z0-9._/-]+|[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+@[0-9a-f]{40})(?: #.*)?\Z")


class ContractError(AssertionError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def top_level_jobs(text: str) -> list[str]:
    body = text.split("\njobs:\n", 1)
    require(len(body) == 2, "workflow has no jobs section")
    return re.findall(r"^  ([a-z0-9-]+):$", body[1], re.MULTILINE)


def job_text(text: str, name: str) -> str:
    body = text.split("\njobs:\n", 1)[1]
    match = re.search(rf"^  {re.escape(name)}:\n(.*?)(?=^  [a-z0-9-]+:\n|\Z)", body,
                      re.MULTILINE | re.DOTALL)
    require(match is not None, f"job {name} is missing")
    return match.group(1)


def check_pinned(text: str) -> None:
    for line in text.splitlines():
        stripped = line.strip().removeprefix("- ")
        if stripped.startswith("uses: "):
            require(PINNED_USE.fullmatch(stripped) is not None, f"unpinned action: {stripped}")


def check_compilers(text: str) -> None:
    trigger = text.split("\non:\n", 1)[1].split("\n\n", 1)[0]
    require(trigger.strip() == "workflow_dispatch:", "compiler workflow must only be dispatched")
    require("toolchain-release.yml" not in text, "compiler workflow names the monolithic workflow")
    require("contents: write" not in text, "compiler workflow requests contents write")
    require(top_level_jobs(text) == ["inputs", "v2-build", "compiler-assembly"],
            "compiler workflow job graph differs")
    inputs = job_text(text, "inputs")
    require("uses: ./.github/workflows/toolchain-v2-inputs.yml" in inputs
            and "mode: qualify-v2-full" in inputs and "scope: full" in inputs,
            "compiler workflow does not call the shared input jobs for the full matrix")
    build = job_text(text, "v2-build")
    require("needs: inputs\n" in build and "needs.inputs.outputs.full_matrix == 'true'" in build,
            "compiler builds are not bound to the shared inputs")
    require("workflow: .github/workflows/toolchain-compilers-v2.yml" in build,
            "compiler owners are not recorded under the compiler workflow")
    assembly = job_text(text, "compiler-assembly")
    require("needs: [inputs, v2-build]" in assembly, "compiler assembly does not wait for every build")
    require("context_from_environment('.github/workflows/toolchain-compilers-v2.yml')" in assembly,
            "compiler assembly context does not name the compiler workflow")
    require(assembly.count("--same-attempt") == 1 and "collect-compiler-owners-v2.sh" in assembly,
            "compiler assembly must read its own owners in the same attempt")
    require("assemble-compiler-candidate-v2.py" in assembly,
            "compiler assembly does not verify and compare the A/B copies")
    require("uses: ./.github/actions/retain-compiler-manifest-v2" in assembly
            and "workflow: .github/workflows/toolchain-compilers-v2.yml" in assembly
            and "job-name: Assemble and compare compiler candidates" in assembly
            and "name: Assemble and compare compiler candidates" in assembly,
            "compiler run manifest is not retained by its exact owning job")
    for workflow in re.findall(r"\.github/workflows/[A-Za-z0-9_-]+\.yml", text):
        require(workflow in (COMPILER_WORKFLOW, ".github/workflows/toolchain-v2-inputs.yml"),
                f"compiler workflow names another workflow: {workflow}")
    check_pinned(text)


def check_inputs(text: str) -> None:
    trigger = text.split("\non:\n", 1)[1].split("\n\npermissions:", 1)[0]
    require(trigger.lstrip().startswith("workflow_call:") and "workflow_dispatch" not in trigger
            and "push:" not in trigger, "shared input jobs must only be called")
    require(top_level_jobs(text) == ["v2-prepare", "v2-sources", "v2-runtimes", "v2-cargo-catalog"],
            "shared input job graph differs")
    # Owner origins are recorded and signed only by direct jobs of the caller.
    configuration = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    for forbidden in ("id-token: write", "attestations: write", "artifact-origin.py",
                      "attest-build-provenance", "contents: write"):
        require(forbidden not in configuration, f"shared input jobs must not use {forbidden}")
    check_pinned(text)


def check_manifest_action(text: str) -> None:
    require(text.count("retention-days: 14") == 2, "manifest payload and proof must keep 14 days")
    require("--role comparison --group compilers --host linux-x86_64" in text
            and "--profile=manifest --copy none" in text,
            "manifest origin selection differs")
    require('[[ "$MANIFEST_WORKFLOW" == .github/workflows/toolchain-compilers-v2.yml ]]' in text,
            "manifest action does not pin the compiler workflow")
    check_pinned(text)


class CompilerQualificationWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.compilers = COMPILERS.read_text(encoding="utf-8")
        self.inputs = INPUTS.read_text(encoding="utf-8")
        self.action = MANIFEST_ACTION.read_text(encoding="utf-8")

    def test_committed_workflows_satisfy_their_contracts(self) -> None:
        check_compilers(self.compilers)
        check_inputs(self.inputs)
        check_manifest_action(self.action)

    def assert_breaks(self, check, text: str, old: str, new: str, message: str) -> None:
        self.assertIn(old, text, old)
        with self.assertRaisesRegex(ContractError, message):
            check(text.replace(old, new, 1))

    def test_compiler_workflow_counterprobes(self) -> None:
        cases = (
            ("on:\n  workflow_dispatch:\n", "on:\n  workflow_dispatch:\n  push:\n", "only be dispatched"),
            ("    needs: [inputs, v2-build]\n", "    needs: [inputs]\n", "wait for every build"),
            ("--workflow .github/workflows/toolchain-compilers-v2.yml --job-name \"$CURRENT_JOB\" --same-attempt",
             "--workflow .github/workflows/toolchain-compilers-v2.yml --job-name \"$CURRENT_JOB\"",
             "same attempt"),
            ("          workflow: .github/workflows/toolchain-compilers-v2.yml\n          job-name: Native",
             "          workflow: .github/workflows/toolchain-release.yml\n          job-name: Native",
             "monolithic workflow"),
            ("      mode: qualify-v2-full\n", "      mode: qualify-v2\n", "full matrix"),
            ("python3 -B scripts/toolchain/assemble-compiler-candidate-v2.py",
             "true scripts/toolchain/assemble-compiler-candidate.py", "A/B copies"),
            ("uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
             "uses: actions/download-artifact@v8", "unpinned action"),
        )
        for old, new, message in cases:
            with self.subTest(message=message):
                self.assert_breaks(check_compilers, self.compilers, old, new, message)

    def test_shared_input_counterprobes(self) -> None:
        cases = (
            ("  workflow_call:\n", "  workflow_dispatch:\n  workflow_call:\n", "only be called"),
            ("permissions:\n  contents: read\n  attestations: read\n",
             "permissions:\n  contents: read\n  attestations: read\n  id-token: write\n", "id-token"),
        )
        for old, new, message in cases:
            with self.subTest(message=message):
                self.assert_breaks(check_inputs, self.inputs, old, new, message)

    def test_manifest_action_counterprobes(self) -> None:
        cases = (
            ("retention-days: 14", "retention-days: 7", "14 days"),
            ("--role comparison", "--role diagnostic", "origin selection"),
        )
        for old, new, message in cases:
            with self.subTest(message=message):
                self.assert_breaks(check_manifest_action, self.action, old, new, message)


if __name__ == "__main__":
    unittest.main()
