#!/usr/bin/env python3
"""Check the CI scope graph and execute its exact aggregate shell block.

The small indentation parser below reads the relevant Actions YAML structures
without adding a PyYAML dependency to the offline producer contract suite.
"""

from __future__ import annotations

import os
import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
WORKFLOW_PATH = ROOT / ".github/workflows/ci.yml"
PRODUCER_SUITE_PATH = ROOT / "scripts/toolchain/tests/test-producer.sh"


class WorkflowContractError(AssertionError):
    """Raised when the workflow no longer meets its scope contract."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise WorkflowContractError(message)


def _top_level_block(text: str, key: str) -> str:
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if line == f"{key}:"), None)
    if start is None:
        raise WorkflowContractError(f"workflow is missing top-level {key!r}")
    end = len(lines)
    for index in range(start + 1, len(lines)):
        line = lines[index]
        if line and not line[0].isspace():
            end = index
            break
    return "\n".join(lines[start:end])


def _job_block(text: str, name: str) -> str:
    matches = list(
        re.finditer(
            rf"^  {re.escape(name)}:\s*$",
            text,
            re.MULTILINE,
        )
    )
    if len(matches) != 1:
        raise WorkflowContractError(f"expected one workflow job named {name!r}")
    start = matches[0].start()
    next_job = re.search(r"^  [A-Za-z0-9][A-Za-z0-9_-]*:\s*$", text[start + 1 :], re.MULTILINE)
    end = start + 1 + next_job.start() if next_job else len(text)
    return text[start:end]


def _field(block: str, name: str, indentation: int = 4) -> str:
    prefix = " " * indentation
    matches = re.findall(
        rf"^{re.escape(prefix)}{re.escape(name)}:[ \t]*(.*?)[ \t]*$",
        block,
        re.MULTILINE,
    )
    if len(matches) != 1:
        raise WorkflowContractError(f"expected one {name!r} field at indentation {indentation}")
    return matches[0]


def _step_block(job: str, name: str) -> str:
    lines = job.splitlines()
    starts = [
        index
        for index, line in enumerate(lines)
        if line == f"      - name: {name}"
    ]
    if len(starts) != 1:
        raise WorkflowContractError(f"expected one workflow step named {name!r}")
    start = starts[0]
    end = len(lines)
    for index in range(start + 1, len(lines)):
        line = lines[index]
        if line.startswith("      - ") or (line and len(line) - len(line.lstrip()) < 6):
            end = index
            break
    return "\n".join(lines[start:end])


def _extract_run_block(step: str) -> str:
    lines = step.splitlines()
    run_indexes = [
        index for index, line in enumerate(lines) if re.match(r"^        run:\s*(.*?)\s*$", line)
    ]
    if len(run_indexes) != 1:
        raise WorkflowContractError("aggregate contract step must have exactly one run field")
    run_index = run_indexes[0]
    run_line = lines[run_index]
    value = run_line.split(":", 1)[1].strip()
    if value != "|":
        raise WorkflowContractError("aggregate contract must remain a literal shell block")

    body: list[str] = []
    for line in lines[run_index + 1 :]:
        if line and len(line) - len(line.lstrip()) <= 8:
            break
        body.append(line)
    while body and not body[-1].strip():
        body.pop()
    nonempty = [line for line in body if line.strip()]
    if not nonempty:
        raise WorkflowContractError("aggregate contract shell block is empty")
    indentation = min(len(line) - len(line.lstrip()) for line in nonempty)
    return "\n".join(line[indentation:] if line.strip() else "" for line in body) + "\n"


def _check_workflow_structure(workflow: str) -> None:
    trigger_block = _top_level_block(workflow, "on")
    trigger_names = re.findall(r"^  ([A-Za-z0-9_-]+):\s*$", trigger_block, re.MULTILINE)
    _require(
        trigger_names == ["pull_request", "push", "workflow_dispatch"],
        "CI event triggers changed unexpectedly",
    )
    _require(
        re.search(r"^\s+(?:paths|paths-ignore):", trigger_block, re.MULTILINE) is None,
        "CI event triggers must not use path filters",
    )

    plan = _job_block(workflow, "plan")
    markdown = _job_block(workflow, "markdown")
    full = _job_block(workflow, "producer-contracts")
    aggregate = _job_block(workflow, "contracts")

    _require(
        "scope: ${{ steps.scope.outputs.scope }}" in plan,
        "plan job must publish the planner's scope output",
    )
    _require(
        _field(markdown, "needs") == "plan"
        and _field(markdown, "if") == "needs.plan.outputs.scope == 'markdown'",
        "Markdown job must depend on plan and run only for Markdown scope",
    )
    _require(
        _field(full, "needs") == "plan"
        and _field(full, "if") == "needs.plan.outputs.scope == 'full'",
        "full producer job must depend on plan and run only for full scope",
    )
    _require(
        _field(aggregate, "if") == "always()",
        "aggregate contract job must run after failed or skipped dependencies",
    )
    _require(
        _field(aggregate, "needs") == "[plan, markdown, producer-contracts]",
        "aggregate contract job must depend on exactly plan, markdown, and producer-contracts",
    )
    for binding in (
        "PLAN_RESULT: ${{ needs.plan.result }}",
        "SCOPE: ${{ needs.plan.outputs.scope }}",
        "MARKDOWN_RESULT: ${{ needs.markdown.result }}",
        "FULL_RESULT: ${{ needs.producer-contracts.result }}",
    ):
        _require(binding in aggregate, f"aggregate job lost required result binding: {binding}")

    full_suite = _step_block(full, "Run complete offline producer contract suite")
    _require(
        "        working-directory: producer" in full_suite
        and _field(full_suite, "run", indentation=8)
        == "scripts/toolchain/tests/test-producer.sh",
        "full producer job must retain the unchanged complete-suite invocation",
    )
    _require(
        workflow.count("scripts/toolchain/tests/test-producer.sh") == 1,
        "full producer suite invocation must remain unique",
    )


def _run_aggregate(workflow: str, values: dict[str, str]) -> subprocess.CompletedProcess[str]:
    aggregate = _job_block(workflow, "contracts")
    step = _step_block(aggregate, "Require the exact planned checks to succeed")
    shell = _extract_run_block(step)
    environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), **values}
    return subprocess.run(
        ["bash", "-c", shell],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )


def _check_aggregate_matrix(workflow: str) -> None:
    all_skipped = {
        "PLAN_RESULT": "success",
        "MARKDOWN_RESULT": "skipped",
        "FULL_RESULT": "skipped",
    }
    cases: tuple[tuple[str, dict[str, str], bool], ...] = (
        (
            "valid Markdown path",
            {**all_skipped, "SCOPE": "markdown", "MARKDOWN_RESULT": "success"},
            True,
        ),
        (
            "valid full path",
            {**all_skipped, "SCOPE": "full", "FULL_RESULT": "success"},
            True,
        ),
        ("absent scope", dict(all_skipped), False),
        ("empty scope", {**all_skipped, "SCOPE": ""}, False),
        ("unknown scope", {**all_skipped, "SCOPE": "future"}, False),
        ("absent plan result", {key: value for key, value in {**all_skipped, "SCOPE": "full"}.items() if key != "PLAN_RESULT"}, False),
        ("failed plan", {**all_skipped, "SCOPE": "full", "PLAN_RESULT": "failure"}, False),
        ("cancelled plan", {**all_skipped, "SCOPE": "full", "PLAN_RESULT": "cancelled"}, False),
        ("skipped plan", {**all_skipped, "SCOPE": "full", "PLAN_RESULT": "skipped"}, False),
        (
            "failed Markdown check",
            {**all_skipped, "SCOPE": "markdown", "MARKDOWN_RESULT": "failure"},
            False,
        ),
        (
            "cancelled Markdown check",
            {**all_skipped, "SCOPE": "markdown", "MARKDOWN_RESULT": "cancelled"},
            False,
        ),
        (
            "skipped required Markdown check",
            {**all_skipped, "SCOPE": "markdown"},
            False,
        ),
        (
            "failed full check",
            {**all_skipped, "SCOPE": "full", "FULL_RESULT": "failure"},
            False,
        ),
        (
            "cancelled full check",
            {**all_skipped, "SCOPE": "full", "FULL_RESULT": "cancelled"},
            False,
        ),
        (
            "skipped required full check",
            {**all_skipped, "SCOPE": "full"},
            False,
        ),
        (
            "Markdown scope with full job also successful",
            {**all_skipped, "SCOPE": "markdown", "MARKDOWN_RESULT": "success", "FULL_RESULT": "success"},
            False,
        ),
        (
            "full scope with Markdown job also successful",
            {**all_skipped, "SCOPE": "full", "MARKDOWN_RESULT": "success", "FULL_RESULT": "success"},
            False,
        ),
    )

    for name, values, expected_success in cases:
        result = _run_aggregate(workflow, values)
        succeeded = result.returncode == 0
        if succeeded != expected_success:
            raise WorkflowContractError(
                f"aggregate shell outcome for {name!r} was {result.returncode}; "
                f"expected success={expected_success}: {result.stdout}{result.stderr}"
            )


def _check_ci_test_registration(producer_script: str) -> None:
    actual = sorted(
        re.findall(
            r'^python3 -B "\$source_root/(scripts/ci/tests/test-[^" ]+\.py)"$',
            producer_script,
            re.MULTILINE,
        )
    )
    expected = sorted(
        path.relative_to(ROOT).as_posix()
        for path in (ROOT / "scripts/ci/tests").glob("test-*.py")
    )
    _require(actual == expected, f"CI Python tests are not all registered: {actual!r} != {expected!r}")


class WorkflowScopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        cls.producer_script = PRODUCER_SUITE_PATH.read_text(encoding="utf-8")

    def test_ci_workflow_scope_structure(self) -> None:
        _check_workflow_structure(self.workflow)

    def test_aggregate_executes_exact_shell_block_for_success_and_failures(self) -> None:
        _check_aggregate_matrix(self.workflow)

    def test_all_ci_python_tests_are_registered_in_full_suite(self) -> None:
        _check_ci_test_registration(self.producer_script)

    def test_mutations_make_workflow_and_aggregate_assertions_fail(self) -> None:
        structure_mutations = (
            self.workflow.replace("    if: always()", "    if: success()", 1),
            self.workflow.replace(
                "    needs: [plan, markdown, producer-contracts]",
                "    needs: [plan, producer-contracts]",
                1,
            ),
            self.workflow.replace(
                "    if: needs.plan.outputs.scope == 'markdown'",
                "    if: needs.plan.outputs.scope == 'full'",
                1,
            ),
            self.workflow.replace("  pull_request:\n", "  pull_request:\n    paths: ['**']\n", 1),
            self.workflow.replace(
                "run: scripts/toolchain/tests/test-producer.sh",
                "run: scripts/toolchain/tests/test-producer.sh --partial",
                1,
            ),
        )
        for index, mutated in enumerate(structure_mutations):
            with self.subTest(structure_mutation=index):
                self.assertNotEqual(mutated, self.workflow)
                with self.assertRaises(WorkflowContractError):
                    _check_workflow_structure(mutated)

        shell_mutation = self.workflow.replace(
            '[[ "$PLAN_RESULT" == success ]]',
            '[[ "$PLAN_RESULT" != success ]]',
            1,
        )
        self.assertNotEqual(shell_mutation, self.workflow)
        with self.assertRaises(WorkflowContractError):
            _check_aggregate_matrix(shell_mutation)

        registration_mutation = self.producer_script.replace(
            'python3 -B "$source_root/scripts/ci/tests/test-plan-changes.py"\n',
            "",
            1,
        )
        self.assertNotEqual(registration_mutation, self.producer_script)
        with self.assertRaises(WorkflowContractError):
            _check_ci_test_registration(registration_mutation)


if __name__ == "__main__":
    unittest.main()
