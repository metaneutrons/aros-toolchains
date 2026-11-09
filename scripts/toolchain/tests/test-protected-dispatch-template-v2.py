#!/usr/bin/env python3
"""Static policy checks for the inactive protected-dispatch workflow template.

These checks inspect YAML text and reject targeted policy mutations. They do
not parse or execute GitHub Actions, call a provider, verify an attestation,
or establish that the future workflow is safe to activate.
"""

from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[3]
TEMPLATE_RELATIVE = "toolchains/workflow-templates/compiler-sdk-release-dispatch.yml"
ACTIVE_RELATIVE = ".github/workflows/compiler-sdk-release-dispatch.yml"
TEMPLATE = ROOT / TEMPLATE_RELATIVE
ACTIVE = ROOT / ACTIVE_RELATIVE

CHECKOUT = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
ATTEST = "actions/attest-build-provenance@0f67c3f4856b2e3261c31976d6725780e5e4c373"
UPLOAD = "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"

EXPECTED_STEP_NAMES = [
    "Checkout reviewed main controller",
    "Stage private controller root",
    "Materialize the locked aros-tools runtime",
    "Checkout the locked aros-tools source",
    "Check the runtime interface",
    "Select the sealed start transport",
    "Derive the independent context files",
    "Upload the claim once to the empty private draft",
    "Capture the claim path and pre-sign digest",
    "Attest the canonical claim with build provenance",
    "Verify the claimed start",
    "Dispatch the native qualification once",
    "Attest the dispatch binding with build provenance",
    "Upload only the dispatch binding transport",
]

# The exact commands and option sets the template may invoke. Every one of
# them exists in the aros runtime that ships the dispatcher (aros-tools#532,
# #534, #535, #539, #540); the template adds no new Python.
COMMANDS = {
    "dispatcher-select": ["--output-dir"],
    "dispatcher-claim": [
        "--record", "--bundle", "--source-context", "--dispatcher-context",
        "--dispatcher-job", "--expected-record-sha256", "--expected-bundle-sha256",
        "--runtime-lock", "--runtime-directory", "--runtime-interface",
        "--runtime-host", "--claim-output", "--asset-output",
    ],
    "dispatcher-verify-claim": [
        "--record", "--bundle", "--claim", "--claim-asset-id", "--source-context",
        "--dispatcher-context", "--dispatcher-job", "--expected-record-sha256",
        "--expected-bundle-sha256", "--expected-claim-sha256", "--runtime-lock",
        "--runtime-directory", "--runtime-interface", "--runtime-host", "--output",
    ],
    "dispatcher-dispatch": [
        "--record", "--bundle", "--claim", "--claim-asset", "--claim-bundle-sha256",
        "--source-context", "--dispatcher-context", "--dispatcher-job", "--output",
    ],
}
COMMAND_STEP = {
    "dispatcher-select": "Select the sealed start transport",
    "dispatcher-claim": "Upload the claim once to the empty private draft",
    "dispatcher-verify-claim": "Verify the claimed start",
    "dispatcher-dispatch": "Dispatch the native qualification once",
}


class PolicyViolation(AssertionError):
    """The inactive template does not satisfy its narrow policy contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PolicyViolation(message)


def top_level_block(text: str, key: str) -> str:
    headers = list(re.finditer(r"(?m)^([A-Za-z0-9_-]+):[ \t]*$", text))
    selected = [match for match in headers if match.group(1) == key]
    require(len(selected) == 1, f"expected one top-level {key} block")
    start = selected[0].start()
    following = next((match.start() for match in headers if match.start() > start), len(text))
    return text[start:following]


def job_block(text: str) -> str:
    jobs = top_level_block(text, "jobs")
    headers = list(re.finditer(r"(?m)^  ([A-Za-z0-9][A-Za-z0-9_-]*):[ \t]*$", jobs[5:]))
    require([m.group(1) for m in headers] == ["protected-dispatch"],
            "template must contain only the protected-dispatch job")
    return jobs[5 + headers[0].start():]


def step_blocks(job: str) -> list[tuple[str, str]]:
    headers = list(re.finditer(r"(?m)^      - name: (.+)$", job))
    result: list[tuple[str, str]] = []
    for index, header in enumerate(headers):
        end = headers[index + 1].start() if index + 1 < len(headers) else len(job)
        result.append((header.group(1), job[header.start():end]))
    return result


def selected_step(steps: list[tuple[str, str]], name: str) -> str:
    matches = [block for step_name, block in steps if step_name == name]
    require(len(matches) == 1, f"expected one step named {name!r}")
    return matches[0]


def run_body(step: str) -> str:
    match = re.search(r"(?m)^        run: \|\n((?:^          .*\n|^          \n)+)", step)
    require(match is not None, "expected one literal run block")
    lines = [line[10:] if line else "" for line in match.group(1).splitlines()]
    return "\n".join(lines).rstrip() + "\n"


def flatten_shell(body: str) -> str:
    return re.sub(r"\\\n[ \t]*", "", body)


def aros_invocations(step: str) -> list[tuple[str, list[str]]]:
    found: list[tuple[str, list[str]]] = []
    if "        run: |\n" not in step:
        return found
    for line in flatten_shell(run_body(step)).splitlines():
        match = re.match(r'"\$PRIVATE_ROOT/runtime/bin/aros" toolchain producer (dispatcher-[a-z-]+) (.*)$', line)
        if match:
            found.append((match.group(1), re.findall(r"(--[a-z0-9-]+)", match.group(2))))
    return found


def validate_template(text: str) -> None:
    require(text.startswith("# Inactive future caller."), "template must identify itself as inactive")
    require(
        top_level_block(text, "on")
        == "on:\n  workflow_run:\n    workflows: ['Protected compiler and SDK start']\n"
        "    types: [completed]\n    branches: [main]\n\n",
        "trigger must be completion of the protected start on main only",
    )
    require(top_level_block(text, "permissions") == "permissions:\n  contents: read\n\n",
            "workflow-level permissions must be contents: read only")
    require(
        top_level_block(text, "concurrency")
        == "concurrency:\n  group: fixed-compiler-sdk-protected-dispatch-main\n"
        "  cancel-in-progress: false\n\n",
        "global concurrency must be fixed and non-cancelling",
    )
    require("env:" not in text.split("jobs:", 1)[0], "workflow must not install global credentials")
    require("continue-on-error" not in text and "|| true" not in text and "retry" not in text.lower(),
            "no step may suppress an error or retry a mutation")
    require("python3" not in text, "the dispatcher template adds no Python")

    job = job_block(text)
    require("    name: Dispatch compiler and SDK qualification\n" in job,
            "dispatcher job identity differs from the one the claim verifier fixes")
    require("    runs-on: ubuntu-24.04\n" in job, "dispatcher runner must be ubuntu-24.04")
    require("    environment: release\n" in job, "dispatcher must use the release environment")
    require("    timeout-minutes: 30\n" in job, "dispatcher timeout must be bounded to 30 minutes")
    expected_gate = (
        "    if: >-\n"
        "      github.repository == 'metaneutrons/aros-toolchains' &&\n"
        "      github.ref == 'refs/heads/main' &&\n"
        "      github.run_attempt == 1 &&\n"
        "      github.event_name == 'workflow_run' &&\n"
        "      github.event.workflow_run.name == 'Protected compiler and SDK start' &&\n"
        "      github.event.workflow_run.path == '.github/workflows/compiler-sdk-release-start.yml' &&\n"
        "      github.event.workflow_run.event == 'workflow_run' &&\n"
        "      github.event.workflow_run.head_branch == 'main' &&\n"
        "      github.event.workflow_run.conclusion == 'success' &&\n"
        "      github.event.workflow_run.run_attempt == 1 &&\n"
        "      github.event.workflow_run.repository.full_name == 'metaneutrons/aros-toolchains' &&\n"
        "      github.event.workflow_run.head_repository.full_name == 'metaneutrons/aros-toolchains'\n"
    )
    require(expected_gate in job, "job must require the exact successful first start attempt on main")
    permissions = re.search(r"(?m)^    permissions:\n((?:^      [^\n]*\n)+)", job)
    require(permissions is not None, "job permissions are required")
    require([line.strip() for line in permissions.group(1).splitlines()] == [
        "contents: write", "actions: write", "id-token: write", "attestations: write",
    ], "job permissions must be exactly the four required scopes")

    steps = step_blocks(job)
    require([name for name, _ in steps] == EXPECTED_STEP_NAMES,
            "the dispatcher step sequence or identity changed")
    checkout = selected_step(steps, "Checkout reviewed main controller")
    require(f"uses: {CHECKOUT} # v7.0.1\n" in checkout, "checkout must use the reviewed immutable pin")
    require("persist-credentials: false" in checkout and "ref: ${{ github.sha }}" in checkout,
            "checkout must use reviewed main without persisted credentials")
    root = run_body(selected_step(steps, "Stage private controller root"))
    for needed in ("umask 077", 'mkdir -- "$root"', 'chmod 700 -- "$root"'):
        require(needed in root, f"private root staging is missing {needed!r}")
    require("mkdir -p" not in root, "private root creation must be exclusive")

    for name, options in COMMANDS.items():
        step = selected_step(steps, COMMAND_STEP[name])
        invocations = aros_invocations(step)
        require(len(invocations) == 1 and invocations[0][0] == name,
                f"{COMMAND_STEP[name]!r} must invoke exactly {name}")
        require(invocations[0][1] == options, f"{name} must use exactly its closed option set")
        require("GH_HOST: github.com" in step and "GH_TOKEN: ${{ github.token }}" in step,
                f"{name} must use the fixed host and the job token only")
    all_invocations = [name for _, block in steps for name, _ in aros_invocations(block)]
    require(all_invocations == list(COMMANDS),
            "the four dispatcher commands must run once each in the fixed order")
    require(all_invocations.count("dispatcher-dispatch") == 1, "exactly one dispatch step")

    claim_attest = selected_step(steps, "Attest the canonical claim with build provenance")
    binding_attest = selected_step(steps, "Attest the dispatch binding with build provenance")
    for attest in (claim_attest, binding_attest):
        require(f"uses: {ATTEST} # v4.1.1\n" in attest, "attestation must use the reviewed immutable pin")
        require("push-to-registry: false" in attest and "create-storage-record: false" in attest,
                "attestation must not push or store records")
    require("subject-path: ${{ steps.claim.outputs.path }}" in claim_attest,
            "the claim attestation must sign the captured claim bytes")
    require("compiler-sdk-dispatch-binding-v2.json" in binding_attest,
            "the binding attestation must sign the binding subject")
    upload = selected_step(steps, "Upload only the dispatch binding transport")
    require(f"uses: {UPLOAD} # v7.0.1\n" in upload, "upload must use the reviewed immutable pin")
    require("overwrite: false" in upload and "if-no-files-found: error" in upload,
            "binding upload must not overwrite and must require its files")
    dispatch = selected_step(steps, "Dispatch the native qualification once")
    require("--claim-bundle-sha256 \"$claim_bundle_sha256\"" in flatten_shell(run_body(dispatch)),
            "dispatch must pass the digest of the claim signature bundle")
    require("CLAIM_BUNDLE_PATH: ${{ steps.claim-signature.outputs.bundle-path }}" in dispatch,
            "dispatch must read the claim bundle produced by the claim attestation")


class ProtectedDispatchTemplateTests(unittest.TestCase):
    def text(self) -> str:
        return TEMPLATE.read_text(encoding="utf-8")

    def test_template_satisfies_its_policy_and_is_not_installed(self) -> None:
        validate_template(self.text())
        self.assertFalse(ACTIVE.exists(), "the template must stay outside .github/workflows")

    def test_targeted_mutations_are_rejected(self) -> None:
        text = self.text()
        mutations = [
            ("trigger on another workflow", "workflows: ['Protected compiler and SDK start']",
             "workflows: ['Producer contracts']"),
            ("trigger on every branch", "    branches: [main]\n", "    branches: ['**']\n"),
            ("write at workflow level", "permissions:\n  contents: read\n",
             "permissions:\n  contents: write\n"),
            ("cancel in progress", "cancel-in-progress: false", "cancel-in-progress: true"),
            ("other job name", "name: Dispatch compiler and SDK qualification",
             "name: Dispatch"),
            ("other runner", "runs-on: ubuntu-24.04", "runs-on: ubuntu-latest"),
            ("drop environment", "    environment: release\n", ""),
            ("allow reruns", "github.run_attempt == 1 &&\n      github.event_name",
             "github.event_name"),
            ("accept a failed start", "github.event.workflow_run.conclusion == 'success'",
             "github.event.workflow_run.conclusion == 'failure'"),
            ("accept forks", "github.event.workflow_run.head_repository.full_name == 'metaneutrons/aros-toolchains'",
             "github.event.workflow_run.head_repository.full_name != ''"),
            ("widen permissions", "      attestations: write\n    steps:",
             "      attestations: write\n      packages: write\n    steps:"),
            ("drop actions write", "      actions: write\n", ""),
            ("unpinned checkout", CHECKOUT, "actions/checkout@v7"),
            ("unpinned attest", ATTEST, "actions/attest-build-provenance@v4"),
            ("persist credentials", "persist-credentials: false", "persist-credentials: true"),
            ("non-exclusive root", 'mkdir -- "$root"\n', 'mkdir -p -- "$root"\n'),
            ("swallow an error", "      - name: Dispatch the native qualification once\n",
             "      - name: Dispatch the native qualification once\n        continue-on-error: true\n"),
            ("retry the dispatch", "toolchain producer dispatcher-dispatch \\\n",
             "toolchain producer dispatcher-dispatch --retry 3 \\\n"),
            ("drop the claim output", " \\\n            --asset-output \"$PRIVATE_ROOT/out/claim-asset.json\"", ""),
            ("dispatch before verify", "dispatcher-verify-claim", "dispatcher-dispatch-x"),
            ("python adapter", "set -euo pipefail\n          selection=",
             "set -euo pipefail\n          python3 -B x.py\n          selection="),
            ("other claim digest source", "${{ steps.claim-signature.outputs.bundle-path }}",
             "${{ steps.claim.outputs.path }}"),
            ("overwrite the transport", "overwrite: false", "overwrite: true"),
        ]
        for label, before, after in mutations:
            with self.subTest(label=label):
                self.assertIn(before, text, f"mutation anchor missing for {label}")
                with self.assertRaises(PolicyViolation):
                    validate_template(text.replace(before, after, 1))

    def test_step_order_and_count_changes_are_rejected(self) -> None:
        text = self.text()
        job = job_block(text)
        steps = step_blocks(job)
        names = [name for name, _ in steps]
        swapped = list(steps)
        index = names.index("Verify the claimed start")
        swapped[index], swapped[index + 1] = swapped[index + 1], swapped[index]
        reordered = text.replace(job, job[: job.index(steps[0][1])] + "".join(b for _, b in swapped), 1)
        with self.assertRaises(PolicyViolation):
            validate_template(reordered)
        duplicate = text.replace(steps[-1][1], steps[-1][1] + steps[-1][1], 1)
        with self.assertRaises(PolicyViolation):
            validate_template(duplicate)
        extra_job = text + "\n  second-job:\n    runs-on: ubuntu-24.04\n    steps: []\n"
        with self.assertRaises(PolicyViolation):
            validate_template(extra_job)


if __name__ == "__main__":
    unittest.main()
