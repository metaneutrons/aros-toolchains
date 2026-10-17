#!/usr/bin/env python3
"""Static policy checks for the inactive protected-start workflow template.

These checks inspect YAML text and reject targeted policy mutations. They do
not parse or execute GitHub Actions, call a provider, verify an attestation,
or establish that the future workflow is safe to activate.
"""

from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[3]
TEMPLATE_RELATIVE = "toolchains/workflow-templates/compiler-sdk-release-start.yml"
ACTIVE_RELATIVE = ".github/workflows/compiler-sdk-release-start.yml"
TEMPLATE = ROOT / TEMPLATE_RELATIVE
ACTIVE = ROOT / ACTIVE_RELATIVE

CHECKOUT = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
COSIGN = "sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6"
RELEASE_PLEASE = "googleapis/release-please-action@45996ed1f6d02564a971a2fa1b5860e934307cf7"
ATTEST = "actions/attest-build-provenance@0f67c3f4856b2e3261c31976d6725780e5e4c373"
UPLOAD = "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
READY_GUARD = "if: success() && steps.admit.outputs.ready == 'true'"

EXPECTED_STEP_NAMES = [
    "Checkout reviewed main controller",
    "Stage private controller root",
    "Admit exact release candidate",
    "Validate derived Release Please draft configuration",
    "Install pinned Cosign",
    "Create the admitted annotated candidate tag",
    "Create the admitted private Release Please draft",
    "Bind the private draft to the admitted tag",
    "Construct the unsigned compiler and SDK start record",
    "Capture record path and pre-sign digest",
    "Attest the start record with build provenance",
    "Seal the exact record and attestation bundle",
    "Upload only the sealed start transport",
]


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


def job_block(text: str) -> tuple[str, list[str]]:
    jobs = top_level_block(text, "jobs")
    headers = list(re.finditer(r"(?m)^  ([A-Za-z0-9][A-Za-z0-9_-]*):[ \t]*$", jobs[5:]))
    names = [match.group(1) for match in headers]
    require(names == ["protected-start"], "template must contain only the protected-start job")
    start = 5 + headers[0].start()
    return jobs[start:], names


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


def mapping_block(step: str, key: str) -> dict[str, str]:
    match = re.search(
        rf"(?m)^        {re.escape(key)}:\n((?:^          [^\n]*\n)+)", step
    )
    require(match is not None, f"step has no {key} mapping")
    values: dict[str, str] = {}
    for line in match.group(1).splitlines():
        item = re.fullmatch(r"          ([A-Za-z0-9_-]+):[ \t]*(.*)", line)
        require(item is not None, f"unsupported nested {key} mapping")
        require(item.group(1) not in values, f"duplicate {key} key {item.group(1)}")
        values[item.group(1)] = item.group(2)
    return values


def run_body(step: str) -> str:
    match = re.search(r"(?m)^        run: \|\n((?:^          .*\n|^          \n)+)", step)
    require(match is not None, "expected one literal run block")
    lines = [line[10:] if line else "" for line in match.group(1).splitlines()]
    return "\n".join(lines).rstrip() + "\n"


def flatten_shell(body: str) -> str:
    return re.sub(r"\\\n[ \t]*", "", body)


def validate_template(text: str) -> None:
    require(text.startswith("# Inactive future caller."), "template must identify itself as inactive")
    require(
        top_level_block(text, "on")
        == "on:\n  workflow_run:\n    workflows: ['Producer contracts']\n"
        "    types: [completed]\n    branches: [main]\n\n",
        "template trigger must be workflow_run completion of Producer contracts on main only",
    )
    require(
        top_level_block(text, "permissions") == "permissions:\n  contents: read\n\n",
        "workflow-level permissions must be contents: read only",
    )
    require(
        top_level_block(text, "concurrency")
        == "concurrency:\n  group: fixed-compiler-sdk-protected-start-main\n"
        "  cancel-in-progress: false\n\n",
        "global concurrency must be fixed and non-cancelling",
    )
    require("env:" not in text.split("jobs:", 1)[0], "workflow must not install global credentials")

    job, _ = job_block(text)
    require("    name: Create protected compiler and SDK start\n" in job,
            "protected start job identity differs")
    require("    runs-on: ubuntu-24.04\n" in job, "protected start runner must be ubuntu-24.04")
    require("    environment: release\n" in job, "protected start must use the release environment")
    require("    timeout-minutes: 30\n" in job, "protected start timeout must be bounded to 30 minutes")
    expected_gate = (
        "    if: >-\n"
        "      github.repository == 'metaneutrons/aros-toolchains' &&\n"
        "      github.ref == 'refs/heads/main' &&\n"
        "      github.run_attempt == 1 &&\n"
        "      github.event_name == 'workflow_run' &&\n"
        "      github.event.workflow_run.name == 'Producer contracts' &&\n"
        "      github.event.workflow_run.path == '.github/workflows/ci.yml' &&\n"
        "      github.event.workflow_run.event == 'push' &&\n"
        "      github.event.workflow_run.head_branch == 'main' &&\n"
        "      github.event.workflow_run.conclusion == 'success' &&\n"
        "      github.event.workflow_run.run_attempt == 1 &&\n"
        "      github.event.workflow_run.repository.full_name == 'metaneutrons/aros-toolchains' &&\n"
        "      github.event.workflow_run.head_repository.full_name == 'metaneutrons/aros-toolchains'\n"
    )
    require(expected_gate in job, "job must require the exact successful first main push attempt in this repository")

    permission_match = re.search(
        r"(?m)^    permissions:\n((?:^      [^\n]*\n)+)", job
    )
    require(permission_match is not None, "job permissions are required")
    job_permissions = [line.strip() for line in permission_match.group(1).splitlines()]
    require(
        job_permissions == [
            "contents: write",
            "pull-requests: read",
            "actions: read",
            "id-token: write",
            "attestations: write",
        ],
        "job permissions must match the five explicitly required scopes",
    )

    steps = step_blocks(job)
    require([name for name, _ in steps] == EXPECTED_STEP_NAMES,
            "the single job step sequence or identity changed")
    admission_index = EXPECTED_STEP_NAMES.index("Admit exact release candidate")
    for step_name, block in steps[admission_index + 1:]:
        require(READY_GUARD in block, f"step {step_name!r} must require success and admission.ready")

    checkout = selected_step(steps, "Checkout reviewed main controller")
    require(f"uses: {CHECKOUT} # v7.0.1\n" in checkout,
            "checkout action must use the reviewed immutable pin")
    require(
        mapping_block(checkout, "with") == {
            "ref": "${{ github.sha }}",
            "fetch-depth": "0",
            "persist-credentials": "false",
        },
        "checkout must use current reviewed main, full history, and no persisted credentials",
    )

    private_root = selected_step(steps, "Stage private controller root")
    root_body = run_body(private_root)
    for required in (
        "umask 077",
        'runner_temp=$(cd -- "$RUNNER_TEMP" && pwd -P)',
        'root="$runner_temp/aros-protected-start-v2"',
        'mkdir -- "$root"',
        'chmod 700 -- "$root"',
        'printf \'root=%s\\n\' "$root" >> "$GITHUB_OUTPUT"',
    ):
        require(required in root_body, f"private root staging is missing {required!r}")
    require("mkdir -p" not in root_body, "private root creation must be exclusive")

    admission = selected_step(steps, "Admit exact release candidate")
    require("id: admit\n" in admission, "admission step output identity is required")
    require(mapping_block(admission, "env") == {"GH_TOKEN": "${{ github.token }}"},
            "admission helper may receive only its job token explicitly")
    admission_command = flatten_shell(run_body(admission))
    require(
        'python3 -B scripts/toolchain/release-admission-v2.py admit '
        '--output "$root/admission.json" --github-output "$GITHUB_OUTPUT"' in admission_command,
        "admission must invoke the current admit CLI and write its readiness output",
    )

    config = selected_step(steps, "Validate derived Release Please draft configuration")
    require(
        'python3 -B scripts/toolchain/prepare-release-draft-config-v2.py '
        '--output "$PRIVATE_ROOT/draft-config-check.json"' in flatten_shell(run_body(config)),
        "draft config derivation must run before mutations in the private root",
    )
    require(config.index("steps.private-root.outputs.root") >= 0,
            "draft config check must use the private root output")

    cosign = selected_step(steps, "Install pinned Cosign")
    require(f"uses: {COSIGN} # v4.1.2\n" in cosign,
            "Cosign installer must use the approved immutable pin")
    require(mapping_block(cosign, "with") == {"cosign-release": "v3.0.6"},
            "Cosign version must be explicit")

    candidate_create = selected_step(steps, "Create the admitted annotated candidate tag")
    require(
        flatten_shell(run_body(candidate_create)).strip()
        == "set -euo pipefail\n"
        "python3 -B scripts/toolchain/create-compiler-sdk-candidate-v2.py create-tag "
        '--admission "$PRIVATE_ROOT/admission.json" '
        '--runtime-lock "$GITHUB_WORKSPACE/toolchains/aros-tools-runtime-v1.json" '
        '--runtime-directory "$PRIVATE_ROOT/runtime" '
        '--runtime-interface "$PRIVATE_ROOT/runtime-interface.json" '
        '--output "$PRIVATE_ROOT/tag.json"',
        "tag creation must use the current candidate-helper CLI and exact locked inputs",
    )
    require(mapping_block(candidate_create, "env") == {
        "GH_TOKEN": "${{ github.token }}",
        "PRIVATE_ROOT": "${{ steps.private-root.outputs.root }}",
    }, "tag creation must use only the job token and staged private root")

    release = selected_step(steps, "Create the admitted private Release Please draft")
    require(f"uses: {RELEASE_PLEASE} # v5.0.0\n" in release,
            "Release Please action must use the approved immutable pin")
    require(mapping_block(release, "with") == {
        "token": "${{ github.token }}",
        "config-file": "toolchains/release-please-draft-config-v2.json",
        "manifest-file": ".release-please-manifest.json",
        "target-branch": "main",
        "skip-github-release": "false",
        "skip-github-pull-request": "true",
        "skip-labeling": "true",
    }, "draft action must use only its fixed repository config, exact token, and three controls")
    require("draft-config-check.json" not in release,
            "private derived config output must never be passed to the Release Please action")

    bind = selected_step(steps, "Bind the private draft to the admitted tag")
    require(
        flatten_shell(run_body(bind)).strip()
        == "set -euo pipefail\n"
        "python3 -B scripts/toolchain/create-compiler-sdk-candidate-v2.py bind-draft "
        '--admission "$PRIVATE_ROOT/admission.json" '
        '--runtime-lock "$GITHUB_WORKSPACE/toolchains/aros-tools-runtime-v1.json" '
        '--runtime-directory "$PRIVATE_ROOT/runtime" '
        '--runtime-interface "$PRIVATE_ROOT/runtime-interface.json" '
        '--output "$PRIVATE_ROOT/draft.json" --tag "$PRIVATE_ROOT/tag.json"',
        "draft binding must use the exact candidate-helper CLI and tag identity",
    )
    bind_env = mapping_block(bind, "env")
    for key, value in {
        "GH_TOKEN": "${{ github.token }}",
        "PRIVATE_ROOT": "${{ steps.private-root.outputs.root }}",
        "RP_CREATED": "${{ steps.release-please.outputs.release_created }}",
        "RP_TAG": "${{ steps.release-please.outputs.tag_name }}",
        "RP_SHA": "${{ steps.release-please.outputs.sha }}",
        "RP_VERSION": "${{ steps.release-please.outputs.version }}",
        "RP_ID": "${{ steps.release-please.outputs.id }}",
    }.items():
        require(bind_env.get(key) == value, f"draft-binding input {key} must use its real action output")
    require(set(bind_env) == {
        "GH_TOKEN", "PRIVATE_ROOT", "RP_CREATED", "RP_TAG", "RP_SHA", "RP_VERSION", "RP_ID"
    }, "draft binding must not add an alternate output or credential")

    construct = selected_step(steps, "Construct the unsigned compiler and SDK start record")
    require(
        flatten_shell(run_body(construct)).strip()
        == "set -euo pipefail\n"
        "python3 -B scripts/toolchain/construct-compiler-sdk-start-v2.py "
        '--admission "$PRIVATE_ROOT/admission.json" '
        '--tag "$PRIVATE_ROOT/tag.json" '
        '--draft "$PRIVATE_ROOT/draft.json" '
        '--runtime-lock "$GITHUB_WORKSPACE/toolchains/aros-tools-runtime-v1.json" '
        '--runtime-directory "$PRIVATE_ROOT/runtime" '
        '--runtime-interface "$PRIVATE_ROOT/runtime-interface.json" '
        '--output "$PRIVATE_ROOT/compiler-sdk-release-start-v2.json"',
        "record construction must use the current constructor CLI and bound inputs",
    )

    capture = selected_step(steps, "Capture record path and pre-sign digest")
    capture_body = run_body(capture)
    require("sha256sum -- \"$record_path\"" in capture_body,
            "record digest must be captured before signing")
    require("printf 'path=%s\\nsha256=%s\\n' \"$record_path\" \"$record_sha256\" >> \"$GITHUB_OUTPUT\"" in capture_body,
            "record path and pre-sign digest must be exposed as step outputs")

    attestation = selected_step(steps, "Attest the start record with build provenance")
    require(f"uses: {ATTEST} # v4.1.1\n" in attestation,
            "build provenance action must use the approved immutable pin")
    require(mapping_block(attestation, "with") == {
        "subject-path": "${{ steps.record.outputs.path }}",
        "push-to-registry": "false",
        "create-storage-record": "false",
    }, "attestation subject must be the captured start record")

    seal = selected_step(steps, "Seal the exact record and attestation bundle")
    require(mapping_block(seal, "env") == {
        "PRIVATE_ROOT": "${{ steps.private-root.outputs.root }}",
        "RECORD_PATH": "${{ steps.record.outputs.path }}",
        "RECORD_SHA256": "${{ steps.record.outputs.sha256 }}",
        "BUNDLE_PATH": "${{ steps.signature.outputs.bundle-path }}",
    }, "sealer inputs must bind the pre-sign digest and signer bundle outputs")
    require(
        flatten_shell(run_body(seal)).strip()
        == "set -euo pipefail\n"
        "python3 -B scripts/toolchain/seal-compiler-sdk-start-v2.py "
        '--record "$RECORD_PATH" --bundle "$BUNDLE_PATH" '
        '--expected-record-sha256 "$RECORD_SHA256" '
        '--output-directory "$PRIVATE_ROOT/retained"',
        "sealer must retain the exact signed subject and bundle in its closed directory",
    )

    upload = selected_step(steps, "Upload only the sealed start transport")
    require(f"uses: {UPLOAD} # v7.0.1\n" in upload,
            "artifact upload must use the approved immutable pin")
    require(mapping_block(upload, "with") == {
        "name": "compiler-sdk-release-start-v2-${{ github.run_id }}-${{ github.run_attempt }}",
        "path": "${{ steps.private-root.outputs.root }}/retained/",
        "if-no-files-found": "error",
        "retention-days": "90",
        "overwrite": "false",
    }, "artifact upload must be bounded to the exact sealed closure")

    uses = [line.strip() for line in text.splitlines() if line.lstrip().startswith("uses:")]
    expected_uses = [
        f"uses: {CHECKOUT} # v7.0.1",
        f"uses: {COSIGN} # v4.1.2",
        f"uses: {RELEASE_PLEASE} # v5.0.0",
        f"uses: {ATTEST} # v4.1.1",
        f"uses: {UPLOAD} # v7.0.1",
    ]
    require(uses == expected_uses, "template must contain only the five approved pinned actions")

    forbidden = (
        "continue-on-error:",
        "always()",
        "failure()",
        "|| true",
        "sleep ",
        "retry",
        "workflow_dispatch:",
        "repository_dispatch:",
        "actions/create-github-app-token",
        "secrets.",
        "GH_AUTH_TOKEN",
        "GOVERNANCE_TOKEN",
        "gh workflow run",
        "gh release",
        "dispatches",
        "config-file: ${{ steps.private-root.outputs.root }}",
    )
    for marker in forbidden:
        require(marker not in text, f"template contains forbidden alternate path {marker!r}")


class ProtectedStartTemplateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = TEMPLATE.read_text(encoding="utf-8")

    def test_template_is_inactive_at_the_exact_future_caller_path(self) -> None:
        self.assertEqual(TEMPLATE.relative_to(ROOT).as_posix(), TEMPLATE_RELATIVE)
        self.assertFalse(ACTIVE.exists(), f"active workflow unexpectedly exists: {ACTIVE_RELATIVE}")
        for path in (ROOT / ".github/workflows").glob("*.yml"):
            self.assertNotIn(TEMPLATE_RELATIVE, path.read_text(encoding="utf-8"))

    def test_template_satisfies_the_static_policy(self) -> None:
        validate_template(self.text)

    def test_policy_rejects_effective_mutation_counterprobes(self) -> None:
        mutations = [
            ("remove ready guard", READY_GUARD, "if: success()"),
            ("wrong reviewed source ref", "ref: ${{ github.sha }}", "ref: ${{ github.event.workflow_run.head_sha }}"),
            ("wrong source branch", "github.event.workflow_run.head_branch == 'main'", "github.event.workflow_run.head_branch == 'release'"),
            ("local derived config passed to action", "config-file: toolchains/release-please-draft-config-v2.json", "config-file: ${{ steps.private-root.outputs.root }}/draft-config-check.json"),
            ("release creation disabled", "skip-github-release: false", "skip-github-release: true"),
            ("pull request phase enabled", "skip-github-pull-request: true", "skip-github-pull-request: false"),
            ("label mutation enabled", "skip-labeling: true", "skip-labeling: false"),
            ("alternate workflow token", "GH_TOKEN: ${{ github.token }}", "GH_TOKEN: ${{ secrets.PAT }}"),
            ("broader pull request permission", "pull-requests: read", "pull-requests: write"),
            ("floating runner", "runs-on: ubuntu-24.04", "runs-on: ubuntu-latest"),
            ("floating attestation action", ATTEST, "actions/attest-build-provenance@main"),
            ("registry push enabled", "push-to-registry: false", "push-to-registry: true"),
            ("storage record creation enabled", "create-storage-record: false", "create-storage-record: true"),
            ("post-sign digest substitution", "RECORD_SHA256: ${{ steps.record.outputs.sha256 }}", "RECORD_SHA256: ${{ steps.signature.outputs.bundle-path }}"),
            ("upload unsealed private root", "path: ${{ steps.private-root.outputs.root }}/retained/", "path: ${{ steps.private-root.outputs.root }}/"),
            ("artifact overwrite enabled", "overwrite: false", "overwrite: true"),
            ("cancellable concurrency", "cancel-in-progress: false", "cancel-in-progress: true"),
            ("manual event added", "types: [completed]", "types: [completed]\n  workflow_dispatch:"),
        ]
        for name, old, new in mutations:
            with self.subTest(mutation=name):
                self.assertIn(old, self.text)
                changed = self.text.replace(old, new, 1)
                self.assertNotEqual(changed, self.text)
                with self.assertRaises(PolicyViolation):
                    validate_template(changed)

        for name, option in (
            ("registry push option missing", "push-to-registry: false\n"),
            ("storage record option missing", "create-storage-record: false\n"),
        ):
            with self.subTest(mutation=name):
                self.assertIn(option, self.text)
                changed = self.text.replace(option, "", 1)
                with self.assertRaises(PolicyViolation):
                    validate_template(changed)

        bypass = self.text.replace(
            "      - name: Install pinned Cosign\n",
            "      - name: Install pinned Cosign\n        continue-on-error: true\n",
            1,
        )
        with self.assertRaises(PolicyViolation):
            validate_template(bypass)


if __name__ == "__main__":
    unittest.main()
