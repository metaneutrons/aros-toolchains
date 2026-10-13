#!/usr/bin/env python3
"""Audit the non-publishing compiler/SDK V2 workflow and its selected inputs.

The checks intentionally use only the Python standard library.  Workflow
policy is inspected from the repository documents and then exercised against
small in-memory mutations so widening the diagnostic graph fails closed.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tempfile
import tomllib
import unittest
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = ".github/workflows/toolchain-release.yml"
ACTION = ".github/actions/materialize-development-aros-tools/action.yml"
RUNTIME_ACTION = ".github/actions/verify-aros-tools-runtime-transport/action.yml"
INTERFACE_ACTION = ".github/actions/check-v2-runtime-interface/action.yml"
INTERFACE_HELPER = "scripts/toolchain/check-v2-runtime-interface.py"
PREPARE = "scripts/toolchain/prepare-compiler-sdk-inputs-v2.py"
QUALIFY = "scripts/toolchain/qualify-compiler-sdk-lane-v2.sh"
MATRIX = "scripts/toolchain/select-release-matrix-v2.py"
ROUTE = "scripts/toolchain/select-compiler-sdk-route-v2.py"
CACHE_TRANSPORT = "scripts/toolchain/cache-archive-transport.py"
SELECTION = "toolchains/compiler-sdk-ci-selection-v2.json"
EXECUTOR = "toolchains/producer-executor-v1.toml"
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
SAFE_GROUP = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?\Z")
SAFE_SDK = re.compile(r"[a-z0-9](?:[-._+a-z0-9]{0,94}[a-z0-9])?\Z")


class PolicyViolation(AssertionError):
    """A V2 workflow, helper or selected input violates its closed policy."""


class Documents:
    """Read repository files with optional, non-mutating test overrides."""

    def __init__(self, overrides: dict[str, bytes | None] | None = None) -> None:
        self.overrides = overrides or {}

    def read(self, relative: str) -> bytes:
        path = PurePosixPath(relative)
        if path.is_absolute() or ".." in path.parts or "\\" in relative:
            raise PolicyViolation(f"unsafe repository reference: {relative}")
        if relative in self.overrides:
            value = self.overrides[relative]
            if value is None:
                raise PolicyViolation(f"required repository file is missing: {relative}")
            return value
        candidate = ROOT.joinpath(*path.parts)
        if candidate.is_symlink() or not candidate.is_file():
            raise PolicyViolation(f"required repository file is missing or linked: {relative}")
        try:
            return candidate.read_bytes()
        except OSError as error:
            raise PolicyViolation(f"cannot read {relative}: {error}") from error

    def text(self, relative: str) -> str:
        try:
            return self.read(relative).decode("utf-8")
        except UnicodeDecodeError as error:
            raise PolicyViolation(f"{relative} is not UTF-8") from error

    def json(self, relative: str) -> Any:
        def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise PolicyViolation(f"{relative} has duplicate JSON field {key!r}")
                result[key] = value
            return result

        try:
            return json.loads(self.read(relative), object_pairs_hook=unique_object)
        except PolicyViolation:
            raise
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise PolicyViolation(f"{relative} is not valid UTF-8 JSON: {error}") from error

    def toml(self, relative: str) -> dict[str, Any]:
        try:
            value = tomllib.loads(self.text(relative))
        except (tomllib.TOMLDecodeError, UnicodeDecodeError) as error:
            raise PolicyViolation(f"{relative} is not valid TOML: {error}") from error
        if not isinstance(value, dict):
            raise PolicyViolation(f"{relative} must be a TOML table")
        return value

    def set_text(self, relative: str, value: str) -> None:
        self.overrides[relative] = value.encode("utf-8")

    def set_json(self, relative: str, value: Any) -> None:
        self.set_text(relative, json.dumps(value, indent=2) + "\n")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PolicyViolation(message)


def workflow_job(workflow: str, name: str) -> str:
    jobs_header = re.search(r"(?m)^jobs:[ \t]*$", workflow)
    if jobs_header is None:
        raise PolicyViolation("workflow has no jobs section")
    jobs_text = workflow[jobs_header.end() :]
    matches = list(
        re.finditer(r"(?m)^  ([A-Za-z0-9][A-Za-z0-9_-]*):[ \t]*$", jobs_text)
    )
    selected = [match for match in matches if match.group(1) == name]
    if len(selected) != 1:
        raise PolicyViolation(f"workflow must define exactly one {name} job")
    start = selected[0].start()
    following = next((match.start() for match in matches if match.start() > start), len(jobs_text))
    return jobs_text[start:following]


def job_names(workflow: str) -> list[str]:
    jobs_header = re.search(r"(?m)^jobs:[ \t]*$", workflow)
    if jobs_header is None:
        raise PolicyViolation("workflow has no jobs section")
    return re.findall(
        r"(?m)^  ([A-Za-z0-9][A-Za-z0-9_-]*):[ \t]*$",
        workflow[jobs_header.end() :],
    )


def workflow_step(job: str, name: str) -> str:
    marker = f"      - name: {name}\n"
    start = job.find(marker)
    if start < 0:
        raise PolicyViolation(f"required workflow step is missing: {name}")
    following = re.search(r"(?m)^      - ", job[start + len(marker) :])
    end = start + len(marker) + following.start() if following else len(job)
    return job[start:end]


def composite_run_script(action: str) -> str:
    match = re.search(
        r"(?m)^      run: \|\n((?:^        .*\n|^        \n)*)",
        action,
    )
    if match is None:
        raise PolicyViolation("runtime interface action has no bounded composite shell")
    return "\n".join(line[8:] for line in match.group(1).splitlines()) + "\n"


def require_read_only_job(job: str, name: str) -> None:
    lines = job.splitlines()
    permissions: list[str] | None = None
    for index, line in enumerate(lines):
        if line == "    permissions:":
            if permissions is not None:
                raise PolicyViolation(f"{name} declares permissions more than once")
            permissions = []
            cursor = index + 1
            while cursor < len(lines) and lines[cursor].startswith("      "):
                if not lines[cursor].lstrip().startswith("#"):
                    permissions.append(lines[cursor].strip())
                cursor += 1
            break
    expected_permissions = ["contents: read"]
    if name in {"v2-prepare", "v2-runtimes"}:
        expected_permissions += ["attestations: read"]
    if name in {"v2-qualify", "v2-build", "v2-sdk"}:
        expected_permissions += ["actions: read", "id-token: write", "attestations: write"]
    if name == "v2-readback":
        expected_permissions += ["actions: read", "id-token: write", "attestations: write"]
    if permissions != expected_permissions:
        raise PolicyViolation(f"{name} permissions must exactly match its non-publishing job scope")
    if re.search(r"(?m)^\s*environment:", job):
        raise PolicyViolation(f"{name} must not use a publication environment")
    permitted_reader_token = (
        "GH_TOKEN: ${{ github.token }}"
        if name in {"v2-prepare", "v2-sdk", "v2-readback"}
        else ""
    )
    inspected_job = job.replace(permitted_reader_token, "") if permitted_reader_token else job
    if re.search(r"\bsecrets\.", inspected_job) or "GH_TOKEN" in inspected_job or "GITHUB_TOKEN" in inspected_job:
        raise PolicyViolation(f"{name} must not request credentials or secrets")
    if re.search(r"(?im)^\s*(?:gh\s+release|git\s+(?:tag|push)\b)", job):
        raise PolicyViolation(f"{name} must not publish a release or create/push a tag")
    for match in re.finditer(r"(?m)^\s*uses:\s*([^\s]+)", job):
        action = match.group(1)
        if action.startswith("./.github/actions/"):
            continue
        allowed = {
            "actions/checkout",
            "actions/download-artifact",
            "actions/upload-artifact",
        }
        if name == "v2-readback" and action == "actions/attest-build-provenance@0f67c3f4856b2e3261c31976d6725780e5e4c373":
            continue
        name_and_ref = action.split("@", 1)
        if (
            len(name_and_ref) != 2
            or name_and_ref[0] not in allowed
            or HEX40.fullmatch(name_and_ref[1]) is None
        ):
            raise PolicyViolation(f"{name} uses an unapproved or unpinned action: {action}")


def read_relative_toolchain_file(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise PolicyViolation(f"{label} must be a toolchains-relative JSON file")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.parts[:1] != ("toolchains",)
        or path.suffix != ".json"
        or ".." in path.parts
        or "\\" in value
        or path.as_posix() != value
    ):
        raise PolicyViolation(f"{label} must be a canonical toolchains-relative JSON file")
    return value


def validate_selected_inputs(documents: Documents) -> dict[str, int]:
    selection = documents.json(SELECTION)
    require(
        isinstance(selection, dict)
        and set(selection) == {"schema", "source_commit", "tools_commit", "groups", "sdks"},
        "selection has missing or unknown fields",
    )
    require(
        selection["schema"] == "aros-compiler-sdk-ci-selection-v2",
        "selection has an unsupported schema",
    )
    source_commit = selection["source_commit"]
    tools_commit = selection["tools_commit"]
    require(
        isinstance(source_commit, str)
        and HEX40.fullmatch(source_commit) is not None
        and source_commit != "0" * 40,
        "selection source pin must be a nonzero lowercase Git object ID",
    )
    require(
        isinstance(tools_commit, str)
        and HEX40.fullmatch(tools_commit) is not None
        and tools_commit != "0" * 40,
        "selection tools pin must be a nonzero lowercase Git object ID",
    )

    groups = selection["groups"]
    sdks = selection["sdks"]
    require(isinstance(groups, list) and groups, "selection must contain compiler groups")
    require(isinstance(sdks, list) and sdks, "selection must contain SDK products")
    executor = documents.toml(EXECUTOR)
    require(executor.get("schema_version") == 2, "executor manifest must use schema version 2")
    require(
        executor.get("contract_id") == "aros-toolchain-producer-v1"
        and executor.get("contract_path") == "contracts/toolchain-producer-v1.toml"
        and isinstance(executor.get("contract_sha256"), str)
        and HEX64.fullmatch(executor["contract_sha256"]) is not None,
        "executor contract pin or manifest digest is malformed",
    )
    require(
        executor.get("tools_commit") == tools_commit,
        "selection tools pin differs from the executor manifest",
    )
    executor_groups = executor.get("groups")
    require(
        isinstance(executor_groups, list) and len(executor_groups) == len(groups),
        "executor groups differ from the selected compiler groups",
    )

    profiles_by_group: dict[str, set[str]] = {}
    selected_ids: set[str] = set()
    for index, group in enumerate(groups):
        require(
            isinstance(group, dict)
            and set(group) == {"id", "source_lock", "profiles", "ports_lock"},
            f"selection group {index} has missing or unknown fields",
        )
        group_id = group["id"]
        require(
            isinstance(group_id, str)
            and SAFE_GROUP.fullmatch(group_id) is not None
            and group_id not in selected_ids,
            f"selection group {index} has an invalid or duplicate ID",
        )
        selected_ids.add(group_id)
        source_lock_path = read_relative_toolchain_file(
            group["source_lock"], f"{group_id} source lock"
        )
        profiles_path = read_relative_toolchain_file(group["profiles"], f"{group_id} profiles")
        ports_path = read_relative_toolchain_file(group["ports_lock"], f"{group_id} ports lock")
        source_lock = documents.json(source_lock_path)
        profiles = documents.json(profiles_path)
        ports = documents.json(ports_path)
        require(
            isinstance(source_lock, dict)
            and source_lock.get("schema") in {
                "aros-toolchain-source-lock-v2",
                "aros-toolchain-source-lock-v3",
            }
            and isinstance(source_lock.get("sources"), list),
            f"{group_id} source lock has an unsupported schema",
        )
        require(
            isinstance(profiles, dict)
            and profiles.get("schema") in {
                "aros-toolchain-profiles-v1",
                "aros-toolchain-profiles-v2",
            }
            and profiles.get("upstream_commit") == source_commit
            and isinstance(profiles.get("profiles"), list),
            f"{group_id} profiles do not match the selected source pin",
        )
        require(
            isinstance(ports, dict)
            and ports.get("schema") == "aros-toolchain-compatibility-ports-v3"
            and ports.get("upstream_commit") == source_commit
            and isinstance(ports.get("inputs"), list),
            f"{group_id} ports lock does not match the selected source pin",
        )
        profile_names = {
            profile.get("name")
            for profile in profiles["profiles"]
            if isinstance(profile, dict) and isinstance(profile.get("name"), str)
        }
        require(
            len(profile_names) == len(profiles["profiles"]),
            f"{group_id} profiles contain malformed or duplicate names",
        )
        profiles_by_group[group_id] = profile_names

        executor_group = executor_groups[index]
        require(
            isinstance(executor_group, dict)
            and executor_group.get("id") == group_id
            and executor_group.get("source_lock") == source_lock_path
            and executor_group.get("profiles") == profiles_path,
            f"executor group {group_id} references differ from the selection",
        )
        for field, path in (
            ("source_lock_sha256", source_lock_path),
            ("profiles_sha256", profiles_path),
        ):
            expected = executor_group.get(field)
            require(
                isinstance(expected, str)
                and HEX64.fullmatch(expected) is not None
                and hashlib.sha256(documents.read(path)).hexdigest() == expected,
                f"executor {group_id} {field} differs from its selected document digest",
            )

    sdk_ids: set[str] = set()
    for index, sdk in enumerate(sdks):
        require(
            isinstance(sdk, dict)
            and set(sdk)
            == {"id", "version", "source_date_epoch", "source_preset", "compiler_profiles"},
            f"selection SDK {index} has missing or unknown fields",
        )
        sdk_id = sdk["id"]
        require(
            isinstance(sdk_id, str)
            and SAFE_SDK.fullmatch(sdk_id) is not None
            and sdk_id not in sdk_ids,
            f"selection SDK {index} has an invalid or duplicate ID",
        )
        sdk_ids.add(sdk_id)
        require(sdk["version"] == "0.1.0", f"SDK {sdk_id} must keep its selected version")
        require(
            isinstance(sdk["source_date_epoch"], int)
            and not isinstance(sdk["source_date_epoch"], bool)
            and sdk["source_date_epoch"] > 0,
            f"SDK {sdk_id} has an invalid source date epoch",
        )
        require(
            isinstance(sdk["source_preset"], str) and sdk["source_preset"],
            f"SDK {sdk_id} has no source-owned preset",
        )
        references = sdk["compiler_profiles"]
        require(isinstance(references, list) and references, f"SDK {sdk_id} has no compiler profile")
        seen_references: set[tuple[str, str]] = set()
        for reference in references:
            require(
                isinstance(reference, dict)
                and set(reference) == {"group_id", "profile"}
                and isinstance(reference.get("group_id"), str)
                and isinstance(reference.get("profile"), str),
                f"SDK {sdk_id} has a malformed compiler profile reference",
            )
            key = (reference["group_id"], reference["profile"])
            require(key not in seen_references, f"SDK {sdk_id} repeats a compiler profile")
            seen_references.add(key)
            require(
                key[0] in profiles_by_group and key[1] in profiles_by_group[key[0]],
                f"SDK {sdk_id} references a profile outside its selected group",
            )
    return {"group_count": len(groups), "sdk_count": len(sdks)}


def validate_runtime_interface_action(action: str) -> str:
    require(
        "name: Check the selected V2 runtime interface" in action
        and "using: composite" in action
        and action.count("    - name:") == 1
        and "      shell: bash" in action
        and "set -euo pipefail" in action
        and not re.search(r"(?m)^\s*if:", action),
        "runtime interface action must execute as one unconditional strict composite step",
    )
    for binding in (
        "RUNTIME_KIND: ${{ inputs.runtime-kind }}",
        "RUNTIME_ROOT: ${{ inputs.root }}",
        "TOOLS_SOURCE: ${{ inputs.tools-source }}",
        "TOOLS_COMMIT: ${{ inputs.tools-commit }}",
        "INTERFACE_OUTPUT: ${{ inputs.output }}",
        "RUNTIME_LOCK: ${{ inputs.lock }}",
        '[[ "$TOOLS_COMMIT" =~ ^[0-9a-f]{40}$ ]]',
        'test "$(git -C "$TOOLS_SOURCE" rev-parse HEAD)" = "$TOOLS_COMMIT"',
        'test -z "$(git -C "$TOOLS_SOURCE" status --porcelain)"',
        'git -C "$TOOLS_SOURCE" show HEAD:Cargo.toml',
        'source_version=$(git -C "$TOOLS_SOURCE" show HEAD:Cargo.toml |',
        'test "$(cat "$RUNTIME_ROOT/DEVELOPMENT_RUNTIME.txt")" = "development-only tools commit: $TOOLS_COMMIT"',
        'runtime_sha=$(awk',
        'if (count != 1) exit 1; print value',
        'expected_version=$(jq -er --arg commit "$TOOLS_COMMIT" --arg version "$source_version"',
        'if .source_commit == $commit and .version == $version then .version',
        'else error("Released runtime differs from the selected tools source") end',
        '[.files[] | select(.path == "bin/aros")] |',
        'if length == 1 then .[0].sha256 else error("Runtime has no unique CLI entry") end',
        "runtime_prefix=${RUNTIME_ROOT%/}",
        'case "$INTERFACE_OUTPUT" in',
        '"$runtime_prefix"|"$runtime_prefix"/*)',
        "Interface-only receipts must remain outside the runtime root.",
        'python3 -B "$GITHUB_WORKSPACE/scripts/toolchain/check-v2-runtime-interface.py"',
        '--aros "$RUNTIME_ROOT/bin/aros" --aros-sha256 "$runtime_sha"',
        '--expected-version "$expected_version" --output "$INTERFACE_OUTPUT"',
        'test -z "$(git -C "$TOOLS_SOURCE" status --porcelain)"',
    ):
        require(binding in action, f"runtime interface action lost required binding: {binding}")
    cases = re.search(
        r'(?s)case "\$RUNTIME_KIND" in\s*development\)\s*(.*?)\s*;;\s*released\)\s*(.*?)\s*;;\s*\*\)\s*(.*?)\s*;;\s*esac',
        action,
    )
    require(
        cases is not None
        and "exit 1" in cases.group(3)
        and "exit 0" not in cases.group(3),
        "runtime interface action must close development/released routes and reject unknown kinds",
    )
    require(
        not re.search(r"\b(?:GH_TOKEN|GITHUB_TOKEN|secrets\.|gh\s+auth)\b", action)
        and not re.search(r"(?m)^\s*(?:gh\s+release|git\s+(?:tag|push)\b)", action),
        "runtime interface action must not bypass authentication or publish",
    )
    return composite_run_script(action)


def interface_step_inputs(step: str) -> list[tuple[str, str]]:
    return re.findall(r"(?m)^          ([a-z][a-z-]*): (.+)$", step)


def require_interface_upload(step: str, expected_name: str, expected_path: str) -> None:
    require(
        "uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a" in step
        and interface_step_inputs(step) == [
            ("name", expected_name),
            ("path", expected_path),
            ("if-no-files-found", "error"),
            ("retention-days", "7"),
        ],
        "runtime interface receipt must be retained as a separate bounded interface-only artifact",
    )


def validate_v2_policy(documents: Documents) -> dict[str, int]:
    workflow = documents.text(WORKFLOW)
    action = documents.text(ACTION)
    runtime_action = documents.text(RUNTIME_ACTION)
    interface_action = documents.text(INTERFACE_ACTION)
    documents.read(INTERFACE_HELPER)
    validate_runtime_interface_action(interface_action)
    route_script = documents.text(ROUTE)
    prepare_script = documents.text(PREPARE)
    qualify_script = documents.text(QUALIFY)
    matrix_script = documents.text(MATRIX)

    require("- qualify-v2" in workflow, "workflow_dispatch must expose qualify-v2 mode")
    names = job_names(workflow)
    v2_names = {name for name in names if name.startswith("v2-")}
    expected_names = {"v2-prepare", "v2-sources", "v2-runtimes", "v2-qualify", "v2-build", "v2-sdk", "v2-readback"}
    require(v2_names == expected_names, "workflow V2 diagnostic job set is not closed")
    prepare = workflow_job(workflow, "v2-prepare")
    sources = workflow_job(workflow, "v2-sources")
    qualify = workflow_job(workflow, "v2-qualify")
    runtimes = workflow_job(workflow, "v2-runtimes")
    builds = workflow_job(workflow, "v2-build")
    sdk = workflow_job(workflow, "v2-sdk")
    readback = workflow_job(workflow, "v2-readback")
    for name, job in (("v2-prepare", prepare), ("v2-sources", sources),
                      ("v2-runtimes", runtimes), ("v2-qualify", qualify),
                      ("v2-build", builds), ("v2-sdk", sdk), ("v2-readback", readback)):
        require_read_only_job(job, name)
        require(re.search(r"(?m)^    timeout-minutes: [1-9][0-9]*$", job) is not None,
                f"{name} must have a bounded job timeout")

    require(
        "if: github.event_name == 'push' || (github.event_name == 'workflow_dispatch' && (inputs.mode == 'qualify-v2' || inputs.mode == 'qualify-v2-full'))" in prepare,
        "V2 preparation must admit only pushes and the two explicit manual qualification modes",
    )
    selection_step = prepare.split("      - id: selection\n", 1)[1].split("      - ", 1)[0]
    require(
        "name: Authenticate the exact route before source checkout or runtime materialization" in selection_step
        and "GH_TOKEN: ${{ github.token }}" in selection_step
        and 'REQUESTED_MODE: ${{ inputs.mode }}' in selection_step
        and 'REQUESTED_SCOPE: ${{ inputs.scope }}' in selection_step
        and 'REQUESTED_GROUP: ${{ inputs.diagnostic_group }}' in selection_step
        and "select-compiler-sdk-route-v2.py" in selection_step
        and '--event "$GITHUB_EVENT_NAME" --ref-type "$GITHUB_REF_TYPE" --source-ref "$GITHUB_REF"' in selection_step
        and '--repository "$GITHUB_REPOSITORY" --producer-commit "$GITHUB_SHA"' in selection_step
        and '--run-attempt "$GITHUB_RUN_ATTEMPT"' in selection_step
        and '--mode "$REQUESTED_MODE" --scope "$REQUESTED_SCOPE" --group "$REQUESTED_GROUP"' in selection_step
        and '--github-output "$GITHUB_OUTPUT"' in selection_step
        and prepare.index("Authenticate the exact route") < prepare.index("checkout-pinned-recursive-source")
        and prepare.index("Authenticate the exact route") < prepare.index("materialize-development-aros-tools"),
        "V2 must authenticate one closed route before source checkout or runtime materialization",
    )
    documents.read(ROUTE)
    push_route = route_script.split('if args.event == "push":', 1)[1].split("\n    else:", 1)[0]
    manual_route = route_script.split("\n    else:", 1)[1].split("\n    return outputs", 1)[0]
    require(
        "authenticate_tag(args, selection[\"tools_commit\"])" in push_route
        and 'runtime_kind="released"' in push_route
        and 'full_matrix="true"' in push_route
        and 'runtime_kind="development"' in manual_route
        and 'full_matrix=str(full).lower()' in manual_route
        and 'release_id=f"toolchain-dev-{args.producer_commit[:12]}"' in manual_route
        and 'args.event == "workflow_dispatch"' in manual_route
        and 'args.run_attempt == "1"' in route_script
        and 'args.mode == args.scope == args.group == ""' in route_script
        and '("qualify-v2", "linux-x86_64")' in route_script
        and '("qualify-v2-full", "full")' in route_script
        and 'not full or args.group == ""' in route_script
        and 'runtime.get("source_commit") == tools_commit' in route_script
        and 'return {"release_id": name' in route_script
        and 'absence.returncode != 0 and statuses == ["404"]' in route_script,
        "route selector must close push and manual identities before writing route outputs",
    )
    require(
        'release_id: ${{ steps.selection.outputs.release_id }}' in prepare
        and 'runtime_kind: ${{ steps.selection.outputs.runtime_kind }}' in prepare
        and 'full_matrix: ${{ steps.selection.outputs.full_matrix }}' in prepare
        and 'tag_object: ${{ steps.selection.outputs.tag_object }}' in prepare
        and 'tag_epoch: ${{ steps.selection.outputs.tag_epoch }}' in prepare,
        "authenticated release identity and route outputs must be exposed by V2 preparation",
    )
    for block_name, block, kind_ref, host_ref in (
        ("v2-prepare", prepare, "steps.selection.outputs.runtime_kind", "linux-x86_64"),
        ("v2-runtimes", runtimes, "needs.v2-prepare.outputs.runtime_kind", "${{ matrix.host }}"),
    ):
        require(
            f"if: {kind_ref} == 'development'" in block
            and "uses: ./.github/actions/materialize-development-aros-tools" in block
            and f"if: {kind_ref} == 'released'" in block
            and "uses: ./.github/actions/materialize-aros-tools-runtime" in block
            and f"host: {host_ref}" in block,
            f"{block_name} must select exactly the route-authenticated development or released runtime",
        )
    require(
        workflow.count("uses: ./.github/actions/verify-aros-tools-runtime-transport") == 7,
        "all seven V2 runtime consumers must use the shared transport verifier",
    )
    for block_name, block in (("v2-prepare", prepare), ("v2-sources", sources),
                              ("v2-runtimes", runtimes), ("v2-qualify", qualify),
                              ("v2-build", builds), ("v2-sdk", sdk), ("v2-readback", readback)):
        require(
            block.count("uses: ./.github/actions/verify-aros-tools-runtime-transport") == 1
            and "root: ${{ runner.temp }}/diagnostic-runtime" in block
            and "runtime-kind:" in block,
            f"{block_name} must reverify its transported selected runtime before use",
        )
    for block_name, block in (("v2-prepare", prepare), ("v2-runtimes", runtimes)):
        verifier = block.index("uses: ./.github/actions/verify-aros-tools-runtime-transport")
        binder = block.find("name: Bind the verified runtime root without fallback")
        require(
            binder > verifier
            and "run: printf 'root=%s/diagnostic-runtime\\n' \"$RUNNER_TEMP\" >> \"$GITHUB_OUTPUT\"" in block,
            f"{block_name} must expose only the route-authenticated runtime root after verification",
        )
    require(
        "include-hidden-files: true" in prepare and "include-hidden-files: true" in runtimes,
        "V2 runtime artifacts must retain hidden metadata through transport",
    )
    require(
        "case \"$RUNTIME_KIND\" in" in runtime_action
        and re.search(
            r"(?s)case \"\$RUNTIME_KIND\" in\s*development\)\s*(.*?)\s*;;\s*released\)\s*(.*?)\s*;;\s*\*\)\s*(.*?)\s*;;\s*esac",
            runtime_action,
        ) is not None,
        "shared runtime transport must have only development, released and rejecting default cases",
    )
    runtime_cases = re.search(
        r"(?s)case \"\$RUNTIME_KIND\" in\s*development\)\s*(.*?)\s*;;\s*released\)\s*(.*?)\s*;;\s*\*\)\s*(.*?)\s*;;\s*esac",
        runtime_action,
    )
    assert runtime_cases is not None
    development_case, released_case, unsupported_case = runtime_cases.groups()
    require(
        'shasum -a 256 -c SHA256SUMS' in development_case
        and 'chmod +x "$RUNTIME_ROOT"/bin/*' in development_case
        and "materialize-aros-tools-runtime.py" not in development_case
        and 'materialize-aros-tools-runtime.py" restore-artifact-modes' in released_case
        and 'materialize-aros-tools-runtime.py" verify' in released_case
        and released_case.count('--lock "$GITHUB_WORKSPACE/$RUNTIME_LOCK" --host "$RUNTIME_HOST" --directory "$RUNTIME_ROOT"') == 2
        and "exit 1" in unsupported_case
        and "exit 0" not in unsupported_case
        and "||" not in runtime_cases.group(0),
        "shared runtime verification must close both kinds independently and reject unknown kinds without fallback",
    )
    interface_prepare = workflow_step(
        prepare, "Check the exact V2 interface before recipe preparation"
    )
    interface_runtimes = workflow_step(
        runtimes, "Check every selected host V2 interface before compiler fan-out"
    )
    require(
        workflow.count("uses: ./.github/actions/check-v2-runtime-interface") == 2,
        "preparation and every native host must run the shared runtime interface check",
    )
    for job_name, block, step, expected_inputs, next_marker in (
        (
            "v2-prepare",
            prepare,
            interface_prepare,
            [
                ("runtime-kind", "${{ steps.selection.outputs.runtime_kind }}"),
                ("root", "${{ steps.runtime.outputs.root }}"),
                ("tools-source", "${{ github.workspace }}/dependencies/aros-tools"),
                ("tools-commit", "${{ steps.selection.outputs.tools_commit }}"),
                ("output", "${{ runner.temp }}/diagnostic-runtime-interface.json"),
            ],
            "- id: matrix",
        ),
        (
            "v2-runtimes",
            runtimes,
            interface_runtimes,
            [
                ("runtime-kind", "${{ needs.v2-prepare.outputs.runtime_kind }}"),
                ("root", "${{ steps.runtime.outputs.root }}"),
                ("tools-source", "${{ github.workspace }}/dependencies/aros-tools"),
                ("tools-commit", "${{ needs.v2-prepare.outputs.tools_commit }}"),
                ("output", "${{ runner.temp }}/diagnostic-native-runtime-interface-${{ matrix.host }}.json"),
            ],
            "name: diagnostic-v2-native-runtime-${{ matrix.host }}",
        ),
    ):
        verifier = block.index("uses: ./.github/actions/verify-aros-tools-runtime-transport")
        binder = block.index("name: Bind the verified runtime root without fallback")
        check = block.index("uses: ./.github/actions/check-v2-runtime-interface")
        require(
            step.count("uses: ./.github/actions/check-v2-runtime-interface") == 1
            and interface_step_inputs(step) == expected_inputs
            and "if:" not in step
            and "continue-on-error:" not in step
            and verifier < binder < check < block.index(next_marker),
            f"{job_name} must run the unconditional interface check after verified transport with exact selected inputs",
        )
    prepare_receipt = workflow_step(prepare, "Retain preparation interface-only evidence")
    native_receipt = workflow_step(runtimes, "Retain selected host interface-only evidence")
    require_interface_upload(
        prepare_receipt,
        "diagnostic-v2-runtime-interface-prepare",
        "${{ runner.temp }}/diagnostic-runtime-interface.json",
    )
    require_interface_upload(
        native_receipt,
        "diagnostic-v2-runtime-interface-${{ matrix.host }}",
        "${{ runner.temp }}/diagnostic-native-runtime-interface-${{ matrix.host }}.json",
    )
    require(
        prepare.index("Check the exact V2 interface before recipe preparation")
        < prepare.index("Retain preparation interface-only evidence")
        < prepare.index("- id: matrix")
        and runtimes.index("Check every selected host V2 interface before compiler fan-out")
        < runtimes.index("Retain selected host interface-only evidence")
        < runtimes.index("name: diagnostic-v2-native-runtime-${{ matrix.host }}")
        and not re.search(r"(?m)^    if: .*full_matrix", runtimes)
        and prepare.count("${{ runner.temp }}/diagnostic-runtime-interface.json") == 2
        and runtimes.count("${{ runner.temp }}/diagnostic-native-runtime-interface-${{ matrix.host }}.json") == 2
        and all("runtime-interface" not in job for job in (sources, qualify, builds, sdk, readback)),
        "interface receipts must remain outside runtime roots and outside later qualification/provenance inputs",
    )
    require("needs: v2-prepare" in sources, "V2 source preparation must depend on V2 preparation")
    require(
        "needs: [v2-prepare, v2-sources, v2-runtimes]" in qualify,
        "V2 qualification must depend on both preparation and verified caches",
    )
    require(
        "matrix: ${{ fromJSON(needs.v2-prepare.outputs.matrix) }}" in qualify,
        "V2 qualification matrix must be derived from validated plan output",
    )
    require(
        "uses: ./.github/actions/retain-sdk-owner-payload-v2" in qualify
        and "'[.[].id] | sort | if length > 0 and . == unique then . else error(\"invalid SDK lane selection\") end'" in qualify
        and '"$RUNNER_TEMP/diagnostic-lane/sdk-selections.jsonl"' in qualify
        and "sdk-ids: ${{ steps.qualify.outputs.sdk-ids }}" in qualify
        and "operation-root: ${{ runner.temp }}/diagnostic-lane" in qualify
        and "job-name: Compiler A/B and SDK (${{ matrix.group_id }}, ${{ matrix.host }}, ${{ matrix.profile }})" in qualify
        and qualify.index("qualify-compiler-sdk-lane-v2.sh") < qualify.index("uses: ./.github/actions/retain-sdk-owner-payload-v2"),
        "successful SDK origin must bind this exact original owner and plan-selected SDK set",
    )
    require(
        "outputs:\n      matrix: ${{ steps.matrix.outputs.verify_matrix }}" in prepare,
        "V2 job output must come from the release-plan scheduler",
    )

    plan = workflow_job(workflow, "plan")
    require(
        "if: github.event_name == 'workflow_dispatch' && inputs.mode == 'produce'" in plan
        and "name: Reject legacy publication during the V2 compiler and SDK migration" in plan
        and "if: github.event_name == 'push'" in plan
        and "exit 1" in plan,
        "legacy plan must stay manual-produce only while retaining its unreachable old tag rejection gate",
    )
    publisher = workflow_job(workflow, "draft-release")
    require(
        "needs: [plan, compatibility]" in publisher
        and "if: github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')" in publisher,
        "the V1 tag publisher must remain downstream of the manual-only legacy plan",
    )
    require(
        re.search(
            r"(?ms)^      scope:\n.*?^        options:\n          - linux-x86_64\n          - linux\n          - full\n",
            workflow,
        ) is not None,
        "existing manual release scopes must remain available",
    )
    for name in names:
        if name in expected_names:
            continue
        job = workflow_job(workflow, name)
        require(
            not re.search(r"\bneeds:\s*(?:\[[^\]]*\bv2-|v2-)", job),
            f"legacy job {name} must not consume diagnostic job outputs",
        )

    require(
        "prepare-compiler-sdk-inputs-v2.py" in prepare
        and "select-release-matrix-v2.py" in prepare
        and '--event "$SELECTED_EVENT" --scope "$SELECTED_SCOPE"' in prepare
        and 'FULL_QUALIFICATION: ${{ steps.selection.outputs.full_qualification }}' in prepare
        and 'if [[ "$FULL_QUALIFICATION" == true ]]; then' in prepare
        and 'group_arguments+=(--full-qualification)' in prepare,
        "V2 matrix preparation must use the authenticated event and explicit native-plan full qualification",
    )
    require(
        "if: inputs.mode == 'qualify-v2'" in qualify
        and "if: needs.v2-prepare.outputs.full_matrix == 'true'" in builds
        and "if: needs.v2-prepare.outputs.full_matrix == 'true'" in sdk
        and "build_matrix: ${{ steps.matrix.outputs.build_matrix }}" in prepare
        and "matrix: ${{ fromJSON(needs.v2-prepare.outputs.build_matrix) }}" in builds
        and "uses: ./.github/actions/build-native-lane-v2" in builds
        and "copy: ${{ matrix.copy }}" in builds
        and "root: ${{ runner.temp }}/native-lane-${{ matrix.copy }}" in builds
        and "job-name: Native compiler (${{ matrix.group_id }}, ${{ matrix.host }}, ${{ matrix.profile }}, ${{ matrix.copy }})" in builds,
        "full native compiler copies must execute in distinct original owning jobs and roots",
    )
    require(
        'release_id: ${{ steps.selection.outputs.release_id }}' in prepare
        and 'SELECTED_RELEASE_ID: ${{ needs.v2-prepare.outputs.release_id }}' in builds
        and 'SELECTED_RELEASE_ID: ${{ needs.v2-prepare.outputs.release_id }}' in sdk
        and 'SELECTED_RELEASE_ID: ${{ needs.v2-prepare.outputs.release_id }}' in readback
        and "toolchain-dev-" not in builds + sdk + readback,
        "authenticated release IDs must flow to full owners and readback without a hardcoded development fallback",
    )
    require(
        "needs: [v2-prepare, v2-sources, v2-runtimes, v2-build]" in sdk
        and "matrix: ${{ fromJSON(needs.v2-prepare.outputs.matrix) }}" in sdk
        and "name: diagnostic-v2-native-runtime-${{ matrix.host }}" in sdk
        and "select-owner-artifacts-v2.py" in sdk
        and '--job-name "Native compiler ($SELECTED_GROUP, $SELECTED_HOST, $SELECTED_PRESET, $copy)"' in sdk
        and "--role build" in sdk
        and "--owner-a-selection" in sdk and "--owner-b-selection" in sdk
        and '--job-name "$CURRENT_JOB" --same-attempt' in sdk
        and ".[0].job.id != .[1].job.id" in sdk
        and "owner-role: sdk" in sdk
        and "job-name: SDK from owned compilers (${{ matrix.group_id }}, ${{ matrix.host }}, ${{ matrix.profile }})" in sdk,
        "SDK owners must authenticate two distinct original compilers without rebuilding",
    )
    require(
        "if: needs.v2-prepare.outputs.full_matrix == 'true'" in readback
        and "needs: [v2-prepare, v2-runtimes, v2-build, v2-sdk]" in readback
        and "runs-on: ubuntu-24.04" in readback
        and "name: diagnostic-v2-native-runtime-linux-x86_64" in readback
        and "collect-sdk-owners-v2.sh" in readback
        and "collect-compiler-owners-v2.sh" in readback
        and readback.index("collect-compiler-owners-v2.sh") < readback.index("collect-sdk-owners-v2.sh")
        and '--release-id "$SELECTED_RELEASE_ID"' in readback.split(
            "collect-compiler-owners-v2.sh", 1
        )[1].split("collect-sdk-owners-v2.sh", 1)[0]
        and '--forbidden-prefix "$GITHUB_WORKSPACE" --forbidden-prefix "$RUNNER_TEMP"' in readback
        and '--producer-commit "$GITHUB_SHA" --tools-commit "$EXPECTED_TOOLS"' in readback
        and '--source-context "$context" --source-context-sha256 "$context_sha"' in readback
        and readback.count('--job-name "$CURRENT_JOB" --same-attempt') == 2
        and "selection-fragment.json" in readback
        and "build-lane-v2.sh" not in readback
        and "sdk build" not in readback,
        "complete SDK owner readback must wait for every native owner and cannot rebuild or publish",
    )
    sdk_selector = "python3 -B scripts/toolchain/select-sdk-package-inputs-v2.py"
    native_plan_command = (
        '"$runtime/bin/aros" toolchain producer release-plan \\\n'
        '            --directory "$RUNNER_TEMP/diagnostic-inputs" --inputs-sha256 "$inputs_sha" \\\n'
        '            --format json > "$plan"'
    )
    require(
        native_plan_command in readback
        and 'test ! -e "$plan" && test ! -L "$plan"' in readback
        and "set -C" in readback
        and readback.index("set -C") < readback.index(native_plan_command),
        "fresh native plan must use the exact runtime and independently bound input directory",
    )
    require(sdk_selector in readback, "SDK package projection must use the reviewed selector")
    selector_command = readback.split(sdk_selector, 1)[1].split('> "$package_inputs"', 1)[0]
    require(
        readback.index("collect-sdk-owners-v2.sh") < readback.index("toolchain producer release-plan")
        < readback.index(sdk_selector)
        and 'package_inputs="$RUNNER_TEMP/sdk-package-inputs.json"' in readback
        and 'plan="$RUNNER_TEMP/sdk-index-native-plan.json"' in readback
        and 'fragment_sha=$(shasum -a 256 "$fragment"' in readback
        and 'plan_sha=$(shasum -a 256 "$plan"' in readback
        and 'test ! -e "$package_inputs" && test ! -L "$package_inputs"' in readback
        and '--owner-root "$RUNNER_TEMP/complete-sdk-readback" > "$package_inputs"' in readback
        and "set -C" in readback
        and all(argument in selector_command for argument in (
            '--plan "$plan" --plan-sha256 "$plan_sha"',
            '--inputs-dir "$RUNNER_TEMP/diagnostic-inputs" --inputs-sha256 "$inputs_sha"',
            '--producer-commit "$GITHUB_SHA" --tools-commit "$EXPECTED_TOOLS"',
            '--fragment "$fragment" --fragment-sha256 "$fragment_sha"',
            '--owner-root "$RUNNER_TEMP/complete-sdk-readback"',
        )),
        "SDK package projection must follow authentication with exact independent bindings",
    )
    documents.read("scripts/toolchain/select-sdk-package-inputs-v2.py")
    combined_assembler = "python3 -B scripts/toolchain/assemble-release-candidate-v2.py"
    require(combined_assembler in readback, "combined candidate assembly must use the reviewed adapter")
    assembly_command = readback.split(combined_assembler, 1)[1].split('> "$candidate_summary"', 1)[0]
    require(
        readback.index(sdk_selector) < readback.index('required_paths="$RUNNER_TEMP/compiler-candidate-required-paths.json"')
        < readback.index("python3 -B scripts/toolchain/required-compiler-payload-v2.py")
        < readback.index(combined_assembler)
        and 'policy="$GITHUB_WORKSPACE/toolchains/compiler-required-payload-v1.json"' in readback
        and 'policy_sha=$(shasum -a 256 "$policy"' in readback
        and '--policy "$policy" --policy-sha256 "$policy_sha"' in readback
        and 'required_paths_sha=$(shasum -a 256 "$required_paths"' in readback
        and 'compiler_fragment="$RUNNER_TEMP/complete-compiler-readback/selection-fragment.json"' in readback
        and 'compiler_fragment_sha=$(shasum -a 256 "$compiler_fragment"' in readback
        and 'candidate_summary="$RUNNER_TEMP/release-candidate-summary.json"' in readback
        and '--root "$RUNNER_TEMP/release-candidate" > "$candidate_summary"' in readback
        and 'test ! -e "$required_paths" && test ! -L "$required_paths"' in readback
        and 'test ! -e "$candidate_summary" && test ! -L "$candidate_summary"' in readback
        and all(argument in assembly_command for argument in (
            '--aros "$runtime/bin/aros" --aros-sha256 "$runtime_sha"',
            '--plan "$plan" --plan-sha256 "$plan_sha"',
            '--inputs-dir "$RUNNER_TEMP/diagnostic-inputs" --inputs-sha256 "$inputs_sha"',
            '--producer-commit "$GITHUB_SHA" --tools-commit "$EXPECTED_TOOLS"',
            '--compiler-fragment "$compiler_fragment" --compiler-fragment-sha256 "$compiler_fragment_sha"',
            '--compiler-owner-root "$RUNNER_TEMP/complete-compiler-readback"',
            '--sdk-fragment "$fragment" --sdk-fragment-sha256 "$fragment_sha"',
            '--sdk-owner-root "$RUNNER_TEMP/complete-sdk-readback"',
            '--required-paths "$required_paths" --required-paths-sha256 "$required_paths_sha"',
            '--release-id "$SELECTED_RELEASE_ID"',
            '--forbidden-prefix "$GITHUB_WORKSPACE" --forbidden-prefix "$RUNNER_TEMP"',
            '--support-dir "$support" --manifest-schema-sha256 "$manifest_schema_sha"',
            '--tree-fixture-sha256 "$tree_fixture_sha"',
            '--base-url "https://github.com/$GITHUB_REPOSITORY/releases/download/$SELECTED_RELEASE_ID"',
            '--root "$RUNNER_TEMP/release-candidate"',
        )),
        "combined candidate assembly must follow authentication with independently selected policy and exact bindings",
    )
    documents.read("scripts/toolchain/assemble-compiler-candidate-v2.py")
    documents.read("scripts/toolchain/assemble-sdk-candidate-v2.py")
    documents.read("scripts/toolchain/assemble-release-candidate-v2.py")
    evidence_selector = "python3 -B scripts/toolchain/select-native-release-evidence-v2.py"
    require(evidence_selector in readback, "native evidence selection must use the reviewed adapter")
    evidence_command = readback.split(evidence_selector, 1)[1].split('> "$evidence_selection"', 1)[0]
    require(
        readback.index(combined_assembler) < readback.index(evidence_selector)
        and 'compiler_lanes="$RUNNER_TEMP/release-candidate/compiler-stage/compiler-index-lanes.json"' in readback
        and 'compiler_evidence="$RUNNER_TEMP/release-candidate/compiler-stage/compiler-evidence-fragment.json"' in readback
        and 'candidate_index="$RUNNER_TEMP/release-candidate/release/toolchain-index-v2.json"' in readback
        and 'evidence_selection="$RUNNER_TEMP/native-release-evidence-selection.json"' in readback
        and 'test ! -e "$evidence_selection" && test ! -L "$evidence_selection"' in readback
        and all(binding in readback for binding in (
            'compiler_lanes_sha=$(shasum -a 256 "$compiler_lanes"',
            'compiler_evidence_sha=$(shasum -a 256 "$compiler_evidence"',
            'candidate_index_sha=$(shasum -a 256 "$candidate_index"',
        ))
        and all(argument in evidence_command for argument in (
            '--plan "$plan" --plan-sha256 "$plan_sha"',
            '--inputs-dir "$RUNNER_TEMP/diagnostic-inputs" --inputs-sha256 "$inputs_sha"',
            '--producer-commit "$GITHUB_SHA" --tools-commit "$EXPECTED_TOOLS"',
            '--compiler-lanes "$compiler_lanes" --compiler-lanes-sha256 "$compiler_lanes_sha"',
            '--compiler-evidence "$compiler_evidence" --compiler-evidence-sha256 "$compiler_evidence_sha"',
            '--sdk-fragment "$fragment" --sdk-fragment-sha256 "$fragment_sha"',
            '--sdk-owner-root "$RUNNER_TEMP/complete-sdk-readback"',
            '--index "$candidate_index" --index-sha256 "$candidate_index_sha"',
        )),
        "native evidence selection must bind complete original-owner evidence to the measured candidate index",
    )
    documents.read("scripts/toolchain/select-native-release-evidence-v2.py")
    attest = "name: Attest closed combined diagnostic subjects"
    final_gate = "name: Verify genuine combined candidate provenance and final native evidence"
    require(
        readback.count(attest) == 1 and readback.count(final_gate) == 1
        and readback.index(evidence_selector) < readback.index(attest) < readback.index(final_gate)
        and "id: candidate-provenance" in readback
        and "subject-checksums: ${{ runner.temp }}/release-candidate/subject-manifest.json" in readback,
        "final diagnostic attestation must follow complete candidate/evidence assembly",
    )
    final_shell = readback.split(final_gate, 1)[1].split("      - name:", 1)[0]
    verifier_commands = [part.split("--output", 1)[0] for part in final_shell.split("bash scripts/toolchain/verify-provenance-attestation.sh")[1:]]
    require(
        "PROVENANCE_BUNDLE: ${{ steps.candidate-provenance.outputs.bundle-path }}" in final_shell
        and all(binding in final_shell for binding in (
            "EXPECTED_INDEX_SHA: ${{ steps.candidate.outputs.index_sha256 }}",
            "EXPECTED_SUBJECT_SHA: ${{ steps.candidate.outputs.subject_sha256 }}",
            "EXPECTED_SELECTION_SHA: ${{ steps.candidate.outputs.selection_sha256 }}",
            "EXPECTED_SUMMARY_SHA: ${{ steps.candidate.outputs.summary_sha256 }}",
            "EXPECTED_INPUTS_SHA: ${{ steps.candidate.outputs.inputs_sha256 }}",
            "EXPECTED_RUNTIME_SHA: ${{ steps.candidate.outputs.runtime_sha256 }}",
        ))
        and final_shell.count("bash scripts/toolchain/verify-provenance-attestation.sh") == 2
        and all(all(argument in command for argument in (
            '--subject-manifest "$subject" --subject-manifest-sha256 "$EXPECTED_SUBJECT_SHA"',
            '--subject-dir "$release"',
            '--repository "$GITHUB_REPOSITORY"',
            '--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/toolchain-release.yml"',
            '--source-digest "$GITHUB_SHA" --source-ref "$GITHUB_REF"',
            '--run-id "$GITHUB_RUN_ID" --run-attempt "$GITHUB_RUN_ATTEMPT"',
        )) for command in verifier_commands)
        and "os.O_EXCL | os.O_NOFOLLOW" in final_shell
        and "toolchain producer record-qualification" not in final_shell
        and "ulimit -f 8192; timeout --signal=KILL" in final_shell,
        "final diagnostic provenance must use real bundle verification and independent held selectors without fake tag recording",
    )
    require(
        '"$runtime" toolchain producer index' in final_shell
        and '"$runtime" toolchain producer verify-release-evidence' in final_shell,
        "final native diagnostic must call both current native stages",
    )
    final_index_command = final_shell.split('"$runtime" toolchain producer index', 1)[1].split('> "$final_index"', 1)[0]
    final_evidence_command = final_shell.split('"$runtime" toolchain producer verify-release-evidence', 1)[1].split('> "$final_evidence"', 1)[0]
    require(
        final_shell.index("--output \"$RUNNER_TEMP/verified-staged-combined-provenance.json\"") < final_shell.index('"$runtime" toolchain producer index')
        < final_shell.index('"$runtime" toolchain producer verify-release-evidence')
        and all(argument in final_index_command for argument in (
            '--directory "$release"', '--release-format family-v2 --lane-inputs "$candidate/lane-inputs.json"',
            '--subject-manifest "$subject" --subject-manifest-sha256 "$EXPECTED_SUBJECT_SHA"',
            '--stage final --format json',
        ))
        and all(argument in final_evidence_command for argument in (
            '--inputs-sha256 "$EXPECTED_INPUTS_SHA" --index-sha256 "$EXPECTED_INDEX_SHA"',
            '--selection "$selection" --selection-sha256 "$EXPECTED_SELECTION_SHA"',
            '--subject-manifest "$subject" --subject-manifest-sha256 "$EXPECTED_SUBJECT_SHA"',
            '--forbidden-prefix "$GITHUB_WORKSPACE" --forbidden-prefix "$RUNNER_TEMP"',
        ))
        and '([$selected[0].sdk_generations[] | [.sdk_id,.group_id,.target_profile,.host]] | sort)' in final_shell
        and '($selected[0].lanes | keys | sort)' in final_shell
        and '($selected[0].sdk_packages | keys | sort)' in final_shell,
        "final native diagnostic must close complete compiler and SDK evidence after genuine staged provenance verification",
    )
    require(
        "repository: metaneutrons/aros-tools\n          ref: ${{ needs.v2-prepare.outputs.tools_commit }}\n          persist-credentials: false\n          path: dependencies/aros-tools-fixtures" in readback
        and 'support="$GITHUB_WORKSPACE/dependencies/aros-tools-fixtures/crates/aros-common/tests/fixtures"' in readback
        and 'manifest_schema_sha=$(shasum -a 256 "$support/toolchain-manifest-v2.schema.json"' in readback
        and 'tree_fixture_sha=$(shasum -a 256 "$support/tree-digest-v1.fixture.json"' in readback
        and "python3 -B scripts/toolchain/assemble-compiler-candidate-v2.py" not in readback
        and "python3 -B scripts/toolchain/assemble-sdk-candidate-v2.py" not in readback,
        "combined candidate support must come from the exact tools checkout without duplicate package stages",
    )
    require(
        "host_matrix: ${{ steps.matrix.outputs.host_matrix }}" in prepare
        and "matrix: ${{ fromJSON(needs.v2-prepare.outputs.host_matrix) }}" in runtimes
        and "runs-on: ${{ matrix.runner }}" in runtimes
        and "uses: ./.github/actions/verify-aros-tools-runtime-transport" in runtimes
        and "runtime-kind: ${{ needs.v2-prepare.outputs.runtime_kind }}" in runtimes
        and "commit: ${{ needs.v2-prepare.outputs.tools_commit }}" in runtimes
        and "name: diagnostic-v2-native-runtime-${{ matrix.host }}" in runtimes
        and "name: diagnostic-v2-native-runtime-${{ matrix.host }}" in qualify
        and "if: runner.os == 'Linux'" in qualify
        and "runtime-kind: ${{ needs.v2-prepare.outputs.runtime_kind }}" in qualify,
        "every native lane must consume and reverify its own selected host runtime with portable readback",
    )
    require(
        'REQUESTED_GROUP: ${{ inputs.diagnostic_group }}' in prepare
        and 'group_arguments+=(--diagnostic-group "$REQUESTED_GROUP")' in prepare
        and '"${group_arguments[@]}"' in prepare,
        "V2 optional diagnostic group must be passed to the validated native-plan projection",
    )
    require(
        '"release-plan"' in prepare_script
        and '"verify-source"' in prepare_script
        and "materialize-engine-free-source" in prepare_script,
        "V2 inputs must be bound through native plan, SDK source verification and projection",
    )
    require(
        "expected_producer_commit" in matrix_script
        and "expected_tools_commit" in matrix_script
        and "release_format" in matrix_script,
        "V2 scheduler must validate plan identity and family format",
    )

    require(
        "jq -r '.groups[].source_lock'" in sources
        and "jq -r '.groups[].ports_lock'" in sources,
        "V2 cache preparation must iterate selected compiler and compatibility locks",
    )
    require(
        "cache sources fetch --source-lock" in sources
        and "cache sources fetch --source-lock" in sources
        and "--offline" in sources
        and "cache sources verify --source-lock" in sources,
        "V2 compiler caches must support offline verification before qualification",
    )
    require(
        "cache sources fetch --compatibility-ports-lock" in sources
        and "cache sources verify --compatibility-ports-lock" in sources
        and "for attempt in 1 2 3; do" in sources,
        "V2 compatibility sources must be seeded, bounded and offline-verified",
    )
    require(
        "cache cargo fetch" in sources and "cache cargo verify" in sources,
        "V2 source preparation must populate and verify Cargo caches",
    )
    require(
        'tar -C "$cache" -czf "$RUNNER_TEMP/diagnostic-cache.tar.gz" .' in sources
        and 'cache_archive_sha256: ${{ steps.cache.outputs.cache_archive_sha256 }}' in sources
        and 'name: diagnostic-v2-cache\n          path: ${{ runner.temp }}/diagnostic-cache.tar.gz' in sources,
        "V2 cache transport must preserve the measured tree in an independently digest-bound archive",
    )
    documents.read(CACHE_TRANSPORT)
    require(
        'CACHE_ARCHIVE_SHA256: ${{ needs.v2-sources.outputs.cache_archive_sha256 }}' in qualify
        and 'python3 -B scripts/toolchain/cache-archive-transport.py' in qualify
        and '--archive-sha256 "$CACHE_ARCHIVE_SHA256" --output-dir "$RUNNER_TEMP/diagnostic-cache"' in qualify
        and qualify.index('python3 -B scripts/toolchain/cache-archive-transport.py')
        < qualify.index('"$runtime/bin/aros" cache cargo verify'),
        "V2 qualification must safely restore the exact cache archive before native verification",
    )
    require(
        'for copy in a b; do' in qualify_script
        and 'build-lane-v2.sh' in qualify_script
        and 'compiler-$copy' in qualify_script,
        "V2 qualification must build two fresh Family V2 compiler packages",
    )
    require(
        "toolchain producer compare --left" in qualify_script
        and 'compiler-a/payload/package' in qualify_script
        and 'compiler-b/payload/package' in qualify_script,
        "V2 qualification must compare the two compiler packages",
    )
    require(
        'compiler_family=$(jq -er \'.family\' "$lock")' in qualify_script
        and 'if [[ "$compiler_family" == gnu ]]; then' in qualify_script
        and 'observe_gcc_inputs "$root/compiler-$copy"' in qualify_script
        and 'observe-gcc-checksum-inputs.py' in qualify_script
        and '--output "${compiler_root%/*}/gcc-checksum-inputs-${compiler_root##*/}.json"' in qualify_script
        and 'gcc-makefiles.list' not in qualify_script
        and 'exactly one generated GCC Makefile' in qualify_script
        and qualify_script.index('observe_gcc_inputs "$root/compiler-$copy"')
        < qualify_script.index('toolchain producer compare --left'),
        "GNU diagnostics must retain the exact checksum input observations before A/B comparison",
    )
    require(
        '"$aros" sdk build --identity' in qualify_script
        and "--materialized-source-dir" in qualify_script
        and "--first-root" in qualify_script
        and "--second-root" in qualify_script
        and "--engine-work-dir" in qualify_script
        and "--reports-dir" in qualify_script
        and "--generation-record" in qualify_script
        and "--sdk-forbidden-prefix" in qualify_script,
        "V2 qualification must run native source-bound SDK builds with relocation evidence",
    )
    require(
        "'.sdks[] | select(any(.compiler_profiles[]; .group_id == $group and .profile == $preset))'"
        in qualify_script,
        "V2 qualification must derive SDK products from the native plan",
    )
    require(
        "cache sources fetch" not in qualify_script,
        "V2 lane qualification must consume verified caches without fetching inputs",
    )
    require(
        "if: always()" in qualify
        and "retention-days: 7" in qualify
        and "sdk-*/reports/" in qualify
        and "sdk-*/local-evidence/" in qualify
        and "sdk-*/result.json" in qualify
        and "compiler-*/payload/" in qualify,
        "V2 diagnostic packages and reports must be retained on success or failure",
    )
    require(
        "retention-days: 7" in prepare and "retention-days: 7" in sources,
        "V2 runtime, inputs and verified cache artifacts must have bounded retention",
    )
    require(
        "compiler-*/work/native-lifecycle/logs/" in qualify
        and "compiler-*/work/native-lifecycle/receipts/" in qualify
        and "compiler-*/work/native-lifecycle/verified-source-usage.log" in qualify
        and "sdk-*/cmake/**/*.log" in qualify
        and "sdk-*/cmake/**/CMakeConfigureLog.yaml" in qualify,
        "V2 diagnostic native compiler and SDK configuration failure logs must be retained",
    )
    require(
        "cargo build --manifest-path" in action
        and "--locked --release --workspace --bins" in action
        and 'test "$(git -C "$TOOLS_SOURCE" rev-parse HEAD)" = "$TOOLS_COMMIT"' in action
        and 'test -z "$(git -C "$TOOLS_SOURCE" status --porcelain)"' in action
        and "GITHUB_EVENT_NAME" in action
        and "RUNNER_OS" in action,
        "development tools helper must build only the clean, selected native dispatch checkout",
    )
    require(
        not re.search(r"(?m)^\s*(?:gh\s+release|git\s+(?:tag|push)\b)", qualify_script),
        "V2 lane script must not publish or create/push tags",
    )
    return validate_selected_inputs(documents)


def mutate_job(text: str, name: str, old: str, new: str) -> str:
    block = workflow_job(text, name)
    if old not in block:
        raise AssertionError(f"test mutation target not found in {name}: {old!r}")
    mutated = block.replace(old, new, 1)
    start = text.index(block)
    return text[:start] + mutated + text[start + len(block) :]


class CompilerSdkWorkflowV2Tests(unittest.TestCase):
    def _runtime_interface_fixture(
        self,
        directory: str,
        *,
        kind: str,
        cli_version: str = "1.2.3",
    ) -> dict[str, Any]:
        base = Path(directory).resolve()
        workspace = base / "workspace"
        tools_source = base / "tools-source"
        runtime = base / "selected-runtime"
        workspace.mkdir()
        tools_source.mkdir()
        (workspace / "scripts/toolchain").mkdir(parents=True)
        (workspace / INTERFACE_HELPER).write_bytes((ROOT / INTERFACE_HELPER).read_bytes())
        (tools_source / "Cargo.toml").write_text(
            '[workspace]\nresolver = "2"\n[workspace.package]\nversion = "1.2.3"\n',
            encoding="utf-8",
        )
        subprocess.run(["git", "-C", str(tools_source), "init", "-q"], check=True)
        subprocess.run(["git", "-C", str(tools_source), "config", "user.name", "Policy Test"], check=True)
        subprocess.run(
            ["git", "-C", str(tools_source), "config", "user.email", "policy@example.invalid"],
            check=True,
        )
        subprocess.run(["git", "-C", str(tools_source), "add", "Cargo.toml"], check=True)
        subprocess.run(
            ["git", "-C", str(tools_source), "commit", "-qm", "selected tools source"],
            check=True,
        )
        tools_commit = subprocess.run(
            ["git", "-C", str(tools_source), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

        helper_spec = importlib.util.spec_from_file_location(
            "runtime_interface_for_workflow_policy", ROOT / INTERFACE_HELPER
        )
        self.assertIsNotNone(helper_spec)
        assert helper_spec is not None and helper_spec.loader is not None
        helper = importlib.util.module_from_spec(helper_spec)
        helper_spec.loader.exec_module(helper)
        options = sorted({option for _, required in helper.INTERFACES for option in required})
        cli = "\n".join(
            (
                "#!/usr/bin/env python3",
                "import os, sys",
                f"VERSION = {cli_version!r}",
                f"OPTIONS = {options!r}",
                "arguments = sys.argv[1:]",
                'if arguments == ["--version"]:',
                '    print("aros " + os.environ.get("INTERFACE_TEST_VERSION", VERSION))',
                'elif arguments and arguments[-1] == "--help":',
                '    missing = os.environ.get("INTERFACE_TEST_MISSING_OPTION", "")',
                '    print("Options:")',
                '    for option in OPTIONS:',
                '        if option != missing: print("  --" + option + " <VALUE>")',
                "else:",
                "    raise SystemExit(2)",
                "",
            )
        )
        binary = runtime / "bin/aros"
        binary.parent.mkdir(parents=True)
        binary.write_text(cli, encoding="utf-8")
        binary.chmod(0o700)
        runtime_sha = hashlib.sha256(binary.read_bytes()).hexdigest()

        lock_path = workspace / "toolchains/aros-tools-runtime-v1.json"
        lock_path.parent.mkdir(parents=True)
        lock_path.write_text(
            json.dumps({"source_commit": tools_commit, "version": "1.2.3"}),
            encoding="utf-8",
        )
        (runtime / ".aros-tools-runtime-manifest.json").write_text(
            json.dumps({"files": [{"path": "bin/aros", "sha256": runtime_sha}]}),
            encoding="utf-8",
        )
        (runtime / "DEVELOPMENT_RUNTIME.txt").write_text(
            f"development-only tools commit: {tools_commit}\n", encoding="utf-8"
        )
        (runtime / "SHA256SUMS").write_text(f"{runtime_sha}  bin/aros\n", encoding="utf-8")

        return {
            "kind": kind,
            "workspace": workspace,
            "tools_source": tools_source,
            "tools_commit": tools_commit,
            "runtime": runtime,
            "binary": binary,
            "runtime_sha": runtime_sha,
            "lock": lock_path,
            "manifest": runtime / ".aros-tools-runtime-manifest.json",
            "checksum_file": runtime / "SHA256SUMS",
            "receipt": base / "runtime-interface-receipt.json",
            "env": {
                "RUNTIME_KIND": kind,
                "RUNTIME_ROOT": str(runtime),
                "TOOLS_SOURCE": str(tools_source),
                "TOOLS_COMMIT": tools_commit,
                "INTERFACE_OUTPUT": str(base / "runtime-interface-receipt.json"),
                "RUNTIME_LOCK": "toolchains/aros-tools-runtime-v1.json",
                "GITHUB_WORKSPACE": str(workspace),
            },
        }

    def _run_interface_action(self, fixture: dict[str, Any], **environment: str) -> subprocess.CompletedProcess[str]:
        script = composite_run_script(Documents().text(INTERFACE_ACTION))
        return subprocess.run(
            ["/bin/bash", "-c", script],
            capture_output=True,
            text=True,
            env={**os.environ, **fixture["env"], **environment},
            check=False,
        )

    def test_composite_interface_action_runs_the_real_helper_for_both_runtime_kinds(self) -> None:
        for kind in ("development", "released"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                fixture = self._runtime_interface_fixture(temporary, kind=kind)
                result = self._run_interface_action(fixture)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(fixture["receipt"].is_file())
                self.assertNotEqual(
                    fixture["receipt"].parent,
                    fixture["runtime"],
                    "the interface receipt must be outside the selected runtime",
                )
                receipt = json.loads(fixture["receipt"].read_text(encoding="utf-8"))
                self.assertEqual(receipt["schema"], "aros-tools-runtime-interface-preflight-v1")
                self.assertEqual(receipt["assurance"], "interface-only-exact-selected-binary")
                self.assertEqual(receipt["runtime"]["sha256"], fixture["runtime_sha"])
                self.assertNotIn("source_commit", receipt)
                self.assertTrue(
                    any("does not authenticate published runtime provenance" in item
                        for item in receipt["limitations"])
                )

    def test_composite_interface_action_rejects_runtime_binding_and_metadata_counterprobes(self) -> None:
        probes = (
            ("development", "digest"),
            ("released", "released-digest"),
            ("development", "version"),
            ("released", "source"),
            ("development", "selected-commit"),
            ("development", "dirty-selected-source"),
            ("development", "duplicate-checksum-metadata"),
            ("development", "missing-checksum-metadata"),
            ("released", "duplicate-manifest-cli-metadata"),
            ("released", "missing-manifest-cli-metadata"),
            ("development", "missing-help-option"),
            ("development", "unknown-kind"),
            ("development", "output-inside-runtime"),
        )
        for kind, probe in probes:
            with self.subTest(probe=probe), tempfile.TemporaryDirectory() as temporary:
                fixture = self._runtime_interface_fixture(temporary, kind=kind)
                extra_environment: dict[str, str] = {}
                if probe == "digest":
                    fixture["checksum_file"].write_text(f"{'0' * 64}  bin/aros\n", encoding="utf-8")
                elif probe == "released-digest":
                    manifest = json.loads(fixture["manifest"].read_text(encoding="utf-8"))
                    manifest["files"][0]["sha256"] = "0" * 64
                    fixture["manifest"].write_text(json.dumps(manifest), encoding="utf-8")
                elif probe == "version":
                    extra_environment["INTERFACE_TEST_VERSION"] = "9.9.9"
                elif probe == "source":
                    lock = json.loads(fixture["lock"].read_text(encoding="utf-8"))
                    lock["source_commit"] = "f" * 40 if fixture["tools_commit"] != "f" * 40 else "e" * 40
                    fixture["lock"].write_text(json.dumps(lock), encoding="utf-8")
                elif probe == "selected-commit":
                    extra_environment["TOOLS_COMMIT"] = "0" * 40
                elif probe == "dirty-selected-source":
                    (fixture["tools_source"] / "untracked.txt").write_text("dirty\n", encoding="utf-8")
                elif probe == "duplicate-checksum-metadata":
                    line = fixture["checksum_file"].read_text(encoding="utf-8")
                    fixture["checksum_file"].write_text(line + line, encoding="utf-8")
                elif probe == "missing-checksum-metadata":
                    fixture["checksum_file"].write_text("", encoding="utf-8")
                elif probe == "duplicate-manifest-cli-metadata":
                    manifest = json.loads(fixture["manifest"].read_text(encoding="utf-8"))
                    manifest["files"].append(dict(manifest["files"][0]))
                    fixture["manifest"].write_text(json.dumps(manifest), encoding="utf-8")
                elif probe == "missing-manifest-cli-metadata":
                    fixture["manifest"].write_text(json.dumps({"files": []}), encoding="utf-8")
                elif probe == "missing-help-option":
                    extra_environment["INTERFACE_TEST_MISSING_OPTION"] = "source-dir"
                elif probe == "unknown-kind":
                    extra_environment["RUNTIME_KIND"] = "unknown"
                elif probe == "output-inside-runtime":
                    extra_environment["INTERFACE_OUTPUT"] = str(
                        fixture["runtime"] / "runtime-interface-receipt.json"
                    )

                result = self._run_interface_action(fixture, **extra_environment)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertFalse(fixture["receipt"].exists())
                if probe == "output-inside-runtime":
                    self.assertFalse((fixture["runtime"] / "runtime-interface-receipt.json").exists())

    def test_rejects_runtime_interface_workflow_skips_and_misbindings(self) -> None:
        mutations = (
            (
                "v2-prepare",
                "        uses: ./.github/actions/check-v2-runtime-interface\n",
                "        if: steps.selection.outputs.full_matrix == 'true'\n"
                "        uses: ./.github/actions/check-v2-runtime-interface\n",
            ),
            (
                "v2-runtimes",
                "        uses: ./.github/actions/check-v2-runtime-interface\n",
                "        uses: ./.github/actions/check-v2-runtime-interface\n"
                "        continue-on-error: true\n",
            ),
            (
                "v2-prepare",
                "          tools-commit: ${{ steps.selection.outputs.tools_commit }}",
                "          tools-commit: ${{ github.sha }}",
            ),
            (
                "v2-runtimes",
                "      - name: Check every selected host V2 interface before compiler fan-out\n"
                "        uses: ./.github/actions/check-v2-runtime-interface\n"
                "        with:\n"
                "          runtime-kind: ${{ needs.v2-prepare.outputs.runtime_kind }}",
                "      - name: Check every selected host V2 interface before compiler fan-out\n"
                "        uses: ./.github/actions/check-v2-runtime-interface\n"
                "        with:\n"
                "          runtime-kind: development",
            ),
            (
                "v2-prepare",
                "          output: ${{ runner.temp }}/diagnostic-runtime-interface.json",
                "          output: ${{ runner.temp }}/diagnostic-runtime/interface.json",
            ),
            (
                "v2-prepare",
                "          root: ${{ steps.runtime.outputs.root }}",
                "          root: ${{ runner.temp }}/fallback-runtime",
            ),
        )
        for job, old, new in mutations:
            with self.subTest(job=job, old=old), self.assertRaises(PolicyViolation):
                documents = self.new_documents()
                documents.set_text(
                    WORKFLOW,
                    mutate_job(documents.text(WORKFLOW), job, old, new),
                )
                validate_v2_policy(documents)

    def test_rejects_runtime_interface_action_authentication_bypass_or_route_fallback(self) -> None:
        action = Documents().text(INTERFACE_ACTION)
        bypasses = (
            (
                'test "$(git -C "$TOOLS_SOURCE" rev-parse HEAD)" = "$TOOLS_COMMIT"',
                'test -n "$TOOLS_COMMIT"',
            ),
            (
                'else error("Runtime has no unique CLI entry") end',
                'else .[0].sha256 end',
            ),
            ('runtime_prefix=${RUNTIME_ROOT%/}', 'runtime_prefix='),
            ("*) echo 'Unsupported V2 runtime interface route.' >&2; exit 1;;",
             "*) echo 'Unsupported V2 runtime interface route.' >&2; exit 0;;"),
        )
        for old, new in bypasses:
            with self.subTest(old=old), self.assertRaises(PolicyViolation):
                documents = self.new_documents()
                documents.set_text(INTERFACE_ACTION, action.replace(old, new, 1))
                validate_v2_policy(documents)

    def new_documents(self) -> Documents:
        return Documents()

    def test_current_diagnostic_workflow_and_selected_documents_are_coherent(self) -> None:
        result = validate_v2_policy(self.new_documents())
        selection = Documents().json(SELECTION)
        self.assertEqual(result["group_count"], len(selection["groups"]))
        self.assertEqual(result["sdk_count"], len(selection["sdks"]))

    def test_actual_route_shell_accepts_manual_modes_and_rejects_tag_without_runtime_lock(self) -> None:
        prepare = workflow_job(Documents().text(WORKFLOW), "v2-prepare")
        block = prepare.split("      - id: selection\n", 1)[1].split("      - ", 1)[0]
        script = block.split("        run: |\n", 1)[1]
        script = "\n".join(line[10:] for line in script.splitlines()) + "\n"
        source_commit = "1" * 40
        tools_commit = "2" * 40
        with tempfile.TemporaryDirectory(prefix="v2-route-shell-") as directory:
            workspace = Path(directory) / "producer"
            workspace.mkdir()
            subprocess.run(["git", "init", "-q", str(workspace)], check=True)
            subprocess.run(["git", "-C", str(workspace), "config", "user.name", "Policy Test"], check=True)
            subprocess.run(["git", "-C", str(workspace), "config", "user.email", "policy@example.invalid"], check=True)
            toolchains = workspace / "toolchains"
            toolchains.mkdir()
            (workspace / "version.txt").write_text("1.2.3\n", encoding="utf-8")
            (toolchains / "compiler-sdk-ci-selection-v2.json").write_text(
                json.dumps({"schema": "aros-compiler-sdk-ci-selection-v2",
                            "source_commit": source_commit, "tools_commit": tools_commit}),
                encoding="utf-8",
            )
            subprocess.run(["git", "-C", str(workspace), "add", "version.txt", "toolchains"], check=True)
            subprocess.run(["git", "-C", str(workspace), "commit", "-qm", "route fixture"], check=True)
            producer_commit = subprocess.run(
                ["git", "-C", str(workspace), "rev-parse", "HEAD"],
                check=True, capture_output=True, text=True,
            ).stdout.strip()
            subprocess.run(["git", "-C", str(workspace), "tag", "-a", "v1.2.3", "-m", "fixture"], check=True)

            scenarios = (
                ("qualify-v2", "linux-x86_64", "", "workflow_dispatch", "branch", True),
                ("qualify-v2-full", "full", "", "workflow_dispatch", "branch", True),
                ("qualify-v2", "full", "", "workflow_dispatch", "branch", False),
                ("qualify-v2-full", "linux-x86_64", "", "workflow_dispatch", "branch", False),
                ("qualify-v2-full", "full", "gnu-rv32", "workflow_dispatch", "branch", False),
                ("qualify-v2-full", "full", "", "workflow_dispatch", "tag", False),
            )
            for mode, scope, group, event, ref_type, accepted in scenarios:
                with self.subTest(mode=mode, scope=scope, group=group, event=event, ref_type=ref_type):
                    output = Path(directory) / "output"
                    output.write_bytes(b"")
                    ref = "refs/heads/policy/route-tests" if ref_type == "branch" else "refs/tags/v1.2.3"
                    environment = {
                        **os.environ,
                        "GITHUB_OUTPUT": str(output),
                        "GITHUB_WORKSPACE": str(workspace),
                        "GITHUB_EVENT_NAME": event,
                        "GITHUB_REF_TYPE": ref_type,
                        "GITHUB_REF": ref,
                        "GITHUB_REPOSITORY": "example/producer",
                        "GITHUB_SHA": producer_commit,
                        "GITHUB_RUN_ATTEMPT": "1",
                        "TOOLS_RUNTIME_LOCK": "toolchains/aros-tools-runtime-v1.json",
                        "GH_TOKEN": "policy-test-token",
                        "REQUESTED_MODE": mode,
                        "REQUESTED_SCOPE": scope,
                        "REQUESTED_GROUP": group,
                    }
                    result = subprocess.run(
                        ["bash", "-c", script], cwd=ROOT, env=environment,
                        capture_output=True, text=True, timeout=10,
                    )
                    self.assertEqual(result.returncode == 0, accepted, result.stderr)
                    if accepted:
                        outputs = dict(line.split("=", 1) for line in output.read_text().splitlines())
                        self.assertEqual(outputs["source_commit"], source_commit)
                        self.assertEqual(outputs["tools_commit"], tools_commit)
                        self.assertEqual(outputs["event"], "workflow_dispatch")
                        self.assertEqual(outputs["scope"], scope)
                        self.assertEqual(outputs["runtime_kind"], "development")
                        self.assertEqual(outputs["full_matrix"], str(mode == "qualify-v2-full").lower())
                        self.assertEqual(outputs["full_qualification"], str(mode == "qualify-v2-full").lower())
                        self.assertEqual(outputs["release_id"], f"toolchain-dev-{producer_commit[:12]}")
                    else:
                        self.assertEqual(output.read_bytes(), b"")

            output = Path(directory) / "tag-output"
            output.write_bytes(b"")
            environment = {
                **os.environ,
                "GITHUB_OUTPUT": str(output),
                "GITHUB_WORKSPACE": str(workspace),
                "GITHUB_EVENT_NAME": "push",
                "GITHUB_REF_TYPE": "tag",
                "GITHUB_REF": "refs/tags/v1.2.3",
                "GITHUB_REPOSITORY": "example/producer",
                "GITHUB_SHA": producer_commit,
                "GITHUB_RUN_ATTEMPT": "1",
                "TOOLS_RUNTIME_LOCK": "toolchains/aros-tools-runtime-v1.json",
                "GH_TOKEN": "policy-test-token",
                "REQUESTED_MODE": "",
                "REQUESTED_SCOPE": "",
                "REQUESTED_GROUP": "",
            }
            result = subprocess.run(
                ["bash", "-c", script], cwd=ROOT, env=environment,
                capture_output=True, text=True, timeout=10,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("route input must be a regular file", result.stderr)
            self.assertEqual(output.read_bytes(), b"")

    def test_rejects_cross_host_runtime_download_and_legacy_route_widening(self) -> None:
        for job, original, replacement, reason in (
            ("v2-qualify", "name: diagnostic-v2-native-runtime-${{ matrix.host }}",
             "name: diagnostic-v2-runtime", "every native lane"),
            ("plan", "if: github.event_name == 'workflow_dispatch' && inputs.mode == 'produce'",
             "if: github.event_name == 'push' || github.event_name == 'workflow_dispatch'",
             "manual-produce only"),
            ("v2-prepare", "group_arguments+=(--full-qualification)",
             "group_arguments+=()", "full qualification"),
        ):
            with self.subTest(job=job):
                documents = self.new_documents()
                documents.set_text(WORKFLOW, mutate_job(documents.text(WORKFLOW), job,
                                                        original, replacement))
                with self.assertRaisesRegex(PolicyViolation, reason):
                    validate_v2_policy(documents)

    def test_rejects_diagnostic_permission_escalation(self) -> None:
        documents = self.new_documents()
        workflow = documents.text(WORKFLOW)
        workflow = mutate_job(
            workflow,
            "v2-qualify",
            "    permissions:\n      contents: read",
            "    permissions:\n      contents: write",
        )
        documents.set_text(WORKFLOW, workflow)
        with self.assertRaisesRegex(PolicyViolation, "permissions"):
            validate_v2_policy(documents)

    def test_rejects_missing_read_only_attestation_access_for_route_authentication(self) -> None:
        for job in ("v2-prepare", "v2-runtimes"):
            with self.subTest(job=job):
                documents = self.new_documents()
                workflow = mutate_job(
                    documents.text(WORKFLOW), job, "      attestations: read\n", "",
                )
                documents.set_text(WORKFLOW, workflow)
                with self.assertRaisesRegex(PolicyViolation, "permissions"):
                    validate_v2_policy(documents)

    def test_rejects_runtime_route_fallback_or_unverified_kind(self) -> None:
        for before, after in (
            ("shasum -a 256 -c SHA256SUMS", "true"),
            ("materialize-aros-tools-runtime.py\" verify", "missing-runtime-verification.py"),
            ("exit 1", "exit 0"),
            ("released)", "*)"),
        ):
            with self.subTest(before=before):
                documents = self.new_documents()
                action = documents.text(RUNTIME_ACTION)
                self.assertIn(before, action)
                documents.set_text(RUNTIME_ACTION, action.replace(before, after, 1))
                with self.assertRaisesRegex(PolicyViolation, "shared runtime (transport|verification)"):
                    validate_v2_policy(documents)

    def test_rejects_release_identity_loss_and_v1_tag_route_reconnection(self) -> None:
        cases = (
            ("v2-prepare", "release_id: ${{ steps.selection.outputs.release_id }}",
             "release_id: toolchain-dev-static", "authenticated release identity"),
            ("v2-build", "SELECTED_RELEASE_ID: ${{ needs.v2-prepare.outputs.release_id }}",
             "SELECTED_RELEASE_ID: toolchain-dev-static", "authenticated release IDs"),
            ("draft-release", "needs: [plan, compatibility]", "needs: [compatibility]",
             "V1 tag publisher"),
        )
        for job, before, after, reason in cases:
            with self.subTest(job=job):
                documents = self.new_documents()
                documents.set_text(WORKFLOW, mutate_job(documents.text(WORKFLOW), job, before, after))
                with self.assertRaisesRegex(PolicyViolation, reason):
                    validate_v2_policy(documents)

    def test_rejects_raw_cache_transport_or_missing_digest_restore(self) -> None:
        for job, original, replacement in (
            ("v2-sources", "path: ${{ runner.temp }}/diagnostic-cache.tar.gz", "path: ${{ runner.temp }}/diagnostic-cache/"),
            ("v2-sources", "cache_archive_sha256: ${{ steps.cache.outputs.cache_archive_sha256 }}", "cache_archive_sha256: unbound"),
            ("v2-qualify", "CACHE_ARCHIVE_SHA256: ${{ needs.v2-sources.outputs.cache_archive_sha256 }}", "CACHE_ARCHIVE_SHA256: unbound"),
            ("v2-qualify", "python3 -B scripts/toolchain/cache-archive-transport.py", "python3 -B missing.py"),
        ):
            with self.subTest(job=job, original=original):
                documents = self.new_documents()
                documents.set_text(WORKFLOW, mutate_job(documents.text(WORKFLOW), job, original, replacement))
                with self.assertRaises(PolicyViolation):
                    validate_v2_policy(documents)

    def test_rejects_missing_native_failure_diagnostics(self) -> None:
        for entry in (
            "compiler-*/work/native-lifecycle/logs/",
            "compiler-*/work/native-lifecycle/receipts/",
            "compiler-*/work/native-lifecycle/verified-source-usage.log",
            "sdk-*/cmake/**/*.log",
            "sdk-*/cmake/**/CMakeConfigureLog.yaml",
        ):
            with self.subTest(entry=entry):
                documents = self.new_documents()
                workflow = documents.text(WORKFLOW)
                workflow = mutate_job(workflow, "v2-qualify", entry, "removed-diagnostics/")
                documents.set_text(WORKFLOW, workflow)
                with self.assertRaisesRegex(PolicyViolation, "failure logs"):
                    validate_v2_policy(documents)

    def test_rejects_missing_or_unbound_gnu_checksum_observation(self) -> None:
        for original, replacement in (
            ('observe_gcc_inputs "$root/compiler-$copy"', ':'),
            ('if [[ "$compiler_family" == gnu ]]; then', 'if false; then'),
            ('--output "${compiler_root%/*}/gcc-checksum-inputs-${compiler_root##*/}.json"',
             '--output "$compiler_root/payload/evidence/gcc-checksum-inputs.json"'),
            ('exactly one generated GCC Makefile', 'take first generated GCC Makefile'),
        ):
            with self.subTest(original=original):
                documents = self.new_documents()
                qualifier = documents.text(QUALIFY)
                self.assertIn(original, qualifier)
                documents.set_text(QUALIFY, qualifier.replace(original, replacement, 1))
                with self.assertRaisesRegex(PolicyViolation, "checksum input observations"):
                    validate_v2_policy(documents)

    def test_rejects_widened_diagnostic_host_scope(self) -> None:
        documents = self.new_documents()
        route_script = documents.text(ROUTE)
        documents.set_text(ROUTE, route_script.replace(
            '("qualify-v2", "linux-x86_64")', '("qualify-v2", "linux")', 1,
        ))
        with self.assertRaisesRegex(PolicyViolation, "route selector must close"):
            validate_v2_policy(documents)

    def test_rejects_unbound_diagnostic_group_selector(self) -> None:
        documents = self.new_documents()
        workflow = documents.text(WORKFLOW)
        workflow = mutate_job(
            workflow,
            "v2-prepare",
            '"${group_arguments[@]}"',
            '""',
        )
        documents.set_text(WORKFLOW, workflow)
        with self.assertRaisesRegex(PolicyViolation, "optional diagnostic group"):
            validate_v2_policy(documents)

    def test_rejects_collapsed_original_compiler_owners(self) -> None:
        for before, after in (
            ("copy: ${{ matrix.copy }}", "copy: a"),
            ("root: ${{ runner.temp }}/native-lane-${{ matrix.copy }}", "root: ${{ runner.temp }}/native-lane"),
            ("if: needs.v2-prepare.outputs.full_matrix == 'true'", "if: inputs.mode == 'qualify-v2'"),
        ):
            with self.subTest(before=before):
                documents = self.new_documents()
                documents.set_text(WORKFLOW, mutate_job(documents.text(WORKFLOW), "v2-build", before, after))
                with self.assertRaisesRegex(PolicyViolation, "distinct original owning jobs"):
                    validate_v2_policy(documents)

    def test_rejects_sdk_without_original_owner_admission(self) -> None:
        for before, after in (
            ("needs: [v2-prepare, v2-sources, v2-runtimes, v2-build]", "needs: [v2-prepare, v2-sources, v2-runtimes]"),
            ("--owner-a-selection", "--unverified-a-selection"),
            ("--owner-b-selection", "--unverified-b-selection"),
            ("select-owner-artifacts-v2.py", "unverified-owner-selection.py"),
        ):
            with self.subTest(before=before):
                documents = self.new_documents()
                documents.set_text(WORKFLOW, mutate_job(documents.text(WORKFLOW), "v2-sdk", before, after))
                with self.assertRaisesRegex(PolicyViolation, "authenticate two distinct original compilers"):
                    validate_v2_policy(documents)

    def test_rejects_incomplete_sdk_owner_readback_graph(self) -> None:
        for before, after in (
            ("needs: [v2-prepare, v2-runtimes, v2-build, v2-sdk]", "needs: [v2-prepare, v2-runtimes, v2-build]"),
            ("if: needs.v2-prepare.outputs.full_matrix == 'true'", "if: inputs.mode == 'qualify-v2'"),
            ("collect-sdk-owners-v2.sh", "unverified-sdk-download.sh"),
            ("collect-compiler-owners-v2.sh", "unverified-compiler-download.sh"),
            ('--release-id "$SELECTED_RELEASE_ID"', '--release-id stale-candidate'),
            ('--job-name "$CURRENT_JOB" --same-attempt', '--job-name "$CURRENT_JOB"'),
        ):
            with self.subTest(before=before):
                documents = self.new_documents()
                documents.set_text(WORKFLOW, mutate_job(documents.text(WORKFLOW), "v2-readback", before, after))
                with self.assertRaisesRegex(PolicyViolation, "wait for every native owner"):
                    validate_v2_policy(documents)

    def test_rejects_disconnected_sdk_package_projection(self) -> None:
        for before, after in (
            ("python3 -B scripts/toolchain/select-sdk-package-inputs-v2.py", "python3 -B unreviewed.py"),
            ('--plan "$plan" --plan-sha256 "$plan_sha"', '--plan "$plan"'),
            ('--fragment "$fragment" --fragment-sha256 "$fragment_sha"', '--fragment "$fragment"'),
            ('--owner-root "$RUNNER_TEMP/complete-sdk-readback"', '--owner-root "$RUNNER_TEMP/other-owner"'),
            ('> "$package_inputs"', '> "$RUNNER_TEMP/unbound-sdk-package-inputs.json"'),
            ('package_inputs="$RUNNER_TEMP/sdk-package-inputs.json"',
             'package_inputs="$RUNNER_TEMP/diagnostic-inputs/sdk-package-inputs.json"'),
        ):
            with self.subTest(before=before):
                documents = self.new_documents()
                documents.set_text(WORKFLOW, mutate_job(documents.text(WORKFLOW), "v2-readback", before, after))
                with self.assertRaisesRegex(PolicyViolation, "SDK package projection"):
                    validate_v2_policy(documents)

    def test_rejects_unbound_fresh_native_readback_plan(self) -> None:
        for before, after in (
            ('"$runtime/bin/aros" toolchain producer release-plan',
             'unverified-aros toolchain producer release-plan'),
            ('--directory "$RUNNER_TEMP/diagnostic-inputs" --inputs-sha256 "$inputs_sha"',
             '--directory "$RUNNER_TEMP/other-inputs" --inputs-sha256 "$inputs_sha"'),
            ('--directory "$RUNNER_TEMP/diagnostic-inputs" --inputs-sha256 "$inputs_sha"',
             '--directory "$RUNNER_TEMP/diagnostic-inputs"'),
            ('set -C', 'set +C'),
        ):
            with self.subTest(before=before):
                documents = self.new_documents()
                documents.set_text(WORKFLOW, mutate_job(documents.text(WORKFLOW), "v2-readback", before, after))
                with self.assertRaisesRegex(PolicyViolation, "fresh native plan"):
                    validate_v2_policy(documents)

    def test_rejects_missing_candidate_attestation_write_permission(self) -> None:
        documents = self.new_documents()
        documents.set_text(WORKFLOW, mutate_job(
            documents.text(WORKFLOW), "v2-readback", "attestations: write", "attestations: read",
        ))
        with self.assertRaisesRegex(PolicyViolation, "non-publishing job scope"):
            validate_v2_policy(documents)

    def test_rejects_disconnected_compiler_candidate_assembly(self) -> None:
        for before, after in (
            ("python3 -B scripts/toolchain/assemble-release-candidate-v2.py", "python3 -B unreviewed.py"),
            ('--compiler-fragment "$compiler_fragment" --compiler-fragment-sha256 "$compiler_fragment_sha"',
             '--compiler-fragment "$compiler_fragment"'),
            ('--required-paths "$required_paths" --required-paths-sha256 "$required_paths_sha"',
             '--required-paths "$required_paths"'),
            ('--compiler-owner-root "$RUNNER_TEMP/complete-compiler-readback"',
             '--compiler-owner-root "$RUNNER_TEMP/complete-sdk-readback"'),
            ('candidate_summary="$RUNNER_TEMP/release-candidate-summary.json"',
             'candidate_summary="$RUNNER_TEMP/diagnostic-inputs/release-candidate-summary.json"'),
            ('--root "$RUNNER_TEMP/release-candidate" > "$candidate_summary"',
             '--root "$RUNNER_TEMP/other-candidate" > "$candidate_summary"'),
        ):
            with self.subTest(before=before):
                documents = self.new_documents()
                documents.set_text(WORKFLOW, mutate_job(documents.text(WORKFLOW), "v2-readback", before, after))
                with self.assertRaisesRegex(PolicyViolation, "combined candidate assembly"):
                    validate_v2_policy(documents)

    def test_rejects_manifest_derived_compiler_payload_policy(self) -> None:
        documents = self.new_documents()
        documents.set_text(WORKFLOW, mutate_job(
            documents.text(WORKFLOW), "v2-readback",
            'policy="$GITHUB_WORKSPACE/toolchains/compiler-required-payload-v1.json"',
            'policy="$RUNNER_TEMP/compiler-candidate/release/manifest.json"',
        ))
        with self.assertRaisesRegex(PolicyViolation, "independently selected policy"):
            validate_v2_policy(documents)

    def test_rejects_disconnected_sdk_candidate_assembly(self) -> None:
        assembler = "python3 -B scripts/toolchain/assemble-release-candidate-v2.py"
        for before, after in (
            ('--aros "$runtime/bin/aros" --aros-sha256 "$runtime_sha"',
             '--aros "$runtime/bin/aros"'),
            ('--plan "$plan" --plan-sha256 "$plan_sha"', '--plan "$plan"'),
            ('--sdk-fragment "$fragment" --sdk-fragment-sha256 "$fragment_sha"', '--sdk-fragment "$fragment"'),
            ('--sdk-owner-root "$RUNNER_TEMP/complete-sdk-readback"',
             '--sdk-owner-root "$RUNNER_TEMP/complete-compiler-readback"'),
            ('--root "$RUNNER_TEMP/release-candidate" > "$candidate_summary"',
             '--root "$RUNNER_TEMP/other-sdk-candidate" > "$candidate_summary"'),
        ):
            with self.subTest(before=before):
                documents = self.new_documents()
                workflow = documents.text(WORKFLOW)
                prefix, command = workflow.split(assembler, 1)
                self.assertIn(before, command)
                documents.set_text(WORKFLOW, prefix + assembler + command.replace(before, after, 1))
                with self.assertRaisesRegex(PolicyViolation, "combined candidate assembly"):
                    validate_v2_policy(documents)

    def test_later_sdk_call_cannot_mask_unbound_compiler_assembly(self) -> None:
        documents = self.new_documents()
        workflow = documents.text(WORKFLOW)
        assembler = "python3 -B scripts/toolchain/assemble-release-candidate-v2.py"
        prefix, command = workflow.split(assembler, 1)
        command = command.replace('--plan "$plan" --plan-sha256 "$plan_sha"', '--plan "$plan"', 1)
        command = command.replace('> "$candidate_summary"',
                                  '> "$candidate_summary"\n          echo --plan "$plan" --plan-sha256 "$plan_sha"', 1)
        documents.set_text(WORKFLOW, prefix + assembler + command)
        with self.assertRaisesRegex(PolicyViolation, "combined candidate assembly"):
            validate_v2_policy(documents)

    def test_rejects_unbound_or_producer_owned_support_fixtures(self) -> None:
        for before, after in (
            ('ref: ${{ needs.v2-prepare.outputs.tools_commit }}', 'ref: main'),
            ('support="$GITHUB_WORKSPACE/dependencies/aros-tools-fixtures/crates/aros-common/tests/fixtures"',
             'support="$GITHUB_WORKSPACE/toolchains"'),
            ('--manifest-schema-sha256 "$manifest_schema_sha"', '--manifest-schema-sha256 stale'),
            ('--tree-fixture-sha256 "$tree_fixture_sha"', '--tree-fixture-sha256 stale'),
        ):
            with self.subTest(before=before):
                documents = self.new_documents()
                documents.set_text(WORKFLOW, mutate_job(documents.text(WORKFLOW), "v2-readback", before, after))
                with self.assertRaisesRegex(PolicyViolation, "combined candidate"):
                    validate_v2_policy(documents)

    def test_rejects_disconnected_native_evidence_selection(self) -> None:
        for before, after in (
            ('python3 -B scripts/toolchain/select-native-release-evidence-v2.py', 'python3 -B unreviewed.py'),
            ('--compiler-lanes-sha256 "$compiler_lanes_sha"', '--compiler-lanes-sha256 stale'),
            ('--compiler-evidence-sha256 "$compiler_evidence_sha"', '--compiler-evidence-sha256 stale'),
            ('--index-sha256 "$candidate_index_sha"', '--index-sha256 stale'),
            ('candidate_index="$RUNNER_TEMP/release-candidate/release/toolchain-index-v2.json"',
             'candidate_index="$RUNNER_TEMP/unbound-index.json"'),
        ):
            with self.subTest(before=before):
                documents = self.new_documents()
                documents.set_text(WORKFLOW, mutate_job(documents.text(WORKFLOW), "v2-readback", before, after))
                with self.assertRaisesRegex(PolicyViolation, "native evidence selection"):
                    validate_v2_policy(documents)

    def test_rejects_disconnected_final_native_diagnostic(self) -> None:
        for before, after in (
            ('subject-checksums: ${{ runner.temp }}/release-candidate/subject-manifest.json', 'subject-checksums: unbound.sha256'),
            ('--source-digest "$GITHUB_SHA" --source-ref "$GITHUB_REF"', '--source-digest "$GITHUB_SHA" --source-ref refs/tags/fake'),
            ('--run-id "$GITHUB_RUN_ID" --run-attempt "$GITHUB_RUN_ATTEMPT"', '--run-id "$GITHUB_RUN_ID"'),
            ('--selection-sha256 "$EXPECTED_SELECTION_SHA"', '--selection-sha256 stale'),
            ('--subject-manifest-sha256 "$EXPECTED_SUBJECT_SHA"', '--subject-manifest-sha256 stale'),
            ('"$runtime" toolchain producer verify-release-evidence', '"$runtime" toolchain producer record-qualification'),
            ('--stage final --format json', '--stage pre-attestation --format json'),
            ('($selected[0].lanes | keys | sort)', '[]'),
            ('([$selected[0].sdk_generations[] | [.sdk_id,.group_id,.target_profile,.host]] | sort)', '[]'),
        ):
            with self.subTest(before=before):
                documents = self.new_documents()
                documents.set_text(WORKFLOW, mutate_job(documents.text(WORKFLOW), "v2-readback", before, after))
                with self.assertRaisesRegex(PolicyViolation, "final (diagnostic|native)"):
                    validate_v2_policy(documents)

    def test_rejects_missing_development_runtime_helper(self) -> None:
        documents = self.new_documents()
        documents.overrides[ACTION] = None
        with self.assertRaisesRegex(PolicyViolation, "missing"):
            validate_v2_policy(documents)

    def test_rejects_tools_pin_drift(self) -> None:
        documents = self.new_documents()
        selection = documents.json(SELECTION)
        selection["tools_commit"] = "0" * 40
        documents.set_json(SELECTION, selection)
        with self.assertRaisesRegex(PolicyViolation, "tools pin"):
            validate_v2_policy(documents)

    def test_rejects_selected_ports_lock_drift(self) -> None:
        documents = self.new_documents()
        selection = documents.json(SELECTION)
        selection["groups"][0]["ports_lock"] = "toolchains/compatibility-ports-v3.json"
        documents.set_json(SELECTION, selection)
        with self.assertRaisesRegex(PolicyViolation, "ports lock"):
            validate_v2_policy(documents)

    def test_rejects_executor_manifest_digest_drift(self) -> None:
        documents = self.new_documents()
        executor_text = documents.text(EXECUTOR)
        executor = tomllib.loads(executor_text)
        digest = executor["groups"][0]["profiles_sha256"]
        self.assertIsInstance(digest, str)
        self.assertIn(digest, executor_text)
        documents.set_text(
            EXECUTOR,
            executor_text.replace(
                f'profiles_sha256 = "{digest}"',
                f'profiles_sha256 = "{"0" * 64}"',
                1,
            ),
        )
        with self.assertRaisesRegex(PolicyViolation, "document digest"):
            validate_v2_policy(documents)

    def test_rejects_source_pin_drift_against_profiles_and_ports(self) -> None:
        documents = self.new_documents()
        selection = documents.json(SELECTION)
        selection["source_commit"] = "0" * 40
        documents.set_json(SELECTION, selection)
        with self.assertRaisesRegex(PolicyViolation, "source pin"):
            validate_v2_policy(documents)


if __name__ == "__main__":
    unittest.main()
