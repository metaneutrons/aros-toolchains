#!/usr/bin/env python3
"""Audit the non-publishing compiler/SDK V2 workflow and its selected inputs.

The checks intentionally use only the Python standard library.  Workflow
policy is inspected from the repository documents and then exercised against
small in-memory mutations so widening the diagnostic graph fails closed.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tomllib
import unittest
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = ".github/workflows/toolchain-release.yml"
ACTION = ".github/actions/materialize-development-aros-tools/action.yml"
PREPARE = "scripts/toolchain/prepare-compiler-sdk-inputs-v2.py"
QUALIFY = "scripts/toolchain/qualify-compiler-sdk-lane-v2.sh"
MATRIX = "scripts/toolchain/select-release-matrix-v2.py"
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
                permissions.append(lines[cursor].strip())
                cursor += 1
            break
    expected_permissions = ["contents: read"]
    if name == "v2-qualify":
        expected_permissions += ["actions: read", "id-token: write", "attestations: write"]
    if permissions != expected_permissions:
        raise PolicyViolation(f"{name} permissions must exactly match its non-publishing job scope")
    if re.search(r"(?m)^\s*environment:", job):
        raise PolicyViolation(f"{name} must not use a publication environment")
    if re.search(r"\bsecrets\.", job) or "GH_TOKEN" in job or "GITHUB_TOKEN" in job:
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


def validate_v2_policy(documents: Documents) -> dict[str, int]:
    workflow = documents.text(WORKFLOW)
    action = documents.text(ACTION)
    prepare_script = documents.text(PREPARE)
    qualify_script = documents.text(QUALIFY)
    matrix_script = documents.text(MATRIX)

    require("- qualify-v2" in workflow, "workflow_dispatch must expose qualify-v2 mode")
    names = job_names(workflow)
    v2_names = {name for name in names if name.startswith("v2-")}
    expected_names = {"v2-prepare", "v2-sources", "v2-qualify"}
    require(v2_names == expected_names, "workflow V2 diagnostic job set is not closed")
    prepare = workflow_job(workflow, "v2-prepare")
    sources = workflow_job(workflow, "v2-sources")
    qualify = workflow_job(workflow, "v2-qualify")
    for name, job in (("v2-prepare", prepare), ("v2-sources", sources), ("v2-qualify", qualify)):
        require_read_only_job(job, name)
        require(re.search(r"(?m)^    timeout-minutes: [1-9][0-9]*$", job) is not None,
                f"{name} must have a bounded job timeout")

    require(
        "if: github.event_name == 'workflow_dispatch' && inputs.mode == 'qualify-v2'" in prepare,
        "V2 preparation must run only for an explicit qualify-v2 dispatch",
    )
    require(
        '[[ "$GITHUB_EVENT_NAME" == workflow_dispatch && "$GITHUB_REF_TYPE" == branch ]]' in prepare,
        "V2 diagnostics must reject tag and non-dispatch refs",
    )
    require(
        '[[ "$REQUESTED_SCOPE" == linux-x86_64 ]]' in prepare,
        "V2 diagnostics must remain scoped to Linux x86-64",
    )
    require("uses: ./.github/actions/materialize-development-aros-tools" in prepare,
            "V2 preparation must use the local development-only tools helper")
    require("needs: v2-prepare" in sources, "V2 source preparation must depend on V2 preparation")
    require(
        "needs: [v2-prepare, v2-sources]" in qualify,
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
        "inputs.mode != 'qualify-v2'" in plan,
        "diagnostic dispatch must not enter the legacy release graph",
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
        and "--event workflow_dispatch --scope linux-x86_64" in prepare,
        "V2 matrix preparation must use the native plan and x86-64 scope selector",
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
        and 'gcc-checksum-inputs.json' in qualify_script
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
        "development tools helper must build only the clean, selected Linux dispatch checkout",
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
    def new_documents(self) -> Documents:
        return Documents()

    def test_current_diagnostic_workflow_and_selected_documents_are_coherent(self) -> None:
        result = validate_v2_policy(self.new_documents())
        selection = Documents().json(SELECTION)
        self.assertEqual(result["group_count"], len(selection["groups"]))
        self.assertEqual(result["sdk_count"], len(selection["sdks"]))

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
            ('gcc-checksum-inputs.json', 'unselected.json'),
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
        workflow = documents.text(WORKFLOW)
        workflow = mutate_job(
            workflow,
            "v2-prepare",
            '[[ "$REQUESTED_SCOPE" == linux-x86_64 ]]',
            '[[ "$REQUESTED_SCOPE" == linux || "$REQUESTED_SCOPE" == linux-x86_64 ]]',
        )
        documents.set_text(WORKFLOW, workflow)
        with self.assertRaisesRegex(PolicyViolation, "Linux x86-64"):
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
