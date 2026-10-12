#!/usr/bin/env python3
"""Project a validated producer release plan into bounded CI matrices.

This helper does not validate collection documents or qualify builds. Its
input must be the exact JSON output of ``aros toolchain producer release-plan``.
SDK selections stay host-independent; the workflow chooses their runner.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any


MAX_PLAN_BYTES = 1024 * 1024
MAX_GROUPS = 32
MAX_SDKS = 32
MAX_SDK_COMPILER_PROFILES = 64
MAX_BUILD_ENTRIES = 256
ACTIVE_HOSTS = ("linux-aarch64", "linux-x86_64", "macos-aarch64")
RUNNERS = {
    "linux-aarch64": "ubuntu-24.04-arm",
    "linux-x86_64": "ubuntu-24.04",
    "macos-aarch64": "macos-15",
}
TOP_LEVEL_FIELDS = {
    "schema",
    "operation",
    "release_format",
    "assurance",
    "inputs_sha256",
    "producer_commit",
    "tools_commit",
    "hosts",
    "groups",
    "lane_count",
    "lanes",
    "sdks",
    "sdk_count",
}
GROUP_FIELDS = {
    "group_id",
    "source_commit",
    "source_tree",
    "upstream_commit",
    "recipe",
    "source_lock",
    "profiles",
}
REFERENCE_FIELDS = {"file", "sha256"}
LANE_FIELDS = {"group_id", "host", "target_profile"}
SDK_FIELDS = {"id", "identity", "source_preset", "compiler_profiles"}
SDK_COMPILER_PROFILE_FIELDS = {"group_id", "profile"}
RESERVED_FILES = {
    "SHA256SUMS",
    "toolchain-index-v1.json",
    "toolchain-index-v2.json",
    "toolchain-release-inputs-v2.json",
    "toolchain-provenance.sigstore.json",
    "toolchain-recipe-v2.json",
    "profiles-v1.json",
    "toolchain-manifest-v1.schema.json",
    "toolchain-manifest-v2.schema.json",
    "tree-digest-v1.fixture.json",
}
LOWER_HEX_40 = re.compile(r"[0-9a-f]{40}\Z")
LOWER_HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
SAFE_ID = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?\Z")
SAFE_PROFILE = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
SAFE_SDK_ID = re.compile(r"[a-z0-9](?:[-._+a-z0-9]{0,94}[a-z0-9])?\Z")
SAFE_SDK_PROFILE = re.compile(r"[a-z0-9](?:[-_a-z0-9]{0,126}[a-z0-9])?\Z")
SAFE_FILE = re.compile(r"[a-z0-9_-]+(?:\.[a-z0-9_-]+)*\.json\Z")


class PlanError(ValueError):
    """The plan or requested projection violates the closed contract."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PlanError("plan contains a duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise PlanError("plan contains a non-JSON numeric constant")


def _read_regular_no_follow(path: Path, limit: int, description: str) -> tuple[bytes, tuple[int, int]]:
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise PlanError("this platform cannot safely open files without following symlinks")
    flags = os.O_RDONLY | no_follow | getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise PlanError(f"cannot safely open {description}") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise PlanError(f"{description} is not a bounded regular file")
        content = bytearray()
        while len(content) <= limit:
            block = os.read(descriptor, min(65536, limit + 1 - len(content)))
            if not block:
                break
            content.extend(block)
        if len(content) > limit:
            raise PlanError(f"{description} exceeds the size limit")
        after = os.fstat(descriptor)
        if (
            before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or len(content) != after.st_size
        ):
            raise PlanError(f"{description} changed while being read")
        return bytes(content), (before.st_dev, before.st_ino)
    finally:
        os.close(descriptor)


def _read_plan(path: Path) -> tuple[bytes, dict[str, Any], tuple[int, int]]:
    raw, identity = _read_regular_no_follow(path, MAX_PLAN_BYTES, "plan")
    try:
        decoded = raw.decode("utf-8")
        value = json.loads(
            decoded,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise PlanError("plan is not valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise PlanError("plan must be a JSON object")
    return raw, value, identity


def _require_exact_fields(value: Any, expected: set[str], description: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise PlanError(f"{description} has missing, unknown, or invalid fields")
    return value


def _require_digest(value: Any, description: str) -> str:
    if not isinstance(value, str) or LOWER_HEX_64.fullmatch(value) is None:
        raise PlanError(f"{description} must be a lowercase SHA-256 digest")
    return value


def _require_commit(value: Any, description: str) -> str:
    if not isinstance(value, str) or LOWER_HEX_40.fullmatch(value) is None:
        raise PlanError(f"{description} must be a lowercase Git object ID")
    return value


def _require_safe_id(value: Any, description: str) -> str:
    if not isinstance(value, str) or SAFE_ID.fullmatch(value) is None:
        raise PlanError(f"{description} is not a safe identifier")
    return value


def _require_profile_id(value: Any) -> str:
    if (
        not isinstance(value, str)
        or SAFE_PROFILE.fullmatch(value) is None
        or value in {".", ".."}
    ):
        raise PlanError("target profile ID is not a safe native profile identifier")
    return value


def _require_sdk_id(value: Any) -> str:
    if not isinstance(value, str) or SAFE_SDK_ID.fullmatch(value) is None:
        raise PlanError("SDK ID is not a safe native SDK identifier")
    return value


def _require_sdk_profile_id(value: Any, description: str) -> str:
    if not isinstance(value, str) or SAFE_SDK_PROFILE.fullmatch(value) is None:
        raise PlanError(f"{description} is not a safe native SDK profile identifier")
    return value


def _validate_reference(value: Any, used_names: set[str]) -> None:
    reference = _require_exact_fields(value, REFERENCE_FIELDS, "document reference")
    filename = reference["file"]
    if (
        not isinstance(filename, str)
        or len(filename.encode("utf-8")) > 128
        or filename.startswith(".")
        or SAFE_FILE.fullmatch(filename) is None
        or filename in RESERVED_FILES
    ):
        raise PlanError("document reference filename is unsafe or reserved")
    if filename in used_names:
        raise PlanError("document reference filenames must be unique")
    used_names.add(filename)
    _require_digest(reference["sha256"], "document reference digest")


def _validate_plan(
    plan: dict[str, Any],
    *,
    expected_inputs_sha256: str,
    expected_producer_commit: str,
    expected_tools_commit: str,
) -> tuple[list[dict[str, str]], list[str], int, list[dict[str, Any]]]:
    value = _require_exact_fields(plan, TOP_LEVEL_FIELDS, "plan")
    if value["schema"] != "aros-toolchain-producer-stage-v2":
        raise PlanError("plan schema is unsupported")
    if value["operation"] != "release-plan" or value["release_format"] != "family-v2":
        raise PlanError("plan operation or release format is unsupported")
    if value["assurance"] != "input-binding-only":
        raise PlanError("plan assurance is unsupported")

    inputs_sha256 = _require_digest(value["inputs_sha256"], "plan inputs digest")
    producer_commit = _require_commit(value["producer_commit"], "plan producer commit")
    tools_commit = _require_commit(value["tools_commit"], "plan tools commit")
    if inputs_sha256 != expected_inputs_sha256:
        raise PlanError("plan differs from the independently selected inputs digest")
    if producer_commit != expected_producer_commit or tools_commit != expected_tools_commit:
        raise PlanError("plan commits differ from independently selected commits")

    hosts = value["hosts"]
    if not isinstance(hosts, list) or hosts != list(ACTIVE_HOSTS):
        raise PlanError("plan hosts do not equal the sorted active host set")

    groups = value["groups"]
    if not isinstance(groups, list) or not 1 <= len(groups) <= MAX_GROUPS:
        raise PlanError("plan requires 1..32 groups")
    group_ids: list[str] = []
    used_files: set[str] = set()
    for group_value in groups:
        group = _require_exact_fields(group_value, GROUP_FIELDS, "group")
        group_id = _require_safe_id(group["group_id"], "group ID")
        group_ids.append(group_id)
        source_commit = _require_commit(group["source_commit"], "source commit")
        _require_commit(group["source_tree"], "source tree")
        upstream_commit = _require_commit(group["upstream_commit"], "upstream commit")
        if source_commit != upstream_commit:
            raise PlanError("group source and upstream commits differ")
        for field in ("recipe", "source_lock", "profiles"):
            _validate_reference(group[field], used_files)
    if group_ids != sorted(set(group_ids)):
        raise PlanError("group IDs must be sorted and unique")

    lanes_value = value["lanes"]
    if not isinstance(lanes_value, list) or not lanes_value:
        raise PlanError("plan lanes must be a nonempty array")
    lane_count = value["lane_count"]
    if type(lane_count) is not int or lane_count != len(lanes_value):
        raise PlanError("plan lane count does not match the lane array")

    lanes: list[dict[str, str]] = []
    profiles_by_group: dict[str, list[str]] = {group_id: [] for group_id in group_ids}
    profile_owners: dict[str, str] = {}
    previous_key: tuple[int, int, int] | None = None
    group_rank = {group_id: index for index, group_id in enumerate(group_ids)}
    host_rank = {host: index for index, host in enumerate(ACTIVE_HOSTS)}
    seen_lanes: set[tuple[str, str, str]] = set()
    for lane_value in lanes_value:
        lane = _require_exact_fields(lane_value, LANE_FIELDS, "lane")
        group_id = _require_safe_id(lane["group_id"], "lane group ID")
        host = lane["host"]
        if group_id not in group_rank:
            raise PlanError("lane refers to an unknown group")
        if not isinstance(host, str) or host not in host_rank:
            raise PlanError("lane refers to an unknown host")
        profile = _require_profile_id(lane["target_profile"])
        lane_key = (group_id, host, profile)
        if lane_key in seen_lanes:
            raise PlanError("plan contains a duplicate lane")
        seen_lanes.add(lane_key)
        profile_owner = profile_owners.setdefault(profile, group_id)
        if profile_owner != group_id:
            raise PlanError("target profile IDs must have one group owner")
        if profile not in profiles_by_group[group_id]:
            profiles_by_group[group_id].append(profile)
        # The producer emits groups in group order, each declared profile in
        # profiles-document order, and that profile crossed with sorted hosts.
        # Profile document order is producer-owned and need not be lexical.
        key = (group_rank[group_id], profiles_by_group[group_id].index(profile), host_rank[host])
        if previous_key is not None and key <= previous_key:
            raise PlanError("plan lanes are not sorted in producer order")
        previous_key = key
        lanes.append({"group_id": group_id, "host": host, "target_profile": profile})

    for group_id, profile_ids in profiles_by_group.items():
        if not profile_ids:
            raise PlanError("every group must declare at least one profile lane")
        for profile in profile_ids:
            actual_hosts = [
                lane["host"]
                for lane in lanes
                if lane["group_id"] == group_id and lane["target_profile"] == profile
            ]
            if actual_hosts != list(ACTIVE_HOSTS):
                raise PlanError("each declared profile must be crossed with every active host")

    sdk_count = value["sdk_count"]
    sdk_values = value["sdks"]
    if (
        type(sdk_count) is not int
        or sdk_count < 0
        or sdk_count > MAX_SDKS
        or not isinstance(sdk_values, list)
        or sdk_count != len(sdk_values)
    ):
        raise PlanError("SDK count must match the 0..32 SDK array")

    previous_sdk_id: str | None = None
    for sdk_value in sdk_values:
        sdk = _require_exact_fields(sdk_value, SDK_FIELDS, "SDK selection")
        sdk_id = _require_sdk_id(sdk["id"])
        if previous_sdk_id is not None and sdk_id <= previous_sdk_id:
            raise PlanError("SDK IDs must be sorted and unique")
        previous_sdk_id = sdk_id
        _validate_reference(sdk["identity"], used_files)
        _require_sdk_profile_id(sdk["source_preset"], "SDK source preset")

        compiler_profiles = sdk["compiler_profiles"]
        if (
            not isinstance(compiler_profiles, list)
            or not 1 <= len(compiler_profiles) <= MAX_SDK_COMPILER_PROFILES
        ):
            raise PlanError("each SDK requires 1..64 compiler profile references")
        profile_references: list[tuple[str, str]] = []
        for profile_value in compiler_profiles:
            profile_reference = _require_exact_fields(
                profile_value, SDK_COMPILER_PROFILE_FIELDS, "SDK compiler profile reference"
            )
            group_id = _require_safe_id(profile_reference["group_id"], "SDK compiler group ID")
            profile = _require_sdk_profile_id(
                profile_reference["profile"], "SDK compiler profile"
            )
            if group_id not in profiles_by_group or profile not in profiles_by_group[group_id]:
                raise PlanError("SDK compiler profile does not match a declared group/profile")
            profile_references.append((group_id, profile))
        if profile_references != sorted(set(profile_references)):
            raise PlanError("SDK compiler profile references must be sorted and unique")

    return lanes, group_ids, lane_count, sdk_values


def _select_scope(event: str, scope: str) -> set[str]:
    if event not in {"push", "workflow_dispatch"} or scope not in {"full", "linux-x86_64", "linux"}:
        raise PlanError("event or scope is unsupported")
    if event == "push" and scope != "full":
        raise PlanError("push events require the complete scope")
    if event == "workflow_dispatch" and scope == "full":
        raise PlanError("manual dispatch cannot select the complete scope")
    if scope == "full":
        return set(ACTIVE_HOSTS)
    if scope == "linux-x86_64":
        return {"linux-x86_64"}
    return {"linux-aarch64", "linux-x86_64"}


def project(
    *,
    raw: bytes,
    plan: dict[str, Any],
    plan_sha256: str,
    inputs_sha256: str,
    producer_commit: str,
    tools_commit: str,
    event: str,
    scope: str,
) -> dict[str, Any]:
    actual_plan_sha256 = hashlib.sha256(raw).hexdigest()
    if _require_digest(plan_sha256, "selected plan digest") != actual_plan_sha256:
        raise PlanError("plan bytes do not match the selected plan digest")
    expected_inputs_sha256 = _require_digest(inputs_sha256, "selected inputs digest")
    expected_producer_commit = _require_commit(producer_commit, "selected producer commit")
    expected_tools_commit = _require_commit(tools_commit, "selected tools commit")
    lanes, _group_ids, owner_lane_count, sdks = _validate_plan(
        plan,
        expected_inputs_sha256=expected_inputs_sha256,
        expected_producer_commit=expected_producer_commit,
        expected_tools_commit=expected_tools_commit,
    )
    selected_hosts = _select_scope(event, scope)
    selected_lanes = [lane for lane in lanes if lane["host"] in selected_hosts]
    hosts = [host for host in ACTIVE_HOSTS if host in selected_hosts]
    host_entries = [{"host": host, "runner": RUNNERS[host]} for host in hosts]
    verify_entries = [
        {
            "group_id": lane["group_id"],
            "host": lane["host"],
            "runner": RUNNERS[lane["host"]],
            "profile": lane["target_profile"],
        }
        for lane in selected_lanes
    ]
    build_entries = [
        {**entry, "copy": copy}
        for entry in verify_entries
        for copy in ("a", "b")
    ]
    if len(build_entries) > MAX_BUILD_ENTRIES:
        raise PlanError("projected build matrix exceeds 256 entries")
    if len(selected_lanes) > owner_lane_count:
        raise PlanError("projected lane count exceeds the validated owner lane count")
    return {
        "schema": "aros-toolchain-producer-release-matrix-v2",
        "assurance": "scheduling-only",
        "inputs_sha256": expected_inputs_sha256,
        "plan_sha256": actual_plan_sha256,
        "producer_commit": expected_producer_commit,
        "tools_commit": expected_tools_commit,
        "event": event,
        "scope": scope,
        "complete_selection": scope == "full",
        "host_matrix": {"include": host_entries},
        "verify_matrix": {"include": verify_entries},
        "build_matrix": {"include": build_entries},
        "sdk_matrix": {"include": sdks},
        "build_count": len(build_entries),
        "lane_count": len(verify_entries),
        "sdk_count": len(sdks),
    }


def _github_output_lines(result: dict[str, Any]) -> str:
    keys = (
        ("host_matrix", "host_matrix"),
        ("verify_matrix", "verify_matrix"),
        ("build_matrix", "build_matrix"),
        ("sdk_matrix", "sdk_matrix"),
    )
    lines = [
        f"{name}={json.dumps(result[field], separators=(',', ':'), ensure_ascii=True)}"
        for name, field in keys
    ]
    for field in ("lane_count", "build_count", "sdk_count"):
        lines.append(f"{field}={result[field]}")
    for field in ("plan_sha256", "inputs_sha256", "producer_commit", "tools_commit"):
        lines.append(f"{field}={result[field]}")
    return "\n".join(lines) + "\n"


def _append_regular_no_follow(path: Path, content: bytes, plan_identity: tuple[int, int]) -> None:
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise PlanError("this platform cannot safely open files without following symlinks")
    flags = os.O_WRONLY | os.O_APPEND | no_follow
    flags |= getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise PlanError("cannot safely open GitHub output") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise PlanError("GitHub output must be an existing regular file")
        if (metadata.st_dev, metadata.st_ino) == plan_identity:
            raise PlanError("GitHub output must not alias the selected plan")
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise PlanError("cannot write GitHub output")
            view = view[written:]
    except OSError as error:
        raise PlanError("cannot write GitHub output") from error
    finally:
        os.close(descriptor)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--plan-sha256", required=True)
    parser.add_argument("--inputs-sha256", required=True)
    parser.add_argument("--producer-commit", required=True)
    parser.add_argument("--tools-commit", required=True)
    parser.add_argument("--event", required=True, choices=("push", "workflow_dispatch"))
    parser.add_argument("--scope", required=True, choices=("full", "linux-x86_64", "linux"))
    parser.add_argument("--github-output", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        raw, plan, plan_identity = _read_plan(args.plan)
        result = project(
            raw=raw,
            plan=plan,
            plan_sha256=args.plan_sha256,
            inputs_sha256=args.inputs_sha256,
            producer_commit=args.producer_commit,
            tools_commit=args.tools_commit,
            event=args.event,
            scope=args.scope,
        )
        if args.github_output is not None:
            _append_regular_no_follow(
                args.github_output, _github_output_lines(result).encode("utf-8"), plan_identity
            )
        sys.stdout.write(json.dumps(result, separators=(",", ":"), ensure_ascii=True) + "\n")
        return 0
    except (OSError, PlanError, UnicodeError) as error:
        sys.stderr.write(f"release matrix selection failed: {error}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
