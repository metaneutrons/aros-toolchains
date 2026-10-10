#!/usr/bin/env python3
"""Project a native, input-bound release plan onto reviewed Actions runners.

This is scheduling policy, not another producer. The verified aros executable
owns recipes, profile semantics, package inventories and qualification. Nothing
here authenticates the executable, admits an artifact or authorizes publication.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import time


MAX_JSON_BYTES = 1024 * 1024
HOSTS = {"linux-aarch64", "linux-x86_64", "macos-aarch64"}
PLAN_FIELDS = {"schema", "operation", "release_format", "assurance", "inputs_sha256",
               "producer_commit", "tools_commit", "hosts", "groups", "lane_count", "lanes"}
GROUP_FIELDS = {"group_id", "source_commit", "source_tree", "upstream_commit",
                "recipe", "source_lock", "profiles"}


class ContractError(Exception):
    """Scheduling inputs violate the reviewed contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def fields(value: object, expected: set[str], label: str) -> dict:
    require(isinstance(value, dict) and set(value) == expected,
            f"{label} has unexpected fields")
    return value


def hexadecimal(value: object, length: int, label: str) -> str:
    require(isinstance(value, str) and re.fullmatch(f"[0-9a-f]{{{length}}}", value) is not None,
            f"{label} must be lowercase hexadecimal")
    return value


def identifier(value: object, label: str) -> str:
    require(isinstance(value, str) and re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", value) is not None,
            f"{label} must be a safe identifier")
    return value


def unique_strings(value: object, label: str) -> list[str]:
    require(isinstance(value, list) and bool(value) and len(value) <= 256,
            f"{label} must be a bounded nonempty list")
    for item in value:
        identifier(item, label)
    require(len(set(value)) == len(value), f"{label} contains duplicates")
    return value


def decode(raw: bytes) -> object:
    require(len(raw) <= MAX_JSON_BYTES, "JSON exceeds the scheduling size limit")

    def pairs(items: list[tuple[str, object]]) -> dict:
        result = {}
        for key, value in items:
            require(key not in result, "JSON contains a duplicate key")
            result[key] = value
        return result

    def nonfinite(_value: str) -> object:
        raise ContractError("JSON contains a nonfinite number")

    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=nonfinite)
    except (UnicodeDecodeError, ValueError, RecursionError) as error:
        raise ContractError("invalid scheduling JSON") from error


def read_json(path: Path, expected_sha256: str | None = None) -> object:
    require(path.is_absolute(), "input path must be absolute")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        require(stat.S_ISREG(os.fstat(descriptor).st_mode), "input must be a regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(MAX_JSON_BYTES + 1)
        if expected_sha256 is not None:
            hexadecimal(expected_sha256, 64, "policy digest")
            require(hashlib.sha256(raw).hexdigest() == expected_sha256,
                    "policy differs from the independently selected digest")
        return decode(raw)
    finally:
        os.close(descriptor)


def project(plan: object, policy: object, *, inputs_sha256: str,
            producer_commit: str, tools_commit: str, scope: str) -> dict:
    hexadecimal(inputs_sha256, 64, "input digest")
    hexadecimal(producer_commit, 40, "producer commit")
    hexadecimal(tools_commit, 40, "tools commit")
    require(scope in {"all", "linux", "linux-x86_64"}, "unsupported diagnostic scope")
    policy = fields(policy, {"schema", "hosts", "groups"}, "policy")
    require(policy["schema"] == "aros-toolchain-workflow-policy-v2", "unsupported policy schema")
    runners = policy["hosts"]
    require(isinstance(runners, dict) and set(runners) == HOSTS,
            "policy must select exactly the three supported release hosts")
    for runner in runners.values():
        require(isinstance(runner, str) and
                re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,63}", runner) is not None,
                "runner must be a safe reviewed label")
    approved = policy["groups"]
    require(isinstance(approved, dict) and 0 < len(approved) <= 32, "invalid policy groups")
    all_profiles = []
    for group_id, profiles in approved.items():
        identifier(group_id, "policy group")
        all_profiles.extend(unique_strings(profiles, "policy profiles"))
    require(len(set(all_profiles)) == len(all_profiles), "policy repeats a target profile")

    plan = fields(plan, PLAN_FIELDS, "native plan")
    require((plan["schema"], plan["operation"], plan["release_format"], plan["assurance"]) ==
            ("aros-toolchain-producer-stage-v2", "release-plan", "family-v2", "input-binding-only"),
            "native plan has unsupported semantics or assurance")
    require(plan["inputs_sha256"] == inputs_sha256, "native plan input digest differs")
    require(plan["producer_commit"] == producer_commit, "native plan producer commit differs")
    require(plan["tools_commit"] == tools_commit, "native plan tools commit differs")
    require(set(unique_strings(plan["hosts"], "native hosts")) == set(runners),
            "native hosts differ from reviewed policy")
    require(isinstance(plan["groups"], list) and len(plan["groups"]) == len(approved),
            "native groups differ from reviewed policy")
    groups = {}
    documents = set()
    for item in plan["groups"]:
        item = fields(item, GROUP_FIELDS, "native group")
        group_id = identifier(item["group_id"], "native group")
        require(group_id in approved and group_id not in groups,
                "native group is unreviewed or duplicated")
        for key in ("source_commit", "source_tree", "upstream_commit"):
            hexadecimal(item[key], 40, key)
        for key in ("recipe", "source_lock", "profiles"):
            ref = fields(item[key], {"file", "sha256"}, "document reference")
            name = ref["file"]
            require(isinstance(name, str) and
                    re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,127}", name) is not None and
                    name not in documents, "document name is unsafe or duplicated")
            hexadecimal(ref["sha256"], 64, "document digest")
            documents.add(name)
        groups[group_id] = item
    expected = {(group_id, host, profile) for group_id, profiles in approved.items()
                for host in runners for profile in profiles}
    require(0 < len(expected) <= 128, "A/B matrix exceeds the Actions job limit")
    require(type(plan["lane_count"]) is int and plan["lane_count"] == len(expected),
            "native lane count differs from reviewed policy")
    require(isinstance(plan["lanes"], list) and len(plan["lanes"]) == len(expected),
            "native lanes differ from reviewed policy")
    actual = set()
    for lane in plan["lanes"]:
        lane = fields(lane, {"group_id", "host", "target_profile"}, "native lane")
        triple = tuple(identifier(lane[key], "native lane")
                       for key in ("group_id", "host", "target_profile"))
        require(triple in expected and triple not in actual,
                "native lane is unreviewed or duplicated")
        actual.add(triple)
    require(actual == expected, "native matrix is incomplete")
    selected_hosts = sorted(host for host in runners if scope == "all" or
                            (scope == "linux" and host.startswith("linux-")) or host == scope)
    verify = []
    for group_id, host, profile in sorted(actual):
        if host in selected_hosts:
            verify.append({**groups[group_id], "host": host, "runner": runners[host],
                           "profile": profile})
    build = [{**lane, "copy": copy} for lane in verify for copy in ("a", "b")]
    return {"schema": "aros-toolchain-workflow-matrix-v2", "assurance": "scheduling-only",
            "scope": scope, "complete_lane_count": len(expected),
            "selected_lane_count": len(verify), "build_count": len(build),
            "host_matrix": {"include": [{"host": host, "runner": runners[host]}
                                        for host in selected_hosts]},
            "group_matrix": {"include": [groups[key] for key in sorted(groups)]},
            "verify_matrix": {"include": verify}, "build_matrix": {"include": build}}


def native_plan(aros: Path, directory: Path, inputs_sha256: str) -> object:
    require(aros.is_absolute() and directory.is_absolute(), "native paths must be absolute")
    require(aros.is_file() and not aros.is_symlink() and os.access(aros, os.X_OK),
            "native executable must be a regular executable")
    hexadecimal(inputs_sha256, 64, "input digest")
    command = [str(aros), "--diagnostic-format=json", "toolchain", "producer", "release-plan",
               "--directory", str(directory), "--inputs-sha256", inputs_sha256, "--format", "json"]
    # Do not echo native diagnostics into Actions outputs. Bound stdout and time;
    # the calling workflow separately authenticates the selected release binary.
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          start_new_session=True) as process:
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        raw = bytearray()
        deadline = time.monotonic() + 60
        try:
            while selector.get_map():
                remaining = deadline - time.monotonic()
                require(remaining > 0, "native release plan timed out")
                for key, _event in selector.select(min(remaining, 1)):
                    block = os.read(key.fd, 65536)
                    if not block:
                        selector.unregister(key.fileobj)
                        continue
                    raw.extend(block)
                    require(len(raw) <= MAX_JSON_BYTES, "native plan exceeds the scheduling size limit")
            require(process.wait(timeout=max(0.001, deadline - time.monotonic())) == 0,
                    "native release plan rejected the collection")
            return decode(bytes(raw))
        finally:
            selector.close()
            # Also terminate inherited pipe holders on contract failure.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--aros", type=Path, required=True)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--inputs-sha256", required=True)
    parser.add_argument("--producer-commit", required=True)
    parser.add_argument("--tools-commit", required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--policy-sha256", required=True)
    parser.add_argument("--scope", choices=("all", "linux", "linux-x86_64"), required=True)
    args = parser.parse_args()
    try:
        policy = read_json(args.policy, args.policy_sha256)
        plan = native_plan(args.aros, args.directory, args.inputs_sha256)
        output = project(plan, policy, inputs_sha256=args.inputs_sha256,
                         producer_commit=args.producer_commit, tools_commit=args.tools_commit,
                         scope=args.scope)
        print(json.dumps(output, sort_keys=True, separators=(",", ":")))
        return 0
    except (ContractError, OSError, subprocess.SubprocessError):
        print("release matrix rejected: invalid native plan, policy or independently selected binding",
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
