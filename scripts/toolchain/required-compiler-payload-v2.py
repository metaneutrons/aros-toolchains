#!/usr/bin/env python3
"""Select required compiler payload paths for a fully bound native release plan.

The result is a path selection only. This helper does not read packages,
indexes, manifests, or payload files and makes no release qualification claim.
"""

import sys

# Disable caching before loading either standard-library or sibling modules.
_ORIGINAL_BYTECODE_POLICY = sys.dont_write_bytecode
sys.dont_write_bytecode = True

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
from typing import Any



MAX_POLICY_BYTES = 1024 * 1024
MAX_POLICY_GROUPS = 32
MAX_PROFILES_PER_GROUP = 64
MAX_TOTAL_PROFILES = 128
MAX_PATHS_PER_PROFILE = 256
MAX_TOTAL_PATHS = 8192
MAX_PATH_BYTES = 1024
MAX_TOTAL_PATH_BYTES = 768 * 1024
POLICY_SCHEMA = "aros-toolchain-required-payload-v1"
RESULT_SCHEMA = "aros-toolchain-required-payload-selection-v1"
ASSURANCE = "required-path-selection-only"
LOWER_HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
SAFE_PATH_COMPONENT = re.compile(r"[A-Za-z0-9._+-]{1,128}\Z")
POLICY_FIELDS = {"schema", "groups"}
GROUP_FIELDS = {"group_id", "source_lock_sha256", "profiles_sha256", "profiles"}


class PolicyError(ValueError):
    """The selected policy, plan, or their independent bindings are invalid."""


_MATRIX_PATH = Path(__file__).resolve().with_name("select-release-matrix-v2.py")
_MATRIX_SPEC = importlib.util.spec_from_file_location(
    "required_payload_release_matrix_v2", _MATRIX_PATH
)
if _MATRIX_SPEC is None or _MATRIX_SPEC.loader is None:
    raise RuntimeError("release matrix validator is unavailable")
release_matrix = importlib.util.module_from_spec(_MATRIX_SPEC)
_MATRIX_SPEC.loader.exec_module(release_matrix)
if __name__ != "__main__":
    sys.dont_write_bytecode = _ORIGINAL_BYTECODE_POLICY


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PolicyError("JSON contains a duplicate key")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise PolicyError("JSON contains a non-JSON numeric constant")


def _parse_json(raw: bytes, description: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except PolicyError:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError) as error:
        raise PolicyError(f"{description} is not valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise PolicyError(f"{description} must be a JSON object")
    return value


def _require_exact_fields(value: Any, expected: set[str], description: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise PolicyError(f"{description} has missing, unknown, or invalid fields")
    return value


def _require_digest(value: Any, description: str) -> str:
    if not isinstance(value, str) or LOWER_HEX_64.fullmatch(value) is None:
        raise PolicyError(f"{description} must be a lowercase SHA-256 digest")
    return value


def _validate_path(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise PolicyError("required path must be a nonempty bounded file path")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise PolicyError("required path is not valid UTF-8 text") from error
    if len(encoded) > MAX_PATH_BYTES:
        raise PolicyError("required path must be a nonempty bounded file path")
    if value.startswith("/") or value.endswith("/") or "\\" in value or ":" in value:
        raise PolicyError("required path is not a safe relative file path")
    parts = value.split("/")
    if any(
        part in {".", ".."} or SAFE_PATH_COMPONENT.fullmatch(part) is None
        for part in parts
    ):
        raise PolicyError("required path contains an unsafe component")
    return value


def _validate_policy(policy: dict[str, Any]) -> dict[str, dict[str, Any]]:
    value = _require_exact_fields(policy, POLICY_FIELDS, "policy")
    if value["schema"] != POLICY_SCHEMA:
        raise PolicyError("policy schema is unsupported")
    groups = value["groups"]
    if not isinstance(groups, list) or not 1 <= len(groups) <= MAX_POLICY_GROUPS:
        raise PolicyError("policy requires 1..32 groups")

    result: dict[str, dict[str, Any]] = {}
    total_profiles = 0
    total_paths = 0
    total_path_bytes = 0
    for group_value in groups:
        group = _require_exact_fields(group_value, GROUP_FIELDS, "policy group")
        group_id = release_matrix._require_safe_id(group["group_id"], "policy group ID")
        if group_id in result:
            raise PolicyError("policy group IDs must be unique")
        source_lock_sha256 = _require_digest(
            group["source_lock_sha256"], "policy source-lock digest"
        )
        profiles_sha256 = _require_digest(group["profiles_sha256"], "policy profiles digest")

        profiles = group["profiles"]
        if not isinstance(profiles, dict) or not 1 <= len(profiles) <= MAX_PROFILES_PER_GROUP:
            raise PolicyError("each policy group requires 1..64 profiles")
        profile_map: dict[str, list[str]] = {}
        for profile_value, paths_value in profiles.items():
            profile = release_matrix._require_profile_id(profile_value)
            if profile in profile_map:
                raise PolicyError("policy profile IDs must be unique")
            if (
                not isinstance(paths_value, list)
                or not 1 <= len(paths_value) <= MAX_PATHS_PER_PROFILE
            ):
                raise PolicyError("each profile requires 1..256 required paths")
            paths = [_validate_path(path) for path in paths_value]
            if paths != sorted(set(paths)):
                raise PolicyError("required paths must be sorted and unique")
            total_paths += len(paths)
            total_path_bytes += sum(len(path.encode("utf-8")) for path in paths)
            if total_paths > MAX_TOTAL_PATHS or total_path_bytes > MAX_TOTAL_PATH_BYTES:
                raise PolicyError("policy required paths exceed the aggregate size limit")
            profile_map[profile] = paths
        total_profiles += len(profile_map)
        if total_profiles > MAX_TOTAL_PROFILES:
            raise PolicyError("policy profile count exceeds 128")
        result[group_id] = {
            "source_lock_sha256": source_lock_sha256,
            "profiles_sha256": profiles_sha256,
            "profiles": profile_map,
        }
    return result


def select_required_payload(
    *,
    raw_policy: bytes,
    expected_policy_sha256: str,
    raw_plan: bytes,
    plan_sha256: str,
    inputs_sha256: str,
    producer_commit: str,
    tools_commit: str,
) -> dict[str, Any]:
    """Validate independent bindings and project policy paths onto every native lane."""
    if not isinstance(raw_policy, bytes) or len(raw_policy) > MAX_POLICY_BYTES:
        raise PolicyError("policy exceeds the bounded byte limit")
    if not isinstance(raw_plan, bytes) or len(raw_plan) > release_matrix.MAX_PLAN_BYTES:
        raise PolicyError("plan exceeds the bounded byte limit")
    native_plan = _parse_json(raw_plan, "plan")
    actual_policy_sha256 = hashlib.sha256(raw_policy).hexdigest()
    expected_policy_sha256 = _require_digest(
        expected_policy_sha256, "selected policy digest"
    )
    if actual_policy_sha256 != expected_policy_sha256:
        raise PolicyError("policy bytes do not match the independently selected digest")
    policy = _validate_policy(_parse_json(raw_policy, "policy"))

    # This exact workflow_dispatch/full qualification call is the shared
    # structural validator for the complete producer plan. Its output remains
    # scheduling evidence only and is never treated as native execution.
    projection = release_matrix.project(
        raw=raw_plan,
        plan=native_plan,
        plan_sha256=plan_sha256,
        inputs_sha256=inputs_sha256,
        producer_commit=producer_commit,
        tools_commit=tools_commit,
        event="workflow_dispatch",
        scope="full",
        full_qualification=True,
    )
    if (
        projection["event"] != "workflow_dispatch"
        or projection["scope"] != "full"
        or projection["complete_selection"] is not True
    ):
        raise PolicyError("native plan is not a complete full-qualification selection")

    plan_groups = {group["group_id"]: group for group in native_plan["groups"]}
    if set(policy) != set(plan_groups):
        raise PolicyError("policy groups do not exactly match the selected plan")

    plan_profiles: dict[str, set[str]] = {group_id: set() for group_id in plan_groups}
    for lane in projection["verify_matrix"]["include"]:
        group_id = lane["group_id"]
        profile = lane["profile"]
        plan_profiles[group_id].add(profile)

    for group_id, policy_group in policy.items():
        plan_group = plan_groups[group_id]
        profile_map = policy_group["profiles"]
        if profile_map.keys() != plan_profiles[group_id]:
            raise PolicyError(f"policy profiles do not exactly match plan group {group_id}")
        if profile_map and any(not paths for paths in profile_map.values()):
            raise PolicyError("every selected profile requires at least one path")
        if policy_group["source_lock_sha256"] != plan_group["source_lock"]["sha256"]:
            raise PolicyError(f"policy source-lock digest differs for group {group_id}")
        if policy_group["profiles_sha256"] != plan_group["profiles"]["sha256"]:
            raise PolicyError(f"policy profiles digest differs for group {group_id}")

    selections = [
        {
            "group_id": lane["group_id"],
            "host": lane["host"],
            "target_profile": lane["profile"],
            "required_paths": policy[lane["group_id"]]["profiles"][lane["profile"]],
        }
        for lane in projection["verify_matrix"]["include"]
    ]
    return {
        "schema": RESULT_SCHEMA,
        "assurance": ASSURANCE,
        "selected_policy_sha256": actual_policy_sha256,
        "plan_sha256": projection["plan_sha256"],
        "inputs_sha256": projection["inputs_sha256"],
        "producer_commit": projection["producer_commit"],
        "tools_commit": projection["tools_commit"],
        "selections": selections,
    }


def _open_canonical_file(path: Path, description: str) -> int:
    if not isinstance(path, Path) or not path.is_absolute():
        raise PolicyError(f"{description} path must be absolute")
    path_text = os.fspath(path)
    if os.path.normpath(path_text) != path_text or len(path.parts) < 2:
        raise PolicyError(f"{description} path must be canonical")
    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if no_follow is None or directory is None or not hasattr(os, "open"):
        raise PolicyError("this platform cannot safely open canonical paths")

    flags = os.O_RDONLY | directory | no_follow | getattr(os, "O_CLOEXEC", 0)
    try:
        current = os.open("/", flags)
    except OSError as error:
        raise PolicyError(f"cannot safely open {description} parent") from error
    try:
        for component in path.parts[1:-1]:
            if component in {"", ".", ".."}:
                raise PolicyError(f"{description} path must be canonical")
            next_fd = os.open(component, flags, dir_fd=current)
            os.close(current)
            current = next_fd
        filename = path.parts[-1]
        if filename in {"", ".", ".."}:
            raise PolicyError(f"{description} path must name a file")
        file_flags = os.O_RDONLY | no_follow | getattr(os, "O_NONBLOCK", 0)
        file_flags |= getattr(os, "O_CLOEXEC", 0)
        return os.open(filename, file_flags, dir_fd=current)
    except OSError as error:
        raise PolicyError(f"cannot safely open {description}") from error
    finally:
        os.close(current)


def _read_canonical_regular(path: Path, limit: int, description: str) -> tuple[bytes, tuple[int, int, int, int]]:
    descriptor = _open_canonical_file(path, description)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise PolicyError(f"{description} is not a bounded regular file")
        content = bytearray()
        while len(content) <= limit:
            block = os.read(descriptor, min(65536, limit + 1 - len(content)))
            if not block:
                break
            content.extend(block)
        if len(content) > limit:
            raise PolicyError(f"{description} exceeds the size limit")
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        )
        if identity_before != identity_after or len(content) != after.st_size:
            raise PolicyError(f"{description} changed while being read")
        return bytes(content), identity_before
    except OSError as error:
        raise PolicyError(f"cannot read {description}") from error
    finally:
        os.close(descriptor)


def _read_stable(path: Path, limit: int, description: str) -> tuple[bytes, tuple[int, int, int, int]]:
    raw, identity = _read_canonical_regular(path, limit, description)
    raw_again, identity_again = _read_canonical_regular(path, limit, description)
    if identity_again != identity or raw_again != raw:
        raise PolicyError(f"{description} changed during selection")
    return raw, identity


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--policy-sha256", required=True)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--plan-sha256", required=True)
    parser.add_argument("--inputs-sha256", required=True)
    parser.add_argument("--producer-commit", required=True)
    parser.add_argument("--tools-commit", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        raw_policy, policy_identity = _read_stable(
            args.policy, MAX_POLICY_BYTES, "policy"
        )
        raw_plan, plan_identity = _read_stable(
            args.plan, release_matrix.MAX_PLAN_BYTES, "plan"
        )
        result = select_required_payload(
            raw_policy=raw_policy,
            expected_policy_sha256=args.policy_sha256,
            raw_plan=raw_plan,
            plan_sha256=args.plan_sha256,
            inputs_sha256=args.inputs_sha256,
            producer_commit=args.producer_commit,
            tools_commit=args.tools_commit,
        )
        policy_again, policy_identity_again = _read_canonical_regular(
            args.policy, MAX_POLICY_BYTES, "policy"
        )
        plan_again, plan_identity_again = _read_canonical_regular(
            args.plan, release_matrix.MAX_PLAN_BYTES, "plan"
        )
        if (
            policy_identity_again != policy_identity
            or policy_again != raw_policy
            or plan_identity_again != plan_identity
            or plan_again != raw_plan
        ):
            raise PolicyError("selected policy or plan changed before returning")
        sys.stdout.write(json.dumps(result, separators=(",", ":"), ensure_ascii=True) + "\n")
        return 0
    except (OSError, PolicyError, release_matrix.PlanError, UnicodeError) as error:
        sys.stderr.write(f"required payload selection failed: {error}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
