#!/usr/bin/env python3
"""Select bounded SDK owners from one exact native release plan.

The output is a scheduling/ownership projection only. It does not qualify
compiler lanes, parse SDK receipts, authenticate artifact provenance, or grant
release authority.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from typing import Any


_HERE = Path(__file__).resolve().parent


def _load_helper(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("required toolchain selector helper is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


artifact_origin = _load_helper("sdk_owner_matrix_artifact_origin", _HERE / "artifact-origin.py")
release_matrix = _load_helper(
    "sdk_owner_matrix_release_matrix", _HERE / "select-release-matrix-v2.py"
)

HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def _require(condition: bool, message: str) -> None:
    artifact_origin.require(condition, message)


def _canonical_existing_path(path: object, description: str) -> Path:
    _require(isinstance(path, Path) and path.is_absolute() and ".." not in path.parts,
             f"{description} path must be absolute and normalized")
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        raise artifact_origin.OriginError(f"{description} path is unavailable") from None
    _require(resolved == path, f"{description} path must be canonical and contain no symlink")
    return path


def _canonical_input_directory(path: object) -> Path:
    path = _canonical_existing_path(path, "inputs directory")
    _require(path.is_dir() and not path.is_symlink(),
             "inputs directory must be an existing canonical directory")
    return path


def _check_sha(value: object, description: str) -> str:
    _require(isinstance(value, str) and HEX64.fullmatch(value) is not None,
             f"{description} must be a lowercase SHA-256 digest")
    return value


def _measure_raw(path: Path, limit: int, description: str) -> tuple[dict, bytes]:
    measurement, raw = artifact_origin.normalized_file(path, limit)
    _require(raw is not None, f"{description} could not be read as bounded metadata")
    return measurement, raw


def _source_locks(plan: dict[str, Any], inputs_dir: Path) -> tuple[dict[str, str], dict[str, tuple[Path, dict, bytes]]]:
    families: dict[str, str] = {}
    snapshots: dict[str, tuple[Path, dict, bytes]] = {}
    for group in plan["groups"]:
        group_id = group["group_id"]
        reference = group["source_lock"]
        path = inputs_dir / reference["file"]
        _canonical_existing_path(path, f"source lock for {group_id}")
        measurement, raw = _measure_raw(path, artifact_origin.MAX_METADATA,
                                        f"source lock for {group_id}")
        _require(measurement["sha256"] == reference["sha256"],
                 f"source lock digest differs for {group_id}")
        lock = artifact_origin.parse_json(raw)
        _require(isinstance(lock, dict) and lock.get("family") in ("gnu", "llvm"),
                 f"source lock family is unsupported for {group_id}")
        families[group_id] = lock["family"]
        snapshots[group_id] = (path, measurement, raw)
    return families, snapshots


def _owner_id(sdk_ids: list[str], group_id: str, host: str, profile: str) -> str:
    compact_ids = json.dumps(sdk_ids, separators=(",", ":"), ensure_ascii=True)
    fields = ("sdk", compact_ids, group_id, host, profile)
    # The action's printf '%s\\0' emits a terminating NUL after every field.
    digest_input = b"\0".join(value.encode("utf-8") for value in fields) + b"\0"
    return hashlib.sha256(digest_input).hexdigest()


def _project_owners(plan: dict[str, Any], families: dict[str, str],
                    run_id: int, run_attempt: int) -> tuple[list[dict], list[dict]]:
    owner_sdks: dict[tuple[str, str, str], set[str]] = {}
    expected: set[tuple[str, str, str, str]] = set()
    sdk_ids: set[str] = set()

    for sdk in plan["sdks"]:
        sdk_id = sdk["id"]
        _require(sdk_id not in sdk_ids, "SDK IDs are not unique")
        sdk_ids.add(sdk_id)
        for reference in sdk["compiler_profiles"]:
            group_id = reference["group_id"]
            profile = reference["profile"]
            for host in plan["hosts"]:
                key = (group_id, host, profile)
                owner_sdks.setdefault(key, set()).add(sdk_id)
                expected_key = (sdk_id, group_id, profile, host)
                _require(expected_key not in expected, "SDK compiler closure contains duplicates")
                expected.add(expected_key)

    _require(bool(sdk_ids), "release plan must select at least one SDK")
    _require(len(owner_sdks) <= release_matrix.MAX_BUILD_ENTRIES,
             "SDK owner matrix exceeds the bounded native matrix count")
    _require(len(expected) <= release_matrix.MAX_SDKS
             * release_matrix.MAX_SDK_COMPILER_PROFILES * len(plan["hosts"]),
             "expected SDK generation closure exceeds the bounded matrix count")

    owners: list[dict] = []
    for group_id, host, profile in sorted(owner_sdks):
        selected_sdk_ids = sorted(owner_sdks[(group_id, host, profile)])
        _require(0 < len(selected_sdk_ids) <= release_matrix.MAX_SDKS,
                 "SDK owner closure is empty or exceeds the SDK bound")
        owner_id = _owner_id(selected_sdk_ids, group_id, host, profile)
        job_name = f"SDK from owned compilers ({group_id}, {host}, {profile})"
        payload_name = f"sdk-v2-{owner_id}-{run_id}-{run_attempt}"
        proof_name = f"sdk-v2-proof-{owner_id}-{run_id}-{run_attempt}"
        _require(all(0 < len(name) <= 256
                     for name in (job_name, payload_name, proof_name)),
                 "SDK owner provider name exceeds 256 characters")
        owners.append({
            "owner_id": owner_id,
            "group_id": group_id,
            "host": host,
            "profile": profile,
            "compiler_family": families[group_id],
            "sdk_ids": selected_sdk_ids,
            "job_name": job_name,
            "payload_name": payload_name,
            "proof_name": proof_name,
        })

    expected_generations = [
        {
            "sdk_id": sdk_id,
            "group_id": group_id,
            "target_profile": profile,
            "host": host,
        }
        for sdk_id, group_id, profile, host in sorted(expected)
    ]
    _require(len({owner["owner_id"] for owner in owners}) == len(owners),
             "SDK owner identities are not unique")
    return owners, expected_generations


def select(args: argparse.Namespace) -> dict[str, Any]:
    plan_path = _canonical_existing_path(args.plan, "plan")
    context_path = _canonical_existing_path(args.source_context, "source context")
    inputs_dir = _canonical_input_directory(args.inputs_dir)
    plan_sha256 = _check_sha(args.plan_sha256, "plan digest")
    inputs_sha256 = _check_sha(args.inputs_sha256, "inputs digest")
    source_context_sha256 = _check_sha(args.source_context_sha256, "source context digest")

    raw_plan, plan, _ = release_matrix._read_plan(plan_path)
    plan_measurement, _ = artifact_origin.normalized_file(
        plan_path, release_matrix.MAX_PLAN_BYTES
    )
    expected_plan_measurement = {
        "sha256": hashlib.sha256(raw_plan).hexdigest(),
        "size": len(raw_plan),
    }
    _require(plan_measurement == expected_plan_measurement,
             "plan changed while it was being selected")

    context_measurement, context_raw = _measure_raw(
        context_path, artifact_origin.MAX_METADATA, "source context"
    )
    _require(context_measurement["sha256"] == source_context_sha256,
             "source context digest differs")
    context = artifact_origin.validate_context(artifact_origin.parse_json(context_raw))
    _require(context["producer_commit"] == args.producer_commit
             and context["workflow"] == args.source_workflow
             and context["source_ref"] == args.source_ref,
             "source context differs from the selected producer/workflow/ref")

    projection = release_matrix.project(
        raw=raw_plan,
        plan=plan,
        plan_sha256=plan_sha256,
        inputs_sha256=inputs_sha256,
        producer_commit=args.producer_commit,
        tools_commit=args.tools_commit,
        event="workflow_dispatch",
        scope="full",
        full_qualification=True,
    )
    _require(projection["complete_selection"] is True,
             "SDK owner selection requires the exact complete native matrix")

    families, lock_snapshots = _source_locks(plan, inputs_dir)
    owners, expected_generations = _project_owners(
        plan, families, context["run_id"], context["run_attempt"]
    )
    result = {
        "schema": "aros-sdk-owner-matrix-v2",
        "assurance": "owner-selection-only",
        "plan_sha256": plan_sha256,
        "inputs_sha256": inputs_sha256,
        "source_context_sha256": source_context_sha256,
        "producer_commit": args.producer_commit,
        "tools_commit": args.tools_commit,
        "owners": owners,
        "expected_sdk_generations": expected_generations,
    }

    # All selected byte inputs are measured again before the first stdout byte.
    final_plan_measurement, _ = artifact_origin.normalized_file(
        plan_path, release_matrix.MAX_PLAN_BYTES
    )
    _require(final_plan_measurement == plan_measurement,
             "plan changed during SDK owner selection")
    final_context_measurement, final_context_raw = _measure_raw(
        context_path, artifact_origin.MAX_METADATA, "source context"
    )
    _require(final_context_measurement == context_measurement
             and final_context_raw == context_raw,
             "source context changed during SDK owner selection")
    for path, measurement, raw in lock_snapshots.values():
        final_measurement, final_raw = _measure_raw(
            path, artifact_origin.MAX_METADATA, "source lock"
        )
        _require(final_measurement == measurement and final_raw == raw,
                 "source lock changed during SDK owner selection")
    _canonical_input_directory(inputs_dir)
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--plan-sha256", required=True)
    parser.add_argument("--inputs-dir", required=True, type=Path)
    parser.add_argument("--inputs-sha256", required=True)
    parser.add_argument("--producer-commit", required=True)
    parser.add_argument("--tools-commit", required=True)
    parser.add_argument("--source-context", required=True, type=Path)
    parser.add_argument("--source-context-sha256", required=True)
    parser.add_argument("--source-workflow", required=True)
    parser.add_argument("--source-ref", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    option_names = [item.split("=", 1)[0] for item in arguments if item.startswith("--")]
    if len(option_names) != len(set(option_names)):
        print("SDK owner matrix selection failed: repeated command-line option", file=sys.stderr)
        return 2
    try:
        args = _parser().parse_args(arguments)
        result = select(args)
        sys.stdout.write(artifact_origin.canonical(result).decode("utf-8"))
        return 0
    except (artifact_origin.OriginError, release_matrix.PlanError, OSError,
            UnicodeError, RecursionError) as error:
        print(f"SDK owner matrix selection failed: {error}", file=sys.stderr)
        return 2
    except Exception:
        print("SDK owner matrix selection failed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
