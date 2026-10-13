#!/usr/bin/env python3
"""Select bounded native compiler owners from one exact release plan.

This helper selects original compiler-job owners and reference bytes only. It
does not interpret compiler recipes, qualify builds, or grant release authority.
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


artifact_origin = _load_helper("compiler_owner_matrix_artifact_origin", _HERE / "artifact-origin.py")
release_matrix = _load_helper(
    "compiler_owner_matrix_release_matrix", _HERE / "select-release-matrix-v2.py"
)

HEX64 = re.compile(r"[0-9a-f]{64}\Z")
REFERENCE_FIELDS = ("recipe", "source_lock", "profiles")


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


def _projection_route(source_ref: str, event: str) -> tuple[str, bool]:
    _require(type(source_ref) is str and type(event) is str,
             "source event/ref does not select a release route")
    if source_ref.startswith("refs/tags/") and event == "push":
        return "push", False
    if source_ref.startswith("refs/heads/") and event == "workflow_dispatch":
        return "workflow_dispatch", True
    if source_ref.startswith("refs/tags/") and event == "workflow_dispatch":
        return "workflow_dispatch", True
    raise artifact_origin.OriginError("source event/ref does not select a release route")


def _measure_raw(path: Path, limit: int, description: str) -> tuple[dict, bytes]:
    measurement, raw = artifact_origin.normalized_file(path, limit)
    _require(raw is not None, f"{description} could not be read as bounded metadata")
    return measurement, raw


def _read_group_references(
    plan: dict[str, Any], inputs_dir: Path
) -> dict[str, dict[str, tuple[Path, dict, bytes]]]:
    snapshots: dict[str, dict[str, tuple[Path, dict, bytes]]] = {}
    for group in plan["groups"]:
        group_id = group["group_id"]
        selected: dict[str, tuple[Path, dict, bytes]] = {}
        for reference_name in REFERENCE_FIELDS:
            reference = group[reference_name]
            path = inputs_dir / reference["file"]
            _canonical_existing_path(path, f"{reference_name} for {group_id}")
            measurement, raw = _measure_raw(
                path, artifact_origin.MAX_METADATA, f"{reference_name} for {group_id}"
            )
            _require(measurement["sha256"] == reference["sha256"],
                     f"{reference_name} digest differs for {group_id}")
            selected[reference_name] = (path, measurement, raw)
        snapshots[group_id] = selected
    return snapshots


def _owner_id(group_id: str, host: str, profile: str, copy: str) -> str:
    fields = (group_id, host, profile, copy)
    # build-native-lane-v2 uses printf '%s\\0' for each of these four values.
    digest_input = b"\0".join(field.encode("utf-8") for field in fields) + b"\0"
    return hashlib.sha256(digest_input).hexdigest()


def _project_owners(plan: dict[str, Any], projection: dict[str, Any],
                    run_id: int, run_attempt: int) -> tuple[list[dict], list[dict]]:
    groups = {group["group_id"]: group for group in plan["groups"]}
    build_entries = projection["build_matrix"]["include"]
    _require(0 < len(build_entries) <= release_matrix.MAX_BUILD_ENTRIES,
             "compiler owner matrix is empty or exceeds the native matrix bound")

    owners: list[dict] = []
    owner_keys: set[tuple[str, str, str, str]] = set()
    for entry in sorted(build_entries, key=lambda value: (
        value["group_id"], value["host"], value["profile"], value["copy"]
    )):
        group_id = entry["group_id"]
        host = entry["host"]
        profile = entry["profile"]
        copy = entry["copy"]
        key = (group_id, host, profile, copy)
        _require(key not in owner_keys, "native compiler owner matrix contains duplicate lanes")
        owner_keys.add(key)
        group = groups[group_id]
        owner_id = _owner_id(group_id, host, profile, copy)
        job_name = f"Native compiler ({group_id}, {host}, {profile}, {copy})"
        payload_name = f"native-v2-{owner_id}-{run_id}-{run_attempt}"
        proof_name = f"native-v2-proof-{owner_id}-{run_id}-{run_attempt}"
        _require(all(0 < len(name) <= 256
                     for name in (job_name, payload_name, proof_name)),
                 "native compiler provider name exceeds 256 characters")
        owners.append({
            "owner_id": owner_id,
            "group_id": group_id,
            "host": host,
            "profile": profile,
            "copy": copy,
            "job_name": job_name,
            "payload_name": payload_name,
            "proof_name": proof_name,
            "recipe": group["recipe"],
            "source_lock": group["source_lock"],
            "profiles": group["profiles"],
        })

    lanes = {
        (entry["group_id"], entry["host"], entry["profile"])
        for entry in projection["verify_matrix"]["include"]
    }
    expected_lanes = [
        {"group_id": group_id, "host": host, "target_profile": profile}
        for group_id, host, profile in sorted(lanes)
    ]
    _require(len(owner_keys) == len(build_entries),
             "native compiler owner matrix is not closed over the validated build projection")
    _require(len(lanes) * 2 == len(owner_keys),
             "native compiler owners do not contain exactly two copies per lane")
    _require(len({owner["owner_id"] for owner in owners}) == len(owners),
             "native compiler owner identities are not unique")
    return owners, expected_lanes


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

    observed_event = artifact_origin.observe_run_event(context)
    projected_event, full_qualification = _projection_route(
        context["source_ref"], observed_event
    )
    _require(projected_event == observed_event,
             "observed provider event does not select the requested release route")
    projection = release_matrix.project(
        raw=raw_plan,
        plan=plan,
        plan_sha256=plan_sha256,
        inputs_sha256=inputs_sha256,
        producer_commit=args.producer_commit,
        tools_commit=args.tools_commit,
        event=observed_event,
        scope="full",
        full_qualification=full_qualification,
    )
    _require(projection["complete_selection"] is True,
             "compiler owner selection requires the exact complete native matrix")

    reference_snapshots = _read_group_references(plan, inputs_dir)
    owners, expected_lanes = _project_owners(
        plan, projection, context["run_id"], context["run_attempt"]
    )
    result = {
        "schema": "aros-compiler-owner-matrix-v2",
        "assurance": "owner-selection-only",
        "plan_sha256": plan_sha256,
        "inputs_sha256": inputs_sha256,
        "source_context_sha256": source_context_sha256,
        "producer_commit": args.producer_commit,
        "tools_commit": args.tools_commit,
        "owners": owners,
        "expected_compiler_lanes": expected_lanes,
    }

    # Re-measure all plan-bound files and the exact provider event before stdout.
    final_plan_measurement, _ = artifact_origin.normalized_file(
        plan_path, release_matrix.MAX_PLAN_BYTES
    )
    _require(final_plan_measurement == plan_measurement,
             "plan changed during compiler owner selection")
    final_context_measurement, final_context_raw = _measure_raw(
        context_path, artifact_origin.MAX_METADATA, "source context"
    )
    _require(final_context_measurement == context_measurement
             and final_context_raw == context_raw,
             "source context changed during compiler owner selection")
    for selected in reference_snapshots.values():
        for path, measurement, raw in selected.values():
            final_measurement, final_raw = _measure_raw(
                path, artifact_origin.MAX_METADATA, "native compiler reference"
            )
            _require(final_measurement == measurement and final_raw == raw,
                     "native compiler reference changed during owner selection")
    _canonical_input_directory(inputs_dir)
    final_event = artifact_origin.observe_run_event(context)
    _require(final_event == observed_event,
             "source run event changed during compiler owner selection")
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
        print("compiler owner matrix selection failed: repeated command-line option", file=sys.stderr)
        return 2
    try:
        args = _parser().parse_args(arguments)
        result = select(args)
        sys.stdout.write(artifact_origin.canonical(result).decode("utf-8"))
        return 0
    except (artifact_origin.OriginError, release_matrix.PlanError, OSError,
            UnicodeError, RecursionError) as error:
        print(f"compiler owner matrix selection failed: {error}", file=sys.stderr)
        return 2
    except Exception:
        print("compiler owner matrix selection failed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
