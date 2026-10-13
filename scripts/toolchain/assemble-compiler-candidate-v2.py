#!/usr/bin/env python3
"""Reverify and assemble a byte-closed compiler-only candidate.

This adapter consumes an authenticated compiler-owner collector fragment. It
does not authenticate provider signatures itself. Run it immediately after
the authenticated collector in the same job. Native package verification and
comparison remain the semantic authorities; the emitted evidence is partial
and grants no qualification, admission, signing, tagging, or publication
authority.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import signal
import stat
import subprocess
import sys
import time
from typing import Any


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
MAX_FRAGMENT = 16 * 1024 * 1024
MAX_NATIVE_RESULT = 4 * 1024 * 1024
MAX_RUNTIME = 1024 * 1024 * 1024
MAX_ORIGIN_BYTES = 16 * 1024 * 1024
MAX_METADATA = 16 * 1024 * 1024
NATIVE_TIMEOUT_SECONDS = 1800
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
LANE_ID_COMPONENT = re.compile(r"[A-Za-z0-9._+-]{1,255}\Z")
ROOT_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
FILE_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
CREATE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)


class AssemblyError(ValueError):
    """A compiler candidate failed its closed selection or readback contract."""


def _load_helper(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("required compiler assembly helper is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_SDK_SELECT = _load_helper("compiler_assembly_sdk_select", HERE / "select-sdk-package-inputs-v2.py")
_MATRIX = _SDK_SELECT._MATRIX
_STAGE = _SDK_SELECT._STAGE
_COMPILER_MATRIX = _load_helper("compiler_assembly_owner_matrix", HERE / "compiler-owner-matrix-v2.py")
_TRANSPORT = _load_helper("compiler_assembly_native_transport", HERE / "native-lane-transport.py")
_ORIGIN = _TRANSPORT.origin
_REQUIRED = _load_helper("compiler_assembly_required_paths", HERE / "required-compiler-payload-v2.py")


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AssemblyError(message)


def _projection_route(source_ref: str, event: str) -> tuple[str, bool]:
    try:
        return _COMPILER_MATRIX._projection_route(source_ref, event)
    except _COMPILER_MATRIX.artifact_origin.OriginError as error:
        raise AssemblyError(str(error)) from error


def _digest(value: object, label: str) -> str:
    _require(isinstance(value, str) and HEX64.fullmatch(value) is not None,
             f"{label} must be a lowercase SHA-256 digest")
    return value


def _commit(value: object, label: str) -> str:
    _require(isinstance(value, str) and HEX40.fullmatch(value) is not None,
             f"{label} must be a lowercase Git commit")
    return value


def _stat_fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_nlink,
            metadata.st_uid, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns)


def _canonical_existing(path: Path, label: str, *, directory: bool | None = None) -> Path:
    _require(path.is_absolute() and ".." not in path.parts,
             f"{label} path must be absolute and normalized")
    _require(_STAGE.path_is_canonical(path, must_exist=True),
             f"{label} path is linked or noncanonical")
    metadata = path.lstat()
    if directory is True:
        _require(stat.S_ISDIR(metadata.st_mode), f"{label} is not an ordinary directory")
    elif directory is False:
        _require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
                 and metadata.st_uid == os.geteuid(),
                 f"{label} is not an owned, singly linked regular file")
    return path


def _record_file(path: Path, limit: int, label: str, selected_files: dict,
                 *, read: bool = False) -> tuple[dict, bytes | None]:
    _canonical_existing(path, label, directory=False)
    if read:
        measured, raw = _STAGE.read_bounded(path, limit, label)
    else:
        measured, raw = _STAGE.measure_file(path, limit, label), None
    named = path.lstat()
    current = (limit, measured, _stat_fingerprint(named))
    prior = selected_files.get(path)
    _require(prior is None or prior == current,
             f"{label} changed between selected observations")
    selected_files[path] = current
    return measured, raw


def _read_json(path: Path, limit: int, label: str, selected_files: dict) -> tuple[dict, bytes, dict]:
    measured, raw = _record_file(path, limit, label, selected_files, read=True)
    value = _STAGE.parse_json(raw, label)
    _require(isinstance(value, dict), f"{label} must be a JSON object")
    return value, raw, measured


def _remember_directory(path: Path, label: str, snapshots: dict) -> dict[str, str]:
    previous = snapshots.get(path)
    if previous is not None:
        return previous[1]
    before = _STAGE.directory_fingerprint(path, label)
    entries = _STAGE.directory_entries(path, label)
    after = _STAGE.directory_fingerprint(path, label)
    _require(before == after, f"{label} changed while being enumerated")
    snapshots[path] = (after, entries)
    return entries


def _verify_selected_files(selected_files: dict, *, include_payload: bool = True) -> None:
    for path, (limit, expected, fingerprint) in selected_files.items():
        # Keep the potentially large retained ZIP/package payload out of the
        # per-command rechecks. Those bytes are checked immediately before and
        # after the native operations by verify_output and again at the final
        # output barrier. Small selection/evidence documents are always joined.
        if not include_payload and (path.name == "payload.zip" or path.name.endswith(".tar.xz")):
            continue
        measured = _STAGE.measure_file(path, limit, f"selected input {path.name}")
        _require(measured == expected and _stat_fingerprint(path.lstat()) == fingerprint,
                 f"selected input changed during compiler assembly: {path.name}")


def _verify_directories(snapshots: dict) -> None:
    for path, expected in snapshots.items():
        before = _STAGE.directory_fingerprint(path, f"selected directory {path.name or path}")
        entries = _STAGE.directory_entries(path, f"selected directory {path.name or path}")
        after = _STAGE.directory_fingerprint(path, f"selected directory {path.name or path}")
        _require(before == after == expected[0] and entries == expected[1],
                 f"selected directory changed during compiler assembly: {path.name or path}")


def _path_field(value: object, label: str) -> Path:
    _require(isinstance(value, str) and 0 < len(value.encode("utf-8")) <= 4096
             and "\n" not in value and "\r" not in value,
             f"{label} is not a bounded absolute path")
    path = Path(value)
    _require(path.is_absolute() and ".." not in path.parts,
             f"{label} is not an absolute normalized path")
    return path


def _read_bound_inputs(args: argparse.Namespace) -> dict:
    plan_sha = _digest(args.plan_sha256, "selected native plan digest")
    inputs_sha = _digest(args.inputs_sha256, "selected release-input digest")
    fragment_sha = _digest(args.fragment_sha256, "selected collector-fragment digest")
    required_sha = _digest(args.required_paths_sha256, "selected required-path digest")
    runtime_sha = _digest(args.aros_sha256, "selected native CLI digest")
    producer = _commit(args.producer_commit, "selected producer commit")
    tools = _commit(args.tools_commit, "selected tools commit")
    release_id = _MATRIX._require_safe_id(args.release_id, "selected release identifier")
    selected_files: dict[Path, tuple[int, dict, tuple[int, ...]]] = {}
    snapshots: dict[Path, tuple[tuple[int, ...], dict[str, str]]] = {}

    source_context_sha = _digest(args.source_context_sha256, "selected source-context digest")
    source_context_path = _canonical_existing(args.source_context, "source context", directory=False)
    source_context, source_context_raw, source_context_measurement = _read_json(
        source_context_path, _ORIGIN.MAX_METADATA, "source context", selected_files
    )
    _require(source_context_measurement["sha256"] == source_context_sha,
             "source context bytes differ from the selected digest")
    source_context = _ORIGIN.validate_context(source_context)
    _require(source_context_raw == _ORIGIN.canonical(source_context),
             "source context is not canonical JSON")
    _require(source_context["producer_commit"] == producer,
             "source context producer commit differs from the selected producer")
    source_event = _ORIGIN.observe_run_event(source_context)
    event, full_qualification = _projection_route(source_context["source_ref"], source_event)

    aros = _canonical_existing(args.aros, "native CLI", directory=False)
    aros_metadata = aros.lstat()
    _require(bool(stat.S_IMODE(aros_metadata.st_mode) & 0o111),
             "selected native CLI is not executable")
    runtime_measurement, _ = _record_file(aros, MAX_RUNTIME, "selected native CLI", selected_files)
    _require(runtime_measurement["sha256"] == runtime_sha and runtime_measurement["size"] > 0,
             "native CLI bytes differ from the selected digest")

    inputs_dir = _canonical_existing(args.inputs_dir, "release-input directory", directory=True)
    _remember_directory(inputs_dir, "digest-bound release-input directory", snapshots)
    collection_path = inputs_dir / "toolchain-release-inputs-v2.json"
    collection, _collection_raw, collection_measurement = _read_json(
        collection_path, _SDK_SELECT.MAX_COLLECTION_BYTES, "release-input collection", selected_files
    )
    _require(collection_measurement["sha256"] == inputs_sha,
             "release-input collection bytes differ from the selected digest")

    plan_path = _canonical_existing(args.plan, "native release plan", directory=False)
    plan, plan_raw, plan_measurement = _read_json(
        plan_path, _MATRIX.MAX_PLAN_BYTES, "native release plan", selected_files
    )
    _require(plan_measurement["sha256"] == plan_sha,
             "native release plan bytes differ from the selected digest")
    _MATRIX._validate_plan(plan, expected_inputs_sha256=inputs_sha,
                           expected_producer_commit=producer, expected_tools_commit=tools)
    _SDK_SELECT._validate_collection(collection, plan, producer_commit=producer, tools_commit=tools)

    group_refs: dict[str, dict[str, Path]] = {}
    for group in plan["groups"]:
        group_id = group["group_id"]
        group_refs[group_id] = {}
        for field in ("recipe", "source_lock", "profiles"):
            reference = group[field]
            reference_path = inputs_dir / reference["file"]
            _canonical_existing(reference_path, f"{field} for {group_id}", directory=False)
            measured, _ = _record_file(reference_path, MAX_METADATA,
                                       f"{field} for {group_id}", selected_files)
            _require(measured["sha256"] == reference["sha256"],
                     f"{field} bytes differ from the native plan for {group_id}")
            group_refs[group_id][field] = reference_path

    fragment_path = _canonical_existing(args.fragment, "compiler collector fragment", directory=False)
    owner_root = _canonical_existing(args.owner_root, "compiler owner root", directory=True)
    _require(fragment_path == owner_root / "selection-fragment.json",
             "compiler collector fragment must be under the supplied owner root")
    fragment, _fragment_raw, fragment_measurement = _read_json(
        fragment_path, MAX_FRAGMENT, "compiler collector fragment", selected_files
    )
    _require(fragment_measurement["sha256"] == fragment_sha,
             "compiler collector fragment bytes differ from the selected digest")
    required_path = _canonical_existing(args.required_paths, "required-path selection", directory=False)
    required, _required_raw, required_measurement = _read_json(
        required_path, _REQUIRED.MAX_POLICY_BYTES, "required-path selection", selected_files
    )
    _require(required_measurement["sha256"] == required_sha,
             "required-path selection bytes differ from the selected digest")

    fragment_fields = {
        "schema", "assurance", "runtime_sha256", "plan_sha256", "inputs_sha256",
        "source_context_sha256", "source_producer_commit", "source_workflow", "source_ref",
        "producer_commit", "tools_commit", "workflow", "job_name", "release_id",
        "owner_count", "expected_compiler_lanes", "compiler_builds", "release_admission",
        "publication",
    }
    _STAGE.exact_keys(fragment, fragment_fields, "compiler collector fragment")
    _require(fragment["schema"] == "aros-compiler-build-selection-fragment-v2"
             and fragment["assurance"] == "authenticated-original-owner-selection-only",
             "compiler collector fragment schema or assurance differs")
    _require(fragment["runtime_sha256"] == runtime_sha and fragment["plan_sha256"] == plan_sha
             and fragment["inputs_sha256"] == inputs_sha
             and fragment["producer_commit"] == producer
             and fragment["tools_commit"] == tools
             and fragment["source_producer_commit"] == producer
             and fragment["source_context_sha256"] == source_context_sha
             and fragment["source_producer_commit"] == source_context["producer_commit"]
             and fragment["source_workflow"] == source_context["workflow"]
             and fragment["source_ref"] == source_context["source_ref"],
             "compiler collector fragment bindings differ from selected inputs")
    _digest(fragment["source_context_sha256"], "fragment source-context digest")
    for field in ("source_workflow", "workflow"):
        value = fragment[field]
        _require(isinstance(value, str) and _SDK_SELECT.SOURCE_WORKFLOW.fullmatch(value) is not None,
                 f"fragment {field} is invalid")
    _require(isinstance(fragment["source_ref"], str)
             and _SDK_SELECT.SOURCE_REF.fullmatch(fragment["source_ref"]) is not None,
             "fragment source ref is invalid")
    _require(isinstance(fragment["job_name"], str) and 0 < len(fragment["job_name"]) <= 256
             and not any(ord(char) < 32 or ord(char) == 127 for char in fragment["job_name"]),
             "fragment current job name is invalid")
    _require(fragment["release_id"] == release_id
             and type(fragment["release_admission"]) is bool and not fragment["release_admission"]
             and type(fragment["publication"]) is bool and not fragment["publication"],
             "compiler collector fragment has a release or publication authority mismatch")

    projection = _MATRIX.project(
        raw=plan_raw, plan=plan, plan_sha256=plan_sha, inputs_sha256=inputs_sha,
        producer_commit=producer, tools_commit=tools, event=event,
        scope="full", full_qualification=full_qualification,
    )
    _require(projection["complete_selection"] is True
             and projection["scope"] == "full" and projection["event"] == event,
             "selected native release plan is not a complete full-scope plan")

    expected_lanes = [
        {"group_id": lane["group_id"], "host": lane["host"],
         "target_profile": lane["profile"]}
        for lane in projection["verify_matrix"]["include"]
    ]
    expected_lanes.sort(key=lambda lane: (lane["group_id"], lane["host"], lane["target_profile"]))
    _require(fragment["expected_compiler_lanes"] == expected_lanes,
             "collector compiler lanes differ from the complete native plan")
    expected_rows = [
        (lane["group_id"], lane["host"], lane["target_profile"], copy)
        for lane in expected_lanes for copy in ("a", "b")
    ]
    _require(type(fragment["owner_count"]) is int and fragment["owner_count"] == len(expected_rows)
             and type(fragment["compiler_builds"]) is list
             and len(fragment["compiler_builds"]) == len(expected_rows),
             "collector compiler owner count differs from the exact A/B plan")
    actual_rows = []
    for row in fragment["compiler_builds"]:
        _STAGE.exact_keys(row, {
            "group_id", "host", "target_profile", "copy", "package_dir", "measurement",
            "executor", "environment", "observation",
        }, "compiler build selection row")
        key = (row["group_id"], row["host"], row["target_profile"], row["copy"])
        actual_rows.append(key)
        _require(row["copy"] in ("a", "b"), "compiler owner copy is invalid")
        for name in ("measurement", "environment", "observation"):
            _STAGE.exact_keys(row[name], {"path", "sha256"}, f"compiler {name} reference")
            _digest(row[name]["sha256"], f"compiler {name} digest")
        _STAGE.exact_keys(row["executor"], {"contract_sha256", "binary_sha256"},
                          "compiler executor selector")
        _digest(row["executor"]["contract_sha256"], "executor contract digest")
        _digest(row["executor"]["binary_sha256"], "executor binary digest")
    _require(actual_rows == expected_rows,
             "collector compiler owner rows are missing, duplicated, extra, or out of order")

    required_fields = {
        "schema", "assurance", "selected_policy_sha256", "plan_sha256", "inputs_sha256",
        "producer_commit", "tools_commit", "selections",
    }
    _STAGE.exact_keys(required, required_fields, "required-path selection")
    _require(required["schema"] == _REQUIRED.RESULT_SCHEMA
             and required["assurance"] == _REQUIRED.ASSURANCE
             and required["plan_sha256"] == plan_sha and required["inputs_sha256"] == inputs_sha
             and required["producer_commit"] == producer and required["tools_commit"] == tools,
             "required-path selection does not rejoin the selected plan, inputs, and commits")
    _digest(required["selected_policy_sha256"], "selected policy digest")
    selections = required["selections"]
    _require(type(selections) is list and len(selections) == len(expected_lanes),
             "required-path selection does not cover every compiler lane")
    expected_lane_keys = {
        (lane["group_id"], lane["host"], lane["target_profile"])
        for lane in expected_lanes
    }
    required_by_lane: dict[tuple[str, str, str], list[str]] = {}
    for selected in selections:
        _STAGE.exact_keys(selected, {"group_id", "host", "target_profile", "required_paths"},
                          "required-path lane selection")
        key = (selected["group_id"], selected["host"], selected["target_profile"])
        _require(key in expected_lane_keys and key not in required_by_lane,
                 "required-path lane tuple is unexpected or duplicated")
        paths = selected["required_paths"]
        _require(type(paths) is list and 1 <= len(paths) <= _REQUIRED.MAX_PATHS_PER_PROFILE,
                 "required-path lane selection is empty or oversized")
        clean_paths = [_REQUIRED._validate_path(path) for path in paths]
        _require(clean_paths == sorted(set(clean_paths)),
                 "required paths are not sorted and unique")
        required_by_lane[key] = clean_paths
    _require(set(required_by_lane) == expected_lane_keys,
             "required-path selections do not join every exact native plan lane")

    matrix_path = owner_root / "matrix.json"
    matrix, _matrix_raw, _matrix_measurement = _read_json(
        matrix_path, MAX_FRAGMENT, "compiler owner matrix", selected_files
    )
    matrix_fields = {
        "schema", "assurance", "plan_sha256", "inputs_sha256", "source_context_sha256",
        "producer_commit", "tools_commit", "owners", "expected_compiler_lanes",
    }
    _STAGE.exact_keys(matrix, matrix_fields, "compiler owner matrix")
    _require(matrix["schema"] == "aros-compiler-owner-matrix-v2"
             and matrix["assurance"] == "owner-selection-only"
             and matrix["plan_sha256"] == plan_sha and matrix["inputs_sha256"] == inputs_sha
             and matrix["source_context_sha256"] == fragment["source_context_sha256"]
             and matrix["producer_commit"] == producer and matrix["tools_commit"] == tools
             and matrix["expected_compiler_lanes"] == expected_lanes,
             "compiler owner matrix bindings differ from the fragment and native plan")
    matrix_owners = matrix["owners"]
    _require(type(matrix_owners) is list and len(matrix_owners) == len(expected_rows),
             "compiler owner matrix does not contain the exact A/B plan")
    owner_map: dict[tuple[str, str, str, str], dict] = {}
    for owner in matrix_owners:
        _STAGE.exact_keys(owner, {
            "owner_id", "group_id", "host", "profile", "copy", "job_name",
            "payload_name", "proof_name", "recipe", "source_lock", "profiles",
        }, "compiler owner matrix row")
        key = (owner["group_id"], owner["host"], owner["profile"], owner["copy"])
        _require(key in expected_rows and key not in owner_map,
                 "compiler owner matrix contains an unexpected or duplicate owner")
        group = next(item for item in plan["groups"] if item["group_id"] == owner["group_id"])
        _require(owner["recipe"] == group["recipe"] and owner["source_lock"] == group["source_lock"]
                 and owner["profiles"] == group["profiles"]
                 and owner["owner_id"] == _COMPILER_MATRIX._owner_id(*key)
                 and owner["job_name"] ==
                 f"Native compiler ({owner['group_id']}, {owner['host']}, {owner['profile']}, {owner['copy']})",
                 "compiler owner matrix row differs from the native plan")
        owner_map[key] = owner
    _require(set(owner_map) == set(expected_rows), "compiler owner matrix is incomplete")

    _remember_directory(owner_root, "compiler owner root", snapshots)
    _require(_remember_directory(owner_root, "compiler owner root", snapshots) == {
        "matrix.json": "file", "owners": "directory", "selection-fragment.json": "file",
    }, "compiler owner root contains unexpected entries")
    owners_dir = owner_root / "owners"
    _remember_directory(owners_dir, "compiler owners directory", snapshots)
    expected_owner_ids = {owner["owner_id"] for owner in owner_map.values()}
    _require(_remember_directory(owners_dir, "compiler owners directory", snapshots) == {
        owner_id: "directory" for owner_id in expected_owner_ids
    }, "compiler owner directory inventory differs from the exact plan")

    root = args.root
    _require(root.is_absolute() and ".." not in root.parts and root.name not in ("", ".", ".."),
             "operation root must be an absolute normalized path")
    _require(root.parent == root.parent.resolve() and root.parent.is_dir()
             and not root.parent.is_symlink(), "operation root parent is not canonical")
    try:
        root.lstat()
    except FileNotFoundError:
        pass
    else:
        raise AssemblyError("operation root must be absent")
    for selected_path in (aros, plan_path, inputs_dir, source_context_path,
                          fragment_path, owner_root, required_path):
        _require(root != selected_path and root not in selected_path.parents
                 and selected_path not in root.parents,
                 "operation root overlaps a selected input")

    forbidden = _validate_forbidden_prefixes(args.forbidden_prefix)
    _require(forbidden, "at least one forbidden prefix is required")

    return {
        "aros": aros, "aros_sha256": runtime_sha, "plan_path": plan_path,
        "plan_sha256": plan_sha, "plan": plan, "inputs_dir": inputs_dir,
        "inputs_sha256": inputs_sha, "collection_path": collection_path,
        "producer_commit": producer, "tools_commit": tools,
        "source_context_path": source_context_path, "source_context": source_context,
        "source_context_sha256": source_context_sha, "source_event": source_event,
        "fragment_path": fragment_path, "fragment_sha256": fragment_sha,
        "fragment": fragment, "owner_root": owner_root,
        "required_path": required_path, "required_paths_sha256": required_sha,
        "required": required, "required_by_lane": required_by_lane,
        "expected_lanes": expected_lanes, "expected_rows": expected_rows,
        "group_refs": group_refs, "matrix": matrix, "owner_map": owner_map,
        "selected_files": selected_files, "snapshots": snapshots,
        "root": root, "release_id": release_id, "forbidden": forbidden,
    }


def _validate_forbidden_prefixes(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        _require(isinstance(value, str) and value.startswith("/") and "\n" not in value
                 and "\r" not in value and "\x00" not in value and ".." not in Path(value).parts
                 and len(value.encode("utf-8")) <= 4096,
                 "forbidden prefix must be a bounded absolute normalized path")
        result.append(value)
    _require(len(result) == len(set(result)), "forbidden prefixes must be unique")
    return result


def _validated_observation(row: dict, key: tuple[str, str, str, str], owner: dict,
                           data: dict) -> dict:
    group_id, host, profile, copy = key
    owner_root = data["owner_root"]
    owner_dir = owner_root / "owners" / owner["owner_id"]
    readback = owner_dir / "readback"
    payload = readback / "payload"
    package_dir = payload / "package"
    expected_paths = {
        "package_dir": package_dir,
        "measurement": payload / "evidence" / "measurement.json",
        "environment": payload / "evidence" / "environment.json",
        "observation": readback / "observation.json",
    }
    for field, expected_path in expected_paths.items():
        if field == "package_dir":
            selected_path = _path_field(row[field], "compiler package directory")
            _require(_STAGE.path_is_canonical(selected_path, must_exist=True)
                     and selected_path.is_dir(), "compiler package directory is linked or missing")
        else:
            selected_path = _path_field(row[field]["path"], f"compiler {field} path")
            _require(_STAGE.path_is_canonical(selected_path, must_exist=True),
                     f"compiler {field} path is linked or missing")
        _require(selected_path == expected_path,
                 f"compiler {field} path differs from its derived owner path")
    _require(owner_dir == owner_root / "owners" / owner["owner_id"]
             and _STAGE.path_is_canonical(owner_dir, must_exist=True),
             "compiler owner path is linked or noncanonical")
    _require(_remember_directory(owner_dir, "compiler owner directory", data["snapshots"]) == {
        "readback": "directory", "selection.json": "file",
    }, "compiler owner directory inventory differs")
    _require(_remember_directory(readback, "compiler owner readback directory", data["snapshots"]) == {
        "native-verification.json": "file", "observation.json": "file",
        "origin-verification.log": "file", "original-expectations.json": "file",
        "payload": "directory", "transport": "directory",
        "transport-readback.json": "file", "transport-result.json": "file",
        "transport-reverification.json": "file",
    }, "compiler owner readback inventory differs")
    _remember_directory(payload, "compiler owner payload", data["snapshots"])
    _require(_remember_directory(payload, "compiler owner payload", data["snapshots"]) == {
        "evidence": "directory", "package": "directory",
    }, "compiler owner payload inventory differs")
    _remember_directory(payload / "evidence", "compiler owner evidence", data["snapshots"])
    _require(_remember_directory(payload / "evidence", "compiler owner evidence", data["snapshots"]) == {
        "build-result.json": "file", "environment.json": "file", "environment-result.json": "file",
        "measurement.json": "file", "package-result.json": "file", "package-verify.json": "file",
    }, "compiler owner evidence inventory differs")
    retained = readback / "transport"
    _require(_STAGE.path_is_canonical(retained, must_exist=True) and retained.is_dir(),
             "compiler retained transport path is linked or missing")
    _remember_directory(retained, "compiler retained transport", data["snapshots"])
    _require(_remember_directory(retained, "compiler retained transport", data["snapshots"]) == {
        "origin.json": "file", "origin.sigstore.json": "file",
        "payload.zip": "file", "selection.json": "file",
    }, "compiler retained transport inventory differs")

    selection_path = owner_dir / "selection.json"
    selection, selection_raw, selection_measurement = _read_json(
        selection_path, MAX_METADATA, "compiler source selection", data["selected_files"]
    )
    observation_path = expected_paths["observation"]
    observation, observation_raw, observation_measurement = _read_json(
        observation_path, MAX_FRAGMENT, "original compiler observation", data["selected_files"]
    )
    _require(observation_measurement["sha256"] == row["observation"]["sha256"],
             "original compiler observation differs from the collector fragment digest")

    selection_obj = _ORIGIN.exact_keys(selection, {
        "schema", "context", "selection", "job", "artifact", "proof",
    })
    _require(selection_obj["schema"] == _ORIGIN.SELECTION_SCHEMA,
             "compiler source selection schema differs")
    context = _ORIGIN.validate_context(selection_obj["context"])
    selected_lane = _ORIGIN.exact_keys(selection_obj["selection"], {
        "role", "group", "host", "profile", "copy",
    })
    _require(_ORIGIN.selection(argparse.Namespace(**selected_lane)) == selected_lane
             and selected_lane == {"role": "build", "group": group_id, "host": host,
                                   "profile": profile, "copy": copy},
             "compiler source selection lane differs from its owner row")
    job = _ORIGIN.exact_keys(selection_obj["job"], {"id", "name"})
    _require(type(job["id"]) is int and _ORIGIN.positive(job["id"]) == job["id"]
             and job["name"] == owner["job_name"],
             "compiler source selection job differs from its owner matrix")
    for item_name in ("artifact", "proof"):
        _TRANSPORT._validate_artifact(selection_obj[item_name],
                                      2 * MAX_METADATA if item_name == "proof" else _ORIGIN.MAX_PAYLOAD)
    _require(selection_obj["artifact"]["name"] == owner["payload_name"]
             and selection_obj["proof"]["name"] == owner["proof_name"],
             "compiler source artifact or proof name differs from the selected owner matrix")
    _require(context["workflow"] == data["fragment"]["source_workflow"]
             and context["source_ref"] == data["fragment"]["source_ref"]
             and context["producer_commit"] == data["fragment"]["source_producer_commit"],
             "compiler source context differs from its authenticated collector binding")
    _require(owner["payload_name"] ==
             f"native-v2-{owner['owner_id']}-{context['run_id']}-{context['run_attempt']}"
             and owner["proof_name"] ==
             f"native-v2-proof-{owner['owner_id']}-{context['run_id']}-{context['run_attempt']}",
             "compiler source artifact names differ from the original owner run context")
    context_raw = _ORIGIN.canonical(context)
    _require(hashlib.sha256(context_raw).hexdigest() == data["fragment"]["source_context_sha256"],
             "compiler source context bytes differ from the selected context digest")
    prior_context = data.setdefault("source_context", context)
    _require(prior_context == context, "compiler A/B owners do not share one selected source context")

    observation_fields = {
        "schema", "assurance", "scope", "current_workflow", "current_job_name",
        "source_workflow", "source_ref", "group", "host", "target_profile", "copy",
        "release_id", "reader_runtime_sha256", "recipe_file_sha256", "source_lock_sha256",
        "profiles_sha256", "source_selection_sha256", "build_result_sha256",
        "environment_sha256", "measurement_sha256", "executor_contract_id",
        "executor_contract_sha256", "executor_binary_sha256", "original_identity",
        "transport", "native",
    }
    _STAGE.exact_keys(observation, observation_fields, "original compiler observation")
    _require(observation["schema"] == "aros-toolchain-original-owner-observation-v2"
             and observation["assurance"] == "authenticated-original-job-and-native-byte-readback-only",
             "original compiler observation schema or assurance differs")
    scope = _STAGE.exact_keys(observation["scope"], {
        "original_owner_job_observation", "native_package_byte_readback",
        "independently_executed_collector", "release_admission", "publication",
    }, "original compiler observation scope")
    _require(scope == {"original_owner_job_observation": True,
                       "native_package_byte_readback": True,
                       "independently_executed_collector": False,
                       "release_admission": False, "publication": False},
             "original compiler observation scope has unsupported authority")
    expected_group = next(group for group in data["plan"]["groups"] if group["group_id"] == group_id)
    _require(observation["current_workflow"] == data["fragment"]["workflow"]
             and observation["current_job_name"] == data["fragment"]["job_name"]
             and observation["source_workflow"] == data["fragment"]["source_workflow"]
             and observation["source_ref"] == data["fragment"]["source_ref"]
             and observation["group"] == group_id and observation["host"] == host
             and observation["target_profile"] == profile and observation["copy"] == copy
             and observation["release_id"] == data["release_id"]
             and observation["reader_runtime_sha256"] == data["aros_sha256"],
             "original compiler observation differs from its collector or native plan selectors")
    for field, group_field in (("recipe_file_sha256", "recipe"),
                               ("source_lock_sha256", "source_lock"),
                               ("profiles_sha256", "profiles")):
        _require(observation[field] == expected_group[group_field]["sha256"],
                 f"original compiler {field} differs from the native plan")
    build_result_sha = _digest(observation["build_result_sha256"], "original build-result digest")
    environment_sha = _digest(observation["environment_sha256"], "original environment digest")
    measurement_sha = _digest(observation["measurement_sha256"], "original measurement digest")
    _require(observation["source_selection_sha256"] == selection_measurement["sha256"],
             "original compiler selection digest differs from the retained selection")
    _require(observation["executor_contract_id"] == "aros-toolchain-producer-v1"
             and observation["executor_contract_sha256"] == row["executor"]["contract_sha256"]
             and observation["executor_binary_sha256"] == row["executor"]["binary_sha256"],
             "original compiler executor differs from its collector-bound selector")
    identity = _STAGE.exact_keys(observation["original_identity"], {
        "recipe_self_sha256", "source_commit", "producer_commit", "tools_commit", "host",
        "target_profile",
    }, "original compiler identity")
    _digest(identity["recipe_self_sha256"], "original recipe self digest")
    _require(identity["source_commit"] == expected_group["source_commit"]
             and identity["producer_commit"] == data["producer_commit"]
             and identity["tools_commit"] == data["tools_commit"]
             and identity["host"] == host and identity["target_profile"] == profile,
             "original compiler identity differs from the native plan")

    environment = None
    for field, expected_sha in (("measurement", measurement_sha), ("environment", environment_sha)):
        path = expected_paths[field]
        measured, _raw = _record_file(path, MAX_METADATA, f"original {field}", data["selected_files"], read=True)
        _require(measured["sha256"] == expected_sha and row[field]["sha256"] == expected_sha,
                 f"original {field} bytes differ from both native and collector selectors")
        if field == "environment":
            environment = _STAGE.parse_json(_raw, "original build environment")
            _require(isinstance(environment, dict), "original build environment must be a JSON object")
    build_path = payload / "evidence" / "build-result.json"
    build_measurement, _ = _record_file(build_path, MAX_METADATA, "original build result",
                                        data["selected_files"])
    _require(build_measurement["sha256"] == build_result_sha,
             "original build-result bytes differ from the authenticated observation")

    expectations_path = readback / "original-expectations.json"
    expectations, _expectations_raw, _expectations_measurement = _read_json(
        expectations_path, MAX_METADATA, "original compiler expectations", data["selected_files"]
    )
    _require(expectations == {
        "build_result_sha256": build_result_sha,
        "recipe_self_sha256": identity["recipe_self_sha256"],
        "source_commit": identity["source_commit"],
        "producer_commit": identity["producer_commit"],
        "tools_commit": identity["tools_commit"],
        "host": identity["host"], "target_profile": identity["target_profile"],
        "executor_contract_id": observation["executor_contract_id"],
        "executor_contract_sha256": observation["executor_contract_sha256"],
        "executor_binary_sha256": observation["executor_binary_sha256"],
    }, "original compiler execution expectations differ from its selected observation")
    native_path = readback / "native-verification.json"
    original_native, _native_raw, native_file_measurement = _read_json(
        native_path, MAX_NATIVE_RESULT, "original native verification result", data["selected_files"]
    )
    _require(original_native == observation["native"],
             "original native verification file differs from the selected observation")

    native = _validate_original_native_result(observation["native"], key, identity,
                                              build_result_sha, measurement_sha, data)
    retained = readback / "transport"
    payload_root = readback / "payload"
    transport_result_path = readback / "transport-result.json"
    transport_result, _transport_raw, transport_measurement = _read_json(
        transport_result_path, MAX_FRAGMENT, "collector-bound transport result", data["selected_files"]
    )
    _require(transport_result == observation["transport"],
             "collector transport result differs from the selected observation")
    transport = _TRANSPORT.verify_output(retained, payload_root)
    _require(transport == observation["transport"] == transport_result,
             "retained original-owner transport does not reverify to its collector-bound observation")
    _require(transport["package_dir"] == str(package_dir)
             and transport["measurement"] == str(expected_paths["measurement"])
             and transport["environment"] == str(expected_paths["environment"]),
             "native transport output paths differ from the selected compiler owner")
    _require(transport["selection_sha256"] == selection_measurement["sha256"],
             "retained transport selection digest differs from its selected source")
    origin_path = retained / "origin.json"
    origin, _origin_raw, origin_measurement = _read_json(
        origin_path, MAX_ORIGIN_BYTES, "retained original origin", data["selected_files"]
    )
    _require(origin_measurement["sha256"] == transport["origin_sha256"],
             "retained origin bytes differ from the collector-captured origin digest")
    signed_job = _ORIGIN.exact_keys(origin["job"], {"id", "check_run_id", "name"})
    _require(type(signed_job["id"]) is int and _ORIGIN.positive(signed_job["id"]) == signed_job["id"]
             and signed_job["id"] == job["id"] and signed_job["name"] == job["name"],
             "retained origin job does not join the selected original owner")
    _require(origin["selection"] == selected_lane and origin["context"] == context,
             "retained origin source context or lane differs from the selected source")
    _require(transport["selection_sha256"] == hashlib.sha256(
        _ORIGIN.canonical({
            "schema": selection_obj["schema"], "context": selection_obj["context"],
            "selection": selection_obj["selection"], "job": selection_obj["job"],
            "artifact": selection_obj["artifact"], "proof": selection_obj["proof"],
        })
    ).hexdigest(), "transport source selection bytes differ from selected identity")
    origin_ids = data.setdefault("origin_job_ids", set())
    _require(signed_job["id"] not in origin_ids,
             "original compiler owner job IDs are not globally unique")
    origin_ids.add(signed_job["id"])

    payload_inventory = transport["output_files"]
    package_inventory = {
        name.removeprefix("package/"): value for name, value in payload_inventory.items()
        if name.startswith("package/")
    }
    _require(len(package_inventory) == 4, "native transport output does not contain four package members")
    archive_names = [name for name in package_inventory if name.endswith(".tar.xz")]
    _require(len(archive_names) == 1, "native transport output does not contain one package archive")
    archive_name = archive_names[0]
    _require(set(package_inventory) == {
        archive_name, archive_name + ".manifest.json", archive_name + ".sha256",
        archive_name + ".spdx.json",
    } and set(payload_inventory) == set(_TRANSPORT.EVIDENCE_NAMES) | {
        f"package/{name}" for name in package_inventory
    }, "native transport output does not have the exact compiler lane closure")
    archive_member = _STAGE.exact_keys(
        package_inventory[archive_name], {"path", "sha256", "size"},
        "retained compiler package archive",
    )
    _require(archive_member["path"] == str(package_dir / archive_name)
             and archive_member["sha256"] == native["sha256"]
             and archive_member["size"] == native["size"],
             "original native package digest or size differs from the retained payload archive")
    _require(transport["output_files"]["evidence/build-result.json"]["sha256"] == build_result_sha
             and transport["output_files"]["evidence/measurement.json"]["sha256"] == measurement_sha
             and transport["output_files"]["evidence/environment.json"]["sha256"] == environment_sha,
             "retained transport inventory differs from selected compiler evidence")

    payload_files = [payload_root / name for name in payload_inventory]
    for path in payload_files:
        limit = _ORIGIN.MAX_PAYLOAD if path.name.endswith(".tar.xz") else MAX_METADATA
        _record_file(path, limit, f"retained output {path.name}", data["selected_files"])
    for name in ("payload.zip", "selection.json", "origin.sigstore.json"):
        limit = _ORIGIN.MAX_PAYLOAD if name == "payload.zip" else MAX_ORIGIN_BYTES
        _record_file(retained / name, limit, f"retained transport {name}", data["selected_files"])
    transport_sigstore_sha = data["selected_files"][retained / "origin.sigstore.json"][1]["sha256"]
    transport_zip_sha = data["selected_files"][retained / "payload.zip"][1]["sha256"]
    _require(transport_zip_sha == transport["raw_zip_sha256"],
             "retained payload ZIP differs from the collector-captured transport digest")
    return {
        "key": key, "owner": owner, "owner_id": owner["owner_id"],
        "owner_dir": owner_dir, "readback": readback, "payload_root": payload_root,
        "package_dir": package_dir, "measurement_path": expected_paths["measurement"],
        "environment_path": expected_paths["environment"], "observation_path": observation_path,
        "observation_sha256": observation_measurement["sha256"],
        "transport": transport, "origin_sha256": transport["origin_sha256"],
        "selection_sha256": transport["selection_sha256"], "payload_zip_sha256": transport_zip_sha,
        "sigstore_sha256": transport_sigstore_sha, "original_job_id": signed_job["id"],
        "build_result_sha256": build_result_sha, "measurement_sha256": measurement_sha,
        "environment_sha256": environment_sha,
        "environment": environment,
        "executor": dict(row["executor"]), "original_native": native,
        "identity": identity, "selection_sha256_owner": selection_measurement["sha256"],
        "native_verification_path": native_path,
        "native_verification_sha256": native_file_measurement["sha256"],
        "native_package_tree_sha256": _digest(
            observation["native"]["finished_candidate"]["package_tree_sha256"],
            "original verified package tree digest",
        ),
    }


def _validate_original_native_result(value: object, key: tuple[str, str, str, str],
                                     identity: dict, build_sha: str, measurement_sha: str,
                                     data: dict) -> dict:
    result = _STAGE.exact_keys(value, {
        "schema", "operation", "sha256", "size", "manifest", "finished_candidate",
    }, "original native package verification")
    _require(result["schema"] == "aros-toolchain-producer-stage-v1"
             and result["operation"] == "verify-package",
             "original native package verification schema or operation differs")
    package_sha = _digest(result["sha256"], "original package archive digest")
    _require(type(result["size"]) is int and result["size"] > 0,
             "original package archive size is invalid")
    group_id, host, profile, _copy = key
    manifest = result["manifest"]
    _require(isinstance(manifest, dict), "original package manifest is missing")
    _require(manifest.get("schema") == 2 and manifest.get("release_id") == data["release_id"]
             and manifest.get("host") == host and manifest.get("target_profile") == profile
             and manifest.get("recipe_sha256") == identity["recipe_self_sha256"]
             and manifest.get("source_lock_sha256") == next(
                 group["source_lock"]["sha256"] for group in data["plan"]["groups"]
                 if group["group_id"] == group_id)
             and manifest.get("profiles_sha256") == next(
                 group["profiles"]["sha256"] for group in data["plan"]["groups"]
                 if group["group_id"] == group_id)
             and manifest.get("source_commit") == identity["source_commit"]
             and manifest.get("producer_commit") == data["producer_commit"]
             and manifest.get("tools_commit") == data["tools_commit"],
             "original native package manifest differs from the selected lane or group documents")
    tree_sha = _digest(manifest.get("tree_sha256"), "original package tree digest")
    finished = _STAGE.exact_keys(result["finished_candidate"], {
        "schema", "assurance", "measurement_sha256", "build_result_sha256",
        "package_tree_sha256", "finished_receipt_sha256", "raw_payload_sha256",
    }, "original portable package result")
    _require(finished["schema"] == "aros-toolchain-portable-package-readback-v2"
             and finished["assurance"] == "portable-byte-readback-only"
             and finished["measurement_sha256"] == measurement_sha
             and finished["build_result_sha256"] == build_sha
             and finished["package_tree_sha256"] == tree_sha,
             "original portable package result differs from selected measurement, build, or manifest")
    for field in ("finished_receipt_sha256", "raw_payload_sha256"):
        _digest(finished[field], f"original portable {field}")
    return {"sha256": package_sha, "size": result["size"], "tree_sha256": tree_sha,
            "manifest": manifest, "finished_candidate": finished}


def _transport_rows(data: dict) -> dict[tuple[str, str, str, str], dict]:
    result = {}
    for row in data["fragment"]["compiler_builds"]:
        key = (row["group_id"], row["host"], row["target_profile"], row["copy"])
        owner = data["owner_map"][key]
        result[key] = _validated_observation(row, key, owner, data)
    job_ids_by_lane: dict[tuple[str, str, str], set[int]] = {}
    for key, selected in result.items():
        job_ids_by_lane.setdefault(key[:3], set()).add(selected["original_job_id"])
    _require(all(len(ids) == 2 for ids in job_ids_by_lane.values()),
             "each compiler A/B lane must have two distinct positive original owner job IDs")
    return result


def _verify_transports(selected_rows: dict) -> None:
    for selected in selected_rows.values():
        actual = _TRANSPORT.verify_output(selected["readback"] / "transport",
                                          selected["payload_root"])
        _require(actual == selected["transport"],
                 "native transport reverification differs from the collector-bound original result")


def _lane_id(key: tuple[str, str, str]) -> str:
    group, host, profile = key
    suffix = hashlib.sha256("\0".join(key).encode("utf-8")).hexdigest()[:12]
    value = f"{group}--{host}--{profile}--{suffix}"
    _require(LANE_ID_COMPONENT.fullmatch(value) is not None,
             "derived compiler lane identifier is not a safe file name")
    return value


def _ensure_directory(path: Path) -> None:
    os.mkdir(path, mode=0o700)
    os.chmod(path, 0o700, follow_symlinks=False)
    metadata = path.lstat()
    _require(stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode)
             and metadata.st_uid == os.geteuid() and stat.S_IMODE(metadata.st_mode) == 0o700,
             "owned output directory is not a private ordinary directory")


def _write_owned(path: Path, raw: bytes, label: str) -> dict:
    _require(path.parent.is_dir() and _STAGE.path_is_canonical(path.parent, must_exist=True),
             f"{label} parent is not a canonical owned directory")
    descriptor = os.open(path, CREATE_FLAGS, 0o600)
    try:
        before = os.fstat(descriptor)
        _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                 and before.st_uid == os.geteuid(), f"{label} is not a private regular file")
        os.fchmod(descriptor, 0o600)
        identity_before = (before.st_dev, before.st_ino, before.st_mode,
                           before.st_nlink, before.st_uid)
        digest = hashlib.sha256()
        size = 0
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            _require(written > 0, f"{label} write was incomplete")
            digest.update(view[:written])
            size += written
            view = view[written:]
        os.fsync(descriptor)
        after = os.fstat(descriptor)
        named = path.lstat()
        identity_after = (after.st_dev, after.st_ino, after.st_mode,
                          after.st_nlink, after.st_uid)
        _require(identity_before == identity_after
                 and _stat_fingerprint(after) == _stat_fingerprint(named)
                 and after.st_size == size and stat.S_IMODE(named.st_mode) == 0o600,
                 f"{label} changed during write")
        return {"path": str(path), "sha256": digest.hexdigest(), "size": size}
    finally:
        os.close(descriptor)


def _create_limited_file(path: Path) -> Any:
    descriptor = os.open(path, CREATE_FLAGS, 0o600)
    metadata = os.fstat(descriptor)
    _require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
             and metadata.st_uid == os.geteuid(), "native result output is not an owned regular file")
    return os.fdopen(descriptor, "wb")


def _native_preexec() -> None:
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_NATIVE_RESULT, MAX_NATIVE_RESULT))


def _run_native(data: dict, output: Path, args: list[str], label: str,
                selected_files: dict) -> dict:
    _require(not output.exists() and not output.is_symlink(), f"{label} result path is not fresh")
    stderr_path = output.with_suffix(output.suffix + ".stderr.log")
    _require(not stderr_path.exists() and not stderr_path.is_symlink(),
             f"{label} diagnostic path is not fresh")
    _verify_selected_files(selected_files, include_payload=False)
    stdout_handle = _create_limited_file(output)
    stderr_handle = _create_limited_file(stderr_path)
    try:
        process = subprocess.Popen(
            [str(data["aros"]), *args], stdin=subprocess.DEVNULL,
            stdout=stdout_handle, stderr=stderr_handle, close_fds=True,
            start_new_session=True, preexec_fn=_native_preexec,
        )
        try:
            return_code = process.wait(timeout=NATIVE_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            raise AssemblyError(f"{label} native CLI timed out; owned process group was terminated") from None
    finally:
        stdout_handle.close()
        stderr_handle.close()
    _require(return_code == 0, f"{label} native CLI failed with exit status {return_code}")
    _require(output.is_file() and not output.is_symlink()
             and output.stat().st_size <= MAX_NATIVE_RESULT
             and stderr_path.is_file() and not stderr_path.is_symlink()
             and stderr_path.stat().st_size <= MAX_NATIVE_RESULT,
             f"{label} native CLI output exceeded its bound or changed type")
    result, raw, measured = _read_json(
        output, MAX_NATIVE_RESULT, f"{label} native result", selected_files
    )
    _require(len(raw) > 0 and measured["size"] <= MAX_NATIVE_RESULT,
             f"{label} native result is empty or oversized")
    _record_file(stderr_path, MAX_NATIVE_RESULT, f"{label} native diagnostics", selected_files)
    _verify_selected_files(selected_files, include_payload=False)
    return {"result": result, "path": output, "sha256": measured["sha256"],
            "size": measured["size"], "stderr_path": stderr_path}


def _validate_verify_result(result: dict, selected: dict, data: dict) -> dict:
    _STAGE.exact_keys(result, {
        "schema", "operation", "sha256", "size", "manifest", "finished_candidate",
    }, "native portable package verification result")
    _require(result["schema"] == "aros-toolchain-producer-stage-v1"
             and result["operation"] == "verify-package",
             "native package verification schema or operation differs")
    _require(result["sha256"] == selected["original_native"]["sha256"]
             and type(result["size"]) is int
             and result["size"] == selected["original_native"]["size"],
             "native package archive digest or size differs from its original-owner observation")
    key = selected["key"]
    group, host, profile, _copy = key
    plan_group = next(item for item in data["plan"]["groups"] if item["group_id"] == group)
    manifest = result["manifest"]
    _require(isinstance(manifest, dict) and manifest.get("schema") == 2
             and manifest.get("release_id") == data["release_id"]
             and manifest.get("host") == host and manifest.get("target_profile") == profile
             and manifest.get("recipe_sha256") == selected["identity"]["recipe_self_sha256"]
             and manifest.get("source_lock_sha256") == plan_group["source_lock"]["sha256"]
             and manifest.get("profiles_sha256") == plan_group["profiles"]["sha256"]
             and manifest.get("source_commit") == selected["identity"]["source_commit"]
             and manifest.get("producer_commit") == data["producer_commit"]
             and manifest.get("tools_commit") == data["tools_commit"],
             "native verified manifest differs from the selected tuple, release, or group documents")
    _require(manifest.get("tree_sha256") == selected["original_native"]["tree_sha256"],
             "native verified package tree differs from the original native observation")
    finished = _STAGE.exact_keys(result["finished_candidate"], {
        "schema", "assurance", "measurement_sha256", "build_result_sha256",
        "package_tree_sha256", "finished_receipt_sha256", "raw_payload_sha256",
    }, "native portable package readback")
    _require(finished["schema"] == "aros-toolchain-portable-package-readback-v2"
             and finished["assurance"] == "portable-byte-readback-only"
             and finished["measurement_sha256"] == selected["measurement_sha256"]
             and finished["build_result_sha256"] == selected["build_result_sha256"]
             and finished["package_tree_sha256"] == manifest["tree_sha256"]
             and finished["finished_receipt_sha256"] ==
             selected["original_native"]["finished_candidate"]["finished_receipt_sha256"]
             and finished["raw_payload_sha256"] ==
             selected["original_native"]["finished_candidate"]["raw_payload_sha256"],
             "native portable readback differs from original measurement, build result, or package tree")
    for field in ("finished_receipt_sha256", "raw_payload_sha256"):
        _digest(finished[field], f"native portable {field}")
    return {"sha256": result["sha256"], "size": result["size"],
            "tree_sha256": manifest["tree_sha256"], "manifest": manifest}


def _closed_outer_members(package_dir: Path, selected_files: dict) -> dict:
    entries = _STAGE.directory_entries(package_dir, "native-verified package directory")
    _require(0 < len(entries) <= 4 and all(kind == "file" for kind in entries.values()),
             "native-verified package directory must contain exactly four regular files")
    inventory = {f"package/{name}": {} for name in entries}
    _STAGE.require_portable_inventory(inventory)
    archives = [name for name in entries if name.endswith(".tar.xz")]
    _require(len(archives) == 1, "native-verified package must contain one archive")
    archive = archives[0]
    _require(entries == {
        archive: "file", archive + ".manifest.json": "file",
        archive + ".sha256": "file", archive + ".spdx.json": "file",
    }, "native-verified package directory does not contain its exact four-member closure")
    measured_members = {}
    for name in sorted(entries):
        path = package_dir / name
        limit = _ORIGIN.MAX_PAYLOAD if name == archive else MAX_METADATA
        measured, _ = _record_file(path, limit, f"verified package member {name}", selected_files)
        measured_members[name] = measured
    return {"archive": archive, "members": measured_members}


def _validate_compare_result(compare: dict, expected_receipt_path: Path, members: dict,
                             selected_files: dict) -> dict:
    result = compare["result"]
    _STAGE.exact_keys(result, {
        "schema", "operation", "byte_identical", "receipt", "receipt_sha256",
        "package_set_sha256", "members",
    }, "native package comparison result")
    _require(result["schema"] == "aros-toolchain-producer-stage-v1"
             and result["operation"] == "compare" and result["byte_identical"] is True,
             "native package comparison did not confirm byte identity")
    receipt_path = _path_field(result["receipt"], "native comparison receipt path")
    _require(receipt_path == expected_receipt_path
             and _STAGE.path_is_canonical(receipt_path, must_exist=True),
             "native comparison receipt path differs from the requested fresh report")
    _digest(result["receipt_sha256"], "native comparison receipt digest")
    _digest(result["package_set_sha256"], "native comparison package-set digest")
    receipt, receipt_raw, receipt_measurement = _read_json(
        receipt_path, MAX_NATIVE_RESULT, "native package comparison receipt", selected_files
    )
    _require(receipt_measurement["sha256"] == result["receipt_sha256"],
             "native comparison receipt bytes differ from the native CLI response")
    _STAGE.exact_keys(receipt, {
        "schema", "operation", "byte_identical", "package_set_sha256", "members",
    }, "native package comparison receipt")
    _require(type(receipt["schema"]) is int and receipt["schema"] == 1 and receipt["operation"] == "compare"
             and receipt["byte_identical"] is True
             and receipt["package_set_sha256"] == result["package_set_sha256"],
             "native comparison receipt schema or identity differs from its CLI result")
    for selected_members in (receipt["members"], result["members"]):
        _require(type(selected_members) is list, "native comparison members are not a closed list")
        for member in selected_members:
            _STAGE.exact_keys(member, {"name", "sha256", "size"}, "native comparison member")
            _require(type(member["size"]) is int and member["size"] >= 0,
                     "native comparison member size must be an unsigned integer")
    expected_members = []
    for name in sorted(members["a"]["members"]):
        left = members["a"]["members"][name]
        right = members["b"]["members"].get(name)
        _require(right == left, "A/B package members differ before native comparison")
        expected_members.append({"name": name, "sha256": left["sha256"], "size": left["size"]})
    expected_set_sha256 = hashlib.sha256(_ORIGIN.canonical(expected_members)).hexdigest()
    _require(receipt["members"] == expected_members and result["members"] == expected_members,
             "native comparison member report does not rejoin the exact A/B package bytes")
    _require(result["package_set_sha256"] == expected_set_sha256,
             "native comparison package-set digest differs from its exact reported members")
    _require(bool(receipt_raw) and receipt_measurement["size"] <= MAX_NATIVE_RESULT,
             "native comparison report is empty or oversized")
    return {"path": receipt_path, "sha256": receipt_measurement["sha256"],
            "size": receipt_measurement["size"], "package_set_sha256": result["package_set_sha256"],
            "members": expected_members, "result_path": compare["path"],
            "result_sha256": compare["sha256"]}


def _copy_regular(source: Path, destination: Path, expected: dict) -> dict:
    source_measure = _STAGE.measure_file(source, _ORIGIN.MAX_PAYLOAD if source.name.endswith(".tar.xz")
                                        else MAX_METADATA, "source package member")
    _require(source_measure == expected, "source package member changed before staging")
    source_flags = FILE_FLAGS | getattr(os, "O_NONBLOCK", 0)
    source_fd = os.open(source, source_flags)
    destination_fd = os.open(destination, CREATE_FLAGS, 0o600)
    digest = hashlib.sha256()
    size = 0
    try:
        source_before = os.fstat(source_fd)
        destination_before = os.fstat(destination_fd)
        _require(stat.S_ISREG(source_before.st_mode) and source_before.st_nlink == 1
                 and source_before.st_uid == os.geteuid()
                 and stat.S_ISREG(destination_before.st_mode) and destination_before.st_nlink == 1
                 and destination_before.st_uid == os.geteuid(),
                 "package staging source or destination is not an owned regular file")
        os.fchmod(destination_fd, 0o600)
        while True:
            block = os.read(source_fd, 1024 * 1024)
            if not block:
                break
            size += len(block)
            _require(size <= expected["size"], "source package member grew during streamed staging")
            digest.update(block)
            view = memoryview(block)
            while view:
                written = os.write(destination_fd, view)
                _require(written > 0, "staged package member write was incomplete")
                view = view[written:]
        os.fsync(destination_fd)
        source_after = os.fstat(source_fd)
        destination_after = os.fstat(destination_fd)
        _require(_stat_fingerprint(source_before) == _stat_fingerprint(source_after)
                 and size == expected["size"] and digest.hexdigest() == expected["sha256"]
                 and stat.S_ISREG(destination_after.st_mode) and destination_after.st_nlink == 1,
                 "streamed source package bytes differ from the native-verified member")
    finally:
        os.close(source_fd)
        os.close(destination_fd)
    source_after_readback = _STAGE.measure_file(
        source, _ORIGIN.MAX_PAYLOAD if source.name.endswith(".tar.xz") else MAX_METADATA,
        "source package member after staging",
    )
    target_measurement = _STAGE.measure_file(
        destination, _ORIGIN.MAX_PAYLOAD if destination.name.endswith(".tar.xz") else MAX_METADATA,
        "staged package member",
    )
    _require(source_after_readback == expected == target_measurement,
             "staged A package member is not byte-identical to its selected native package")
    return target_measurement


def _run_verify(data: dict, selected: dict, copy: str, native_dir: Path) -> dict:
    key = selected["key"]
    group, host, profile, _row_copy = key
    plan_group = next(item for item in data["plan"]["groups"] if item["group_id"] == group)
    args = [
        "toolchain", "producer", "verify-package",
        "--recipe", str(data["group_refs"][group]["recipe"]),
        "--source-lock", str(data["group_refs"][group]["source_lock"]),
        "--profiles", str(data["group_refs"][group]["profiles"]),
        f"--preset={profile}", "--host", host, "--release-id", data["release_id"],
        "--build-environment", str(selected["environment_path"]),
        "--package-format", "family-v2", "--input-dir", str(selected["package_dir"]),
        "--package-measurement", str(selected["measurement_path"]),
        "--package-measurement-sha256", selected["measurement_sha256"],
        "--executor-contract-sha256", selected["executor"]["contract_sha256"],
        "--executor-binary-sha256", selected["executor"]["binary_sha256"],
    ]
    for prefix in data["forbidden"]:
        args.extend(("--forbidden-prefix", prefix))
    args.extend(("--format", "json"))
    out = native_dir / f"verify-{_lane_id(key[:3])}-{copy}.json"
    result = _run_native(data, out, args, f"{group}/{host}/{profile}/{copy} verification",
                         data["selected_files"])
    result["selected"] = selected
    result["verification"] = _validate_verify_result(result["result"], selected, data)
    return result


def _build_evidence(selected: dict, native: dict, copy: str) -> dict:
    return {
        "copy": copy,
        "original_job_id": selected["original_job_id"],
        "origin_sha256": selected["origin_sha256"],
        "selection_sha256": selected["selection_sha256"],
        "payload_zip_sha256": selected["payload_zip_sha256"],
        "origin_sigstore_sha256": selected["sigstore_sha256"],
        "package": {
            "directory": str(selected["package_dir"]),
            "archive": native["verification"]["sha256"],
            "archive_sha256": native["verification"]["sha256"],
            "archive_size": native["verification"]["size"],
        },
        "measurement": {"path": str(selected["measurement_path"]),
                        "sha256": selected["measurement_sha256"]},
        "executor": dict(selected["executor"]),
        "build_result_sha256": selected["build_result_sha256"],
        "original_observation": {"path": str(selected["observation_path"]),
                                 "sha256": selected["observation_sha256"]},
        "original_native_verification": {
            "path": str(selected["native_verification_path"]),
            "sha256": selected["native_verification_sha256"],
        },
        "native_verification": {"path": str(native["path"]), "sha256": native["sha256"]},
    }


def _copy_index_lanes(lanes: dict) -> dict:
    return {
        "schema": "aros-toolchain-index-lanes-v1",
        "lanes": {
            asset: {"build_environment": selection["build_environment"],
                    "required_paths": selection["required_paths"]}
            for asset, selection in sorted(lanes.items())
        },
    }


def _file_selector(path: Path) -> dict:
    measured = _STAGE.measure_file(path, MAX_NATIVE_RESULT, "owned operation output")
    return {"path": str(path), "sha256": measured["sha256"], "size": measured["size"]}


def assemble(args: argparse.Namespace) -> dict:
    data = _read_bound_inputs(args)
    rows = _transport_rows(data)
    # These readbacks must be adjacent to the authenticated collector and run
    # before any native package or comparison command.
    _verify_transports(rows)
    _verify_selected_files(data["selected_files"])
    _verify_directories(data["snapshots"])

    root = data["root"]
    os.mkdir(root, mode=0o700)
    os.chmod(root, 0o700, follow_symlinks=False)
    _require(_STAGE.path_is_canonical(root, must_exist=True)
             and stat.S_IMODE(root.lstat().st_mode) == 0o700
             and root.lstat().st_uid == os.geteuid(),
             "owned operation root is not a private canonical directory")
    native_dir = root / "native"
    reports_dir = root / "reports"
    _ensure_directory(native_dir)
    _ensure_directory(reports_dir)

    comparisons: dict = {}
    for lane in data["expected_lanes"]:
        key3 = (lane["group_id"], lane["host"], lane["target_profile"])
        a = rows[(*key3, "a")]
        b = rows[(*key3, "b")]
        native_a = _run_verify(data, a, "a", native_dir)
        native_b = _run_verify(data, b, "b", native_dir)
        _require(a["environment_sha256"] == b["environment_sha256"]
                 and a["environment"] == b["environment"],
                 "compiler A/B lane does not select one identical native build environment")
        members_a = _closed_outer_members(a["package_dir"], data["selected_files"])
        members_b = _closed_outer_members(b["package_dir"], data["selected_files"])
        _require(members_a == members_b, "compiler A/B original-owner package members differ")
        lane_id = _lane_id(key3)
        receipt_path = reports_dir / f"{lane_id}.json"
        compare_stdout = native_dir / f"compare-{lane_id}.json"
        compare_args = ["toolchain", "producer", "compare", "--left", str(a["package_dir"]),
                        "--right", str(b["package_dir"]), "--output", str(receipt_path),
                        "--format", "json"]
        compare_result = _run_native(data, compare_stdout, compare_args,
                                     f"{lane_id} A/B comparison", data["selected_files"])
        compare_result["receipt_path"] = receipt_path
        compare_result["selected_files"] = data["selected_files"]
        comparison = _validate_compare_result(compare_result, receipt_path,
                                              {"a": members_a, "b": members_b},
                                              data["selected_files"])
        comparisons[key3] = {
            "comparison": comparison, "row_a": a, "row_b": b,
            "native_a": native_a, "native_b": native_b,
            "members": members_a,
        }

    release_dir = root / "release"
    _ensure_directory(release_dir)
    index_lanes: dict[str, dict] = {}
    evidence_assets: dict[str, dict] = {}
    staged: dict[str, dict] = {}
    folded_assets: dict[str, str] = {}
    folded_members: dict[str, str] = {}
    for key3, selected in sorted(comparisons.items()):
        a = selected["row_a"]
        b = selected["row_b"]
        members = selected["members"]
        archive = members["archive"]
        _require(archive.casefold() not in folded_assets,
                 "compiler asset names collide under case folding")
        folded_assets[archive.casefold()] = archive
        for member_name in sorted(members["members"]):
            folded = member_name.casefold()
            _require(folded not in folded_members,
                     "compiler staged members collide under case folding")
            folded_members[folded] = member_name
            staged[member_name] = _copy_regular(
                a["package_dir"] / member_name, release_dir / member_name,
                members["members"][member_name],
            )
        index_lanes[archive] = {
            "build_environment": a["environment"],
            "required_paths": data["required_by_lane"][key3],
        }
        evidence_assets[archive] = {
            "group_id": key3[0], "host": key3[1], "target_profile": key3[2],
            "builds": [
                _build_evidence(a, selected["native_a"], "a"),
                _build_evidence(b, selected["native_b"], "b"),
            ],
            "comparison": {"selectedFile": {
                "path": str(selected["comparison"]["path"]),
                "sha256": selected["comparison"]["sha256"],
            }},
        }

    # The source transport is revalidated after all native work and streamed
    # copies; the selected collector evidence and plan inputs must still match.
    _verify_transports(rows)
    _verify_selected_files(data["selected_files"])
    _verify_directories(data["snapshots"])
    _verify_staged(staged, release_dir)

    index_path = root / "compiler-index-lanes.json"
    index_doc = _copy_index_lanes(index_lanes)
    index_selector = _write_owned(index_path, _ORIGIN.canonical(index_doc), "compiler index lanes")
    index_measurement, _ = _record_file(index_path, MAX_FRAGMENT, "owned compiler index lanes", data["selected_files"])
    _require(index_measurement == {"sha256": index_selector["sha256"], "size": index_selector["size"]},
             "compiler index lanes changed after their owned write")
    evidence_doc = {
        "schema": "aros-toolchain-compiler-evidence-fragment-v1",
        "assurance": "partial-compiler-candidate-assembly-no-admission",
        "complete": False, "admission": False, "publication": False,
        "bindings": {
            "aros_sha256": data["aros_sha256"], "plan_sha256": data["plan_sha256"],
            "inputs_sha256": data["inputs_sha256"],
            "fragment_sha256": data["fragment_sha256"],
            "required_paths_sha256": data["required_paths_sha256"],
            "source_context_sha256": data["fragment"]["source_context_sha256"],
            "producer_commit": data["producer_commit"], "tools_commit": data["tools_commit"],
            "release_id": data["release_id"],
        },
        "assets": evidence_assets,
    }
    evidence_path = root / "compiler-evidence-fragment.json"
    evidence_selector = _write_owned(evidence_path, _ORIGIN.canonical(evidence_doc),
                                     "compiler partial evidence fragment")
    evidence_measurement, _ = _record_file(evidence_path, MAX_FRAGMENT, "owned compiler evidence fragment",
                                         data["selected_files"])
    _require(evidence_measurement == {"sha256": evidence_selector["sha256"], "size": evidence_selector["size"]},
             "compiler evidence fragment changed after its owned write")
    report_selectors = {}
    native_selectors = {}
    for asset, entry in evidence_assets.items():
        comparison_file = entry["comparison"]["selectedFile"]
        report_selector = _file_selector(Path(comparison_file["path"]))
        _require(report_selector["sha256"] == comparison_file["sha256"],
                 "native comparison report changed after its evidence selection")
        report_selectors[asset] = report_selector
        native_selectors[asset] = []
        for build in entry["builds"]:
            native_file = build["native_verification"]
            native_selector = _file_selector(Path(native_file["path"]))
            _require(native_selector["sha256"] == native_file["sha256"],
                     "native verification result changed after its evidence selection")
            native_selectors[asset].append(native_selector)
    summary = {
        "schema": "aros-toolchain-compiler-candidate-assembly-v2",
        "assurance": "compiler-candidate-byte-assembly-partial-no-admission",
        "bindings": {
            "aros_sha256": data["aros_sha256"], "plan_sha256": data["plan_sha256"],
            "inputs_sha256": data["inputs_sha256"],
            "fragment_sha256": data["fragment_sha256"],
            "required_paths_sha256": data["required_paths_sha256"],
            "source_context_sha256": data["fragment"]["source_context_sha256"],
            "producer_commit": data["producer_commit"], "tools_commit": data["tools_commit"],
            "release_id": data["release_id"],
        },
        "staged_inventory": {name: measured for name, measured in sorted(staged.items())},
        "artifacts": {
            "compiler_index_lanes": index_selector,
            "compiler_evidence_fragment": evidence_selector,
            "comparisons": report_selectors,
            "native_verifications": native_selectors,
        },
        "scope": {"compiler_only": True, "sdk_included": False,
                  "admission": False, "publication": False},
    }
    _verify_transports(rows)
    _verify_selected_files(data["selected_files"])
    _verify_directories(data["snapshots"])
    _verify_staged(staged, release_dir)
    _verify_owned_result_files(root, data["selected_files"])
    try:
        final_source_event = _ORIGIN.observe_run_event(data["source_context"])
    except _ORIGIN.OriginError as error:
        raise AssemblyError(str(error)) from error
    _require(final_source_event == data["source_event"],
             "source run event changed during compiler assembly")
    return summary


def _verify_staged(staged: dict, release_dir: Path) -> None:
    expected = {name: "file" for name in staged}
    _require(_STAGE.directory_entries(release_dir, "compiler staged release directory") == expected,
             "staged compiler release directory contains unexpected or missing members")
    for name, expected_measurement in staged.items():
        path = release_dir / name
        measured = _STAGE.measure_file(path, _ORIGIN.MAX_PAYLOAD if name.endswith(".tar.xz")
                                       else MAX_METADATA, "staged compiler member")
        _require(measured == expected_measurement,
                 "staged compiler member changed before assembly completion")


def _verify_owned_result_files(root: Path, selected_files: dict) -> None:
    _require(_STAGE.directory_entries(root, "compiler operation root") == {
        "compiler-evidence-fragment.json": "file", "compiler-index-lanes.json": "file",
        "native": "directory", "release": "directory", "reports": "directory",
    }, "compiler operation root contains unexpected entries")
    expected = {root / "native": {}, root / "reports": {}}
    for path in selected_files:
        if path.parent in expected:
            expected[path.parent][path.name] = "file"
    for directory, entries in expected.items():
        _require(bool(entries) and _STAGE.directory_entries(
            directory, "owned compiler command result directory") == entries,
            "compiler assembly native outputs differ from the selected command results")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--aros", type=Path, required=True)
    parser.add_argument("--aros-sha256", required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--plan-sha256", required=True)
    parser.add_argument("--inputs-dir", type=Path, required=True)
    parser.add_argument("--inputs-sha256", required=True)
    parser.add_argument("--producer-commit", required=True)
    parser.add_argument("--tools-commit", required=True)
    parser.add_argument("--source-context", type=Path, required=True)
    parser.add_argument("--source-context-sha256", required=True)
    parser.add_argument("--fragment", type=Path, required=True)
    parser.add_argument("--fragment-sha256", required=True)
    parser.add_argument("--owner-root", type=Path, required=True)
    parser.add_argument("--required-paths", type=Path, required=True)
    parser.add_argument("--required-paths-sha256", required=True)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--forbidden-prefix", action="append", default=[])
    parser.add_argument("--root", type=Path, required=True)
    return parser


def main() -> int:
    try:
        options = [value.split("=", 1)[0] for value in sys.argv[1:]
                   if value.startswith("--") and value.split("=", 1)[0] != "--forbidden-prefix"]
        _require(len(options) == len(set(options)), "repeated command-line option")
        args = _parser().parse_args()
        summary = assemble(args)
        sys.stdout.write(json.dumps(summary, sort_keys=True, separators=(",", ":")) + "\n")
        return 0
    except (AssemblyError, OSError, RuntimeError, ValueError, KeyError, TypeError,
            IndexError, StopIteration, _STAGE.StageError, _ORIGIN.OriginError) as error:
        sys.stderr.write(f"compiler candidate assembly failed: {error}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
