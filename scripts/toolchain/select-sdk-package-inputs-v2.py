#!/usr/bin/env python3
"""Project byte-consistent native SDK package inputs for index construction.

This helper selects package bytes only. It does not authenticate collection
artifacts, execute or qualify an SDK, validate a native index, or authorize
release or publication. Invoke it only after collect-sdk-owners-v2.sh has
authenticated and reverified the complete owner collection. Native SDK
verify-package and index checks remain the semantic authorities.
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


# Imported helpers are read-only; never create bytecode in the shared workspace.
sys.dont_write_bytecode = True

_HERE = Path(__file__).resolve().parent
MAX_ROWS = 6144
MAX_OWNER_COUNT = 256
MAX_COLLECTION_BYTES = 1024 * 1024
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
OWNER_ID = re.compile(r"[0-9a-f]{64}\Z")
SOURCE_WORKFLOW = re.compile(r"\.github/workflows/[A-Za-z0-9_-]+\.yml\Z")
SOURCE_REF = re.compile(r"refs/(?:heads|tags)/[A-Za-z0-9._/-]+\Z")


def _load_helper(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("required toolchain selection helper is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_MATRIX = _load_helper(
    "sdk_package_inputs_release_matrix", _HERE / "select-release-matrix-v2.py"
)
_STAGE = _load_helper(
    "sdk_package_inputs_stage_payload", _HERE / "stage-sdk-owner-payload-v2.py"
)
_SDK_MATRIX = _load_helper(
    "sdk_package_inputs_sdk_owner_matrix", _HERE / "sdk-owner-matrix-v2.py"
)
_TRANSPORT = _load_helper(
    "sdk_package_inputs_owner_transport", _HERE / "sdk-owner-transport-v2.py"
)


class SelectionError(ValueError):
    """A package input failed the bounded byte-selection contract."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise SelectionError(message)


def _digest(value: object, label: str) -> str:
    _require(isinstance(value, str) and HEX64.fullmatch(value) is not None,
             f"{label} must be a lowercase SHA-256 digest")
    return value


def _read_json(path: Path, limit: int, label: str,
               selected_files: dict[Path, tuple[int, dict]]) -> tuple[dict, bytes, dict]:
    measured, raw = _STAGE.read_bounded(path, limit, label)
    selected_files[path] = (limit, measured)
    value = _STAGE.parse_json(raw, label)
    _require(isinstance(value, dict), f"{label} must be a JSON object")
    return value, raw, measured


def _measure(path: Path, limit: int, label: str,
             selected_files: dict[Path, tuple[int, dict]]) -> dict:
    measured = _STAGE.measure_file(path, limit, label)
    prior = selected_files.get(path)
    _require(prior is None or prior[1] == measured,
             f"{label} changed between selected observations")
    selected_files[path] = (limit, measured)
    return measured


def _directory_snapshot(path: Path, label: str) -> tuple[tuple[int, ...], dict[str, str]]:
    before = _STAGE.directory_fingerprint(path, label)
    entries = _STAGE.directory_entries(path, label)
    after = _STAGE.directory_fingerprint(path, label)
    _require(before == after, f"{label} changed while being enumerated")
    return after, entries


def _remember_directory(path: Path, label: str,
                        snapshots: dict[Path, tuple[tuple[int, ...], dict[str, str]]]) -> dict[str, str]:
    prior = snapshots.get(path)
    if prior is not None:
        return prior[1]
    current = _directory_snapshot(path, label)
    snapshots[path] = current
    return current[1]


def _path_field(value: object, label: str) -> Path:
    _require(isinstance(value, str) and 0 < len(value.encode("utf-8")) <= 4096
             and "\n" not in value and "\r" not in value,
             f"{label} is not a bounded absolute path")
    path = Path(value)
    _require(path.is_absolute() and ".." not in path.parts,
             f"{label} is not an absolute normalized path")
    return path


def _expected_package_tuples(plan: dict[str, Any]) -> list[tuple[str, str, str, str]]:
    result = []
    for sdk in plan["sdks"]:
        for reference in sdk["compiler_profiles"]:
            for host in plan["hosts"]:
                result.append((sdk["id"], reference["group_id"], reference["profile"], host))
    result.sort()
    _require(0 < len(result) <= MAX_ROWS,
             "native release plan has no SDK package tuples or exceeds the tuple bound")
    _require(len(result) == len(set(result)), "native release plan contains duplicate SDK tuples")
    return result


def _validate_collection(collection: dict, plan: dict, *, producer_commit: str,
                         tools_commit: str) -> None:
    _STAGE.exact_keys(collection, {
        "schema", "producer_commit", "tools_commit", "hosts", "groups", "sdks",
    }, "release-input collection")
    _require(collection["schema"] == "aros-toolchain-release-inputs-v2"
             and collection["producer_commit"] == producer_commit
             and collection["tools_commit"] == tools_commit
             and collection["hosts"] == plan["hosts"],
             "release-input collection selectors differ from the native plan")

    groups = collection["groups"]
    _require(type(groups) is list and len(groups) == len(plan["groups"]),
             "release-input group documents differ in count from the native plan")
    for group in groups:
        _STAGE.exact_keys(group, {"id", "recipe", "source_lock", "profiles"},
                          "release-input group")
        for field in ("recipe", "source_lock", "profiles"):
            _STAGE.exact_keys(group[field], {"file", "sha256"},
                              "release-input group document reference")
    expected_groups = [
        {"id": group["group_id"], "recipe": group["recipe"],
         "source_lock": group["source_lock"], "profiles": group["profiles"]}
        for group in plan["groups"]
    ]
    _require(groups == expected_groups,
             "release-input group document references differ from the native plan")

    sdks = collection["sdks"]
    _require(type(sdks) is list and len(sdks) == len(plan["sdks"]),
             "release-input SDK selections differ in count from the native plan")
    for sdk in sdks:
        _STAGE.exact_keys(sdk, {"id", "identity", "source_preset", "compiler_profiles"},
                          "release-input SDK")
        _STAGE.exact_keys(sdk["identity"], {"file", "sha256"},
                          "release-input SDK identity reference")
        profiles = sdk["compiler_profiles"]
        _require(type(profiles) is list,
                 "release-input SDK compiler profiles must be an array")
        for profile in profiles:
            _STAGE.exact_keys(profile, {"group_id", "profile"},
                              "release-input SDK compiler profile")
    _require(sdks == plan["sdks"],
             "release-input SDK identity or compiler references differ from the native plan")


def _validate_fragment(fragment: dict, *, plan_sha256: str,
                       inputs_sha256: str, producer_commit: str, tools_commit: str,
                       expected_tuples: list[tuple[str, str, str, str]],
                       owner_root: Path, selected_files: dict, snapshots: dict
                       ) -> tuple[list[dict], dict[str, dict]]:
    expected_fields = {
        "schema", "assurance", "aros_sha256", "plan_sha256", "inputs_sha256",
        "source_context_sha256", "source_producer_commit", "source_workflow", "source_ref",
        "producer_commit", "tools_commit", "owner_count", "sdk_generation_count",
        "owner_transports", "sdk_generations", "release_admission", "publication",
    }
    _STAGE.exact_keys(fragment, expected_fields, "SDK generation selection fragment")
    _require(fragment["schema"] == "aros-sdk-generation-selection-fragment-v2"
             and fragment["assurance"] == "authenticated-owner-transport-selection-only",
             "SDK generation selection fragment schema or assurance differs")
    _digest(fragment["aros_sha256"], "fragment runtime digest")
    _require(_digest(fragment["plan_sha256"], "fragment plan digest") == plan_sha256
             and _digest(fragment["inputs_sha256"], "fragment inputs digest") == inputs_sha256,
             "SDK generation selection fragment plan or inputs binding differs")
    _digest(fragment["source_context_sha256"], "fragment source-context digest")
    _require(fragment["source_producer_commit"] == producer_commit
             and fragment["producer_commit"] == producer_commit
             and fragment["tools_commit"] == tools_commit,
             "SDK generation selection fragment commits differ from selected commits")
    _require(isinstance(fragment["source_workflow"], str)
             and SOURCE_WORKFLOW.fullmatch(fragment["source_workflow"]) is not None
             and isinstance(fragment["source_ref"], str)
             and SOURCE_REF.fullmatch(fragment["source_ref"]) is not None,
             "SDK generation selection fragment source selectors are invalid")
    _require(type(fragment["release_admission"]) is bool and fragment["release_admission"] is False
             and type(fragment["publication"]) is bool and fragment["publication"] is False,
             "SDK generation selection fragment carries unsupported authority fields")
    _require(type(fragment["owner_count"]) is int
             and 1 <= fragment["owner_count"] <= MAX_OWNER_COUNT,
             "SDK generation selection fragment owner count is invalid")
    rows = fragment["sdk_generations"]
    _require(type(rows) is list and type(fragment["sdk_generation_count"]) is int
             and fragment["sdk_generation_count"] == len(rows)
             and 1 <= len(rows) <= MAX_ROWS,
             "SDK generation selection fragment count differs from its rows")

    owners_by_id: dict[str, set[str]] = {}
    owner_tuple: dict[str, tuple[str, str, str]] = {}
    tuple_owner: dict[tuple[str, str, str], str] = {}
    actual_tuples = []
    for row in rows:
        _STAGE.exact_keys(row, {
            "sdk_id", "group_id", "target_profile", "host", "package_dir", "record",
            "compatibility",
        }, "SDK generation row")
        sdk_id, group, profile, host = (row[name] for name in
                                       ("sdk_id", "group_id", "target_profile", "host"))
        _STAGE.validate_selection(sdk_id, group, profile, host)
        tuple_key = (sdk_id, group, profile, host)
        actual_tuples.append(tuple_key)

        package_dir = _path_field(row["package_dir"], "SDK package directory")
        _require(_STAGE.path_is_canonical(package_dir, must_exist=True),
                 "SDK package directory is linked or noncanonical")
        try:
            relative = package_dir.relative_to(owner_root)
        except ValueError:
            raise SelectionError("SDK package directory is outside the canonical owner root") from None
        parts = relative.parts
        _require(len(parts) == 6 and parts[0] == "owners" and parts[2:] ==
                 ("readback", "payload", f"sdk-{sdk_id}", "package")
                 and OWNER_ID.fullmatch(parts[1]) is not None,
                 "SDK package directory does not follow the authenticated owner-root layout")
        owner_id = parts[1]
        owner_path = owner_root / "owners" / owner_id
        readback_root = owner_path / "readback"
        payload_root = readback_root / "payload"
        product_root = payload_root / f"sdk-{sdk_id}"
        _require(package_dir == product_root / "package",
                 "SDK package directory differs from its derived owner path")

        record = _STAGE.exact_keys(row["record"], {"path", "sha256"}, "SDK generation marker")
        record_path = _path_field(record["path"], "SDK generation record path")
        _require(record_path == product_root / "generation.json",
                 "SDK generation record path differs from its derived owner path")
        _digest(record["sha256"], "SDK generation record marker digest")

        compatibility = _STAGE.exact_keys(row["compatibility"], {
            "directory", "inputs", "manifest_sha256", "native_sdk_required",
        }, "SDK compatibility marker")
        compatibility_dir = _path_field(compatibility["directory"],
                                        "SDK compatibility directory")
        _require(compatibility_dir == product_root / "compatibility",
                 "SDK compatibility directory differs from its derived owner path")
        inputs_marker = _STAGE.exact_keys(compatibility["inputs"], {"path", "sha256"},
                                          "SDK compatibility inputs marker")
        inputs_path = _path_field(inputs_marker["path"], "SDK compatibility inputs path")
        _require(inputs_path == product_root / "compatibility-inputs.json",
                 "SDK compatibility inputs path differs from its derived owner path")
        _digest(inputs_marker["sha256"], "SDK compatibility inputs marker digest")
        _digest(compatibility["manifest_sha256"], "SDK compatibility manifest marker digest")
        _require(type(compatibility["native_sdk_required"]) is bool,
                 "SDK compatibility native-SDK marker is invalid")

        owner_selection = (group, profile, host)
        _require(owner_id not in owner_tuple or owner_tuple[owner_id] == owner_selection,
                 "one retained owner path refers to different native tuples")
        _require(owner_selection not in tuple_owner or tuple_owner[owner_selection] == owner_id,
                 "one native owner tuple refers to multiple retained owner paths")
        owner_tuple[owner_id] = owner_selection
        tuple_owner[owner_selection] = owner_id
        owners_by_id.setdefault(owner_id, set()).add(sdk_id)

        # Check every path ancestor without following symlinks and snapshot each
        # directory whose contents or identity are used by the selection.
        _remember_directory(owner_root, "owner collection root", snapshots)
        _remember_directory(owner_root / "owners", "owner collection owners directory", snapshots)
        _remember_directory(owner_path, "SDK owner directory", snapshots)
        readback_entries = _remember_directory(
            readback_root, "SDK owner readback directory", snapshots
        )
        _require(readback_entries == {
            "payload": "directory", "readback.json": "file", "transport": "directory",
            "transport-result.json": "file", "transport-reverification.json": "file",
            "transport-readback.json": "file", "origin-verification.log": "file",
        }, "retained SDK owner readback inventory differs")
        _remember_directory(payload_root, "SDK owner payload directory", snapshots)
        product_entries = _remember_directory(product_root, "SDK product directory", snapshots)
        _require(product_entries == {
            "generation.json": "file", "package": "directory",
            "compatibility-inputs.json": "file", "compatibility": "directory",
            "sdk-lane.json": "file",
        }, "SDK owner product directory inventory differs")

    _require(actual_tuples == expected_tuples,
             "SDK generation rows are missing, duplicated, extra, or out of canonical order")
    _require(len(owners_by_id) == fragment["owner_count"],
             "SDK generation owner count differs from its retained owner paths")
    owner_entries = _remember_directory(owner_root / "owners", "owner collection owners directory",
                                        snapshots)
    _require(owner_entries == {owner_id: "directory" for owner_id in owners_by_id},
             "retained owner directory inventory differs from SDK generation rows")
    plan_owners = {}
    for owner_id, sdk_ids in owners_by_id.items():
        group, profile, host = owner_tuple[owner_id]
        expected_owner_id = _SDK_MATRIX._owner_id(sorted(sdk_ids), group, host, profile)
        _require(owner_id == expected_owner_id,
                 "retained owner path differs from the deterministic native owner tuple")
        owner_path = owner_root / "owners" / owner_id
        entries = _remember_directory(owner_path, "SDK owner directory", snapshots)
        _require(entries == {"readback": "directory", "selection.json": "file"},
                 "retained SDK owner directory inventory differs")
        plan_owners[owner_id] = {
            "sdk_ids": sorted(sdk_ids), "group": group, "profile": profile, "host": host,
            "transport_path": owner_path / "readback" / "transport-result.json",
            "retained_path": owner_path / "readback" / "transport",
            "payload_path": owner_path / "readback" / "payload",
        }
        payload_root = owner_path / "readback" / "payload"
        entries = _remember_directory(payload_root, "SDK owner payload directory", snapshots)
        _require(entries == {f"sdk-{sdk_id}": "directory" for sdk_id in sdk_ids},
                 "retained SDK payload inventory differs from its selected tuples")

    transports = fragment["owner_transports"]
    _require(type(transports) is dict and set(transports) == set(plan_owners),
             "SDK owner transport bindings differ from the exact native owner set")
    for owner_id, owner in plan_owners.items():
        binding = _STAGE.exact_keys(transports[owner_id], {"path", "sha256"},
                                    "SDK owner transport binding")
        transport_path = _path_field(binding["path"], "SDK owner transport result path")
        _require(transport_path == owner["transport_path"]
                 and _STAGE.path_is_canonical(transport_path, must_exist=True),
                 "SDK owner transport result path differs from its derived owner path")
        expected_sha = _digest(binding["sha256"], "SDK owner transport result digest")
        result, _raw, measured = _read_json(
            transport_path, _STAGE.MAX_METADATA, "SDK owner transport result", selected_files
        )
        _require(measured["sha256"] == expected_sha,
                 "SDK owner transport result differs from its collector-bound digest")
        owner["transport_result"] = result
        owner["transport_sha256"] = expected_sha
    return rows, plan_owners


def _verify_owner_transports(owners: dict[str, dict], families: dict[str, str], *,
                             selected_files: dict) -> None:
    for owner_id in sorted(owners):
        owner = owners[owner_id]
        result = _TRANSPORT.verify_output(
            owner["retained_path"], owner["payload_path"],
            sdk_ids=owner["sdk_ids"], group=owner["group"],
            profile=owner["profile"], host=owner["host"],
            compiler_family=families[owner["group"]], owner_role="sdk",
        )
        _require(result == owner["transport_result"],
                 "retained SDK transport verification differs from the collector-bound result")
        measured, raw = _STAGE.read_bounded(
            owner["transport_path"], _STAGE.MAX_METADATA, "SDK owner transport result"
        )
        _require(measured["sha256"] == owner["transport_sha256"]
                 and measured == selected_files[owner["transport_path"]][1],
                 "SDK owner transport result changed after its collector-bound read")
        parsed = _STAGE.parse_json(raw, "SDK owner transport result")
        _require(parsed == owner["transport_result"] and parsed == result,
                 "SDK owner transport result bytes differ from independent transport verification")


def _join_owner_rows(rows: list[dict], owners: dict[str, dict]) -> None:
    row_fields = ("sdk_id", "group_id", "target_profile", "host", "package_dir",
                  "record", "compatibility")
    by_owner: dict[str, list[dict]] = {owner_id: [] for owner_id in owners}
    for row in rows:
        package_dir = Path(row["package_dir"])
        owner_id = package_dir.parts[-5]
        _require(owner_id in by_owner,
                 "SDK generation row has no matching native owner transport")
        by_owner[owner_id].append({field: row[field] for field in row_fields})
    for owner_id, owner_rows in by_owner.items():
        expected = sorted(owner_rows, key=lambda row: row["sdk_id"])
        _require(owners[owner_id]["transport_result"].get("sdk_generations") == expected,
                 "collector transport markers differ from their SDK generation fragment rows")


def _validate_lane_and_package(row: dict, selected_identity: dict,
                               *, selected_files: dict,
                               snapshots: dict) -> dict:
    sdk_id = row["sdk_id"]
    package_dir = Path(row["package_dir"])
    product_root = package_dir.parent
    package_entries = _remember_directory(package_dir, "SDK package directory", snapshots)
    _require(0 < len(package_entries) <= 3
             and all(kind == "file" for kind in package_entries.values()),
             "SDK package directory must contain exactly three regular package files")
    archives = [name for name in package_entries if name.endswith(".tar.xz")]
    _require(len(archives) == 1, "SDK package directory must contain one archive")
    archive_name = archives[0]
    _STAGE.require_portable_inventory({f"package/{name}": {} for name in package_entries})

    lane_path = product_root / "sdk-lane.json"
    lane, lane_raw, _ = _read_json(lane_path, _STAGE.MAX_METADATA,
                                   "SDK lane manifest", selected_files)
    _STAGE.exact_keys(lane, {
        "schema", "assurance", "sdk_id", "group_id", "target_profile", "host", "files",
    }, "SDK lane manifest")
    _require(lane["schema"] == _STAGE.SCHEMA and lane["assurance"] == _STAGE.ASSURANCE,
             "SDK lane manifest schema or assurance differs")
    tuple_fields = {key: row[key] for key in ("sdk_id", "group_id", "target_profile", "host")}
    _require({key: lane[key] for key in tuple_fields} == tuple_fields,
             "SDK lane tuple differs from its authenticated fragment row")
    _require(_STAGE.canonical_json(lane) == lane_raw,
             "SDK lane manifest is not canonical JSON")

    files = lane["files"]
    _STAGE.require_portable_inventory(files)
    _require(0 < len(files) <= _STAGE.MAX_FILES,
             "SDK lane file inventory is empty or oversized")
    for name, measurement in files.items():
        measurement = _STAGE.exact_keys(measurement, {"sha256", "size"},
                                        "SDK lane file measurement")
        _digest(measurement["sha256"], "SDK lane file digest")
        _require(type(measurement["size"]) is int
                 and 0 <= measurement["size"] <= _STAGE.MAX_PAYLOAD,
                 "SDK lane file size is invalid")
    compatibility_entries = _remember_directory(product_root / "compatibility",
                                                  "SDK compatibility directory", snapshots)
    _require("compatibility-measurement.json" in compatibility_entries,
             "SDK compatibility directory is missing its measurement manifest")
    expected_names = {
        "generation.json", "compatibility-inputs.json",
        *(f"package/{name}" for name in package_entries),
        *(f"compatibility/{name}" for name in compatibility_entries),
    }
    _require(files.keys() == expected_names,
             "SDK lane file inventory differs from its package and compatibility directories")

    generation_path = product_root / "generation.json"
    generation_measurement, generation_raw = _STAGE.read_bounded(
        generation_path, _STAGE.MAX_METADATA, "SDK generation record"
    )
    selected_files[generation_path] = (_STAGE.MAX_METADATA, generation_measurement)
    _require(generation_measurement == files["generation.json"]
             and generation_measurement["sha256"] == row["record"]["sha256"],
             "SDK generation marker differs from lane bytes")
    generation, _family = _STAGE._generation(generation_raw, sdk_id)
    _require(generation["identity"] == selected_identity,
             "SDK generation identity differs from the independently selected plan identity")

    manifest_names = [name for name in package_entries if name.endswith(".manifest.json")]
    checksum_names = [name for name in package_entries if name.endswith(".sha256")]
    _require(manifest_names == [f"{archive_name}.manifest.json"]
             and checksum_names == [f"{archive_name}.sha256"],
             "SDK package directory does not contain the exact archive sidecars")
    manifest_path = package_dir / manifest_names[0]
    _manifest, manifest_raw, manifest_measurement = _read_json(
        manifest_path, _STAGE.MAX_METADATA, "SDK package manifest", selected_files)
    parsed_manifest, expected_archive_name = _STAGE._package_manifest(manifest_raw, sdk_id)
    _require(expected_archive_name == archive_name,
             "SDK archive basename differs from its package identity")
    _require(parsed_manifest["identity"] == selected_identity
             and parsed_manifest["identity"] == generation["identity"],
             "SDK package manifest identity differs from the selected native plan identity")
    _require(manifest_measurement == files[f"package/{manifest_names[0]}"],
             "SDK package manifest bytes differ from the SDK lane file map")
    archive_path = package_dir / archive_name
    archive_measurement = _measure(archive_path, _STAGE.MAX_PAYLOAD,
                                   "SDK package archive", selected_files)
    _require(archive_measurement == files[f"package/{archive_name}"],
             "SDK archive bytes differ from the SDK lane file map")
    checksum_path = package_dir / f"{archive_name}.sha256"
    checksum_measurement, checksum_raw = _STAGE.read_bounded(
        checksum_path, _STAGE.MAX_METADATA, "SDK archive checksum")
    selected_files[checksum_path] = (_STAGE.MAX_METADATA, checksum_measurement)
    _require(checksum_measurement == files[f"package/{archive_name}.sha256"]
             and checksum_raw ==
             f"{archive_measurement['sha256']}  {archive_name}\n".encode("ascii"),
             "SDK archive checksum sidecar differs from the streamed archive digest")

    compatibility = row["compatibility"]
    measurement_path = product_root / "compatibility" / "compatibility-measurement.json"
    compatibility_measurement = _measure(
        measurement_path, _STAGE.MAX_METADATA, "SDK compatibility measurement", selected_files
    )
    _require(compatibility_measurement["sha256"] == compatibility["manifest_sha256"]
             and compatibility_measurement == files[
                 "compatibility/compatibility-measurement.json"],
             "SDK compatibility marker differs from its lane file map")
    inputs_path = product_root / "compatibility-inputs.json"
    inputs_measurement = _measure(inputs_path, _STAGE.MAX_METADATA,
                                  "SDK compatibility inputs", selected_files)
    _require(inputs_measurement["sha256"] == compatibility["inputs"]["sha256"]
             and inputs_measurement == files["compatibility-inputs.json"],
             "SDK compatibility inputs marker differs from its lane file map")

    return {
        "sdk_id": sdk_id,
        "group_id": row["group_id"],
        "target_profile": row["target_profile"],
        "host": row["host"],
        "manifest_raw": manifest_raw,
        "tree_sha256": parsed_manifest["tree_sha256"],
        "archive_sha256": archive_measurement["sha256"],
        "archive_size": archive_measurement["size"],
        "checksum_raw": checksum_raw,
        "package_dir": package_dir,
        "archive_name": archive_name,
        "archive_path": archive_path,
        "manifest_path": manifest_path,
        "checksum_path": checksum_path,
    }


def select(*, plan_path: Path, plan_sha256: str, inputs_dir: Path,
           inputs_sha256: str, producer_commit: str, tools_commit: str,
           fragment_path: Path, fragment_sha256: str, owner_root: Path) -> dict:
    plan_sha256 = _digest(plan_sha256, "selected plan digest")
    inputs_sha256 = _digest(inputs_sha256, "selected inputs digest")
    fragment_sha256 = _digest(fragment_sha256, "selected fragment digest")
    producer_commit = _MATRIX._require_commit(producer_commit, "selected producer commit")
    tools_commit = _MATRIX._require_commit(tools_commit, "selected tools commit")
    for path, label in ((plan_path, "native plan"), (inputs_dir, "inputs directory"),
                        (fragment_path, "SDK selection fragment"),
                        (owner_root, "SDK owner root")):
        _require(path.is_absolute() and ".." not in path.parts,
                 f"{label} path must be absolute and normalized")
    _require(_STAGE.path_is_canonical(inputs_dir, must_exist=True)
             and inputs_dir.is_dir(), "inputs directory is linked or noncanonical")
    _require(_STAGE.path_is_canonical(owner_root, must_exist=True)
             and owner_root.is_dir(), "SDK owner root is linked or noncanonical")
    _require(fragment_path == owner_root / "selection-fragment.json",
             "SDK selection fragment must be the collector fragment under the supplied owner root")

    selected_files: dict[Path, tuple[int, dict]] = {}
    snapshots: dict[Path, tuple[tuple[int, ...], dict[str, str]]] = {}
    _remember_directory(inputs_dir, "digest-bound inputs directory", snapshots)
    _remember_directory(owner_root, "owner collection root", snapshots)

    collection_path = inputs_dir / "toolchain-release-inputs-v2.json"
    collection_measurement, collection_raw = _STAGE.read_bounded(
        collection_path, MAX_COLLECTION_BYTES, "release-input collection"
    )
    selected_files[collection_path] = (MAX_COLLECTION_BYTES, collection_measurement)
    _require(collection_measurement["sha256"] == inputs_sha256,
             "release-input collection bytes differ from the selected digest")
    collection = _STAGE.parse_json(collection_raw, "release-input collection")
    _require(isinstance(collection, dict), "release-input collection must be a JSON object")

    plan_measurement, raw_plan = _STAGE.read_bounded(
        plan_path, _MATRIX.MAX_PLAN_BYTES, "native release plan"
    )
    selected_files[plan_path] = (_MATRIX.MAX_PLAN_BYTES, plan_measurement)
    actual_plan_sha256 = plan_measurement["sha256"]
    _require(actual_plan_sha256 == plan_sha256,
             "native release plan bytes differ from the selected digest")
    try:
        plan = json.loads(
            raw_plan.decode("utf-8"),
            object_pairs_hook=_MATRIX._reject_duplicate_keys,
            parse_constant=_MATRIX._reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise SelectionError("native release plan is not valid duplicate-free UTF-8 JSON") from error
    _require(isinstance(plan, dict), "native release plan must be a JSON object")
    _MATRIX._validate_plan(
        plan,
        expected_inputs_sha256=inputs_sha256,
        expected_producer_commit=producer_commit,
        expected_tools_commit=tools_commit,
    )
    _validate_collection(collection, plan, producer_commit=producer_commit,
                         tools_commit=tools_commit)
    expected_tuples = _expected_package_tuples(plan)

    # Use the existing owner-matrix source-lock reader: package bytes are
    # interpreted only under the compiler family bound by the native plan.
    families, source_lock_snapshots = _SDK_MATRIX._source_locks(plan, inputs_dir)
    for path, measured, _raw in source_lock_snapshots.values():
        prior = selected_files.get(path)
        _require(prior is None or prior[1] == measured,
                 "source-lock bytes changed between selected observations")
        selected_files[path] = (_STAGE.MAX_METADATA, measured)

    selected_identities = {}
    for sdk in plan["sdks"]:
        sdk_id = sdk["id"]
        reference = sdk["identity"]
        identity_path = inputs_dir / reference["file"]
        identity, _identity_raw, identity_measurement = _read_json(
            identity_path, _STAGE.MAX_METADATA, f"selected identity for {sdk_id}", selected_files
        )
        _require(identity_measurement["sha256"] == reference["sha256"],
                 f"selected identity bytes differ from the native plan reference for {sdk_id}")
        selected_identity = _STAGE._validate_identity(identity, f"selected native plan {sdk_id}")
        _require(selected_identity["sdk_id"] == sdk_id,
                 f"selected identity SDK ID differs from the native plan for {sdk_id}")
        selected_identities[sdk_id] = selected_identity

    fragment, _fragment_raw, fragment_measurement = _read_json(
        fragment_path, _STAGE.MAX_METADATA, "SDK generation selection fragment", selected_files
    )
    _require(fragment_measurement["sha256"] == fragment_sha256,
             "SDK selection fragment bytes differ from the selected digest")
    rows, owners = _validate_fragment(
        fragment,
        plan_sha256=actual_plan_sha256,
        inputs_sha256=inputs_sha256,
        producer_commit=producer_commit,
        tools_commit=tools_commit,
        expected_tuples=expected_tuples,
        owner_root=owner_root,
        selected_files=selected_files,
        snapshots=snapshots,
    )
    _verify_owner_transports(owners, families, selected_files=selected_files)
    _join_owner_rows(rows, owners)

    byte_results = []
    for row in rows:
        byte_results.append(_validate_lane_and_package(
            row,
            selected_identities[row["sdk_id"]],
            selected_files=selected_files,
            snapshots=snapshots,
        ))

    # Compare every observed tuple before choosing a representative path.
    by_sdk: dict[str, list[dict]] = {}
    for result in byte_results:
        by_sdk.setdefault(result["sdk_id"], []).append(result)
    sdk_packages = {}
    package_locations = []
    for sdk_id in sorted(by_sdk):
        candidates = sorted(by_sdk[sdk_id], key=lambda item: (
            item["sdk_id"], item["group_id"], item["target_profile"], item["host"]
        ))
        representative = candidates[0]
        expected_bytes = (
            representative["manifest_raw"], representative["tree_sha256"],
            representative["archive_sha256"], representative["archive_size"],
            representative["checksum_raw"],
        )
        _require(all((candidate["manifest_raw"], candidate["tree_sha256"],
                      candidate["archive_sha256"], candidate["archive_size"],
                      candidate["checksum_raw"]) == expected_bytes
                     for candidate in candidates[1:]),
                 f"native SDK package bytes differ across selected hosts for {sdk_id}")
        sdk_packages[sdk_id] = {
            "tree_sha256": representative["tree_sha256"],
            "archive_sha256": representative["archive_sha256"],
            "archive_size": representative["archive_size"],
        }
        package_locations.append({
            "sdk_id": sdk_id,
            "group_id": representative["group_id"],
            "target_profile": representative["target_profile"],
            "host": representative["host"],
            "package_dir": str(representative["package_dir"]),
            "archive": representative["archive_name"],
            "archive_path": str(representative["archive_path"]),
            "manifest_path": str(representative["manifest_path"]),
            "checksum_path": str(representative["checksum_path"]),
        })

    _require(set(sdk_packages) == {sdk["id"] for sdk in plan["sdks"]},
             "selected package map differs from the native plan SDK set")
    # The collector-bound transport and extracted payload are reverified after
    # all package projections and again immediately before the output barrier.
    _verify_owner_transports(owners, families, selected_files=selected_files)
    # Re-measure every selected byte input and every relevant directory before
    # emitting even one byte on stdout.
    for path, (limit, expected_measurement) in selected_files.items():
        measured = _STAGE.measure_file(path, limit, f"selected input {path.name}")
        _require(measured == expected_measurement,
                 f"selected input changed before package selection output: {path.name}")
    for path, expected_snapshot in snapshots.items():
        current_snapshot = _directory_snapshot(path, f"selected directory {path.name or path}")
        _require(current_snapshot == expected_snapshot,
                 f"selected directory changed before package selection output: {path.name or path}")

    return {
        "schema": "aros-sdk-package-inputs-v2",
        "assurance": "package-byte-selection-only",
        "inputs_sha256": inputs_sha256,
        "plan_sha256": actual_plan_sha256,
        "fragment_sha256": fragment_sha256,
        "producer_commit": producer_commit,
        "tools_commit": tools_commit,
        "sdk_package_count": len(sdk_packages),
        "sdk_packages": sdk_packages,
        "package_locations": package_locations,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--plan-sha256", required=True)
    parser.add_argument("--inputs-dir", required=True, type=Path)
    parser.add_argument("--inputs-sha256", required=True)
    parser.add_argument("--producer-commit", required=True)
    parser.add_argument("--tools-commit", required=True)
    parser.add_argument("--fragment", required=True, type=Path)
    parser.add_argument("--fragment-sha256", required=True)
    parser.add_argument("--owner-root", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    option_names = [item.split("=", 1)[0] for item in arguments if item.startswith("--")]
    if len(option_names) != len(set(option_names)):
        print("SDK package selection failed: repeated command-line option", file=sys.stderr)
        return 2
    try:
        args = _parser().parse_args(arguments)
        result = select(
            plan_path=args.plan,
            plan_sha256=args.plan_sha256,
            inputs_dir=args.inputs_dir,
            inputs_sha256=args.inputs_sha256,
            producer_commit=args.producer_commit,
            tools_commit=args.tools_commit,
            fragment_path=args.fragment,
            fragment_sha256=args.fragment_sha256,
            owner_root=args.owner_root,
        )
        sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=True, allow_nan=False) + "\n")
        return 0
    except (_STAGE.StageError, _MATRIX.PlanError, SelectionError, OSError,
            UnicodeError, RecursionError, ValueError) as error:
        print(f"SDK package selection failed: {error}", file=sys.stderr)
        return 2
    except Exception:
        print("SDK package selection failed: closed byte boundary", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
