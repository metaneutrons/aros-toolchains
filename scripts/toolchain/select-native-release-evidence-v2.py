#!/usr/bin/env python3
"""Select a closed native release-evidence DTO from measured partial evidence.

This helper selects bytes and joins already produced compiler and SDK evidence.
It does not execute a producer, authenticate a signature, verify a native index,
qualify a release, sign, publish, or grant release authority. The caller remains
responsible for native index verification and subsequent release operations.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
MAX_METADATA = 16 * 1024 * 1024
MAX_FRAGMENT = 16 * 1024 * 1024
MAX_NATIVE_RESULT = 4 * 1024 * 1024
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
SELECTION_SCHEMA = "aros-toolchain-release-evidence-selection-v2"


def _load_helper(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("required release-evidence selector helper is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_SDK = _load_helper("native_release_evidence_sdk_selector",
                    HERE / "select-sdk-package-inputs-v2.py")
_MATRIX = _SDK._MATRIX
_STAGE = _SDK._STAGE
_ORIGIN = _STAGE._ORIGIN


class SelectionError(ValueError):
    """The requested native evidence selection is not byte-closed."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise SelectionError(message)


def _digest(value: object, label: str) -> str:
    _require(isinstance(value, str) and HEX64.fullmatch(value) is not None,
             f"{label} must be a lowercase SHA-256 digest")
    return value


def _stat_fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_nlink,
            metadata.st_uid, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns)


def _canonical(path: Path, label: str, *, directory: bool) -> Path:
    _require(isinstance(path, Path) and path.is_absolute() and ".." not in path.parts,
             f"{label} path must be absolute and normalized")
    _require(_STAGE.path_is_canonical(path, must_exist=True),
             f"{label} path is linked or noncanonical")
    try:
        metadata = path.lstat()
    except OSError as error:
        raise SelectionError(f"{label} is unavailable") from error
    if directory:
        _require(stat.S_ISDIR(metadata.st_mode), f"{label} is not an ordinary directory")
    else:
        _require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
                 and metadata.st_uid == os.geteuid(),
                 f"{label} is not an owned, singly linked regular file")
    return path


def _remember_directory(path: Path, label: str,
                        snapshots: dict[Path, tuple[tuple[int, ...], dict[str, str]]]
                        ) -> dict[str, str]:
    path = _canonical(path, label, directory=True)
    prior = snapshots.get(path)
    if prior is not None:
        return prior[1]
    before = _STAGE.directory_fingerprint(path, label)
    entries = _STAGE.directory_entries(path, label)
    after = _STAGE.directory_fingerprint(path, label)
    _require(before == after, f"{label} changed while it was enumerated")
    snapshots[path] = (after, entries)
    return entries


def _remember_file(path: Path, limit: int, label: str,
                   selected: dict[Path, tuple[int, dict, tuple[int, ...], bytes | None]],
                   *, read: bool = False) -> tuple[dict, bytes | None]:
    _canonical(path, label, directory=False)
    if read:
        measured, raw = _STAGE.read_bounded(path, limit, label)
    else:
        measured, raw = _STAGE.measure_file(path, limit, label), None
    fingerprint = _stat_fingerprint(path.lstat())
    value = (limit, measured, fingerprint, raw)
    prior = selected.get(path)
    if prior is not None:
        _require(prior[:3] == value[:3], f"{label} changed between selected observations")
        _require(prior[3] is None or raw is None or prior[3] == raw,
                 f"{label} bytes changed between selected observations")
        if prior[3] is not None:
            raw = prior[3]
        value = (limit, measured, fingerprint, raw)
    selected[path] = value
    return measured, raw


def _read_json(path: Path, limit: int, label: str,
               selected: dict[Path, tuple[int, dict, tuple[int, ...], bytes | None]]) -> tuple[dict, bytes, dict]:
    measured, raw = _remember_file(path, limit, label, selected, read=True)
    value = _STAGE.parse_json(raw, label)
    _require(isinstance(value, dict), f"{label} must be a JSON object")
    return value, raw, measured


def _reference(value: object, label: str) -> tuple[Path, str]:
    reference = _STAGE.exact_keys(value, {"path", "sha256"}, label)
    raw_path = reference["path"]
    _require(isinstance(raw_path, str) and 0 < len(raw_path.encode("utf-8")) <= 4096
             and "\n" not in raw_path and "\r" not in raw_path,
             f"{label} path is not bounded")
    path = Path(raw_path)
    _require(path.is_absolute() and ".." not in path.parts,
             f"{label} path must be absolute and normalized")
    return path, _digest(reference["sha256"], f"{label} digest")


def _measure_reference(value: object, label: str, limit: int,
                       selected: dict[Path, tuple[int, dict, tuple[int, ...], bytes | None]],
                       *, parse: bool = False) -> tuple[Path, dict, dict | None]:
    path, expected_sha = _reference(value, label)
    if parse:
        parsed, _raw, measured = _read_json(path, limit, label, selected)
    else:
        measured, _raw = _remember_file(path, limit, label, selected)
        parsed = None
    _require(measured["sha256"] == expected_sha,
             f"{label} bytes differ from their selected digest")
    return path, measured, parsed


def _check_bound_inputs(args: argparse.Namespace,
                        selected: dict[Path, tuple[int, dict, tuple[int, ...], bytes | None]],
                        snapshots: dict[Path, tuple[tuple[int, ...], dict[str, str]]]
                        ) -> tuple[dict, bytes, dict, dict[str, str]]:
    plan_path = _canonical(args.plan, "native release plan", directory=False)
    inputs_dir = _canonical(args.inputs_dir, "release-input directory", directory=True)
    _remember_directory(inputs_dir, "digest-bound release-input directory", snapshots)

    plan, plan_raw, plan_measurement = _read_json(
        plan_path, _MATRIX.MAX_PLAN_BYTES, "native release plan", selected
    )
    plan_sha = _digest(args.plan_sha256, "selected plan digest")
    inputs_sha = _digest(args.inputs_sha256, "selected release-input digest")
    producer = _MATRIX._require_commit(args.producer_commit, "selected producer commit")
    tools = _MATRIX._require_commit(args.tools_commit, "selected tools commit")
    _require(plan_measurement["sha256"] == plan_sha,
             "native release plan bytes differ from the selected digest")
    _MATRIX._validate_plan(plan, expected_inputs_sha256=inputs_sha,
                           expected_producer_commit=producer,
                           expected_tools_commit=tools)
    projection = _MATRIX.project(
        raw=plan_raw, plan=plan, plan_sha256=plan_sha, inputs_sha256=inputs_sha,
        producer_commit=producer, tools_commit=tools, event="workflow_dispatch",
        scope="full", full_qualification=True,
    )
    _require(projection["complete_selection"] is True,
             "native release plan is not a complete full-qualification plan")

    collection_path = inputs_dir / "toolchain-release-inputs-v2.json"
    collection, _collection_raw, collection_measurement = _read_json(
        collection_path, _SDK.MAX_COLLECTION_BYTES, "release-input collection", selected
    )
    _require(collection_measurement["sha256"] == inputs_sha,
             "release-input collection bytes differ from the selected digest")
    _SDK._validate_collection(collection, plan, producer_commit=producer,
                              tools_commit=tools)

    for group in plan["groups"]:
        for field in ("recipe", "source_lock", "profiles"):
            reference = group[field]
            path = inputs_dir / reference["file"]
            document, _raw, measured = _read_json(
                path, MAX_METADATA, f"{field} for {group['group_id']}", selected
            )
            _require(measured["sha256"] == reference["sha256"],
                     f"{field} bytes differ from the native plan for {group['group_id']}")
            _require(isinstance(document, dict),
                     f"{field} for {group['group_id']} must be a JSON object")

    for sdk in plan["sdks"]:
        reference = sdk["identity"]
        identity_path = inputs_dir / reference["file"]
        identity, _raw, measured = _read_json(
            identity_path, MAX_METADATA, f"identity for {sdk['id']}", selected
        )
        _require(measured["sha256"] == reference["sha256"],
                 f"identity bytes differ from the native plan for {sdk['id']}")
        validated_identity = _STAGE._validate_identity(identity, f"native plan {sdk['id']}")
        _require(validated_identity["sdk_id"] == sdk["id"],
                 f"identity SDK ID differs from the native plan for {sdk['id']}")

    # Retain the existing source-lock family selector; family is source policy,
    # never inferred from an SDK receipt or generation row.
    families, lock_snapshots = _SDK._SDK_MATRIX._source_locks(plan, inputs_dir)
    for group_id, (path, measured, raw) in lock_snapshots.items():
        prior = selected.get(path)
        _require(prior is not None and prior[1] == measured and prior[3] == raw,
                 f"source-lock selector differs from the plan-bound bytes for {group_id}")

    return plan, plan_raw, projection, families


def _validate_index(index: dict, *, inputs_sha: str, producer: str, tools: str,
                    release_id: str, expected_lanes: set[tuple[str, str, str]]) -> dict[tuple[str, str, str], dict]:
    required_fields = {"schema", "release_id", "base_url", "inputs_sha256",
                       "producer_commit", "tools_commit", "artifacts"}
    _require(set(index) in (required_fields, required_fields | {"sdks"}),
             "native pre-index document has an unsupported top-level shape")
    _require(type(index["schema"]) is int and index["schema"] == 2
             and index["release_id"] == release_id
             and index["inputs_sha256"] == inputs_sha
             and index["producer_commit"] == producer
             and index["tools_commit"] == tools,
             "native pre-index headers differ from the selected compiler evidence")
    artifacts = index["artifacts"]
    _require(type(artifacts) is list and len(artifacts) == len(expected_lanes),
             "native pre-index artifacts do not cover the complete plan")
    fields = {"group_id", "asset", "sha256", "size", "host", "target_profile",
              "target_triple", "source_commit", "compiler", "tree_sha256", "enabled",
              "strip_components", "required_paths"}
    by_lane: dict[tuple[str, str, str], dict] = {}
    by_asset: set[str] = set()
    for item in artifacts:
        artifact = _STAGE.exact_keys(item, fields, "native pre-index artifact")
        _require(all(isinstance(artifact[field], str) for field in
                     ("group_id", "host", "target_profile", "target_triple", "source_commit"))
                 and isinstance(artifact["compiler"], dict),
                 "native pre-index artifact tuple or compiler identity is invalid")
        lane = (artifact["group_id"], artifact["host"], artifact["target_profile"])
        _require(lane in expected_lanes and lane not in by_lane,
                 "native pre-index contains an unexpected or duplicate compiler tuple")
        asset = artifact["asset"]
        _require(isinstance(asset, str) and _STAGE.portable_component(asset)
                 and asset.endswith(".tar.xz") and asset not in by_asset,
                 "native pre-index artifact name is unsafe or duplicated")
        _digest(artifact["sha256"], "native pre-index archive digest")
        _digest(artifact["tree_sha256"], "native pre-index tree digest")
        _MATRIX._require_commit(artifact["source_commit"],
                                "native pre-index artifact source commit")
        _require(type(artifact["size"]) is int and artifact["size"] > 0,
                 "native pre-index archive size is invalid")
        _require(type(artifact["enabled"]) is bool and artifact["enabled"] is True,
                 "native pre-index plan lane must be enabled")
        paths = artifact["required_paths"]
        _require(type(paths) is list
                 and all(isinstance(path, str) for path in paths),
                 "native pre-index required paths are not a string array")
        by_lane[lane] = artifact
        by_asset.add(asset)
    _require(set(by_lane) == expected_lanes,
             "native pre-index artifacts omit a plan tuple")
    return by_lane


def _positive_job_id(value: object) -> int:
    _require(type(value) is int and value > 0,
             "original compiler owner job ID must be a positive integer")
    return value


def _validate_build(build: dict, *, asset: str, lane: tuple[str, str, str],
                    copy_id: str, expected_artifact: dict, bindings: dict,
                    group: dict, selected: dict,
                    snapshots: dict[Path, tuple[tuple[int, ...], dict[str, str]]]
                    ) -> dict:
    fields = {"copy", "original_job_id", "origin_sha256", "selection_sha256",
              "payload_zip_sha256", "origin_sigstore_sha256", "package", "measurement",
              "executor", "build_result_sha256", "original_observation",
              "original_native_verification", "native_verification"}
    build = _STAGE.exact_keys(build, fields, "compiler build evidence")
    _require(build["copy"] == copy_id,
             "compiler build copies are missing, duplicated, or reordered")
    original_job_id = _positive_job_id(build["original_job_id"])
    for field in ("origin_sha256", "selection_sha256", "payload_zip_sha256",
                  "origin_sigstore_sha256", "build_result_sha256"):
        _digest(build[field], f"compiler build {field}")

    package = _STAGE.exact_keys(build["package"],
                                {"directory", "archive", "archive_sha256", "archive_size"},
                                "compiler package evidence")
    package_dir_raw = package["directory"]
    _require(isinstance(package_dir_raw, str) and "\n" not in package_dir_raw
             and "\r" not in package_dir_raw,
             "compiler package directory path is invalid")
    package_dir = Path(package_dir_raw)
    _canonical(package_dir, "compiler package directory", directory=True)
    _require(package_dir.name == "package",
             "compiler package directory has an unexpected basename")
    _require(package["archive"] == package["archive_sha256"],
             "compiler package archive field must contain its digest")
    archive_sha = _digest(package["archive_sha256"], "compiler package archive digest")
    _require(type(package["archive_size"]) is int and package["archive_size"] > 0
             and archive_sha == expected_artifact["sha256"]
             and package["archive_size"] == expected_artifact["size"],
             "compiler package bytes differ from the native pre-index")

    payload_dir = package_dir.parent
    readback = payload_dir.parent
    _require(_remember_directory(payload_dir, "retained compiler payload directory", snapshots)
             == {"evidence": "directory", "package": "directory"},
             "retained compiler payload closure differs")
    package_entries = _remember_directory(
        package_dir, "retained compiler package directory", snapshots
    )
    _require(package_entries == {
        asset: "file", f"{asset}.manifest.json": "file", f"{asset}.sha256": "file",
        f"{asset}.spdx.json": "file",
    }, "retained compiler package does not contain its exact named closure")
    transport_dir = readback / "transport"
    _require(_remember_directory(transport_dir, "retained compiler transport directory", snapshots)
             == {"origin.json": "file", "origin.sigstore.json": "file",
                 "payload.zip": "file", "selection.json": "file"},
             "retained compiler transport inventory differs")
    archive_path = package_dir / asset
    archive_measurement, _ = _remember_file(
        archive_path, _ORIGIN.MAX_PAYLOAD, "retained compiler archive", selected
    )
    _require(archive_measurement["sha256"] == archive_sha
             and archive_measurement["size"] == package["archive_size"],
             "retained compiler archive bytes differ from the pre-index selector")

    measurement_path, measurement, _ = _measure_reference(
        build["measurement"], "compiler measurement", MAX_METADATA, selected, parse=True
    )
    _require(measurement_path == payload_dir / "evidence" / "measurement.json",
             "compiler measurement path differs from its retained payload")
    executor = _STAGE.exact_keys(build["executor"],
                                 {"contract_sha256", "binary_sha256"},
                                 "compiler executor selector")
    contract_sha = _digest(executor["contract_sha256"], "executor contract digest")
    binary_sha = _digest(executor["binary_sha256"], "executor binary digest")

    evidence_dir = payload_dir / "evidence"
    _require(_remember_directory(evidence_dir, "retained compiler evidence directory", snapshots)
             == {"build-result.json": "file", "environment.json": "file",
                 "environment-result.json": "file", "measurement.json": "file",
                 "package-result.json": "file", "package-verify.json": "file"},
             "retained compiler evidence closure differs")
    build_result_path = evidence_dir / "build-result.json"
    build_result_measurement, _ = _remember_file(
        build_result_path, MAX_METADATA, "retained compiler build result", selected
    )
    environment_path = evidence_dir / "environment.json"
    environment_measurement, environment_raw = _remember_file(
        environment_path, MAX_METADATA, "retained compiler build environment", selected,
        read=True,
    )
    environment = _STAGE.parse_json(environment_raw, "retained compiler build environment")
    _require(isinstance(environment, dict), "retained build environment must be an object")
    _require(build_result_measurement["sha256"] == build["build_result_sha256"],
             "compiler build-result bytes differ from the evidence selector")

    origin_path = readback / "transport" / "origin.json"
    selection_path = readback / "transport" / "selection.json"
    zip_path = readback / "transport" / "payload.zip"
    sigstore_path = readback / "transport" / "origin.sigstore.json"
    for path, limit, digest, label in (
        (origin_path, MAX_METADATA, build["origin_sha256"], "compiler origin document"),
        (selection_path, MAX_METADATA, build["selection_sha256"], "compiler selection document"),
        (zip_path, _ORIGIN.MAX_PAYLOAD, build["payload_zip_sha256"], "compiler retained payload ZIP"),
        (sigstore_path, MAX_METADATA, build["origin_sigstore_sha256"],
         "compiler retained signature bundle"),
    ):
        measured, _ = _remember_file(path, limit, label, selected)
        _require(measured["sha256"] == digest, f"{label} bytes differ from their selector")

    observation_path, observation_sha = _reference(
        build["original_observation"], "original compiler observation"
    )
    _require(observation_path == readback / "observation.json",
             "original compiler observation path differs from its retained owner")
    observation, _observation_raw, observation_measurement = _read_json(
        observation_path, MAX_METADATA, "original compiler observation", selected
    )
    _require(observation_measurement["sha256"] == observation_sha,
             "original compiler observation bytes differ from their selector")
    expected_group = group
    _require(observation.get("schema") == "aros-toolchain-original-owner-observation-v2"
             and observation.get("group") == lane[0]
             and observation.get("host") == lane[1]
             and observation.get("target_profile") == lane[2]
             and observation.get("copy") == copy_id
             and observation.get("release_id") == bindings["release_id"]
             and observation.get("reader_runtime_sha256") == bindings["aros_sha256"]
             and observation.get("recipe_file_sha256") == expected_group["recipe"]["sha256"]
             and observation.get("source_lock_sha256") == expected_group["source_lock"]["sha256"]
             and observation.get("profiles_sha256") == expected_group["profiles"]["sha256"]
             and observation.get("source_selection_sha256") == build["selection_sha256"]
             and observation.get("build_result_sha256") == build["build_result_sha256"]
             and observation.get("environment_sha256") == environment_measurement["sha256"]
             and observation.get("measurement_sha256") == measurement["sha256"]
             and observation.get("executor_contract_sha256") == contract_sha
             and observation.get("executor_binary_sha256") == binary_sha,
             "original compiler observation does not rejoin the selected lane and files")
    transport = observation.get("transport")
    _require(isinstance(transport, dict)
             and transport.get("origin_sha256") == build["origin_sha256"]
             and transport.get("selection_sha256") == build["selection_sha256"]
             and transport.get("raw_zip_sha256") == build["payload_zip_sha256"],
             "original compiler transport selectors differ from their retained bytes")
    identity = observation.get("original_identity")
    _require(isinstance(identity, dict)
             and identity.get("source_commit") == expected_group["source_commit"]
             and identity.get("producer_commit") == bindings["producer_commit"]
             and identity.get("tools_commit") == bindings["tools_commit"]
             and identity.get("host") == lane[1]
             and identity.get("target_profile") == lane[2],
             "original compiler identity differs from the plan-bound lane")

    original_native_path, original_native_sha = _reference(
        build["original_native_verification"], "original native verification"
    )
    _require(original_native_path == readback / "native-verification.json",
             "original native verification path differs from its retained owner")
    original_native, _original_native_raw, original_native_measurement = _read_json(
        original_native_path, MAX_NATIVE_RESULT, "original native verification", selected
    )
    _require(original_native_measurement["sha256"] == original_native_sha
             and original_native == observation.get("native"),
             "original native verification file differs from its observation")

    native_path, native_sha = _reference(build["native_verification"],
                                         "selected native verification")
    native_result, _native_raw, native_measurement = _read_json(
        native_path, MAX_NATIVE_RESULT, "selected native verification", selected
    )
    _require(native_measurement["sha256"] == native_sha
             and native_result.get("schema") == "aros-toolchain-producer-stage-v1"
             and native_result.get("operation") == "verify-package"
             and native_result.get("sha256") == archive_sha
             and native_result.get("size") == package["archive_size"],
             "selected native verification output differs from the package bytes")

    manifest = native_result.get("manifest")
    _require(isinstance(manifest, dict)
             and manifest.get("release_id") == bindings["release_id"]
             and manifest.get("host") == lane[1]
             and manifest.get("target_profile") == lane[2]
             and manifest.get("source_commit") == expected_group["source_commit"]
             and manifest.get("producer_commit") == bindings["producer_commit"]
             and manifest.get("tools_commit") == bindings["tools_commit"]
             and manifest.get("source_lock_sha256") == expected_group["source_lock"]["sha256"]
             and manifest.get("profiles_sha256") == expected_group["profiles"]["sha256"]
             and manifest.get("tree_sha256") == expected_artifact["tree_sha256"],
             "selected native verification manifest differs from the plan-bound lane")

    return {
        "package_dir": package_dir,
        "measurement": {"path": measurement_path, "sha256": measurement["sha256"]},
        "executor": {"contract_sha256": contract_sha, "binary_sha256": binary_sha},
        "job_id": original_job_id,
    }


def _validate_compiler(evidence: dict, lanes_doc: dict, index: dict,
                       plan: dict, *, plan_sha: str, inputs_sha: str,
                       producer: str, tools: str,
                       selected: dict[Path, tuple[int, dict, tuple[int, ...], bytes | None]],
                       snapshots: dict[Path, tuple[tuple[int, ...], dict[str, str]]]
                       ) -> tuple[dict[str, dict], dict[tuple[str, str, str], dict], dict]:
    evidence = _STAGE.exact_keys(evidence, {
        "schema", "assurance", "complete", "admission", "publication", "bindings", "assets",
    }, "compiler evidence fragment")
    _require(evidence["schema"] == "aros-toolchain-compiler-evidence-fragment-v1"
             and evidence["assurance"] == "partial-compiler-candidate-assembly-no-admission"
             and type(evidence["complete"]) is bool and not evidence["complete"]
             and type(evidence["admission"]) is bool and not evidence["admission"]
             and type(evidence["publication"]) is bool and not evidence["publication"],
             "compiler evidence fragment has unsupported authority")
    bindings = _STAGE.exact_keys(evidence["bindings"], {
        "aros_sha256", "plan_sha256", "inputs_sha256", "fragment_sha256",
        "required_paths_sha256", "source_context_sha256", "producer_commit",
        "tools_commit", "release_id",
    }, "compiler evidence bindings")
    for field in ("aros_sha256", "plan_sha256", "inputs_sha256", "fragment_sha256",
                  "required_paths_sha256", "source_context_sha256"):
        _digest(bindings[field], f"compiler evidence {field}")
    _require(bindings["plan_sha256"] == plan_sha and bindings["inputs_sha256"] == inputs_sha
             and bindings["producer_commit"] == producer and bindings["tools_commit"] == tools,
             "compiler evidence bindings differ from the explicit inputs")
    _MATRIX._require_safe_id(bindings["release_id"], "compiler evidence release ID")
    _MATRIX._require_commit(bindings["producer_commit"], "compiler evidence producer commit")
    _MATRIX._require_commit(bindings["tools_commit"], "compiler evidence tools commit")

    lanes_doc = _STAGE.exact_keys(lanes_doc, {"schema", "lanes"}, "compiler lane document")
    _require(lanes_doc["schema"] == "aros-toolchain-index-lanes-v1"
             and type(lanes_doc["lanes"]) is dict,
             "compiler lane document schema is unsupported")

    expected_lanes = {
        (lane["group_id"], lane["host"], lane["target_profile"])
        for lane in plan["lanes"]
    }
    group_by_id = {group["group_id"]: group for group in plan["groups"]}
    index_by_lane = _validate_index(
        index, inputs_sha=inputs_sha, producer=producer, tools=tools,
        release_id=bindings["release_id"], expected_lanes=expected_lanes,
    )
    assets = evidence["assets"]
    _require(type(assets) is dict
             and set(assets) == {item["asset"] for item in index_by_lane.values()}
             and set(lanes_doc["lanes"]) == set(assets),
             "compiler evidence, lane document, and native index asset names differ")

    lanes_by_asset: dict[str, dict] = {}
    job_ids: set[int] = set()
    for asset, raw_lane in assets.items():
        matching = [item for item in index_by_lane.values() if item["asset"] == asset]
        _require(len(matching) == 1,
                 "compiler asset name does not select exactly one native index tuple")
        artifact = matching[0]
        lane = (artifact["group_id"], artifact["host"], artifact["target_profile"])
        group = group_by_id.get(lane[0])
        _require(group is not None and artifact["source_commit"] == group["source_commit"],
                 "native pre-index source commit differs from the exact plan group")
        raw_lane = _STAGE.exact_keys(raw_lane,
                                     {"group_id", "host", "target_profile", "builds", "comparison"},
                                     "compiler asset evidence")
        _require((raw_lane["group_id"], raw_lane["host"], raw_lane["target_profile"]) == lane,
                 "compiler evidence asset tuple differs from the native index")
        lane_doc = _STAGE.exact_keys(lanes_doc["lanes"][asset],
                                     {"build_environment", "required_paths"},
                                     "compiler index lane")
        _require(isinstance(lane_doc["build_environment"], dict)
                 and type(lane_doc["required_paths"]) is list
                 and lane_doc["required_paths"] == artifact["required_paths"],
                 "compiler index lane differs from the actual native index lane")
        builds = raw_lane["builds"]
        _require(type(builds) is list and len(builds) == 2,
                 "compiler evidence must contain exactly two original builds")
        build_dtos = []
        observed_ids = []
        for index_copy, copy_id in enumerate(("a", "b")):
            dto = _validate_build(
                builds[index_copy], asset=asset, lane=lane, copy_id=copy_id,
                expected_artifact=artifact, bindings=bindings,
                group=group_by_id[lane[0]], selected=selected, snapshots=snapshots,
            )
            _require(dto["job_id"] not in job_ids,
                     "original compiler owner job IDs must be globally distinct")
            job_ids.add(dto["job_id"])
            observed_ids.append(dto["job_id"])
            build_dtos.append({
                "package_dir": str(dto["package_dir"]),
                "measurement": {"path": str(dto["measurement"]["path"]),
                                "sha256": dto["measurement"]["sha256"]},
                "executor": dto["executor"],
            })
        _require(observed_ids[0] != observed_ids[1],
                 "A/B original compiler owner job IDs must be distinct")

        comparison = _STAGE.exact_keys(raw_lane["comparison"], {"selectedFile"},
                                       "compiler comparison evidence")
        comparison_path, comparison_sha = _reference(comparison["selectedFile"],
                                                       "compiler comparison receipt")
        comparison_doc, _comparison_raw, comparison_measurement = _read_json(
            comparison_path, MAX_NATIVE_RESULT, "compiler comparison receipt", selected
        )
        _require(comparison_measurement["sha256"] == comparison_sha
                 and comparison_doc.get("schema") == 1
                 and comparison_doc.get("operation") == "compare"
                 and comparison_doc.get("byte_identical") is True,
                 "compiler comparison receipt differs from its selected bytes")

        lanes_by_asset[asset] = {
            "build_environment": lane_doc["build_environment"],
            "required_paths": lane_doc["required_paths"],
            "builds": build_dtos,
            "comparison": {"path": str(comparison_path), "sha256": comparison_sha},
            "artifact": artifact,
            "tuple": lane,
        }

    _require(len(lanes_by_asset) == len(expected_lanes)
             and {entry["tuple"] for entry in lanes_by_asset.values()} == expected_lanes,
             "compiler evidence does not cover every plan tuple exactly once")
    return lanes_by_asset, index_by_lane, bindings


def _expected_sdk_for_lane(plan: dict, lane: tuple[str, str, str]) -> dict:
    matches = []
    for sdk in plan["sdks"]:
        if any(reference["group_id"] == lane[0] and reference["profile"] == lane[2]
               for reference in sdk["compiler_profiles"]):
            matches.append(sdk)
    _require(len(matches) == 1,
             f"compiler lane {lane!r} has no unique source-declared SDK product binding")
    return matches[0]


def _hold_sdk_generation_documents(rows: list[dict], selected: dict,
                                   snapshots: dict) -> None:
    for row in rows:
        label = f"SDK generation {row['sdk_id']} {row['group_id']}/{row['host']}/{row['target_profile']}"
        _measure_reference(row["record"], f"{label} record", MAX_METADATA,
                           selected, parse=True)
        compatibility = row["compatibility"]
        _measure_reference(compatibility["inputs"], f"{label} compatibility inputs",
                           MAX_METADATA, selected, parse=True)
        directory = Path(compatibility["directory"])
        _remember_directory(directory, f"{label} compatibility directory", snapshots)
        manifest_path = directory / "compatibility-measurement.json"
        manifest, _manifest_raw, measured = _read_json(
            manifest_path, MAX_METADATA, f"{label} compatibility manifest", selected
        )
        _require(measured["sha256"] == compatibility["manifest_sha256"]
                 and isinstance(manifest, dict),
                 f"{label} compatibility manifest differs from its selected digest")


def _select_sdk(args: argparse.Namespace, plan: dict, bindings: dict,
                selected: dict[Path, tuple[int, dict, tuple[int, ...], bytes | None]],
                snapshots: dict[Path, tuple[tuple[int, ...], dict[str, str]]]
                ) -> tuple[dict, dict]:
    fragment = _canonical(args.sdk_fragment, "SDK selection fragment", directory=False)
    owner_root = _canonical(args.sdk_owner_root, "SDK owner root", directory=True)
    _require(fragment == owner_root / "selection-fragment.json",
             "SDK selection fragment must be the collector fragment under its owner root")
    before = _SDK.select(
        plan_path=args.plan, plan_sha256=args.plan_sha256,
        inputs_dir=args.inputs_dir, inputs_sha256=args.inputs_sha256,
        producer_commit=args.producer_commit, tools_commit=args.tools_commit,
        fragment_path=fragment, fragment_sha256=args.sdk_fragment_sha256,
        owner_root=owner_root,
    )
    raw_fragment, _raw, measured = _read_json(
        fragment, MAX_FRAGMENT, "SDK selection fragment", selected
    )
    _require(measured["sha256"] == args.sdk_fragment_sha256,
             "SDK selection fragment bytes differ from the selected digest")
    _STAGE.exact_keys(raw_fragment, {
        "schema", "assurance", "aros_sha256", "plan_sha256", "inputs_sha256",
        "source_context_sha256", "source_producer_commit", "source_workflow", "source_ref",
        "producer_commit", "tools_commit", "owner_count", "sdk_generation_count",
        "owner_transports", "sdk_generations", "release_admission", "publication",
    }, "SDK selection fragment")
    _require(raw_fragment["schema"] == "aros-sdk-generation-selection-fragment-v2"
             and raw_fragment["assurance"] == "authenticated-owner-transport-selection-only"
             and raw_fragment["plan_sha256"] == args.plan_sha256
             and raw_fragment["inputs_sha256"] == args.inputs_sha256
             and raw_fragment["producer_commit"] == args.producer_commit
             and raw_fragment["source_producer_commit"] == args.producer_commit
             and raw_fragment["tools_commit"] == args.tools_commit
             and raw_fragment["release_admission"] is False
             and raw_fragment["publication"] is False,
             "SDK fragment bindings differ from the selected plan, commits, or scope")
    for field in ("aros_sha256", "source_context_sha256"):
        _digest(raw_fragment[field], f"SDK fragment {field}")
    _require(raw_fragment["aros_sha256"] == bindings["aros_sha256"]
             and raw_fragment["source_context_sha256"] == bindings["source_context_sha256"],
             "compiler and SDK evidence do not share one source context and runtime")
    _require(isinstance(raw_fragment["source_workflow"], str)
             and _SDK.SOURCE_WORKFLOW.fullmatch(raw_fragment["source_workflow"]) is not None
             and isinstance(raw_fragment["source_ref"], str)
             and _SDK.SOURCE_REF.fullmatch(raw_fragment["source_ref"]) is not None,
             "SDK fragment source selectors are invalid")

    rows = raw_fragment["sdk_generations"]
    _require(type(rows) is list, "SDK fragment generations must be an array")
    expected_tuples = _SDK._expected_package_tuples(plan)
    _require(len(rows) == len(expected_tuples),
             "SDK fragment does not contain every plan-bound generation tuple")
    by_tuple: dict[tuple[str, str, str, str], dict] = {}
    for row in rows:
        key = tuple(row.get(field) for field in
                    ("sdk_id", "group_id", "target_profile", "host"))
        _require(key not in by_tuple, "SDK fragment contains a duplicate generation tuple")
        by_tuple[key] = row
    _require(set(by_tuple) == set(expected_tuples),
             "SDK fragment generation tuples differ from the source plan")
    _hold_sdk_generation_documents(rows, selected, snapshots)
    for owner_id, reference in raw_fragment["owner_transports"].items():
        _measure_reference(reference, f"SDK owner transport result {owner_id}",
                           MAX_FRAGMENT, selected, parse=True)

    return before, raw_fragment


def select(args: argparse.Namespace) -> dict:
    selected: dict[Path, tuple[int, dict, tuple[int, ...], bytes | None]] = {}
    snapshots: dict[Path, tuple[tuple[int, ...], dict[str, str]]] = {}
    plan, _plan_raw, _projection, families = _check_bound_inputs(args, selected, snapshots)

    compiler_evidence_path = _canonical(args.compiler_evidence,
                                         "compiler evidence fragment", directory=False)
    compiler_lanes_path = _canonical(args.compiler_lanes,
                                     "compiler lane document", directory=False)
    _require(compiler_evidence_path.name == "compiler-evidence-fragment.json"
             and compiler_lanes_path.name == "compiler-index-lanes.json"
             and compiler_evidence_path.parent == compiler_lanes_path.parent,
             "compiler evidence and lane documents must be the sibling assembler outputs")
    compiler_root = _canonical(compiler_evidence_path.parent,
                               "compiler candidate directory", directory=True)
    _remember_directory(compiler_root, "compiler candidate directory", snapshots)
    evidence, _evidence_raw, evidence_measurement = _read_json(
        compiler_evidence_path, MAX_FRAGMENT, "compiler evidence fragment", selected
    )
    lanes_doc, _lanes_raw, lanes_measurement = _read_json(
        compiler_lanes_path, MAX_FRAGMENT, "compiler lane document", selected
    )
    _require(evidence_measurement["sha256"] == args.compiler_evidence_sha256
             and lanes_measurement["sha256"] == args.compiler_lanes_sha256,
             "compiler evidence or lane bytes differ from the selected digest")

    index_path = _canonical(args.index, "native pre-index document", directory=False)
    index, _index_raw, index_measurement = _read_json(
        index_path, MAX_METADATA, "native pre-index document", selected
    )
    _require(index_measurement["sha256"] == args.index_sha256,
             "native pre-index bytes differ from the selected digest")

    compiler_by_asset, _index_by_lane, bindings = _validate_compiler(
        evidence, lanes_doc, index, plan, plan_sha=args.plan_sha256,
        inputs_sha=args.inputs_sha256, producer=args.producer_commit,
        tools=args.tools_commit, selected=selected, snapshots=snapshots,
    )
    sdk_before, sdk_fragment = _select_sdk(args, plan, bindings, selected, snapshots)
    _require(sdk_before["schema"] == "aros-sdk-package-inputs-v2"
             and sdk_before["plan_sha256"] == args.plan_sha256
             and sdk_before["inputs_sha256"] == args.inputs_sha256
             and sdk_before["producer_commit"] == args.producer_commit
             and sdk_before["tools_commit"] == args.tools_commit,
             "SDK selector output differs from the explicit release bindings")

    generations = {}
    for row in sdk_fragment["sdk_generations"]:
        key = (row["sdk_id"], row["group_id"], row["target_profile"], row["host"])
        generations[key] = row
    selected_lanes = {}
    for asset, compiler in compiler_by_asset.items():
        group_id, host, profile = compiler["tuple"]
        sdk = _expected_sdk_for_lane(plan, compiler["tuple"])
        generation_key = (sdk["id"], group_id, profile, host)
        matches = [row for key, row in generations.items() if key == generation_key]
        _require(len(matches) == 1,
                 f"compiler tuple {compiler['tuple']!r} lacks its exact declared SDK generation")
        generation = matches[0]
        compatibility = generation["compatibility"]
        family = families[group_id]
        _require(family in ("gnu", "llvm"), "source-lock family is unsupported")
        required_policy = family == "gnu"
        _require(type(compatibility["native_sdk_required"]) is bool
                 and compatibility["native_sdk_required"] is required_policy,
                 "SDK generation compatibility policy differs from its source-lock family")
        lane_dto = {
            "build_environment": compiler["build_environment"],
            "required_paths": compiler["required_paths"],
            "builds": compiler["builds"],
            "comparison": compiler["comparison"],
            "compatibility": compatibility,
        }
        if family == "llvm":
            lane_dto["llvm_sdk_id"] = sdk["id"]
        selected_lanes[asset] = lane_dto

    _require(set(sdk_before["sdk_packages"]) == {sdk["id"] for sdk in plan["sdks"]},
             "SDK package metrics do not cover the complete source plan")
    output = {
        "schema": SELECTION_SCHEMA,
        "lanes": selected_lanes,
        "sdk_packages": sdk_before["sdk_packages"],
        "sdk_generations": sdk_fragment["sdk_generations"],
    }

    # Rerun the complete retained SDK transport/package selector after the DTO
    # is assembled, then measure every held reference before returning stdout.
    sdk_after = _SDK.select(
        plan_path=args.plan, plan_sha256=args.plan_sha256,
        inputs_dir=args.inputs_dir, inputs_sha256=args.inputs_sha256,
        producer_commit=args.producer_commit, tools_commit=args.tools_commit,
        fragment_path=args.sdk_fragment, fragment_sha256=args.sdk_fragment_sha256,
        owner_root=args.sdk_owner_root,
    )
    _require(sdk_after == sdk_before,
             "SDK package selection changed before the final evidence barrier")
    for path, (limit, expected, fingerprint, _raw) in selected.items():
        measured = _STAGE.measure_file(path, limit, f"selected input {path.name}")
        _require(measured == expected and _stat_fingerprint(path.lstat()) == fingerprint,
                 f"selected input changed before output: {path.name}")
    for path, expected in snapshots.items():
        _require(_STAGE.path_is_canonical(path, must_exist=True)
                 and _STAGE.directory_fingerprint(path, f"selected directory {path.name}")
                 == expected[0]
                 and _STAGE.directory_entries(path, f"selected directory {path.name}")
                 == expected[1],
                 f"selected directory changed before output: {path.name}")
    return output


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--plan-sha256", required=True)
    parser.add_argument("--inputs-dir", required=True, type=Path)
    parser.add_argument("--inputs-sha256", required=True)
    parser.add_argument("--producer-commit", required=True)
    parser.add_argument("--tools-commit", required=True)
    parser.add_argument("--compiler-lanes", required=True, type=Path)
    parser.add_argument("--compiler-lanes-sha256", required=True)
    parser.add_argument("--compiler-evidence", required=True, type=Path)
    parser.add_argument("--compiler-evidence-sha256", required=True)
    parser.add_argument("--sdk-fragment", required=True, type=Path)
    parser.add_argument("--sdk-fragment-sha256", required=True)
    parser.add_argument("--sdk-owner-root", required=True, type=Path)
    parser.add_argument("--index", required=True, type=Path)
    parser.add_argument("--index-sha256", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    option_names = [value.split("=", 1)[0] for value in arguments
                    if value.startswith("--")]
    if len(option_names) != len(set(option_names)):
        print("native release evidence selection failed: repeated command-line option",
              file=sys.stderr)
        return 2
    try:
        args = _parser().parse_args(arguments)
        output = select(args)
        sys.stdout.write(json.dumps(output, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=True, allow_nan=False) + "\n")
        return 0
    except (_STAGE.StageError, _MATRIX.PlanError, _SDK.SelectionError, SelectionError,
            OSError, UnicodeError, RecursionError, ValueError) as error:
        print(f"native release evidence selection failed: {error}", file=sys.stderr)
        return 2
    except Exception:
        print("native release evidence selection failed: closed byte boundary", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
