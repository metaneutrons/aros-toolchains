#!/usr/bin/env python3
"""Prepare an independently observed V2 recovery request and reacquire bytes.

This helper is an adapter for a protected caller. It does not authenticate the
provider, tag, signer, original owner jobs, or release state, and it does not
execute compatibility replay, create tags/releases, or package files. The
caller must authenticate every supplied observation before invoking it.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
HELPERS_PATH = HERE / "record-complete-qualification-v2.py"
_HELPERS_SPEC = importlib.util.spec_from_file_location("_qualification_v2_helpers", HELPERS_PATH)
if _HELPERS_SPEC is None or _HELPERS_SPEC.loader is None:
    raise RuntimeError("could not load bounded V2 file and child-process helpers")
_HELPERS = importlib.util.module_from_spec(_HELPERS_SPEC)
sys.modules[_HELPERS_SPEC.name] = _HELPERS
_HELPERS_SPEC.loader.exec_module(_HELPERS)

AdapterError = _HELPERS.AdapterError
MAX_METADATA = _HELPERS.MAX_METADATA
MAX_OBSERVATION = 1024 * 1024
MAX_SUBJECT_MANIFEST = _HELPERS.MAX_SUBJECT_MANIFEST
MAX_RUNTIME = _HELPERS.MAX_RUNTIME
NATIVE_TIMEOUT_SECONDS = _HELPERS.NATIVE_TIMEOUT_SECONDS
HEX40 = _HELPERS.HEX40
HEX64 = _HELPERS.HEX64
TAG = _HELPERS.TAG
RECOVERY_SCHEMA = "aros-toolchain-recovery-request-v2"
QUALIFICATION_SCHEMA = "aros-toolchain-qualification-evidence-v2"
SELECTION_SCHEMA = "aros-toolchain-release-evidence-selection-v2"
RESULT_SCHEMA = "aros-toolchain-producer-stage-v2"
OPERATIONS = {
    "packaging-recovery": "packaging",
    "compatibility-replay": "compatibility-harness",
}
FAILED_STAGES = {
    "compatibility-harness", "packaging", "configure", "compiler",
    "comparison", "compatibility", "attestation", "unknown",
}
REPOSITORY_URL = re.compile(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
WORKFLOW = re.compile(
    r"\.github/workflows/(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+\.yml\Z"
)


def _require(condition: bool, message: str) -> None:
    _HELPERS._require(condition, message)


def _digest(value: object, label: str) -> str:
    return _HELPERS._digest(value, label)


def _json(raw: bytes | None, label: str) -> dict:
    return _HELPERS._json(raw, label)


def _keys(value: object, keys: set[str], label: str) -> dict:
    return _HELPERS._exact_keys(value, keys, label)


def _u64(value: object, label: str, *, positive: bool = True) -> int:
    _require(type(value) is int and value <= 2**64 - 1
             and (value > 0 if positive else value >= 0),
             f"{label} must be a {'positive ' if positive else ''}u64 JSON integer")
    return value


def _safe_string(value: object, label: str, *, limit: int = 512) -> str:
    _require(isinstance(value, str) and 0 < len(value) <= limit
             and "\0" not in value and "\n" not in value and "\r" not in value,
             f"{label} is not a bounded string")
    return value


def _read_selected(path: Path, limit: int, expected_sha: str, label: str,
                   held: dict[Path, dict[str, Any]], *, retain: bool = True) -> bytes | None:
    measurement, raw, fingerprint = _HELPERS._read_owned(path, limit, label, retain=retain)
    _require(measurement["sha256"] == expected_sha,
             f"{label} bytes differ from their independent SHA-256 selector")
    _require(path not in held, f"{label} reuses another selected input path")
    held[path] = {"limit": limit, "label": label, "measurement": measurement,
                  "fingerprint": fingerprint}
    return raw


def _source_run(value: object, label: str) -> dict:
    item = _keys(value, {
        "repository", "workflow", "run_id", "run_attempt", "producer_commit",
        "source_tag", "tag_object",
    }, label)
    repository = _safe_string(item["repository"], f"{label} repository", limit=256)
    _require(REPOSITORY_URL.fullmatch(repository) is not None,
             f"{label} repository must be a canonical GitHub HTTPS repository URL")
    workflow = _safe_string(item["workflow"], f"{label} workflow")
    _require(WORKFLOW.fullmatch(workflow) is not None
             and all(part not in ("", ".", "..") for part in workflow.split("/")),
             f"{label} workflow must be a canonical repository-relative .yml path")
    _u64(item["run_id"], f"{label} run ID")
    _u64(item["run_attempt"], f"{label} run attempt")
    _require(isinstance(item["producer_commit"], str)
             and HEX40.fullmatch(item["producer_commit"]) is not None,
             f"{label} producer commit must be a lowercase Git object ID")
    _require(isinstance(item["tag_object"], str)
             and HEX40.fullmatch(item["tag_object"]) is not None
             and item["tag_object"] != item["producer_commit"],
             f"{label} tag object must be a distinct annotated Git object ID")
    _require(isinstance(item["source_tag"], str) and TAG.fullmatch(item["source_tag"]) is not None,
             f"{label} source tag must use the project's stable or rc.N release grammar")
    return item


def _observed_tag(value: object, label: str) -> dict:
    item = _keys(value, {"name", "tag_object", "peeled_commit"}, label)
    _require(isinstance(item["name"], str) and TAG.fullmatch(item["name"]) is not None,
             f"{label} name must use the project's stable or rc.N release grammar")
    _require(isinstance(item["tag_object"], str)
             and HEX40.fullmatch(item["tag_object"]) is not None,
             f"{label} tag object must be a lowercase Git object ID")
    _require(isinstance(item["peeled_commit"], str)
             and HEX40.fullmatch(item["peeled_commit"]) is not None
             and item["tag_object"] != item["peeled_commit"],
             f"{label} peeled commit must differ from its annotated tag object")
    return item


def _attestation(value: object, label: str) -> dict:
    item = _keys(value, {
        "repository", "workflow", "signer", "subject_manifest_sha256",
    }, label)
    repository = _safe_string(item["repository"], f"{label} repository", limit=256)
    _require(REPOSITORY_URL.fullmatch(repository) is not None,
             f"{label} repository must be a canonical GitHub HTTPS repository URL")
    workflow = _safe_string(item["workflow"], f"{label} workflow")
    _require(WORKFLOW.fullmatch(workflow) is not None,
             f"{label} workflow must be a repository-relative .yml path")
    signer = _safe_string(item["signer"], f"{label} signer", limit=128)
    _require(all(char.isascii() and (char.isalnum() or char in "._-:") for char in signer),
             f"{label} signer contains an unsupported character")
    _digest(item["subject_manifest_sha256"], f"{label} subject-manifest digest")
    return item


def _handoff(value: object, source_run: dict, release_id: str) -> dict:
    item = _keys(value, {"release_id", "tag", "state"}, "observed recovery handoff")
    new_id = _safe_string(item["release_id"], "handoff release ID", limit=128)
    tag = _observed_tag(item["tag"], "handoff annotated tag")
    _require(item["state"] == "absent",
             "packaging recovery requires an exact absent remote handoff state")
    _require(TAG.fullmatch(new_id) is not None and new_id == tag["name"],
             "fresh handoff release ID and tag name must be the same stable or rc.N SemVer")
    _require(new_id != release_id and new_id != source_run["source_tag"],
             "fresh handoff must use a release ID distinct from the original candidate")
    _require(tag["tag_object"] != source_run["tag_object"],
             "fresh handoff must use a distinct annotated tag object")
    _require(tag["peeled_commit"] == source_run["producer_commit"],
             "fresh handoff tag must peel to the original producer commit")
    return item


def _check_qualification(value: object, *, release_id: str, base_url: str,
                         inputs_sha: str, index_sha: str, selection: dict) -> dict:
    _require(type(value) is dict, "qualification evidence must be a JSON object")
    keys = {"schema", "created_at", "expires_at", "source_run", "release",
            "attestation", "lanes", "coverage"}
    if "sdk_generations" in value:
        keys.add("sdk_generations")
    evidence = _keys(value, keys, "qualification evidence")
    _require(evidence["schema"] == QUALIFICATION_SCHEMA,
             "selected qualification must use the family-v2 evidence schema")
    _u64(evidence["created_at"], "qualification creation epoch")
    _u64(evidence["expires_at"], "qualification expiry epoch")
    _require(evidence["expires_at"] > evidence["created_at"],
             "qualification expiry must follow its creation epoch")
    source_run = _source_run(evidence["source_run"], "qualification source run")
    release = _keys(evidence["release"], {
        "release_id", "base_url", "inputs_sha256", "release_index_sha256",
        "pre_attestation_checksums_sha256", "checksums_sha256", "provenance_sha256",
        "producer_commit", "tools_commit",
    }, "qualification release identity")
    _require(release["release_id"] == release_id
             and source_run["source_tag"] == release_id,
             "original release ID, qualification release ID, and source tag must be identical")
    canonical_url = f"{source_run['repository']}/releases/download/{source_run['source_tag']}"
    _require(base_url == canonical_url and release["base_url"] == canonical_url,
             "base URL must be the canonical repository and original source-tag download URL")
    _require(release["inputs_sha256"] == inputs_sha
             and release["release_index_sha256"] == index_sha,
             "qualification input or index digest differs from its explicit selector")
    _require(release["producer_commit"] == source_run["producer_commit"],
             "qualification release producer commit differs from the selected source run")
    for field in ("inputs_sha256", "release_index_sha256", "pre_attestation_checksums_sha256",
                  "checksums_sha256", "provenance_sha256"):
        _digest(release[field], f"qualification release {field}")
    _require(type(evidence["lanes"]) is list and evidence["coverage"] == "release-candidate",
             "recovery requires release-candidate coverage and a lane array")
    lane_fields = {
        "group_id", "asset", "host", "target_profile", "target_triple", "source_commit",
        "compiler", "recipe_sha256", "source_lock_sha256", "profiles_sha256",
        "archive_sha256", "archive_size", "tree_sha256", "build_a_report_sha256",
        "build_b_report_sha256", "comparison_report_sha256", "compatibility_report_sha256",
    }
    qualified_lanes: dict[str, dict] = {}
    for raw_lane in evidence["lanes"]:
        lane = _keys(raw_lane, lane_fields, "qualification compiler lane")
        asset = _safe_string(lane["asset"], "qualification compiler asset", limit=255)
        _require(asset not in qualified_lanes, "qualification repeats a compiler asset")
        for field in ("group_id", "host", "target_profile", "target_triple"):
            _safe_string(lane[field], f"qualification lane {field}")
        _require(type(lane["compiler"]) is dict,
                 "qualification compiler identity must be an object")
        _require(isinstance(lane["source_commit"], str)
                 and HEX40.fullmatch(lane["source_commit"]) is not None,
                 "qualification lane source commit must be a Git object ID")
        _u64(lane["archive_size"], "qualification lane archive size")
        for field in ("recipe_sha256", "source_lock_sha256", "profiles_sha256",
                      "archive_sha256", "tree_sha256", "build_a_report_sha256",
                      "build_b_report_sha256", "comparison_report_sha256",
                      "compatibility_report_sha256"):
            _digest(lane[field], f"qualification lane {field}")
        qualified_lanes[asset] = lane
    _require(set(qualified_lanes) == set(selection["lanes"]),
             "qualification compiler assets differ from the independently selected lane set")
    for asset, lane in qualified_lanes.items():
        selected_lane = selection["lanes"][asset]
        _require(type(selected_lane) is dict and type(selected_lane.get("builds")) is list
                 and len(selected_lane["builds"]) == 2,
                 f"selected compiler lane {asset} is not a complete A/B pair")
        selected_measurements = [
            selected_lane["builds"][0]["measurement"]["sha256"],
            selected_lane["builds"][1]["measurement"]["sha256"],
        ]
        _require(lane["build_a_report_sha256"] == selected_measurements[0]
                 and lane["build_b_report_sha256"] == selected_measurements[1]
                 and lane["comparison_report_sha256"]
                 == selected_lane["comparison"]["sha256"]
                 and lane["compatibility_report_sha256"]
                 == selected_lane["compatibility"]["manifest_sha256"],
                 f"qualification compiler digests differ from selected evidence for {asset}")
    if "sdk_generations" in evidence:
        _require(type(evidence["sdk_generations"]) is list,
                 "qualification SDK generation claims must be an array")
    _require(bool(selection["sdk_generations"]) == bool(evidence.get("sdk_generations", [])),
             "qualification SDK generation coverage differs from the independent selection")
    generation_fields = {
        "sdk_id", "group_id", "target_profile", "host", "generation_record_sha256",
        "compatibility_report_sha256", "compatibility_receipt_sha256", "sdk_link_receipt_sha256",
    }
    qualified_generations: dict[tuple[str, str, str, str], dict] = {}
    for raw_generation in evidence.get("sdk_generations", []):
        generation = _keys(raw_generation, generation_fields,
                           "qualification SDK generation tuple")
        identity = tuple(_safe_string(generation[field], f"qualification SDK tuple {field}")
                         for field in ("sdk_id", "group_id", "target_profile", "host"))
        _require(identity not in qualified_generations,
                 "qualification repeats an SDK generation tuple")
        for field in ("generation_record_sha256", "compatibility_report_sha256",
                      "compatibility_receipt_sha256", "sdk_link_receipt_sha256"):
            _digest(generation[field], f"qualification SDK tuple {field}")
        qualified_generations[identity] = generation
    selected_generations = selection["sdk_generations"]
    selected_generation_ids: set[tuple[str, str, str, str]] = set()
    for row in selected_generations:
        row = _keys(row, {
            "sdk_id", "group_id", "target_profile", "host", "package_dir", "record",
            "compatibility",
        }, "selected SDK generation tuple")
        identity = tuple(_safe_string(row.get(field), f"selected SDK tuple {field}")
                         for field in ("sdk_id", "group_id", "target_profile", "host"))
        _require(identity not in selected_generation_ids,
                 "selection repeats an SDK generation tuple")
        selected_generation_ids.add(identity)
        _HELPERS._normalized_path(row["package_dir"], "selected SDK package directory")
        record = _keys(row.get("record"), {"path", "sha256"},
                       "selected SDK generation record")
        _HELPERS._normalized_path(record["path"], "selected SDK generation record")
        _digest(record["sha256"], "selected SDK generation record digest")
        compatibility = _keys(row.get("compatibility"), {
            "directory", "inputs", "manifest_sha256", "native_sdk_required",
        }, "selected SDK compatibility claim")
        _HELPERS._normalized_path(compatibility["directory"],
                                  "selected SDK compatibility directory")
        input_reference = _keys(compatibility["inputs"], {"path", "sha256"},
                                "selected SDK compatibility input")
        _HELPERS._normalized_path(input_reference["path"], "selected SDK compatibility input")
        _digest(input_reference["sha256"], "selected SDK compatibility-input digest")
        _digest(compatibility["manifest_sha256"], "selected SDK compatibility digest")
        _require(type(compatibility["native_sdk_required"]) is bool,
                 "selected SDK compatibility policy must be a JSON boolean")
    _require(set(qualified_generations) == selected_generation_ids,
             "qualification SDK generation tuples differ from the independent selection")
    for identity, generation in qualified_generations.items():
        selected = next(row for row in selected_generations
                        if tuple(row[field] for field in
                                 ("sdk_id", "group_id", "target_profile", "host")) == identity)
        _require(generation["generation_record_sha256"] == selected["record"]["sha256"]
                 and generation["compatibility_report_sha256"]
                 == selected["compatibility"]["manifest_sha256"],
                 "qualification SDK generation digests differ from their selected records")
    attestation = _attestation(evidence["attestation"], "qualification attestation")
    _require(attestation["repository"] == source_run["repository"]
             and attestation["workflow"] == source_run["workflow"],
             "qualification attestation repository/workflow differs from its source run")
    return {"evidence": evidence, "source_run": source_run,
            "release": release, "attestation": attestation,
            "qualified_lanes": qualified_lanes,
            "qualified_generations": qualified_generations}


def _result(raw: bytes, *, state: dict[str, Any], expected_decision: object) -> dict:
    result = _HELPERS._parse_child_json(raw, "native verify-recovery")
    base = {
        "schema", "operation", "release_format", "assurance", "release_id",
        "inputs_sha256", "index_sha256", "selection_sha256", "subject_manifest_sha256",
        "checksums_sha256", "provenance_sha256", "lane_count", "build_count", "lanes",
        "qualification_sha256", "policy_sha256", "recovery_request_sha256", "decision",
    }
    sdk_fields = {"sdk_count", "sdks"}
    generation_fields = {"sdk_generation_count", "sdk_generations"}
    allowed_shapes = {frozenset(base), frozenset(base | sdk_fields),
                      frozenset(base | generation_fields),
                      frozenset(base | sdk_fields | generation_fields)}
    _require(frozenset(result) in allowed_shapes,
             "native verify-recovery returned an unsupported closed result shape")
    _require(result["schema"] == RESULT_SCHEMA and result["operation"] == "verify-recovery"
             and result["release_format"] == "family-v2"
             and result["assurance"] == "byte-consistency-only",
             "native result does not select family-v2 verify-recovery byte consistency")
    for field, expected in (
        ("release_id", state["release_id"]),
        ("inputs_sha256", state["inputs_sha256"]),
        ("index_sha256", state["index_sha256"]),
        ("selection_sha256", state["selection_sha256"]),
        ("subject_manifest_sha256", state["subject_sha256"]),
        ("qualification_sha256", state["qualification_sha256"]),
        ("policy_sha256", state["policy_sha256"]),
        ("recovery_request_sha256", state["request_sha256"]),
    ):
        _require(result.get(field) == expected,
                 f"native verify-recovery result differs from the selected {field} join")
    release_claims = state["release_claims"]
    _require(result.get("checksums_sha256") == release_claims["checksums_sha256"]
             and result.get("provenance_sha256") == release_claims["provenance_sha256"],
             "native checksum or provenance digest differs from the held qualification claims")
    _digest(result.get("checksums_sha256"), "native measured checksum-document digest")
    _digest(result.get("provenance_sha256"), "native measured provenance digest")
    lane_count = result.get("lane_count")
    build_count = result.get("build_count")
    _u64(lane_count, "native compiler lane count", positive=False)
    _u64(build_count, "native build count", positive=False)
    _require(result.get("decision") == expected_decision,
             "native result recovery decision differs from the exact requested operation")

    selection = state["selection"]
    expected_sdk_count = len(selection["sdk_packages"])
    expected_generation_count = len(selection["sdk_generations"])
    _require(("sdk_count" in result) == bool(expected_sdk_count)
             and ("sdk_generation_count" in result) == bool(expected_generation_count),
             "native SDK result fields do not match the independently selected complete closure")
    result_state = {
        "selection": selection,
        "summary": {"bindings": {"release_id": state["release_id"],
                                  "base_url": state["base_url"]}},
        "lane_count": len(selection["lanes"]),
        "sdk_count": expected_sdk_count,
        "checksums_sha256": release_claims["checksums_sha256"],
        "bundle_sha256": release_claims["provenance_sha256"],
        "inputs_sha256": state["inputs_sha256"],
        "index_sha256": state["index_sha256"],
        "selection_sha256": state["selection_sha256"],
        "subject_sha256": state["subject_sha256"],
    }
    # Reuse the recorder's complete result-to-selection checker before looking
    # inside any child rows. This requires every compiler and SDK row, binds
    # package bytes to the independent selection, and rejects partial closures.
    _HELPERS._check_readback_result(result, result_state, operation="verify-recovery",
                                    evidence_sha=state["qualification_sha256"],
                                    policy_sha=state["policy_sha256"])

    for lane in result["lanes"]:
        claim = state["qualified_lanes"][lane["asset"]]
        _require(lane["measurement_sha256"] == [claim["build_a_report_sha256"],
                                                claim["build_b_report_sha256"]]
                 and lane["comparison_sha256"] == claim["comparison_report_sha256"]
                 and lane["compatibility_manifest_sha256"]
                 == claim["compatibility_report_sha256"],
                 f"native compiler report digests differ from qualification for {lane['asset']}")
    if "sdk_count" in result:
        selected_sdk_ids = set(selection["sdk_packages"])
        for row in result["sdks"]:
            _require(type(row["identity"]) is dict
                     and isinstance(row["identity"].get("sdk_id"), str)
                     and row["identity"].get("sdk_id") == row["sdk_id"],
                     "native SDK result identity differs from its selected product ID")
            _require(row["sdk_id"] in selected_sdk_ids,
                     "native SDK result product ID differs from the independent selection")
    if "sdk_generation_count" in result:
        result_generations = {
            (row["sdk_id"], row["group_id"], row["target_profile"], row["host"]): row
            for row in result["sdk_generations"]
        }
        _require(set(result_generations) == set(state["qualified_generations"]),
                 "native SDK generation tuples differ from held qualification tuples")
        for identity, row in result_generations.items():
            claim = state["qualified_generations"][identity]
            _require(row["generation_record_sha256"] == claim["generation_record_sha256"]
                     and row["compatibility_manifest_sha256"]
                     == claim["compatibility_report_sha256"]
                     and row["compatibility_receipt_sha256"]
                     == claim["compatibility_receipt_sha256"]
                     and row["sdk_link_receipt_sha256"] == claim["sdk_link_receipt_sha256"],
                     "native SDK generation readback differs from qualification tuple digests")

    return result


def _preflight(args: argparse.Namespace) -> dict[str, Any]:
    runtime = _HELPERS._normalized_path(args.runtime, "selected runtime")
    release_dir = _HELPERS._normalized_path(args.release_dir, "release directory")
    selection_path = _HELPERS._normalized_path(args.selection, "release-evidence selection")
    subject_path = _HELPERS._normalized_path(args.subject_manifest, "subject manifest")
    qualification_path = _HELPERS._normalized_path(args.qualification_evidence,
                                                    "qualification evidence")
    policy_path = _HELPERS._normalized_path(args.policy, "verifier policy")
    observed_run_path = _HELPERS._normalized_path(args.observed_run, "observed source run")
    observed_tag_path = _HELPERS._normalized_path(args.observed_source_tag,
                                                  "observed source tag")
    observed_attestation_path = _HELPERS._normalized_path(args.observed_attestation,
                                                           "observed attestation")
    handoff_path = (_HELPERS._normalized_path(args.handoff, "observed recovery handoff")
                    if args.handoff is not None else None)
    operation_dir = _HELPERS._normalized_path(args.operation_dir, "operation directory")

    runtime_sha = _digest(args.runtime_sha256, "selected runtime digest")
    inputs_sha = _digest(args.inputs_sha256, "selected release-input digest")
    index_sha = _digest(args.index_sha256, "selected release-index digest")
    selection_sha = _digest(args.selection_sha256, "selected selection digest")
    subject_sha = _digest(args.subject_manifest_sha256, "selected subject-manifest digest")
    qualification_sha = _digest(args.qualification_sha256, "selected qualification digest")
    policy_sha = _digest(args.policy_sha256, "selected verifier-policy digest")
    run_sha = _digest(args.observed_run_sha256, "observed source-run digest")
    tag_sha = _digest(args.observed_source_tag_sha256, "observed source-tag digest")
    attestation_sha = _digest(args.observed_attestation_sha256,
                              "observed attestation digest")
    handoff_sha = (_digest(args.handoff_sha256, "observed handoff digest")
                   if args.handoff_sha256 is not None else None)
    release_id = _safe_string(args.release_id, "selected original release ID", limit=128)
    _require(TAG.fullmatch(release_id) is not None,
             "original release ID must use the project's stable or rc.N release grammar")
    _require(args.operation in OPERATIONS, "operation is not an eligible V2 recovery operation")
    failed_stage = args.failed_stage
    _require(failed_stage in FAILED_STAGES and failed_stage == OPERATIONS[args.operation],
             "only packaging-recovery/packaging or compatibility-replay/compatibility-harness is eligible")
    _require(isinstance(args.base_url, str), "base URL must be a string")
    _require(type(args.forbidden_prefix) is list and bool(args.forbidden_prefix),
             "at least one repeated forbidden-prefix selector is required")
    forbidden: list[Path] = []
    for raw_prefix in args.forbidden_prefix:
        prefix = _HELPERS._normalized_path(raw_prefix, "forbidden prefix")
        _HELPERS._directory(prefix, "forbidden prefix", owned=False)
        _require(prefix not in forbidden, "forbidden-prefix selectors must be unique")
        forbidden.append(prefix)

    if args.operation == "packaging-recovery":
        _require(handoff_path is not None and handoff_sha is not None,
                 "packaging recovery requires an independently selected handoff document and digest")
    else:
        _require(handoff_path is None and handoff_sha is None,
                 "compatibility replay forbids any handoff document or digest")

    _HELPERS._directory(release_dir, "selected release", owned=True)
    operation_parent = operation_dir.parent
    _HELPERS._directory(operation_parent, "operation directory parent", owned=True)
    _require(operation_dir.name not in ("", ".", "..")
             and not os.path.lexists(operation_dir),
             "operation directory must be absent; refusing to adopt or overwrite it")

    held: dict[Path, dict[str, Any]] = {}
    # These are the exact release-directory documents selected by the explicit
    # digests and consumed by the native reader. Hash and retain their file
    # identities here so every child/finalization boundary rechecks them; the
    # native command remains authoritative for their Rust schemas and joins.
    _read_selected(release_dir / "toolchain-release-inputs-v2.json", MAX_METADATA,
                   inputs_sha, "selected family-v2 release inputs", held, retain=False)
    _read_selected(release_dir / "toolchain-index-v2.json", MAX_METADATA,
                   index_sha, "selected family-v2 release index", held, retain=False)
    runtime_raw = _read_selected(runtime, MAX_RUNTIME, runtime_sha, "selected native runtime",
                                 held, retain=False)
    del runtime_raw
    runtime_stat = runtime.lstat()
    _require(runtime_stat.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH),
             "selected native runtime is not executable")

    selection_raw = _read_selected(selection_path, MAX_METADATA, selection_sha,
                                   "closed release-evidence selection", held)
    selection = _keys(_json(selection_raw, "closed release-evidence selection"),
                      {"schema", "lanes", "sdk_packages", "sdk_generations"},
                      "closed release-evidence selection")
    _require(selection["schema"] == SELECTION_SCHEMA and type(selection["lanes"]) is dict
             and type(selection["sdk_packages"]) is dict
             and type(selection["sdk_generations"]) is list,
             "release-evidence selection has the wrong family-v2 schema or collection types")
    _require(bool(selection["lanes"]), "release-evidence selection has no compiler lanes")

    subject_raw = _read_selected(subject_path, MAX_SUBJECT_MANIFEST, subject_sha,
                                 "external pre-attestation subject manifest", held)
    del subject_raw
    qualification_raw = _read_selected(qualification_path, MAX_METADATA, qualification_sha,
                                        "selected family-v2 qualification", held)
    qualification = _json(qualification_raw, "selected family-v2 qualification")
    checked = _check_qualification(qualification, release_id=release_id,
                                   base_url=args.base_url, inputs_sha=inputs_sha,
                                   index_sha=index_sha, selection=selection)
    policy_raw = _read_selected(policy_path, MAX_METADATA, policy_sha,
                                "selected verifier policy", held)
    _json(policy_raw, "selected verifier policy")
    observed_run_raw = _read_selected(observed_run_path, MAX_OBSERVATION, run_sha,
                                      "independent source-run observation", held)
    observed_run = _source_run(_json(observed_run_raw, "independent source-run observation"),
                               "independent source-run observation")
    observed_tag_raw = _read_selected(observed_tag_path, MAX_OBSERVATION, tag_sha,
                                      "independent source-tag observation", held)
    observed_tag = _observed_tag(_json(observed_tag_raw, "independent source-tag observation"),
                                 "independent source-tag observation")
    observed_attestation_raw = _read_selected(
        observed_attestation_path, MAX_OBSERVATION, attestation_sha,
        "independent verifier attestation observation", held)
    observed_attestation = _attestation(
        _json(observed_attestation_raw, "independent verifier attestation observation"),
        "independent verifier attestation observation")
    _require(observed_run == checked["source_run"],
             "independent run observation differs from the exact qualification source attempt")
    expected_source_tag = {
        "name": checked["source_run"]["source_tag"],
        "tag_object": checked["source_run"]["tag_object"],
        "peeled_commit": checked["source_run"]["producer_commit"],
    }
    _require(observed_tag == expected_source_tag,
             "independent source tag observation differs from the original annotated tag")
    _require(observed_attestation == checked["attestation"],
             "independent verifier claim differs from the exact qualification attestation")
    _require(observed_attestation["subject_manifest_sha256"] == subject_sha,
             "independent verifier claim does not bind the selected subject manifest")
    _require(checked["release"]["pre_attestation_checksums_sha256"] == subject_sha,
             "qualification pre-attestation subject digest differs from the selected manifest")

    handoff = None
    if handoff_path is not None and handoff_sha is not None:
        handoff_raw = _read_selected(handoff_path, MAX_OBSERVATION, handoff_sha,
                                     "independent recovery handoff observation", held)
        handoff = _handoff(_json(handoff_raw, "independent recovery handoff observation"),
                           checked["source_run"], release_id)

    # Keep every operation artifact outside the release, selected evidence
    # roots, selection-referenced package paths, and caller-forbidden roots.
    evidence_paths = [selection_path, subject_path, qualification_path, policy_path,
                      observed_run_path, observed_tag_path, observed_attestation_path]
    if handoff_path is not None:
        evidence_paths.append(handoff_path)
    protected_roots = [release_dir, *forbidden, *evidence_paths,
                       *(path.parent for path in evidence_paths),
                       *_HELPERS._selection_paths(selection)]
    for root in protected_roots:
        _require(not _HELPERS._path_overlaps(operation_dir, root),
                 "operation directory must remain outside all selected release/evidence/forbidden roots")

    request = {
        "schema": RECOVERY_SCHEMA,
        "qualification_sha256": qualification_sha,
        "operation": args.operation,
        "failed_stage": failed_stage,
        "observed_run": observed_run,
        "source_tag": observed_tag,
        "observed_attestation": observed_attestation,
        "handoff": handoff,
    }
    request_bytes = (json.dumps(request, sort_keys=True, separators=(",", ":")) + "\n").encode()
    _require(len(request_bytes) <= MAX_OBSERVATION,
             "closed recovery request exceeds the native recovery metadata limit")
    request_sha = hashlib.sha256(request_bytes).hexdigest()
    _HELPERS._check_held(held)
    return {
        "runtime": runtime, "release_dir": release_dir, "release_id": release_id,
        "base_url": args.base_url, "inputs_sha256": inputs_sha, "index_sha256": index_sha,
        "selection_path": selection_path, "selection_sha256": selection_sha,
        "selection": selection, "subject_path": subject_path, "subject_sha256": subject_sha,
        "qualification_path": qualification_path, "qualification_sha256": qualification_sha,
        "qualification": checked["evidence"],
        "release_claims": checked["release"],
        "qualified_lanes": checked["qualified_lanes"],
        "qualified_generations": checked["qualified_generations"],
        "policy_path": policy_path, "policy_sha256": policy_sha,
        "operation_dir": operation_dir, "forbidden_prefixes": forbidden,
        "request_bytes": request_bytes, "request_sha256": request_sha, "held": held,
    }


def _native_argv(state: dict[str, Any], pending_path: Path) -> list[str]:
    argv = [str(state["runtime"]), "toolchain", "producer", "verify-recovery"]
    for prefix in state["forbidden_prefixes"]:
        argv.extend(("--forbidden-prefix", str(prefix)))
    argv.extend([
        "--directory", str(state["release_dir"]),
        "--release-id", state["release_id"],
        "--base-url", state["base_url"],
        "--inputs-sha256", state["inputs_sha256"],
        "--index-sha256", state["index_sha256"],
        "--selection", str(state["selection_path"]),
        "--selection-sha256", state["selection_sha256"],
        "--subject-manifest", str(state["subject_path"]),
        "--subject-manifest-sha256", state["subject_sha256"],
        "--qualification-evidence", str(state["qualification_path"]),
        "--qualification-sha256", state["qualification_sha256"],
        "--policy", str(state["policy_path"]),
        "--policy-sha256", state["policy_sha256"],
        "--recovery-request", str(pending_path),
        "--recovery-request-sha256", state["request_sha256"],
        "--format", "json",
    ])
    return argv


def _directory_identity(path: Path) -> tuple[int, int, int, int]:
    metadata = _HELPERS._directory(path, "operation directory", owned=True)
    return metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_mode


def _unlink_created_final(directory_fd: int, name: str,
                          identity: tuple[int, int, int, int]) -> None:
    try:
        metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError:
        return
    current = (metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_mode)
    if (current == identity and stat.S_ISREG(metadata.st_mode)
            and metadata.st_nlink == 1 and metadata.st_uid == os.geteuid()):
        try:
            os.unlink(name, dir_fd=directory_fd)
        except OSError:
            pass


def _write_final_request(path: Path, data: bytes, expected_sha: str, *,
                         held: dict[Path, dict[str, Any]], operation_dir: Path,
                         expected_directory_identity: tuple[int, int, int, int]) -> None:
    """Create the final request exclusively and remove only our inode on failure."""
    directory_fd = os.open(operation_dir, _HELPERS.ROOT_FLAGS)
    try:
        metadata = os.fstat(directory_fd)
        identity = (metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_mode)
        _require(identity == expected_directory_identity,
                 "operation directory identity changed before final request creation")
        descriptor = os.open(path.name, _HELPERS.CREATE_FLAGS, 0o600, dir_fd=directory_fd)
        try:
            created_metadata = os.fstat(descriptor)
            created_identity = (created_metadata.st_dev, created_metadata.st_ino,
                                created_metadata.st_uid, created_metadata.st_mode)
            _require(stat.S_ISREG(created_metadata.st_mode)
                     and created_metadata.st_nlink == 1
                     and created_metadata.st_uid == os.geteuid(),
                     "final recovery request is not an owned, singly linked regular file")
            os.fchmod(descriptor, 0o600)
            created_metadata = os.fstat(descriptor)
            created_identity = (created_metadata.st_dev, created_metadata.st_ino,
                                created_metadata.st_uid, created_metadata.st_mode)
            view = memoryview(data)
            while view:
                written = os.write(descriptor, view)
                _require(written > 0, "could not write final recovery request")
                view = view[written:]
            os.fsync(descriptor)
        except BaseException:
            os.close(descriptor)
            _unlink_created_final(directory_fd, path.name, created_identity)
            raise
        else:
            os.close(descriptor)
        try:
            measured, _raw, _fingerprint = _HELPERS._read_owned(
                path, MAX_OBSERVATION, "final recovery request", retain=False)
            _require(measured["sha256"] == expected_sha and measured["size"] == len(data),
                     "final recovery request differs from the exact natively verified bytes")
            _HELPERS._check_held(held)
            _require(_directory_identity(operation_dir) == expected_directory_identity,
                     "operation directory identity changed before success summary")
        except BaseException:
            _unlink_created_final(directory_fd, path.name, created_identity)
            raise
    finally:
        os.close(directory_fd)


def run(args: argparse.Namespace) -> dict[str, Any]:
    state = _preflight(args)
    operation_dir: Path = state["operation_dir"]
    try:
        os.mkdir(operation_dir, 0o700)
    except OSError as error:
        raise AdapterError("could not create the previously absent operation directory") from error
    directory_identity = _directory_identity(operation_dir)
    pending_path = operation_dir / ".recovery-request-v2.pending.json"
    final_path = operation_dir / "recovery-request-v2.json"
    _require(not os.path.lexists(pending_path) and not os.path.lexists(final_path),
             "fresh operation request outputs unexpectedly exist")
    _HELPERS._check_held(state["held"])
    _HELPERS._write_exclusive(pending_path, state["request_bytes"], "pending recovery request")
    pending_measurement, _pending_raw, pending_fingerprint = _HELPERS._read_owned(
        pending_path, MAX_OBSERVATION, "pending recovery request", retain=False)
    _require(pending_measurement["sha256"] == state["request_sha256"],
             "pending recovery request differs from the exact selected observation bytes")

    raw, _stderr = _HELPERS._run_child(
        operation_dir, "verify-recovery", _native_argv(state, pending_path),
        NATIVE_TIMEOUT_SECONDS, state["held"], cwd=operation_dir.parent)
    result = _result(raw, state=state,
                     expected_decision=(
                         "replay-compatibility" if args.operation == "compatibility-replay" else
                         {"repackage": {
                             "release_id": json.loads(state["request_bytes"])["handoff"]["release_id"],
                             "tag": json.loads(state["request_bytes"])["handoff"]["tag"],
                         }}))
    _HELPERS._check_held(state["held"])
    _HELPERS._stat_expected(pending_path, MAX_OBSERVATION, "pending recovery request",
                            pending_measurement, pending_fingerprint)
    _require(_directory_identity(operation_dir) == directory_identity,
             "operation directory identity changed during native verification")
    _require(not os.path.lexists(final_path),
             "final recovery request output unexpectedly exists")

    _write_final_request(final_path, state["request_bytes"], state["request_sha256"],
                         held=state["held"], operation_dir=operation_dir,
                         expected_directory_identity=directory_identity)
    return {
        "schema": "aros-toolchain-recovery-request-adapter-v2",
        "operation": "prepare-recovery-request",
        "assurance": "independent-observations-and-native-byte-consistency-only",
        "recovery_request": {"path": str(final_path), "sha256": state["request_sha256"]},
        "native_result": result,
        "scope": {
            "provider_run_attempt_authenticated": False,
            "tag_object_authenticated": False,
            "signature_verified": False,
            "original_owner_jobs_verified": False,
            "publication_authorized": False,
            "replay_or_repackage_executed": False,
        },
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", required=True)
    parser.add_argument("--runtime-sha256", required=True)
    parser.add_argument("--release-dir", required=True)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--inputs-sha256", required=True)
    parser.add_argument("--index-sha256", required=True)
    parser.add_argument("--selection", required=True)
    parser.add_argument("--selection-sha256", required=True)
    parser.add_argument("--subject-manifest", required=True)
    parser.add_argument("--subject-manifest-sha256", required=True)
    parser.add_argument("--qualification-evidence", required=True)
    parser.add_argument("--qualification-sha256", required=True)
    parser.add_argument("--policy", required=True)
    parser.add_argument("--policy-sha256", required=True)
    parser.add_argument("--observed-run", required=True)
    parser.add_argument("--observed-run-sha256", required=True)
    parser.add_argument("--observed-source-tag", required=True)
    parser.add_argument("--observed-source-tag-sha256", required=True)
    parser.add_argument("--observed-attestation", required=True)
    parser.add_argument("--observed-attestation-sha256", required=True)
    parser.add_argument("--operation", required=True,
                        choices=("packaging-recovery", "compatibility-replay"))
    parser.add_argument("--failed-stage", choices=sorted(FAILED_STAGES), required=True)
    parser.add_argument("--handoff")
    parser.add_argument("--handoff-sha256")
    parser.add_argument("--operation-dir", required=True)
    parser.add_argument("--forbidden-prefix", action="append", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        result = run(_parser().parse_args(argv))
    except (AdapterError, OSError, subprocess.SubprocessError, KeyError, TypeError) as error:
        print(f"V2 recovery request preparation failed: {error}", file=sys.stderr)
        return 1
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
