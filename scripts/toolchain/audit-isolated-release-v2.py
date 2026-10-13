#!/usr/bin/env python3
"""Audit an isolated family-v2 release against an existing qualification.

This adapter verifies held local release bytes, the selected signed provenance,
and an independently supplied qualification document. It never records or
publishes qualification evidence. Caller-supplied source observations are not
independently authenticated here beyond the external signed provenance check.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
RECORDER_PATH = HERE / "record-complete-qualification-v2.py"
SPEC = importlib.util.spec_from_file_location("record_complete_qualification_v2", RECORDER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load the bounded V2 qualification helpers")
RECORDER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RECORDER
SPEC.loader.exec_module(RECORDER)

AdapterError = RECORDER.AdapterError
MAX_METADATA = RECORDER.MAX_METADATA
MAX_ARCHIVE = RECORDER.MAX_ARCHIVE
PROVENANCE_TIMEOUT_SECONDS = RECORDER.PROVENANCE_TIMEOUT_SECONDS
NATIVE_TIMEOUT_SECONDS = RECORDER.NATIVE_TIMEOUT_SECONDS
VERIFIER_COMMAND = RECORDER.VERIFIER_COMMAND


def _state(args: argparse.Namespace) -> dict[str, Any]:
    """Select the complete V2 candidate and hold the caller's original claim."""
    state = RECORDER._preflight(args)
    _hold_release_inventory(state)
    qualification_path = RECORDER._normalized_path(
        args.qualification_evidence, "original qualification evidence"
    )
    qualification_sha = RECORDER._digest(
        args.qualification_sha256, "original qualification SHA-256"
    )
    now = int(RECORDER._epoch(args.now, "policy current time"))
    RECORDER._require(
        state["created_at"] <= now < state["expires_at"],
        "policy current time is outside the original qualification validity interval",
    )
    _require_operation_separation(state, qualification_path, args.operation_dir)

    measurement, raw, fingerprint = RECORDER._read_owned(
        qualification_path, MAX_METADATA, "original qualification evidence", retain=True
    )
    RECORDER._require(
        measurement["sha256"] == qualification_sha,
        "original qualification bytes differ from their independent SHA-256 selector",
    )
    evidence = RECORDER._json(raw, "original qualification evidence")
    RECORDER._check_recorded_evidence(evidence, state)
    RECORDER._require(
        qualification_path not in state["held"],
        "original qualification evidence aliases another selected evidence file",
    )
    state["held"][qualification_path] = {
        "limit": MAX_METADATA,
        "label": "original qualification evidence",
        "measurement": measurement,
        "fingerprint": fingerprint,
    }
    state["qualification_path"] = qualification_path
    state["qualification_sha256"] = qualification_sha
    state["qualification_measurement"] = measurement
    state["qualification_fingerprint"] = fingerprint
    state["now"] = now
    RECORDER._check_held(state["held"])
    return state


def _hold_release_inventory(state: dict[str, Any]) -> None:
    """Hold every physical final-release file selected by the native summary."""
    release_dir = state["release_dir"]
    inventory = state["summary"]["release_inventory"]
    expected_names = set(inventory) | {"SHA256SUMS", "toolchain-provenance.sigstore.json"}
    try:
        actual_names = set(os.listdir(release_dir))
    except OSError as error:
        raise AdapterError("selected release directory could not be enumerated") from error
    RECORDER._require(
        actual_names == expected_names,
        "release directory has missing or extra files outside the closed V2 inventory",
    )
    state["release_inventory_names"] = expected_names
    for name, expected in inventory.items():
        path = release_dir / name
        measurement, _raw, fingerprint = RECORDER._read_owned(
            path, MAX_ARCHIVE, f"selected release file {name}", retain=False
        )
        RECORDER._require(
            measurement == expected,
            f"release file {name} differs from its closed candidate-summary measurement",
        )
        prior = state["held"].get(path)
        RECORDER._require(
            prior is None or (
                prior["measurement"] == measurement and prior["fingerprint"] == fingerprint
            ),
            f"release file {name} changed between candidate preflight and inventory hold",
        )
        state["held"][path] = {
            "limit": MAX_ARCHIVE,
            "label": f"selected release file {name}",
            "measurement": measurement,
            "fingerprint": fingerprint,
        }


def _check_release_inventory(state: dict[str, Any]) -> None:
    try:
        actual_names = set(os.listdir(state["release_dir"]))
    except OSError as error:
        raise AdapterError("selected release directory changed or became unavailable") from error
    RECORDER._require(
        actual_names == state["release_inventory_names"],
        "selected release directory gained or lost files during the audit",
    )
    RECORDER._check_held(state["held"])


def _require_operation_separation(state: dict[str, Any], qualification_path: Path,
                                  operation_raw: str) -> None:
    operation_dir = RECORDER._normalized_path(operation_raw, "operation directory")
    qualification_parent = qualification_path.parent
    RECORDER._directory(qualification_parent, "original qualification parent", owned=True)
    protected = [
        state["release_dir"], state["runtime"], state["selection_path"],
        state["subject_path"], state["summary_path"], qualification_path,
        qualification_parent, *state["held"],
        *(path.parent for path in state["held"]),
        state["runtime"].parent, state["selection_path"].parent,
        state["subject_path"].parent, state["summary_path"].parent,
        *state["forbidden_prefixes"],
    ]
    for path in protected:
        RECORDER._require(
            not RECORDER._path_overlaps(operation_dir, path),
            "operation directory overlaps selected release, evidence, or a protected root",
        )
    RECORDER._require(
        not os.path.lexists(operation_dir),
        "operation directory must be absent; refusing to adopt or overwrite it",
    )


def _recheck_original(state: dict[str, Any]) -> None:
    _check_operation_directory(state)
    _check_release_inventory(state)
    measurement, raw, fingerprint = RECORDER._read_owned(
        state["qualification_path"], MAX_METADATA,
        "original qualification evidence", retain=True,
    )
    RECORDER._require(
        measurement == state["qualification_measurement"]
        and fingerprint == state["qualification_fingerprint"],
        "original qualification changed at the final audit boundary",
    )
    RECORDER._check_recorded_evidence(
        RECORDER._json(raw, "original qualification evidence"), state
    )


def _check_operation_directory(state: dict[str, Any]) -> None:
    metadata = RECORDER._directory(state["operation_dir"], "operation directory", owned=True)
    identity = (metadata.st_dev, metadata.st_ino, metadata.st_uid)
    RECORDER._require(
        identity == state["operation_identity"],
        "operation directory was replaced during the audit",
    )


def run(args: argparse.Namespace) -> dict[str, Any]:
    state = _state(args)
    operation_dir = RECORDER._normalized_path(args.operation_dir, "operation directory")
    os.mkdir(operation_dir, 0o700)
    operation_metadata = RECORDER._directory(
        operation_dir, "new operation directory", owned=True
    )
    state["operation_dir"] = operation_dir
    state["operation_identity"] = (
        operation_metadata.st_dev, operation_metadata.st_ino, operation_metadata.st_uid
    )

    verification_path = operation_dir / "external-provenance-verification.json"
    verification_command = [
        *VERIFIER_COMMAND,
        "--subject-manifest", str(state["subject_path"]),
        "--subject-manifest-sha256", state["subject_sha256"],
        "--subject-dir", str(state["release_dir"]),
        "--bundle", str(state["bundle_path"]),
        "--repository", args.repository,
        "--signer-workflow", f"{args.repository}/{args.workflow}",
        "--source-digest", args.source_tag_commit,
        "--source-ref", f"refs/tags/{args.source_tag}",
        "--run-id", args.run_id,
        "--run-attempt", args.run_attempt,
        "--output", str(verification_path),
    ]
    RECORDER._run_child(
        operation_dir, "provenance-verifier", verification_command,
        PROVENANCE_TIMEOUT_SECONDS, state["held"], cwd=HERE.parent.parent,
    )
    _check_operation_directory(state)
    verification_measurement, verification_raw, verification_fingerprint = RECORDER._read_owned(
        verification_path, MAX_METADATA, "external verifier result", retain=True
    )
    verified_attestations = RECORDER._json_array(
        verification_raw or b"", "external verifier result"
    )
    RECORDER._require(bool(verified_attestations), "external verifier returned no verified attestations")
    state["held"][verification_path] = {
        "limit": MAX_METADATA,
        "label": "external verifier result",
        "measurement": verification_measurement,
        "fingerprint": verification_fingerprint,
    }
    RECORDER._check_held(state["held"])
    _check_release_inventory(state)

    policy_path = operation_dir / "evidence-policy.json"
    _check_operation_directory(state)
    policy = {
        "source_repository": state["source_run"]["repository"],
        "source_workflow": state["source_run"]["workflow"],
        "signer_repository": state["attestation_repository"],
        "signer_workflow": state["attestation_workflow"],
        "signer": state["attestation_signer"],
        "now": state["now"],
    }
    policy_bytes = (json.dumps(policy, sort_keys=True, separators=(",", ":")) + "\n").encode()
    RECORDER._write_exclusive(policy_path, policy_bytes, "V2 evidence policy")
    policy_measurement, _policy_raw, policy_fingerprint = RECORDER._read_owned(
        policy_path, MAX_METADATA, "V2 evidence policy", retain=False
    )
    state["held"][policy_path] = {
        "limit": MAX_METADATA,
        "label": "V2 evidence policy",
        "measurement": policy_measurement,
        "fingerprint": policy_fingerprint,
    }

    _check_operation_directory(state)
    verify_command = RECORDER._verify_argv(
        state, state["qualification_path"], state["qualification_sha256"],
        policy_path, policy_measurement["sha256"],
    )
    verify_raw, _verify_stderr = RECORDER._run_child(
        operation_dir, "native-verify", verify_command, NATIVE_TIMEOUT_SECONDS,
        state["held"], cwd=HERE.parent.parent,
    )
    _check_operation_directory(state)
    native_result = RECORDER._parse_result(verify_raw, "native verify-qualification")
    RECORDER._check_readback_result(
        native_result, state, operation="verify-qualification",
        evidence_sha=state["qualification_sha256"],
        policy_sha=policy_measurement["sha256"],
    )
    _recheck_original(state)

    summary = {
        "schema": "aros-toolchain-isolated-release-audit-v2",
        "operation": "audit-isolated-release-v2",
        "assurance": "external-provenance-and-original-qualification-native-byte-consistency-only",
        "original_qualification": {
            "path": str(state["qualification_path"]),
            "sha256": state["qualification_sha256"],
        },
        "evidence_policy": {
            "path": str(policy_path), "sha256": policy_measurement["sha256"],
            "now": state["now"],
        },
        "external_verifier_result": {
            "path": str(verification_path), "sha256": verification_measurement["sha256"],
            "bundle_sha256": state["bundle_sha256"],
        },
        "source_observation": {
            "repository": args.repository, "workflow": args.workflow,
            "run_id": state["source_run"]["run_id"],
            "run_attempt": state["source_run"]["run_attempt"],
            "tag": args.source_tag, "tag_object": args.source_tag_object,
            "peeled_commit": args.source_tag_commit,
        },
        "counts": {
            "lane_count": state["lane_count"], "build_count": state["lane_count"] * 2,
            "sdk_count": state["sdk_count"],
            "sdk_generation_count": state["generation_count"],
        },
        # Keep detailed row values from the hash-selected native CLI result.
        "native_readback": native_result,
        "scope": {
            "provider_run_attempt_verified_by_external_attestation": True,
            "tag_object_independently_authenticated": False,
            "original_owner_jobs_verified_by_this_adapter": False,
            "runtime_publication_verified_by_this_adapter": False,
            "qualification_recorded_by_this_adapter": False,
            "release_download_or_provider_state_verified": False,
            "publication": False,
        },
    }
    summary_bytes = (json.dumps(summary, sort_keys=True, separators=(",", ":")) + "\n").encode()
    RECORDER._require(len(summary_bytes) <= MAX_METADATA,
                      "isolated release audit summary exceeds its metadata limit")
    _recheck_original(state)
    return summary


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", required=True)
    parser.add_argument("--runtime-sha256", required=True)
    parser.add_argument("--release-dir", required=True)
    parser.add_argument("--inputs-sha256", required=True)
    parser.add_argument("--index-sha256", required=True)
    parser.add_argument("--selection", required=True)
    parser.add_argument("--selection-sha256", required=True)
    parser.add_argument("--subject-manifest", required=True)
    parser.add_argument("--subject-manifest-sha256", required=True)
    parser.add_argument("--candidate-summary", required=True)
    parser.add_argument("--candidate-summary-sha256", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--workflow", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    parser.add_argument("--source-tag", required=True)
    parser.add_argument("--source-tag-object", required=True)
    parser.add_argument("--source-tag-commit", required=True)
    parser.add_argument("--created-at", required=True)
    parser.add_argument("--expires-at", required=True)
    parser.add_argument("--qualification-evidence", required=True)
    parser.add_argument("--qualification-sha256", required=True)
    parser.add_argument("--now", required=True)
    parser.add_argument("--operation-dir", required=True)
    parser.add_argument("--forbidden-prefix", action="append", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        result = run(_parser().parse_args(argv))
    except (AdapterError, OSError, subprocess.SubprocessError, KeyError, TypeError) as error:
        print(f"isolated V2 release audit failed: {error}", file=sys.stderr)
        return 1
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
