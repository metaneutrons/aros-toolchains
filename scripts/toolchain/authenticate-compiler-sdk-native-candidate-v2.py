#!/usr/bin/env python3
"""Inactive read-only authentication of one independently selected candidate.

Compose the original successful dispatcher's claim-signature gate with the
closed post-claim original-start signature/runtime/sole-asset reader. Neither
structural claim bytes nor caller-supplied result dictionaries stand in for
either verifier. All four input byte pins and provider selectors are trusted
caller selections, not fields discovered from an unauthenticated payload.

This is candidate authentication only, not actual native-run identity, signed
dispatch-run binding, durable consumption, fan-out or publication authority.
No workflow invokes it. Provider/signature fixtures are not live qualification;
token custody and quiescent local staging remain caller premises.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path


SPEC = importlib.util.spec_from_file_location(
    "native_candidate_claimed_start",
    Path(__file__).with_name("verify-claimed-compiler-sdk-start-v2.py"))
POST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POST)
CLAIM = POST.CLAIM
START = POST.START
SCHEMA = "aros-toolchains-native-candidate-authentication-v2"
ASSURANCE = "authenticated-candidate-only-not-native-dispatch-or-qualification"
LIMITATIONS = [
    "does not authenticate the actual native workflow_dispatch event or OIDC identity",
    "does not establish a signed native dispatch-run binding",
    "does not provide durable exclusive claim consumption",
    "does not authorize dispatch or qualify a release",
]


def authenticate_candidate(
    record_path: Path, start_bundle_path: Path, claim_path: Path,
    claim_bundle_path: Path, source_context: dict, dispatcher_context: dict,
    dispatcher_job: dict, *, expected_record_sha256: str,
    expected_start_bundle_sha256: str, expected_claim_sha256: str,
    expected_claim_bundle_sha256: str, expected_claim_asset_id: int,
    runtime_lock: Path, runtime_directory: Path, runtime_interface: Path,
    runtime_host: str,
) -> dict:
    """Authenticate both original signatures and the exact selected candidate.

    A native caller must still authenticate its own actual event/OIDC/provider
    identity and signed run binding, then establish exclusive consumption.
    Successful completion here is not authorization for any native work.
    """
    START.require(os.environ.get("GH_HOST") == "github.com"
                  and bool(os.environ.get("GH_TOKEN", "").strip()),
                  "native candidate requires the fixed-host job token")
    START.positive(expected_claim_asset_id, "independently selected claim asset ID")
    START.ORIGIN.positive(expected_claim_asset_id)
    START.require(claim_path.name == CLAIM.CLAIM_NAME,
                  "selected claim subject name differs")
    selections = (
        (record_path, START.MAX_RECORD, expected_record_sha256, "selected start record"),
        (start_bundle_path, START.MAX_BUNDLE, expected_start_bundle_sha256,
         "selected start signature"),
        (claim_path, START.MAX_RECORD, expected_claim_sha256, "selected dispatcher claim"),
        (claim_bundle_path, START.MAX_BUNDLE, expected_claim_bundle_sha256,
         "selected dispatcher signature"),
    )
    separate_paths = [item[0].absolute() for item in selections] + [
        runtime_lock.absolute(),
        (runtime_directory / ".aros-tools-runtime-receipt-v1.json").absolute(),
        runtime_interface.absolute(),
    ]
    START.require(len(set(separate_paths)) == len(separate_paths),
                  "captured metadata, signatures and runtime evidence must use separate paths")
    captured = []
    for path, maximum, pin, label in selections:
        START.digest(pin, label)
        raw = START.ADMISSION.read_regular_file(path, label, maximum)
        START.require(raw and hashlib.sha256(raw).hexdigest() == pin,
                      "candidate input differs from its independent byte selection")
        captured.append(raw)
    record_raw, start_bundle, claim_raw, _claim_bundle = captured
    selected_start = START.validate_start(START.ADMISSION.parse_json(
        record_raw, "selected start record", maximum=START.MAX_RECORD), source_context)
    START.require(record_raw == (START.ADMISSION.canonical_json(selected_start) + "\n").encode("ascii"),
                  "selected start record is not canonical JSON")

    def selected_claim() -> dict:
        return CLAIM.validate_claim(
            claim_raw, record_raw, start_bundle, source_context=source_context,
            dispatcher_context=dispatcher_context, dispatcher_job=dispatcher_job,
            dispatcher_event="workflow_run", trigger_context=source_context)

    expected_claim = selected_claim()

    def verify_dispatcher() -> dict:
        verified = CLAIM.verify_dispatcher_claim_signature(
            claim_path, claim_bundle_path, record_bytes=record_raw,
            start_bundle_bytes=start_bundle, source_context=source_context,
            dispatcher_context=dispatcher_context, dispatcher_job=dispatcher_job,
            expected_claim_sha256=expected_claim_sha256,
            expected_signature_sha256=expected_claim_bundle_sha256)
        START.require(verified == expected_claim,
                      "dispatcher signature verification selected another claim")
        return verified

    verified_claim = verify_dispatcher()
    authenticated_start = POST.verify_claimed_start(
        record_path, start_bundle_path, source_context,
        dispatcher_context=dispatcher_context, dispatcher_job=dispatcher_job,
        claim_path=claim_path, claim_asset_id=expected_claim_asset_id,
        expected_claim_sha256=expected_claim_sha256,
        expected_record_sha256=expected_record_sha256,
        expected_bundle_sha256=expected_start_bundle_sha256,
        runtime_lock=runtime_lock, runtime_directory=runtime_directory,
        runtime_interface=runtime_interface, runtime_host=runtime_host)
    START.require(authenticated_start == selected_start,
                  "start authentication selected another captured record")
    # Reobserve the completed original dispatcher and its owning job after
    # the intervening start/runtime/provider checks, without dispatch retries.
    START.require(verify_dispatcher() == verified_claim,
                  "dispatcher claim changed after start authentication")
    for (path, maximum, _, label), raw in zip(selections, captured, strict=True):
        START.require(START.ADMISSION.read_regular_file(path, label, maximum) == raw,
                      "candidate start, claim or signature changed during authentication")
    START.require(selected_claim() == expected_claim,
                  "candidate source or dispatcher selections changed during authentication")
    return {
        "schema": SCHEMA,
        "assurance": ASSURANCE,
        "authenticated_candidate_only": {
            "tag_name": selected_start["tag"]["name"],
            "commit": selected_start["tag"]["commit"],
            "draft_id": selected_start["draft"]["id"],
            "claim_asset": {"id": expected_claim_asset_id, "name": CLAIM.CLAIM_NAME,
                            "size": len(claim_raw), "sha256": expected_claim_sha256},
        },
        "limitations": list(LIMITATIONS),
    }
