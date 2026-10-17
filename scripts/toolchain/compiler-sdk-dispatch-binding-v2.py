#!/usr/bin/env python3
"""Inactive post-dispatch payload codec; never dispatches or authenticates.

A future trusted dispatcher must capture the HTTP 200 response to its ONE
dispatch with return_run_details=true and independently read back that numeric
run before signing this exact payload. A 204, timeout or uncertain response
cannot select a run and must never cause a mutation retry. This module does
not send that request, observe provider state, sign, retain or activate anything.

The payload joins one confirmed-response run selector to the exact sole claim
asset, claim signature bytes, original start and dispatcher. Native consumption
must independently authenticate both signatures, original successful owners,
candidate/runtime/provider state and its own actual runner event/context. The
closed consumer codec checks those supplied joins, not their authenticity.
In particular callers must not derive actual_native_context from this payload.
Local fixtures cannot prove exclusive consumption or START-A5/A7.
"""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path


SPEC = importlib.util.spec_from_file_location(
    "dispatch_binding_claim", Path(__file__).with_name("compiler-sdk-dispatch-claim-v2.py"))
CLAIM = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CLAIM)
START = CLAIM.START
BINDING_NAME = "compiler-sdk-dispatch-binding-v2.json"
SCHEMA = "aros-toolchains-dispatch-binding-v2"
ASSURANCE = "dispatch-run-binding-payload-only-not-native-authority"
MAX_RESPONSE = 4096


def _run_urls(run_id: int) -> dict:
    repository = START.ADMISSION.REPOSITORY
    return {
        "workflow_run_id": run_id,
        "run_url": f"https://api.github.com/repos/{repository}/actions/runs/{run_id}",
        "html_url": f"https://github.com/{repository}/actions/runs/{run_id}",
    }


def confirmed_run(status: int, raw: bytes) -> dict:
    """Parse one closed confirmed response; this does not observe that run.

    An empty legacy response supplies no selector. A caller must stop rather
    than searching recent runs, retargeting, or retrying the dispatch.
    """
    START.require(type(status) is int and status == 200,
                  "dispatch is not confirmed HTTP 200; no mutation retry")
    START.require(type(raw) is bytes and 0 < len(raw) <= MAX_RESPONSE,
                  "dispatch response is not bounded bytes; no mutation retry")
    value = START.exact(START.ADMISSION.parse_json(
        raw, "confirmed dispatch response", maximum=MAX_RESPONSE),
        {"workflow_run_id", "run_url", "html_url"}, "confirmed dispatch response")
    run_id = START.positive(value["workflow_run_id"], "confirmed dispatch run ID")
    # Match the origin context's exact-integer bound, not a bool, numeric
    # string, fractional JSON value or a rounded provider identifier.
    START.ORIGIN.positive(run_id)
    START.require(value == _run_urls(run_id),
                  "confirmed dispatch run URLs differ; no mutation retry")
    return value


def _binding_value(claim_raw: bytes, record_bytes: bytes, start_bundle_bytes: bytes, *,
                   source_context: dict, dispatcher_context: dict, dispatcher_job: dict,
                   claim_asset: dict, expected_claim_bundle_sha256: str,
                   actual_native_context: dict, actual_native_event: str) -> dict:
    claim = CLAIM.validate_claim(
        claim_raw, record_bytes, start_bundle_bytes,
        source_context=source_context, dispatcher_context=dispatcher_context,
        dispatcher_job=dispatcher_job, dispatcher_event="workflow_run",
        trigger_context=source_context)
    asset = START.exact(claim_asset, {"id", "name", "size", "sha256"}, "binding claim asset")
    START.positive(asset["id"], "binding claim asset ID")
    START.require(asset["name"] == CLAIM.CLAIM_NAME
                  and type(asset["size"]) is int and asset["size"] == len(claim_raw)
                  and asset["sha256"] == hashlib.sha256(claim_raw).hexdigest(),
                  "binding claim asset differs from the exact selected bytes")
    bundle_pin = START.digest(expected_claim_bundle_sha256, "binding claim signature")
    native = START.ORIGIN.validate_context(actual_native_context)
    source = claim["start"]["context"]
    dispatcher = claim["dispatcher"]["context"]
    expected = {
        "repository": source["repository"],
        "repository_id": source["repository_id"],
        "producer_commit": claim["native"]["producer_commit"],
        "source_ref": claim["native"]["source_ref"],
        "workflow": CLAIM.NATIVE_WORKFLOW,
        "run_id": native["run_id"],
        "run_attempt": 1,
    }
    START.require(actual_native_event == "workflow_dispatch" and native == expected
                  and native["run_id"] not in (source["run_id"], dispatcher["run_id"]),
                  "binding native event or independently selected original context differs")
    return {
        "schema": SCHEMA,
        "assurance": ASSURANCE,
        "name": BINDING_NAME,
        "start": claim["start"],
        "dispatcher": claim["dispatcher"],
        "candidate": {"tag": claim["candidate"]["tag"], "draft": claim["candidate"]["draft"]},
        "claim": asset,
        "claim_bundle_sha256": bundle_pin,
        "native": {"context": native, "event": "workflow_dispatch",
                   "response": _run_urls(native["run_id"])},
    }


def _encode(value: dict) -> bytes:
    raw = (START.ADMISSION.canonical_json(value) + "\n").encode("ascii")
    START.require(0 < len(raw) <= START.MAX_RECORD, "encoded dispatch binding exceeds its metadata limit")
    return raw


def binding_bytes(claim_raw: bytes, record_bytes: bytes, start_bundle_bytes: bytes, *,
                  source_context: dict, dispatcher_context: dict, dispatcher_job: dict,
                  claim_asset: dict, expected_claim_bundle_sha256: str,
                  response_status: int, response_body: bytes) -> bytes:
    """Construct only a structural signing subject after a confirmed response.

    The caller must authenticate the selected claim/start and numeric provider
    readbacks first. Merely being able to construct this payload gives no
    authority; no response or claimed field authenticates itself.
    """
    response = confirmed_run(response_status, response_body)
    # Validate the original claim before deriving any field from it.
    claim = CLAIM.validate_claim(
        claim_raw, record_bytes, start_bundle_bytes,
        source_context=source_context, dispatcher_context=dispatcher_context,
        dispatcher_job=dispatcher_job, dispatcher_event="workflow_run",
        trigger_context=source_context)
    source = claim["start"]["context"]
    native = {
        "repository": source["repository"],
        "repository_id": source["repository_id"],
        "producer_commit": claim["native"]["producer_commit"],
        "source_ref": claim["native"]["source_ref"],
        "workflow": CLAIM.NATIVE_WORKFLOW,
        "run_id": response["workflow_run_id"],
        "run_attempt": 1,
    }
    return _encode(_binding_value(
        claim_raw, record_bytes, start_bundle_bytes,
        source_context=source_context, dispatcher_context=dispatcher_context,
        dispatcher_job=dispatcher_job, claim_asset=claim_asset,
        expected_claim_bundle_sha256=expected_claim_bundle_sha256,
        actual_native_context=native, actual_native_event="workflow_dispatch"))


def validate_binding(raw: bytes, claim_raw: bytes, record_bytes: bytes, start_bundle_bytes: bytes, *,
                     source_context: dict, dispatcher_context: dict, dispatcher_job: dict,
                     claim_asset: dict, expected_claim_bundle_sha256: str,
                     actual_native_context: dict, actual_native_event: str) -> dict:
    """Match canonical bytes to the native caller's INDEPENDENT actual context.

    Signature/original-owner/provider checks remain mandatory elsewhere. A
    copied binding from another native run cannot pass this structural join.
    """
    START.require(type(raw) is bytes and 0 < len(raw) <= START.MAX_RECORD,
                  "dispatch binding is not bounded bytes")
    value = _binding_value(
        claim_raw, record_bytes, start_bundle_bytes,
        source_context=source_context, dispatcher_context=dispatcher_context,
        dispatcher_job=dispatcher_job, claim_asset=claim_asset,
        expected_claim_bundle_sha256=expected_claim_bundle_sha256,
        actual_native_context=actual_native_context, actual_native_event=actual_native_event)
    START.require(raw == _encode(value),
                  "dispatch binding differs from the independent native run, claim or owners")
    return value
