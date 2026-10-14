#!/usr/bin/env python3
"""Inactive closed claim-payload codec; no upload or dispatch authority.

The future dispatcher must first authenticate the signed start, its own provider
context/job, and runtime evidence. It must then require a confirmed HTTP 201 and
exact numeric asset readback for this fixed-name payload before dispatching.
This codec alone proves neither authenticity nor exclusive consumption.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile


SPEC = importlib.util.spec_from_file_location(
    "claim_start", Path(__file__).with_name("compiler-sdk-release-start-v2.py"))
START = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(START)
CLAIM_NAME = "compiler-sdk-dispatch-claim-v2.json"
SCHEMA = "aros-toolchains-dispatch-claim-v2"
ASSURANCE = "claim-payload-only-not-dispatch-evidence"
WORKFLOW = ".github/workflows/compiler-sdk-release-dispatch.yml"
JOB = "Dispatch compiler and SDK qualification"
NATIVE_WORKFLOW = ".github/workflows/toolchain-release.yml"


def claim_bytes(record_bytes: bytes, bundle_bytes: bytes, *, source_context: dict,
                dispatcher_context: dict, dispatcher_job: dict, dispatcher_event: str,
                trigger_context: dict) -> bytes:
    """Encode structural joins; independent provider/crypto checks are required."""
    START.require(type(record_bytes) is bytes and 0 < len(record_bytes) <= START.MAX_RECORD,
                  "claim requires bounded original start bytes")
    START.require(type(bundle_bytes) is bytes and 0 < len(bundle_bytes) <= START.MAX_BUNDLE,
                  "claim requires bounded original signature bytes")
    record = START.validate_start(START.ADMISSION.parse_json(record_bytes, "claim start record"),
                                  source_context)
    dispatcher = START.ORIGIN.validate_context(dispatcher_context)
    source = record["context"]
    trigger = START.ORIGIN.validate_context(trigger_context)
    START.require(dispatcher_event == "workflow_run" and trigger == source,
                  "claim dispatcher event or triggering start context differs")
    START.require(dispatcher["repository"] == source["repository"]
                  and dispatcher["repository_id"] == source["repository_id"]
                  and dispatcher["source_ref"] == START.ADMISSION.MAIN_REF
                  and dispatcher["workflow"] == WORKFLOW and dispatcher["run_attempt"] == 1
                  and dispatcher["run_id"] != source["run_id"],
                  "claim dispatcher is not a distinct original protected-main workflow")
    job = START.exact(dispatcher_job, {"id", "check_run_id", "name"}, "claim dispatcher job")
    START.positive(job["id"], "claim dispatcher job id")
    START.positive(job["check_run_id"], "claim dispatcher check id")
    START.require(job["name"] == JOB and job["id"] != record["job"]["id"]
                  and job["check_run_id"] != record["job"]["check_run_id"],
                  "claim dispatcher job differs or reuses the start owner")
    value = {
        "schema": SCHEMA,
        "assurance": ASSURANCE,
        "name": CLAIM_NAME,
        "start": {
            "context": source,
            "job": record["job"],
            "record_sha256": hashlib.sha256(record_bytes).hexdigest(),
            "bundle_sha256": hashlib.sha256(bundle_bytes).hexdigest(),
        },
        "candidate": {
            "tag": record["tag"],
            "draft": record["draft"],
            "inputs": record["admission"]["inputs"],
            "runtime": record["runtime"],
        },
        "dispatcher": {"context": dispatcher, "event": dispatcher_event, "trigger_context": trigger,
                       "job": job},
        "native": {"workflow": NATIVE_WORKFLOW, "event": "workflow_dispatch",
                   "source_ref": f'refs/tags/{record["tag"]["name"]}',
                   "producer_commit": record["tag"]["commit"]},
    }
    encoded = (START.ADMISSION.canonical_json(value) + "\n").encode("ascii")
    START.require(len(encoded) <= START.MAX_RECORD, "encoded claim exceeds its metadata limit")
    return encoded


def validate_claim(raw: bytes, record_bytes: bytes, bundle_bytes: bytes, *, source_context: dict,
                   dispatcher_context: dict, dispatcher_job: dict, dispatcher_event: str,
                   trigger_context: dict) -> dict:
    """Require exact canonical bytes, independently selected joins, no extras."""
    START.require(type(raw) is bytes and 0 < len(raw) <= START.MAX_RECORD,
                  "claim payload is not bounded bytes")
    expected = claim_bytes(record_bytes, bundle_bytes, source_context=source_context,
                           dispatcher_context=dispatcher_context, dispatcher_job=dispatcher_job,
                           dispatcher_event=dispatcher_event, trigger_context=trigger_context)
    START.require(raw == expected, "claim payload differs from the exact selected start and dispatcher")
    return START.ADMISSION.parse_json(raw, "dispatch claim")


def verify_dispatcher_claim_signature(claim_path: Path, signature_path: Path, *,
                                      record_bytes: bytes, start_bundle_bytes: bytes,
                                      source_context: dict, dispatcher_context: dict,
                                      dispatcher_job: dict, expected_claim_sha256: str,
                                      expected_signature_sha256: str) -> dict:
    """Read-only original-dispatcher signature gate, not native authorization.

    The caller must independently select the original contexts and byte pins,
    authenticate the signed start, retrieve the sole numeric draft asset, and
    validate the actual native event. This gate never trusts predicate metadata
    as provider identity and never uploads, dispatches or publishes anything.
    An original dispatcher must attest these exact claim bytes before dispatch.
    No production workflow currently signs or invokes this gate.
    """
    START.require(os.environ.get("GH_HOST") == "github.com"
                  and bool(os.environ.get("GH_TOKEN")),
                  "dispatcher claim verification requires the fixed-host job token")
    START.require(claim_path.name == CLAIM_NAME
                  and claim_path.absolute() != signature_path.absolute(),
                  "dispatcher claim subject or separate signature path differs")
    raw = START.ADMISSION.read_regular_file(claim_path, "selected dispatch claim", START.MAX_RECORD)
    signature = START.ADMISSION.read_regular_file(
        signature_path, "selected dispatcher signature", START.MAX_BUNDLE)
    START.require(hashlib.sha256(raw).hexdigest()
                  == START.digest(expected_claim_sha256, "selected dispatch claim")
                  and hashlib.sha256(signature).hexdigest()
                  == START.digest(expected_signature_sha256, "selected dispatcher signature"),
                  "dispatcher claim or signature differs from selected bytes")
    claim = validate_claim(
        raw, record_bytes, start_bundle_bytes, source_context=source_context,
        dispatcher_context=dispatcher_context, dispatcher_job=dispatcher_job,
        dispatcher_event="workflow_run", trigger_context=source_context)
    context = claim["dispatcher"]["context"]
    job = claim["dispatcher"]["job"]

    def observe_owner() -> None:
        # The origin reader verifies the attempt-specific repository, workflow,
        # main ref, source commit and event. The latest run rejects a rerun even
        # when its retained first attempt had previously succeeded.
        START.observe_start_run(context)
        selected = START.ORIGIN.select_source_job(
            START.ORIGIN.jobs_for(context), context, {"id": job["id"], "name": JOB})
        START.require(selected == job, "dispatcher claim owning job differs")

    observe_owner()
    with tempfile.TemporaryDirectory(prefix="aros-dispatch-signature-") as directory:
        root = Path(directory)
        root.chmod(0o700)
        subject = root / CLAIM_NAME
        bundle = root / "signature.json"
        for path, content in ((subject, raw), (bundle, signature)):
            with path.open("xb") as handle:
                path.chmod(0o600)
                handle.write(content)
        verified = START.bounded_gh([
            "attestation", "verify", str(subject), "--bundle", str(bundle),
            "--hostname", "github.com", "--repo", context["repository"],
            "--signer-workflow", f'{context["repository"]}/{WORKFLOW}',
            "--signer-digest", context["producer_commit"],
            "--source-digest", context["producer_commit"],
            "--source-ref", START.ADMISSION.MAIN_REF,
            "--deny-self-hosted-runners", "--format", "json",
        ], "dispatcher claim signature authentication")
    START.require(type(verified) is list and len(verified) == 1,
                  "dispatcher claim requires exactly one verified signature")
    result = verified[0]["verificationResult"]
    invocation = (f'https://github.com/{context["repository"]}/actions/runs/'
                  f'{context["run_id"]}/attempts/1')
    START.require(result["signature"]["certificate"]["runInvocationURI"] == invocation,
                  "dispatcher claim signature belongs to another original attempt")
    START.require(result["statement"]["subject"] == [{"name": CLAIM_NAME,
                  "digest": {"sha256": hashlib.sha256(raw).hexdigest()}}],
                  "dispatcher claim signature subject differs")
    observe_owner()
    START.require(START.ADMISSION.read_regular_file(
        claim_path, "selected dispatch claim", START.MAX_RECORD) == raw
        and START.ADMISSION.read_regular_file(
            signature_path, "selected dispatcher signature", START.MAX_BUNDLE) == signature,
        "dispatcher claim or signature changed during verification")
    return claim
