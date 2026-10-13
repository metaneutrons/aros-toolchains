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
from pathlib import Path


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
