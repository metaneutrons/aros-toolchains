#!/usr/bin/env python3
"""Inactive authenticated-start to claim-upload boundary; never dispatches.

The caller must first materialize the authentic published runtime in private,
quiescent staging. This component then binds its exact runtime evidence to the
signed start, authenticates the executing dispatcher and its causal edge, and
uploads only a claim derived from the exact authenticated record/bundle bytes.
No workflow calls it; real provider qualification and native release gates
remain prerequisites. It grants no native dispatch or publication authority.
"""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path


SPEC = importlib.util.spec_from_file_location(
    "authenticated_claim_dispatcher", Path(__file__).with_name("compiler-sdk-dispatcher-auth-v2.py"))
AUTH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUTH)
START = AUTH.START
UPLOAD = AUTH.UPLOAD
CLAIM = AUTH.CLAIM


def authenticate_and_upload(record_path: Path, bundle_path: Path, source_context: dict, *,
                            runtime_lock: Path, runtime_directory: Path,
                            runtime_interface: Path, runtime_host: str) -> dict:
    """One upload after original identity, signed bytes and runtime joins pass."""
    source = START.ORIGIN.validate_context(source_context)
    raw = START.ADMISSION.read_regular_file(record_path, "selected start record", START.MAX_RECORD)
    bundle = START.ADMISSION.read_regular_file(bundle_path, "selected start bundle", START.MAX_BUNDLE)
    identity = AUTH.authenticate_dispatcher(source)
    selection = {"runtime_lock": runtime_lock, "runtime_directory": runtime_directory,
                 "runtime_interface": runtime_interface, "runtime_host": runtime_host,
                 "expected_record_sha256": hashlib.sha256(raw).hexdigest(),
                 "expected_bundle_sha256": hashlib.sha256(bundle).hexdigest()}
    record = START.verify_start(record_path, bundle_path, source, **selection)
    START.require(record == START.validate_start(
        START.ADMISSION.parse_json(raw, "selected start record"), source),
        "authenticated start differs from the selected claim input")
    claim_selection = {"source_context": source, "dispatcher_context": identity["context"],
                       "dispatcher_job": identity["job"], "dispatcher_event": identity["event"],
                       "trigger_context": identity["trigger_context"]}
    claim = CLAIM.claim_bytes(raw, bundle, **claim_selection)
    START.require(AUTH.authenticate_dispatcher(source) == identity,
                  "dispatcher identity changed before claim upload")
    START.require(START.verify_start(record_path, bundle_path, source, **selection) == record,
                  "authenticated start changed before claim upload")
    asset = UPLOAD.upload_claim_once(claim, raw, bundle, **claim_selection)
    return {"schema": "aros-toolchains-authenticated-claim-upload-v2",
            "assurance": "authenticated-claim-upload-only-not-native-dispatch",
            "dispatcher": identity, "claim": asset}
