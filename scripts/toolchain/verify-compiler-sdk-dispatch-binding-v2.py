#!/usr/bin/env python3
"""Inactive original-dispatcher signature reader for a native-run binding.

The pure codec checks joins, not authenticity. This reader captures independently
pinned binding/signature bytes and authenticates the original successful
dispatcher, exact signing workflow/commit/ref/attempt and fixed binding subject.
Actual native context/event and the start/claim/candidate authenticity must still
be established independently. No workflow invokes this module; it never signs,
dispatches, consumes, publishes or grants native fan-out authority.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile


HERE = Path(__file__).resolve().parent


def load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


AUTH = load("binding_signature_dispatcher", "compiler-sdk-dispatcher-auth-v2.py")
START = AUTH.START
CLAIM = AUTH.CLAIM
CODEC = load("binding_signature_codec", "compiler-sdk-dispatch-binding-v2.py")
# This private codec instance shares the closed job-token/provider graph. Its
# structural joins must not introduce a second, independently configured origin.
CODEC.START = START
CODEC.CLAIM = CLAIM
SCHEMA = "aros-toolchains-authenticated-dispatch-binding-v2"
ASSURANCE = "dispatcher-signature-only-not-native-consumption-or-qualification"
LIMITATIONS = [
    "actual native execution identity must be authenticated independently",
    "start, claim and candidate authenticity must be established independently",
    "does not establish durable consumption, authorize fan-out or qualify a release",
]


def verify_binding_signature(
    binding_path: Path, signature_path: Path, *, claim_raw: bytes,
    record_bytes: bytes, start_bundle_bytes: bytes, source_context: dict,
    dispatcher_context: dict, dispatcher_job: dict, claim_asset: dict,
    expected_claim_bundle_sha256: str, actual_native_context: dict,
    actual_native_event: str, expected_binding_sha256: str,
    expected_signature_sha256: str,
) -> dict:
    """Authenticate one selected binding signature, not native authorization.

    Independent selectors and real job-token custody are trusted caller inputs.
    In particular actual_native_context must not be obtained from this binding.
    Quiescent owned staging is required; these point-in-time observations are
    neither an atomic provider snapshot nor an OS sandbox.
    """
    START.require(os.environ.get("GH_HOST") == "github.com"
                  and bool(os.environ.get("GH_TOKEN", "").strip()),
                  "binding verification requires the fixed-host job token")
    START.require(binding_path.name == CODEC.BINDING_NAME
                  and binding_path.absolute() != signature_path.absolute(),
                  "binding subject name or separate signature path differs")
    START.digest(expected_binding_sha256, "selected dispatch binding")
    START.digest(expected_signature_sha256, "selected binding signature")
    raw = START.ADMISSION.read_regular_file(
        binding_path, "selected dispatch binding", START.MAX_RECORD)
    signature = START.ADMISSION.read_regular_file(
        signature_path, "selected binding signature", START.MAX_BUNDLE)
    START.require(raw and signature
                  and hashlib.sha256(raw).hexdigest() == expected_binding_sha256
                  and hashlib.sha256(signature).hexdigest() == expected_signature_sha256,
                  "binding or signature differs from the independent byte selection")
    selection = {
        "source_context": source_context, "dispatcher_context": dispatcher_context,
        "dispatcher_job": dispatcher_job, "claim_asset": claim_asset,
        "expected_claim_bundle_sha256": expected_claim_bundle_sha256,
        "actual_native_context": actual_native_context,
        "actual_native_event": actual_native_event,
    }

    def selected_binding() -> dict:
        return CODEC.validate_binding(
            raw, claim_raw, record_bytes, start_bundle_bytes, **selection)

    binding = selected_binding()
    context = binding["dispatcher"]["context"]
    job = binding["dispatcher"]["job"]
    for selected_id in (binding["start"]["job"]["id"],
                        binding["start"]["job"]["check_run_id"],
                        job["id"], job["check_run_id"],
                        binding["candidate"]["draft"]["id"], binding["claim"]["id"]):
        START.ORIGIN.positive(selected_id)

    def observe_owner() -> None:
        START.observe_start_run(context)
        observed = START.ORIGIN.select_source_job(
            START.ORIGIN.jobs_for(context), context, {"id": job["id"], "name": CLAIM.JOB})
        START.require(observed == job, "binding original dispatcher job differs")

    observe_owner()
    with tempfile.TemporaryDirectory(prefix="aros-binding-signature-") as directory:
        root = Path(directory)
        root.chmod(0o700)
        subject = root / CODEC.BINDING_NAME
        bundle = root / "signature.json"
        for path, content in ((subject, raw), (bundle, signature)):
            with path.open("xb") as handle:
                path.chmod(0o600)
                handle.write(content)
        verified = START.bounded_gh([
            "attestation", "verify", str(subject), "--bundle", str(bundle),
            "--hostname", "github.com", "--repo", context["repository"],
            "--signer-workflow", f'{context["repository"]}/{CLAIM.WORKFLOW}',
            "--signer-digest", context["producer_commit"],
            "--source-digest", context["producer_commit"],
            "--source-ref", START.ADMISSION.MAIN_REF,
            "--deny-self-hosted-runners", "--format", "json",
        ], "dispatch binding signature authentication")
    START.require(type(verified) is list and len(verified) == 1
                  and type(verified[0]) is dict,
                  "binding requires exactly one verified signature")
    result = verified[0].get("verificationResult")
    START.require(type(result) is dict, "binding signature result is malformed")
    signed = result.get("signature")
    certificate = signed.get("certificate") if type(signed) is dict else None
    invocation = (f'https://github.com/{context["repository"]}/actions/runs/'
                  f'{context["run_id"]}/attempts/1')
    START.require(type(certificate) is dict
                  and certificate.get("runInvocationURI") == invocation,
                  "binding signature belongs to another original dispatcher attempt")
    statement = result.get("statement")
    START.require(type(statement) is dict and statement.get("subject") == [
        {"name": CODEC.BINDING_NAME, "digest": {"sha256": hashlib.sha256(raw).hexdigest()}}],
        "binding signature subject differs from the selected bytes")
    observe_owner()
    START.require(START.ADMISSION.read_regular_file(
        binding_path, "selected dispatch binding", START.MAX_RECORD) == raw
        and START.ADMISSION.read_regular_file(
            signature_path, "selected binding signature", START.MAX_BUNDLE) == signature,
        "binding or signature changed during authentication")
    START.require(selected_binding() == binding,
                  "binding selectors changed during authentication")
    return {"schema": SCHEMA, "assurance": ASSURANCE,
            "binding": START.ADMISSION.parse_json(raw, "authenticated dispatch binding"),
            "limitations": list(LIMITATIONS)}
