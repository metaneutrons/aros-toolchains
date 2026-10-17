#!/usr/bin/env python3
"""Inactive read-only signed-start verification after the expected claim exists.

The original verify_start API still requires an empty draft before claim upload.
This separate closed wrapper authenticates the same original start/signature/
runtime while requiring exactly one independently selected claim asset and its
exact numeric-ID byte readback. It never permits arbitrary occupied candidates.

The claim's joins are structural here: its dispatcher signature, completed
dispatcher owner, signed native-run binding and actual native identity remain
separate mandatory gates. Returning the authenticated start is NOT native or
dispatch authority. No workflow calls this module; no request is a mutation,
and mocked signatures/provider fixtures cannot establish live qualification.
The trusted caller owns independent selectors, actual job-token custody and
quiescent local staging. No ACL, sandbox or atomic writer exclusion is claimed.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path


SPEC = importlib.util.spec_from_file_location(
    "claimed_start_dispatcher", Path(__file__).with_name("compiler-sdk-dispatcher-auth-v2.py"))
AUTH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUTH)
UPLOAD = AUTH.UPLOAD
CLAIM = AUTH.CLAIM
START = AUTH.START


def _download_claim(asset_id: int) -> bytes:
    """One fixed numeric read, bounded before capture; never retry a failure."""
    environment = START.ADMISSION._subprocess_environment(require_job_token=True)
    for key in ("GITHUB_TOKEN", "GH_AUTH_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN"):
        environment.pop(key, None)
    environment["GH_HOST"] = "github.com"
    result = START.ADMISSION._bounded_subprocess(
        ["gh", "api", f"repos/{START.ADMISSION.REPOSITORY}/releases/assets/{asset_id}",
         "--method", "GET", "--include", "--hostname", "github.com",
         "-H", "Accept: application/octet-stream",
         "-H", "X-GitHub-Api-Version: 2022-11-28"],
        cwd=None, timeout=START.ADMISSION.API_TIMEOUT_SECONDS,
        stdout_limit=START.MAX_RECORD + UPLOAD.MAX_HEADERS,
        stderr_limit=START.ADMISSION.MAX_API_STDERR_BYTES,
        env=environment, label="selected claim numeric readback")
    START.require(result.returncode == 0, "selected claim readback failed; no retry")
    status, raw = UPLOAD.included_response(result.stdout)
    START.require(status == 200 and len(raw) <= START.MAX_RECORD,
                  "selected claim readback is not bounded HTTP 200; no retry")
    return raw


def _selected_asset(record: dict, asset_id: int, claim_raw: bytes) -> dict:
    draft = record["draft"]
    release = START.ADMISSION.api(
        f"repos/{START.ADMISSION.REPOSITORY}/releases/{draft['id']}")
    START.require(type(release) is dict and type(release.get("id")) is int
                  and release["id"] == draft["id"]
                  and release.get("tag_name") == record["tag"]["name"]
                  and release.get("target_commitish") == record["tag"]["commit"]
                  and release.get("draft") is True and release.get("prerelease") is False
                  and release.get("immutable") is False
                  and type(release.get("assets")) is list and len(release["assets"]) == 1,
                  "claimed start requires the exact private sole-claim candidate")
    asset = UPLOAD.validate_asset(release["assets"][0], claim_raw)
    START.require(asset["id"] == asset_id, "candidate claim differs from the independent numeric selection")
    return asset


def _observe_claimed_candidate(record: dict, asset_id: int, claim_raw: bytes) -> None:
    START.ADMISSION.require_active_repository()
    START.observe_tag(record["tag"])
    before = _selected_asset(record, asset_id, claim_raw)
    by_tag = START.ADMISSION.api(
        f"repos/{START.ADMISSION.REPOSITORY}/releases/tags/{record['tag']['name']}")
    START.require(type(by_tag) is dict and type(by_tag.get("id")) is int
                  and by_tag["id"] == record["draft"]["id"],
                  "claimed start draft ID and tag lookup differ")
    START.require(_download_claim(asset_id) == claim_raw,
                  "selected claim numeric readback differs from the captured bytes")
    # A GET may change download counters. Compare the frozen selection and
    # exact one-asset closure, not unrelated mutable provider counter fields.
    START.require(_selected_asset(record, asset_id, claim_raw) == before,
                  "candidate claim changed during numeric readback")
    by_tag_after = START.ADMISSION.api(
        f"repos/{START.ADMISSION.REPOSITORY}/releases/tags/{record['tag']['name']}")
    START.require(type(by_tag_after) is dict and type(by_tag_after.get("id")) is int
                  and by_tag_after["id"] == record["draft"]["id"],
                  "claimed start tag lookup changed during numeric readback")
    START.observe_tag(record["tag"])
    START.ADMISSION.require_active_repository()


def verify_claimed_start(record_path: Path, bundle_path: Path, source_context: dict, *,
                         dispatcher_context: dict, dispatcher_job: dict,
                         claim_path: Path, claim_asset_id: int, expected_claim_sha256: str,
                         expected_record_sha256: str, expected_bundle_sha256: str,
                         runtime_lock: Path, runtime_directory: Path,
                         runtime_interface: Path, runtime_host: str) -> dict:
    """Authenticate only the signed start in a closed selected-claim phase.

    All selectors must be independently chosen by the trusted caller. This
    wrapper does not authenticate the claim signature or the executing native
    run, complete the dispatcher gate, or grant upload/publication authority.
    """
    START.require(os.environ.get("GH_HOST") == "github.com"
                  and bool(os.environ.get("GH_TOKEN", "").strip()),
                  "claimed start requires the fixed-host job token")
    START.positive(claim_asset_id, "selected claim asset ID")
    START.ORIGIN.positive(claim_asset_id)
    START.require(claim_path.name == CLAIM.CLAIM_NAME, "selected claim filename differs")
    selections = (
        (record_path, START.MAX_RECORD, expected_record_sha256, "selected start record"),
        (bundle_path, START.MAX_BUNDLE, expected_bundle_sha256, "selected start signature"),
        (claim_path, START.MAX_RECORD, expected_claim_sha256, "selected claim"),
    )
    captured = []
    for path, maximum, pin, label in selections:
        START.digest(pin, label)
        raw = START.ADMISSION.read_regular_file(path, label, maximum)
        START.require(raw and hashlib.sha256(raw).hexdigest() == pin,
                      "claimed start input differs from its independent byte selection")
        captured.append(raw)
    record_raw, bundle_raw, claim_raw = captured

    def validate_claim() -> None:
        CLAIM.validate_claim(
            claim_raw, record_raw, bundle_raw, source_context=source_context,
            dispatcher_context=dispatcher_context, dispatcher_job=dispatcher_job,
            dispatcher_event="workflow_run", trigger_context=source_context)

    validate_claim()
    record = START._verify_start(
        record_path, bundle_path, source_context, runtime_lock=runtime_lock,
        runtime_directory=runtime_directory, runtime_interface=runtime_interface,
        runtime_host=runtime_host,
        expected_record_sha256=expected_record_sha256,
        expected_bundle_sha256=expected_bundle_sha256,
        candidate_observer=lambda value: _observe_claimed_candidate(value, claim_asset_id, claim_raw))
    for (path, maximum, _, label), raw in zip(selections, captured, strict=True):
        START.require(START.ADMISSION.read_regular_file(path, label, maximum) == raw,
                      "selected start, signature or claim changed during verification")
    validate_claim()
    return record
