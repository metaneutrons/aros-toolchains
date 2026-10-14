#!/usr/bin/env python3
"""Inactive fixed-name claim upload primitive, not a release dispatcher.

No workflow calls this component. Its future trusted caller must authenticate
the start, runtime, dispatcher and triggering provider edge first. This helper
checks an exact empty private candidate, makes one upload call, and requires
HTTP 201 plus exact numeric-ID byte readback. It never dispatches, retries,
deletes, replaces, renames or infers success from a timeout. Provider behavior
and activation remain unqualified until an isolated real observation.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import re
import subprocess
import tempfile


SPEC = importlib.util.spec_from_file_location(
    "upload_claim_codec", Path(__file__).with_name("compiler-sdk-dispatch-claim-v2.py"))
CLAIM = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CLAIM)
START = CLAIM.START
MAX_HEADERS = 64 * 1024


def included_response(raw: bytes) -> tuple[int, bytes]:
    """Read only one bounded final HTTP status block; never echo headers/body."""
    START.require(type(raw) is bytes and len(raw) <= START.ADMISSION.MAX_API_BYTES,
                  "claim HTTP response exceeds the metadata limit")
    status = re.match(rb"HTTP/(?:1\.[01]|2(?:\.0)?|3(?:\.0)?) ([0-9]{3})(?: [^\r\n]*)?\r?\n", raw)
    START.require(status is not None, "claim HTTP status is missing or malformed")
    divider = re.search(rb"\r?\n\r?\n", raw)
    START.require(divider is not None and divider.end() <= MAX_HEADERS,
                  "claim HTTP header block is missing or too large")
    return int(status[1]), raw[divider.end():]


def gh_response(arguments: list[str], purpose: str) -> tuple[int, bytes]:
    environment = START.ADMISSION._subprocess_environment()
    START.require(bool(environment.get("GH_TOKEN")), "claim transport requires the job token")
    for key in ("GITHUB_TOKEN", "GH_AUTH_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN"):
        environment.pop(key, None)
    environment["GH_HOST"] = "github.com"
    try:
        result = START.ADMISSION._bounded_subprocess(
            ["gh", "api", *arguments, "--include", "--hostname", "github.com",
             "-H", "X-GitHub-Api-Version: 2022-11-28"], cwd=None,
            timeout=START.ADMISSION.API_TIMEOUT_SECONDS,
            stdout_limit=START.ADMISSION.MAX_API_BYTES,
            stderr_limit=START.ADMISSION.MAX_API_STDERR_BYTES,
            env=environment, label=purpose,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise START.StartError(f"{purpose} failed or is unknown; no mutation retry") from None
    START.require(result.returncode == 0, f"{purpose} failed or is unknown; no mutation retry")
    return included_response(result.stdout)


def validate_asset(value: object, raw: bytes) -> dict:
    START.require(type(value) is dict, "claim upload returned no asset object")
    identifier = START.positive(value.get("id"), "claim asset ID")
    expected = {"name": CLAIM.CLAIM_NAME, "state": "uploaded", "content_type": "application/json",
                "size": len(raw), "digest": f'sha256:{hashlib.sha256(raw).hexdigest()}',
                "url": f'https://api.github.com/repos/{START.ADMISSION.REPOSITORY}/releases/assets/{identifier}'}
    START.require(type(value.get("size")) is int and all(value.get(key) == item for key, item in expected.items()),
                  "claim asset identity, bytes or upload state differs")
    return {"id": identifier, "name": CLAIM.CLAIM_NAME, "size": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest()}


def fixed_metadata(path: str, *, governance: bool = False) -> object:
    # Admission pagination forwards its explicit ordinary-read selector.
    # This private reader has no privileged credential or governance mode.
    START.require(governance is False, "claim metadata reader accepts only ordinary job-token reads")
    repository = START.ADMISSION.REPOSITORY
    START.require((path == f"repos/{repository}" or path.startswith(f"repos/{repository}/"))
                  and ".." not in path.split("/"), "claim metadata endpoint is outside its fixed repository")
    status, raw = gh_response([path, "--method", "GET"], "claim candidate observation")
    START.require(status == 200, "claim candidate metadata is unavailable; no fallback")
    return START.ADMISSION.parse_json(raw, "claim candidate metadata")


# This is a private imported instance. Candidate reads and mutation/readback
# must share one fixed-host, job-token transport; GHES/config fallback cannot
# qualify a GitHub.com candidate. No other caller module is changed.
START.ADMISSION.api = fixed_metadata


def upload_claim_once(raw: bytes, record_bytes: bytes, bundle_bytes: bytes, **selection) -> dict:
    """Internal post-authentication primitive; this is not dispatch authority."""
    value = CLAIM.validate_claim(raw, record_bytes, bundle_bytes, **selection)
    candidate = value["candidate"]
    # Includes active-repository, annotated-tag and exact empty private-draft
    # readbacks. Historical/public/occupied candidates fail before the upload.
    START.observe_candidate({"tag": candidate["tag"], "draft": candidate["draft"]})
    release_id = candidate["draft"]["id"]
    repository = START.ADMISSION.REPOSITORY
    endpoint = f"https://uploads.github.com/repos/{repository}/releases/{release_id}/assets?name={CLAIM.CLAIM_NAME}"
    with tempfile.TemporaryDirectory(prefix="aros-dispatch-claim-") as directory:
        payload = Path(directory) / CLAIM.CLAIM_NAME
        with payload.open("xb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        status, response = gh_response(
            [endpoint, "--method", "POST", "-H", "Content-Type: application/json",
             "--input", str(payload)], "claim upload")
    START.require(status == 201, "claim upload is not confirmed HTTP 201; no retry or dispatch")
    asset = validate_asset(START.ADMISSION.parse_json(response, "claim upload asset"), raw)
    status, readback = gh_response(
        [f"repos/{repository}/releases/assets/{asset['id']}", "--method", "GET",
         "-H", "Accept: application/octet-stream"], "claim numeric readback")
    START.require(status == 200 and readback == raw,
                  "claim numeric readback differs; no retry or dispatch")
    release = START.ADMISSION.api(f"repos/{repository}/releases/{release_id}")
    START.require(type(release) is dict and type(release.get("id")) is int
                  and release["id"] == release_id
                  and release.get("tag_name") == candidate["tag"]["name"]
                  and release.get("target_commitish") == candidate["tag"]["commit"]
                  and release.get("draft") is True and release.get("prerelease") is False
                  and release.get("immutable") is False
                  and type(release.get("assets")) is list and len(release["assets"]) == 1,
                  "claim candidate changed or has an unexpected asset closure; no dispatch")
    START.require(validate_asset(release["assets"][0], raw) == asset,
                  "claim does not belong to the exact selected draft; no dispatch")
    START.ADMISSION.require_active_repository()
    START.observe_tag(candidate["tag"])
    return asset
