#!/usr/bin/env python3
"""Select bounded ZIP bytes for an independently observed compiler/SDK start.

This inactive transport selector performs read-only provider observations. It
does not verify the start signature, establish native qualification, or grant
upload, dispatch, or publication authority. A future caller must keep those
checks as separate gates.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def _load_module(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load the local start transport dependency")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


AUTH = _load_module("start_selector_dispatcher_auth", "compiler-sdk-dispatcher-auth-v2.py")
START = AUTH.START
UPLOAD = AUTH.UPLOAD
ORIGIN = AUTH.ORIGIN
ADMISSION = START.ADMISSION
ARCHIVE = _load_module("start_selector_archive_reader", "compiler-sdk-start-artifact-v2.py")

ASSURANCE = "transport-selection-only-not-signature-or-native-authority"
ARTIFACT_PREFIX = "compiler-sdk-release-start-v2-"
DIGEST = re.compile(r"sha256:([0-9a-f]{64})\Z")
MAX_ARTIFACT_PAGES = ADMISSION.MAX_PAGES
ARTIFACT_PAGE_SIZE = ADMISSION.PAGE_SIZE
FALLBACK_CREDENTIALS = (
    "GITHUB_TOKEN", "GH_AUTH_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN",
)
OIDC_CREDENTIALS = ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL")


def _require_provider_environment() -> None:
    START.require(os.environ.get("GH_HOST") == "github.com",
                  "start transport requires the fixed github.com host")
    token = os.environ.get("GH_TOKEN")
    START.require(type(token) is str and bool(token.strip()),
                  "start transport requires the GitHub job token")
    START.require(os.environ.get("GITHUB_EVENT_NAME") == "workflow_run",
                  "start transport requires the actual workflow_run event")


def _event_file() -> tuple[Path, bytes, dict]:
    selected = os.environ.get("GITHUB_EVENT_PATH", "")
    event_path = Path(selected)
    START.require(bool(selected) and event_path.is_absolute(),
                  "start transport requires the runner event file")
    try:
        canonical = event_path.resolve(strict=True)
    except (OSError, RuntimeError):
        raise START.StartError("runner event file is unavailable") from None
    START.require(canonical == event_path and ".." not in event_path.parts,
                  "runner event path is not canonical")
    raw = ADMISSION.read_regular_file(event_path, "dispatcher event", ADMISSION.MAX_EVENT_BYTES)
    value = ADMISSION.parse_json(raw, "dispatcher event", maximum=ADMISSION.MAX_EVENT_BYTES)
    START.require(type(value) is dict, "dispatcher event is not an object")
    return event_path, raw, value


def _source_context_from_event(event: dict) -> dict:
    """Derive the source selector only from the bounded runner event."""
    repository = event.get("repository")
    run = event.get("workflow_run")
    START.require(event.get("action") == "completed"
                  and type(repository) is dict and type(run) is dict,
                  "runner event is not a workflow_run completion")
    source_repository = START.ADMISSION.REPOSITORY
    START.require(repository.get("full_name") == source_repository,
                  "runner event repository differs from the fixed source repository")

    repository_id = repository.get("id")
    run_id = run.get("id")
    attempt = run.get("run_attempt")
    head_sha = run.get("head_sha")
    head = run.get("head_repository")
    START.require(type(repository_id) is int and type(run_id) is int and type(attempt) is int,
                  "runner event identities must be typed integers")
    START.positive(repository_id, "event repository ID")
    START.positive(run_id, "event workflow-run ID")
    START.require(attempt == 1, "start source must be original attempt one")
    START.require(type(head_sha) is str and START.ADMISSION.OID.fullmatch(head_sha) is not None,
                  "runner event source commit is not an exact SHA")
    START.require(type(head) is dict and type(head.get("id")) is int,
                  "runner event head repository identity must be a typed integer")
    head_repository_id = START.positive(head["id"], "event head repository ID")
    START.require(head_repository_id == repository_id
                  and head.get("full_name") == source_repository
                  and run.get("head_branch") == "main"
                  and run.get("event") == "workflow_run"
                  and run.get("status") == "completed"
                  and run.get("conclusion") == "success",
                  "runner event does not select the successful original main start")

    return ORIGIN.validate_context({
        "repository": source_repository,
        "repository_id": repository_id,
        "producer_commit": head_sha,
        "source_ref": ADMISSION.MAIN_REF,
        "workflow": START.WORKFLOW,
        "run_id": run_id,
        "run_attempt": attempt,
    })


def _validate_artifact_metadata(value: object, context: dict, expected_name: str) -> dict:
    START.require(type(value) is dict, "start artifact metadata is not an object")
    artifact_id = value.get("id")
    size = value.get("size_in_bytes")
    name = value.get("name")
    digest_value = value.get("digest")
    workflow_run = value.get("workflow_run")

    START.require(type(artifact_id) is int and type(size) is int,
                  "start artifact ID and size must be typed integers")
    START.positive(artifact_id, "start artifact ID")
    START.require(0 < size <= ARCHIVE.MAX_ARCHIVE,
                  "start artifact size is empty or exceeds the archive limit")
    START.require(name == expected_name and value.get("expired") is False,
                  "start artifact name or expiry state differs")
    match = DIGEST.fullmatch(digest_value) if type(digest_value) is str else None
    START.require(match is not None, "start artifact digest is not canonical SHA-256")
    START.require(type(workflow_run) is dict,
                  "start artifact has no workflow-run identity")

    for key in ("id", "repository_id", "head_repository_id"):
        START.require(type(workflow_run.get(key)) is int,
                      "start artifact workflow identities must be typed integers")
    START.require(type(workflow_run.get("head_sha")) is str,
                  "start artifact workflow commit must be a string")
    START.require(workflow_run["id"] == context["run_id"]
                  and workflow_run["head_sha"] == context["producer_commit"]
                  and workflow_run["repository_id"] == context["repository_id"]
                  and workflow_run["head_repository_id"] == context["repository_id"],
                  "start artifact workflow run or repository differs from the source")

    # Origin's normalizer is deliberately secondary to exact JSON type checks:
    # its general purpose positive() also accepts canonical decimal strings.
    normalized = ORIGIN.select_artifact(value, context, artifact_id, expected_name, match[1])
    expected = {
        "id": artifact_id,
        "name": expected_name,
        "sha256": match[1],
        "size_in_bytes": size,
    }
    START.require(normalized == expected,
                  "normalized start artifact selector differs")
    return normalized


def _list_source_artifacts(context: dict) -> list[dict]:
    endpoint = (f'repos/{context["repository"]}/actions/runs/{context["run_id"]}'
                "/artifacts?per_page=100&page=")
    rows: list[dict] = []
    identities: set[int] = set()
    total_count: int | None = None
    pages = 0

    for page in range(1, MAX_ARTIFACT_PAGES + 1):
        value = UPLOAD.fixed_metadata(f"{endpoint}{page}")
        START.require(type(value) is dict and type(value.get("artifacts")) is list
                      and type(value.get("total_count")) is int,
                      "start artifact page has an invalid shape")
        page_total = value["total_count"]
        START.require(0 <= page_total <= MAX_ARTIFACT_PAGES * ARTIFACT_PAGE_SIZE,
                      "start artifact count exceeds the bounded page limit")
        if total_count is None:
            total_count = page_total
        START.require(page_total == total_count,
                      "start artifact total count changed during pagination")

        artifacts = value["artifacts"]
        START.require(len(artifacts) <= ARTIFACT_PAGE_SIZE,
                      "start artifact page exceeds its row limit")
        remaining = total_count - len(rows)
        expected_rows = min(ARTIFACT_PAGE_SIZE, max(0, remaining))
        START.require(len(artifacts) == expected_rows,
                      "start artifact pages are short, truncated, or exceed total_count")
        for artifact in artifacts:
            START.require(type(artifact) is dict,
                          "start artifact page contains a non-object row")
            artifact_id = artifact.get("id")
            START.require(type(artifact_id) is int,
                          "start artifact page ID must be a typed integer")
            START.positive(artifact_id, "start artifact page ID")
            START.require(artifact_id not in identities,
                          "start artifact pages contain a duplicate ID")
            identities.add(artifact_id)
            rows.append(artifact)

        pages = page
        if total_count == 0 or len(rows) == total_count:
            break
    else:
        raise START.StartError("start artifact list exceeds the bounded page limit")

    START.require(total_count is not None and len(rows) == total_count,
                  "start artifact list is incomplete")
    expected_pages = max(1, (total_count + ARTIFACT_PAGE_SIZE - 1) // ARTIFACT_PAGE_SIZE)
    START.require(pages == expected_pages,
                  "start artifact pagination ended before the complete list")
    return rows


def _select_from_list(rows: list[dict], context: dict) -> dict:
    expected_name = f"{ARTIFACT_PREFIX}{context['run_id']}-1"
    selected = [item for item in rows if item.get("name") == expected_name]
    START.require(len(selected) == 1,
                  "source run does not contain exactly one original start artifact")
    return _validate_artifact_metadata(selected[0], context, expected_name)


def _download_environment() -> dict[str, str]:
    environment = ADMISSION._subprocess_environment(require_job_token=True)
    for key in (*FALLBACK_CREDENTIALS, *OIDC_CREDENTIALS):
        environment.pop(key, None)
    environment["GH_HOST"] = "github.com"
    START.require(bool(environment.get("GH_TOKEN", "").strip()),
                  "start archive download requires the GitHub job token")
    return environment


def _download_archive(context: dict, artifact: dict) -> bytes:
    command = [
        "gh", "api", "--hostname", "github.com", "--method", "GET",
        f'repos/{context["repository"]}/actions/artifacts/{artifact["id"]}/zip',
    ]
    try:
        result = ADMISSION._bounded_subprocess(
            command,
            cwd=None,
            timeout=ADMISSION.API_TIMEOUT_SECONDS,
            stdout_limit=artifact["size_in_bytes"],
            stderr_limit=ADMISSION.MAX_API_STDERR_BYTES,
            env=_download_environment(),
            label="start artifact ZIP download",
        )
    except subprocess.TimeoutExpired:
        raise START.StartError("start artifact ZIP download failed or is unknown") from None
    START.require(result.returncode == 0,
                  "start artifact ZIP download failed or is unknown")
    raw = result.stdout
    START.require(type(raw) is bytes and len(raw) == artifact["size_in_bytes"],
                  "downloaded start artifact size differs from provider metadata")
    START.require(hashlib.sha256(raw).hexdigest() == artifact["sha256"],
                  "downloaded start artifact digest differs from provider metadata")
    return raw


def _read_archive(raw: bytes, artifact: dict) -> dict[str, bytes]:
    with tempfile.TemporaryDirectory(prefix="aros-start-transport-") as temporary:
        directory = Path(temporary).resolve(strict=True)
        START.require(directory.is_absolute() and directory.is_dir()
                      and not directory.is_symlink()
                      and directory.stat().st_mode & 0o077 == 0,
                      "private start archive directory is not owner-only and canonical")
        path = directory / "start-artifact.zip"
        ADMISSION._write_exclusive(path, raw)
        return ARCHIVE.read_start_archive(path, artifact["sha256"], artifact["size_in_bytes"])


def select_start_transport() -> dict:
    """Return exact record and bundle bytes for the independently selected run.

    The provider's job token and the runner's actual event file are caller
    premises. Returned bytes remain transport data until separate signature,
    runtime, and native qualification checks succeed.
    """
    _require_provider_environment()
    event_path, event_raw, event = _event_file()
    source_context = _source_context_from_event(event)
    dispatcher_context = ORIGIN.context_from_environment(UPLOAD.CLAIM.WORKFLOW)
    AUTH.validate_trigger(event, source_context, dispatcher_context)

    dispatcher_identity = AUTH.authenticate_dispatcher(source_context)
    START.require(type(dispatcher_identity) is dict
                  and dispatcher_identity.get("context") == dispatcher_context
                  and dispatcher_identity.get("trigger_context") == source_context,
                  "authenticated dispatcher identity differs from the executing context")
    START.require(ADMISSION.read_regular_file(
        event_path, "dispatcher event", ADMISSION.MAX_EVENT_BYTES) == event_raw,
        "runner event changed during dispatcher authentication")

    expected_name = f"{ARTIFACT_PREFIX}{source_context['run_id']}-1"
    listed_rows = _list_source_artifacts(source_context)
    listed_selector = _select_from_list(listed_rows, source_context)
    direct_path = (f'repos/{source_context["repository"]}/actions/artifacts/'
                   f'{listed_selector["id"]}')
    direct_selector = _validate_artifact_metadata(
        UPLOAD.fixed_metadata(direct_path), source_context, expected_name)
    START.require(direct_selector == listed_selector,
                  "direct start artifact metadata differs from the complete run listing")

    archive_bytes = _download_archive(source_context, listed_selector)
    contents = _read_archive(archive_bytes, listed_selector)

    # Reobserve both provider selector surfaces and all dispatcher/source
    # identity edges after the one download, then bind them to the original
    # event bytes captured above.
    final_rows = _list_source_artifacts(source_context)
    START.require(final_rows == listed_rows,
                  "complete start artifact metadata changed during transport")
    final_selector = _select_from_list(final_rows, source_context)
    START.require(final_selector == listed_selector,
                  "complete start artifact listing changed during transport")
    final_direct = _validate_artifact_metadata(
        UPLOAD.fixed_metadata(direct_path), source_context, expected_name)
    START.require(final_direct == listed_selector,
                  "direct start artifact metadata changed during transport")
    final_dispatcher = AUTH.authenticate_dispatcher(source_context)
    START.require(final_dispatcher == dispatcher_identity,
                  "authenticated dispatcher identity changed during transport")
    START.require(ADMISSION.read_regular_file(
        event_path, "dispatcher event", ADMISSION.MAX_EVENT_BYTES) == event_raw,
        "runner event bytes changed during start transport selection")

    return {
        "assurance": ASSURANCE,
        "source_context": source_context,
        "dispatcher_identity": dispatcher_identity,
        "artifact_selector": listed_selector,
        "record_bytes": contents[ARCHIVE.RECORD_BASENAME],
        "bundle_bytes": contents[ARCHIVE.BUNDLE_BASENAME],
    }
