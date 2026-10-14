#!/usr/bin/env python3
"""Inactive protected controller for an unsigned compiler/SDK candidate.

The controller authenticates the exact admitted source and published runtime,
then can create one annotated tag or bind one independently-created private
Release Please draft. It is not called by an active workflow and its metadata
does not qualify a compiler or SDK release. Its outputs are local hand-off
records only; neither file is release authority.

``create-tag`` writes one canonical tag identity after a confirmed GitHub
readback. ``bind-draft`` observes the separate pinned Release Please action's
already-created private draft and writes its identity. Neither subcommand
publishes assets, signs a start record, dispatches work, retries mutations, or
deletes/replaces provider state.
"""

from __future__ import annotations

import argparse
from contextlib import redirect_stdout
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
API_VERSION = "2022-11-28"
HOST = "linux-x86_64"
MAX_RECORD = 128 * 1024
MAX_RUNTIME_ASSET = 2 * 1024 * 1024 * 1024
TAG_MESSAGE = "Protected compiler and SDK candidate start"
TAGGER_NAME = "github-actions[bot]"
TAGGER_EMAIL = "41898282+github-actions[bot]@users.noreply.github.com"
FALLBACK_TOKEN_NAMES = (
    "GITHUB_TOKEN", "GH_AUTH_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN",
    "GOVERNANCE_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL",
)


def load_module(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    if spec is None or spec.loader is None:
        raise RuntimeError("candidate controller dependency is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


START = load_module("candidate_start_reader", "compiler-sdk-release-start-v2.py")
# This must remain an independent import. The reader's private copy is not the
# fresh admission implementation used to qualify candidate creation.
ADMISSION = load_module("candidate_fresh_release_admission", "release-admission-v2.py")
ORIGIN = START.ORIGIN
RUNTIME = START.RUNTIME
INTERFACE = START.INTERFACE
WORKFLOW = START.WORKFLOW
JOB = START.JOB
REPOSITORY = ADMISSION.REPOSITORY
RUNTIME_REPOSITORY = ADMISSION.RUNTIME_REPOSITORY


class CandidateError(ValueError):
    """The protected candidate boundary rejected an observation."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CandidateError(message)


def _environment(*, require_job_token: bool = True) -> dict[str, str]:
    environment = dict(os.environ)
    token = environment.get("GH_TOKEN", "")
    for name in FALLBACK_TOKEN_NAMES:
        environment.pop(name, None)
    if require_job_token and not token:
        raise CandidateError("authenticated GitHub job token is unavailable")
    if require_job_token and token:
        environment["GH_TOKEN"] = token
    else:
        environment.pop("GH_TOKEN", None)
    environment["GH_HOST"] = "github.com"
    environment["GH_PROMPT_DISABLED"] = "1"
    environment["GH_NO_UPDATE_NOTIFIER"] = "1"
    environment["GH_PAGER"] = "cat"
    return environment


def _admission_environment(*, require_job_token: bool = False) -> dict[str, str]:
    # The admission helper is reused for fresh qualification and governance,
    # but its generic environment helper also supports local Git reads. Route
    # those subprocesses through the same GH_TOKEN-only environment boundary.
    return _environment(require_job_token=require_job_token)


ADMISSION._subprocess_environment = _admission_environment
START.ADMISSION._subprocess_environment = _admission_environment


def _http_status(stderr: bytes) -> str | None:
    matches = re.findall(rb"\(HTTP ([0-9]{3})\)", stderr)
    return matches[0].decode("ascii") if len(matches) == 1 else None


def _repository_endpoint(path: str) -> None:
    prefixes = (f"repos/{REPOSITORY}", f"repos/{RUNTIME_REPOSITORY}")
    require(type(path) is str and ".." not in path.split("/")
            and any(path == prefix or path.startswith(prefix + "/") for prefix in prefixes),
            "provider endpoint is outside the fixed GitHub repositories")
    require(not path.startswith("/") and "\\" not in path and "\n" not in path,
            "provider endpoint is malformed")


def _api_get(path: str, *, allow_404: bool = False, governance: bool = False) -> Any:
    _repository_endpoint(path)
    if governance:
        allowed = re.fullmatch(
            rf"repos/{re.escape(REPOSITORY)}/rulesets(?:\?includes_parents=true&targets=tag&per_page=100&page=[1-9][0-9]*|/[1-9][0-9]*)",
            path,
        )
        require(allowed is not None, "governance metadata reads are restricted to tag rulesets")
    command = ["gh", "api", "--method", "GET", "-H",
               f"X-GitHub-Api-Version: {API_VERSION}", path]
    try:
        result = ADMISSION._bounded_subprocess(
            command, cwd=None, timeout=ADMISSION.API_TIMEOUT_SECONDS,
            stdout_limit=ADMISSION.MAX_API_BYTES,
            stderr_limit=ADMISSION.MAX_API_STDERR_BYTES,
            env=_environment(), label="GitHub metadata read",
        )
    except subprocess.TimeoutExpired:
        raise CandidateError("GitHub metadata read timed out") from None
    if result.returncode:
        status = _http_status(result.stderr)
        if allow_404 and status == "404":
            return None
        detail = f" (HTTP {status})" if status else ""
        raise CandidateError(f"GitHub metadata read failed{detail}")
    if not result.stdout:
        raise CandidateError("GitHub metadata read returned an empty response")
    return ADMISSION.parse_json(result.stdout, "GitHub metadata response")


def _api_post(path: str, payload: dict[str, Any]) -> tuple[int, Any]:
    _repository_endpoint(path)
    body = (ADMISSION.canonical_json(payload) + "\n").encode("utf-8")
    require(0 < len(body) <= MAX_RECORD, "GitHub mutation body exceeds its metadata limit")
    with tempfile.TemporaryDirectory(prefix="candidate-gh-post-") as temporary_name:
        body_path = Path(temporary_name) / "request.json"
        descriptor = os.open(body_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        command = ["gh", "api", "--include", "--method", "POST", "-H",
                   f"X-GitHub-Api-Version: {API_VERSION}", "--input", str(body_path), path]
        try:
            response = ADMISSION._bounded_subprocess(
                command, cwd=None, timeout=ADMISSION.API_TIMEOUT_SECONDS,
                stdout_limit=ADMISSION.MAX_API_BYTES,
                stderr_limit=ADMISSION.MAX_API_STDERR_BYTES,
                env=_environment(), label="GitHub candidate mutation",
            )
        except subprocess.TimeoutExpired:
            raise CandidateError("GitHub mutation outcome is unknown; stop without retry") from None
    if response.returncode != 0:
        status = _http_status(response.stderr)
        detail = f" (HTTP {status})" if status else ""
        raise CandidateError(f"GitHub mutation was not confirmed{detail}; stop without retry")
    statuses = re.findall(rb"(?m)^HTTP/(?:1\.1|2(?:\.0)?) ([0-9]{3})(?:[ \t].*)?$", response.stdout)
    require(len(statuses) == 1, "GitHub mutation response status is ambiguous; stop without retry")
    status = int(statuses[0])
    separator = response.stdout.find(b"\r\n\r\n")
    if separator < 0:
        separator = response.stdout.find(b"\n\n")
        width = 2
    else:
        width = 4
    require(separator >= 0, "GitHub mutation response body is malformed; stop without retry")
    raw_body = response.stdout[separator + width:]
    value = ADMISSION.parse_json(raw_body, "GitHub mutation response")
    return status, value


def _gh_observation(arguments: list[str], purpose: str = "GitHub provider observation") -> Any:
    require(type(arguments) is list and arguments and arguments[0] == "api",
            "provider observation command is outside the fixed GitHub API")
    tail = arguments[1:]
    if len(tail) == 1:
        endpoint = tail[0]
        paginated = False
    elif len(tail) == 3 and tail[:2] == ["--paginate", "--slurp"]:
        endpoint = tail[2]
        paginated = True
    else:
        raise CandidateError("provider observation selector is unsupported")
    _repository_endpoint(endpoint.split("?", 1)[0])
    if not paginated:
        return _api_get(endpoint)
    require(re.fullmatch(
        rf"repos/{re.escape(REPOSITORY)}/actions/runs/[1-9][0-9]*/attempts/[1-9][0-9]*/jobs\?per_page=100",
        endpoint) is not None, "provider job pagination selector differs")
    pages: list[dict] = []
    observed = 0
    for page in range(1, ADMISSION.MAX_PAGES + 1):
        value = _api_get(f"{endpoint}&page={page}")
        require(type(value) is dict and type(value.get("jobs")) is list
                and len(value["jobs"]) <= ADMISSION.PAGE_SIZE
                and type(value.get("total_count")) is int and value["total_count"] > 0,
                "provider job page is malformed")
        pages.append(value)
        observed += len(value["jobs"])
        if observed >= value["total_count"] or len(value["jobs"]) < ADMISSION.PAGE_SIZE:
            ORIGIN.complete_jobs(pages)
            return pages
    raise CandidateError("provider jobs exceed the finite page limit")


# Every module instance used by the admission and reader resolves provider
# calls through the same fixed-host, job-token-only, bounded adapter.
ADMISSION.api = _api_get
START.ADMISSION.api = _api_get
ORIGIN.gh_json = _gh_observation


def _runtime_run(command: list[str], label: str, *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    selected = list(command)
    require(selected and selected[0] in {"gh", "cosign"},
            "runtime verification command is outside the fixed tool set")
    if selected[:2] == ["gh", "api"]:
        require(len(selected) == 3, "runtime metadata selector is unsupported")
        selected = ["gh", "api", "--method", "GET", "-H",
                    f"X-GitHub-Api-Version: {API_VERSION}", selected[2]]
        _repository_endpoint(selected[-1].split("?", 1)[0])
    try:
        result = ADMISSION._bounded_subprocess(
            selected, cwd=cwd, timeout=120,
            stdout_limit=ADMISSION.MAX_API_BYTES,
            stderr_limit=ADMISSION.MAX_API_STDERR_BYTES,
            env=_environment(require_job_token=selected[0] == "gh"), label=label,
        )
    except (subprocess.TimeoutExpired, OSError):
        raise RUNTIME.RuntimeError(f"{label} failed; no retry or credential fallback") from None
    if result.returncode:
        raise RUNTIME.RuntimeError(f"{label} failed; no retry or credential fallback")
    try:
        stdout = result.stdout.decode("utf-8")
        stderr = result.stderr.decode("utf-8")
    except UnicodeDecodeError:
        raise RUNTIME.RuntimeError(f"{label} returned invalid text") from None
    return subprocess.CompletedProcess(selected, 0, stdout, stderr)


def _download_runtime_asset(lock: dict, asset: dict, asset_id: int, directory: Path) -> Path:
    require(lock.get("repository") == RUNTIME_REPOSITORY,
            "runtime download repository differs from the fixed runtime repository")
    require(type(asset_id) is int and asset_id > 0,
            "runtime download asset identity is invalid")
    require(type(asset.get("size")) is int and 0 < asset["size"] <= MAX_RUNTIME_ASSET,
            "runtime asset exceeds the download limit")
    path = directory / asset["name"]
    endpoint = f"repos/{RUNTIME_REPOSITORY}/releases/assets/{asset_id}"
    command = ["gh", "api", "--method", "GET", "-H",
               f"X-GitHub-Api-Version: {API_VERSION}",
               "-H", "Accept: application/octet-stream", endpoint]
    _repository_endpoint(endpoint)
    try:
        output = path.open("xb")
    except OSError:
        raise RUNTIME.RuntimeError("runtime asset destination is unavailable") from None
    process = None
    selector = selectors.DefaultSelector()
    errors = bytearray()
    total = 0
    deadline = time.monotonic() + 180
    try:
        process = subprocess.Popen(
            command, cwd=None, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, bufsize=0, env=_environment(),
        )
        assert process.stdout is not None and process.stderr is not None
        for stream, name in ((process.stdout, "stdout"), (process.stderr, "stderr")):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(command, 180)
            events = selector.select(remaining)
            if not events:
                raise subprocess.TimeoutExpired(command, 180)
            for key, _ in events:
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                if key.data == "stdout":
                    total += len(chunk)
                    if total > asset["size"]:
                        raise CandidateError("runtime asset exceeded its locked size")
                    output.write(chunk)
                else:
                    if len(errors) + len(chunk) > ADMISSION.MAX_API_STDERR_BYTES:
                        raise CandidateError("runtime asset transport exceeded its diagnostic limit")
                    errors.extend(chunk)
        returncode = process.wait(timeout=max(0, deadline - time.monotonic()))
        output.flush()
        os.fsync(output.fileno())
        if returncode != 0:
            status = _http_status(bytes(errors))
            detail = f" (HTTP {status})" if status else ""
            raise CandidateError(f"runtime asset download failed{detail}")
        output.close()
        if total != asset["size"] or RUNTIME.sha256_file(path) != asset["sha256"]:
            raise CandidateError("runtime asset bytes differ from the committed lock")
        return path
    except (OSError, subprocess.TimeoutExpired):
        raise CandidateError("runtime asset download failed; stop without retry") from None
    finally:
        selector.close()
        if process is not None:
            if process.poll() is None:
                process.kill()
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        if not output.closed:
            output.close()


RUNTIME.run = _runtime_run
RUNTIME.download_asset = _download_runtime_asset
# This repeats the complete fixed GitHub metadata check without the legacy raw
# git transport. The materializer still performs its own release, signature,
# attestation, manifest and archive checks.
RUNTIME.require_git_identity = ADMISSION._require_runtime


def _absolute(path: Path, label: str) -> Path:
    require(isinstance(path, Path) and path.is_absolute() and ".." not in path.parts,
            f"{label} must be an absolute normalized path")
    return path


def _private_runtime_destination(path: Path, *, existing: bool = False) -> None:
    _absolute(path, "runtime directory")
    parent_fd, name = ADMISSION._open_parent_directory(path)
    try:
        parent = os.fstat(parent_fd)
        require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.geteuid()
                and stat.S_IMODE(parent.st_mode) & 0o077 == 0,
                "runtime parent must be a private directory owned by this job")
        try:
            target = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            target = None
        if existing:
            require(target is not None and stat.S_ISDIR(target.st_mode)
                    and target.st_uid == os.geteuid()
                    and stat.S_IMODE(target.st_mode) & 0o077 == 0,
                    "materialized runtime must be a private job-owned directory")
        else:
            require(target is None, "runtime directory already exists")
            partial = f".{name}.partial"
            try:
                os.stat(partial, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise CandidateError("runtime partial directory already exists")
    finally:
        os.close(parent_fd)


def _file_destinations(paths: list[Path], *, existing: bool = False) -> None:
    selected = [_absolute(path, "candidate file path") for path in paths]
    names = [os.path.abspath(os.fspath(path)) for path in selected]
    require(len(names) == len(set(names)), "candidate file paths must be distinct")
    for path in selected:
        ADMISSION._check_output_destination(path, existing=existing)


def _read_json(path: Path, label: str, *, maximum: int = MAX_RECORD) -> tuple[bytes, dict]:
    raw = ADMISSION.read_regular_file(path, label, maximum)
    value = ADMISSION.parse_json(raw, label, maximum=maximum)
    require(type(value) is dict, f"{label} must be a JSON object")
    require(raw == (ADMISSION.canonical_json(value) + "\n").encode("utf-8"),
            f"{label} must be canonical JSON")
    return raw, value


def _unchanged(paths: dict[str, Path], captured: dict[str, bytes]) -> None:
    for key, path in paths.items():
        require(ADMISSION.read_regular_file(path, f"candidate {key} input", MAX_RECORD)
                == captured[key], f"candidate {key} input changed during the protected step")


def _source_context(receipt: dict) -> dict:
    context = ORIGIN.context_from_environment(WORKFLOW)
    require(context["repository"] == REPOSITORY
            and context["source_ref"] == ADMISSION.MAIN_REF
            and context["producer_commit"] == receipt["commit"]
            and context["run_attempt"] == 1
            and os.environ.get("GITHUB_EVENT_NAME") == "workflow_run"
            and os.environ.get("RUNNER_OS") == "Linux"
            and os.environ.get("RUNNER_ARCH") == "X64",
            "candidate controller is not the original Linux x64 protected-main job")
    event_path = Path(os.environ.get("GITHUB_EVENT_PATH", ""))
    raw = ADMISSION.read_regular_file(event_path, "candidate workflow event", ADMISSION.MAX_EVENT_BYTES)
    event = ADMISSION.parse_json(raw, "candidate workflow event", maximum=ADMISSION.MAX_EVENT_BYTES)
    require(type(event) is dict and event.get("action") == "completed"
            and type(event.get("workflow_run")) is dict,
            "candidate event is not a completed workflow_run")
    ci = receipt["runs"]["producer_contracts"]
    run = event["workflow_run"]
    for repository in (event.get("repository"), run.get("head_repository")):
        require(type(repository) is dict and type(repository.get("id")) is int
                and repository["id"] == context["repository_id"]
                and repository.get("full_name") == context["repository"],
                "candidate event repository identity differs")
    require(type(run.get("id")) is int and run["id"] == ci["id"]
            and type(run.get("run_attempt")) is int and run["run_attempt"] == ci["attempt"] == 1
            and run.get("name") == ADMISSION.CI_WORKFLOW_NAME
            and run.get("path") == ADMISSION.CI_WORKFLOW
            and run.get("event") == "push" and run.get("head_branch") == "main"
            and run.get("head_sha") == context["producer_commit"]
            and run.get("status") == "completed" and run.get("conclusion") == "success",
            "candidate trigger differs from the exact admitted successful CI run")
    require(ADMISSION._event_context(context["producer_commit"])
            == ("workflow_run", ci["id"], ci["attempt"]),
            "candidate event is not the admitted workflow_run source")
    return context


def _own_run(context: dict) -> None:
    require(ORIGIN.observe_run_event(context) == "workflow_run",
            "candidate provider run event differs")
    run = _api_get(f"repos/{REPOSITORY}/actions/runs/{context['run_id']}")
    require(type(run) is dict and type(run.get("id")) is int
            and run["id"] == context["run_id"]
            and type(run.get("run_attempt")) is int and run["run_attempt"] == 1
            and run.get("head_sha") == context["producer_commit"]
            and run.get("status") == "in_progress" and run.get("conclusion") is None,
            "candidate controller run is rerun, changed or not executing")


def _own_job(context: dict, *, expected_check: int | None = None) -> dict:
    check_id = ORIGIN.owning_check_id(context, expected_event="workflow_run")
    if expected_check is not None:
        require(check_id == expected_check, "candidate OIDC owning check identity changed")
    pages = ORIGIN.jobs_for(context)
    job = ORIGIN.select_job(pages, context, check_id, JOB, "in_progress")
    jobs = ORIGIN.complete_jobs(pages)
    selected = [item for item in jobs if item.get("id") == job["id"]]
    require(len(selected) == 1 and selected[0].get("labels") == ["ubuntu-24.04"],
            "candidate job is not the fixed hosted Ubuntu 24.04 runner")
    return job


def _own_identity(context: dict, *, expected_check: int | None = None) -> int:
    _own_run(context)
    job = _own_job(context, expected_check=expected_check)
    _own_run(context)
    final = _own_job(context, expected_check=job["check_run_id"])
    require(final == job, "candidate owning job identity changed")
    return job["check_run_id"]


def _fresh_admission(receipt: dict) -> dict:
    fresh = ADMISSION.admission(governance_receipt=receipt["governance"])
    require(type(fresh) is dict and fresh == receipt,
            "fresh full release admission no longer equals the captured receipt")
    return fresh


def _privileged_absence(tag: str) -> None:
    ref = _api_get(f"repos/{REPOSITORY}/git/ref/tags/{tag}", allow_404=True)
    require(ref is None, "candidate tag ref already exists")
    by_tag = _api_get(f"repos/{REPOSITORY}/releases/tags/{tag}", allow_404=True)
    require(by_tag is None, "private or public release already exists for the candidate tag")
    releases = ADMISSION.paginated(f"repos/{REPOSITORY}/releases")
    require(not any(item.get("tag_name") == tag for item in releases),
            "complete release listing contains the candidate tag")


def _lock_from_receipt(path: Path, receipt: dict) -> tuple[bytes, dict, str]:
    raw = ADMISSION.read_regular_file(path, "candidate runtime lock", MAX_RECORD)
    sha = hashlib.sha256(raw).hexdigest()
    require(sha == receipt["inputs"]["toolchains/aros-tools-runtime-v1.json"],
            "runtime lock bytes differ from the admitted Git blob")
    value = ADMISSION.parse_json(raw, "candidate runtime lock", maximum=MAX_RECORD)
    lock = RUNTIME.validate_lock(value)
    require(lock["repository"] == RUNTIME_REPOSITORY,
            "runtime lock names an unexpected repository")
    return raw, lock, sha


def _runtime_evidence(receipt: dict, lock_path: Path, runtime_directory: Path,
                      interface_path: Path) -> dict[str, str]:
    lock_raw = ADMISSION.read_regular_file(lock_path, "candidate runtime lock", MAX_RECORD)
    lock_sha = hashlib.sha256(lock_raw).hexdigest()
    require(lock_sha == receipt["inputs"]["toolchains/aros-tools-runtime-v1.json"],
            "candidate runtime lock changed from the admitted bytes")
    lock = RUNTIME.validate_lock(ADMISSION.parse_json(lock_raw, "candidate runtime lock",
                                                       maximum=MAX_RECORD))
    runtime_receipt_path = runtime_directory / ".aros-tools-runtime-receipt-v1.json"
    raw_receipt = ADMISSION.read_regular_file(runtime_receipt_path, "candidate runtime receipt", MAX_RECORD)
    raw_interface = ADMISSION.read_regular_file(interface_path, "candidate runtime interface", MAX_RECORD)
    manifest = RUNTIME.verify_extracted_frozen(lock, lock_sha, HOST, runtime_directory)
    executable = next((item for item in manifest["files"] if item.get("path") == "bin/aros"), None)
    require(type(executable) is dict, "candidate runtime manifest lacks bin/aros")
    hashes = {
        "lock_sha256": lock_sha,
        "receipt_sha256": hashlib.sha256(raw_receipt).hexdigest(),
        "interface_sha256": hashlib.sha256(raw_interface).hexdigest(),
        "executable_sha256": executable["sha256"],
    }
    placeholder = {
        "admission": {"inputs": {"toolchains/aros-tools-runtime-v1.json": lock_sha}},
        "runtime": hashes,
    }
    START.verify_runtime_evidence(
        placeholder, lock_path=lock_path, directory=runtime_directory,
        interface_path=interface_path, host=HOST,
    )
    return hashes


def _materialize_runtime(lock_path: Path, receipt: dict, runtime_directory: Path,
                         interface_path: Path) -> dict[str, str]:
    raw, lock, lock_sha = _lock_from_receipt(lock_path, receipt)
    require(os.environ.get("RUNNER_OS") == "Linux" and os.environ.get("RUNNER_ARCH") == "X64",
            "candidate runtime host is not Linux x64")
    _private_runtime_destination(runtime_directory)
    ADMISSION._check_output_destination(interface_path, existing=False)
    with tempfile.TemporaryDirectory(prefix="candidate-frozen-lock-",
                                     dir=runtime_directory.parent) as private:
        captured_lock = Path(private) / "runtime-lock.json"
        descriptor = os.open(captured_lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        require(ADMISSION.read_regular_file(captured_lock, "captured runtime lock", MAX_RECORD) == raw,
                "captured runtime lock changed before materialization")
        original_umask = os.umask(0o077)
        try:
            with open(os.devnull, "w", encoding="utf-8") as sink, redirect_stdout(sink):
                RUNTIME.materialize(captured_lock, HOST, runtime_directory)
        finally:
            os.umask(original_umask)
    try:
        os.chmod(runtime_directory, 0o700, follow_symlinks=False)
    except OSError:
        raise CandidateError("runtime root could not be protected for this job") from None
    require(hashlib.sha256(ADMISSION.read_regular_file(lock_path, "candidate runtime lock", MAX_RECORD)).hexdigest()
            == lock_sha, "runtime lock changed during materialization")
    manifest = RUNTIME.verify_extracted_frozen(lock, lock_sha, HOST, runtime_directory)
    executable = next((item for item in manifest["files"] if item.get("path") == "bin/aros"), None)
    require(type(executable) is dict, "materialized runtime lacks bin/aros")
    interface = INTERFACE.preflight(
        aros=str(runtime_directory / "bin/aros"),
        aros_sha256=executable["sha256"], expected_version=lock["version"],
        output=str(interface_path),
    )
    encoded = (ADMISSION.canonical_json(interface) + "\n").encode("utf-8")
    require(ADMISSION.read_regular_file(interface_path, "candidate runtime interface", MAX_RECORD) == encoded,
            "runtime interface receipt differs from the exact preflight result")
    return _runtime_evidence(receipt, lock_path, runtime_directory, interface_path)


def _frozen_candidate_metadata(receipt: dict) -> dict:
    """Repeat source, CI, governance and frozen-input gates without absence."""
    head = ADMISSION._load_head()
    require(head == receipt["commit"] and ADMISSION._event_context(head)
            == ("workflow_run", receipt["runs"]["producer_contracts"]["id"],
                receipt["runs"]["producer_contracts"]["attempt"]),
            "candidate source context or admitted CI event changed")
    require(ADMISSION.require_main(head), "main advanced before draft binding")
    ADMISSION.require_clean_tracked_checkout()
    version = ADMISSION.committed_release_version()
    require(version == receipt["version"], "candidate version changed")
    pull = ADMISSION._candidate_pull(head, version)
    require(type(pull) is dict and pull.get("number") == receipt["pull_request"],
            "the exact merged pending Release Please PR changed")
    labels = pull.get("labels")
    require(type(labels) is list and all(type(label) is dict for label in labels),
            "Release Please label metadata is malformed")
    label_names = {label.get("name") for label in labels}
    require("autorelease: pending" in label_names
            and "autorelease: tagged" not in label_names,
            "Release Please PR is no longer pending")
    inputs, lock = ADMISSION.input_context(version)
    require(inputs == receipt["inputs"], "candidate committed input bytes changed")
    governance = ADMISSION._governance(receipt["governance"])
    require(governance == receipt["governance"], "live governance differs from admission")
    ADMISSION._require_runtime(lock)
    runs = ADMISSION._require_ci(head, (receipt["runs"]["producer_contracts"]["id"],
                                        receipt["runs"]["producer_contracts"]["attempt"]))
    require(runs == receipt["runs"]["producer_contracts"],
            "the exact successful Producer contracts attempt changed")
    ADMISSION.require_active_repository()
    require(ADMISSION.require_main(head), "main advanced during draft binding")
    return lock


def _tag_timestamp(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _observe_tag(tag: dict) -> dict:
    name = tag["name"]
    ref = _api_get(f"repos/{REPOSITORY}/git/ref/tags/{name}")
    require(type(ref) is dict and ref.get("ref") == f"refs/tags/{name}"
            and type(ref.get("object")) is dict
            and ref["object"].get("type") == "tag"
            and ref["object"].get("sha") == tag["object"],
            "tag ref readback differs from the created annotated tag")
    annotated = _api_get(f"repos/{REPOSITORY}/git/tags/{tag['object']}")
    target = annotated.get("object") if type(annotated) is dict else None
    tagger = annotated.get("tagger") if type(annotated) is dict else None
    require(type(annotated) is dict and annotated.get("sha") == tag["object"]
            and annotated.get("tag") == name and annotated.get("message") == TAG_MESSAGE
            and type(target) is dict and target.get("sha") == tag["commit"]
            and target.get("type") == "commit"
            and type(tagger) is dict and tagger.get("name") == TAGGER_NAME
            and tagger.get("email") == TAGGER_EMAIL
            and tagger.get("date") == _tag_timestamp(tag["epoch"]),
            "annotated tag readback differs from the exact created identity")
    return annotated


def _create_tag(receipt: dict, context: dict, check_id: int,
                lock_path: Path, runtime_directory: Path, interface_path: Path,
                input_paths: dict[str, Path], input_bytes: dict[str, bytes],
                runtime_hashes: dict[str, str]) -> dict:
    _fresh_admission(receipt)
    _own_identity(context, expected_check=check_id)
    _frozen_candidate_metadata(receipt)
    current_runtime = _runtime_evidence(receipt, lock_path, runtime_directory, interface_path)
    require(current_runtime == runtime_hashes, "authenticated runtime bytes changed before tag creation")
    _unchanged(input_paths, input_bytes)
    _privileged_absence(receipt["tag"])
    require(ADMISSION.require_main(receipt["commit"])
            and ADMISSION._load_head() == receipt["commit"],
            "protected main changed immediately before tag creation")
    _unchanged(input_paths, input_bytes)
    require(_runtime_evidence(receipt, lock_path, runtime_directory, interface_path) == runtime_hashes,
            "authenticated runtime changed immediately before tag creation")

    epoch = int(datetime.now(timezone.utc).replace(microsecond=0).timestamp())
    date = _tag_timestamp(epoch)
    tag_object = {
        "tag": receipt["tag"], "message": TAG_MESSAGE,
        "object": receipt["commit"], "type": "commit",
        "tagger": {"name": TAGGER_NAME, "email": TAGGER_EMAIL, "date": date},
    }
    status, created = _api_post(f"repos/{REPOSITORY}/git/tags", tag_object)
    require(status == 201 and type(created) is dict
            and created.get("tag") == receipt["tag"]
            and type(created.get("object")) is dict
            and created["object"].get("sha") == receipt["commit"]
            and created["object"].get("type") == "commit"
            and created.get("message") == TAG_MESSAGE
            and type(created.get("tagger")) is dict
            and created["tagger"].get("name") == TAGGER_NAME
            and created["tagger"].get("email") == TAGGER_EMAIL
            and created["tagger"].get("date") == date
            and type(created.get("sha")) is str and ADMISSION.OID.fullmatch(created["sha"]) is not None,
            "annotated tag object creation was not exactly confirmed; stop without retry")
    tag = {"name": receipt["tag"], "object": created["sha"],
           "commit": receipt["commit"], "epoch": epoch}
    # An orphaned object is not a tag ref. Recheck the full initial admission
    # and held local bytes before the separate ref mutation; drift must not
    # turn a confirmed object creation into permission for a second write.
    _fresh_admission(receipt)
    _own_identity(context, expected_check=check_id)
    _privileged_absence(receipt["tag"])
    _unchanged(input_paths, input_bytes)
    require(_runtime_evidence(receipt, lock_path, runtime_directory, interface_path) == runtime_hashes,
            "authenticated runtime changed before tag ref creation")
    status, created_ref = _api_post(
        f"repos/{REPOSITORY}/git/refs", {"ref": f"refs/tags/{receipt['tag']}", "sha": tag["object"]}
    )
    require(status == 201 and type(created_ref) is dict
            and created_ref.get("ref") == f"refs/tags/{receipt['tag']}"
            and type(created_ref.get("object")) is dict
            and created_ref["object"].get("type") == "tag"
            and created_ref["object"].get("sha") == tag["object"],
            "tag ref creation was not exactly confirmed; stop without retry")
    _observe_tag(tag)
    _own_identity(context, expected_check=check_id)
    _frozen_candidate_metadata(receipt)
    require(ADMISSION._load_head() == receipt["commit"]
            and ADMISSION.require_main(receipt["commit"]),
            "protected main changed during tag creation")
    _unchanged(input_paths, input_bytes)
    require(_runtime_evidence(receipt, lock_path, runtime_directory, interface_path) == runtime_hashes,
            "authenticated runtime changed during tag creation")
    return tag


def _validate_tag_input(value: dict, receipt: dict) -> dict:
    tag = ADMISSION._exact_keys(value, {"name", "object", "commit", "epoch"}, "candidate tag input")
    require(tag["name"] == receipt["tag"] and tag["commit"] == receipt["commit"]
            and type(tag["object"]) is str and ADMISSION.OID.fullmatch(tag["object"]) is not None
            and type(tag["epoch"]) is int and tag["epoch"] > 0,
            "candidate tag input differs from admission")
    return tag


def _release_candidates(tag: dict, release_id: int) -> dict:
    _observe_tag(tag)
    numeric = _api_get(f"repos/{REPOSITORY}/releases/{release_id}")
    by_tag = _api_get(f"repos/{REPOSITORY}/releases/tags/{tag['name']}")
    releases = ADMISSION.paginated(f"repos/{REPOSITORY}/releases")
    matches = [item for item in releases if item.get("tag_name") == tag["name"]]
    require(len(matches) == 1 and type(matches[0].get("id")) is int
            and matches[0]["id"] == release_id,
            "complete release listing does not select exactly one candidate")
    for value in (numeric, by_tag, matches[0]):
        require(type(value) is dict and type(value.get("id")) is int
                and value["id"] == release_id and value.get("tag_name") == tag["name"]
                and value.get("target_commitish") == tag["commit"]
                and value.get("draft") is True and value.get("prerelease") is False
                and value.get("immutable") is False and type(value.get("assets")) is list
                and value["assets"] == [],
                "Release Please candidate is not the exact private stable empty draft")
    return {"id": release_id, "tag_name": tag["name"],
            "target_commitish": tag["commit"]}


def _bind_draft(receipt: dict, tag: dict, context: dict, check_id: int,
                lock_path: Path, runtime_directory: Path, interface_path: Path,
                input_paths: dict[str, Path], input_bytes: dict[str, bytes]) -> dict:
    require(os.environ.get("RP_CREATED") == "true"
            and os.environ.get("RP_TAG") == tag["name"]
            and os.environ.get("RP_SHA") == tag["commit"]
            and os.environ.get("RP_VERSION") == receipt["version"],
            "Release Please outputs do not select the admitted candidate")
    raw_id = os.environ.get("RP_ID", "")
    require(re.fullmatch(r"[1-9][0-9]{0,15}", raw_id) is not None
            and int(raw_id) <= 9007199254740991,
            "Release Please draft ID is not a canonical positive integer")
    release_id = int(raw_id)
    _own_identity(context, expected_check=check_id)
    _frozen_candidate_metadata(receipt)
    current_runtime = _runtime_evidence(receipt, lock_path, runtime_directory, interface_path)
    require(current_runtime["lock_sha256"] == receipt["inputs"]["toolchains/aros-tools-runtime-v1.json"],
            "runtime bytes differ from the admitted lock")
    _unchanged(input_paths, input_bytes)
    draft = _release_candidates(tag, release_id)
    _frozen_candidate_metadata(receipt)
    _own_identity(context, expected_check=check_id)
    require(_runtime_evidence(receipt, lock_path, runtime_directory, interface_path) == current_runtime,
            "runtime bytes changed during draft binding")
    _unchanged(input_paths, input_bytes)
    _observe_tag(tag)
    return draft


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create-tag", allow_abbrev=False)
    bind = subparsers.add_parser("bind-draft", allow_abbrev=False)
    for selected in (create, bind):
        selected.add_argument("--admission", type=Path, required=True)
        selected.add_argument("--runtime-lock", type=Path, required=True)
        selected.add_argument("--runtime-directory", type=Path, required=True)
        selected.add_argument("--runtime-interface", type=Path, required=True)
        selected.add_argument("--output", type=Path, required=True)
    bind.add_argument("--tag", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    output_paths = [args.output]
    if args.command == "create-tag":
        output_paths.append(args.runtime_interface)
    try:
        # All output destinations, including the materialized runtime root,
        # are checked before OIDC or provider calls.
        _file_destinations(output_paths)
        _private_runtime_destination(args.runtime_directory, existing=args.command == "bind-draft")
        all_paths = [args.admission, args.runtime_lock, args.runtime_directory,
                     args.runtime_interface, args.output]
        if args.command == "bind-draft":
            all_paths.append(args.tag)
        normalized = [Path(os.path.abspath(os.fspath(path))) for path in all_paths]
        for index, left in enumerate(normalized):
            for right in normalized[index + 1:]:
                require(left != right and not left.is_relative_to(right)
                        and not right.is_relative_to(left),
                        "candidate file and runtime paths must be distinct")
        admission_raw, admission_value = _read_json(args.admission, "candidate admission input")
        receipt = ADMISSION.validate_receipt(admission_value)
        runtime_raw, lock, lock_sha = _lock_from_receipt(args.runtime_lock, receipt)
        require(lock_sha == receipt["inputs"]["toolchains/aros-tools-runtime-v1.json"],
                "runtime lock is not the admitted frozen blob")
        input_paths = {"admission": args.admission, "runtime_lock": args.runtime_lock}
        input_bytes = {"admission": admission_raw, "runtime_lock": runtime_raw}
        tag = None
        if args.command == "bind-draft":
            tag_raw, tag_value = _read_json(args.tag, "candidate tag input")
            tag = _validate_tag_input(tag_value, receipt)
            input_paths["tag"] = args.tag
            input_bytes["tag"] = tag_raw
            runtime_hashes = _runtime_evidence(
                receipt, args.runtime_lock, args.runtime_directory, args.runtime_interface
            )
        context = _source_context(receipt)
        check_id = _own_identity(context)
        if args.command == "create-tag":
            fresh = _fresh_admission(receipt)
            _privileged_absence(receipt["tag"])
            runtime_hashes = _materialize_runtime(
                args.runtime_lock, fresh, args.runtime_directory, args.runtime_interface
            )
            tag_value = _create_tag(
                fresh, context, check_id, args.runtime_lock, args.runtime_directory,
                args.runtime_interface, input_paths, input_bytes, runtime_hashes,
            )
            output_value = tag_value
        else:
            _frozen_candidate_metadata(receipt)
            output_value = _bind_draft(
                receipt, tag, context, check_id, args.runtime_lock, args.runtime_directory,
                args.runtime_interface, input_paths, input_bytes,
            )
            require(_runtime_evidence(receipt, args.runtime_lock, args.runtime_directory,
                                      args.runtime_interface) == runtime_hashes,
                    "runtime bytes changed before draft identity output")
        _unchanged(input_paths, input_bytes)
        encoded = (ADMISSION.canonical_json(output_value) + "\n").encode("utf-8")
        require(0 < len(encoded) <= MAX_RECORD, "candidate identity output exceeds its size limit")
        ADMISSION._write_exclusive(args.output, encoded)
        print("Protected candidate identity recorded; this output is not release authority.")
        return 0
    except (CandidateError, ADMISSION.AdmissionError, START.StartError, ORIGIN.OriginError,
            RUNTIME.RuntimeError, INTERFACE.PreflightError, OSError, ValueError, KeyError,
            TypeError, AttributeError, RecursionError, OverflowError, subprocess.SubprocessError):
        print("protected candidate step rejected; output is not authorized", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
