#!/usr/bin/env python3
"""Inactive record constructor for an executing protected start job.

Creates no files, signatures, tags or drafts. The future protected caller must
first perform admission, authenticate/materialize the published runtime and
create its exact candidate. This helper joins those retained inputs to actual
provider/OIDC job ownership before returning an unsigned closed record.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path


SPEC = importlib.util.spec_from_file_location(
    "construct_start_auth", Path(__file__).with_name("compiler-sdk-dispatcher-auth-v2.py"))
AUTH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUTH)
START = AUTH.START
ADMISSION = START.ADMISSION
ORIGIN = START.ORIGIN


def own_run(context: dict) -> None:
    START.require(ORIGIN.observe_run_event(context) == "workflow_run", "start provider event differs")
    latest = ADMISSION.api(f'repos/{context["repository"]}/actions/runs/{context["run_id"]}')
    START.require(type(latest) is dict and type(latest.get("id")) is int
                  and latest["id"] == context["run_id"]
                  and type(latest.get("run_attempt")) is int and latest["run_attempt"] == 1
                  and latest.get("head_sha") == context["producer_commit"]
                  and latest.get("status") == "in_progress" and latest.get("conclusion") is None,
                  "start is rerun, changed or not executing")


def construct_start(admission: dict, tag: dict, draft: dict, *, runtime_lock: Path,
                    runtime_directory: Path, runtime_interface: Path) -> dict:
    """Construct only after exact inputs, runtime closure and own identity join."""
    context = ORIGIN.context_from_environment(START.WORKFLOW)
    receipt = ADMISSION.validate_receipt(admission)
    START.require(context["repository"] == ADMISSION.REPOSITORY
                  and context["source_ref"] == ADMISSION.MAIN_REF and context["run_attempt"] == 1
                  and context["producer_commit"] == receipt["commit"]
                  and os.environ.get("GITHUB_EVENT_NAME") == "workflow_run"
                  and os.environ.get("RUNNER_OS") == "Linux" and os.environ.get("RUNNER_ARCH") == "X64",
                  "constructor requires the original Linux x64 protected-main start job")
    event_path = Path(os.environ.get("GITHUB_EVENT_PATH", ""))
    event = ADMISSION.read_regular_file(event_path, "start trigger", ADMISSION.MAX_EVENT_BYTES)
    parsed_event = ADMISSION.parse_json(event, "start trigger")
    START.require(type(parsed_event) is dict and parsed_event.get("action") == "completed"
                  and type(parsed_event.get("workflow_run")) is dict,
                  "start trigger is not a completed workflow event")
    for repository in (parsed_event.get("repository"),
                       parsed_event.get("workflow_run", {}).get("head_repository")):
        START.require(type(repository) is dict and type(repository.get("id")) is int
                      and repository["id"] == context["repository_id"]
                      and repository.get("full_name") == context["repository"],
                      "start trigger repository identity differs")
    ci = receipt["runs"]["producer_contracts"]
    trigger = parsed_event["workflow_run"]
    START.require(type(trigger.get("id")) is int and trigger["id"] == ci["id"]
                  and type(trigger.get("run_attempt")) is int and trigger["run_attempt"] == ci["attempt"]
                  and trigger.get("name") == ADMISSION.CI_WORKFLOW_NAME
                  and trigger.get("path") == ADMISSION.CI_WORKFLOW
                  and trigger.get("event") == "push" and trigger.get("head_branch") == "main"
                  and trigger.get("head_sha") == context["producer_commit"]
                  and trigger.get("status") == "completed" and trigger.get("conclusion") == "success",
                  "captured start trigger differs from the admitted CI source")

    def recheck_source() -> None:
        START.require(ADMISSION._event_context(context["producer_commit"])
                      == ("workflow_run", ci["id"], ci["attempt"]),
                      "start trigger differs from the admitted CI attempt")
        START.require(ADMISSION._require_ci(context["producer_commit"], (ci["id"], ci["attempt"])) == ci,
                      "admitted CI attempt is no longer the exact successful source")
        source_run = ADMISSION.api(
            f'repos/{context["repository"]}/actions/runs/{ci["id"]}/attempts/{ci["attempt"]}')
        START.require(type(source_run) is dict and type(source_run.get("head_repository")) is dict,
                      "admitted source CI lacks repository identity")
        source_repository = source_run["head_repository"]
        START.require(type(source_repository.get("id")) is int
                      and source_repository["id"] == context["repository_id"]
                      and source_repository.get("full_name") == context["repository"],
                      "admitted source CI repository ID differs")
        START.require(ADMISSION.require_main(context["producer_commit"]), "main advanced before start construction")
        START.require(ADMISSION._load_head() == context["producer_commit"], "start checkout differs")
        ADMISSION.require_clean_tracked_checkout()
        for path, expected in receipt["inputs"].items():
            START.require(hashlib.sha256(ADMISSION.git("show", f'{context["producer_commit"]}:{path}')).hexdigest()
                          == expected, "admitted start input differs from the frozen Git blob")

    ADMISSION.require_active_repository()
    recheck_source()
    own_run(context)
    check_id = ORIGIN.owning_check_id(context, expected_event="workflow_run")
    pages = ORIGIN.jobs_for(context)
    job = ORIGIN.select_job(pages, context, check_id, START.JOB, "in_progress")
    provider_job = next(item for item in ORIGIN.complete_jobs(pages) if item["id"] == job["id"])
    START.require(provider_job.get("labels") == ["ubuntu-24.04"],
                  "start runtime host is not bound to its fixed provider runner label")
    paths = {"lock_sha256": runtime_lock,
             "receipt_sha256": runtime_directory / ".aros-tools-runtime-receipt-v1.json",
             "interface_sha256": runtime_interface}
    raw = {key: ADMISSION.read_regular_file(path, "start construction runtime", START.MAX_RECORD)
           for key, path in paths.items()}
    lock = START.RUNTIME.validate_lock(ADMISSION.parse_json(raw["lock_sha256"], "start runtime lock"))
    lock_sha = hashlib.sha256(raw["lock_sha256"]).hexdigest()
    manifest = START.RUNTIME.verify_extracted_frozen(lock, lock_sha, "linux-x86_64", runtime_directory)
    executable = next(item for item in manifest["files"] if item["path"] == "bin/aros")
    runtime = {key: hashlib.sha256(value).hexdigest() for key, value in raw.items()}
    runtime["executable_sha256"] = executable["sha256"]
    record = START.validate_start({"schema": START.SCHEMA, "assurance": START.ASSURANCE,
                                   "context": context, "event": "workflow_run", "job": job,
                                   "admission": receipt, "tag": tag, "draft": draft,
                                   "runtime": runtime}, context)
    selection = {"lock_path": runtime_lock, "directory": runtime_directory,
                 "interface_path": runtime_interface, "host": "linux-x86_64"}
    START.verify_runtime_evidence(record, **selection)
    START.observe_candidate(record)
    recheck_source()
    own_run(context)
    final_pages = ORIGIN.jobs_for(context)
    START.require(ORIGIN.select_job(final_pages, context, check_id, START.JOB, "in_progress") == job,
                  "start owning job changed during construction")
    final_job = next(item for item in ORIGIN.complete_jobs(final_pages) if item["id"] == job["id"])
    START.require(final_job.get("labels") == ["ubuntu-24.04"], "start provider runner label changed")
    START.verify_runtime_evidence(record, **selection)
    START.observe_candidate(record)
    START.require(ADMISSION.read_regular_file(event_path, "start trigger", ADMISSION.MAX_EVENT_BYTES) == event,
                  "start trigger changed during construction")
    return record
