#!/usr/bin/env python3
"""Inactive, read-only identity/causal-edge authentication for a dispatcher.

OIDC comes from the authenticated runner issuer, never a caller-supplied JWT.
This component grants no upload or native dispatch authority: the signed start,
runtime authenticity, fresh candidate and exclusive claim remain separate gates.
No workflow calls it yet; fixtures are not a live provider qualification.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import re


SPEC = importlib.util.spec_from_file_location(
    "dispatcher_upload", Path(__file__).with_name("compiler-sdk-claim-upload-v2.py"))
UPLOAD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(UPLOAD)
START = UPLOAD.START
CLAIM = UPLOAD.CLAIM
ORIGIN = START.ORIGIN
SCHEMA = "aros-toolchains-dispatcher-identity-v2"
ASSURANCE = "dispatcher-identity-only-not-start-or-upload-authorization"


def provider_json(arguments: list[str], purpose: str = "dispatcher provider observation") -> object:
    """Bound existing origin lookups to fixed-host GETs and finite job pages."""
    paged = arguments[:3] == ["api", "--paginate", "--slurp"] and len(arguments) == 4
    direct = arguments[:1] == ["api"] and len(arguments) == 2
    START.require(paged or direct, "dispatcher observation accepts only closed GET selectors")
    path = arguments[-1]
    base = rf"repos/{re.escape(START.ADMISSION.REPOSITORY)}/actions/runs/[1-9][0-9]*"
    START.require(re.fullmatch(base + r"(?:/attempts/[1-9][0-9]*)?(?:/jobs\?per_page=100)?", path) is not None,
                  "dispatcher provider endpoint is outside the fixed run boundary")
    if direct:
        START.require("/jobs?" not in path, "dispatcher job observation requires complete pages")
        return UPLOAD.fixed_metadata(path)
    START.require(re.fullmatch(base + r"/attempts/[1-9][0-9]*/jobs\?per_page=100", path) is not None,
                  "dispatcher pagination requires attempt-bound jobs")
    pages = []
    observed = 0
    for page in range(1, START.ADMISSION.MAX_PAGES + 1):
        value = UPLOAD.fixed_metadata(f"{path}&page={page}")
        START.require(type(value) is dict and type(value.get("jobs")) is list
                      and len(value["jobs"]) <= START.ADMISSION.PAGE_SIZE,
                      "dispatcher job page is malformed")
        total = START.positive(value.get("total_count"), "dispatcher total jobs")
        pages.append(value)
        observed += len(value["jobs"])
        if observed >= total or len(value["jobs"]) < START.ADMISSION.PAGE_SIZE:
            ORIGIN.complete_jobs(pages)
            return pages
    raise START.StartError("dispatcher jobs exceed the bounded page limit")


# Private instance only: origin's provider/event/job checks must use the same
# fixed GitHub.com job-token transport as the candidate and claim observations.
ORIGIN.gh_json = provider_json


def validate_trigger(event: object, source: dict, dispatcher: dict) -> None:
    START.require(type(event) is dict and event.get("action") == "completed",
                  "dispatcher requires the actual start-completion event")
    repository = event.get("repository")
    START.require(type(repository) is dict and type(repository.get("id")) is int
                  and repository["id"] == dispatcher["repository_id"]
                  and repository.get("full_name") == dispatcher["repository"],
                  "dispatcher event repository differs")
    run = event.get("workflow_run")
    START.require(type(run) is dict and type(run.get("id")) is int
                  and type(run.get("run_attempt")) is int and run["id"] == source["run_id"]
                  and run["run_attempt"] == source["run_attempt"]
                  and run.get("head_sha") == source["producer_commit"]
                  and run.get("head_branch") == "main" and run.get("event") == "workflow_run"
                  and run.get("status") == "completed" and run.get("conclusion") == "success",
                  "dispatcher trigger does not select the exact successful original start")
    head = run.get("head_repository")
    START.require(type(head) is dict and type(head.get("id")) is int
                  and head["id"] == source["repository_id"]
                  and head.get("full_name") == source["repository"],
                  "dispatcher trigger head repository differs")


def observe_dispatcher(context: dict) -> None:
    START.require(ORIGIN.observe_run_event(context) == "workflow_run",
                  "dispatcher provider event differs")
    latest = START.ADMISSION.api(
        f'repos/{context["repository"]}/actions/runs/{context["run_id"]}')
    START.require(type(latest) is dict and type(latest.get("id")) is int
                  and latest["id"] == context["run_id"]
                  and type(latest.get("run_attempt")) is int and latest["run_attempt"] == 1
                  and latest.get("head_sha") == context["producer_commit"]
                  and latest.get("status") == "in_progress" and latest.get("conclusion") is None,
                  "dispatcher run changed, was rerun or is not executing")


def authenticate_dispatcher(source_context: dict) -> dict:
    """Authenticate current identity and triggering edge, not candidate assets."""
    source = ORIGIN.validate_context(source_context)
    context = ORIGIN.context_from_environment(CLAIM.WORKFLOW)
    START.require(source["repository"] == START.ADMISSION.REPOSITORY
                  and source["source_ref"] == START.ADMISSION.MAIN_REF
                  and source["workflow"] == START.WORKFLOW and source["run_attempt"] == 1
                  and context["repository"] == source["repository"]
                  and context["repository_id"] == source["repository_id"]
                  and context["source_ref"] == START.ADMISSION.MAIN_REF and context["run_attempt"] == 1
                  and context["run_id"] != source["run_id"]
                  and os.environ.get("GITHUB_EVENT_NAME") == "workflow_run",
                  "dispatcher is not a distinct original main-based start-completion reader")
    event_path = Path(os.environ.get("GITHUB_EVENT_PATH", ""))
    raw = START.ADMISSION.read_regular_file(event_path, "dispatcher event", START.ADMISSION.MAX_EVENT_BYTES)
    validate_trigger(START.ADMISSION.parse_json(raw, "dispatcher event"), source, context)
    START.ADMISSION.require_active_repository()
    observe_dispatcher(context)
    START.observe_start_run(source)
    check_id = ORIGIN.owning_check_id(context, expected_event="workflow_run")
    job = ORIGIN.select_job(ORIGIN.jobs_for(context), context, check_id, CLAIM.JOB, "in_progress")
    observe_dispatcher(context)
    START.observe_start_run(source)
    START.require(ORIGIN.select_job(ORIGIN.jobs_for(context), context, check_id, CLAIM.JOB, "in_progress") == job,
                  "dispatcher owning job changed during authentication")
    START.require(START.ADMISSION.read_regular_file(
        event_path, "dispatcher event", START.ADMISSION.MAX_EVENT_BYTES) == raw,
        "dispatcher event changed during authentication")
    return {"schema": SCHEMA, "assurance": ASSURANCE, "context": context, "job": job,
            "event": "workflow_run", "trigger_context": source}
