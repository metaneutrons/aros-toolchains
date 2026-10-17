#!/usr/bin/env python3
"""Read-only identity gate for the native compiler/SDK workflow.

The caller must supply a claim already authenticated by the original
dispatcher-signature gate and a candidate result already authenticated by the
native-candidate gate. Structural claim bytes or a successful codec check do
not satisfy that precondition. This module independently binds the current
workflow_dispatch runner, event file, OIDC-owned check and exact in-progress
hosted job to those prior results. It provides identity only: no durable
consumption, signed native-run binding, fan-out, dispatch authority or release
qualification.

No workflow invokes this component. Test fixtures establish no live GitHub or
OIDC qualification.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path


HERE = Path(__file__).resolve().parent
_SPEC = importlib.util.spec_from_file_location(
    "native_identity_dispatcher_auth",
    HERE / "compiler-sdk-dispatcher-auth-v2.py",
)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError("native identity dependency is unavailable")
AUTH = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(AUTH)
START = AUTH.START
UPLOAD = AUTH.UPLOAD
CLAIM = AUTH.CLAIM
ORIGIN = AUTH.ORIGIN

SCHEMA = "aros-toolchains-native-execution-identity-v2"
ASSURANCE = "native-execution-identity-only-not-consumption-or-qualification"
LIMITATIONS = [
    "claim authenticity must be established independently by the original-dispatcher signature gate",
    "candidate authenticity must be established independently by the native-candidate gate",
    "does not authenticate a signed native dispatch-run binding",
    "does not provide durable exclusive claim consumption",
    "does not authorize fan-out, dispatch or release qualification",
]
NATIVE_JOB = "Authenticate and consume compiler and SDK candidate"
NATIVE_WORKFLOW_NAME = "AROS Compiler and SDK Producer"


def _same_repository(first: dict, second: dict) -> bool:
    return (first["repository"] == second["repository"]
            and first["repository_id"] == second["repository_id"])


def _validated_inputs(authenticated_claim: object,
                      candidate_authentication: object) -> tuple[dict, dict, dict]:
    """Check closed result shapes and joins; caller remains responsible for proof."""
    claim = START.exact(
        authenticated_claim,
        {"schema", "assurance", "name", "start", "candidate", "dispatcher", "native"},
        "independently authenticated claim",
    )
    START.require(claim["schema"] == CLAIM.SCHEMA
                  and claim["assurance"] == CLAIM.ASSURANCE
                  and claim["name"] == CLAIM.CLAIM_NAME,
                  "independently authenticated claim identity differs")

    start = START.exact(claim["start"],
                        {"context", "job", "record_sha256", "bundle_sha256"},
                        "authenticated claim start")
    source = ORIGIN.validate_context(start["context"])
    START.digest(start["record_sha256"], "authenticated start record digest")
    START.digest(start["bundle_sha256"], "authenticated start bundle digest")
    start_job = START.exact(start["job"], {"id", "check_run_id", "name"}, "authenticated start job")
    START.positive(start_job["id"], "authenticated start job ID")
    START.positive(start_job["check_run_id"], "authenticated start check ID")
    START.require(source["repository"] == START.ADMISSION.REPOSITORY
                  and source["workflow"] == START.WORKFLOW
                  and source["source_ref"] == START.ADMISSION.MAIN_REF
                  and source["run_attempt"] == 1
                  and start_job["name"] == START.JOB,
                  "authenticated start context or owning job differs")

    candidate = START.exact(claim["candidate"], {"tag", "draft", "inputs", "runtime"},
                             "authenticated claim candidate")
    tag = START.exact(candidate["tag"], {"name", "object", "commit", "epoch"},
                      "authenticated candidate tag")
    START.require(type(tag["name"]) is str and tag["name"].startswith("v")
                  and START.ADMISSION.SEMVER.fullmatch(tag["name"][1:]) is not None,
                  "authenticated candidate tag name is invalid")
    START.require(type(tag["object"]) is str and START.ADMISSION.OID.fullmatch(tag["object"]) is not None
                  and type(tag["commit"]) is str and START.ADMISSION.OID.fullmatch(tag["commit"]) is not None,
                  "authenticated candidate tag identity is invalid")
    START.require(source["producer_commit"] == tag["commit"],
                  "authenticated candidate tag differs from the signed start commit")
    START.positive(tag["epoch"], "authenticated candidate tag epoch")
    draft = START.exact(candidate["draft"], {"id", "tag_name", "target_commitish"},
                        "authenticated candidate draft")
    START.positive(draft["id"], "authenticated candidate draft ID")
    START.require(draft["tag_name"] == tag["name"] and draft["target_commitish"] == tag["commit"],
                  "authenticated draft differs from its tag")
    START.require(type(candidate["inputs"]) is dict and type(candidate["runtime"]) is dict,
                  "authenticated candidate evidence is malformed")

    dispatcher = START.exact(claim["dispatcher"],
                             {"context", "event", "trigger_context", "job"},
                             "authenticated claim dispatcher")
    dispatcher_context = ORIGIN.validate_context(dispatcher["context"])
    trigger_context = ORIGIN.validate_context(dispatcher["trigger_context"])
    START.require(dispatcher["event"] == "workflow_run" and trigger_context == source,
                  "authenticated dispatcher edge differs from the original start")
    dispatcher_job = START.exact(dispatcher["job"], {"id", "check_run_id", "name"},
                                 "authenticated dispatcher job")
    START.positive(dispatcher_job["id"], "authenticated dispatcher job ID")
    START.positive(dispatcher_job["check_run_id"], "authenticated dispatcher check ID")
    START.require(dispatcher_job["name"] == CLAIM.JOB
                  and dispatcher_job["id"] != start_job["id"]
                  and dispatcher_job["check_run_id"] != start_job["check_run_id"]
                  and dispatcher_context["repository"] == source["repository"]
                  and dispatcher_context["repository_id"] == source["repository_id"]
                  and dispatcher_context["workflow"] == CLAIM.WORKFLOW
                  and dispatcher_context["source_ref"] == START.ADMISSION.MAIN_REF
                  and dispatcher_context["run_attempt"] == 1
                  and dispatcher_context["run_id"] != source["run_id"],
                  "authenticated dispatcher identity reuses the original start")

    native = START.exact(claim["native"],
                         {"workflow", "event", "source_ref", "producer_commit"},
                         "authenticated native selector")
    START.require(native["workflow"] == CLAIM.NATIVE_WORKFLOW
                  and native["event"] == "workflow_dispatch"
                  and native["source_ref"] == f'refs/tags/{tag["name"]}'
                  and native["producer_commit"] == tag["commit"],
                  "authenticated native selector differs from the exact candidate tag")
    START.require(_same_repository(source, dispatcher_context),
                  "authenticated source and dispatcher repositories differ")

    result = START.exact(candidate_authentication,
                         {"schema", "assurance", "authenticated_candidate_only", "limitations"},
                         "prior candidate-authentication result")
    START.require(result["schema"] == "aros-toolchains-native-candidate-authentication-v2"
                  and result["assurance"] == "authenticated-candidate-only-not-native-dispatch-or-qualification"
                  and result["limitations"] == [
                      "does not authenticate the actual native workflow_dispatch event or OIDC identity",
                      "does not establish a signed native dispatch-run binding",
                      "does not provide durable exclusive claim consumption",
                      "does not authorize dispatch or qualify a release",
                  ],
                  "prior candidate-authentication result has an unexpected assurance")
    projection = START.exact(result["authenticated_candidate_only"],
                             {"tag_name", "commit", "draft_id", "claim_asset"},
                             "prior authenticated candidate projection")
    START.require(projection["tag_name"] == tag["name"] and projection["commit"] == tag["commit"]
                  and type(projection["draft_id"]) is int and projection["draft_id"] == draft["id"],
                  "prior authenticated candidate differs from the claim tag or draft")
    asset = START.exact(projection["claim_asset"], {"id", "name", "size", "sha256"},
                        "prior authenticated claim asset")
    START.positive(asset["id"], "prior authenticated claim asset ID")
    START.require(asset["name"] == CLAIM.CLAIM_NAME
                  and type(asset["size"]) is int and 0 < asset["size"] <= START.MAX_RECORD
                  and type(asset["sha256"]) is str
                  and START.ADMISSION.SHA256.fullmatch(asset["sha256"]) is not None,
                  "prior authenticated claim asset identity is malformed")
    # Context and selected provider identities use the origin reader's exact
    # integer bound; a positive u64 alone can exceed JSON-safe identifiers.
    for selected_id in (start_job["id"], start_job["check_run_id"],
                        dispatcher_job["id"], dispatcher_job["check_run_id"],
                        draft["id"], asset["id"]):
        ORIGIN.positive(selected_id)
    encoded_claim = (START.ADMISSION.canonical_json(claim) + "\n").encode("ascii")
    START.require(0 < len(encoded_claim) <= START.MAX_RECORD
                  and asset["size"] == len(encoded_claim)
                  and asset["sha256"] == hashlib.sha256(encoded_claim).hexdigest(),
                  "authenticated claim bytes differ from the prior authenticated asset")
    return claim, result, {"source": source, "dispatcher": dispatcher_context,
                           "tag": tag, "draft": draft, "asset": asset}


def _validate_event(value: object, *, source: dict, context: dict) -> None:
    START.require(type(value) is dict, "workflow_dispatch event is not an object")
    START.require({"ref", "repository", "workflow"} <= set(value),
                  "workflow_dispatch event omits its repository, workflow or ref")
    repository = value["repository"]
    START.require(type(repository) is dict
                  and type(repository.get("id")) is int
                  and repository["id"] == source["repository_id"]
                  and repository.get("full_name") == source["repository"],
                  "workflow_dispatch event repository differs from the authenticated source")
    # The dispatch API accepts a bare tag; the runner/OIDC/provider context
    # remains bound to the full ref. Do not assume the event payload normalizes
    # that request string in the same way.
    full_ref = context["source_ref"]
    START.require(full_ref.startswith("refs/tags/")
                  and type(value["ref"]) is str
                  and value["ref"] in {full_ref, full_ref.removeprefix("refs/tags/")},
                  "workflow_dispatch event ref differs from the native runner")
    workflow_name = os.environ.get("GITHUB_WORKFLOW")
    # GitHub documents these strings separately, without promising an identical
    # display-name representation. Only OIDC workflow_ref/workflow_sha and the
    # provider run path authenticate the file; this field is bounded metadata.
    START.require(type(value["workflow"]) is str
                  and 0 < len(value["workflow"]) <= 1024
                  and not any(ord(character) < 32 for character in value["workflow"])
                  and type(workflow_name) is str
                  and workflow_name == NATIVE_WORKFLOW_NAME,
                  "workflow_dispatch workflow metadata or native display name is malformed")


def _observe_native(context: dict, check_id: int) -> dict:
    event = ORIGIN.observe_run_event(context)
    START.require(event == "workflow_dispatch", "native provider run event differs")
    latest = START.ADMISSION.api(
        f'repos/{context["repository"]}/actions/runs/{context["run_id"]}')
    START.require(type(latest) is dict and type(latest.get("id")) is int
                  and latest["id"] == context["run_id"]
                  and type(latest.get("run_attempt")) is int and latest["run_attempt"] == 1
                  and latest.get("head_sha") == context["producer_commit"]
                  and latest.get("status") == "in_progress" and latest.get("conclusion") is None,
                  "native run changed, was rerun or is not currently executing")
    pages = ORIGIN.jobs_for(context)
    job = ORIGIN.select_job(pages, context, check_id, NATIVE_JOB, "in_progress")
    selected = [item for item in ORIGIN.complete_jobs(pages)
                if item.get("check_run_url") ==
                f'https://api.github.com/repos/{context["repository"]}/check-runs/{check_id}']
    START.require(len(selected) == 1 and selected[0].get("labels") == ["ubuntu-24.04"],
                  "native owning job is not the exact hosted ubuntu-24.04 job")
    return {"event": event, "job": job, "labels": ["ubuntu-24.04"]}


def authenticate_native_execution(authenticated_claim: object,
                                  candidate_authentication: object) -> dict:
    """Bind native workflow identity to independently authenticated results.

    ``authenticated_claim`` must be the result of the original dispatcher's
    independent claim-signature verification. ``candidate_authentication``
    must be the result of the native candidate-authentication gate. This
    function does not authenticate either object from structure alone.
    """
    START.require(os.environ.get("GH_HOST") == "github.com"
                  and bool(os.environ.get("GH_TOKEN", "").strip()),
                  "native identity requires the fixed-host job token")
    claim, candidate_result, joined = _validated_inputs(
        authenticated_claim, candidate_authentication)
    try:
        claim_pin = START.ADMISSION.canonical_json(authenticated_claim)
        candidate_pin = START.ADMISSION.canonical_json(candidate_authentication)
    except (TypeError, ValueError, RecursionError):
        raise START.StartError("authenticated native identity inputs are not closed JSON") from None
    source, dispatcher = joined["source"], joined["dispatcher"]
    tag, draft, asset = joined["tag"], joined["draft"], joined["asset"]

    context = ORIGIN.context_from_environment(CLAIM.NATIVE_WORKFLOW)
    native = claim["native"]
    START.require(context["repository"] == source["repository"]
                  and context["repository_id"] == source["repository_id"]
                  and context["source_ref"] == native["source_ref"]
                  and context["producer_commit"] == native["producer_commit"] == tag["commit"]
                  and context["run_attempt"] == 1
                  and context["run_id"] not in {source["run_id"], dispatcher["run_id"]}
                  and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch",
                  "native runner context is not the distinct original candidate-tag dispatch")

    event_path_value = os.environ.get("GITHUB_EVENT_PATH", "")
    START.require(bool(event_path_value), "native workflow_dispatch event file is unavailable")
    event_path = Path(event_path_value)
    START.require(event_path.is_absolute() and ".." not in event_path.parts,
                  "native workflow_dispatch event path is not absolute and normalized")
    event_raw = START.ADMISSION.read_regular_file(
        event_path, "native workflow_dispatch event", START.ADMISSION.MAX_EVENT_BYTES)
    event = START.ADMISSION.parse_json(
        event_raw, "native workflow_dispatch event",
        maximum=START.ADMISSION.MAX_EVENT_BYTES,
    )
    _validate_event(event, source=source, context=context)

    # Repository visibility and run ownership are checked independently of the
    # caller's claim; all requests go through the existing job-token boundary.
    START.ADMISSION.require_active_repository()
    check_id = ORIGIN.owning_check_id(context, expected_event="workflow_dispatch")
    before = _observe_native(context, check_id)
    START.ADMISSION.require_active_repository()
    after = _observe_native(context, check_id)
    START.require(after == before, "native owning run or job changed during identity authentication")

    START.require(ORIGIN.context_from_environment(CLAIM.NATIVE_WORKFLOW) == context
                  and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
                  and os.environ.get("GITHUB_EVENT_PATH") == event_path_value
                  and os.environ.get("GITHUB_WORKFLOW") == NATIVE_WORKFLOW_NAME,
                  "native runner environment changed during identity authentication")
    START.require(START.ADMISSION.read_regular_file(
        event_path, "native workflow_dispatch event", START.ADMISSION.MAX_EVENT_BYTES) == event_raw,
        "native workflow_dispatch event changed during identity authentication")
    START.require(START.ADMISSION.canonical_json(authenticated_claim) == claim_pin
                  and START.ADMISSION.canonical_json(candidate_authentication) == candidate_pin
                  and claim == authenticated_claim and candidate_result == candidate_authentication,
                  "authenticated claim or candidate result changed during identity authentication")
    return {
        "schema": SCHEMA,
        "assurance": ASSURANCE,
        "event": "workflow_dispatch",
        "context": context,
        "job": {"id": before["job"]["id"], "check_run_id": check_id,
                "name": NATIVE_JOB, "labels": before["labels"]},
        "candidate_identity": {"tag_name": tag["name"], "commit": tag["commit"],
                               "draft_id": draft["id"], "claim_asset_id": asset["id"]},
        "limitations": list(LIMITATIONS),
    }
