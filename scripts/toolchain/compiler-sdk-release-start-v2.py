#!/usr/bin/env python3
"""Inactive authentication component for the protected compiler/SDK start.

This reader authenticates a signed start against independently selected provider
context and immutable inputs. It creates no tag, draft, dispatch or admission.
It is not connected to a production workflow yet. Native product qualification
and durable exclusive consumption remain separate requirements.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
from pathlib import Path
import sys


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def load_module(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ADMISSION = load_module("start_admission", "release-admission-v2.py")
ORIGIN = load_module("start_origin", "artifact-origin.py")
WORKFLOW = ".github/workflows/compiler-sdk-release-start.yml"
JOB = "Create protected compiler and SDK start"
SCHEMA = "aros-toolchains-release-start-v2"
ASSURANCE = "protected-start-only-not-native-qualification"
MAX_RECORD = 128 * 1024
MAX_BUNDLE = 8 * 1024 * 1024


class StartError(ValueError):
    """The source start did not pass the closed authentication boundary."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise StartError(message)


def exact(value: object, keys: set[str], label: str) -> dict:
    require(type(value) is dict and set(value) == keys, f"{label} has an unexpected field set")
    return value


def digest(value: object, label: str) -> str:
    require(type(value) is str and ADMISSION.SHA256.fullmatch(value) is not None,
            f"{label} is not a canonical SHA-256 digest")
    return value


def positive(value: object, label: str) -> int:
    require(type(value) is int and 0 < value < 2**64, f"{label} is not a positive u64 integer")
    return value


def validate_start(value: object, source_context: dict) -> dict:
    """Validate joins only; this function alone confers no authenticity."""
    context = ORIGIN.validate_context(source_context)
    require(context["repository"] == ADMISSION.REPOSITORY
            and context["workflow"] == WORKFLOW and context["source_ref"] == ADMISSION.MAIN_REF
            and context["run_attempt"] == 1, "start source is not the original protected-main workflow")
    record = exact(value, {"schema", "assurance", "context", "event", "job", "admission",
                           "tag", "draft", "runtime"}, "start record")
    require(record["schema"] == SCHEMA and record["assurance"] == ASSURANCE,
            "start record schema or assurance differs")
    require(ORIGIN.validate_context(record["context"]) == context,
            "start record context differs from independent source selection")
    require(record["event"] == "workflow_run", "start record requires the actual main-CI completion event")
    admission = ADMISSION.validate_receipt(record["admission"])
    require(admission["commit"] == context["producer_commit"], "admission selects another producer commit")
    job = exact(record["job"], {"id", "check_run_id", "name"}, "start job")
    positive(job["id"], "start job id")
    positive(job["check_run_id"], "start check id")
    require(job["name"] == JOB, "start job name differs")
    tag = exact(record["tag"], {"name", "object", "commit", "epoch"}, "start tag")
    require(tag["name"] == admission["tag"] and tag["commit"] == admission["commit"],
            "start tag differs from admitted version and producer commit")
    require(type(tag["object"]) is str and ADMISSION.OID.fullmatch(tag["object"]) is not None,
            "start tag object is invalid")
    positive(tag["epoch"], "start tag epoch")
    draft = exact(record["draft"], {"id", "tag_name", "target_commitish"}, "start draft")
    positive(draft["id"], "start draft id")
    require(draft["tag_name"] == tag["name"] and draft["target_commitish"] == tag["commit"],
            "start draft selects another tag or commit")
    runtime = exact(record["runtime"], {"lock_sha256", "receipt_sha256", "interface_sha256",
                                        "executable_sha256"}, "start runtime")
    for key, value in runtime.items():
        digest(value, f"start runtime {key}")
    require(runtime["lock_sha256"] == admission["inputs"]["toolchains/aros-tools-runtime-v1.json"],
            "start runtime lock differs from admitted input bytes")
    return record


def bounded_gh(arguments: list[str], purpose: str = "start provider observation") -> object:
    result = ADMISSION._bounded_subprocess(
        ["gh", *arguments], cwd=None, timeout=90,
        stdout_limit=ADMISSION.MAX_API_BYTES, stderr_limit=ADMISSION.MAX_API_STDERR_BYTES,
        env=ADMISSION._subprocess_environment(), label=purpose,
    )
    require(result.returncode == 0, f"{purpose} failed; no retry or credential fallback")
    return ADMISSION.parse_json(result.stdout, purpose)


# The private imported instance retains origin's exact provider and job joins,
# but its subprocess transport is bounded by this controller's metadata limits.
ORIGIN.gh_json = bounded_gh


def observe_start_run(context: dict) -> dict:
    run = ADMISSION.api(f'repos/{context["repository"]}/actions/runs/{context["run_id"]}'
                        f'/attempts/{context["run_attempt"]}')
    require(type(run) is dict and run.get("status") == "completed" and run.get("conclusion") == "success",
            "original start attempt is incomplete or unsuccessful")
    require(ORIGIN.observe_run_event(context) == "workflow_run", "provider start event differs")
    latest = ADMISSION.api(f'repos/{context["repository"]}/actions/runs/{context["run_id"]}')
    require(type(latest) is dict and type(latest.get("id")) is int
            and latest["id"] == context["run_id"] and type(latest.get("run_attempt")) is int
            and latest["run_attempt"] == 1 and latest.get("head_sha") == context["producer_commit"]
            and latest.get("status") == "completed" and latest.get("conclusion") == "success",
            "start run was rerun, changed or did not complete successfully")
    return run


def observe_candidate(record: dict) -> None:
    ADMISSION.require_active_repository()
    tag, draft = record["tag"], record["draft"]
    ref = ADMISSION.api(f'repos/{ADMISSION.REPOSITORY}/git/ref/tags/{tag["name"]}')
    require(type(ref) is dict and ref.get("ref") == f'refs/tags/{tag["name"]}'
            and ref.get("object") == {"type": "tag", "sha": tag["object"],
                                       "url": f'https://api.github.com/repos/{ADMISSION.REPOSITORY}/git/tags/{tag["object"]}'},
            "remote ref differs from the exact annotated start tag")
    annotated = ADMISSION.api(f'repos/{ADMISSION.REPOSITORY}/git/tags/{tag["object"]}')
    require(type(annotated) is dict and annotated.get("sha") == tag["object"]
            and annotated.get("tag") == tag["name"], "remote annotated tag identity differs")
    target = annotated.get("object")
    require(type(target) is dict and target.get("type") == "commit" and target.get("sha") == tag["commit"],
            "remote annotated tag does not directly select the admitted commit")
    tagger = annotated.get("tagger")
    require(type(tagger) is dict and type(tagger.get("date")) is str, "remote tag timestamp is absent")
    try:
        timestamp = datetime.fromisoformat(tagger["date"].replace("Z", "+00:00"))
        require(timestamp.tzinfo is not None and timestamp.microsecond == 0,
                "remote tag timestamp is not an exact timezone-aware second")
        epoch = int(timestamp.astimezone(timezone.utc).timestamp())
    except (ValueError, OverflowError):
        raise StartError("remote tag timestamp is malformed") from None
    require(epoch == tag["epoch"], "remote tag timestamp differs from the start")
    release = ADMISSION.api(f'repos/{ADMISSION.REPOSITORY}/releases/{draft["id"]}')
    require(type(release) is dict and type(release.get("id")) is int and release["id"] == draft["id"]
            and release.get("tag_name") == tag["name"] and release.get("target_commitish") == tag["commit"]
            and release.get("draft") is True and release.get("prerelease") is False
            and release.get("immutable") is False and release.get("assets") == [],
            "start draft is not the exact private empty stable candidate")
    by_tag = ADMISSION.api(f'repos/{ADMISSION.REPOSITORY}/releases/tags/{tag["name"]}')
    require(type(by_tag) is dict and type(by_tag.get("id")) is int and by_tag["id"] == draft["id"],
            "draft ID and tag lookup select different candidates")


def verify_start(record_path: Path, bundle_path: Path, source_context: dict) -> dict:
    require(record_path.absolute() != bundle_path.absolute(),
            "start record and signature bundle must be separate files")
    raw = ADMISSION.read_regular_file(record_path, "signed start record", MAX_RECORD)
    bundle = ADMISSION.read_regular_file(bundle_path, "start signature bundle", MAX_BUNDLE)
    record = validate_start(ADMISSION.parse_json(raw, "signed start", maximum=MAX_RECORD), source_context)
    context = record["context"]
    observe_start_run(context)
    expected = ORIGIN.select_source_job(ORIGIN.jobs_for(context), context,
                                       {"id": record["job"]["id"], "name": JOB})
    require(expected == record["job"], "completed provider job differs from the signed start")
    verified = bounded_gh([
        "attestation", "verify", str(record_path), "--bundle", str(bundle_path),
        "--repo", context["repository"], "--signer-workflow", f'{context["repository"]}/{WORKFLOW}',
        "--signer-digest", context["producer_commit"], "--source-digest", context["producer_commit"],
        "--source-ref", ADMISSION.MAIN_REF, "--deny-self-hosted-runners", "--format", "json",
    ], "start signature authentication")
    require(type(verified) is list and len(verified) == 1, "start requires exactly one verified signature")
    result = verified[0]["verificationResult"]
    invocation = f'https://github.com/{context["repository"]}/actions/runs/{context["run_id"]}/attempts/1'
    require(result["signature"]["certificate"]["runInvocationURI"] == invocation,
            "start signature belongs to another original run attempt")
    require(result["statement"]["subject"] == [{"name": record_path.name,
             "digest": {"sha256": hashlib.sha256(raw).hexdigest()}}], "start signature subject differs")
    for path, selected_digest in record["admission"]["inputs"].items():
        observed = ADMISSION.git("show", f'{context["producer_commit"]}:{path}')
        require(hashlib.sha256(observed).hexdigest() == selected_digest,
                "frozen start input bytes differ from the signed admission")
    observe_candidate(record)
    observe_start_run(context)
    require(ORIGIN.select_source_job(ORIGIN.jobs_for(context), context,
            {"id": record["job"]["id"], "name": JOB}) == expected,
            "provider start job changed during authentication")
    observe_candidate(record)
    require(ADMISSION.read_regular_file(record_path, "signed start record", MAX_RECORD) == raw
            and ADMISSION.read_regular_file(bundle_path, "start signature bundle", MAX_BUNDLE) == bundle,
            "start record or signature changed during authentication")
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--source-context", type=Path, required=True)
    args = parser.parse_args()
    try:
        context = ADMISSION.parse_json(ADMISSION.read_regular_file(
            args.source_context, "independently selected source context", MAX_RECORD), "source context")
        verify_start(args.record, args.bundle, context)
        print("Authenticated protected start; native qualification and exclusive consumption remain required.")
        return 0
    except (StartError, ADMISSION.AdmissionError, ORIGIN.OriginError, OSError, ValueError,
            KeyError, TypeError, AttributeError, RecursionError, OverflowError) as error:
        print(f"protected start rejected: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
