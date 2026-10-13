#!/usr/bin/env python3
"""Select provider metadata for a later authenticated artifact-origin read.

This command emits a caller-bound selection record. Run-level artifact metadata
does not bind artifacts to a job; authenticated verify-source remains required.
This command does not read or authenticate an origin, download either artifact,
or make a qualification claim.
"""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import re
import sys


ORIGIN_PATH = Path(__file__).resolve().with_name("artifact-origin.py")
ORIGIN_SPEC = importlib.util.spec_from_file_location("artifact_origin_selector", ORIGIN_PATH)
if ORIGIN_SPEC is None or ORIGIN_SPEC.loader is None:
    raise RuntimeError("artifact-origin helpers are unavailable")
artifact_origin = importlib.util.module_from_spec(ORIGIN_SPEC)
ORIGIN_SPEC.loader.exec_module(artifact_origin)


def require(condition: bool, message: str) -> None:
    artifact_origin.require(condition, message)


def complete_artifacts(pages: object) -> list[dict]:
    """Validate a complete, stable, nonduplicated run-artifact listing."""
    require(isinstance(pages, list) and 0 < len(pages) <= 100,
            "artifact pages are invalid")
    totals: list[int] = []
    artifacts: list[object] = []
    for page in pages:
        require(isinstance(page, dict) and isinstance(page.get("artifacts"), list),
                "artifact page is invalid")
        total = page.get("total_count")
        require(type(total) is int and 0 <= total <= 9007199254740991,
                "artifact total is invalid")
        totals.append(total)
        artifacts.extend(page["artifacts"])
    require(len(set(totals)) == 1 and len(artifacts) == totals[0],
            "artifact pages are incomplete")
    require(all(isinstance(item, dict) for item in artifacts),
            "artifact metadata is invalid")
    ids = [artifact_origin.positive(item.get("id")) for item in artifacts]
    require(len(set(ids)) == len(ids), "artifact pages repeat an identity")
    require(all(isinstance(item.get("name"), str) for item in artifacts),
            "artifact name metadata is invalid")
    return artifacts


def _artifact_digest(item: dict) -> str:
    digest = item.get("digest")
    require(isinstance(digest, str)
            and re.fullmatch(r"sha256:([0-9a-f]{64})", digest) is not None,
            "provider artifact digest is invalid")
    return digest.removeprefix("sha256:")


def _preflight(args: argparse.Namespace) -> tuple[dict, dict]:
    """Validate every caller selector and context byte before provider I/O."""
    lane = artifact_origin.selection(args)
    require(isinstance(args.source_context, Path) and args.source_context.is_absolute()
            and ".." not in args.source_context.parts,
            "source context path must be absolute and normalized")
    require(isinstance(args.source_context_sha256, str)
            and re.fullmatch(r"[0-9a-f]{64}", args.source_context_sha256) is not None,
            "source context digest is invalid")
    require(isinstance(args.job_name, str) and 0 < len(args.job_name) <= 256
            and all(ord(character) >= 0x20 and ord(character) != 0x7f
                    for character in args.job_name),
            "source job name is invalid")
    for name in (args.payload_name, args.proof_name):
        require(isinstance(name, str) and artifact_origin.SEGMENT.fullmatch(name) is not None,
                "source artifact name is invalid")
    require(args.payload_name != args.proof_name,
            "payload and proof artifact names must be distinct")

    measured, raw = artifact_origin.normalized_file(args.source_context,
                                                     artifact_origin.MAX_METADATA)
    require(raw is not None and measured["sha256"] == args.source_context_sha256,
            "source context digest differs")
    context = artifact_origin.validate_context(artifact_origin.parse_json(raw))
    require(artifact_origin.canonical(context) == raw,
            "source context bytes are not canonical")
    return context, {"measurement": measured, "raw": raw, "lane": lane}


def select_owner_artifacts(args: argparse.Namespace) -> dict:
    """Resolve one independently named successful job and its two artifacts."""
    context, snapshot = _preflight(args)

    job_pages = artifact_origin.jobs_for(context)
    jobs = artifact_origin.complete_jobs(job_pages)
    named_jobs = [job for job in jobs if job.get("name") == args.job_name]
    require(len(named_jobs) == 1,
            "source job name does not select exactly one attempt job")
    job_identity = {"id": artifact_origin.positive(named_jobs[0].get("id")),
                    "name": args.job_name}
    selected_job = artifact_origin.select_source_job(job_pages, context, job_identity)

    artifact_pages = artifact_origin.gh_json(
        ["api", "--paginate", "--slurp",
         f'repos/{context["repository"]}/actions/runs/{context["run_id"]}/artifacts?per_page=100'],
        "source run artifacts lookup",
    )
    artifacts = complete_artifacts(artifact_pages)

    selected_artifacts = []
    for name in (args.payload_name, args.proof_name):
        matches = [item for item in artifacts if item.get("name") == name]
        require(len(matches) == 1,
                "requested artifact name does not select exactly one run artifact")
        provider_item = matches[0]
        selected = artifact_origin.select_artifact(
            provider_item, context, artifact_origin.positive(provider_item.get("id")),
            name, _artifact_digest(provider_item),
        )
        selected_artifacts.append(selected)

    payload, proof = selected_artifacts
    require(payload["id"] != proof["id"] and payload["name"] != proof["name"],
            "payload and proof must have separate artifact identities")
    require(proof["size_in_bytes"] <= 2 * artifact_origin.MAX_METADATA,
            "proof artifact exceeds the metadata byte limit")

    result = {
        "schema": artifact_origin.SELECTION_SCHEMA,
        "context": context,
        "selection": snapshot["lane"],
        "job": {"id": selected_job["id"], "name": selected_job["name"]},
        "artifact": payload,
        "proof": proof,
    }

    measured_again, raw_again = artifact_origin.normalized_file(
        args.source_context, artifact_origin.MAX_METADATA)
    require(measured_again == snapshot["measurement"] and raw_again == snapshot["raw"],
            "source context changed during provider selection")
    return result


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--source-context", required=True, type=Path)
    result.add_argument("--source-context-sha256", required=True)
    result.add_argument("--job-name", required=True)
    result.add_argument("--payload-name", required=True)
    result.add_argument("--proof-name", required=True)
    result.add_argument("--role", required=True)
    result.add_argument("--group", required=True)
    result.add_argument("--host", required=True)
    result.add_argument("--profile", required=True)
    result.add_argument("--copy", required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    try:
        arguments = sys.argv[1:] if argv is None else argv
        flags = [argument.split("=", 1)[0] for argument in arguments
                 if argument.startswith("--")]
        require(len(flags) == len(set(flags)), "duplicate argument selector")
        args = parser().parse_args(arguments)
        result = select_owner_artifacts(args)
        sys.stdout.write(artifact_origin.canonical(result).decode("utf-8"))
        return 0
    except artifact_origin.OriginError as exc:
        print(f"owner artifact selection failed: {exc}", file=sys.stderr)
        return 1
    except Exception:
        # Provider response bodies and unexpected exception details stay private.
        print("owner artifact selection failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
