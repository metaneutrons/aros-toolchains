#!/usr/bin/env python3
"""Read one signed observation from the last successful SDK run on this branch."""

import hashlib
import importlib.util
import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "artifact_origin", Path(__file__).with_name("artifact-origin.py")
)
origin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(origin)

SUBJECT = "sdk-reuse-observation.json"
BUNDLE = "observation.sigstore.json"
SCHEMA = "aros-sdk-reuse-observation-v1"


def select_baseline(caller, workflow_number):
    # GitHub orders runs newest first. A rerun must not select a newer workflow number.
    repo = caller["repository"]
    workflow = Path(caller["workflow"]).name
    page = 1
    while True:
        runs = origin.gh_json(
            [
                "api",
                "--method",
                "GET",
                f"repos/{repo}/actions/workflows/{workflow}/runs",
                "-f",
                "branch=" + caller["source_ref"].removeprefix("refs/heads/"),
                "-f",
                "status=success",
                "-f",
                "event=workflow_dispatch",
                "-f",
                "per_page=100",
                "-f",
                f"page={page}",
            ]
        )["workflow_runs"]
        candidates = [r for r in runs if r["run_number"] < workflow_number]
        if candidates:
            run = max(candidates, key=lambda r: r["run_number"])
            source = dict(
                caller, run_id=run["id"], run_attempt=run["run_attempt"], producer_commit=run["head_sha"]
            )
            origin.require(
                origin.observe_run_event(source, require_success=True) == "workflow_dispatch",
                "previous SDK run has a different event",
            )
            return source
        if len(runs) < 100:
            return None
        page += 1


def authenticate(source, artifact, root):
    name = f"sdk-reuse-{source['run_id']}-{source['run_attempt']}"
    selected = origin.select_artifact(
        artifact, source, artifact["id"], name, artifact["digest"].removeprefix("sha256:")
    )
    origin.require(
        selected["size_in_bytes"] <= 2 * origin.MAX_METADATA, "SDK observation ZIP exceeds size bound"
    )
    archive = root / "bundle.zip"
    origin.download_payload(source, selected, archive)
    measured, _ = origin.normalized_file(archive, 2 * origin.MAX_METADATA)
    origin.require(
        measured == {"size": selected["size_in_bytes"], "sha256": selected["sha256"]},
        "SDK observation download differs from provider digest",
    )
    with zipfile.ZipFile(archive) as z:
        origin.require(
            sorted(z.namelist()) == sorted((SUBJECT, BUNDLE)), "unexpected SDK observation ZIP inventory"
        )
        for name in (SUBJECT, BUNDLE):
            origin.require(
                0 < z.getinfo(name).file_size <= origin.MAX_METADATA, "SDK observation member exceeds limit"
            )
            (root / name).write_bytes(z.read(name))
    subject = root / SUBJECT
    raw = subject.read_bytes()
    origin.verify_signed_subject(subject, hashlib.sha256(raw).hexdigest(), root / BUNDLE, source)
    data = origin.parse_json(raw)
    origin.require(
        raw == origin.canonical(data) and data["schema"] == SCHEMA and data["context"] == source,
        "SDK baseline record format or context differs",
    )
    return data


def baseline():
    caller = origin.context_from_environment(origin.SPLIT_SDK_WORKFLOW)
    source = select_baseline(caller, int(os.environ["GITHUB_RUN_NUMBER"]))
    if source is None:
        return None
    name = f"sdk-reuse-{source['run_id']}-{source['run_attempt']}"
    response = origin.gh_json(
        [
            "api",
            "--method",
            "GET",
            f"repos/{source['repository']}/actions/runs/{source['run_id']}/artifacts",
            "-f",
            f"name={name}",
        ]
    )
    rows = [r for r in response["artifacts"] if r["name"] == name]
    if not rows or (len(rows) == 1 and rows[0]["expired"]):
        return None
    origin.require(len(rows) == 1, "ambiguous SDK observation artifact")
    with tempfile.TemporaryDirectory() as tmp:
        return authenticate(source, rows[0], Path(tmp).resolve())


if __name__ == "__main__":
    try:
        sys.stdout.buffer.write(origin.canonical(baseline()))
    except (
        origin.OriginError,
        OSError,
        KeyError,
        TypeError,
        ValueError,
        subprocess.SubprocessError,
        zipfile.BadZipFile,
    ) as exc:
        sys.exit(f"SDK baseline verification failed: {exc}")
