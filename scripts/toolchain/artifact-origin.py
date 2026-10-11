#!/usr/bin/env python3
"""Job-bound Actions artifact transport, not compiler or release qualification.

The writer obtains its job check ID directly from the authenticated runner OIDC
endpoint. It never persists or prints the token. Its record must subsequently
be signed on that owning job. The reader verifies that signature, provider job
and artifact metadata, and the exact downloaded ZIP/file bytes independently.
No API artifact field is invented to stand for an owning job or run attempt.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import zipfile

SCHEMA = "aros-toolchain-artifact-origin-v1"
SELECTION_SCHEMA = "aros-toolchain-artifact-selection-v1"
AUDIENCE = "aros-toolchain-artifact-origin"
MAX_METADATA = 16 * 1024 * 1024
MAX_PAYLOAD = 32 * 1024 * 1024 * 1024
MAX_FILES = 8192
SEGMENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
PROFILE = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")


class OriginError(Exception):
    """A closed transport boundary rejected an observation."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise OriginError(message)


def positive(value: object) -> int:
    require(type(value) in (str, int), "provider identity must be a canonical integer")
    text = str(value)
    require(bool(re.fullmatch(r"[1-9][0-9]{0,15}", text)), "provider identity is not canonical")
    number = int(text)
    require(number <= 9007199254740991, "provider identity exceeds the exact integer limit")
    return number


def duplicate_free(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        require(key not in result, "metadata contains a duplicate object key")
        result[key] = value
    return result


def parse_json(raw: bytes) -> object:
    require(len(raw) <= MAX_METADATA, "metadata exceeds its byte limit")
    try:
        return json.loads(raw, object_pairs_hook=duplicate_free,
                          parse_constant=lambda _: (_ for _ in ()).throw(OriginError("nonfinite JSON")))
    except (ValueError, UnicodeError):
        raise OriginError("metadata is not valid closed JSON") from None


def exact_keys(value: object, keys: set[str]) -> dict:
    require(isinstance(value, dict) and set(value) == keys, "origin metadata has unexpected fields")
    return value


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode() + b"\n"


def validate_context(value: object) -> dict:
    ctx = exact_keys(value, {"repository", "repository_id", "producer_commit", "source_ref",
                             "workflow", "run_id", "run_attempt"})
    repository, source, ref, workflow = (ctx[key] for key in
                                       ("repository", "producer_commit", "source_ref", "workflow"))
    require(all(isinstance(item, str) for item in (repository, source, ref, workflow)),
            "workflow/source selectors must be strings")
    require(bool(re.fullmatch(r"[A-Za-z0-9._-]+/[A-Za-z0-9._-]+", repository)), "repository is invalid")
    require(bool(re.fullmatch(r"[0-9a-f]{40}", source)), "producer commit is invalid")
    require(bool(re.fullmatch(r"refs/(heads|tags)/[A-Za-z0-9._/-]+", ref)), "source ref is invalid")
    require(bool(re.fullmatch(r"\.github/workflows/[A-Za-z0-9_-]+\.yml", workflow)), "workflow path is invalid")
    for key in ("repository_id", "run_id", "run_attempt"):
        require(type(ctx[key]) is int and positive(ctx[key]) == ctx[key],
                "selected provider identity is not an integer")
    return ctx


def context_from_environment(workflow: str) -> dict:
    return validate_context({
        "repository": os.environ.get("GITHUB_REPOSITORY", ""),
        "repository_id": positive(os.environ.get("GITHUB_REPOSITORY_ID", "")),
        "producer_commit": os.environ.get("GITHUB_SHA", ""),
        "source_ref": os.environ.get("GITHUB_REF", ""),
        "workflow": workflow,
        "run_id": positive(os.environ.get("GITHUB_RUN_ID", "")),
        "run_attempt": positive(os.environ.get("GITHUB_RUN_ATTEMPT", "")),
    })


def require_oidc_claims(claims: dict, context: dict, now: int) -> int:
    require(isinstance(claims, dict), "OIDC claims are not an object")
    require(claims.get("iss") == "https://token.actions.githubusercontent.com"
            and claims.get("aud") == AUDIENCE, "OIDC issuer or audience differs")
    for key in ("repository", "sha", "ref", "workflow_ref", "workflow_sha", "runner_environment"):
        expected = {
            "repository": context["repository"], "sha": context["producer_commit"],
            "ref": context["source_ref"],
            "workflow_ref": f'{context["repository"]}/{context["workflow"]}@{context["source_ref"]}',
            "workflow_sha": context["producer_commit"], "runner_environment": "github-hosted",
        }[key]
        require(claims.get(key) == expected, "OIDC workflow/source/runner binding differs")
    for key in ("repository_id", "run_id", "run_attempt"):
        require(positive(claims.get(key)) == context[key], "OIDC provider identity differs")
    if "job_workflow_ref" in claims or "job_workflow_sha" in claims:
        # Emit only closed classifications, never arbitrary claims or a JWT.
        # Live direct-job issuance includes this pair for the calling file.
        # Admit only that exact self-reference; called workflows need their
        # own independently approved policy, not a presence/absence heuristic.
        def identity_shape(key: str, expected: str) -> str:
            if key not in claims:
                return "absent"
            value = claims[key]
            if value is None:
                return "null"
            if not isinstance(value, str):
                return "non-string"
            if not value:
                return "empty"
            return "matches-caller" if value == expected else "differs"

        ref_shape = identity_shape("job_workflow_ref", claims["workflow_ref"])
        sha_shape = identity_shape("job_workflow_sha", context["producer_commit"])
        require(
            ref_shape == "matches-caller" and sha_shape == "matches-caller",
            "unapproved job workflow identity "
            f"(ref={ref_shape}, sha={sha_shape}); no token or claim values logged",
        )
    epochs = [claims.get(key) for key in ("iat", "nbf", "exp")]
    require(all(type(epoch) is int for epoch in epochs), "OIDC token times are invalid")
    issued, starts, expires = epochs
    require(0 < issued <= now + 30 and 0 < starts <= now + 30 < expires
            and issued <= expires <= issued + 3600, "OIDC token is expired or outside its time bound")
    return positive(claims.get("check_run_id"))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise OriginError("OIDC endpoint redirect is not permitted")


def owning_check_id(context: dict) -> int:
    """Read claims from the authenticated TLS issuer response, not a caller file.

    This is not a standalone JWT signature verifier. Trust depends on the
    approved workflow/runner and HTTPS issuance; the later Sigstore signature
    independently authenticates the workflow that created this record.
    """
    endpoint = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", "")
    bearer = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
    url = urllib.parse.urlsplit(endpoint)
    require(url.scheme == "https" and bool(url.hostname)
            and url.hostname.endswith(".actions.githubusercontent.com")
            and url.port in (None, 443) and not url.username and not url.password
            and not url.fragment and bool(bearer), "runner OIDC access is unavailable")
    query = urllib.parse.parse_qsl(url.query, keep_blank_values=True)
    require(not any(key == "audience" for key, _ in query), "OIDC audience is already selected")
    query.append(("audience", AUDIENCE))
    request = urllib.request.Request(
        urllib.parse.urlunsplit(url._replace(query=urllib.parse.urlencode(query))),
        headers={"Authorization": f"bearer {bearer}"},
    )
    try:
        with urllib.request.build_opener(NoRedirect).open(request, timeout=30) as response:
            raw = response.read(MAX_METADATA + 1)
        token = parse_json(raw)["value"]
        require(isinstance(token, str) and len(token) <= MAX_METADATA, "OIDC response is invalid")
        parts = token.split(".")
        require(len(parts) == 3, "OIDC response is not a JWT")
        def decode(part: str) -> object:
            return parse_json(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
        require(decode(parts[0]).get("alg") == "RS256", "OIDC response algorithm differs")
        return require_oidc_claims(decode(parts[1]), context, int(time.time()))
    except OriginError:
        raise
    except Exception:
        # Never expose response bodies, JWTs, request URLs or bearer values.
        raise OriginError("authenticated runner OIDC acquisition failed") from None


def gh_json(arguments: list[str], purpose: str = "GitHub observation") -> object:
    try:
        result = subprocess.run(["gh", *arguments], stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=90, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise OriginError("GitHub observation is unavailable") from None
    require(result.returncode == 0, f"{purpose} failed; no retry or credential fallback")
    return parse_json(result.stdout)


def jobs_for(context: dict) -> list:
    return gh_json(["api", "--paginate", "--slurp",
                    f'repos/{context["repository"]}/actions/runs/{context["run_id"]}'
                    f'/attempts/{context["run_attempt"]}/jobs?per_page=100'])


def complete_jobs(pages: list) -> list:
    require(isinstance(pages, list) and 0 < len(pages) <= 100, "job pages are invalid")
    totals = []
    jobs = []
    for page in pages:
        require(isinstance(page, dict) and isinstance(page.get("jobs"), list), "job page is invalid")
        totals.append(positive(page.get("total_count")))
        jobs.extend(page["jobs"])
    require(len(set(totals)) == 1 and len(jobs) == totals[0], "job pages are incomplete")
    require(all(isinstance(job, dict) for job in jobs), "job metadata is invalid")
    ids = [positive(job.get("id")) for job in jobs]
    require(len(set(ids)) == len(ids), "job pages repeat an identity")
    return jobs


def select_job(pages: list, context: dict, check_id: int, name: str, status: str) -> dict:
    jobs = complete_jobs(pages)
    check_url = f'https://api.github.com/repos/{context["repository"]}/check-runs/{check_id}'
    selected = [job for job in jobs if job.get("check_run_url") == check_url]
    require(len(selected) == 1, "OIDC check ID does not select exactly one owning job")
    job = selected[0]
    require(job.get("name") == name and job.get("head_sha") == context["producer_commit"]
            and positive(job.get("run_id")) == context["run_id"], "owning job identity differs")
    # Attempt membership comes from the attempt-specific endpoint. The REST
    # schema does not promise a run_attempt member on each job; if supplied,
    # it must agree rather than silently overriding that endpoint selection.
    if "run_attempt" in job:
        require(positive(job["run_attempt"]) == context["run_attempt"], "owning job attempt differs")
    require(job.get("status") == status, "owning job has the wrong execution state")
    require(job.get("conclusion") == ("success" if status == "completed" else None),
            "owning job did not succeed or is not currently executing")
    return {"id": positive(job["id"]), "check_run_id": check_id, "name": name}


def select_source_job(pages: list, context: dict, expected: dict) -> dict:
    """Select provider ownership before reading a signed origin's check ID."""
    jobs = complete_jobs(pages)
    selected = [job for job in jobs if positive(job.get("id")) == expected["id"]]
    require(len(selected) == 1 and selected[0].get("name") == expected["name"],
            "source job ID/name does not select one provider job")
    match = re.fullmatch(
        rf'https://api\.github\.com/repos/{re.escape(context["repository"])}/check-runs/([1-9][0-9]*)',
        selected[0].get("check_run_url", ""),
    )
    require(match is not None, "source job check URL is invalid")
    return select_job(pages, context, positive(match.group(1)), expected["name"], "completed")


def select_artifact(artifact: dict, context: dict, artifact_id: int, name: str, digest: str) -> dict:
    require(isinstance(artifact, dict), "artifact metadata is invalid")
    require(bool(re.fullmatch(r"[0-9a-f]{64}", digest)), "artifact digest is invalid")
    run = artifact.get("workflow_run")
    require(isinstance(run, dict), "artifact has no workflow identity")
    require(positive(artifact.get("id")) == artifact_id and artifact.get("name") == name
            and artifact.get("digest") == f"sha256:{digest}"
            and artifact.get("expired") is False, "artifact ID/name/digest/state differs")
    require(positive(run.get("id")) == context["run_id"]
            and run.get("head_sha") == context["producer_commit"]
            and positive(run.get("repository_id")) == context["repository_id"]
            and positive(run.get("head_repository_id")) == context["repository_id"],
            "artifact repository/run/source differs")
    size = positive(artifact.get("size_in_bytes"))
    require(size <= MAX_PAYLOAD, "provider artifact exceeds the byte limit")
    return {"id": artifact_id, "name": name, "sha256": digest, "size_in_bytes": size}


def normalized_file(path: Path, limit: int) -> tuple[dict, bytes | None]:
    require(path.is_absolute() and ".." not in path.parts, "path must be absolute and normalized")
    for parent in path.parents:
        require(not parent.is_symlink() and parent.is_dir(), "path has a linked or missing parent")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as handle:
        before = os.fstat(handle.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and 0 <= before.st_size <= limit, "input is not a bounded singly linked regular file")
        digest = hashlib.sha256()
        chunks = [] if limit == MAX_METADATA else None
        size = 0
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            size += len(block)
            require(size <= limit, "input grew beyond its byte limit")
            digest.update(block)
            if chunks is not None:
                chunks.append(block)
        after = os.fstat(handle.fileno())
        current = path.lstat()
        identity = lambda entry: (entry.st_dev, entry.st_ino, entry.st_size, entry.st_mtime_ns, entry.st_ctime_ns)
        require(identity(before) == identity(after) == identity(current) and size == before.st_size,
                "input changed while measured")
        return {"sha256": digest.hexdigest(), "size": size}, b"".join(chunks) if chunks is not None else None


def portable_path(name: str) -> bool:
    return isinstance(name, str) and 0 < len(name) <= 1024 and len(name.split("/")) <= 16 \
        and all(SEGMENT.fullmatch(part) and part not in (".", "..") for part in name.split("/"))


def require_portable_inventory(files: dict) -> None:
    """Reject aliases in file names and every implicit directory component."""
    require(isinstance(files, dict) and 0 < len(files) <= MAX_FILES, "signed file inventory is invalid")
    seen = {}
    for name in files:
        require(portable_path(name), "signed paths are unsafe")
        parts = name.split("/")
        for length in range(1, len(parts) + 1):
            prefix = "/".join(parts[:length])
            folded = prefix.lower()
            kind = "file" if length == len(parts) else "directory"
            require(folded not in seen or seen[folded] == (prefix, kind),
                    "signed paths are case-aliased or have file/directory conflicts")
            seen[folded] = (prefix, kind)


def measure_files(root: Path) -> dict:
    require(root.is_absolute() and root == root.resolve() and root.is_dir() and not root.is_symlink(),
            "payload root is not a canonical owned directory")
    result = {}
    portable_names = set()
    total = 0
    for parent, dirs, files in os.walk(root, followlinks=False):
        for name in dirs:
            entry = Path(parent, name)
            relative = entry.relative_to(root).as_posix()
            require(not entry.is_symlink() and portable_path(relative),
                    "payload directory is linked or nonportable")
            require(relative.lower() not in portable_names, "payload paths have a case-fold collision")
            portable_names.add(relative.lower())
        for name in files:
            path = Path(parent, name)
            relative = path.relative_to(root).as_posix()
            require(portable_path(relative) and len(result) < MAX_FILES, "payload inventory is unsafe or oversized")
            require(relative.lower() not in portable_names, "payload paths have a case-fold collision")
            portable_names.add(relative.lower())
            measured, _ = normalized_file(path, MAX_PAYLOAD)
            total += measured["size"]
            require(total <= MAX_PAYLOAD, "payload exceeds its aggregate byte limit")
            result[relative] = measured
    require(bool(result), "payload inventory is empty")
    return dict(sorted(result.items()))


def verify_zip(path: Path, files: dict, digest: str, size: int | None = None) -> None:
    measured, _ = normalized_file(path, MAX_PAYLOAD)
    require(measured["sha256"] == digest and (size is None or measured["size"] == size),
            "downloaded artifact ZIP digest or size differs")
    require_portable_inventory(files)
    seen = set()
    total = 0
    with zipfile.ZipFile(path) as archive:
        require(len(archive.infolist()) == len(files), "ZIP member count differs from signed files")
        for member in archive.infolist():
            name = member.filename
            require(member.orig_filename == name and "\x00" not in member.orig_filename
                    and portable_path(name) and name not in seen and name in files,
                    "ZIP contains a duplicate or unselected member")
            seen.add(name)
            mode = member.external_attr >> 16
            require(stat.S_IFMT(mode) in (0, stat.S_IFREG)
                    and not member.is_dir() and not (member.flag_bits & 1)
                    and member.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED),
                    "ZIP member is not an ordinary unencrypted file")
            expected = exact_keys(files[name], {"sha256", "size"})
            require(type(expected["size"]) is int and 0 <= expected["size"] == member.file_size <= MAX_PAYLOAD
                    and isinstance(expected["sha256"], str)
                    and bool(re.fullmatch(r"[0-9a-f]{64}", expected["sha256"])), "ZIP member measurement differs")
            size = 0
            sha = hashlib.sha256()
            with archive.open(member) as handle:
                for block in iter(lambda: handle.read(1024 * 1024), b""):
                    size += len(block)
                    require(size <= member.file_size, "ZIP member exceeds its declared size")
                    sha.update(block)
            total += size
            require(total <= MAX_PAYLOAD and size == expected["size"]
                    and sha.hexdigest() == expected["sha256"], "ZIP member bytes differ")
    require(normalized_file(path, MAX_PAYLOAD)[0] == measured, "artifact ZIP changed during verification")


def selection(args: argparse.Namespace) -> dict:
    result = {key: getattr(args, key) for key in ("role", "group", "host", "profile", "copy")}
    require(all(isinstance(value, str) and SEGMENT.fullmatch(value)
                for key, value in result.items() if key != "profile")
            and isinstance(result["profile"], str) and PROFILE.fullmatch(result["profile"])
            and result["profile"] not in (".", ".."),
            "artifact lane selection is invalid")
    require(result["role"] in ("build", "comparison", "compatibility", "diagnostic")
            and result["copy"] in ("a", "b", "none"), "artifact role/copy is invalid")
    require((result["role"] == "build") == (result["copy"] in ("a", "b")), "artifact copy does not match its role")
    return result


def record(args: argparse.Namespace, context: dict) -> None:
    output = args.output
    require(output.is_absolute() and not output.exists() and not output.is_symlink()
            and output.parent == output.parent.resolve() and output.parent.is_dir(), "origin output is not fresh")
    require(not output.is_relative_to(args.payload_dir), "origin must stay outside the payload")
    selected = selection(args)
    files = measure_files(args.payload_dir)
    check_id = owning_check_id(context)
    job = select_job(jobs_for(context), context, check_id, args.job_name, "in_progress")
    artifact = gh_json(["api", f'repos/{context["repository"]}/actions/artifacts/{args.artifact_id}'])
    metadata = select_artifact(artifact, context, args.artifact_id, args.artifact_name, args.artifact_sha256)
    require(files == measure_files(args.payload_dir), "payload changed before origin recording")
    origin = {"schema": SCHEMA, "context": context, "selection": selected,
              "job": job, "artifact": metadata, "files": files}
    # Owned, quiescent runner root. Exclusive creation never replaces an output.
    with output.open("xb") as handle:
        handle.write(canonical(origin))
    print("Recorded unsigned owning-job observation; signature and independent verification remain required.")


def verify(args: argparse.Namespace, context: dict, *, expected_job: dict | None = None,
           expected_artifact: dict | None = None,
           payload_archive: Path | None = None, report: bool = True) -> None:
    measured, raw = normalized_file(args.origin, MAX_METADATA)
    bundle_measurement, _ = normalized_file(args.bundle, MAX_METADATA)
    require(args.origin != args.bundle, "origin and signature bundle must be separate files")
    origin = exact_keys(parse_json(raw), {"schema", "context", "selection", "job", "artifact", "files"})
    require(origin["schema"] == SCHEMA and canonical(origin["context"]) == canonical(context)
            and origin["selection"] == selection(args), "signed origin differs from independent selection")
    job = exact_keys(origin["job"], {"id", "check_run_id", "name"})
    artifact = exact_keys(origin["artifact"], {"id", "name", "sha256", "size_in_bytes"})
    require(expected_job is None or job == expected_job,
            "signed owner differs from independently selected source job")
    require(expected_artifact is None or artifact == expected_artifact,
            "signed payload differs from independently selected source artifact")
    for identity in (job["id"], job["check_run_id"], artifact["id"], artifact["size_in_bytes"]):
        require(type(identity) is int and positive(identity) == identity, "signed identity is not an integer")
    require(job["name"] == args.job_name and artifact["id"] == args.artifact_id
            and artifact["name"] == args.artifact_name, "signed job/artifact selection differs")
    verified = gh_json([
        "attestation", "verify", str(args.origin), "--bundle", str(args.bundle),
        "--repo", context["repository"], "--signer-workflow", f'{context["repository"]}/{context["workflow"]}',
        "--signer-digest", context["producer_commit"],
        "--source-digest", context["producer_commit"], "--source-ref", context["source_ref"],
        "--deny-self-hosted-runners", "--format", "json",
    ], "origin signature authentication")
    invocation = f'https://github.com/{context["repository"]}/actions/runs/{context["run_id"]}/attempts/{context["run_attempt"]}'
    require(isinstance(verified, list) and len(verified) == 1, "origin must have one verified signature result")
    result = verified[0]["verificationResult"]
    require(result["signature"]["certificate"]["runInvocationURI"] == invocation,
            "origin certificate differs from the exact run attempt")
    require(result["statement"]["subject"] == [{"name": args.origin.name, "digest": {"sha256": measured["sha256"]}}],
            "origin attestation subject differs from the exact record bytes")
    require(select_job(jobs_for(context), context, positive(job["check_run_id"]), args.job_name, "completed") == job,
            "completed owning job differs from signed origin")
    observed = gh_json(["api", f'repos/{context["repository"]}/actions/artifacts/{args.artifact_id}'])
    require(select_artifact(observed, context, args.artifact_id, args.artifact_name, artifact["sha256"]) == artifact,
            "provider artifact differs from signed origin")
    # Fetch by numeric identity, not a glob/name or an untrusted download URL.
    # A source reader may supply its private temporary archive so that the
    # exact verified transport remains available until its final context
    # readbacks complete. Ordinary verify callers keep the original cleanup.
    if payload_archive is None:
        with tempfile.TemporaryDirectory(prefix="aros-artifact-origin-") as temporary:
            archive = Path(temporary).resolve() / "payload.zip"
            download_payload(context, artifact, archive)
            verify_zip(archive, origin["files"], artifact["sha256"], artifact["size_in_bytes"])
    else:
        require(payload_archive.is_absolute() and payload_archive.parent == payload_archive.parent.resolve()
                and payload_archive.parent.is_dir() and not payload_archive.parent.is_symlink()
                and not payload_archive.exists() and not payload_archive.is_symlink(),
                "verified payload temporary path is not fresh and canonical")
        download_payload(context, artifact, payload_archive)
        verify_zip(payload_archive, origin["files"], artifact["sha256"], artifact["size_in_bytes"])
    require(normalized_file(args.origin, MAX_METADATA)[0] == measured, "origin changed during verification")
    require(normalized_file(args.bundle, MAX_METADATA)[0] == bundle_measurement,
            "signature bundle changed during verification")
    if report:
        print("Verified owning workflow/run-attempt/job and exact artifact ZIP/file bytes; not release qualification.")


def source_selection(value: object, caller: dict, *, same_attempt: bool = False) -> dict:
    """Validate a caller-owned plan, never a selection inferred from origin.json."""
    require(type(same_attempt) is bool, "same-attempt selector must be boolean")
    selected = exact_keys(value, {"schema", "context", "selection", "job", "artifact", "proof"})
    require(selected["schema"] == SELECTION_SCHEMA, "source selection schema differs")
    source = validate_context(selected["context"])
    require(source["repository"] == caller["repository"]
            and source["repository_id"] == caller["repository_id"],
            "cross-repository artifact recovery is not admitted")
    if same_attempt:
        require(source == caller, "same-attempt source context must exactly match current caller")
    else:
        require((source["run_id"], source["run_attempt"]) != (caller["run_id"], caller["run_attempt"]),
                "source attempt must differ from the current caller attempt")
    lane = exact_keys(selected["selection"], {"role", "group", "host", "profile", "copy"})
    require(selection(argparse.Namespace(**lane)) == lane, "source lane differs")
    job = exact_keys(selected["job"], {"id", "name"})
    require(type(job["id"]) is int and positive(job["id"]) == job["id"]
            and isinstance(job["name"], str) and 0 < len(job["name"]) <= 256,
            "source job selection is invalid")
    for key in ("artifact", "proof"):
        item = exact_keys(selected[key], {"id", "name", "sha256", "size_in_bytes"})
        require(all(type(item[field]) is int and positive(item[field]) == item[field]
                    for field in ("id", "size_in_bytes"))
                and item["size_in_bytes"] <= (2 * MAX_METADATA if key == "proof" else MAX_PAYLOAD)
                and isinstance(item["name"], str) and bool(SEGMENT.fullmatch(item["name"]))
                and isinstance(item["sha256"], str) and bool(re.fullmatch(r"[0-9a-f]{64}", item["sha256"])),
                "source artifact selection is invalid")
    require(selected["artifact"]["id"] != selected["proof"]["id"]
            and selected["artifact"]["name"] != selected["proof"]["name"],
            "payload and proof must have separate artifact identities")
    return selected


def download_payload(context: dict, artifact: dict, archive: Path) -> None:
    """Bound payload writes before the GET, not only during ZIP verification."""
    require(type(artifact["size_in_bytes"]) is int
            and 0 < artifact["size_in_bytes"] <= MAX_PAYLOAD,
            "payload download size is invalid")
    limit = artifact["size_in_bytes"] + 1
    with archive.open("xb") as handle:
        command = subprocess.run(["gh", "api", f'repos/{context["repository"]}/actions/artifacts/{artifact["id"]}/zip'],
                                 stdout=handle, stderr=subprocess.DEVNULL, timeout=180, check=False,
                                 preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit)))
    require(command.returncode == 0, "numeric artifact download failed")


def download_proof(context: dict, proof: dict, archive: Path) -> None:
    """Numeric proof transport with a kernel byte cap before the GET."""
    require(type(proof["size_in_bytes"]) is int and 0 < proof["size_in_bytes"] <= 2 * MAX_METADATA,
            "proof download size is invalid")
    with archive.open("xb") as handle:
        # All supported reader hosts are Unix. Cap child regular-file writes
        # before downloading; a small declared proof must not exhaust disk.
        limit = proof["size_in_bytes"] + 1
        command = subprocess.run(["gh", "api", f'repos/{context["repository"]}/actions/artifacts/{proof["id"]}/zip'],
                                 stdout=handle, stderr=subprocess.DEVNULL, timeout=180, check=False,
                                 preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit)))
    require(command.returncode == 0, "numeric proof artifact download failed")


def proof_members(archive: Path, proof: dict) -> dict[str, bytes]:
    """Read two bounded ordinary members, never extract untrusted ZIP paths."""
    measured, _ = normalized_file(archive, 2 * MAX_METADATA)
    require(measured == {"sha256": proof["sha256"], "size": proof["size_in_bytes"]},
            "downloaded proof ZIP digest or size differs")
    contents = {}
    with zipfile.ZipFile(archive) as handle:
        members = handle.infolist()
        require(len(members) == 2 and {item.filename for item in members} ==
                {"origin.json", "origin.sigstore.json"}, "proof ZIP must contain exactly two selected files")
        for item in members:
            mode = item.external_attr >> 16
            require(item.orig_filename == item.filename and "\x00" not in item.orig_filename
                    and 0 <= item.file_size <= MAX_METADATA
                    and stat.S_IFMT(mode) in (0, stat.S_IFREG)
                    and not item.is_dir() and not (item.flag_bits & 1)
                    and item.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED),
                    "proof ZIP member is not a bounded ordinary file")
            with handle.open(item) as member:
                raw = member.read(MAX_METADATA + 1)
            require(len(raw) == item.file_size <= MAX_METADATA, "proof ZIP member size differs")
            contents[item.filename] = raw
    files = {name: {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}
             for name, raw in contents.items()}
    verify_zip(archive, files, proof["sha256"], proof["size_in_bytes"])
    return contents


def verified_output_preflight(output: object, inputs: list[Path | None]) -> Path:
    """Reject unsafe retention targets before the reader performs provider I/O."""
    require(isinstance(output, Path) and output.is_absolute() and ".." not in output.parts
            and output.name not in ("", ".", ".."),
            "verified output directory must be an absolute normalized path")
    for path in inputs:
        if path is None:
            continue
        require(isinstance(path, Path) and path.is_absolute() and ".." not in path.parts,
                "verified output inputs must be absolute normalized paths")
        require(output != path and output not in path.parents and path not in output.parents,
                "verified output directory overlaps a selected input")
    parent = output.parent
    require(parent == parent.resolve() and parent.is_dir() and not parent.is_symlink(),
            "verified output parent must be an existing canonical directory")
    try:
        output.lstat()
    except FileNotFoundError:
        pass
    else:
        raise OriginError("verified output directory must be fresh")
    return output


def _inode_identity(entry: os.stat_result) -> tuple[int, int]:
    return entry.st_dev, entry.st_ino


def _private_owned(entry: os.stat_result) -> bool:
    return entry.st_uid == os.geteuid() and not (stat.S_IMODE(entry.st_mode) & 0o077)


def _write_retained_file(root_fd: int, name: str, source: bytes | Path,
                         expected: dict, limit: int, created: dict[str, tuple[int, int]]) -> None:
    """Create an exclusive owner-only file and bind the copied bytes to a prior measurement."""
    require(set(expected) == {"sha256", "size"} and type(expected["size"]) is int
            and 0 <= expected["size"] <= limit
            and isinstance(expected["sha256"], str)
            and bool(re.fullmatch(r"[0-9a-f]{64}", expected["sha256"])),
            "verified output measurement is invalid")
    output_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    output_fd = os.open(name, output_flags, 0o600, dir_fd=root_fd)
    source_fd = None
    try:
        output_before = os.fstat(output_fd)
        created[name] = _inode_identity(output_before)
        os.fchmod(output_fd, 0o600)
        output_before = os.fstat(output_fd)
        require(stat.S_ISREG(output_before.st_mode) and output_before.st_nlink == 1
                and _private_owned(output_before), "verified output file is not private and ordinary")
        if isinstance(source, Path):
            source_fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            source_before = os.fstat(source_fd)
            named_before = source.lstat()
            require(stat.S_ISREG(source_before.st_mode) and source_before.st_nlink == 1
                    and _inode_identity(source_before) == _inode_identity(named_before)
                    and 0 <= source_before.st_size <= limit
                    and source_before.st_size == expected["size"],
                    "verified temporary payload is not an exact ordinary file")
            source_handle = os.fdopen(source_fd, "rb")
            source_fd = None
        else:
            require(isinstance(source, bytes) and len(source) <= limit,
                    "verified metadata bytes exceed their limit")
            source_before = None
            named_before = None
            source_handle = None

        digest = hashlib.sha256()
        size = 0
        with os.fdopen(output_fd, "wb") as target:
            output_fd = -1
            def write_block(block: bytes) -> None:
                nonlocal size
                size += len(block)
                require(size <= limit and size <= expected["size"],
                        "verified output exceeded its selected byte size")
                digest.update(block)
                view = memoryview(block)
                while view:
                    written = target.write(view)
                    require(written is not None and written > 0,
                            "verified output write was incomplete")
                    view = view[written:]

            if source_handle is None:
                assert isinstance(source, bytes)
                for offset in range(0, len(source), 1024 * 1024):
                    write_block(source[offset:offset + 1024 * 1024])
            else:
                with source_handle:
                    for block in iter(lambda: source_handle.read(1024 * 1024), b""):
                        write_block(block)
                    source_after = os.fstat(source_handle.fileno())
                named_after = source.lstat()
                source_identity = lambda entry: (entry.st_dev, entry.st_ino, entry.st_size,
                                                 entry.st_mtime_ns, entry.st_ctime_ns)
                require(source_identity(source_before) == source_identity(source_after)
                        == source_identity(named_before) == source_identity(named_after),
                        "verified temporary payload changed while retaining it")
            target.flush()
            os.fsync(target.fileno())
            output_after = os.fstat(target.fileno())
            named_output = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
            require(stat.S_ISREG(output_after.st_mode) and output_after.st_nlink == 1
                    and _private_owned(output_after)
                    and _inode_identity(output_before) == _inode_identity(output_after)
                    == _inode_identity(named_output) and output_after.st_size == size,
                    "verified output file changed while writing")
        require({"sha256": digest.hexdigest(), "size": size} == expected,
                "retained bytes differ from their independently verified identity")
    finally:
        if output_fd >= 0:
            os.close(output_fd)
        if source_fd is not None:
            os.close(source_fd)


def _measure_retained_file(root_fd: int, name: str, limit: int) -> dict:
    descriptor = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=root_fd)
    with os.fdopen(descriptor, "rb") as handle:
        before = os.fstat(handle.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and _private_owned(before)
                and 0 <= before.st_size <= limit,
                "retained output is not a bounded private ordinary file")
        digest = hashlib.sha256()
        size = 0
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            size += len(block)
            require(size <= limit, "retained output exceeded its byte limit")
            digest.update(block)
        after = os.fstat(handle.fileno())
    named = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
    identity = lambda entry: (entry.st_dev, entry.st_ino, entry.st_size,
                              entry.st_mtime_ns, entry.st_ctime_ns)
    require(identity(before) == identity(after) == identity(named) and size == before.st_size,
            "retained output changed while remeasured")
    return {"sha256": digest.hexdigest(), "size": size}


def _cleanup_retained_output(parent_fd: int, name: str, root_fd: int | None,
                             root_identity: tuple[int, int] | None,
                             created: dict[str, tuple[int, int]]) -> bool:
    """Remove only files whose inodes this call created, and only its own empty root."""
    if root_fd is not None:
        for filename, identity in created.items():
            try:
                current = os.stat(filename, dir_fd=root_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            except OSError:
                return False
            if not (stat.S_ISREG(current.st_mode) and current.st_nlink == 1
                    and _inode_identity(current) == identity):
                return False
            try:
                os.unlink(filename, dir_fd=root_fd)
            except OSError:
                return False
        try:
            if os.listdir(root_fd):
                return False
        except OSError:
            return False
    try:
        current_root = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    if not stat.S_ISDIR(current_root.st_mode) or root_identity is None \
            or _inode_identity(current_root) != root_identity:
        return False
    if root_fd is None:
        try:
            probe_fd = os.open(name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                               | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
            try:
                if os.listdir(probe_fd):
                    return False
            finally:
                os.close(probe_fd)
        except OSError:
            return False
    try:
        os.rmdir(name, dir_fd=parent_fd)
        return True
    except OSError:
        return False


def retain_verified_output(output: Path, sources: dict[str, bytes | Path],
                           expected: dict[str, dict], limits: dict[str, int],
                           final_check) -> None:
    """Retain four exact files in a new private directory, or report failure."""
    names = {"payload.zip", "origin.json", "origin.sigstore.json", "selection.json"}
    require(set(sources) == names and set(expected) == names and set(limits) == names,
            "verified output inventory is not closed")
    # Recheck immediately before creation. mkdirat is exclusive, so a path
    # created after preflight can never be overwritten.
    output = verified_output_preflight(output, [])
    parent_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        parent_fd = os.open(output.parent, parent_flags)
    except OSError:
        raise OriginError("verified output parent is unavailable") from None
    root_fd = None
    root_identity = None
    created: dict[str, tuple[int, int]] = {}
    made_root = False
    try:
        parent_before = os.fstat(parent_fd)
        parent_named = output.parent.lstat()
        require(stat.S_ISDIR(parent_before.st_mode) and not output.parent.is_symlink()
                and output.parent == output.parent.resolve()
                and _inode_identity(parent_before) == _inode_identity(parent_named),
                "verified output parent changed after preflight")
        try:
            os.mkdir(output.name, mode=0o700, dir_fd=parent_fd)
        except FileExistsError:
            raise OriginError("verified output directory must remain fresh") from None
        made_root = True
        root_named = os.stat(output.name, dir_fd=parent_fd, follow_symlinks=False)
        root_identity = _inode_identity(root_named)
        require(stat.S_ISDIR(root_named.st_mode) and _private_owned(root_named),
                "verified output root is not an owner-only directory")
        os.chmod(output.name, 0o700, dir_fd=parent_fd, follow_symlinks=False)
        root_named = os.stat(output.name, dir_fd=parent_fd, follow_symlinks=False)
        require(_inode_identity(root_named) == root_identity and stat.S_ISDIR(root_named.st_mode)
                and _private_owned(root_named), "verified output root changed while securing permissions")
        root_fd = os.open(output.name, parent_flags, dir_fd=parent_fd)
        root_open = os.fstat(root_fd)
        require(_inode_identity(root_open) == root_identity and stat.S_ISDIR(root_open.st_mode)
                and _private_owned(root_open), "verified output root changed during creation")
        for name in ("payload.zip", "origin.json", "origin.sigstore.json", "selection.json"):
            _write_retained_file(root_fd, name, sources[name], expected[name], limits[name], created)
        require(set(os.listdir(root_fd)) == names,
                "verified output contains an unexpected directory entry")
        for name in names:
            require(_measure_retained_file(root_fd, name, limits[name]) == expected[name],
                    "retained output differs from its verified identity")
        final_check()
        root_final = os.stat(output.name, dir_fd=parent_fd, follow_symlinks=False)
        require(_inode_identity(root_final) == root_identity and stat.S_ISDIR(root_final.st_mode)
                and _private_owned(root_final), "verified output root changed before completion")
        parent_final = os.stat(output.parent, follow_symlinks=False)
        require(_inode_identity(parent_final) == _inode_identity(parent_before)
                and output.parent == output.parent.resolve(),
                "verified output parent changed before completion")
    except Exception as error:
        cleaned = (_cleanup_retained_output(parent_fd, output.name, root_fd,
                                            root_identity, created) if made_root else True)
        if not cleaned:
            raise OriginError("verified output failed; an incomplete owned directory may need cleanup") from None
        if isinstance(error, OriginError):
            raise
        raise OriginError("verified output retention failed") from None
    finally:
        if root_fd is not None:
            os.close(root_fd)
        os.close(parent_fd)


def verify_source(args: argparse.Namespace, caller: dict) -> None:
    verified_output = getattr(args, "verified_output_dir", None)
    if verified_output is not None:
        verified_output = verified_output_preflight(
            verified_output, [args.source_selection, args.origin, args.bundle])
    plan_measurement, selection_raw = normalized_file(args.source_selection, MAX_METADATA)
    # Preserve diagnostic/internal Namespace callers created before this
    # optional mode existed.
    same_attempt = getattr(args, "same_attempt", False)
    selected = source_selection(parse_json(selection_raw), caller, same_attempt=same_attempt)
    local = args.origin is not None or args.bundle is not None
    require(not local or (args.origin is not None and args.bundle is not None),
            "local origin and bundle must be supplied together")
    if local:
        require(args.origin.name == "origin.json" and args.bundle.name == "origin.sigstore.json",
                "cross-run proof must use the closed origin/signature file names")
        origin_measurement, _ = normalized_file(args.origin, MAX_METADATA)
        bundle_measurement, _ = normalized_file(args.bundle, MAX_METADATA)
        require(args.origin != args.bundle and args.source_selection not in (args.origin, args.bundle),
                "source selection, origin and bundle must be separate files")
    # Authenticate the CURRENT reader independently. Never spoof GITHUB_* to
    # resemble the original owner, or select the caller from a source record.
    require(os.environ.get("GITHUB_WORKFLOW_REF") ==
            f'{caller["repository"]}/{caller["workflow"]}@{caller["source_ref"]}'
            and os.environ.get("GITHUB_WORKFLOW_SHA") == caller["producer_commit"],
            "current caller workflow identity differs")
    caller_check = owning_check_id(caller)
    caller_job = select_job(jobs_for(caller), caller, caller_check, args.job_name, "in_progress")
    source = selected["context"]
    if same_attempt:
        require(selected["job"]["id"] != caller_job["id"],
                "same-attempt source owner must be a different job")
    owner = select_source_job(jobs_for(source), source, selected["job"])
    proof = selected["proof"]
    observed = gh_json(["api", f'repos/{source["repository"]}/actions/artifacts/{proof["id"]}'])
    require(select_artifact(observed, source, proof["id"], proof["name"], proof["sha256"]) == proof,
            "provider proof differs from independently selected source artifact")
    # Keep both raw transport archives under one private temporary root. The
    # optional retained payload remains there until final input/context checks
    # pass; nothing is extracted from the payload ZIP.
    with tempfile.TemporaryDirectory(prefix="aros-artifact-proof-") as temporary:
        temporary_root = Path(temporary).resolve()
        archive = temporary_root / "proof.zip"
        download_proof(source, proof, archive)
        contents = proof_members(archive, proof)
        if local:
            verify_zip(archive, {"origin.json": origin_measurement,
                                 "origin.sigstore.json": bundle_measurement},
                       proof["sha256"], proof["size_in_bytes"])
            origin_path, bundle_path = args.origin, args.bundle
        else:
            for name, member_bytes in contents.items():
                with (archive.parent / name).open("xb") as handle:
                    handle.write(member_bytes)
            origin_path, bundle_path = archive.parent / "origin.json", archive.parent / "origin.sigstore.json"
        payload = selected["artifact"]
        source_args = argparse.Namespace(**selected["selection"],
                                         job_name=selected["job"]["name"],
                                         artifact_id=payload["id"], artifact_name=payload["name"],
                                         origin=origin_path, bundle=bundle_path)
        payload_archive = temporary_root / "payload.zip" if verified_output is not None else None
        verify(source_args, source, expected_job=owner, expected_artifact=payload,
               payload_archive=payload_archive, report=False)

        def final_check() -> None:
            require(normalized_file(args.source_selection, MAX_METADATA)[0] == plan_measurement,
                    "source selection changed during verification")
            require(normalized_file(archive, 2 * MAX_METADATA)[0] == {
                "sha256": proof["sha256"], "size": proof["size_in_bytes"]},
                "source proof archive changed during verification")
            require(not local or (normalized_file(args.origin, MAX_METADATA)[0] == origin_measurement
                    and normalized_file(args.bundle, MAX_METADATA)[0] == bundle_measurement),
                    "source proof changed during verification")
            require(context_from_environment(args.workflow) == caller,
                    "current caller context changed")

        final_check()
        if verified_output is not None:
            assert payload_archive is not None
            identities = {
                "payload.zip": {"sha256": payload["sha256"], "size": payload["size_in_bytes"]},
                "origin.json": {"sha256": hashlib.sha256(contents["origin.json"]).hexdigest(),
                                "size": len(contents["origin.json"])},
                "origin.sigstore.json": {
                    "sha256": hashlib.sha256(contents["origin.sigstore.json"]).hexdigest(),
                    "size": len(contents["origin.sigstore.json"])},
                "selection.json": plan_measurement,
            }
            limits = {"payload.zip": MAX_PAYLOAD,
                      "origin.json": MAX_METADATA,
                      "origin.sigstore.json": MAX_METADATA,
                      "selection.json": MAX_METADATA}
            retain_verified_output(
                verified_output,
                {"payload.zip": payload_archive,
                 "origin.json": contents["origin.json"],
                 "origin.sigstore.json": contents["origin.sigstore.json"],
                 "selection.json": selection_raw},
                identities, limits, final_check,
            )
    if verified_output is None:
        print("Verified independently selected source owner; current caller remains separate; no publication authority.")
    else:
        print("Verified source owner and retained exact raw transport bytes; no publication authority.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    for mode in ("record", "verify"):
        command = modes.add_parser(mode)
        command.add_argument("--workflow", required=True)
        command.add_argument("--job-name", required=True)
        command.add_argument("--artifact-id", type=positive, required=True)
        command.add_argument("--artifact-name", required=True)
        for key in ("role", "group", "host", "profile", "copy"):
            command.add_argument(f"--{key}", required=True)
        if mode == "record":
            command.add_argument("--artifact-sha256", required=True)
            command.add_argument("--payload-dir", type=Path, required=True)
            command.add_argument("--output", type=Path, required=True)
        else:
            command.add_argument("--origin", type=Path, required=True)
            command.add_argument("--bundle", type=Path, required=True)
    command = modes.add_parser("verify-source")
    for key in ("workflow", "job-name"):
        command.add_argument(f"--{key}", required=True)
    command.add_argument("--source-selection", type=Path, required=True)
    command.add_argument("--verified-output-dir", type=Path,
                         help="Optional fresh owner-only directory for the exact verified transport bytes")
    for key in ("origin", "bundle"):
        command.add_argument(f"--{key}", type=Path,
                             help="Optional local proof; supply both files or verify directly from the selected raw ZIP")
    command.add_argument("--same-attempt", action="store_true",
                         help="Allow a source in this exact run attempt only when its owner is a different completed job")
    try:
        flags = [arg.split("=", 1)[0] for arg in sys.argv[1:] if arg.startswith("--")]
        require(len(flags) == len(set(flags)), "duplicate argument selector")
        args = parser.parse_args()
        require((args.mode == "verify-source" or bool(SEGMENT.fullmatch(args.artifact_name)))
                and 0 < len(args.job_name) <= 256,
                "artifact/job name selection is invalid")
        context = context_from_environment(args.workflow)
        if args.mode == "record":
            record(args, context)
        elif args.mode == "verify":
            verify(args, context)
        else:
            verify_source(args, context)
        return 0
    except OriginError as error:
        # Every OriginError message is a code-owned reason, never provider
        # input, a credential, an endpoint URL or an exception body.
        print(f"artifact origin verification failed: {error}", file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile, subprocess.TimeoutExpired):
        # Malformed third-party metadata and token transports must not spill
        # inputs or credentials into logs. Detailed unit cases retain reasons.
        print("artifact origin verification failed at a closed provider/byte boundary", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
