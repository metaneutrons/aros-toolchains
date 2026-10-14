#!/usr/bin/env python3
"""Read-only metadata admission for a future aros-toolchains release flow.

This adapter proves a narrow repository, Release Please, CI, runtime-lock, and
tag-governance metadata contract. It creates no tag, release, dispatch, or
workflow run. It does not authenticate runtime payload bytes, prove CLI
capabilities, qualify native toolchains, or authorize publication.

The release listing proves only that no release visible to the current token
exists. It cannot prove that a private draft is absent. A future protected
start job must repeat the release lookup with contents:write visibility before
any mutation.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import sys
import time
import types
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
REPOSITORY = "metaneutrons/aros-toolchains"
RUNTIME_REPOSITORY = "metaneutrons/aros-tools"
MAIN_REF = "refs/heads/main"
CI_WORKFLOW = ".github/workflows/ci.yml"
CI_WORKFLOW_NAME = "Producer contracts"
CI_JOB_NAME = "contracts"
BOT_LOGINS = {"metaneutrons-release-please[bot]", "app/metaneutrons-release-please"}
RELEASE_BRANCH = re.compile(r"release-please--[A-Za-z0-9._-]+\Z")
SEMVER = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
OID = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
MAX_API_BYTES = 8 * 1024 * 1024
MAX_API_STDERR_BYTES = 64 * 1024
MAX_LOCAL_INPUT_BYTES = 4 * 1024 * 1024
MAX_EVENT_BYTES = 1024 * 1024
MAX_RECEIPT_BYTES = 64 * 1024
MAX_PAGES = 20
PAGE_SIZE = 100
API_TIMEOUT_SECONDS = 30
GIT_TIMEOUT_SECONDS = 20
GOVERNANCE_RECEIPT_SECONDS = 900
GRAPHQL_TAG_RULESET_BYPASS_QUERY = (
    "query ReleaseAdmissionTagRuleset($rulesetID: ID!) { "
    "node(id: $rulesetID) { __typename id "
    "... on RepositoryRuleset { databaseId "
    "bypassActors(first: 100) { totalCount nodes { __typename } pageInfo { hasNextPage } } "
    "} } }"
)
INPUT_PATHS = (
    ".release-please-manifest.json",
    "version.txt",
    "CHANGELOG.md",
    "toolchains/aros-tools-runtime-v1.json",
    "toolchains/compiler-sdk-ci-selection-v2.json",
    CI_WORKFLOW,
    "scripts/toolchain/materialize-aros-tools-runtime.py",
)
RECEIPT_KEYS = {
    "schema", "assurance", "repository", "commit", "version", "tag",
    "pull_request", "runs", "governance", "inputs", "release_absence",
}


class AdmissionError(Exception):
    """A closed-world admission check failed."""


class DuplicateKeyError(ValueError):
    """JSON input repeated an object key."""


def fail(message: str) -> None:
    raise AdmissionError(message)


def _pairs_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number {value}")


def parse_json(raw: bytes | str, label: str, *, maximum: int = MAX_API_BYTES) -> Any:
    encoded = raw.encode("utf-8") if isinstance(raw, str) else raw
    if len(encoded) > maximum:
        fail(f"{label} exceeds the metadata size limit")
    try:
        return json.loads(
            encoded.decode("utf-8"),
            object_pairs_hook=_pairs_without_duplicates,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, DuplicateKeyError, ValueError):
        fail(f"{label} is invalid JSON")


def read_regular_file(path: Path, label: str, maximum: int) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    parent_descriptor, name = _open_parent_directory(path)
    try:
        try:
            descriptor = os.open(name, flags, dir_fd=parent_descriptor)
        except OSError:
            fail(f"{label} cannot be opened as a regular file")
        try:
            with os.fdopen(descriptor, "rb") as handle:
                metadata = os.fstat(handle.fileno())
                if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                        or metadata.st_size > maximum):
                    fail(f"{label} must be a bounded, singly-linked regular file")
                result = handle.read(maximum + 1)
        except OSError:
            fail(f"{label} cannot be read safely")
    finally:
        os.close(parent_descriptor)
    if len(result) > maximum:
        fail(f"{label} exceeds the metadata size limit")
    return result


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _positive_int(value: Any, label: str) -> int:
    if type(value) is not int or value <= 0:
        fail(f"{label} must be a positive integer")
    return value


def _required_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    return value


def _exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    result = _required_object(value, label)
    if set(result) != expected:
        fail(f"{label} has an unexpected field set")
    return result


def _subprocess_environment(*, require_job_token: bool = False) -> dict[str, str]:
    environment = dict(os.environ)
    environment.pop("GOVERNANCE_TOKEN", None)
    # Runner OIDC is acquired by the controller itself. Local Git and provider
    # read/verification children must not redeem its signing credential.
    environment.pop("ACTIONS_ID_TOKEN_REQUEST_TOKEN", None)
    environment.pop("ACTIONS_ID_TOKEN_REQUEST_URL", None)
    if require_job_token and not environment.get("GH_TOKEN"):
        fail("authenticated GitHub metadata is unavailable")
    return environment


def _bounded_subprocess(
    command: list[str],
    *,
    cwd: Path | None,
    timeout: int,
    stdout_limit: int,
    stderr_limit: int,
    env: dict[str, str],
    label: str,
) -> subprocess.CompletedProcess[bytes]:
    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            env=env,
        )
    except OSError:
        fail(f"{label} could not be started")
    selector = selectors.DefaultSelector()
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    limits = {"stdout": stdout_limit, "stderr": stderr_limit}
    deadline = time.monotonic() + timeout
    try:
        assert process.stdout is not None and process.stderr is not None
        for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(command, timeout)
            events = selector.select(remaining)
            if not events:
                raise subprocess.TimeoutExpired(command, timeout)
            for key, _ in events:
                name = key.data
                remaining_bytes = limits[name] - len(buffers[name])
                chunk = os.read(key.fd, min(65536, remaining_bytes + 1))
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                if len(chunk) > remaining_bytes:
                    fail(f"{label} exceeded its output limit")
                buffers[name].extend(chunk)
        returncode = process.wait(timeout=max(0, deadline - time.monotonic()))
        return subprocess.CompletedProcess(
            command, returncode, bytes(buffers["stdout"]), bytes(buffers["stderr"])
        )
    finally:
        selector.close()
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


def api(path: str, *, allow_404: bool = False, governance: bool = False) -> Any:
    allowed_prefixes = (f"repos/{REPOSITORY}/", f"repos/{RUNTIME_REPOSITORY}/")
    if (path != f"repos/{REPOSITORY}" and not path.startswith(allowed_prefixes)) or ".." in path.split("/"):
        fail("GitHub metadata endpoint is outside the fixed repository")
    if governance and re.fullmatch(
        r"repos/metaneutrons/aros-toolchains/rulesets(?:\?includes_parents=true&targets=tag&per_page=100&page=[1-9][0-9]*|/[1-9][0-9]*)",
        path,
    ) is None:
        fail("governance metadata reads are restricted to tag ruleset endpoints")
    command = ["gh", "api", "--method", "GET", path]
    try:
        result = _bounded_subprocess(
            command,
            cwd=None,
            timeout=API_TIMEOUT_SECONDS,
            stdout_limit=MAX_API_BYTES,
            stderr_limit=MAX_API_STDERR_BYTES,
            env=_subprocess_environment(require_job_token=True),
            label="GitHub GET response",
        )
    except subprocess.TimeoutExpired:
        fail(f"GitHub GET transport failed for {path}")
    if result.returncode:
        error = result.stderr.decode("utf-8", errors="replace")
        status = re.search(r"\(HTTP ([0-9]{3})\)", error)
        code = status.group(1) if status else None
        if allow_404 and code == "404":
            return None
        detail = f" (HTTP {code})" if code else ""
        fail(f"GitHub GET failed{detail} for {path}")
    if not result.stdout:
        fail(f"GitHub GET returned an empty response for {path}")
    return parse_json(result.stdout, f"GitHub GET response for {path}")


def _graphql_tag_ruleset_bypass(node_id: str, database_id: int) -> None:
    if type(node_id) is not str or not node_id:
        fail("tag ruleset GraphQL node id is malformed")
    _positive_int(database_id, "tag ruleset REST id")
    command = [
        "gh", "api", "--method", "POST", "graphql",
        "-f", f"query={GRAPHQL_TAG_RULESET_BYPASS_QUERY}",
        "-f", f"rulesetID={node_id}",
    ]
    try:
        result = _bounded_subprocess(
            command,
            cwd=None,
            timeout=API_TIMEOUT_SECONDS,
            stdout_limit=MAX_API_BYTES,
            stderr_limit=MAX_API_STDERR_BYTES,
            env=_subprocess_environment(require_job_token=True),
            label="GitHub GraphQL response",
        )
    except subprocess.TimeoutExpired:
        fail("GitHub GraphQL transport failed for tag ruleset bypass metadata")
    if result.returncode:
        error = result.stderr.decode("utf-8", errors="replace")
        status = re.search(r"\(HTTP ([0-9]{3})\)", error)
        code = status.group(1) if status else None
        detail = f" (HTTP {code})" if code else ""
        fail(f"GitHub GraphQL query failed{detail} for tag ruleset bypass metadata")
    if not result.stdout:
        fail("GitHub GraphQL returned an empty response for tag ruleset bypass metadata")
    response = _required_object(
        parse_json(result.stdout, "GitHub GraphQL response"), "GitHub GraphQL response"
    )
    if set(response) - {"data", "errors", "extensions"}:
        fail("GitHub GraphQL response has unexpected fields")
    if "errors" in response:
        errors = response["errors"]
        if not isinstance(errors, list) or errors:
            fail("GitHub GraphQL query returned errors")
    data = _exact_keys(response.get("data"), {"node"}, "GitHub GraphQL data")
    node = _required_object(data.get("node"), "GitHub GraphQL ruleset node")
    node = _exact_keys(
        node,
        {"__typename", "id", "databaseId", "bypassActors"},
        "GitHub GraphQL ruleset node",
    )
    if (type(node.get("__typename")) is not str
            or node["__typename"] != "RepositoryRuleset"
            or type(node.get("id")) is not str
            or node["id"] != node_id
            or type(node.get("databaseId")) is not int
            or node["databaseId"] != database_id):
        fail("GitHub GraphQL ruleset identity differs from the REST ruleset")
    connection = _exact_keys(
        node.get("bypassActors"), {"totalCount", "nodes", "pageInfo"},
        "GitHub GraphQL ruleset bypass connection",
    )
    page_info = _exact_keys(
        connection.get("pageInfo"), {"hasNextPage"}, "GitHub GraphQL bypass page info"
    )
    if (type(connection.get("totalCount")) is not int
            or connection["totalCount"] != 0
            or type(connection.get("nodes")) is not list
            or connection["nodes"] != []
            or type(page_info.get("hasNextPage")) is not bool
            or page_info["hasNextPage"] is not False):
        fail("tag ruleset GraphQL bypass actors are nonempty, paginated, or malformed")


def paginated(
    endpoint: str,
    *,
    array_field: str | None = None,
    governance: bool = False,
    identity_field: str | None = "id",
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    identities: set[int | str] = set()
    for page in range(1, MAX_PAGES + 1):
        separator = "&" if "?" in endpoint else "?"
        response = api(f"{endpoint}{separator}per_page={PAGE_SIZE}&page={page}", governance=governance)
        if array_field is None:
            values = response
        else:
            body = _required_object(response, f"{endpoint} page")
            values = body.get(array_field)
        if not isinstance(values, list):
            fail(f"GitHub GET list shape is invalid for {endpoint}")
        for value in values:
            item = _required_object(value, f"{endpoint} item")
            if identity_field is not None:
                identity = item.get(identity_field)
                if type(identity) is not int or identity <= 0:
                    fail(f"GitHub GET identity is invalid for {endpoint}")
                if identity in identities:
                    fail(f"GitHub GET returned a duplicate identity for {endpoint}")
                identities.add(identity)
            rows.append(item)
        if len(values) < PAGE_SIZE:
            return rows
    fail(f"GitHub GET pagination exceeds the page limit for {endpoint}")


def git(*arguments: str) -> bytes:
    try:
        result = _bounded_subprocess(
            ["git", *arguments],
            cwd=ROOT,
            timeout=GIT_TIMEOUT_SECONDS,
            stdout_limit=MAX_LOCAL_INPUT_BYTES,
            stderr_limit=MAX_API_STDERR_BYTES,
            env=_subprocess_environment(),
            label="local Git metadata command",
        )
    except subprocess.TimeoutExpired:
        fail("local Git metadata command failed")
    if result.returncode:
        fail("local Git metadata command failed")
    return result.stdout


def require_clean_tracked_checkout() -> None:
    for arguments in (("diff", "--quiet", "HEAD", "--"),
                      ("diff", "--cached", "--quiet", "HEAD", "--")):
        try:
            result = subprocess.run(
                ["git", *arguments],
                cwd=ROOT,
                capture_output=True,
                timeout=GIT_TIMEOUT_SECONDS,
                check=False,
                env=_subprocess_environment(),
            )
        except (OSError, subprocess.TimeoutExpired):
            fail("tracked checkout cleanliness could not be verified")
        if result.returncode != 0:
            fail("tracked checkout differs from HEAD")


def committed_input(path: str) -> bytes:
    data = git("show", f"HEAD:{path}")
    if len(data) > MAX_LOCAL_INPUT_BYTES:
        fail(f"committed input exceeds the metadata size limit: {path}")
    return data


def _load_runtime_validator() -> Any:
    path = "scripts/toolchain/materialize-aros-tools-runtime.py"
    try:
        source = committed_input(path).decode("utf-8")
        module = types.ModuleType("release_admission_runtime_validator")
        module.__file__ = str(ROOT / path)
        exec(compile(source, module.__file__, "exec"), module.__dict__)
    except Exception:
        fail("runtime lock validator could not be loaded")
    return module


def committed_release_version() -> str:
    manifest = parse_json(
        committed_input(".release-please-manifest.json"),
        "committed release manifest",
        maximum=MAX_LOCAL_INPUT_BYTES,
    )
    version_raw = committed_input("version.txt")
    try:
        version_file = version_raw.decode("utf-8")
    except UnicodeDecodeError:
        fail("committed version file is not UTF-8")
    if not isinstance(manifest, dict) or set(manifest) != {"."}:
        fail("committed release manifest must contain only the root package")
    version = manifest.get(".")
    if not isinstance(version, str) or SEMVER.fullmatch(version) is None:
        fail("committed release version is not canonical stable SemVer")
    if version_file not in {version, version + "\n"}:
        fail("committed version.txt differs from the release manifest")
    return version


def input_context(expected_version: str) -> tuple[dict[str, str], dict[str, Any]]:
    contents = {path: committed_input(path) for path in INPUT_PATHS}
    try:
        manifest = parse_json(contents[".release-please-manifest.json"], "committed release manifest",
                              maximum=MAX_LOCAL_INPUT_BYTES)
        version_file = contents["version.txt"].decode("utf-8")
        ci_selection = parse_json(contents["toolchains/compiler-sdk-ci-selection-v2.json"],
                                  "committed CI selection", maximum=MAX_LOCAL_INPUT_BYTES)
        runtime_lock = parse_json(contents["toolchains/aros-tools-runtime-v1.json"],
                                  "committed runtime lock", maximum=MAX_LOCAL_INPUT_BYTES)
    except UnicodeDecodeError:
        fail("committed version file is not UTF-8")
    if not isinstance(manifest, dict) or set(manifest) != {"."}:
        fail("committed release manifest must contain only the root package")
    version = manifest.get(".")
    if not isinstance(version, str) or SEMVER.fullmatch(version) is None:
        fail("committed release version is not canonical stable SemVer")
    if version != expected_version or version_file not in {version, version + "\n"}:
        fail("committed version.txt differs from the release manifest")
    _required_object(ci_selection, "committed CI selection")
    tools_commit = ci_selection.get("tools_commit")
    if not isinstance(tools_commit, str) or OID.fullmatch(tools_commit) is None:
        fail("committed CI tools_commit is malformed")
    runtime_validator = _load_runtime_validator()
    try:
        lock = runtime_validator.validate_lock(runtime_lock)
    except Exception:
        fail("committed aros-tools runtime lock is invalid")
    _positive_int(lock.get("release_id"), "runtime lock release_id")
    _positive_int(lock.get("source_date_epoch"), "runtime lock source_date_epoch")
    if lock.get("repository") != RUNTIME_REPOSITORY:
        fail("runtime lock names an unexpected repository")
    if not isinstance(lock.get("version"), str) or SEMVER.fullmatch(lock["version"]) is None:
        fail("runtime lock version is not canonical stable SemVer")
    if tools_commit != lock.get("source_commit"):
        fail("committed CI tools_commit differs from the runtime lock source_commit")
    input_digests = {path: hashlib.sha256(contents[path]).hexdigest() for path in INPUT_PATHS}
    return input_digests, lock


def _event_context(head: str) -> tuple[str, int | None, int | None] | None:
    if os.environ.get("GITHUB_REPOSITORY") != REPOSITORY or os.environ.get("GITHUB_REF") != MAIN_REF:
        return None
    event_name = os.environ.get("GITHUB_EVENT_NAME", "")
    if event_name == "workflow_dispatch":
        return event_name, None, None
    if event_name != "workflow_run":
        return None
    path = os.environ.get("GITHUB_EVENT_PATH")
    if not path:
        fail("workflow_run event metadata is unavailable")
    raw = read_regular_file(Path(path), "workflow_run event", MAX_EVENT_BYTES)
    event = _required_object(parse_json(raw, "workflow_run event", maximum=MAX_EVENT_BYTES),
                            "workflow_run event")
    run = _required_object(event.get("workflow_run"), "workflow_run event object")
    repository = run.get("head_repository")
    if not isinstance(repository, dict):
        return None
    if not (
        run.get("name") == CI_WORKFLOW_NAME
        and run.get("path") == CI_WORKFLOW
        and run.get("event") == "push"
        and run.get("head_branch") == "main"
        and run.get("head_sha") == head
        and run.get("conclusion") == "success"
        and run.get("status") == "completed"
        and repository.get("full_name") == REPOSITORY
    ):
        return None
    run_id = run.get("id")
    attempt = run.get("run_attempt")
    if type(run_id) is not int or run_id <= 0 or type(attempt) is not int or attempt <= 0:
        return None
    return event_name, run_id, attempt


def _load_head() -> str:
    try:
        head = git("rev-parse", "--verify", "HEAD").decode("ascii").strip()
    except UnicodeDecodeError:
        fail("local Git HEAD is malformed")
    if OID.fullmatch(head) is None:
        fail("local Git HEAD is malformed")
    return head


def require_main(head: str) -> bool:
    branch = _required_object(api(f"repos/{REPOSITORY}/branches/main"), "main branch metadata")
    if branch.get("protected") is not True:
        fail("main is not protected")
    commit = branch.get("commit")
    if not isinstance(commit, dict) or not isinstance(commit.get("sha"), str) or OID.fullmatch(commit["sha"]) is None:
        fail("provider main commit metadata is malformed")
    return commit["sha"] == head


def require_active_repository() -> None:
    repository = _required_object(api(f"repos/{REPOSITORY}"), "repository metadata")
    if type(repository.get("full_name")) is not str or repository["full_name"] != REPOSITORY:
        fail("provider repository identity differs from the fixed repository")
    for field in ("archived", "disabled"):
        if type(repository.get(field)) is not bool or repository[field] is not False:
            fail(f"provider repository {field} flag is not explicitly false")
    if type(repository.get("default_branch")) is not str or repository["default_branch"] != "main":
        fail("provider repository default branch is not main")


def _require_runtime(lock: dict[str, Any]) -> None:
    release = _required_object(
        api(f"repos/{RUNTIME_REPOSITORY}/releases/{lock['release_id']}"), "runtime release metadata"
    )
    _positive_int(release.get("id"), "runtime release id")
    expected_identity = {
        "id": lock["release_id"], "tag_name": lock["tag"], "draft": False,
        "prerelease": False, "immutable": True,
    }
    if any(release.get(key) != value for key, value in expected_identity.items()):
        fail("runtime release identity differs from the committed lock")
    assets = release.get("assets")
    if not isinstance(assets, list):
        fail("runtime release assets are malformed")
    locked_assets = {
        asset["name"]: asset
        for host in lock["hosts"].values()
        for asset in (host["archive"], host["manifest"], host["archive_bundle"], host["manifest_bundle"])
    }
    actual: dict[str, dict[str, Any]] = {}
    asset_ids: set[int] = set()
    asset_names: set[str] = set()
    for asset_value in assets:
        asset = _required_object(asset_value, "runtime release asset")
        name = asset.get("name")
        if not isinstance(name, str) or not name or name in asset_names:
            fail("runtime release contains malformed or duplicate asset names")
        asset_names.add(name)
        asset_id = asset.get("id")
        _positive_int(asset_id, f"runtime asset {name} id")
        if asset_id in asset_ids:
            fail("runtime release contains duplicate asset IDs")
        asset_ids.add(asset_id)
        if name not in locked_assets:
            continue
        if name in actual:
            fail("runtime release contains a duplicate locked asset")
        expected = locked_assets[name]
        actual_size = asset.get("size")
        if (type(actual_size) is not int or actual_size != expected["size"]
                or asset.get("digest") != f"sha256:{expected['sha256']}"):
            fail(f"runtime release asset metadata differs for {name}")
        actual[name] = asset
    if set(actual) != set(locked_assets) or len(locked_assets) != 12:
        fail("runtime release does not expose all twelve locked assets")

    ref = _required_object(api(f"repos/{RUNTIME_REPOSITORY}/git/ref/tags/{lock['tag']}"),
                           "runtime tag ref")
    ref_object = ref.get("object")
    if not isinstance(ref_object, dict) or ref_object.get("type") != "tag" or ref_object.get("sha") != lock["tag_object"]:
        fail("runtime tag ref differs from the annotated object in the committed lock")
    tag = _required_object(api(f"repos/{RUNTIME_REPOSITORY}/git/tags/{lock['tag_object']}"),
                           "runtime annotated tag")
    target = tag.get("object")
    if (tag.get("tag") != lock["tag"] or not isinstance(target, dict)
            or target.get("type") != "commit" or target.get("sha") != lock["source_commit"]):
        fail("runtime annotated tag target differs from the committed lock")
    commit = _required_object(api(f"repos/{RUNTIME_REPOSITORY}/git/commits/{lock['source_commit']}"),
                              "runtime source commit")
    tree = commit.get("tree")
    committer = commit.get("committer")
    if (commit.get("sha") != lock["source_commit"] or not isinstance(tree, dict)
            or tree.get("sha") != lock["source_tree"] or not isinstance(committer, dict)):
        fail("runtime source tree differs from the committed lock")
    date = committer.get("date")
    if not isinstance(date, str):
        fail("runtime source commit date is missing")
    try:
        parsed_date = datetime.fromisoformat(date.replace("Z", "+00:00"))
        if parsed_date.tzinfo is None:
            fail("runtime source commit date lacks a timezone")
        epoch = int(parsed_date.timestamp())
    except (ValueError, OverflowError):
        fail("runtime source commit date is malformed")
    if epoch != lock["source_date_epoch"]:
        fail("runtime source commit epoch differs from the committed lock")


def _public_policy(ruleset: dict[str, Any]) -> dict[str, Any]:
    policy = {key: ruleset.get(key) for key in ("id", "target", "enforcement", "conditions")}
    rules = ruleset.get("rules")
    if not isinstance(rules, list) or any(not isinstance(rule, dict) for rule in rules):
        fail("tag ruleset rules are malformed")
    policy["rules"] = sorted(rules, key=canonical_json)
    return policy


def _governance(receipt: dict[str, Any] | None = None) -> dict[str, Any]:
    if receipt is not None:
        receipt = _exact_keys(receipt, {"ruleset_id", "policy_sha256", "checked_at"}, "governance receipt")
        _positive_int(receipt.get("ruleset_id"), "governance receipt ruleset_id")
        digest = receipt.get("policy_sha256")
        if not isinstance(digest, str) or SHA256.fullmatch(digest) is None:
            fail("governance receipt policy digest is malformed")
        checked_at = receipt.get("checked_at")
        if type(checked_at) is not int or not -60 <= int(time.time()) - checked_at <= GOVERNANCE_RECEIPT_SECONDS:
            fail("governance receipt is expired or from the future")
    listing = paginated(
        f"repos/{REPOSITORY}/rulesets?includes_parents=true&targets=tag",
        governance=True,
    )
    tag_ids = [item.get("id") for item in listing if item.get("target") == "tag" and item.get("enforcement") == "active"]
    for identifier in tag_ids:
        _positive_int(identifier, "active tag ruleset id")
    if len(tag_ids) != len(set(tag_ids)):
        fail("ruleset listing contains duplicate active tag IDs")
    if len(tag_ids) != 1:
        fail("tag governance is ambiguous or missing")
    identifier = tag_ids[0]
    ruleset = _required_object(
        api(f"repos/{REPOSITORY}/rulesets/{identifier}", governance=True),
        "tag ruleset details",
    )
    rest_id = _positive_int(ruleset.get("id"), "tag ruleset detail id")
    node_id = ruleset.get("node_id")
    conditions = ruleset.get("conditions")
    ref_names = conditions.get("ref_name") if isinstance(conditions, dict) else None
    rules = ruleset.get("rules")
    rule_types = [rule.get("type") for rule in rules] if isinstance(rules, list) and all(
        isinstance(rule, dict) for rule in rules
    ) else []
    if not (
        rest_id == identifier
        and ruleset.get("target") == "tag"
        and ruleset.get("enforcement") == "active"
        and isinstance(ref_names, dict)
        and ref_names.get("include") == ["refs/tags/v*"]
        and ref_names.get("exclude") == []
        and {"update", "deletion"} <= set(rule_types)
    ):
        fail("active tag ruleset does not enforce the exact immutable v* ref scope")
    if "bypass_actors" in ruleset:
        rest_bypass = ruleset["bypass_actors"]
        if type(rest_bypass) is not list or rest_bypass != []:
            fail("REST tag ruleset bypass metadata is nonempty or malformed")
    if type(node_id) is not str or not node_id:
        fail("tag ruleset REST node id is malformed")
    _graphql_tag_ruleset_bypass(node_id, rest_id)
    policy_digest = hashlib.sha256(canonical_json(_public_policy(ruleset)).encode("utf-8")).hexdigest()
    if receipt is not None:
        if identifier != receipt["ruleset_id"] or policy_digest != receipt["policy_sha256"]:
            fail("tag governance policy changed since admission")
        return receipt
    return {"ruleset_id": identifier, "policy_sha256": policy_digest, "checked_at": int(time.time())}


def _candidate_pull(head: str, version: str) -> dict[str, Any] | None:
    pulls = paginated(f"repos/{REPOSITORY}/commits/{head}/pulls")
    candidates = []
    for pull in pulls:
        base = pull.get("base")
        pull_head = pull.get("head")
        if (pull.get("merge_commit_sha") == head
                and pull.get("state") == "closed"
                and bool(pull.get("merged_at"))
                and isinstance(base, dict) and base.get("ref") == "main"
                and isinstance(pull_head, dict)
                and RELEASE_BRANCH.fullmatch(pull_head.get("ref", "")) is not None):
            candidates.append(pull)
    if not candidates:
        return None
    if len(candidates) != 1:
        fail("release merge has ambiguous pull request identity")
    pull = candidates[0]
    user = pull.get("user")
    base = pull.get("base")
    pull_head = pull.get("head")
    if not isinstance(user, dict) or not isinstance(base, dict) or not isinstance(pull_head, dict):
        fail("merged release pull request identity metadata is malformed")
    base_repo = base.get("repo")
    head_repo = pull_head.get("repo")
    if not isinstance(base_repo, dict) or not isinstance(head_repo, dict):
        fail("merged release pull request repository metadata is malformed")
    if (user.get("login") not in BOT_LOGINS
            or base_repo.get("full_name") != REPOSITORY
            or head_repo.get("full_name") != REPOSITORY
            or pull.get("title") != f"chore(main): release {version}"):
        fail("merged release pull request is not the exact same-repository Release Please App change")
    number = _positive_int(pull.get("number"), "release pull request number")
    files = paginated(f"repos/{REPOSITORY}/pulls/{number}/files", identity_field=None)
    expected_paths = {".release-please-manifest.json", "version.txt", "CHANGELOG.md"}
    paths: list[str] = []
    for item in files:
        filename = item.get("filename")
        if not isinstance(filename, str):
            fail("release pull request file metadata is malformed")
        paths.append(filename)
        if item.get("status") != "modified":
            fail("release pull request contains a non-modified file")
    if len(paths) != len(set(paths)) or set(paths) != expected_paths or len(paths) != 3:
        fail("release pull request must modify exactly the manifest, version.txt and changelog")
    labels = pull.get("labels")
    if not isinstance(labels, list) or any(not isinstance(label, dict) for label in labels):
        fail("release pull request labels are malformed")
    if "autorelease: pending" not in {label.get("name") for label in labels}:
        return None
    closed = paginated(f"repos/{REPOSITORY}/pulls?state=closed&base=main")
    other_pending = []
    for item in closed:
        item_head = item.get("head")
        if (item.get("merged_at") and isinstance(item_head, dict)
                and RELEASE_BRANCH.fullmatch(item_head.get("ref", ""))
                and "autorelease: pending" in {
                    label.get("name") for label in item.get("labels", []) if isinstance(label, dict)
                }):
            other_pending.append(_positive_int(item.get("number"), "pending release pull request number"))
    if other_pending != [number]:
        fail("another merged pending Release Please PR exists")
    return pull


def _require_ci(head: str, event_run: tuple[int, int] | None) -> dict[str, int] | None:
    runs = paginated(
        f"repos/{REPOSITORY}/actions/workflows/ci.yml/runs?event=push&branch=main&head_sha={head}",
        array_field="workflow_runs",
    )
    candidates = [
        run for run in runs
        if run.get("event") == "push"
        and run.get("head_branch") == "main"
        and run.get("head_sha") == head
        and isinstance(run.get("head_repository"), dict)
        and run["head_repository"].get("full_name") == REPOSITORY
    ]
    if not candidates:
        return None
    selected = max(candidates, key=lambda run: _positive_int(run.get("id"), "Producer contracts run id"))
    run_id = selected["id"]
    latest_attempt = _positive_int(selected.get("run_attempt"), "Producer contracts run attempt")
    if selected.get("name") != CI_WORKFLOW_NAME or selected.get("path") != CI_WORKFLOW:
        fail("selected CI run is not the Producer contracts workflow")
    current = _required_object(api(f"repos/{REPOSITORY}/actions/runs/{run_id}"), "latest CI run metadata")
    current_attempt = _positive_int(current.get("run_attempt"), "latest Producer contracts attempt")
    if current_attempt != latest_attempt:
        fail("Producer contracts latest run attempt changed during admission")
    if (_positive_int(current.get("id"), "latest Producer contracts run id") != run_id
            or current.get("event") != "push"
            or current.get("head_branch") != "main" or current.get("head_sha") != head
            or not isinstance(current.get("head_repository"), dict)
            or current["head_repository"].get("full_name") != REPOSITORY
            or current.get("name") != CI_WORKFLOW_NAME or current.get("path") != CI_WORKFLOW):
        fail("latest Producer contracts run identity changed during admission")
    if current.get("status") != "completed" or current.get("conclusion") != "success":
        return None
    attempt = _required_object(
        api(f"repos/{REPOSITORY}/actions/runs/{run_id}/attempts/{latest_attempt}"),
        "explicit latest CI attempt",
    )
    if (_positive_int(attempt.get("id"), "explicit Producer contracts run id") != run_id
            or _positive_int(attempt.get("run_attempt"), "explicit Producer contracts attempt number") != latest_attempt
            or attempt.get("head_sha") != head or attempt.get("event") != "push"
            or attempt.get("head_branch") != "main" or attempt.get("status") != "completed"
            or attempt.get("conclusion") != "success"):
        fail("explicit Producer contracts attempt is not the latest successful main push")
    if event_run is not None and event_run != (run_id, latest_attempt):
        return None
    jobs = paginated(
        f"repos/{REPOSITORY}/actions/runs/{run_id}/attempts/{latest_attempt}/jobs",
        array_field="jobs",
    )
    contracts = [job for job in jobs if job.get("name") == CI_JOB_NAME]
    if len(contracts) != 1 or contracts[0].get("conclusion") != "success":
        fail("latest CI attempt lacks one unique successful contracts job")
    for job in jobs:
        if job.get("status") != "completed" or job.get("conclusion") not in {"success", "skipped"}:
            fail("latest CI attempt contains an incomplete or unsuccessful job")
    return {"id": run_id, "attempt": latest_attempt}


def _no_candidate_tag_or_release(tag: str) -> bool:
    ref = api(f"repos/{REPOSITORY}/git/ref/tags/{tag}", allow_404=True)
    if ref is not None:
        return False
    releases = paginated(f"repos/{REPOSITORY}/releases")
    return not any(release.get("tag_name") == tag for release in releases)


def _release_absence_requirement(tag: str) -> dict[str, Any]:
    return {
        "candidate_tag_ref": "absent",
        "visible_release": "absent",
        "private_draft_absence": "unproven",
        "required_start_recheck": {
            "method": "GET",
            "endpoint": f"repos/{REPOSITORY}/releases/tags/{tag}",
            "permission": "contents:write",
            "absence_status": 404,
        },
    }


def admission(*, governance_receipt: dict[str, Any] | None = None) -> dict[str, Any] | None:
    head = _load_head()
    event = _event_context(head)
    if event is None:
        return None
    event_name, event_run_id, event_attempt = event
    if not require_main(head):
        return None
    require_clean_tracked_checkout()
    version = committed_release_version()
    pull = _candidate_pull(head, version)
    if pull is None:
        return None
    input_digests, lock = input_context(version)
    governance = _governance(governance_receipt)
    _require_runtime(lock)
    event_run = (event_run_id, event_attempt) if event_name == "workflow_run" else None
    runs = _require_ci(head, event_run)
    if runs is None:
        return None
    tag = f"v{version}"
    require_active_repository()
    if not _no_candidate_tag_or_release(tag):
        return None
    require_active_repository()
    # The initial main snapshot may have changed during the finite API survey.
    # The future privileged start must still recheck this metadata receipt.
    if not require_main(head):
        return None
    receipt = {
        "schema": "aros-toolchains-release-admission-v2",
        "assurance": "metadata-only",
        "repository": REPOSITORY,
        "commit": head,
        "version": version,
        "tag": tag,
        "pull_request": pull["number"],
        "runs": {"producer_contracts": runs},
        "governance": governance,
        "inputs": input_digests,
        "release_absence": _release_absence_requirement(tag),
    }
    validate_receipt(receipt)
    return receipt


def validate_receipt(value: Any) -> dict[str, Any]:
    receipt = _exact_keys(value, RECEIPT_KEYS, "admission receipt")
    if (receipt.get("schema") != "aros-toolchains-release-admission-v2"
            or receipt.get("assurance") != "metadata-only"
            or receipt.get("repository") != REPOSITORY):
        fail("admission receipt identity is malformed")
    commit = receipt.get("commit")
    version = receipt.get("version")
    if not isinstance(commit, str) or OID.fullmatch(commit) is None:
        fail("admission receipt commit is malformed")
    if not isinstance(version, str) or SEMVER.fullmatch(version) is None or receipt.get("tag") != f"v{version}":
        fail("admission receipt version or tag is malformed")
    _positive_int(receipt.get("pull_request"), "admission receipt pull request")
    runs = _exact_keys(receipt.get("runs"), {"producer_contracts"}, "admission receipt runs")
    ci = _exact_keys(runs.get("producer_contracts"), {"id", "attempt"}, "producer contracts receipt")
    _positive_int(ci.get("id"), "admission receipt CI run id")
    _positive_int(ci.get("attempt"), "admission receipt CI attempt")
    governance = _exact_keys(receipt.get("governance"), {"ruleset_id", "policy_sha256", "checked_at"},
                             "admission receipt governance")
    _positive_int(governance.get("ruleset_id"), "admission receipt ruleset id")
    if not isinstance(governance.get("policy_sha256"), str) or SHA256.fullmatch(governance["policy_sha256"]) is None:
        fail("admission receipt governance digest is malformed")
    if type(governance.get("checked_at")) is not int:
        fail("admission receipt governance time is malformed")
    inputs = _exact_keys(receipt.get("inputs"), set(INPUT_PATHS), "admission receipt input hashes")
    if any(not isinstance(digest, str) or SHA256.fullmatch(digest) is None for digest in inputs.values()):
        fail("admission receipt input hash is malformed")
    absence = _exact_keys(
        receipt.get("release_absence"),
        {"candidate_tag_ref", "visible_release", "private_draft_absence", "required_start_recheck"},
        "admission receipt release absence",
    )
    recheck = _exact_keys(
        absence.get("required_start_recheck"),
        {"method", "endpoint", "permission", "absence_status"},
        "privileged release absence recheck",
    )
    if (absence.get("candidate_tag_ref") != "absent" or absence.get("visible_release") != "absent"
            or absence.get("private_draft_absence") != "unproven"
            or recheck.get("method") != "GET"
            or recheck.get("endpoint") != f"repos/{REPOSITORY}/releases/tags/{receipt['tag']}"
            or recheck.get("permission") != "contents:write"
            or recheck.get("absence_status") != 404):
        fail("admission receipt overstates release absence or omits its privileged start recheck")
    return receipt


def _open_parent_directory(path: Path) -> tuple[int, str]:
    absolute = Path(os.path.abspath(os.fspath(path)))
    if not absolute.name or absolute.name in {".", ".."}:
        fail("output path must name a file")
    directory_flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        directory_flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(absolute.anchor, directory_flags)
    except OSError:
        fail("output parent directory cannot be opened without following links")
    try:
        for component in absolute.parent.parts[1:]:
            next_descriptor = os.open(component, directory_flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor, absolute.name
    except OSError:
        os.close(descriptor)
        fail("output parent contains a linked or invalid directory component")


def _check_output_destination(path: Path, *, existing: bool) -> None:
    descriptor, name = _open_parent_directory(path)
    try:
        try:
            info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            if existing:
                fail("GitHub output file does not exist")
            return
        except OSError:
            fail("output path cannot be inspected")
        if existing:
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                fail("GitHub output must be a singly-linked regular file")
        else:
            fail("output receipt already exists")
    finally:
        os.close(descriptor)


def _write_exclusive(path: Path, content: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    parent_descriptor, name = _open_parent_directory(path)
    try:
        descriptor = os.open(name, flags, 0o600, dir_fd=parent_descriptor)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError:
        fail("output receipt already exists")
    except OSError:
        fail("output receipt could not be created exclusively")
    finally:
        os.close(parent_descriptor)


def _append_github_output(path: Path, *, receipt: dict[str, Any] | None) -> None:
    lines = ["ready=true\n", f"admission={canonical_json(receipt)}\n"] if receipt is not None else ["ready=false\n"]
    flags = os.O_WRONLY | os.O_APPEND
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    parent_descriptor, name = _open_parent_directory(path)
    try:
        descriptor = os.open(name, flags, dir_fd=parent_descriptor)
        with os.fdopen(descriptor, "ab") as handle:
            metadata = os.fstat(handle.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                fail("GitHub output path must be a regular file")
            handle.write("".join(lines).encode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())
    except OSError:
        fail("GitHub output could not be appended")
    finally:
        os.close(parent_descriptor)


def command_admit(output: Path, github_output: Path) -> None:
    _check_output_destination(github_output, existing=True)
    if output.absolute() == github_output.absolute():
        fail("receipt and GitHub output paths must differ")
    candidate = admission()
    if candidate is None:
        _append_github_output(github_output, receipt=None)
        print("No current release candidate admitted")
        return
    _check_output_destination(output, existing=False)
    _write_exclusive(output, (canonical_json(candidate) + "\n").encode("utf-8"))
    _append_github_output(github_output, receipt=candidate)
    print("Current release candidate admitted")


def command_recheck(admission_path: Path, output: Path) -> None:
    _check_output_destination(output, existing=False)
    saved = validate_receipt(parse_json(
        read_regular_file(admission_path, "saved admission receipt", MAX_RECEIPT_BYTES),
        "saved admission receipt", maximum=MAX_RECEIPT_BYTES,
    ))
    governance = saved["governance"]
    current = admission(governance_receipt=governance)
    if current is None or current != saved:
        fail("read-only admission changed before recheck")
    _write_exclusive(output, (canonical_json(current) + "\n").encode("utf-8"))
    print("Read-only admission rechecked")


def command_probe_visibility(output: Path, profile: str) -> None:
    """Observe normal job-token visibility; never emit an admission receipt."""
    _check_output_destination(output, existing=False)
    require_active_repository()
    listing = paginated(f"repos/{REPOSITORY}/rulesets?includes_parents=true&targets=tag")
    selected = [entry for entry in listing
                if entry.get("target") == "tag" and entry.get("enforcement") == "active"]
    if len(selected) != 1:
        fail("visibility probe requires one active tag ruleset")
    identifier = _positive_int(selected[0].get("id"), "visibility ruleset id")
    ruleset = _required_object(api(f"repos/{REPOSITORY}/rulesets/{identifier}"), "visibility ruleset")
    if (type(ruleset.get("id")) is not int or ruleset["id"] != identifier or ruleset.get("target") != "tag"
            or ruleset.get("enforcement") != "active"):
        fail("visibility ruleset identity changed")
    visible = "bypass_actors" in ruleset
    bypass = ruleset.get("bypass_actors")
    if visible and not isinstance(bypass, list):
        fail("visibility bypass field is malformed")
    report = {
        "schema": "aros-toolchains-governance-visibility-probe-v1",
        "assurance": "visibility-only-not-release-admission",
        "repository": REPOSITORY,
        "declared_job_contents_permission": profile,
        "ruleset_id": identifier,
        "bypass_visible": visible,
        "bypass_count": len(bypass) if visible else None,
        "explicitly_empty_bypass": visible and bypass == [],
        "public_policy_sha256": hashlib.sha256(canonical_json(_public_policy(ruleset)).encode()).hexdigest(),
    }
    require_active_repository()
    _write_exclusive(output, (canonical_json(report) + "\n").encode())
    print(canonical_json(report))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    admit = subparsers.add_parser("admit")
    admit.add_argument("--output", type=Path, required=True)
    admit.add_argument("--github-output", type=Path, required=True)
    recheck = subparsers.add_parser("recheck")
    recheck.add_argument("--admission", type=Path, required=True)
    recheck.add_argument("--output", type=Path, required=True)
    probe = subparsers.add_parser("probe-governance-visibility")
    probe.add_argument("--output", type=Path, required=True)
    probe.add_argument("--contents-permission", choices=("read", "write"), required=True)
    args = parser.parse_args()
    try:
        if args.command == "admit":
            command_admit(args.output, args.github_output)
        elif args.command == "recheck":
            command_recheck(args.admission, args.output)
        else:
            command_probe_visibility(args.output, args.contents_permission)
    except AdmissionError as error:
        print(f"release admission failed: {error}", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
