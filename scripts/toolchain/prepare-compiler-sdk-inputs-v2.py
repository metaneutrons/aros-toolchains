#!/usr/bin/env python3
"""Prepare locally bound compiler/SDK release inputs; never build or publish.

The input selection is an independently reviewed workflow document.  This
adapter only projects it into native toolchain documents and delegates all
recipe, source, SDK identity and release-input semantics to ``aros``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tomllib
from typing import Any


SELECTION_SCHEMA = "aros-compiler-sdk-ci-selection-v2"
RELEASE_INPUTS_SCHEMA = "aros-toolchain-release-inputs-v2"
ACTIVE_HOSTS = ["linux-aarch64", "linux-x86_64", "macos-aarch64"]
MAX_DOCUMENT_BYTES = 1_048_576
MAX_SELECTION_BYTES = 1_048_576
MAX_GROUPS = 32
MAX_SDKS = 32
MAX_SDK_PROFILES = 64
MAX_SOURCE_DATE_EPOCH = 8_589_934_591
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
SAFE_SOURCE_TOKEN = re.compile(r"[a-z0-9](?:[a-z0-9_-]{0,126}[a-z0-9])?\Z")
SAFE_GROUP_ID = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?\Z")
SAFE_SDK_ID = re.compile(r"(?!\.\.\Z)(?!\.\Z)[a-z0-9_.+-]{1,96}\Z")


class PreparationError(Exception):
    """A bounded, user-actionable preparation failure."""


def fail(message: str) -> None:
    raise PreparationError(message)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"JSON contains duplicate field {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    fail(f"JSON contains unsupported numeric constant {value}")


def parse_json(data: bytes, label: str) -> Any:
    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except PreparationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{label} is not valid UTF-8 JSON: {error}")


def require_object(value: Any, label: str, fields: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{label} must be a JSON object")
    unknown = set(value) - fields
    missing = fields - set(value)
    if unknown:
        fail(f"{label} has unknown fields: {', '.join(sorted(unknown))}")
    if missing:
        fail(f"{label} is missing fields: {', '.join(sorted(missing))}")
    return value


def reject_symlink_components(path: Path, label: str) -> None:
    if not path.is_absolute():
        fail(f"{label} must be absolute")
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current = current / component
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            fail(f"cannot inspect {label}: {error}")
        if stat.S_ISLNK(metadata.st_mode):
            fail(f"{label} path contains a symbolic link")


def absolute_existing(path_text: str, label: str, kind: str) -> Path:
    path = Path(path_text)
    if not path.is_absolute():
        fail(f"{label} must be an absolute path")
    reject_symlink_components(path, label)
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.lstat()
    except OSError as error:
        fail(f"{label} is unavailable: {error}")
    if resolved != path:
        fail(f"{label} must use its canonical absolute path")
    if kind == "directory" and not stat.S_ISDIR(metadata.st_mode):
        fail(f"{label} must be a real directory")
    if kind == "file" and not stat.S_ISREG(metadata.st_mode):
        fail(f"{label} must be a regular file")
    if kind == "executable" and (
        not stat.S_ISREG(metadata.st_mode) or not os.access(resolved, os.X_OK)
    ):
        fail(f"{label} must be a regular executable file")
    return resolved


def existing_selection_file(path_text: str) -> Path:
    path = Path(path_text)
    if not path.is_absolute():
        path = Path.cwd() / path
    reject_symlink_components(path, "--selection")
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.lstat()
    except OSError as error:
        fail(f"--selection is unavailable: {error}")
    if not stat.S_ISREG(metadata.st_mode):
        fail("--selection must be a regular file")
    return resolved


def absent_destination(path_text: str, label: str) -> Path:
    path = Path(path_text)
    if not path.is_absolute() or path.name in ("", ".", ".."):
        fail(f"{label} must be an absolute directory path")
    parent = path.parent
    reject_symlink_components(parent, f"{label} parent")
    try:
        real_parent = parent.resolve(strict=True)
        parent_metadata = real_parent.lstat()
    except OSError as error:
        fail(f"{label} parent must already exist: {error}")
    if real_parent != parent or not stat.S_ISDIR(parent_metadata.st_mode):
        fail(f"{label} parent must be a canonical real directory")
    reject_symlink_components(path, label)
    if os.path.lexists(path):
        fail(f"{label} already exists; refusing to replace it")
    return path


def paths_overlap(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents


def run_process(
    arguments: list[str], *, cwd: Path | None = None, label: str
) -> subprocess.CompletedProcess[bytes]:
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    try:
        result = subprocess.run(
            arguments,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as error:
        fail(f"cannot run {label}: {error}")
    if result.returncode != 0:
        diagnostic = result.stderr.decode("utf-8", errors="replace").strip()
        if len(diagnostic) > 2000:
            diagnostic = diagnostic[:2000] + "…"
        suffix = f": {diagnostic}" if diagnostic else ""
        fail(f"{label} failed with exit status {result.returncode}{suffix}")
    return result


def git(root: Path, *arguments: str) -> bytes:
    return run_process(["git", "-C", str(root), *arguments], label="Git inspection").stdout


def git_snapshot(root: Path, label: str) -> tuple[str, str]:
    top = git(root, "rev-parse", "--show-toplevel").decode("utf-8").strip()
    if Path(top) != root:
        fail(f"{label} is not the selected Git worktree root")
    commit = git(root, "rev-parse", "--verify", "HEAD^{commit}").decode("ascii").strip()
    tree = git(root, "rev-parse", "--verify", "HEAD^{tree}").decode("ascii").strip()
    if not HEX40.fullmatch(commit) or not HEX40.fullmatch(tree):
        fail(f"{label} has a noncanonical Git identity")
    status = git(
        root,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--ignore-submodules=none",
    )
    if status:
        fail(f"{label} worktree is not clean")
    return commit, tree


def validate_producer_reference(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 256:
        fail(f"{label} must be a bounded producer-relative path")
    if value.startswith("/") or "\\" in value or ":" in value:
        fail(f"{label} must be a portable producer-relative path")
    parts = value.split("/")
    if any(
        part in ("", ".", "..")
        or not part.isascii()
        or any(not (char.isalnum() or char in "-_.+") for char in part)
        for part in parts
    ):
        fail(f"{label} contains an unsafe path component")
    if PurePosixPath(value).as_posix() != value:
        fail(f"{label} is not in canonical slash-separated form")
    return tuple(parts)


def committed_producer_file(
    producer: Path, relative: tuple[str, ...], label: str
) -> bytes:
    text = "/".join(relative)
    raw_tree_entry = git(producer, "ls-tree", "-z", "HEAD", "--", text)
    entries = raw_tree_entry.split(b"\0")
    if len(entries) != 2 or not entries[0]:
        fail(f"{label} is not one exact file in the selected producer commit")
    header, separator, raw_path = entries[0].partition(b"\t")
    fields = header.split()
    if (
        not separator
        or raw_path.decode("utf-8", errors="strict") != text
        or len(fields) != 3
        or fields[0] not in (b"100644", b"100755")
        or fields[1] != b"blob"
        or not re.fullmatch(rb"[0-9a-f]{40}", fields[2])
    ):
        fail(f"{label} must be a regular committed producer file, not a symlink or submodule")

    path = producer.joinpath(*relative)
    reject_symlink_components(path, label)
    try:
        metadata = path.lstat()
    except OSError as error:
        fail(f"cannot inspect {label}: {error}")
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_DOCUMENT_BYTES:
        fail(f"{label} must be a bounded regular file")
    try:
        working_bytes = read_regular_file(path, MAX_DOCUMENT_BYTES, label)
    except PreparationError:
        raise
    committed_bytes = git(producer, "cat-file", "blob", fields[2].decode("ascii"))
    if working_bytes != committed_bytes:
        fail(f"{label} differs from its exact committed producer bytes")
    return working_bytes


def read_regular_file(path: Path, limit: int, label: str) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        fail(f"cannot safely open {label}: {error}")
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
            fail(f"{label} is not a bounded regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read(limit + 1)
        if len(data) > limit:
            fail(f"{label} exceeds its byte limit")
        return data
    finally:
        os.close(descriptor)


def write_new(path: Path, data: bytes, label: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o644)
    except OSError as error:
        fail(f"cannot create absent {label}: {error}")
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            fail(f"created {label} is not a new regular file")
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(descriptor)
    finally:
        os.close(descriptor)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_bytes(document: Any) -> bytes:
    return (json.dumps(document, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )


def parse_stage(result: subprocess.CompletedProcess[bytes], label: str) -> dict[str, Any]:
    value = parse_json(result.stdout, f"native {label} result")
    if not isinstance(value, dict):
        fail(f"native {label} result must be a JSON object")
    return value


def require_stage(
    document: dict[str, Any],
    *,
    label: str,
    schema: str,
    operation: str,
    fields: set[str],
) -> None:
    if set(document) != fields:
        fail(f"native {label} result has an unexpected closed field set")
    if document.get("schema") != schema or document.get("operation") != operation:
        fail(f"native {label} result has an unexpected schema or operation")


def validate_selection(value: Any) -> dict[str, Any]:
    selection = require_object(
        value,
        "selection",
        {"schema", "source_commit", "tools_commit", "groups", "sdks"},
    )
    if selection["schema"] != SELECTION_SCHEMA:
        fail(f"selection schema must be {SELECTION_SCHEMA!r}")
    for field in ("source_commit", "tools_commit"):
        commit = selection[field]
        if not isinstance(commit, str) or not HEX40.fullmatch(commit) or set(commit) == {"0"}:
            fail(f"selection {field} must be a nonzero lowercase 40-hex Git identity")

    groups = selection["groups"]
    if not isinstance(groups, list) or not 1 <= len(groups) <= MAX_GROUPS:
        fail(f"selection groups must contain 1..{MAX_GROUPS} entries")
    group_ids: set[str] = set()
    for index, value in enumerate(groups):
        group = require_object(
            value,
            f"selection groups[{index}]",
            {"id", "source_lock", "profiles", "ports_lock"},
        )
        group_id = group["id"]
        if not isinstance(group_id, str) or not SAFE_GROUP_ID.fullmatch(group_id):
            fail(f"selection groups[{index}].id is not a safe group ID")
        if group_id in group_ids:
            fail(f"selection has duplicate group ID {group_id!r}")
        group_ids.add(group_id)
        for field in ("source_lock", "profiles", "ports_lock"):
            group[field] = validate_producer_reference(
                group[field], f"group {group_id} {field}"
            )

    sdks = selection["sdks"]
    if not isinstance(sdks, list) or len(sdks) > MAX_SDKS:
        fail(f"selection sdks must contain at most {MAX_SDKS} entries")
    sdk_ids: set[str] = set()
    for index, value in enumerate(sdks):
        sdk = require_object(
            value,
            f"selection sdks[{index}]",
            {"id", "version", "source_preset", "source_date_epoch", "compiler_profiles"},
        )
        sdk_id = sdk["id"]
        if not isinstance(sdk_id, str) or not SAFE_SDK_ID.fullmatch(sdk_id):
            fail(f"selection sdks[{index}].id is not a safe lowercase SDK ID")
        if sdk_id in sdk_ids:
            fail(f"selection has duplicate SDK ID {sdk_id!r}")
        sdk_ids.add(sdk_id)
        if not isinstance(sdk["version"], str) or not 1 <= len(sdk["version"]) <= 96:
            fail(f"SDK {sdk_id} version must be an explicit bounded string")
        if not isinstance(sdk["source_preset"], str) or not SAFE_SOURCE_TOKEN.fullmatch(
            sdk["source_preset"]
        ):
            fail(f"SDK {sdk_id} source_preset is not a safe source profile")
        epoch = sdk["source_date_epoch"]
        if (
            isinstance(epoch, bool)
            or not isinstance(epoch, int)
            or not 0 <= epoch <= MAX_SOURCE_DATE_EPOCH
        ):
            fail(f"SDK {sdk_id} source_date_epoch is outside the portable SDK range")
        references = sdk["compiler_profiles"]
        if not isinstance(references, list) or not 1 <= len(references) <= MAX_SDK_PROFILES:
            fail(f"SDK {sdk_id} compiler_profiles must contain 1..{MAX_SDK_PROFILES} refs")
        seen: set[tuple[str, str]] = set()
        for ref_index, ref_value in enumerate(references):
            ref = require_object(
                ref_value,
                f"SDK {sdk_id} compiler_profiles[{ref_index}]",
                {"group_id", "profile"},
            )
            group_id = ref["group_id"]
            profile = ref["profile"]
            if not isinstance(group_id, str) or not SAFE_GROUP_ID.fullmatch(group_id):
                fail(f"SDK {sdk_id} has an unsafe compiler group reference")
            if group_id not in group_ids:
                fail(f"SDK {sdk_id} references unselected group {group_id!r}")
            if not isinstance(profile, str) or not SAFE_SOURCE_TOKEN.fullmatch(profile):
                fail(f"SDK {sdk_id} has an unsafe compiler profile reference")
            pair = (group_id, profile)
            if pair in seen:
                fail(f"SDK {sdk_id} has duplicate compiler profile reference {pair!r}")
            seen.add(pair)
    return selection


def projected_target(projection: Path, source_preset: str) -> tuple[dict[str, Any], str, bytes]:
    targets_path = projection / "aros-targets.toml"
    reject_symlink_components(targets_path, "projected aros-targets.toml")
    target_bytes = read_regular_file(targets_path, MAX_DOCUMENT_BYTES, "projected aros-targets.toml")
    try:
        config = tomllib.loads(target_bytes.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        fail(f"projected aros-targets.toml is invalid: {error}")
    profiles = config.get("targets") if isinstance(config, dict) else None
    if not isinstance(profiles, list):
        fail("projected aros-targets.toml has no target profile list")
    matches = [profile for profile in profiles if isinstance(profile, dict) and profile.get("name") == source_preset]
    if len(matches) != 1:
        fail(f"source preset {source_preset!r} is absent or ambiguous in aros-targets.toml")
    profile = matches[0]
    native_path = profile.get("native_consumer_contract")
    sdk_path = profile.get("sdk_consumer_contract")
    if (native_path is None) == (sdk_path is None):
        fail(f"source preset {source_preset!r} must declare exactly one SDK consumer contract")
    contract_ref = native_path if native_path is not None else sdk_path
    if not isinstance(contract_ref, str) or not contract_ref:
        fail(f"source preset {source_preset!r} has an invalid consumer contract path")
    relative = validate_source_relative_reference(contract_ref)
    contract_path = projection.joinpath(*relative)
    reject_symlink_components(contract_path, "projected SDK consumer contract")
    contract_bytes = read_regular_file(
        contract_path, MAX_DOCUMENT_BYTES, "projected SDK consumer contract"
    )
    contract = parse_json(contract_bytes, "projected SDK consumer contract")
    if not isinstance(contract, dict):
        fail("projected SDK consumer contract must be a JSON object")
    if native_path is not None:
        if contract.get("schema") != "aros-native-consumer-contract-v2":
            fail("native SDK consumer contract must use schema v2")
        abi = contract.get("abi")
        if not isinstance(abi, dict) or not isinstance(abi.get("target_triple"), str):
            fail("native SDK consumer contract has no scalar ABI target triple")
        target = {"target_triple": abi["target_triple"], "abi": abi}
    else:
        if contract.get("schema") != "aros-sdk-consumer-contract-v1":
            fail("generic SDK consumer contract must use schema v1")
        target = contract.get("target")
        if not isinstance(target, dict):
            fail("generic SDK consumer contract has no target descriptor")
    return target, digest(contract_bytes), contract_bytes


def validate_source_relative_reference(value: str) -> tuple[str, ...]:
    if value.startswith("/") or "\\" in value or ":" in value:
        fail("consumer contract path is not portable source-relative syntax")
    parts = value.split("/")
    if any(
        part in ("", ".", "..")
        or not part.isascii()
        or any(not (char.isalnum() or char in "-_.+") for char in part)
        for part in parts
    ):
        fail("consumer contract path contains an unsafe component")
    return tuple(parts)


def invoke_sdk_source_verifier(
    aros: Path,
    identity_path: Path,
    identity_bytes: bytes,
    source: Path,
    projection: Path,
    source_preset: str,
) -> None:
    result = run_process(
        [
            str(aros),
            "sdk",
            "verify-source",
            "--identity",
            str(identity_path),
            "--identity-sha256",
            digest(identity_bytes),
            "--source-dir",
            str(source),
            "--materialized-source-dir",
            str(projection),
            "--source-preset",
            source_preset,
        ],
        label=f"native SDK source verification for {source_preset}",
    )
    response = parse_json(result.stdout, "native SDK source verification result")
    if not isinstance(response, dict) or set(response) != {
        "schema",
        "operation",
        "assurance",
        "identity",
        "source_preset",
        "materialized_source_dir",
    }:
        fail("native SDK source verification returned an unexpected closed result")
    if (
        response["schema"] != "aros-sdk-source-binding-v2"
        or response["operation"] != "sdk.verify-source"
        or response["assurance"] != "local-source-binding-not-execution-or-release-admission"
        or response["identity"] != parse_json(identity_bytes, "candidate SDK identity")
        or response["source_preset"] != source_preset
        or response["materialized_source_dir"] != str(projection)
    ):
        fail("native SDK source verification result differs from the selected identity")


def validate_release_plan(
    plan: dict[str, Any],
    *,
    collection_sha256: str,
    producer_commit: str,
    tools_commit: str,
    source_commit: str,
    source_tree: str,
    group_records: list[dict[str, Any]],
    sdk_records: list[dict[str, Any]],
) -> None:
    expected_fields = {
        "schema",
        "operation",
        "release_format",
        "assurance",
        "inputs_sha256",
        "producer_commit",
        "tools_commit",
        "hosts",
        "groups",
        "sdk_count",
        "sdks",
        "lane_count",
        "lanes",
    }
    require_stage(
        plan,
        label="release plan",
        schema="aros-toolchain-producer-stage-v2",
        operation="release-plan",
        fields=expected_fields,
    )
    expected_groups = [
        {
            "group_id": record["id"],
            "source_commit": source_commit,
            "source_tree": source_tree,
            "upstream_commit": source_commit,
            "recipe": record["recipe"],
            "source_lock": record["source_lock"],
            "profiles": record["profiles"],
        }
        for record in group_records
    ]
    if (
        plan["release_format"] != "family-v2"
        or plan["assurance"] != "input-binding-only"
        or plan["inputs_sha256"] != collection_sha256
        or plan["producer_commit"] != producer_commit
        or plan["tools_commit"] != tools_commit
        or plan["hosts"] != ACTIVE_HOSTS
        or plan["groups"] != expected_groups
        or plan["sdks"] != sdk_records
        or isinstance(plan["sdk_count"], bool)
        or not isinstance(plan["sdk_count"], int)
        or plan["sdk_count"] != len(sdk_records)
    ):
        fail("native release plan differs from the independently assembled selection")
    lanes = plan["lanes"]
    if (
        not isinstance(lanes, list)
        or isinstance(plan["lane_count"], bool)
        or not isinstance(plan["lane_count"], int)
        or plan["lane_count"] != len(lanes)
    ):
        fail("native release plan has an invalid lane count")
    group_ids = {record["id"] for record in group_records}
    seen_lanes: set[tuple[str, str, str]] = set()
    for lane in lanes:
        if not isinstance(lane, dict) or set(lane) != {"group_id", "host", "target_profile"}:
            fail("native release plan contains an invalid lane record")
        group_id, host, profile = (
            lane["group_id"],
            lane["host"],
            lane["target_profile"],
        )
        if (
            not isinstance(group_id, str)
            or group_id not in group_ids
            or not isinstance(host, str)
            or host not in ACTIVE_HOSTS
            or not isinstance(profile, str)
            or not SAFE_SOURCE_TOKEN.fullmatch(profile)
        ):
            fail("native release plan contains an invalid lane")
        key = (group_id, host, profile)
        if key in seen_lanes:
            fail("native release plan contains an invalid or duplicate lane")
        seen_lanes.add(key)


def prepare(args: argparse.Namespace) -> None:
    aros = absolute_existing(args.aros, "--aros", "executable")
    source = absolute_existing(args.source_dir, "--source-dir", "directory")
    producer = absolute_existing(args.producer_dir, "--producer-dir", "directory")
    tools = absolute_existing(args.tools_dir, "--tools-dir", "directory")
    selection_path = existing_selection_file(args.selection)
    output = absent_destination(args.output_dir, "--output-dir")
    projection_output = absent_destination(args.projection_dir, "--projection-dir")
    if paths_overlap(output, projection_output):
        fail("output and projection directories must be disjoint")
    for destination in (output, projection_output):
        for root in (source, producer, tools):
            if paths_overlap(destination, root):
                fail("output directories must be outside every selected Git checkout")

    selection_bytes = read_regular_file(selection_path, MAX_SELECTION_BYTES, "selection")
    selection = validate_selection(parse_json(selection_bytes, "selection"))
    source_commit, source_tree = git_snapshot(source, "source")
    producer_commit, producer_tree = git_snapshot(producer, "producer")
    tools_commit, tools_tree = git_snapshot(tools, "tools")
    if source_commit != selection["source_commit"]:
        fail("source checkout HEAD differs from the selected source_commit")
    if tools_commit != selection["tools_commit"]:
        fail("tools checkout HEAD differs from the selected tools_commit")

    group_documents: dict[str, dict[str, bytes]] = {}
    for group in selection["groups"]:
        group_documents[group["id"]] = {
            field: committed_producer_file(producer, group[field], f"group {group['id']} {field}")
            for field in ("source_lock", "profiles", "ports_lock")
        }

    output.mkdir(mode=0o755)
    recipe_refs: dict[str, dict[str, str]] = {}
    group_records: list[dict[str, Any]] = []
    for group in sorted(selection["groups"], key=lambda record: record["id"]):
        group_id = group["id"]
        recipe_name = f"recipe-{group_id}.json"
        source_lock_name = f"source-lock-{group_id}.json"
        profiles_name = f"profiles-{group_id}.json"
        recipe_path = output / recipe_name
        command = [
            str(aros),
            "toolchain",
            "producer",
            "recipe",
            "--source-dir",
            str(source),
            "--producer-dir",
            str(producer),
            "--tools-dir",
            str(tools),
            "--source-lock",
            str(producer.joinpath(*group["source_lock"])),
            "--profiles",
            str(producer.joinpath(*group["profiles"])),
            "--output",
            str(recipe_path),
            "--format",
            "json",
        ]
        result = run_process(command, cwd=tools, label=f"native recipe for group {group_id}")
        recipe_stage = parse_stage(result, f"recipe for group {group_id}")
        require_stage(
            recipe_stage,
            label=f"recipe for group {group_id}",
            schema="aros-toolchain-producer-stage-v1",
            operation="recipe",
            fields={"schema", "operation", "path", "sha256"},
        )
        recipe_bytes = read_regular_file(recipe_path, MAX_DOCUMENT_BYTES, f"recipe {group_id}")
        recipe_sha = digest(recipe_bytes)
        if recipe_stage["path"] != str(recipe_path) or recipe_stage["sha256"] != recipe_sha:
            fail(f"native recipe stage for group {group_id} does not bind its output bytes")
        source_lock_bytes = group_documents[group_id]["source_lock"]
        profiles_bytes = group_documents[group_id]["profiles"]
        write_new(output / source_lock_name, source_lock_bytes, f"source lock for {group_id}")
        write_new(output / profiles_name, profiles_bytes, f"profiles for {group_id}")
        recipe_refs[group_id] = {"file": recipe_name, "sha256": recipe_sha}
        group_records.append(
            {
                "id": group_id,
                "recipe": recipe_refs[group_id],
                "source_lock": {"file": source_lock_name, "sha256": digest(source_lock_bytes)},
                "profiles": {"file": profiles_name, "sha256": digest(profiles_bytes)},
            }
        )

    sdk_records: list[dict[str, Any]] = []
    if selection["sdks"]:
        materialize_result = run_process(
            [
                str(aros),
                "toolchain",
                "producer",
                "materialize-engine-free-source",
                "--source-dir",
                str(source),
                "--source-commit",
                source_commit,
                "--source-tree",
                source_tree,
                "--output-dir",
                str(projection_output),
                "--format",
                "json",
            ],
            cwd=tools,
            label="native engine-free source materialization",
        )
        materialized = parse_stage(materialize_result, "engine-free source materialization")
        require_stage(
            materialized,
            label="engine-free source materialization",
            schema="aros-toolchain-producer-stage-v1",
            operation="materialize-engine-free-source",
            fields={"schema", "operation", "root", "source_commit", "source_tree", "source_tree_sha256"},
        )
        if (
            materialized["root"] != str(projection_output)
            or materialized["source_commit"] != source_commit
            or materialized["source_tree"] != source_tree
            or not isinstance(materialized["source_tree_sha256"], str)
            or not HEX64.fullmatch(materialized["source_tree_sha256"])
        ):
            fail("native materialization result does not bind the selected source projection")

        for index, sdk in enumerate(sorted(selection["sdks"], key=lambda record: record["id"])):
            target, contract_sha, _contract_bytes = projected_target(
                projection_output, sdk["source_preset"]
            )
            identity = {
                "sdk_id": sdk["id"],
                "version": sdk["version"],
                "target": target,
                "source": {
                    "commit": source_commit,
                    "git_tree": source_tree,
                    "content_sha256": materialized["source_tree_sha256"],
                    "contract_sha256": contract_sha,
                },
                "source_date_epoch": sdk["source_date_epoch"],
            }
            identity_bytes = json_bytes(identity)
            identity_name = f"sdk-{index:02d}-identity.json"
            identity_path = output / identity_name
            write_new(identity_path, identity_bytes, f"SDK identity {sdk['id']}")
            # Source semantics and the measured raw Git projection are delegated
            # immediately; no release collection references this candidate yet.
            invoke_sdk_source_verifier(
                aros,
                identity_path,
                identity_bytes,
                source,
                projection_output,
                sdk["source_preset"],
            )
            sdk_records.append(
                {
                    "id": sdk["id"],
                    "identity": {"file": identity_name, "sha256": digest(identity_bytes)},
                    "source_preset": sdk["source_preset"],
                    "compiler_profiles": sorted(
                        sdk["compiler_profiles"],
                        key=lambda reference: (reference["group_id"], reference["profile"]),
                    ),
                }
            )

    if git_snapshot(source, "source") != (source_commit, source_tree):
        fail("source checkout changed during preparation")
    if git_snapshot(producer, "producer") != (producer_commit, producer_tree):
        fail("producer checkout changed during preparation")
    if git_snapshot(tools, "tools") != (tools_commit, tools_tree):
        fail("tools checkout changed during preparation")

    collection = {
        "schema": RELEASE_INPUTS_SCHEMA,
        "producer_commit": producer_commit,
        "tools_commit": tools_commit,
        "hosts": ACTIVE_HOSTS,
        "groups": group_records,
        "sdks": sdk_records,
    }
    collection_bytes = json_bytes(collection)
    if len(collection_bytes) > MAX_DOCUMENT_BYTES:
        fail("release-input collection exceeds the native 1 MiB limit")
    collection_path = output / "toolchain-release-inputs-v2.json"
    write_new(collection_path, collection_bytes, "release-input collection")
    collection_sha = digest(collection_bytes)
    plan_result = run_process(
        [
            str(aros),
            "toolchain",
            "producer",
            "release-plan",
            "--directory",
            str(output),
            "--inputs-sha256",
            collection_sha,
            "--format",
            "json",
        ],
        cwd=tools,
        label="native release-plan digest verification",
    )
    plan = parse_stage(plan_result, "release-plan")
    validate_release_plan(
        plan,
        collection_sha256=collection_sha,
        producer_commit=producer_commit,
        tools_commit=tools_commit,
        source_commit=source_commit,
        source_tree=source_tree,
        group_records=group_records,
        sdk_records=sdk_records,
    )
    if git_snapshot(source, "source") != (source_commit, source_tree):
        fail("source checkout changed during release-plan verification")
    if git_snapshot(producer, "producer") != (producer_commit, producer_tree):
        fail("producer checkout changed during release-plan verification")
    if git_snapshot(tools, "tools") != (tools_commit, tools_tree):
        fail("tools checkout changed during release-plan verification")
    plan_bytes = plan_result.stdout
    write_new(output / "plan.json", plan_bytes, "native release plan")
    print(
        json.dumps(
            {
                "schema": "aros-compiler-sdk-ci-preparation-v2",
                "assurance": "input-binding-only-not-build-or-release-admission",
                "inputs_sha256": collection_sha,
                "collection": str(collection_path),
                "plan": str(output / "plan.json"),
                "projection": str(projection_output) if selection["sdks"] else None,
                "groups": len(group_records),
                "sdks": len(sdk_records),
            },
            sort_keys=True,
        )
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--aros", required=True, help="absolute native aros CLI executable")
    result.add_argument("--source-dir", required=True, help="clean pinned AROS source worktree")
    result.add_argument("--producer-dir", required=True, help="clean producer data worktree")
    result.add_argument("--tools-dir", required=True, help="clean pinned aros-tools worktree")
    result.add_argument("--selection", required=True, help="closed compiler/SDK CI selection JSON")
    result.add_argument("--output-dir", required=True, help="absent release-input output directory")
    result.add_argument("--projection-dir", required=True, help="absent engine-free source directory")
    return result


def main() -> int:
    try:
        prepare(parser().parse_args())
    except PreparationError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    except OSError as error:
        print(f"error: filesystem operation failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
