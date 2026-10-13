#!/usr/bin/env python3
"""Record a full family-v2 qualification after external and native checks.

This protected-caller adapter deliberately does not fetch provider records or
inspect Git tags. Its repository, workflow, run, tag object and peeled commit
arguments are caller observations. The attestation verifier binds the exact
tag ref, peeled commit and run attempt to the signed subject bundle; a
protected production workflow must separately verify the original owners and
obtain genuine tag/provider observations before calling this helper.
The held runtime digest detects changes during this operation; it does not
authenticate that runtime as the one published by the selected repository.

Success means that the checked-in external provenance verifier succeeded and
the native producer both recorded and reread the complete selected bytes. The
result is not owner authentication, publication approval, or tag-object
authentication, and this helper performs no tag or publication mutation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import signal
import stat
import subprocess
import sys
from typing import Any


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
VERIFIER_COMMAND = ("bash", str(HERE / "verify-provenance-attestation.sh"))
MAX_METADATA = 16 * 1024 * 1024
MAX_SUBJECT_MANIFEST = 1024 * 1024
MAX_RUNTIME = 1024 * 1024 * 1024
MAX_ARCHIVE = 32 * 1024 * 1024 * 1024
MAX_CHILD_OUTPUT = 16 * 1024 * 1024
PROVENANCE_TIMEOUT_SECONDS = 600
NATIVE_TIMEOUT_SECONDS = 5400
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
REPOSITORY = re.compile(r"[A-Za-z0-9._-]+/[A-Za-z0-9._-]+\Z")
WORKFLOW = re.compile(r"\.github/workflows/(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+\.yml\Z")
TAG = re.compile(
    r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-rc\.[1-9][0-9]*)?\Z"
)
SAFE_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,254}\Z")
ROOT_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
FILE_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
CREATE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)


class AdapterError(ValueError):
    """The selected evidence did not pass a closed recording boundary."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AdapterError(message)


def _exact_keys(value: object, keys: set[str], label: str) -> dict:
    _require(type(value) is dict and set(value) == keys,
             f"{label} has an unsupported closed shape")
    return value


def _digest(value: object, label: str) -> str:
    _require(isinstance(value, str) and HEX64.fullmatch(value) is not None,
             f"{label} must be a lowercase SHA-256 digest")
    return value


def _valid_workflow(value: object) -> bool:
    return (isinstance(value, str) and WORKFLOW.fullmatch(value) is not None
            and all(segment not in ("", ".", "..") for segment in value.split("/")))


def _positive_decimal(value: object, label: str) -> str:
    _require(isinstance(value, str) and re.fullmatch(r"[1-9][0-9]*", value) is not None
             and int(value) <= 2**64 - 1,
             f"{label} must be a positive canonical u64 decimal integer")
    return value


def _epoch(value: object, label: str) -> str:
    return _positive_decimal(value, label)


def _fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_nlink,
            metadata.st_uid, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns)


def _normalized_path(raw: object, label: str) -> Path:
    _require(isinstance(raw, str) and 0 < len(raw.encode("utf-8")) <= 4096
             and "\n" not in raw and "\r" not in raw and "\0" not in raw,
             f"{label} path is not bounded")
    _require(os.path.isabs(raw) and os.path.normpath(raw) == raw,
             f"{label} path must be absolute and normalized")
    path = Path(raw)
    _require(".." not in path.parts, f"{label} path may not contain parent traversal")
    return path


def _check_components(path: Path, label: str, *, must_exist: bool) -> None:
    _require(path.is_absolute() and ".." not in path.parts,
             f"{label} path must be absolute and normalized")
    try:
        resolved = path.resolve(strict=must_exist)
    except OSError as error:
        raise AdapterError(f"{label} path is unavailable") from error
    _require(resolved == path, f"{label} path has a symlink or noncanonical component")
    if must_exist:
        for component in (path, *path.parents):
            try:
                metadata = component.lstat()
            except OSError as error:
                raise AdapterError(f"{label} path is unavailable") from error
            _require(not stat.S_ISLNK(metadata.st_mode),
                     f"{label} path has a symlink component")


def _directory(path: Path, label: str, *, owned: bool = True) -> os.stat_result:
    _check_components(path, label, must_exist=True)
    try:
        metadata = path.lstat()
    except OSError as error:
        raise AdapterError(f"{label} directory is unavailable") from error
    _require(stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode),
             f"{label} is not an ordinary directory")
    if owned:
        _require(metadata.st_uid == os.geteuid(), f"{label} directory is not owned by this user")
    return metadata


def _read_owned(path: Path, limit: int, label: str, *, retain: bool = True,
                positive: bool = True) -> tuple[dict[str, Any], bytes | None, tuple[int, ...]]:
    """Check ownership, link count and size before hashing a no-follow file."""
    _check_components(path, label, must_exist=True)
    try:
        link_metadata = path.lstat()
    except OSError as error:
        raise AdapterError(f"{label} is unavailable") from error
    _require(stat.S_ISREG(link_metadata.st_mode) and not stat.S_ISLNK(link_metadata.st_mode)
             and link_metadata.st_nlink == 1 and link_metadata.st_uid == os.geteuid(),
             f"{label} is not an owned, singly linked regular file")
    _require((link_metadata.st_size > 0 or not positive) and link_metadata.st_size <= limit,
             f"{label} is empty or exceeds its {limit}-byte limit")
    try:
        descriptor = os.open(path, FILE_FLAGS)
    except OSError as error:
        raise AdapterError(f"{label} could not be opened without following links") from error
    digest = hashlib.sha256()
    chunks: list[bytes] | None = [] if retain else None
    total = 0
    try:
        before = os.fstat(descriptor)
        _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                 and before.st_uid == os.geteuid()
                 and (before.st_size > 0 or not positive) and before.st_size <= limit,
                 f"{label} changed to a non-owned, nonregular or oversized file")
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, limit + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            _require(total <= limit, f"{label} grew beyond its {limit}-byte limit")
            digest.update(chunk)
            if chunks is not None:
                chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    _require(_fingerprint(before) == _fingerprint(after) == _fingerprint(link_metadata)
             and total == before.st_size,
             f"{label} changed while being read")
    raw = b"".join(chunks) if chunks is not None else None
    return {"sha256": digest.hexdigest(), "size": total}, raw, _fingerprint(after)


def _json(raw: bytes | None, label: str) -> dict:
    _require(raw is not None, f"{label} bytes were not retained for parsing")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict:
        result = {}
        for key, value in pairs:
            _require(key not in result, f"{label} contains duplicate JSON keys")
            result[key] = value
        return result

    try:
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object,
                            parse_constant=lambda _value: (_ for _ in ()).throw(
                                AdapterError(f"{label} contains a non-JSON numeric value")))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AdapterError(f"{label} is not valid UTF-8 JSON") from error
    _require(type(parsed) is dict, f"{label} must be a JSON object")
    return parsed


def _stat_expected(path: Path, limit: int, label: str,
                   expected: dict[str, Any], fingerprint: tuple[int, ...] | None = None) -> None:
    measured, _raw, actual_fingerprint = _read_owned(path, limit, label, retain=False)
    _require(measured == expected and (fingerprint is None or actual_fingerprint == fingerprint),
             f"{label} changed after its independent selection")


def _path_overlaps(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents


def _selection_paths(value: object) -> list[Path]:
    paths: list[Path] = []

    def visit(item: object, key: str = "") -> None:
        if isinstance(item, dict):
            for child_key, child in item.items():
                if child_key in {"path", "package_dir", "directory", "root"} \
                        or child_key.endswith(("_dir", "_root")):
                    if isinstance(child, str) and child.startswith("/"):
                        candidate = _normalized_path(child, "selected evidence")
                        paths.append(candidate)
                visit(child, child_key)
        elif isinstance(item, list):
            for child in item:
                visit(child, key)

    visit(value)
    return paths


def _reference(value: object, label: str) -> dict:
    item = _exact_keys(value, {"path", "sha256"}, label)
    _normalized_path(item["path"], label)
    _digest(item["sha256"], f"{label} SHA-256")
    return item


def _subject_entries(raw: bytes, label: str) -> dict[str, str]:
    _require(raw.endswith(b"\n"), f"{label} must end with LF")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise AdapterError(f"{label} must contain canonical ASCII entries") from error
    entries: dict[str, str] = {}
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._+-]{0,254})", line)
        _require(match is not None, f"{label} contains a noncanonical subject entry")
        sha, name = match.groups()
        _require(name != "SHA256SUMS" and name not in entries,
                 f"{label} repeats or self-references a subject")
        entries[name] = sha
    _require(bool(entries), f"{label} has no subjects")
    return entries


def _preflight(args: argparse.Namespace) -> dict[str, Any]:
    runtime = _normalized_path(args.runtime, "selected runtime")
    release_dir = _normalized_path(args.release_dir, "release directory")
    selection_path = _normalized_path(args.selection, "release-evidence selection")
    subject_path = _normalized_path(args.subject_manifest, "subject manifest")
    summary_path = _normalized_path(args.candidate_summary, "candidate summary")
    operation_dir = _normalized_path(args.operation_dir, "operation directory")

    runtime_sha = _digest(args.runtime_sha256, "selected runtime digest")
    inputs_sha = _digest(args.inputs_sha256, "selected inputs digest")
    index_sha = _digest(args.index_sha256, "selected index digest")
    selection_sha = _digest(args.selection_sha256, "selected selection digest")
    subject_sha = _digest(args.subject_manifest_sha256, "selected subject-manifest digest")
    summary_sha = _digest(args.candidate_summary_sha256, "selected candidate-summary digest")
    _require(REPOSITORY.fullmatch(args.repository) is not None,
             "repository must be canonical OWNER/REPO")
    _require(_valid_workflow(args.workflow),
             "workflow must be a repository-relative .github/workflows/*.yml path")
    _positive_decimal(args.run_id, "run ID")
    _positive_decimal(args.run_attempt, "run attempt")
    _require(TAG.fullmatch(args.source_tag) is not None,
             "source tag must be a canonical vMAJOR.MINOR.PATCH or vMAJOR.MINOR.PATCH-rc.N release tag")
    _require(HEX40.fullmatch(args.source_tag_object) is not None
             and HEX40.fullmatch(args.source_tag_commit) is not None
             and args.source_tag_object != args.source_tag_commit,
             "source tag object and peeled commit must be distinct lowercase Git object IDs")
    created = int(_epoch(args.created_at, "creation epoch"))
    expires = int(_epoch(args.expires_at, "expiry epoch"))
    _require(expires > created, "expiry epoch must be later than creation epoch")

    _directory(release_dir, "selected release", owned=True)
    _require(operation_dir.name not in ("", ".", ".."),
             "operation directory must have a concrete basename")
    parent = operation_dir.parent
    _directory(parent, "operation directory parent", owned=True)
    _require(not os.path.lexists(operation_dir),
             "operation directory must be absent; refusing to adopt or overwrite it")

    forbidden_prefixes = []
    _require(type(args.forbidden_prefix) is list and bool(args.forbidden_prefix),
             "at least one repeated forbidden-prefix selector is required")
    for raw_prefix in args.forbidden_prefix:
        prefix = _normalized_path(raw_prefix, "forbidden prefix")
        _directory(prefix, "forbidden prefix", owned=False)
        _require(prefix not in forbidden_prefixes, "forbidden-prefix selectors must be unique")
        forbidden_prefixes.append(prefix)

    held: dict[Path, dict[str, Any]] = {}

    def selected(path: Path, limit: int, label: str, expected_sha: str | None = None,
                 *, retain: bool = False) -> tuple[bytes | None, dict[str, Any]]:
        measured, raw, fingerprint = _read_owned(path, limit, label, retain=retain)
        if expected_sha is not None:
            _require(measured["sha256"] == expected_sha,
                     f"{label} bytes differ from their held SHA-256 selector")
        held[path] = {"limit": limit, "label": label, "measurement": measured,
                      "fingerprint": fingerprint}
        return raw, measured

    runtime_measurement = selected(runtime, MAX_RUNTIME, "selected native runtime", runtime_sha)[1]
    runtime_stat = runtime.lstat()
    _require(runtime_stat.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH),
             "selected native runtime is not executable")

    selection_raw, _ = selected(selection_path, MAX_METADATA, "closed release-evidence selection",
                                selection_sha, retain=True)
    selection = _json(selection_raw, "closed release-evidence selection")
    selection = _exact_keys(selection, {"schema", "lanes", "sdk_packages", "sdk_generations"},
                            "closed release-evidence selection")
    _require(selection["schema"] == "aros-toolchain-release-evidence-selection-v2"
             and type(selection["lanes"]) is dict and type(selection["sdk_packages"]) is dict
             and type(selection["sdk_generations"]) is list,
             "release-evidence selection has the wrong schema or collection types")

    summary_raw, _ = selected(summary_path, MAX_METADATA, "candidate summary", summary_sha,
                              retain=True)
    summary = _json(summary_raw, "candidate summary")
    summary = _exact_keys(summary, {
        "schema", "operation", "assurance", "bindings", "release_root", "stage",
        "release_format", "outputs", "release_inventory", "counts", "scope",
    }, "candidate summary")
    _require(summary["schema"] == "aros-toolchain-release-candidate-assembly-v2"
             and summary["operation"] == "shared-native-pre-index-inventory"
             and summary["assurance"] == "complete-native-pre-index-inventory-no-admission"
             and summary["stage"] == "pre-attestation"
             and summary["release_format"] == "family-v2"
             and summary["release_root"] == str(release_dir),
             "candidate summary does not select this complete family-v2 release directory")
    bindings = summary["bindings"]
    _require(type(bindings) is dict and bindings.get("aros_sha256") == runtime_sha
             and bindings.get("inputs_sha256") == inputs_sha
             and bindings.get("release_id") and bindings.get("base_url"),
             "candidate summary runtime, inputs, or release identity differs from the selectors")
    expected_release_url = (
        f"https://github.com/{args.repository}/releases/download/{args.source_tag}"
    )
    _require(bindings.get("release_id") == args.source_tag,
             "candidate release ID must exactly equal the independently selected source tag")
    _require(bindings.get("base_url") == expected_release_url,
             "candidate download URL must exactly match the selected repository and source tag")
    _require(bindings.get("producer_commit") == args.source_tag_commit,
             "peeled source-tag observation differs from the selected candidate producer commit")
    scope = _exact_keys(summary["scope"], {
        "sdk_factory_execution_complete", "release_admission", "publication",
    }, "candidate summary scope")
    _require(scope == {"sdk_factory_execution_complete": False,
                       "release_admission": False, "publication": False},
             "candidate summary claims execution, admission, or publication authority")

    outputs = _exact_keys(summary["outputs"], {
        "index", "lane_inputs", "subject_manifest", "native_index_result", "sdk_sboms",
    }, "candidate summary outputs")
    index_selector = _exact_keys(outputs["index"], {"path", "sha256", "size"},
                                 "candidate index selector")
    summary_subject = _exact_keys(outputs["subject_manifest"], {"path", "sha256", "size"},
                                  "candidate subject-manifest selector")
    index_path = release_dir / "toolchain-index-v2.json"
    inputs_path = release_dir / "toolchain-release-inputs-v2.json"
    checksums_path = release_dir / "SHA256SUMS"
    bundle_path = release_dir / "toolchain-provenance.sigstore.json"
    _require(_normalized_path(index_selector["path"], "candidate index") == index_path
             and index_selector["sha256"] == index_sha
             and type(index_selector["size"]) is int and index_selector["size"] > 0,
             "candidate summary index selector differs from the exact release index selector")
    _require(_normalized_path(summary_subject["path"], "candidate subject manifest") == subject_path
             and summary_subject["sha256"] == subject_sha
             and type(summary_subject["size"]) is int and summary_subject["size"] > 0,
             "candidate summary subject-manifest selector differs from its independent selector")
    _require(not _path_overlaps(subject_path, release_dir),
             "external pre-attestation subject manifest must remain outside the release directory")

    index_raw, index_measurement = selected(index_path, MAX_METADATA,
                                            "selected native family-v2 index", index_sha,
                                            retain=True)
    _require(index_measurement["size"] == index_selector["size"],
             "candidate index selector size differs from the exact index bytes")
    index = _json(index_raw, "selected native family-v2 index")
    _require(set(index) in ({"schema", "release_id", "base_url", "inputs_sha256",
                             "producer_commit", "tools_commit", "artifacts"},
                            {"schema", "release_id", "base_url", "inputs_sha256",
                             "producer_commit", "tools_commit", "artifacts", "sdks"})
             and type(index["schema"]) is int and index["schema"] == 2
             and index["release_id"] == bindings["release_id"]
             and index["base_url"] == bindings["base_url"]
             and index["inputs_sha256"] == inputs_sha
             and index["producer_commit"] == args.source_tag_commit
             and type(index["artifacts"]) is list,
             "selected native index headers differ from the candidate and source observations")

    inputs_raw, inputs_measurement = selected(inputs_path, MAX_METADATA,
                                               "selected release-input collection", inputs_sha,
                                               retain=True)
    del inputs_raw  # The native CLI reacquires and validates the full input collection.

    inventory = summary["release_inventory"]
    _require(type(inventory) is dict and bool(inventory),
             "candidate summary release inventory is empty or malformed")
    checked_inventory: dict[str, dict[str, Any]] = {}
    for name, measured in inventory.items():
        _require(isinstance(name, str) and SAFE_COMPONENT.fullmatch(name) is not None
                 and name not in {"SHA256SUMS", "toolchain-provenance.sigstore.json"},
                 "candidate summary contains an unsafe or post-attestation inventory name")
        item = _exact_keys(measured, {"sha256", "size"}, "candidate inventory measurement")
        checked_inventory[name] = {
            "sha256": _digest(item["sha256"], "candidate inventory digest"),
            "size": item["size"],
        }
        _require(type(item["size"]) is int and 0 < item["size"] <= MAX_ARCHIVE,
                 "candidate inventory size is invalid")
    _require("toolchain-index-v2.json" in checked_inventory
             and checked_inventory["toolchain-index-v2.json"] == index_measurement
             and "toolchain-release-inputs-v2.json" in checked_inventory
             and checked_inventory["toolchain-release-inputs-v2.json"] == inputs_measurement,
             "candidate release inventory does not bind the selected index and inputs")

    subject_raw, subject_measurement = selected(
        subject_path, MAX_SUBJECT_MANIFEST, "pre-attestation subject manifest", subject_sha,
        retain=True,
    )
    _require(subject_measurement["size"] == summary_subject["size"],
             "subject-manifest selector size differs from the exact bytes")
    subject_entries = _subject_entries(subject_raw or b"", "pre-attestation subject manifest")
    _require(subject_entries == {name: item["sha256"] for name, item in checked_inventory.items()},
             "pre-attestation subjects do not exactly cover the held candidate inventory")

    checksums_measurement = selected(checksums_path, MAX_METADATA, "final checksum document")[1]
    bundle_measurement = selected(bundle_path, MAX_METADATA, "provenance bundle")[1]

    counts = _exact_keys(summary["counts"], {
        "lane_count", "sdk_count", "subject_count", "inventory_count",
    }, "candidate summary counts")
    lane_count = counts["lane_count"]
    sdk_count = counts["sdk_count"]
    subject_count = counts["subject_count"]
    inventory_count = counts["inventory_count"]
    _require(all(type(value) is int and value >= 0
                 for value in (lane_count, sdk_count, subject_count, inventory_count))
             and lane_count > 0 and subject_count == len(subject_entries) == len(checked_inventory)
             and inventory_count == subject_count + 2,
             "candidate summary counts do not match the complete held inventory")
    _require(lane_count == len(index["artifacts"]) == len(selection["lanes"])
             and sdk_count == len(index.get("sdks", [])) == len(selection["sdk_packages"]),
             "candidate, index and selection compiler or SDK counts differ")

    assets: dict[str, dict[str, Any]] = {}
    for artifact in index["artifacts"]:
        _require(type(artifact) is dict and isinstance(artifact.get("asset"), str)
                 and SAFE_COMPONENT.fullmatch(artifact["asset"]) is not None
                 and artifact["asset"] not in assets,
                 "native index has an invalid or duplicate compiler asset")
        assets[artifact["asset"]] = artifact
    _require(set(assets) == set(selection["lanes"]),
             "selected compiler assets do not exactly cover the native index")
    for asset, lane in selection["lanes"].items():
        _require(isinstance(asset, str) and SAFE_COMPONENT.fullmatch(asset) is not None
                 and type(lane) is dict and type(lane.get("builds")) is list
                 and len(lane["builds"]) == 2,
                 "closed selection has an invalid compiler lane")
        for position, build in enumerate(lane["builds"]):
            _require(type(build) is dict and type(build.get("measurement")) is dict,
                     "closed selection build report reference is malformed")
            _digest(build["measurement"].get("sha256"),
                    f"{asset} build {position} measurement digest")
        comparison = lane.get("comparison")
        compatibility = lane.get("compatibility")
        _require(type(comparison) is dict and type(compatibility) is dict
                 and type(compatibility.get("inputs")) is dict,
                 "closed selection comparison or compatibility reference is malformed")
        _digest(comparison.get("sha256"), f"{asset} comparison digest")
        _digest(compatibility["inputs"].get("sha256"),
                f"{asset} compatibility-input digest")
        _digest(compatibility.get("manifest_sha256"),
                f"{asset} compatibility-manifest digest")

    index_sdks = index.get("sdks", [])
    sdk_ids: set[str] = set()
    for sdk in index_sdks:
        _require(type(sdk) is dict and type(sdk.get("identity")) is dict
                 and isinstance(sdk["identity"].get("sdk_id"), str),
                 "native index has a malformed SDK identity")
        sdk_id = sdk["identity"]["sdk_id"]
        _require(sdk_id not in sdk_ids, "native index has duplicate SDK identities")
        sdk_ids.add(sdk_id)
    _require(sdk_ids == set(selection["sdk_packages"]),
             "selected SDK products do not exactly cover the native index")
    for sdk_id, package in selection["sdk_packages"].items():
        _require(isinstance(sdk_id, str) and type(package) is dict
                 and type(package.get("archive_size")) is int and package["archive_size"] > 0,
                 "closed selection has a malformed SDK package measurement")
        for field in ("tree_sha256", "archive_sha256"):
            _digest(package.get(field), f"{sdk_id} {field}")

    generation_rows = selection["sdk_generations"]
    generation_tuples: set[tuple[str, str, str, str]] = set()
    for generation in generation_rows:
        _require(type(generation) is dict, "closed selection has a malformed SDK generation")
        fields = tuple(generation.get(field) for field in
                       ("sdk_id", "group_id", "target_profile", "host"))
        _require(all(isinstance(value, str) and value for value in fields)
                 and fields not in generation_tuples,
                 "closed selection has an invalid or duplicate SDK generation tuple")
        generation_tuples.add(fields)
        _reference(generation.get("record"), "SDK generation record")
        compatibility = generation.get("compatibility")
        _require(type(compatibility) is dict,
                 "SDK generation compatibility selector is malformed")
        _digest(compatibility.get("manifest_sha256"), "SDK generation compatibility manifest")
    _require((sdk_count == 0 and not generation_rows)
             or (sdk_count > 0 and bool(generation_rows)),
             "SDK product and generation coverage are inconsistent")

    selection_roots = _selection_paths(selection)
    held_paths = list(held)
    protected = [release_dir, runtime, selection_path, subject_path, summary_path,
                 *held_paths, *selection_roots, *forbidden_prefixes]
    for protected_path in protected:
        _require(not _path_overlaps(operation_dir, protected_path),
                 "operation directory overlaps selected runtime, release or evidence")
    return {
        "runtime": runtime, "runtime_sha256": runtime_sha,
        "runtime_measurement": runtime_measurement,
        "release_dir": release_dir, "selection_path": selection_path,
        "selection_sha256": selection_sha, "selection": selection,
        "summary_path": summary_path, "summary_sha256": summary_sha, "summary": summary,
        "subject_path": subject_path, "subject_sha256": subject_sha,
        "subject_count": subject_count, "subject_entries": subject_entries,
        "index_path": index_path, "index_sha256": index_sha, "index": index,
        "inputs_sha256": inputs_sha, "checksums_sha256": checksums_measurement["sha256"],
        "bundle_path": bundle_path, "bundle_sha256": bundle_measurement["sha256"],
        "sdk_count": sdk_count, "lane_count": lane_count,
        "generation_count": len(generation_rows),
        "source_run": {
            "repository": f"https://github.com/{args.repository}",
            "workflow": args.workflow,
            "run_id": int(args.run_id), "run_attempt": int(args.run_attempt),
            "source_tag": args.source_tag, "tag_object": args.source_tag_object,
            "producer_commit": args.source_tag_commit,
        },
        "attestation_repository": f"https://github.com/{args.repository}",
        "attestation_workflow": args.workflow,
        "attestation_signer": "github-actions",
        "created_at": created, "expires_at": expires,
        "forbidden_prefixes": forbidden_prefixes,
        "held": held,
    }


def _check_held(held: dict[Path, dict[str, Any]]) -> None:
    for path, selection in held.items():
        _stat_expected(path, selection["limit"], selection["label"],
                       selection["measurement"], selection["fingerprint"])


def _create_file(path: Path, label: str):
    descriptor = os.open(path, CREATE_FLAGS, 0o600)
    metadata = os.fstat(descriptor)
    _require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
             and metadata.st_uid == os.geteuid(),
             f"{label} output is not an owned, singly linked regular file")
    os.fchmod(descriptor, 0o600)
    return os.fdopen(descriptor, "wb")


def _write_exclusive(path: Path, data: bytes, label: str) -> None:
    _require(len(data) <= MAX_METADATA, f"{label} exceeds its metadata limit")
    with _create_file(path, label) as handle:
        view = memoryview(data)
        while view:
            written = handle.write(view)
            _require(written is not None and written > 0, f"could not write {label}")
            view = view[written:]
        handle.flush()
        os.fsync(handle.fileno())


def _limit_child_files() -> None:
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_CHILD_OUTPUT, MAX_CHILD_OUTPUT))


def _run_child(operation_dir: Path, name: str, command: list[str], timeout: float,
               held: dict[Path, dict[str, Any]], *, cwd: Path) -> tuple[bytes, bytes]:
    stdout_path = operation_dir / f"{name}.stdout.log"
    stderr_path = operation_dir / f"{name}.stderr.log"
    _require(not os.path.lexists(stdout_path) and not os.path.lexists(stderr_path),
             f"{name} diagnostic paths are not fresh")
    _check_held(held)
    stdout_handle = _create_file(stdout_path, f"{name} stdout")
    stderr_handle = _create_file(stderr_path, f"{name} stderr")
    return_code: int | None = None
    timed_out = False
    try:
        process = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=stdout_handle, stderr=stderr_handle,
            cwd=cwd, close_fds=True, start_new_session=True,
            preexec_fn=_limit_child_files,
        )
        try:
            return_code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
    except OSError as error:
        raise AdapterError(f"could not start {name}; bounded diagnostics retained") from error
    finally:
        stdout_handle.close()
        stderr_handle.close()
    _check_held(held)
    stdout_measurement, stdout_raw, _ = _read_owned(
        stdout_path, MAX_CHILD_OUTPUT, f"{name} stdout log", retain=True, positive=False
    )
    stderr_measurement, stderr_raw, _ = _read_owned(
        stderr_path, MAX_CHILD_OUTPUT, f"{name} stderr log", retain=True, positive=False
    )
    _require(stdout_measurement["size"] <= MAX_CHILD_OUTPUT
             and stderr_measurement["size"] <= MAX_CHILD_OUTPUT,
             f"{name} exceeded its retained output limit")
    if timed_out:
        raise AdapterError(f"{name} timed out after {timeout}s; its process group was terminated; "
                           f"bounded diagnostics retained at {stderr_path}")
    _require(return_code == 0,
             f"{name} failed with exit status {return_code}; bounded diagnostics retained at {stderr_path}")
    return stdout_raw or b"", stderr_raw or b""


def _parse_child_json(raw: bytes, label: str) -> dict:
    parsed = _json(raw, label)
    return parsed


def _native_common(state: dict[str, Any]) -> list[str]:
    return [str(state["runtime"]), "toolchain", "producer"]


def _forbidden_args(state: dict[str, Any]) -> list[str]:
    return [argument for prefix in state["forbidden_prefixes"]
            for argument in ("--forbidden-prefix", str(prefix))]


def _record_argv(args: argparse.Namespace, state: dict[str, Any],
                 output_path: Path) -> list[str]:
    source = state["source_run"]
    argv = _native_common(state) + [
        "record-qualification", "--release-format", "family-v2",
        *_forbidden_args(state),
        "--release-dir", str(state["release_dir"]),
        "--inputs-sha256", state["inputs_sha256"],
        "--index-sha256", state["index_sha256"],
        "--selection", str(state["selection_path"]),
        "--selection-sha256", state["selection_sha256"],
        "--subject-manifest", str(state["subject_path"]),
        "--subject-manifest-sha256", state["subject_sha256"],
        "--source-repository", source["repository"],
        "--source-workflow", source["workflow"],
        "--source-run-id", str(source["run_id"]),
        "--source-run-attempt", str(source["run_attempt"]),
        "--source-tag", source["source_tag"],
        "--source-tag-object", source["tag_object"],
        "--source-tag-commit", source["producer_commit"],
        "--attestation-repository", state["attestation_repository"],
        "--attestation-workflow", state["attestation_workflow"],
        "--attestation-signer", state["attestation_signer"],
        "--created-at", str(state["created_at"]),
        "--expires-at", str(state["expires_at"]),
        "--output", str(output_path), "--format", "json",
    ]
    return argv


def _verify_argv(state: dict[str, Any], evidence_path: Path, evidence_sha: str,
                 policy_path: Path, policy_sha: str) -> list[str]:
    summary = state["summary"]
    argv = _native_common(state) + [
        "verify-qualification", *_forbidden_args(state),
        "--directory", str(state["release_dir"]),
        "--release-id", summary["bindings"]["release_id"],
        "--base-url", summary["bindings"]["base_url"],
        "--inputs-sha256", state["inputs_sha256"],
        "--index-sha256", state["index_sha256"],
        "--selection", str(state["selection_path"]),
        "--selection-sha256", state["selection_sha256"],
        "--subject-manifest", str(state["subject_path"]),
        "--subject-manifest-sha256", state["subject_sha256"],
        "--qualification-evidence", str(evidence_path),
        "--qualification-sha256", evidence_sha,
        "--policy", str(policy_path),
        "--policy-sha256", policy_sha,
        "--format", "json",
    ]
    return argv


def _parse_result(raw: bytes, label: str) -> dict:
    result = _parse_child_json(raw, label)
    _require(result.get("schema") == "aros-toolchain-producer-stage-v2"
             and result.get("release_format") == "family-v2"
             and result.get("assurance") == "byte-consistency-only",
             f"{label} returned an unexpected family-v2 result envelope")
    operation = result.get("operation")
    base = {
        "schema", "operation", "release_format", "assurance", "release_id",
        "inputs_sha256", "index_sha256", "selection_sha256",
        "subject_manifest_sha256", "checksums_sha256", "provenance_sha256",
        "lane_count", "build_count", "lanes",
    }
    if operation == "record-qualification":
        expected = base | {"qualification_sha256", "qualification_evidence"}
    elif operation == "verify-qualification":
        expected = base | {"qualification_sha256", "policy_sha256"}
    else:
        raise AdapterError(f"{label} returned an unexpected operation name")
    sdk_fields = {"sdk_count", "sdks", "sdk_generation_count", "sdk_generations"}
    _require(set(result) in (expected, expected | {"sdk_count", "sdks"},
                            expected | {"sdk_generation_count", "sdk_generations"},
                            expected | sdk_fields),
             f"{label} returned an unsupported closed result shape")
    for field in ("execution_authenticated", "signature_verified", "job_origin_verified",
                  "publication_authorized", "recovery_authorized"):
        _require(result.get(field) is not True,
                 f"{label} returned an unsupported authority claim")
    return result


def _expected_generations(selection: dict) -> list[dict[str, Any]]:
    expected = []
    for row in selection["sdk_generations"]:
        expected.append({
            "sdk_id": row["sdk_id"], "group_id": row["group_id"],
            "target_profile": row["target_profile"], "host": row["host"],
            "generation_record_sha256": row["record"]["sha256"],
            "compatibility_manifest_sha256": row["compatibility"]["manifest_sha256"],
        })
    return sorted(expected, key=lambda row: tuple(row[key] for key in
                                                   ("sdk_id", "group_id", "target_profile", "host")))


def _check_readback_result(result: dict, state: dict[str, Any], *, operation: str,
                           evidence_sha: str | None = None,
                           policy_sha: str | None = None) -> None:
    selection = state["selection"]
    summary = state["summary"]
    lane_count = state["lane_count"]
    sdk_count = state["sdk_count"]
    generations = _expected_generations(selection)
    _require(result.get("operation") == operation
             and result.get("release_id") == summary["bindings"]["release_id"]
             and result.get("inputs_sha256") == state["inputs_sha256"]
             and result.get("index_sha256") == state["index_sha256"]
             and result.get("selection_sha256") == state["selection_sha256"]
             and result.get("subject_manifest_sha256") == state["subject_sha256"]
             and result.get("checksums_sha256") == state["checksums_sha256"]
             and result.get("provenance_sha256") == state["bundle_sha256"],
             f"{operation} result does not bind the selected release and provenance bytes")
    _require(type(result.get("lane_count")) is int and result["lane_count"] == lane_count
             and type(result.get("build_count")) is int and result["build_count"] == lane_count * 2
             and type(result.get("lanes")) is list and len(result["lanes"]) == lane_count,
             f"{operation} result does not cover the complete compiler lane set")
    expected_assets = set(selection["lanes"])
    actual_assets = [lane.get("asset") for lane in result["lanes"] if type(lane) is dict]
    _require(len(actual_assets) == lane_count and len(set(actual_assets)) == lane_count
             and set(actual_assets) == expected_assets,
             f"{operation} result compiler assets differ from the closed selection")
    for row in result["lanes"]:
        _exact_keys(row, {
            "asset", "measurement_sha256", "build_result_sha256", "finished_receipt_sha256",
            "comparison_sha256", "compatibility_inputs_sha256",
            "compatibility_manifest_sha256", "compatibility_receipt_sha256", "standalone",
        }, f"{operation} compiler lane result")
        asset = row["asset"]
        selected_lane = selection["lanes"][asset]
        selected_measurements = [
            selected_lane["builds"][0]["measurement"]["sha256"],
            selected_lane["builds"][1]["measurement"]["sha256"],
        ]
        _require(row.get("measurement_sha256") == selected_measurements
                 and row.get("comparison_sha256") == selected_lane["comparison"]["sha256"]
                 and row.get("compatibility_inputs_sha256")
                 == selected_lane["compatibility"]["inputs"]["sha256"]
                 and row.get("compatibility_manifest_sha256")
                 == selected_lane["compatibility"]["manifest_sha256"],
                 f"{operation} measured compiler digests differ for {asset}")
    _require(type(result.get("sdk_count", 0)) is int
             and result.get("sdk_count", 0) == sdk_count,
             f"{operation} result SDK product count differs from the candidate summary")
    actual_sdks = result.get("sdks", [])
    _require(type(actual_sdks) is list and len(actual_sdks) == sdk_count,
             f"{operation} result does not cover the complete SDK product set")
    expected_sdks = selection["sdk_packages"]
    sdk_rows = {}
    for row in actual_sdks:
        _require(type(row) is dict and isinstance(row.get("sdk_id"), str)
                 and row["sdk_id"] not in sdk_rows,
                 f"{operation} result has a duplicate or malformed SDK product")
        _exact_keys(row, {"sdk_id", "identity", "tree_sha256", "archive_sha256", "archive_size",
                          "manifest_sha256", "manifest_size"},
                    f"{operation} SDK product result")
        sdk_rows[row["sdk_id"]] = row
    _require(set(sdk_rows) == set(expected_sdks),
             f"{operation} SDK products differ from the closed selection")
    for sdk_id, row in sdk_rows.items():
        selected_sdk = expected_sdks[sdk_id]
        _require(row.get("tree_sha256") == selected_sdk["tree_sha256"]
                 and row.get("archive_sha256") == selected_sdk["archive_sha256"]
                 and row.get("archive_size") == selected_sdk["archive_size"],
                 f"{operation} measured SDK digests differ for {sdk_id}")
    actual_generations = result.get("sdk_generations", [])
    _require(type(actual_generations) is list and len(actual_generations) == len(generations)
             and type(result.get("sdk_generation_count", 0)) is int
             and result.get("sdk_generation_count", 0) == len(generations),
             f"{operation} result does not cover the complete SDK generation matrix")
    normalized_actual = []
    for row in actual_generations:
        _exact_keys(row, {
            "sdk_id", "group_id", "target_profile", "host", "generation_record_sha256",
            "compatibility_manifest_sha256", "compatibility_receipt_sha256",
            "sdk_link_receipt_sha256",
        }, f"{operation} SDK generation result")
        normalized_actual.append({key: row.get(key) for key in (
            "sdk_id", "group_id", "target_profile", "host",
            "generation_record_sha256", "compatibility_manifest_sha256",
        )})
        _digest(row.get("generation_record_sha256"), "measured generation-record digest")
        _digest(row.get("compatibility_manifest_sha256"),
                "measured generation compatibility digest")
        _digest(row.get("compatibility_receipt_sha256"),
                "measured generation compatibility receipt digest")
        _digest(row.get("sdk_link_receipt_sha256"), "measured SDK-link receipt digest")
    _require(sorted(normalized_actual, key=lambda row: tuple(row[key] for key in
                                                               ("sdk_id", "group_id", "target_profile", "host")))
             == generations,
             f"{operation} SDK generation tuples or selected record digests differ")
    if evidence_sha is not None:
        _require(result.get("qualification_sha256") == evidence_sha,
                 "verify-qualification result reports a different qualification digest")
    if policy_sha is not None:
        _require(result.get("policy_sha256") == policy_sha,
                 "verify-qualification result reports a different policy digest")


def _check_recorded_evidence(evidence: dict, state: dict[str, Any]) -> None:
    evidence_keys = {
        "schema", "created_at", "expires_at", "source_run", "release", "attestation",
        "lanes", "coverage",
    }
    if state["generation_count"]:
        evidence_keys.add("sdk_generations")
    _exact_keys(evidence, evidence_keys, "recorded qualification evidence")
    source = evidence.get("source_run")
    _exact_keys(source, {
        "repository", "workflow", "run_id", "run_attempt", "producer_commit",
        "source_tag", "tag_object",
    }, "recorded source-run identity")
    _require(type(source) is dict and source.get("repository") == state["source_run"]["repository"]
             and source.get("workflow") == state["source_run"]["workflow"]
             and source.get("run_id") == state["source_run"]["run_id"]
             and source.get("run_attempt") == state["source_run"]["run_attempt"]
             and source.get("producer_commit") == state["source_run"]["producer_commit"]
             and source.get("source_tag") == state["source_run"]["source_tag"]
             and source.get("tag_object") == state["source_run"]["tag_object"],
             "recorded qualification differs from explicit source-run observations")
    release = evidence.get("release")
    _exact_keys(release, {
        "release_id", "base_url", "inputs_sha256", "release_index_sha256",
        "pre_attestation_checksums_sha256", "checksums_sha256", "provenance_sha256",
        "producer_commit", "tools_commit",
    }, "recorded release identity")
    summary = state["summary"]
    _require(type(release) is dict
             and release.get("release_id") == summary["bindings"]["release_id"]
             and release.get("base_url") == summary["bindings"]["base_url"]
             and release.get("inputs_sha256") == state["inputs_sha256"]
             and release.get("release_index_sha256") == state["index_sha256"]
             and release.get("pre_attestation_checksums_sha256") == state["subject_sha256"]
             and release.get("checksums_sha256") == state["checksums_sha256"]
             and release.get("provenance_sha256") == state["bundle_sha256"]
             and release.get("producer_commit") == state["source_run"]["producer_commit"]
             and release.get("tools_commit") == state["index"]["tools_commit"],
             "recorded qualification differs from selected release and provenance identities")
    attestation = evidence.get("attestation")
    _exact_keys(attestation, {
        "repository", "workflow", "signer", "subject_manifest_sha256",
    }, "recorded attestation identity")
    _require(type(attestation) is dict
             and attestation.get("repository") == state["attestation_repository"]
             and attestation.get("workflow") == state["attestation_workflow"]
             and attestation.get("signer") == state["attestation_signer"]
             and attestation.get("subject_manifest_sha256") == state["subject_sha256"],
             "recorded qualification differs from externally verified attestation selectors")
    _require(evidence.get("schema") == "aros-toolchain-qualification-evidence-v2"
             and evidence.get("coverage") == "release-candidate"
             and type(evidence.get("created_at")) is int
             and evidence["created_at"] == state["created_at"]
             and type(evidence.get("expires_at")) is int
             and evidence["expires_at"] == state["expires_at"],
             "recorded qualification is not a full V2 release-candidate claim")

    artifacts = {row["asset"]: row for row in state["index"]["artifacts"]}
    lanes = evidence.get("lanes")
    _require(type(lanes) is list and len(lanes) == state["lane_count"],
             "recorded qualification does not cover the complete candidate compiler matrix")
    lane_by_asset = {}
    for lane in lanes:
        _require(type(lane) is dict and isinstance(lane.get("asset"), str)
                 and lane["asset"] not in lane_by_asset,
                 "recorded qualification has a duplicate or malformed compiler lane")
        _exact_keys(lane, {
            "group_id", "asset", "host", "target_profile", "target_triple", "source_commit",
            "compiler", "recipe_sha256", "source_lock_sha256", "profiles_sha256",
            "archive_sha256", "archive_size", "tree_sha256", "build_a_report_sha256",
            "build_b_report_sha256", "comparison_report_sha256", "compatibility_report_sha256",
        }, "recorded qualification compiler lane")
        asset = lane["asset"]
        lane_by_asset[asset] = lane
        artifact = artifacts.get(asset)
        selected = state["selection"]["lanes"].get(asset)
        _require(artifact is not None and selected is not None
                 and lane.get("group_id") == artifact.get("group_id")
                 and lane.get("host") == artifact.get("host")
                 and lane.get("target_profile") == artifact.get("target_profile")
                 and lane.get("target_triple") == artifact.get("target_triple")
                 and lane.get("source_commit") == artifact.get("source_commit")
                 and lane.get("compiler") == artifact.get("compiler")
                 and lane.get("archive_sha256") == artifact.get("sha256")
                 and lane.get("archive_size") == artifact.get("size")
                 and lane.get("tree_sha256") == artifact.get("tree_sha256")
                 and lane.get("build_a_report_sha256")
                 == selected["builds"][0]["measurement"]["sha256"]
                 and lane.get("build_b_report_sha256")
                 == selected["builds"][1]["measurement"]["sha256"]
                 and lane.get("comparison_report_sha256") == selected["comparison"]["sha256"]
                 and lane.get("compatibility_report_sha256")
                 == selected["compatibility"]["manifest_sha256"],
                 f"recorded qualification tuple or measured digest differs for {asset}")
    _require(set(lane_by_asset) == set(artifacts) == set(state["selection"]["lanes"]),
             "recorded qualification omits or adds a compiler asset")

    expected_generations = _expected_generations(state["selection"])
    evidence_generations = evidence.get("sdk_generations", [])
    _require(type(evidence_generations) is list
             and len(evidence_generations) == len(expected_generations),
             "recorded qualification does not cover the complete SDK generation matrix")
    mapped_claims = []
    for row in evidence_generations:
        _exact_keys(row, {
            "sdk_id", "group_id", "target_profile", "host", "generation_record_sha256",
            "compatibility_report_sha256", "compatibility_receipt_sha256",
            "sdk_link_receipt_sha256",
        }, "recorded qualification SDK generation claim")
        _digest(row.get("generation_record_sha256"), "recorded generation-record digest")
        _digest(row.get("compatibility_report_sha256"),
                "recorded generation compatibility report digest")
        _digest(row.get("compatibility_receipt_sha256"),
                "recorded generation compatibility receipt digest")
        _digest(row.get("sdk_link_receipt_sha256"), "recorded SDK-link receipt digest")
        mapped_claims.append({
            "sdk_id": row.get("sdk_id"), "group_id": row.get("group_id"),
            "target_profile": row.get("target_profile"), "host": row.get("host"),
            "generation_record_sha256": row.get("generation_record_sha256"),
            "compatibility_manifest_sha256": row.get("compatibility_report_sha256"),
        })
    _require(sorted(mapped_claims, key=lambda row: tuple(row[key] for key in
                                                           ("sdk_id", "group_id", "target_profile", "host")))
             == expected_generations,
             "recorded qualification SDK generation tuples or digests differ from selection")


def run(args: argparse.Namespace) -> dict[str, Any]:
    state = _preflight(args)
    operation_dir = _normalized_path(args.operation_dir, "operation directory")
    os.mkdir(operation_dir, 0o700)
    operation_metadata = operation_dir.lstat()
    _require(stat.S_ISDIR(operation_metadata.st_mode)
             and operation_metadata.st_uid == os.geteuid()
             and not stat.S_ISLNK(operation_metadata.st_mode),
             "new operation directory is not an owned ordinary directory")

    verification_path = operation_dir / "external-provenance-verification.json"
    verification_command = [
        *VERIFIER_COMMAND,
        "--subject-manifest", str(state["subject_path"]),
        "--subject-manifest-sha256", state["subject_sha256"],
        "--subject-dir", str(state["release_dir"]),
        "--bundle", str(state["bundle_path"]),
        "--repository", args.repository,
        "--signer-workflow", f"{args.repository}/{args.workflow}",
        "--source-digest", args.source_tag_commit,
        "--source-ref", f"refs/tags/{args.source_tag}",
        "--run-id", args.run_id,
        "--run-attempt", args.run_attempt,
        "--output", str(verification_path),
    ]
    _run_child(operation_dir, "provenance-verifier", verification_command,
               PROVENANCE_TIMEOUT_SECONDS, state["held"], cwd=HERE.parent.parent)
    verification_measurement, verification_raw, verification_fingerprint = _read_owned(
        verification_path, MAX_METADATA, "external verifier result", retain=True
    )
    verification_json = _json_array(verification_raw or b"", "external verifier result")
    _require(bool(verification_json), "external verifier returned no verified attestations")
    state["held"][verification_path] = {
        "limit": MAX_METADATA, "label": "external verifier result",
        "measurement": verification_measurement, "fingerprint": verification_fingerprint,
    }
    _check_held(state["held"])

    policy_path = operation_dir / "evidence-policy.json"
    policy = {
        "source_repository": state["source_run"]["repository"],
        "source_workflow": state["source_run"]["workflow"],
        "signer_repository": state["attestation_repository"],
        "signer_workflow": state["attestation_workflow"],
        "signer": state["attestation_signer"],
        "now": state["created_at"],
    }
    policy_bytes = (json.dumps(policy, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    _write_exclusive(policy_path, policy_bytes, "V2 evidence policy")
    policy_measurement, _policy_raw, policy_fingerprint = _read_owned(
        policy_path, MAX_METADATA, "V2 evidence policy", retain=False
    )
    state["held"][policy_path] = {
        "limit": MAX_METADATA, "label": "V2 evidence policy",
        "measurement": policy_measurement, "fingerprint": policy_fingerprint,
    }
    policy_sha = policy_measurement["sha256"]

    pending_path = operation_dir / ".qualification-evidence-pending.json"
    record_command = _record_argv(args, state, pending_path)
    record_raw, _record_stderr = _run_child(
        operation_dir, "native-record", record_command, NATIVE_TIMEOUT_SECONDS,
        state["held"], cwd=HERE.parent.parent,
    )
    record_result = _parse_result(record_raw, "native record-qualification")
    _require(record_result.get("qualification_evidence") == str(pending_path),
             "record-qualification reported a different qualification output path")
    record_measurement, evidence_raw, evidence_fingerprint = _read_owned(
        pending_path, MAX_METADATA, "recorded qualification evidence", retain=True
    )
    evidence_sha = record_measurement["sha256"]
    _require(record_result.get("qualification_sha256") == evidence_sha,
             "record-qualification reported a different raw qualification digest")
    evidence = _json(evidence_raw, "recorded qualification evidence")
    _check_recorded_evidence(evidence, state)
    _check_readback_result(record_result, state, operation="record-qualification")
    state["held"][pending_path] = {
        "limit": MAX_METADATA, "label": "pending recorded qualification evidence",
        "measurement": record_measurement, "fingerprint": evidence_fingerprint,
    }
    _check_held(state["held"])

    verify_command = _verify_argv(state, pending_path, evidence_sha, policy_path, policy_sha)
    verify_raw, _verify_stderr = _run_child(
        operation_dir, "native-verify", verify_command, NATIVE_TIMEOUT_SECONDS,
        state["held"], cwd=HERE.parent.parent,
    )
    verify_result = _parse_result(verify_raw, "native verify-qualification")
    _check_readback_result(verify_result, state, operation="verify-qualification",
                           evidence_sha=evidence_sha, policy_sha=policy_sha)
    _check_readback_result(record_result, state, operation="record-qualification")
    _require(verify_result.get("lanes") == record_result.get("lanes")
             and verify_result.get("sdks", []) == record_result.get("sdks", [])
             and verify_result.get("sdk_generations", []) == record_result.get("sdk_generations", []),
             "recording and qualification readback measured different compiler or SDK tuples")
    _check_held(state["held"])

    final_evidence_path = operation_dir / "qualification-evidence-v2.json"
    _require(not os.path.lexists(final_evidence_path),
             "final qualification evidence output unexpectedly exists")
    final_bytes = evidence_raw or b""
    _write_exclusive(final_evidence_path, final_bytes, "verified qualification evidence")
    final_measurement, _final_raw, _ = _read_owned(
        final_evidence_path, MAX_METADATA, "verified qualification evidence", retain=False
    )
    _require(final_measurement["sha256"] == evidence_sha
             and final_measurement["size"] == record_measurement["size"],
             "final qualification evidence differs from the fully reread native record")
    _check_held(state["held"])

    return {
        "schema": "aros-toolchain-full-qualification-record-adapter-v2",
        "operation": "record-full-qualification",
        "assurance": "external-provenance-and-native-byte-consistency-only",
        "qualification_evidence": {"path": str(final_evidence_path), "sha256": evidence_sha},
        "evidence_policy": {"path": str(policy_path), "sha256": policy_sha},
        "external_verifier_result": {
            "path": str(verification_path), "sha256": verification_measurement["sha256"],
            "bundle_sha256": state["bundle_sha256"],
        },
        "source_observation": {
            "repository": args.repository, "workflow": args.workflow,
            "run_id": state["source_run"]["run_id"],
            "run_attempt": state["source_run"]["run_attempt"],
            "tag": args.source_tag, "tag_object": args.source_tag_object,
            "peeled_commit": args.source_tag_commit,
        },
        "counts": {
            "lane_count": state["lane_count"], "build_count": state["lane_count"] * 2,
            "sdk_count": state["sdk_count"],
            "sdk_generation_count": state["generation_count"],
        },
        "scope": {
            "provider_run_attempt_verified_by_external_attestation": True,
            "tag_object_independently_authenticated": False,
            "original_owner_jobs_verified_by_this_adapter": False,
            "runtime_publication_verified_by_this_adapter": False,
            "publication": False,
        },
    }


def _json_array(raw: bytes, label: str) -> list:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict:
        result = {}
        for key, value in pairs:
            _require(key not in result, f"{label} contains duplicate JSON keys")
            result[key] = value
        return result

    try:
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AdapterError(f"{label} is not valid UTF-8 JSON") from error
    _require(type(parsed) is list, f"{label} must be a JSON array")
    return parsed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", required=True)
    parser.add_argument("--runtime-sha256", required=True)
    parser.add_argument("--release-dir", required=True)
    parser.add_argument("--inputs-sha256", required=True)
    parser.add_argument("--index-sha256", required=True)
    parser.add_argument("--selection", required=True)
    parser.add_argument("--selection-sha256", required=True)
    parser.add_argument("--subject-manifest", required=True)
    parser.add_argument("--subject-manifest-sha256", required=True)
    parser.add_argument("--candidate-summary", required=True)
    parser.add_argument("--candidate-summary-sha256", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--workflow", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    parser.add_argument("--source-tag", required=True)
    parser.add_argument("--source-tag-object", required=True)
    parser.add_argument("--source-tag-commit", required=True)
    parser.add_argument("--created-at", required=True)
    parser.add_argument("--expires-at", required=True)
    parser.add_argument("--operation-dir", required=True)
    parser.add_argument("--forbidden-prefix", action="append", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        result = run(_parser().parse_args(argv))
    except (AdapterError, OSError, subprocess.SubprocessError, KeyError, TypeError) as error:
        print(f"complete V2 qualification recording failed: {error}", file=sys.stderr)
        return 1
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
