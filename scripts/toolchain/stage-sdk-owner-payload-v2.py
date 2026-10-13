#!/usr/bin/env python3
"""Stage one SDK owner's bounded portable byte payload.

This is a closed transport boundary. Its result establishes only consistency
of the bytes observed while staging; it does not establish host execution,
job ownership, SDK validity, release qualification, signing, or publication.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys


_ORIGIN_PATH = Path(__file__).with_name("artifact-origin.py")
_ORIGIN_SPEC = importlib.util.spec_from_file_location("artifact_origin_for_sdk_stage", _ORIGIN_PATH)
if _ORIGIN_SPEC is None or _ORIGIN_SPEC.loader is None:  # pragma: no cover - installation failure
    raise RuntimeError("artifact-origin helper is unavailable")
_ORIGIN = importlib.util.module_from_spec(_ORIGIN_SPEC)
_ORIGIN_SPEC.loader.exec_module(_ORIGIN)


SCHEMA = "aros-sdk-owner-payload-v2"
ASSURANCE = "staging-byte-consistency-only"
GNU_GENERATION_SCHEMA = "aros-sdk-generation-record-v1"
LLVM_GENERATION_SCHEMA = "aros-llvm-sdk-generation-record-v1"
GENERATION_ASSURANCE = "local-generation-binding-not-release-admission"
SDK_MANIFEST_SCHEMA = "aros-sdk-manifest-v2"
GNU_MEASUREMENT_SCHEMA = "aros-toolchain-compatibility-measurement-v3"
LLVM_MEASUREMENT_SCHEMA = "aros-toolchain-compatibility-measurement-v4"
MEASUREMENT_NAME = "compatibility-measurement.json"
NATIVE_HOSTS = {"linux-x86_64", "linux-aarch64", "macos-aarch64"}
MAX_METADATA = _ORIGIN.MAX_METADATA
MAX_PAYLOAD = _ORIGIN.MAX_PAYLOAD
MAX_FILES = _ORIGIN.MAX_FILES
BLOCK_SIZE = 1024 * 1024
SEGMENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
PROFILE = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
SDK_ID = re.compile(r"[a-z0-9._+-]{1,96}\Z")
SEMVER = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z.-]+)?\Z"
)
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
SDK_MAX_ENTRIES = 100_000


class StageError(Exception):
    """A bounded SDK owner-payload staging check failed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise StageError(message)


def exact_keys(value: object, keys: set[str], label: str) -> dict:
    require(isinstance(value, dict) and set(value) == keys, f"{label} has unexpected fields")
    return value


def canonical_json(value: object) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                          allow_nan=False).encode("utf-8") + b"\n"
    except (TypeError, ValueError, UnicodeError) as error:
        raise StageError("cannot encode canonical SDK owner-payload JSON") from error


def require_portable_inventory(files: dict) -> None:
    require(isinstance(files, dict) and 0 < len(files) <= MAX_FILES,
            "SDK owner-payload inventory is empty or oversized")
    seen = {}
    for name in files:
        require(_ORIGIN.portable_path(name), "SDK owner-payload path is unsafe")
        parts = name.split("/")
        for index, part in enumerate(parts):
            prefix = "/".join(parts[:index + 1])
            folded = prefix.casefold()
            kind = "file" if index == len(parts) - 1 else "directory"
            require(folded not in seen or seen[folded] == (prefix, kind),
                    "SDK owner-payload paths are case-aliased or conflict")
            seen[folded] = (prefix, kind)


def parse_json(raw: bytes, label: str) -> object:
    try:
        return _ORIGIN.parse_json(raw)
    except Exception as error:
        raise StageError(f"{label} is not bounded duplicate-free JSON") from error


def path_is_canonical(path: Path, *, must_exist: bool) -> bool:
    if not path.is_absolute() or ".." in path.parts:
        return False
    try:
        if not must_exist:
            if not portable_component(path.name):
                return False
            for ancestor in path.parent.parents:
                entry = ancestor.lstat()
                if stat.S_ISLNK(entry.st_mode) or not stat.S_ISDIR(entry.st_mode):
                    return False
            parent_metadata = path.parent.lstat()
            if stat.S_ISLNK(parent_metadata.st_mode) or not stat.S_ISDIR(parent_metadata.st_mode):
                return False
            try:
                path.lstat()
            except FileNotFoundError:
                return path.parent.resolve(strict=True) == path.parent
            return False
        for ancestor in (path, *path.parents):
            entry = ancestor.lstat()
            if stat.S_ISLNK(entry.st_mode):
                return False
            if ancestor != path and not stat.S_ISDIR(entry.st_mode):
                return False
        return path.resolve(strict=True) == path
    except (OSError, RuntimeError):
        return False


def portable_component(name: str) -> bool:
    return isinstance(name, str) and "/" not in name and _ORIGIN.portable_path(name)


def _fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _check_file_metadata(metadata: os.stat_result, limit: int, label: str) -> None:
    require(stat.S_ISREG(metadata.st_mode), f"{label} is not a regular file")
    require(metadata.st_nlink == 1, f"{label} is linked or has a hard-link alias")
    require(metadata.st_uid == os.geteuid(), f"{label} is not owned by the current user")
    require(0 <= metadata.st_size <= limit, f"{label} exceeds its byte limit")


def measure_file(path: Path, limit: int, label: str) -> dict:
    """Hash a no-follow, owned, singly linked input and recheck its name."""
    require(path_is_canonical(path, must_exist=True), f"{label} has a linked or noncanonical path")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise StageError(f"{label} cannot be opened without following links") from error
    try:
        before = os.fstat(descriptor)
        _check_file_metadata(before, limit, label)
        digest = hashlib.sha256()
        size = 0
        while True:
            block = os.read(descriptor, BLOCK_SIZE)
            if not block:
                break
            size += len(block)
            require(size <= limit, f"{label} grew beyond its byte limit")
            digest.update(block)
        after = os.fstat(descriptor)
        try:
            named = path.lstat()
        except OSError as error:
            raise StageError(f"{label} disappeared while being measured") from error
        require(
            _fingerprint(before) == _fingerprint(after) == _fingerprint(named)
            and size == before.st_size,
            f"{label} changed while being measured",
        )
        return {"sha256": digest.hexdigest(), "size": size}
    finally:
        os.close(descriptor)


def read_bounded(path: Path, limit: int, label: str) -> tuple[dict, bytes]:
    measurement = measure_file(path, limit, label)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise StageError(f"{label} cannot be reopened without following links") from error
    try:
        before = os.fstat(descriptor)
        _check_file_metadata(before, limit, label)
        chunks = []
        size = 0
        while True:
            block = os.read(descriptor, BLOCK_SIZE)
            if not block:
                break
            size += len(block)
            require(size <= limit, f"{label} grew beyond its byte limit")
            chunks.append(block)
        after = os.fstat(descriptor)
        named = path.lstat()
        raw = b"".join(chunks)
        require(
            _fingerprint(before) == _fingerprint(after) == _fingerprint(named)
            and size == before.st_size
            and hashlib.sha256(raw).hexdigest() == measurement["sha256"],
            f"{label} changed while being read",
        )
        return measurement, raw
    finally:
        os.close(descriptor)


def directory_fingerprint(path: Path, label: str) -> tuple[int, ...]:
    require(path_is_canonical(path, must_exist=True), f"{label} is linked or noncanonical")
    metadata = path.lstat()
    require(stat.S_ISDIR(metadata.st_mode), f"{label} is not a directory")
    require(metadata.st_uid == os.geteuid(), f"{label} is not owned by the current user")
    return _fingerprint(metadata)


def directory_entries(path: Path, label: str) -> dict[str, str]:
    directory_fingerprint(path, label)
    result = {}
    try:
        with os.scandir(path) as entries:
            for entry in entries:
                require(len(result) < MAX_FILES, f"{label} exceeds its file-entry bound")
                name = entry.name
                require(portable_component(name),
                        f"{label} contains a nonportable name")
                if entry.is_symlink():
                    raise StageError(f"{label} contains a symbolic link")
                if entry.is_dir(follow_symlinks=False):
                    result[name] = "directory"
                elif entry.is_file(follow_symlinks=False):
                    result[name] = "file"
                else:
                    raise StageError(f"{label} contains a special filesystem entry")
    except OSError as error:
        raise StageError(f"{label} cannot be enumerated") from error
    return result


def _selected_operation_entries(operation_dir: Path) -> dict[str, tuple[str, tuple[int, ...]]]:
    """Fingerprint only the source closure's direct operation-root entries.

    SDK build operations intentionally contain other outputs (and transient
    lock files). They are not part of this transport closure and are neither
    enumerated nor traversed here.
    """
    selected = {
        "generation.json": "file",
        "package": "directory",
        "local-evidence": "directory",
    }
    result = {}
    for name, expected_kind in selected.items():
        path = operation_dir / name
        try:
            metadata = path.lstat()
        except OSError as error:
            raise StageError(f"SDK operation is missing selected entry {name}") from error
        require(not stat.S_ISLNK(metadata.st_mode),
                f"SDK operation selected entry {name} is a symbolic link")
        if expected_kind == "file":
            _check_file_metadata(metadata, MAX_METADATA, f"SDK operation {name}")
        else:
            require(stat.S_ISDIR(metadata.st_mode),
                    f"SDK operation selected entry {name} is not a directory")
            require(metadata.st_uid == os.geteuid(),
                    f"SDK operation selected directory {name} is not owned by the current user")
        result[name] = (expected_kind, _fingerprint(metadata))
    return result


def _selected_local_evidence_entries(local_dir: Path) -> dict[str, tuple[str, tuple[int, ...]]]:
    """Fingerprint only inputs.json and evidence, ignoring export lock files."""
    selected = {"inputs.json": "file", "evidence": "directory"}
    result = {}
    for name, expected_kind in selected.items():
        path = local_dir / name
        try:
            metadata = path.lstat()
        except OSError as error:
            raise StageError(f"SDK local-evidence is missing selected entry {name}") from error
        require(not stat.S_ISLNK(metadata.st_mode),
                f"SDK local-evidence selected entry {name} is a symbolic link")
        if expected_kind == "file":
            _check_file_metadata(metadata, MAX_METADATA, "SDK compatibility inputs")
        else:
            require(stat.S_ISDIR(metadata.st_mode),
                    "SDK local-evidence evidence entry is not a directory")
            require(metadata.st_uid == os.geteuid(),
                    "SDK local-evidence evidence directory is not owned by the current user")
        result[name] = (expected_kind, _fingerprint(metadata))
    return result


def validate_selection(sdk_id: str, group: str, profile: str, host: str) -> dict:
    require(isinstance(sdk_id, str) and bool(SDK_ID.fullmatch(sdk_id))
            and sdk_id not in (".", ".."), "SDK ID is invalid")
    require(isinstance(group, str) and bool(SEGMENT.fullmatch(group)), "compiler group ID is invalid")
    require(isinstance(profile, str) and bool(PROFILE.fullmatch(profile))
            and profile not in (".", ".."), "target profile is invalid")
    require(isinstance(host, str) and host in NATIVE_HOSTS,
            "selected host is not one of the three native hosts")
    return {"sdk_id": sdk_id, "group_id": group, "target_profile": profile, "host": host}


def _validate_identity(identity: object, label: str) -> dict:
    identity = exact_keys(
        identity,
        {"sdk_id", "version", "target", "source", "source_date_epoch"},
        f"{label} identity",
    )
    require(isinstance(identity["sdk_id"], str) and bool(SDK_ID.fullmatch(identity["sdk_id"]))
            and identity["sdk_id"] not in (".", ".."),
            f"{label} SDK identity ID is invalid")
    require(isinstance(identity["version"], str) and bool(SEMVER.fullmatch(identity["version"])),
            f"{label} SDK identity version is invalid")
    target = exact_keys(identity["target"], {"target_triple", "abi"}, f"{label} SDK target")
    require(isinstance(target["target_triple"], str) and 0 < len(target["target_triple"]) <= 128,
            f"{label} SDK target triple is invalid")
    require(isinstance(target["abi"], dict) and 0 < len(target["abi"]) <= 32,
            f"{label} SDK ABI facts are invalid")
    for key, value in target["abi"].items():
        require(isinstance(key, str) and 0 < len(key) <= 64
                and (isinstance(value, str) or type(value) is bool
                     or (type(value) is int and 0 <= value <= 18446744073709551615)),
                f"{label} SDK ABI fact is invalid")
    source = exact_keys(
        identity["source"],
        {"commit", "git_tree", "content_sha256", "contract_sha256"},
        f"{label} SDK source identity",
    )
    for key in ("commit", "git_tree"):
        require(isinstance(source[key], str) and bool(re.fullmatch(r"[0-9a-f]{40}", source[key]))
                and set(source[key]) != {"0"}, f"{label} SDK source identity is invalid")
    for key in ("content_sha256", "contract_sha256"):
        require(isinstance(source[key], str) and bool(SHA256.fullmatch(source[key]))
                and set(source[key]) != {"0"}, f"{label} SDK source digest is invalid")
    require(type(identity["source_date_epoch"]) is int
            and 0 <= identity["source_date_epoch"] <= 0o77_777_777_777,
            f"{label} SDK source epoch is invalid")
    return identity


def _generation(record_raw: bytes, sdk_id: str) -> tuple[dict, str]:
    record = parse_json(record_raw, "SDK generation record")
    require(isinstance(record, dict), "SDK generation record is not an object")
    schema = record.get("schema")
    if schema == GNU_GENERATION_SCHEMA:
        family = "gnu"
        keys = {
            "schema", "assurance", "identity", "source_profile", "environment_sha256",
            "compatibility_receipt_sha256", "sdk_link_receipt_sha256", "sdk_inventory_sha256",
            "sdk_entries",
        }
    elif schema == LLVM_GENERATION_SCHEMA:
        family = "llvm"
        keys = {
            "schema", "assurance", "identity", "source_profile", "binding_sha256",
            "environment_sha256", "compatibility_receipt_sha256", "sdk_link_receipt_sha256",
            "sdk_inventory_sha256", "sdk_entries",
        }
    else:
        raise StageError("SDK generation record schema is not a supported GNU/LLVM SDK schema")
    exact_keys(record, keys, "SDK generation record")
    require(record["assurance"] == GENERATION_ASSURANCE,
            "SDK generation record assurance is not local generation binding")
    identity = _validate_identity(record["identity"], "generation record")
    require(identity["sdk_id"] == sdk_id, "SDK generation identity differs from explicit SDK selection")
    require(isinstance(record["source_profile"], str) and bool(PROFILE.fullmatch(record["source_profile"])),
            "SDK generation source profile is invalid")
    require(record["source_profile"] not in (".", ".."), "SDK generation source profile is invalid")
    digest_keys = ["environment_sha256", "compatibility_receipt_sha256",
                   "sdk_link_receipt_sha256", "sdk_inventory_sha256"]
    if family == "llvm":
        digest_keys.append("binding_sha256")
    for key in digest_keys:
        require(isinstance(record[key], str) and bool(SHA256.fullmatch(record[key])),
                f"SDK generation {key} is invalid")
    require(type(record["sdk_entries"]) is int and record["sdk_entries"] > 0,
            "SDK generation entry count is invalid")
    require(canonical_json(record) == record_raw, "SDK generation record is not canonical JSON")
    return record, family


def _package_manifest(raw: bytes, sdk_id: str) -> tuple[dict, str]:
    manifest = parse_json(raw, "SDK package manifest")
    manifest = exact_keys(manifest, {"schema", "identity", "tree_sha256", "files"},
                          "SDK package manifest")
    require(manifest["schema"] == SDK_MANIFEST_SCHEMA, "SDK package manifest schema differs")
    identity = _validate_identity(manifest["identity"], "package manifest")
    require(identity["sdk_id"] == sdk_id, "package manifest identity differs from explicit SDK selection")
    require(isinstance(manifest["tree_sha256"], str) and bool(SHA256.fullmatch(manifest["tree_sha256"])),
            "SDK package tree digest is invalid")
    require(type(manifest["files"]) is list and len(manifest["files"]) <= SDK_MAX_ENTRIES,
            "SDK package file inventory is not a bounded list")
    asset = f"aros-sdk-{sdk_id}-{identity['version']}.tar.xz"
    require(portable_component(asset), "SDK package archive name is unsafe")
    return manifest, asset


def _measurement(raw: bytes, evidence_names: set[str], family: str) -> dict:
    document = parse_json(raw, "compatibility measurement")
    document = exact_keys(document, {"schema", "files"}, "compatibility measurement")
    expected_schema = GNU_MEASUREMENT_SCHEMA if family == "gnu" else LLVM_MEASUREMENT_SCHEMA
    require(document["schema"] == expected_schema,
            "compatibility measurement schema differs from the selected SDK compiler family")
    files = document["files"]
    require(isinstance(files, dict) and bool(files), "compatibility measurement inventory is empty")
    require(set(files) == evidence_names - {MEASUREMENT_NAME},
            "compatibility measurement inventory differs from the flat evidence files")
    require_portable_inventory({name: {} for name in files})
    for name, measured in files.items():
        measured = exact_keys(measured, {"sha256", "size"}, "compatibility member measurement")
        require(isinstance(measured["sha256"], str) and bool(SHA256.fullmatch(measured["sha256"]))
                and type(measured["size"]) is int and 0 <= measured["size"] <= MAX_PAYLOAD,
                "compatibility member measurement is invalid")
    require(canonical_json(document) == raw, "compatibility measurement is not canonical JSON")
    return document


def _capture_operation(operation_dir: Path, sdk_id: str) -> dict:
    require(path_is_canonical(operation_dir, must_exist=True),
            "SDK operation directory is linked or noncanonical")
    directories = {".": directory_fingerprint(operation_dir, "SDK operation directory")}
    root_entries = _selected_operation_entries(operation_dir)

    package_dir = operation_dir / "package"
    directories["package"] = directory_fingerprint(package_dir, "SDK package directory")
    package_entries = directory_entries(package_dir, "SDK package directory")
    archives = [name for name, kind in package_entries.items()
                if kind == "file" and name.endswith(".tar.xz")]
    require(len(archives) == 1 and len(package_entries) == 3
            and all(kind == "file" for kind in package_entries.values()),
            "SDK package directory must contain one archive and its two sidecars")
    archive_name = archives[0]

    local_dir = operation_dir / "local-evidence"
    directories["local-evidence"] = directory_fingerprint(local_dir, "SDK local-evidence directory")
    local_entries = _selected_local_evidence_entries(local_dir)
    evidence_dir = local_dir / "evidence"
    directories["local-evidence/evidence"] = directory_fingerprint(evidence_dir, "SDK evidence directory")
    evidence_entries = directory_entries(evidence_dir, "SDK evidence directory")
    require(bool(evidence_entries) and all(kind == "file" for kind in evidence_entries.values())
            and MEASUREMENT_NAME in evidence_entries,
            "SDK compatibility evidence must be flat and include its measurement manifest")

    # Reject case, file/directory, and prefix aliases across the complete source closure.
    source_paths = {
        "generation.json": {},
        **{f"package/{name}": {} for name in package_entries},
        "local-evidence/inputs.json": {},
        **{f"local-evidence/evidence/{name}": {} for name in evidence_entries},
    }
    require_portable_inventory(source_paths)

    generation_measurement, generation_raw = read_bounded(
        operation_dir / "generation.json", MAX_METADATA, "SDK generation record")
    generation, family = _generation(generation_raw, sdk_id)

    manifest_names = [name for name in package_entries if name.endswith(".manifest.json")]
    checksum_names = [name for name in package_entries if name.endswith(".sha256")]
    expected_manifest_name = f"{archive_name}.manifest.json"
    expected_checksum_name = f"{archive_name}.sha256"
    require(archive_name.startswith(f"aros-sdk-{sdk_id}-") and archive_name.endswith(".tar.xz")
            and manifest_names == [expected_manifest_name]
            and checksum_names == [expected_checksum_name],
            "SDK package sidecars do not match its safe archive basename")
    manifest_measurement, manifest_raw = read_bounded(
        package_dir / expected_manifest_name, MAX_METADATA, "SDK package manifest")
    manifest, expected_asset = _package_manifest(manifest_raw, sdk_id)
    require(archive_name == expected_asset, "SDK archive name differs from package identity")
    require(generation["identity"] == manifest["identity"],
            "SDK generation identity differs from package manifest identity")

    archive_measurement = measure_file(package_dir / archive_name, MAX_PAYLOAD, "SDK package archive")
    checksum_measurement, checksum_raw = read_bounded(
        package_dir / expected_checksum_name, MAX_METADATA, "SDK archive checksum")
    expected_checksum = f"{archive_measurement['sha256']}  {archive_name}\n".encode()
    require(checksum_raw == expected_checksum, "SDK archive checksum sidecar differs")

    _, inputs_raw = read_bounded(local_dir / "inputs.json", MAX_METADATA, "SDK compatibility inputs")
    parse_json(inputs_raw, "SDK compatibility inputs")
    evidence_measurements = {}
    evidence_raw = {}
    evidence_names = set(evidence_entries)
    total_size = (generation_measurement["size"] + archive_measurement["size"]
                  + manifest_measurement["size"] + checksum_measurement["size"]
                  + len(inputs_raw))
    for name in sorted(evidence_names):
        path = evidence_dir / name
        if name == MEASUREMENT_NAME:
            measurement, raw = read_bounded(path, MAX_METADATA, "compatibility measurement")
        else:
            measurement = measure_file(path, MAX_PAYLOAD, f"compatibility evidence {name}")
            raw = None
        evidence_measurements[name] = measurement
        evidence_raw[name] = raw
        total_size += measurement["size"]
        require(total_size <= MAX_PAYLOAD, "SDK owner payload exceeds its aggregate byte limit")
    measurement_doc = _measurement(evidence_raw[MEASUREMENT_NAME], evidence_names, family)
    for name, expected in measurement_doc["files"].items():
        actual = evidence_measurements[name]
        require(expected["sha256"] == actual["sha256"] and expected["size"] == actual["size"],
                f"compatibility evidence measurement differs for {name}")

    files = {
        "generation.json": generation_measurement,
        f"package/{archive_name}": archive_measurement,
        f"package/{expected_manifest_name}": manifest_measurement,
        f"package/{expected_checksum_name}": checksum_measurement,
        "compatibility-inputs.json": {"sha256": hashlib.sha256(inputs_raw).hexdigest(),
                                      "size": len(inputs_raw)},
    }
    files.update({f"compatibility/{name}": measurement
                  for name, measurement in evidence_measurements.items()})
    require_portable_inventory(files)
    require(sum(item["size"] for item in files.values()) <= MAX_PAYLOAD,
            "staged SDK owner payload exceeds its aggregate byte limit")

    file_paths = {
        "generation.json": (operation_dir / "generation.json", MAX_METADATA),
        f"package/{archive_name}": (package_dir / archive_name, MAX_PAYLOAD),
        f"package/{expected_manifest_name}": (package_dir / expected_manifest_name, MAX_METADATA),
        f"package/{expected_checksum_name}": (package_dir / expected_checksum_name, MAX_METADATA),
        "compatibility-inputs.json": (local_dir / "inputs.json", MAX_METADATA),
    }
    file_paths.update({f"compatibility/{name}": (evidence_dir / name,
                                                   MAX_METADATA if name == MEASUREMENT_NAME else MAX_PAYLOAD)
                       for name in evidence_names})
    return {
        "files": dict(sorted(files.items())),
        "paths": file_paths,
        "directories": directories,
        "source_directories": {
            ".": root_entries,
            "package": package_entries,
            "local-evidence": local_entries,
            "local-evidence/evidence": evidence_entries,
        },
    }


def _write_all(descriptor: int, data: bytes) -> None:
    position = 0
    while position < len(data):
        written = os.write(descriptor, data[position:])
        require(written > 0, "cannot write staged metadata")
        position += written


def _create_owner_directory(path: Path) -> None:
    os.mkdir(path, 0o700)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                         | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fchmod(descriptor, 0o700)
        metadata = os.fstat(descriptor)
        require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == os.geteuid()
                and metadata.st_nlink >= 2 and stat.S_IMODE(metadata.st_mode) == 0o700,
                "staged directory is not owner-only")
    finally:
        os.close(descriptor)


def _copy_source(source: Path, destination: Path, expected: dict, limit: int) -> dict:
    require(path_is_canonical(source, must_exist=True), "SDK source changed to a linked or noncanonical path")
    source_fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    output_fd = None
    try:
        before = os.fstat(source_fd)
        _check_file_metadata(before, limit, "SDK source member")
        require(_fingerprint(before)[-3] == expected["size"], "SDK source member size changed before staging")
        output_fd = os.open(destination,
                            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        os.fchmod(output_fd, 0o600)
        output_before = os.fstat(output_fd)
        require(stat.S_ISREG(output_before.st_mode) and output_before.st_nlink == 1
                and output_before.st_uid == os.geteuid()
                and stat.S_IMODE(output_before.st_mode) == 0o600,
                "staged file is not an exclusive owner-only regular file")
        digest = hashlib.sha256()
        size = 0
        while True:
            block = os.read(source_fd, BLOCK_SIZE)
            if not block:
                break
            size += len(block)
            require(size <= limit, "SDK source member grew beyond its byte limit")
            digest.update(block)
            _write_all(output_fd, block)
        source_after = os.fstat(source_fd)
        source_named = source.lstat()
        output_after = os.fstat(output_fd)
        require(_fingerprint(before) == _fingerprint(source_after) == _fingerprint(source_named)
                and size == before.st_size == expected["size"]
                and digest.hexdigest() == expected["sha256"],
                "SDK source member changed while it was staged")
        require(stat.S_ISREG(output_after.st_mode) and output_after.st_nlink == 1
                and output_after.st_uid == os.geteuid() and output_after.st_size == size
                and stat.S_IMODE(output_after.st_mode) == 0o600,
                "staged file changed while it was written")
        return {"sha256": digest.hexdigest(), "size": size}
    except OSError as error:
        raise StageError("cannot copy bounded SDK owner-payload member") from error
    finally:
        if output_fd is not None:
            os.close(output_fd)
        os.close(source_fd)


def _write_exclusive(path: Path, raw: bytes) -> dict:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, raw)
        metadata = os.fstat(descriptor)
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
                and metadata.st_uid == os.geteuid() and metadata.st_size == len(raw)
                and stat.S_IMODE(metadata.st_mode) == 0o600,
                "staged metadata is not an owner-only exclusive regular file")
    finally:
        os.close(descriptor)
    return {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}


def _staged_inventory(output_dir: Path, expected_paths: set[str]) -> dict:
    require(path_is_canonical(output_dir, must_exist=True), "staged root is linked or noncanonical")
    for path in (output_dir, output_dir / "package", output_dir / "compatibility"):
        metadata = path.lstat()
        require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == os.geteuid()
                and stat.S_IMODE(metadata.st_mode) == 0o700,
                "staged directory is not owner-only")
    root_entries = directory_entries(output_dir, "staged owner-payload root")
    require(root_entries == {"generation.json": "file", "package": "directory",
                             "compatibility-inputs.json": "file", "compatibility": "directory",
                             "sdk-lane.json": "file"},
            "staged owner-payload root inventory differs")
    package_entries = directory_entries(output_dir / "package", "staged package directory")
    compatibility_entries = directory_entries(output_dir / "compatibility", "staged compatibility directory")
    expected_package = {PurePathName(path) for path in expected_paths if path.startswith("package/")}
    expected_compatibility = {PurePathName(path) for path in expected_paths if path.startswith("compatibility/")}
    require(package_entries == {name: "file" for name in expected_package}
            and compatibility_entries == {name: "file" for name in expected_compatibility},
            "staged owner-payload member inventory differs")
    result = {}
    for relative in sorted(expected_paths):
        result[relative] = measure_file(output_dir / relative, MAX_PAYLOAD,
                                        f"staged member {relative}")
    return result


def PurePathName(path: str) -> str:
    return path.rsplit("/", 1)[1]


def _stage(operation_dir: Path, output_dir: Path, *, sdk_id: str, group: str,
           profile: str, host: str) -> dict:
    """Stage the exact portable SDK-owner closure into a fresh private root.

    Directory and byte observations are repeated before success. The caller
    remains responsible for exclusive ownership of quiescent input roots; this
    function does not provide isolation from a hostile concurrent writer.
    """
    selection = validate_selection(sdk_id, group, profile, host)
    require(path_is_canonical(operation_dir, must_exist=True),
            "SDK operation directory is linked or noncanonical")
    require(path_is_canonical(output_dir, must_exist=False),
            "SDK owner-payload output root must be fresh with a canonical parent")
    require(not output_dir.is_relative_to(operation_dir)
            and not operation_dir.is_relative_to(output_dir),
            "SDK owner-payload output overlaps the source operation")

    preflight = _capture_operation(operation_dir, sdk_id)
    expected = preflight["files"]
    copied = {}

    # Every source/path/schema/inventory check above completes before output
    # creation. A later failure intentionally leaves this invocation's partial
    # output in place for inspection and does not delete caller data.
    _create_owner_directory(output_dir)
    _create_owner_directory(output_dir / "package")
    _create_owner_directory(output_dir / "compatibility")
    for relative, (source, limit) in sorted(preflight["paths"].items()):
        copied[relative] = _copy_source(source, output_dir / relative, expected[relative], limit)
    require(copied == expected, "staged SDK owner-payload measurements differ from preflight")

    lane = {"schema": SCHEMA, "assurance": ASSURANCE, **selection,
            "files": dict(sorted(copied.items()))}
    lane_raw = canonical_json(lane)
    _write_exclusive(output_dir / "sdk-lane.json", lane_raw)

    # Reobserve every source member and directory listing after the copy.
    rechecked = _capture_operation(operation_dir, sdk_id)
    require(rechecked["files"] == expected
            and rechecked["source_directories"] == preflight["source_directories"]
            and rechecked["directories"] == preflight["directories"],
            "SDK source closure changed during staging")

    staged = _staged_inventory(output_dir, set(expected))
    require(staged == expected, "staged SDK owner-payload bytes differ from source observations")
    lane_measurement, lane_again = read_bounded(output_dir / "sdk-lane.json", MAX_METADATA,
                                                "staged SDK lane manifest")
    lane_metadata = (output_dir / "sdk-lane.json").lstat()
    require(stat.S_IMODE(lane_metadata.st_mode) == 0o600,
            "staged SDK lane manifest is not owner-only")
    require(lane_again == lane_raw and parse_json(lane_again, "staged SDK lane manifest") == lane,
            "staged SDK lane manifest changed")
    require(directory_entries(output_dir, "staged owner-payload root") ==
            {"generation.json": "file", "package": "directory",
             "compatibility-inputs.json": "file", "compatibility": "directory",
             "sdk-lane.json": "file"},
            "staged owner-payload root changed before completion")
    return {"schema": SCHEMA, "assurance": ASSURANCE, "selection": selection,
            "files": staged, "lane": lane_measurement}


def stage(operation_dir: Path, output_dir: Path, *, sdk_id: str, group: str,
          profile: str, host: str) -> dict:
    """Public API for one selected SDK owner payload."""
    try:
        return _stage(operation_dir, output_dir, sdk_id=sdk_id, group=group,
                      profile=profile, host=host)
    except StageError:
        raise
    except (_ORIGIN.OriginError, OSError) as error:
        raise StageError("SDK owner-payload staging I/O or inventory check failed") from error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--operation-dir", required=True, type=Path)
    parser.add_argument("--sdk-id", required=True)
    parser.add_argument("--group", required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = stage(args.operation_dir, args.output_dir, sdk_id=args.sdk_id,
                       group=args.group, profile=args.profile, host=args.host)
    except (StageError, _ORIGIN.OriginError) as error:
        print(f"SDK owner-payload staging rejected: {error}", file=sys.stderr)
        return 2
    print(f"Staged {len(result['files'])} SDK owner-payload members; staging-byte-consistency-only.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
