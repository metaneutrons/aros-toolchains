#!/usr/bin/env python3
"""Stage the exact native-owner package/evidence closure for byte transport.

The result establishes staging byte consistency only. It does not authenticate
the native job, build, package, provider artifact, or release qualification.
Persistent advisory lock files at the source root are checked but never copied
or removed.
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

sys.dont_write_bytecode = True


def _load_sibling(filename: str, module_name: str):
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:  # pragma: no cover - installation failure
        raise RuntimeError(f"required toolchain helper is unavailable: {filename}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_STAGE = _load_sibling("stage-sdk-owner-payload-v2.py", "stage_sdk_owner_for_native_payload")
_NATIVE = _load_sibling("native-lane-transport.py", "native_lane_transport_for_owner_payload")
_ORIGIN = _NATIVE.origin

SCHEMA = "aros-native-owner-payload-v2"
ASSURANCE = "staging-byte-consistency-only"
LOCK_NAME = re.compile(r"\.aros-lock-[0-9a-f]{16}-0000000000000000\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
MAX_METADATA = _ORIGIN.MAX_METADATA
MAX_PAYLOAD = _ORIGIN.MAX_PAYLOAD


class StageError(ValueError):
    """The native-owner staging boundary rejected the selected source."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise StageError(message)


def _fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
    return _STAGE._fingerprint(metadata)


def _directory_identity(directory: Path, label: str) -> tuple[int, ...]:
    try:
        return _STAGE.directory_fingerprint(directory, label)
    except _STAGE.StageError as error:
        raise StageError(str(error)) from error


def _root_entries(source: Path) -> tuple[dict[str, str], dict[str, dict]]:
    """Enumerate the two payload directories and only recognized root lock files."""
    entries: dict[str, str] = {}
    locks: dict[str, dict] = {}
    try:
        with os.scandir(source) as children:
            for child in children:
                _require(len(entries) < _ORIGIN.MAX_FILES,
                         "native source root exceeds its entry bound")
                name = child.name
                _require(name not in entries, "native source root repeats an entry")
                if name in ("evidence", "package"):
                    _require(not child.is_symlink() and child.is_dir(follow_symlinks=False),
                             "native source root payload entries must be ordinary directories")
                    entries[name] = "directory"
                    continue
                _require(LOCK_NAME.fullmatch(name) is not None,
                         "native source root contains an unexpected entry")
                _require(not child.is_symlink() and child.is_file(follow_symlinks=False),
                         "native source advisory lock must be an ordinary file")
                path = source / name
                named_before = path.lstat()
                _require(stat.S_ISREG(named_before.st_mode) and named_before.st_size == 0,
                         "native source advisory lock must be a zero-byte regular file")
                measured = _STAGE.measure_file(path, 0, "native source advisory lock")
                named_after = path.lstat()
                _require(_fingerprint(named_before) == _fingerprint(named_after)
                         and measured == {"sha256": hashlib.sha256(b"").hexdigest(), "size": 0},
                         "native source advisory lock changed while it was checked")
                entries[name] = "advisory-lock"
                locks[name] = {"fingerprint": _fingerprint(named_after), **measured}
    except _STAGE.StageError as error:
        raise StageError(str(error)) from error
    except OSError as error:
        raise StageError("native source root cannot be enumerated") from error
    _require(entries.get("evidence") == "directory" and entries.get("package") == "directory",
             "native source root must contain evidence and package directories")
    return dict(sorted(entries.items())), dict(sorted(locks.items()))


def _package_result(source: Path, archive_name: str, archive: dict,
                    measurement_raw: bytes) -> tuple[bytes, dict]:
    path = source / "evidence/package-result.json"
    try:
        measured, raw = _STAGE.read_bounded(path, MAX_METADATA, "native package result")
        result = _STAGE.parse_json(raw, "native package result")
    except _STAGE.StageError as error:
        raise StageError(str(error)) from error
    _require(type(result) is dict and result.get("schema") == "aros-toolchain-producer-stage-v1"
             and result.get("operation") == "package",
             "native package result schema or operation differs")
    package_dir = source / "package"
    archive_path = package_dir / archive_name
    expected_paths = {
        "package_dir": package_dir,
        "archive": archive_path,
        "manifest": Path(str(archive_path) + ".manifest.json"),
        "checksum": Path(str(archive_path) + ".sha256"),
        "sbom": Path(str(archive_path) + ".spdx.json"),
    }
    for key, expected in expected_paths.items():
        value = result.get(key)
        _require(isinstance(value, str) and Path(value).is_absolute()
                 and value == str(expected),
                 f"native package result {key} path differs from the original source path")
    _require(result.get("sha256") == archive["sha256"]
             and type(result.get("size")) is int and result["size"] == archive["size"],
             "native package result archive measurement differs from the source bytes")

    finished = result.get("finished_candidate")
    _require(type(finished) is dict, "native package result omits its finished-candidate measurement")
    portable = finished.get("portable_measurement")
    portable_sha = finished.get("portable_measurement_sha256")
    _require(isinstance(portable, str) and isinstance(portable_sha, str)
             and SHA256.fullmatch(portable_sha) is not None,
             "native package result portable measurement is invalid")
    try:
        portable_raw = portable.encode("utf-8")
    except UnicodeError as error:
        raise StageError("native package result portable measurement is not UTF-8") from error
    _require(0 < len(portable_raw) <= MAX_METADATA and portable_raw == measurement_raw
             and hashlib.sha256(portable_raw).hexdigest() == portable_sha,
             "native package result portable measurement differs from evidence bytes")
    return raw, measured


def _capture_source(source: Path) -> dict:
    _require(_STAGE.path_is_canonical(source, must_exist=True),
             "native source directory is linked or noncanonical")
    root_before = _directory_identity(source, "native source root")
    root_entries, locks = _root_entries(source)
    evidence_dir = source / "evidence"
    package_dir = source / "package"
    evidence_identity = _directory_identity(evidence_dir, "native evidence directory")
    package_identity = _directory_identity(package_dir, "native package directory")
    try:
        evidence_entries = _STAGE.directory_entries(evidence_dir, "native evidence directory")
        package_entries = _STAGE.directory_entries(package_dir, "native package directory")
    except _STAGE.StageError as error:
        raise StageError(str(error)) from error

    expected_evidence = {name.split("/", 1)[1] for name in _NATIVE.EVIDENCE_NAMES}
    _require(set(evidence_entries) == expected_evidence
             and all(kind == "file" for kind in evidence_entries.values()),
             "native evidence directory is not the exact six-file closure")
    archives = sorted(name for name, kind in package_entries.items()
                      if kind == "file" and name.endswith(".tar.xz"))
    _require(len(archives) == 1, "native package directory must contain exactly one archive")
    archive_name = archives[0]
    _require(_ORIGIN.portable_path(archive_name) and "/" not in archive_name,
             "native package archive basename is not portable")
    expected_package = {
        archive_name,
        archive_name + ".manifest.json",
        archive_name + ".sha256",
        archive_name + ".spdx.json",
    }
    _require(set(package_entries) == expected_package
             and all(kind == "file" for kind in package_entries.values()),
             "native package directory is not one archive and its exact sidecars")

    paths: dict[str, tuple[Path, int]] = {}
    for name in sorted(expected_evidence):
        relative = f"evidence/{name}"
        limit = MAX_METADATA
        paths[relative] = (evidence_dir / name, limit)
    for name in sorted(expected_package):
        paths[f"package/{name}"] = (
            package_dir / name, MAX_PAYLOAD if name == archive_name else MAX_METADATA
        )

    files: dict[str, dict] = {}
    retained_raw: dict[str, bytes] = {}
    for relative, (path, limit) in sorted(paths.items()):
        if relative == "evidence/package-result.json":
            measurement, raw = _STAGE.read_bounded(path, limit, "native package result")
            files[relative] = measurement
            retained_raw[relative] = raw
        elif relative == "evidence/measurement.json":
            measurement, raw = _STAGE.read_bounded(path, limit, "native portable measurement")
            files[relative] = measurement
            retained_raw[relative] = raw
        else:
            try:
                files[relative] = _STAGE.measure_file(path, limit, f"native member {relative}")
            except _STAGE.StageError as error:
                raise StageError(str(error)) from error
    _require(sum(item["size"] for item in files.values()) <= MAX_PAYLOAD,
             "native owner payload exceeds the aggregate payload limit")
    try:
        _NATIVE._closed_inventory(files)
    except _ORIGIN.OriginError as error:
        raise StageError("native owner payload is not the exact ten-file inventory") from error

    archive_measurement = files[f"package/{archive_name}"]
    measurement_raw = retained_raw["evidence/measurement.json"]
    package_raw, package_result_measurement = _package_result(
        source, archive_name, archive_measurement, measurement_raw
    )
    _require(package_result_measurement == files["evidence/package-result.json"]
             and package_raw == retained_raw["evidence/package-result.json"],
             "native package result changed between bounded reads")
    root_after = _directory_identity(source, "native source root")
    _require(root_before == root_after, "native source root changed while it was measured")
    root_entries_after, locks_after = _root_entries(source)
    _require(root_entries == root_entries_after and locks == locks_after,
             "native source root or advisory locks changed while measured")
    _require(evidence_identity == _directory_identity(evidence_dir, "native evidence directory")
             and package_identity == _directory_identity(package_dir, "native package directory"),
             "native source subdirectory changed while measured")
    try:
        _require(evidence_entries == _STAGE.directory_entries(evidence_dir, "native evidence directory")
                 and package_entries == _STAGE.directory_entries(package_dir, "native package directory"),
                 "native source file inventory changed while measured")
    except _STAGE.StageError as error:
        raise StageError(str(error)) from error
    return {
        "files": dict(sorted(files.items())),
        "paths": paths,
        "archive_name": archive_name,
        "directories": {
            ".": root_before, "evidence": evidence_identity, "package": package_identity,
        },
        "entries": {
            ".": root_entries, "evidence": dict(sorted(evidence_entries.items())),
            "package": dict(sorted(package_entries.items())),
        },
        "locks": locks,
    }


def _output_preflight(source: Path, output: Path) -> os.stat_result:
    _require(source != output and source not in output.parents and output not in source.parents,
             "native source and output directories must not overlap")
    _require(_STAGE.path_is_canonical(output, must_exist=False),
             "native owner-payload output must be fresh with a canonical parent")
    parent = output.parent.lstat()
    _require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.geteuid(),
             "native owner-payload output parent is not an owned directory")
    return parent


def _capture_output(output: Path, expected_files: dict[str, dict]) -> dict:
    _require(_STAGE.path_is_canonical(output, must_exist=True),
             "staged native owner-payload root is linked or noncanonical")
    root_stat = output.lstat()
    _require(stat.S_ISDIR(root_stat.st_mode) and root_stat.st_uid == os.geteuid()
             and stat.S_IMODE(root_stat.st_mode) == 0o700,
             "staged native owner-payload root is not private and owned")
    try:
        root_entries = _STAGE.directory_entries(output, "staged native payload root")
        expected_root = {"evidence": "directory", "package": "directory"}
        _require(root_entries == expected_root, "staged native payload root has unexpected entries")
        directories = {".": _fingerprint(root_stat)}
        entries = {".": root_entries}
        for folder in ("evidence", "package"):
            directory = output / folder
            directory_stat = directory.lstat()
            _require(stat.S_ISDIR(directory_stat.st_mode) and directory_stat.st_uid == os.geteuid()
                     and stat.S_IMODE(directory_stat.st_mode) == 0o700,
                     "staged native payload subdirectory is not private and owned")
            directories[folder] = _fingerprint(directory_stat)
            actual = _STAGE.directory_entries(directory, f"staged native {folder} directory")
            expected_names = {name.split("/", 1)[1] for name in expected_files
                              if name.startswith(folder + "/")}
            _require(actual == {name: "file" for name in expected_names},
                     "staged native payload subdirectory members differ")
            entries[folder] = actual
        archive_paths = [name for name in expected_files
                         if name.startswith("package/") and name.endswith(".tar.xz")]
        _require(len(archive_paths) == 1, "staged native payload has no unique package archive")
        archive_path = archive_paths[0]
        measurements: dict[str, dict] = {}
        for relative, expected in sorted(expected_files.items()):
            path = output / relative
            metadata = path.lstat()
            _require(stat.S_IMODE(metadata.st_mode) == 0o600,
                     "staged native payload file is not owner-only")
            limit = MAX_PAYLOAD if relative == archive_path else MAX_METADATA
            measurement = _STAGE.measure_file(path, limit,
                                              f"staged native payload member {relative}")
            _require(measurement == expected,
                     "staged native payload bytes differ from source observations")
            measurements[relative] = measurement
        root_after = output.lstat()
        _require(_fingerprint(root_stat) == _fingerprint(root_after)
                 and _STAGE.directory_entries(output, "staged native payload root") == root_entries,
                 "staged native payload root changed during readback")
        for folder in ("evidence", "package"):
            directory = output / folder
            current = directory.lstat()
            _require(_fingerprint(current) == directories[folder]
                     and _STAGE.directory_entries(
                         directory, f"staged native {folder} directory"
                     ) == entries[folder],
                     "staged native payload directory changed during readback")
        return {"files": measurements, "directories": directories, "entries": entries}
    except _STAGE.StageError as error:
        raise StageError(str(error)) from error


def _stage(source: Path, output: Path) -> dict:
    _require(source.is_absolute() and ".." not in source.parts,
             "native source directory must be absolute and normalized")
    _require(output.is_absolute() and ".." not in output.parts,
             "native output directory must be absolute and normalized")
    parent_before = _output_preflight(source, output)
    selected = _capture_source(source)

    # Every source member, sidecar, advisory lock and directory check completes
    # before creating the fresh destination. A later failure leaves its partial
    # output in place; caller-owned paths are never removed as cleanup.
    _STAGE._create_owner_directory(output)
    _STAGE._create_owner_directory(output / "evidence")
    _STAGE._create_owner_directory(output / "package")
    copied: dict[str, dict] = {}
    try:
        for relative, (source_path, limit) in sorted(selected["paths"].items()):
            copied[relative] = _STAGE._copy_source(
                source_path, output / relative, selected["files"][relative], limit
            )
    except _STAGE.StageError as error:
        raise StageError("native owner payload changed or failed during byte copy") from error
    _require(copied == selected["files"], "native owner-payload copy measurements differ")

    source_after = _capture_source(source)
    _require(source_after["files"] == selected["files"]
             and source_after["directories"] == selected["directories"]
             and source_after["entries"] == selected["entries"]
             and source_after["locks"] == selected["locks"],
             "native source bytes, directories or advisory locks changed during staging")
    output_after = _capture_output(output, selected["files"])
    _require(output_after["files"] == selected["files"],
             "staged native payload readback differs from source observations")
    parent_after = output.parent.lstat()
    _require((parent_before.st_dev, parent_before.st_ino, parent_before.st_mode, parent_before.st_uid)
             == (parent_after.st_dev, parent_after.st_ino, parent_after.st_mode, parent_after.st_uid),
             "native owner-payload output parent changed during staging")
    return {
        "schema": SCHEMA,
        "assurance": ASSURANCE,
        "files": output_after["files"],
    }


def stage(source: Path, output: Path) -> dict:
    """Copy and read back the exact ten selected owner-payload files."""
    try:
        return _stage(source, output)
    except StageError:
        raise
    except (_STAGE.StageError, _ORIGIN.OriginError, OSError, ValueError) as error:
        raise StageError("native owner-payload staging I/O or inventory check failed") from error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = stage(args.source_dir, args.output_dir)
    except StageError:
        print("native owner-payload staging rejected; no authority was created", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
