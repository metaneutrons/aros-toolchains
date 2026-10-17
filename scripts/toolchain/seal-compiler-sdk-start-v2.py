#!/usr/bin/env python3
"""Copy selected signed-start transport bytes into a fresh private directory.

This inactive local helper preserves the fixed record basename used by a
future attestation subject. It checks an independently supplied record digest
and safely retains bounded record and bundle bytes. It does not verify or sign
the bundle, authenticate the start or provider, or grant release authority.
Future use still requires a genuine signer, an authenticated consumer,
cross-run byte pins and the separately authorized upload path.

The caller must use an owned direct output parent with no group or other
permissions and keep that staging directory quiescent during this operation.
The no-follow stat immediately after mkdir is a point-in-time observation;
comparing it with the opened directory does not atomically prove which inode
mkdir created against a concurrent writer. This helper makes no defense claim
against concurrent same-user or privileged writers and provides no ACL or
sandbox guarantee.

If a failure occurs after output-directory creation, partial private output may
remain. A nonzero result makes that directory unusable: do not retry against
it, and do not automatically clean it up. Diagnose the failure before an
operator removes the partial directory.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import stat
import sys


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load local helper {name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


RECORD = _load_module("start_record_transport_record_helpers",
                      HERE / "record-complete-qualification-v2.py")
ADMISSION = _load_module("start_record_transport_admission_helpers",
                         HERE / "release-admission-v2.py")

RECORD_BASENAME = "compiler-sdk-release-start-v2.json"
BUNDLE_BASENAME = "compiler-sdk-release-start-v2.sigstore.json"
MAX_RECORD = 128 * 1024
MAX_BUNDLE = 8 * 1024 * 1024
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class SealError(ValueError):
    """Selected start transport bytes failed the local retention boundary."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise SealError(message)


def _absolute_path(value: str | Path, label: str) -> Path:
    raw = os.fspath(value)
    _require(isinstance(raw, str) and "\0" not in raw
             and 0 < len(os.fsencode(raw)) <= 4096,
             f"{label} path is not bounded")
    path = Path(raw)
    _require(path.is_absolute() and ".." not in path.parts
             and os.path.normpath(raw) == raw,
             f"{label} path must be absolute and normalized")
    return path


def _object_identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid


def _same_directory(path: Path, label: str, expected_identity: tuple[int, int, int, int]) -> os.stat_result:
    metadata = RECORD._directory(path, label, owned=True)
    _require(_object_identity(metadata) == expected_identity,
             f"{label} identity changed")
    return metadata


def _capture(path: Path, label: str, limit: int) -> dict:
    parent = path.parent
    parent_metadata = RECORD._directory(parent, f"{label} parent", owned=True)
    measured, raw, fingerprint = RECORD._read_owned(path, limit, label, retain=True)
    _require(raw is not None and 0 < len(raw) <= limit and measured["size"] == len(raw),
             f"{label} is empty or outside its byte limit")
    return {
        "path": path,
        "parent": parent,
        "parent_identity": _object_identity(parent_metadata),
        "label": label,
        "limit": limit,
        "measurement": measured,
        "raw": raw,
        "fingerprint": fingerprint,
    }


def _recheck_source(source: dict) -> None:
    _same_directory(source["parent"], f'{source["label"]} parent', source["parent_identity"])
    RECORD._stat_expected(source["path"], source["limit"], source["label"],
                          source["measurement"], source["fingerprint"])


def _write_all(descriptor: int, raw: bytes, label: str) -> None:
    remaining = memoryview(raw)
    while remaining:
        try:
            written = os.write(descriptor, remaining)
        except InterruptedError:
            continue
        except OSError as error:
            raise SealError(f"{label} could not be written") from error
        _require(written > 0, f"{label} could not be written completely")
        remaining = remaining[written:]


def _write_retained_file(directory_fd: int, name: str, raw: bytes, label: str) -> tuple[int, ...]:
    flags = RECORD.CREATE_FLAGS
    try:
        descriptor = os.open(name, flags, 0o600, dir_fd=directory_fd)
    except FileExistsError as error:
        raise SealError(f"{label} output is already occupied") from error
    except OSError as error:
        raise SealError(f"{label} output could not be created exclusively") from error
    try:
        os.fchmod(descriptor, 0o600)
        before = os.fstat(descriptor)
        _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                 and before.st_uid == os.geteuid(),
                 f"{label} output is not an owned, singly linked regular file")
        _write_all(descriptor, raw, label)
        os.fsync(descriptor)
        after = os.fstat(descriptor)
        _require(stat.S_ISREG(after.st_mode) and after.st_nlink == 1
                 and after.st_uid == os.geteuid() and after.st_size == len(raw)
                 and stat.S_IMODE(after.st_mode) == 0o600
                 and (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino),
                 f"{label} output changed while being written")
        return RECORD._fingerprint(after)
    except OSError as error:
        raise SealError(f"{label} output could not be retained") from error
    finally:
        os.close(descriptor)


def _check_output_directory(path: Path, parent_fd: int, name: str,
                            directory_fd: int,
                            identity: tuple[int, int, int, int]) -> None:
    held = os.fstat(directory_fd)
    _require(stat.S_ISDIR(held.st_mode) and held.st_uid == os.geteuid()
             and stat.S_IMODE(held.st_mode) == 0o700
             and _object_identity(held) == identity,
             "private output directory identity or mode changed")
    try:
        linked = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as error:
        raise SealError("private output directory path changed") from error
    _require(stat.S_ISDIR(linked.st_mode) and _object_identity(linked) == identity,
             "private output directory path changed")
    current = RECORD._directory(path, "private output directory", owned=True)
    _require(_object_identity(current) == identity,
             "private output directory path changed")


def _readback(path: Path, label: str, raw: bytes, limit: int,
              written_fingerprint: tuple[int, ...]) -> None:
    measured, retained, fingerprint = RECORD._read_owned(path, limit, label, retain=True)
    _require(retained == raw and measured == {
        "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw),
    } and fingerprint == written_fingerprint,
        f"{label} output readback differs from the captured bytes")
    try:
        metadata = path.lstat()
    except OSError as error:
        raise SealError(f"{label} output cannot be inspected") from error
    _require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
             and metadata.st_uid == os.geteuid()
             and RECORD._fingerprint(metadata) == written_fingerprint
             and stat.S_IMODE(metadata.st_mode) == 0o600,
             f"{label} output identity or permissions changed after readback")


def seal_start_transport(record_path: str | Path, bundle_path: str | Path,
                         expected_record_sha256: str,
                         output_directory: str | Path) -> dict[str, str]:
    """Retain exact bounded input bytes without making an authenticity claim."""
    record_source_path = _absolute_path(record_path, "signed start record")
    bundle_source_path = _absolute_path(bundle_path, "start signature bundle")
    output_path = _absolute_path(output_directory, "private output directory")
    _require(record_source_path.name == RECORD_BASENAME,
             f"signed start record basename must be {RECORD_BASENAME}")
    _require(record_source_path != bundle_source_path,
             "start record and signature bundle must be separate files")
    _require(type(expected_record_sha256) is str and HEX64.fullmatch(expected_record_sha256) is not None,
             "expected record digest must be lowercase SHA-256")

    # Freeze and validate every input before the first output-side operation.
    record = _capture(record_source_path, "signed start record", MAX_RECORD)
    bundle = _capture(bundle_source_path, "start signature bundle", MAX_BUNDLE)
    _require(record["measurement"]["sha256"] == expected_record_sha256,
             "signed start record differs from the independently selected digest")
    _recheck_source(record)
    _recheck_source(bundle)

    RECORD._check_components(output_path, "private output directory", must_exist=False)
    parent = output_path.parent
    parent_metadata = RECORD._directory(parent, "private output parent", owned=True)
    _require(stat.S_IMODE(parent_metadata.st_mode) & 0o077 == 0,
             "private output parent grants group or other access")
    parent_identity = _object_identity(parent_metadata)
    try:
        parent_fd, name = ADMISSION._open_parent_directory(output_path)
    except ADMISSION.AdmissionError as error:
        raise SealError("private output parent could not be opened without following links") from error
    directory_fd = -1
    try:
        parent_held = os.fstat(parent_fd)
        _require(stat.S_ISDIR(parent_held.st_mode) and parent_held.st_uid == os.geteuid()
                 and _object_identity(parent_held) == parent_identity,
                 "private output parent identity changed")
        _same_directory(parent, "private output parent", parent_identity)
        try:
            os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        except OSError as error:
            raise SealError("private output directory cannot be inspected") from error
        else:
            raise SealError("private output directory is already occupied")

        try:
            os.mkdir(name, mode=0o700, dir_fd=parent_fd)
        except FileExistsError as error:
            raise SealError("private output directory is already occupied") from error
        except OSError as error:
            raise SealError("private output directory could not be created exclusively") from error
        try:
            created_metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            _require(stat.S_ISDIR(created_metadata.st_mode)
                     and created_metadata.st_uid == os.geteuid()
                     and stat.S_IMODE(created_metadata.st_mode) & ~0o700 == 0,
                     "new private output directory has an unexpected identity or mode")
            directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) \
                | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
            directory_fd = os.open(name, directory_flags, dir_fd=parent_fd)
            opened_metadata = os.fstat(directory_fd)
            _require(stat.S_ISDIR(opened_metadata.st_mode)
                     and _object_identity(opened_metadata) == _object_identity(created_metadata),
                     "private output directory changed before it was opened")
            # chmod is safe only after the descriptor has been tied to the
            # no-follow identity observed immediately after exclusive mkdir.
            os.fchmod(directory_fd, 0o700)
            directory_metadata = os.fstat(directory_fd)
        except OSError as error:
            raise SealError("private output directory could not be opened safely") from error
        _require(stat.S_ISDIR(directory_metadata.st_mode)
                 and directory_metadata.st_uid == os.geteuid()
                 and stat.S_IMODE(directory_metadata.st_mode) == 0o700,
                 "private output directory is not owned and mode 0700")
        directory_identity = _object_identity(directory_metadata)
        _check_output_directory(output_path, parent_fd, name, directory_fd, directory_identity)
        try:
            os.fsync(parent_fd)
        except OSError as error:
            raise SealError("private output directory creation could not be synced") from error

        record_fingerprint = _write_retained_file(
            directory_fd, RECORD_BASENAME, record["raw"], "retained signed start record")
        bundle_fingerprint = _write_retained_file(
            directory_fd, BUNDLE_BASENAME, bundle["raw"], "retained start signature bundle")
        try:
            os.fsync(directory_fd)
        except OSError as error:
            raise SealError("private output directory contents could not be synced") from error

        _check_output_directory(output_path, parent_fd, name, directory_fd, directory_identity)
        _require(set(os.listdir(directory_fd)) == {RECORD_BASENAME, BUNDLE_BASENAME},
                 "private output directory contains unexpected entries")
        _readback(output_path / RECORD_BASENAME, "retained signed start record",
                  record["raw"], MAX_RECORD, record_fingerprint)
        _readback(output_path / BUNDLE_BASENAME, "retained start signature bundle",
                  bundle["raw"], MAX_BUNDLE, bundle_fingerprint)
        _check_output_directory(output_path, parent_fd, name, directory_fd, directory_identity)
        _require(set(os.listdir(directory_fd)) == {RECORD_BASENAME, BUNDLE_BASENAME},
                 "private output directory changed during readback")
        _recheck_source(record)
        _recheck_source(bundle)
        return {
            "record_path": str(output_path / RECORD_BASENAME),
            "bundle_path": str(output_path / BUNDLE_BASENAME),
            "record_sha256": record["measurement"]["sha256"],
            "bundle_sha256": bundle["measurement"]["sha256"],
        }
    finally:
        if directory_fd >= 0:
            os.close(directory_fd)
        os.close(parent_fd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--record", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--expected-record-sha256", required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = seal_start_transport(args.record, args.bundle,
                                      args.expected_record_sha256, args.output_directory)
    except (SealError, RECORD.AdapterError, ADMISSION.AdmissionError, OSError) as error:
        print("start transport sealing failed; any created output is unusable and must not be retried",
              file=sys.stderr)
        return 1
    print("copied exact record and bundle bytes; no bundle verification or start authentication performed")
    print(result["record_path"])
    print(result["bundle_path"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
