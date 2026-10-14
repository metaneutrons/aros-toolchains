#!/usr/bin/env python3
"""Collect same-run native Cargo-cache archive digests from identity artifacts.

This helper only binds the per-host transport digests to the selected matrix,
source/tool commits and workflow run. It does not authenticate the Cargo cache
contents or establish provenance for them. Native consumers must still perform
their strict ``cache cargo verify`` checks before trusting a cache tree.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any


sys.dont_write_bytecode = True

SCHEMA = "aros-native-cargo-cache-v1"
RUNNERS = {
    "linux-aarch64": "ubuntu-24.04-arm",
    "linux-x86_64": "ubuntu-24.04",
    "macos-aarch64": "macos-15",
}
MAX_MATRIX_BYTES = 64 * 1024
MAX_IDENTITY_BYTES = 16 * 1024
MAX_OUTPUT_BYTES = 64 * 1024
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
DECIMAL = re.compile(r"[1-9][0-9]*\Z")
DIRECTORY_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) \
    | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
READ_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) \
    | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)


class CatalogError(ValueError):
    """The identity-artifact catalog is not a closed valid selection."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CatalogError(message)


def _fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_nlink,
        metadata.st_uid, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns,
    )


def _normalized_path(raw: object, label: str) -> Path:
    _require(isinstance(raw, str) and 0 < len(raw.encode("utf-8")) <= 4096
             and "\n" not in raw and "\r" not in raw and "\0" not in raw,
             f"{label} path is not bounded")
    _require(os.path.isabs(raw) and os.path.normpath(raw) == raw,
             f"{label} path must be absolute and normalized")
    path = Path(raw)
    _require(".." not in path.parts, f"{label} path may not contain parent traversal")
    return path


def _check_components(path: Path, label: str) -> None:
    _require(path.is_absolute() and ".." not in path.parts,
             f"{label} path must be absolute and normalized")
    try:
        _require(path.resolve(strict=True) == path,
                 f"{label} path has a symlink or noncanonical component")
        for component in (path, *path.parents):
            metadata = component.lstat()
            _require(not stat.S_ISLNK(metadata.st_mode),
                     f"{label} path has a symlink component")
    except OSError as error:
        raise CatalogError(f"{label} path is unavailable") from error


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CatalogError("identity metadata contains duplicate JSON keys")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise CatalogError("identity metadata contains a non-JSON numeric value")


def _json_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise CatalogError(f"{label} is not valid UTF-8 JSON") from error
    _require(type(value) is dict, f"{label} must be a JSON object")
    return value


def _exact_keys(value: object, keys: set[str], label: str) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == keys,
             f"{label} has an unsupported closed shape")
    return value


def _canonical_decimal(value: object, label: str) -> str:
    _require(isinstance(value, str) and DECIMAL.fullmatch(value) is not None
             and len(value) <= 20 and int(value) <= 2**64 - 1,
             f"{label} must be a positive canonical u64 decimal string")
    return value


def _commit(value: object, label: str) -> str:
    _require(isinstance(value, str) and HEX40.fullmatch(value) is not None,
             f"{label} must be a lowercase commit SHA")
    return value


def _digest(value: object) -> str:
    _require(isinstance(value, str) and HEX64.fullmatch(value) is not None
             and value != "0" * 64,
             "archive digest must be a nonzero lowercase SHA-256 value")
    return value


def _host_matrix(raw: str) -> dict[str, str]:
    _require(len(raw.encode("utf-8")) <= MAX_MATRIX_BYTES,
             "host matrix exceeds its size limit")
    matrix = _json_object(raw.encode("utf-8"), "host matrix")
    _exact_keys(matrix, {"include"}, "host matrix")
    rows = matrix["include"]
    _require(type(rows) is list and 0 < len(rows) <= len(RUNNERS),
             "host matrix must select one or more supported hosts")
    selected: dict[str, str] = {}
    for index, item in enumerate(rows):
        row = _exact_keys(item, {"host", "runner"}, f"host matrix row {index}")
        host = row["host"]
        runner = row["runner"]
        _require(isinstance(host, str) and host in RUNNERS,
                 f"host matrix row {index} selects an unsupported host")
        _require(host not in selected, "host matrix contains a duplicate host")
        _require(isinstance(runner, str) and runner == RUNNERS[host],
                 f"host matrix row {index} has a mismatched runner")
        selected[host] = runner
    return selected


def _directory_at(parent_fd: int, name: str, label: str) -> tuple[int, tuple[int, ...]]:
    try:
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        descriptor = os.open(name, DIRECTORY_FLAGS, dir_fd=parent_fd)
    except OSError as error:
        raise CatalogError(f"{label} is unavailable or linked") from error
    try:
        opened = os.fstat(descriptor)
        _require(stat.S_ISDIR(named.st_mode) and stat.S_ISDIR(opened.st_mode)
                 and opened.st_uid == os.geteuid()
                 and _fingerprint(named) == _fingerprint(opened),
                 f"{label} is not a stable ordinary directory")
        return descriptor, _fingerprint(opened)
    except BaseException:
        os.close(descriptor)
        raise


def _read_identity_at(directory_fd: int, filename: str, label: str) -> bytes:
    try:
        named = os.stat(filename, dir_fd=directory_fd, follow_symlinks=False)
        _require(stat.S_ISREG(named.st_mode) and named.st_nlink == 1
                 and named.st_uid == os.geteuid() and 0 < named.st_size <= MAX_IDENTITY_BYTES,
                 f"{label} must be an owned, singly linked bounded regular file")
        descriptor = os.open(filename, READ_FLAGS, dir_fd=directory_fd)
    except OSError as error:
        raise CatalogError(f"{label} is unavailable or linked") from error
    try:
        before = os.fstat(descriptor)
        _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                 and before.st_uid == os.geteuid() and 0 < before.st_size <= MAX_IDENTITY_BYTES
                 and _fingerprint(before) == _fingerprint(named),
                 f"{label} changed to an invalid file")
        content = bytearray()
        while len(content) <= MAX_IDENTITY_BYTES:
            chunk = os.read(descriptor, min(64 * 1024, MAX_IDENTITY_BYTES + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    _require(len(content) <= MAX_IDENTITY_BYTES and len(content) == before.st_size
             and _fingerprint(before) == _fingerprint(after) == _fingerprint(named),
             f"{label} changed while being read")
    return bytes(content)


def _read_catalog(root: Path, hosts: dict[str, str], producer_commit: str,
                  tools_commit: str, run_id: str, run_attempt: str) -> dict[str, str]:
    _check_components(root, "identity directory")
    try:
        root_named = root.lstat()
        _require(stat.S_ISDIR(root_named.st_mode) and root_named.st_uid == os.geteuid(),
                 "identity root must be an owned ordinary directory")
        root_fd = os.open(root, DIRECTORY_FLAGS)
    except OSError as error:
        raise CatalogError("identity root is unavailable or linked") from error
    try:
        root_opened = os.fstat(root_fd)
        _require(stat.S_ISDIR(root_opened.st_mode)
                 and _fingerprint(root_named) == _fingerprint(root_opened),
                 "identity root changed during open")
        expected_directories = {
            f"diagnostic-v2-cargo-identity-{host}" for host in hosts
        }
        root_names_before = set(os.listdir(root_fd))
        _require(root_names_before == expected_directories,
                 "identity root contains missing or unexpected host artifacts")

        catalog: dict[str, str] = {}
        directory_fingerprints: dict[str, tuple[int, ...]] = {}
        for host in sorted(hosts):
            directory_name = f"diagnostic-v2-cargo-identity-{host}"
            host_fd, directory_fingerprints[directory_name] = _directory_at(
                root_fd, directory_name, f"{host} identity artifact directory"
            )
            try:
                expected_file = f"{host}.json"
                _require(set(os.listdir(host_fd)) == {expected_file},
                         f"{host} identity artifact has missing or unexpected files")
                raw = _read_identity_at(host_fd, expected_file, f"{host} identity metadata")
                record = _json_object(raw, f"{host} identity metadata")
                _exact_keys(record, {
                    "schema", "host", "producer_commit", "tools_commit", "run_id",
                    "run_attempt", "archive_sha256",
                }, f"{host} identity metadata")
                _require(record["schema"] == SCHEMA and record["host"] == host,
                         f"{host} identity metadata selects a different schema or host")
                _require(record["producer_commit"] == producer_commit
                         and record["tools_commit"] == tools_commit,
                         f"{host} identity metadata has a different source/tool commit")
                _require(record["run_id"] == run_id and record["run_attempt"] == run_attempt,
                         f"{host} identity metadata belongs to a different workflow run")
                catalog[host] = _digest(record["archive_sha256"])
                _require(set(os.listdir(host_fd)) == {expected_file},
                         f"{host} identity artifact changed during read")
            finally:
                os.close(host_fd)

        _require(set(os.listdir(root_fd)) == root_names_before,
                 "identity root changed during read")
        for name, expected_fingerprint in directory_fingerprints.items():
            named = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
            _require(_fingerprint(named) == expected_fingerprint,
                     "identity artifact directory changed during read")
        _require(_fingerprint(os.fstat(root_fd)) == _fingerprint(root_opened),
                 "identity root changed during read")
        return catalog
    finally:
        os.close(root_fd)


def _append_github_output(path: Path, root: Path, catalog: dict[str, str]) -> None:
    _check_components(path.parent, "GitHub output parent")
    try:
        parent_metadata = path.parent.lstat()
        _require(stat.S_ISDIR(parent_metadata.st_mode)
                 and parent_metadata.st_uid == os.geteuid(),
                 "GitHub output parent must be an owned ordinary directory")
        named = path.lstat()
    except OSError as error:
        raise CatalogError("GitHub output is unavailable") from error
    _require(stat.S_ISREG(named.st_mode) and named.st_nlink == 1
             and named.st_uid == os.geteuid() and named.st_size <= MAX_OUTPUT_BYTES,
             "GitHub output must be an owned, singly linked bounded regular file")
    _require(path != root and root not in path.parents and path not in root.parents,
             "GitHub output must not overlap identity metadata")
    flags = os.O_RDWR | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0) \
        | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise CatalogError("GitHub output could not be opened safely") from error
    try:
        opened = os.fstat(descriptor)
        _require(stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1
                 and opened.st_uid == os.geteuid() and opened.st_size <= MAX_OUTPUT_BYTES
                 and _fingerprint(opened) == _fingerprint(named),
                 "GitHub output changed after validation")
        _require(opened.st_size == 0 or os.pread(descriptor, 1, opened.st_size - 1) == b"\n",
                 "GitHub output must end with a newline")
        value = json.dumps(catalog, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        content = f"cache_archives={value}\n".encode("ascii")
        _require(opened.st_size + len(content) <= MAX_OUTPUT_BYTES,
                 "GitHub output would exceed its size limit")
        _require(_fingerprint(os.fstat(descriptor)) == _fingerprint(opened),
                 "GitHub output changed before append")
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            _require(written > 0, "GitHub output append was incomplete")
            view = view[written:]
    except OSError as error:
        raise CatalogError("GitHub output append failed") from error
    finally:
        os.close(descriptor)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--identity-dir", required=True)
    parser.add_argument("--host-matrix", required=True)
    parser.add_argument("--producer-commit", required=True)
    parser.add_argument("--tools-commit", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    parser.add_argument("--github-output", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        root = _normalized_path(args.identity_dir, "identity directory")
        output = _normalized_path(args.github_output, "GitHub output")
        hosts = _host_matrix(args.host_matrix)
        producer_commit = _commit(args.producer_commit, "producer commit")
        tools_commit = _commit(args.tools_commit, "tools commit")
        run_id = _canonical_decimal(args.run_id, "run ID")
        run_attempt = _canonical_decimal(args.run_attempt, "run attempt")
        catalog = _read_catalog(root, hosts, producer_commit, tools_commit, run_id, run_attempt)
        _append_github_output(output, root, catalog)
        return 0
    except (CatalogError, OSError, UnicodeError, OverflowError, ValueError):
        sys.stderr.write(
            "native Cargo cache identity catalog rejected; no valid mapping was authorized\n"
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
