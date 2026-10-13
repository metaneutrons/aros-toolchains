#!/usr/bin/env python3
"""Reverify and stage selected SDK package bytes for later native index work.

This boundary is local package-byte verification and staging only. It does not
run SDK generations, complete an SDK inventory, admit a release, sign, or
publish. Run it after the authenticated owner collector in the same invocation;
the native SDK verifier and later native index verifier remain authoritative.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
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
MAX_NATIVE_OUTPUT = 4 * 1024 * 1024
MAX_RUNTIME = 1024 * 1024 * 1024
NATIVE_TIMEOUT_SECONDS = 1800
MAX_FORBIDDEN_PREFIXES = 64
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
ROOT_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
FILE_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
CREATE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)


class AssemblyError(ValueError):
    """The SDK package candidate failed its local bounded staging contract."""


def _load_helper(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("required SDK assembly helper is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_SELECT = _load_helper("sdk_assembly_package_selector", HERE / "select-sdk-package-inputs-v2.py")
_STAGE = _SELECT._STAGE
_MATRIX = _SELECT._MATRIX


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AssemblyError(message)


def _digest(value: object, label: str) -> str:
    _require(isinstance(value, str) and HEX64.fullmatch(value) is not None,
             f"{label} must be a lowercase SHA-256 digest")
    return value


def _canonical_existing(path: Path, label: str, *, directory: bool | None = None) -> Path:
    _require(path.is_absolute() and ".." not in path.parts,
             f"{label} path must be absolute and normalized")
    _require(_STAGE.path_is_canonical(path, must_exist=True),
             f"{label} path is linked or noncanonical")
    metadata = path.lstat()
    if directory is True:
        _require(stat.S_ISDIR(metadata.st_mode), f"{label} is not an ordinary directory")
    elif directory is False:
        _require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
                 and metadata.st_uid == os.geteuid(),
                 f"{label} is not an owned, singly linked regular file")
    return path


def _record_measurement(path: Path, limit: int, expected_sha: str, label: str,
                        selected_files: dict[Path, tuple[int, dict]]) -> dict:
    measured = _STAGE.measure_file(path, limit, label)
    _require(measured["sha256"] == expected_sha,
             f"{label} bytes differ from their selected digest")
    prior = selected_files.get(path)
    _require(prior is None or prior[1] == measured,
             f"{label} changed between selected observations")
    selected_files[path] = (limit, measured)
    return measured


def _verify_measurements(selected_files: dict[Path, tuple[int, dict]]) -> None:
    for path, (limit, expected) in selected_files.items():
        _require(_STAGE.measure_file(path, limit, f"selected input {path.name}") == expected,
                 f"selected input changed before SDK package staging output: {path.name}")


def _directory_snapshot(path: Path, label: str) -> tuple[tuple[int, ...], dict[str, str]]:
    before = _STAGE.directory_fingerprint(path, label)
    entries = _STAGE.directory_entries(path, label)
    after = _STAGE.directory_fingerprint(path, label)
    _require(before == after, f"{label} changed while being enumerated")
    return after, entries


def _remember_directory(path: Path, label: str, snapshots: dict) -> dict[str, str]:
    prior = snapshots.get(path)
    if prior is not None:
        return prior[1]
    current = _directory_snapshot(path, label)
    snapshots[path] = current
    return current[1]


def _verify_directories(snapshots: dict) -> None:
    for path, expected in snapshots.items():
        _require(_directory_snapshot(path, f"selected directory {path.name or path}") == expected,
                 f"selected directory changed before SDK package staging output: {path.name or path}")


def _selector_result(args: argparse.Namespace) -> dict:
    return _SELECT.select(
        plan_path=args.plan, plan_sha256=args.plan_sha256,
        inputs_dir=args.inputs_dir, inputs_sha256=args.inputs_sha256,
        producer_commit=args.producer_commit, tools_commit=args.tools_commit,
        fragment_path=args.fragment, fragment_sha256=args.fragment_sha256,
        owner_root=args.owner_root,
    )


def _load_bound_documents(args: argparse.Namespace, selected: dict,
                          selected_files: dict[Path, tuple[int, dict]],
                          snapshots: dict) -> tuple[dict, dict[str, dict], str]:
    runtime = _canonical_existing(args.aros, "native CLI", directory=False)
    _require(bool(stat.S_IMODE(runtime.lstat().st_mode) & 0o111),
             "selected native CLI is not executable")
    runtime_measurement = _STAGE.measure_file(runtime, MAX_RUNTIME, "selected native CLI")
    _require(runtime_measurement["sha256"] == args.aros_sha256
             and runtime_measurement["size"] > 0,
             "native CLI bytes differ from the selected runtime digest")
    selected_files[runtime] = (MAX_RUNTIME, runtime_measurement)

    inputs_dir = _canonical_existing(args.inputs_dir, "release-input directory", directory=True)
    snapshots[inputs_dir] = _directory_snapshot(inputs_dir, "digest-bound release-input directory")
    plan_measurement, plan_raw = _STAGE.read_bounded(
        args.plan, _MATRIX.MAX_PLAN_BYTES, "native release plan"
    )
    _require(plan_measurement["sha256"] == args.plan_sha256,
             "native release plan changed after package selection")
    selected_files[args.plan] = (_MATRIX.MAX_PLAN_BYTES, plan_measurement)
    plan = _STAGE.parse_json(plan_raw, "native release plan")
    _require(isinstance(plan, dict), "native release plan must be a JSON object")

    collection_path = inputs_dir / "toolchain-release-inputs-v2.json"
    collection_measurement = _record_measurement(
        collection_path, _SELECT.MAX_COLLECTION_BYTES, args.inputs_sha256,
        "digest-bound release-input collection", selected_files,
    )
    del collection_measurement
    fragment_measurement, fragment_raw = _STAGE.read_bounded(
        args.fragment, _STAGE.MAX_METADATA, "digest-bound SDK selection fragment"
    )
    _require(fragment_measurement["sha256"] == args.fragment_sha256,
             "SDK selection fragment bytes differ from the selected digest")
    fragment = _STAGE.parse_json(fragment_raw, "digest-bound SDK selection fragment")
    _require(isinstance(fragment, dict)
             and fragment.get("aros_sha256") == runtime_measurement["sha256"],
             "SDK selection fragment does not bind the selected native CLI")
    source_context_sha256 = _digest(
        fragment.get("source_context_sha256"), "selected source-context digest"
    )
    selected_files[args.fragment] = (_STAGE.MAX_METADATA, fragment_measurement)
    sdks = plan.get("sdks")
    groups = plan.get("groups")
    _require(type(sdks) is list and type(groups) is list,
             "selected native plan SDK and group arrays are invalid")
    package_ids = set(selected["sdk_packages"])
    _require({sdk.get("id") for sdk in sdks if isinstance(sdk, dict)} == package_ids
             and len(sdks) == len(package_ids),
             "selected native plan SDK IDs differ from the package projection")

    identities = {}
    for sdk in sdks:
        sdk_id = sdk["id"]
        reference = sdk["identity"]
        relative = Path(reference["file"])
        _require(not relative.is_absolute() and ".." not in relative.parts,
                 "native SDK identity reference escapes the selected inputs directory")
        identity_path = inputs_dir / relative
        _canonical_existing(identity_path, f"selected identity for {sdk_id}", directory=False)
        identity_measurement, identity_raw = _STAGE.read_bounded(
            identity_path, _STAGE.MAX_METADATA, f"selected identity for {sdk_id}"
        )
        _require(identity_measurement["sha256"] == reference["sha256"],
                 f"selected identity for {sdk_id} differs from the native plan digest")
        identity = _STAGE.parse_json(identity_raw, f"selected identity for {sdk_id}")
        _require(isinstance(identity, dict) and identity.get("sdk_id") == sdk_id,
                 f"selected identity for {sdk_id} does not name its native SDK")
        selected_files[identity_path] = (_STAGE.MAX_METADATA, identity_measurement)
        identities[sdk_id] = {"path": identity_path, "sha256": reference["sha256"],
                              "identity": identity}

    for group in groups:
        group_id = group["group_id"]
        for field in ("recipe", "source_lock", "profiles"):
            reference = group[field]
            relative = Path(reference["file"])
            _require(not relative.is_absolute() and ".." not in relative.parts,
                     f"selected {field} document for {group_id} escapes its inputs directory")
            document_path = inputs_dir / relative
            _canonical_existing(document_path, f"selected {field} document for {group_id}",
                                directory=False)
            _record_measurement(document_path, _STAGE.MAX_METADATA, reference["sha256"],
                                f"selected {field} document for {group_id}", selected_files)

    # The selector owns semantic validation; its digest-bound inputs were just
    # parsed here only to obtain native identity paths and their exact bytes.
    _require(selected["sdk_package_count"] == len(identities),
             "selected identity document count differs from the SDK package projection")
    return plan, identities, source_context_sha256


def _selector_packages(selected: dict) -> tuple[dict[str, dict], dict[str, dict]]:
    _STAGE.exact_keys(selected, {
        "schema", "assurance", "inputs_sha256", "plan_sha256", "fragment_sha256",
        "producer_commit", "tools_commit", "sdk_package_count", "sdk_packages",
        "package_locations",
    }, "SDK package selector result")
    _require(selected["schema"] == "aros-sdk-package-inputs-v2"
             and selected["assurance"] == "package-byte-selection-only"
             and type(selected["sdk_package_count"]) is int
             and selected["sdk_package_count"] == len(selected["sdk_packages"])
             and 0 < selected["sdk_package_count"] <= _MATRIX.MAX_SDKS,
             "SDK package selector result schema or count differs")
    packages = selected["sdk_packages"]
    _require(type(packages) is dict, "SDK package projection must be an object")
    for sdk_id, package in packages.items():
        _STAGE.validate_selection(sdk_id, "group", "profile", _MATRIX.ACTIVE_HOSTS[0])
        _STAGE.exact_keys(package, {"tree_sha256", "archive_sha256", "archive_size"},
                          "selected SDK package DTO")
        _digest(package["tree_sha256"], "selected SDK tree digest")
        _digest(package["archive_sha256"], "selected SDK archive digest")
        _require(type(package["archive_size"]) is int and package["archive_size"] > 0,
                 "selected SDK archive size is invalid")
    locations = selected["package_locations"]
    _require(type(locations) is list and len(locations) == len(packages),
             "SDK package representative locations differ from the exact SDK set")
    by_id = {}
    fields = {"sdk_id", "group_id", "target_profile", "host", "package_dir", "archive",
              "archive_path", "manifest_path", "checksum_path"}
    for location in locations:
        _STAGE.exact_keys(location, fields, "selected SDK package location")
        sdk_id = location["sdk_id"]
        _require(sdk_id in packages and sdk_id not in by_id,
                 "SDK package location IDs are missing, duplicated, or extra")
        by_id[sdk_id] = location
    _require(set(by_id) == set(packages),
             "SDK package location set differs from its package projection")
    return packages, by_id


def _package_snapshots(packages: dict[str, dict], locations: dict[str, dict],
                       selected_files: dict[Path, tuple[int, dict]], snapshots: dict
                       ) -> dict[str, dict]:
    result = {}
    for sdk_id in sorted(packages):
        location = locations[sdk_id]
        package_dir = Path(location["package_dir"])
        _canonical_existing(package_dir, f"selected SDK package directory for {sdk_id}",
                            directory=True)
        entries = _remember_directory(package_dir, f"selected package directory for {sdk_id}",
                                      snapshots)
        archive = location["archive"]
        _require(isinstance(archive, str) and _STAGE.portable_component(archive)
                 and archive.startswith(f"aros-sdk-{sdk_id}-") and archive.endswith(".tar.xz"),
                 f"selected SDK archive basename is invalid for {sdk_id}")
        member_names = {archive, f"{archive}.manifest.json", f"{archive}.sha256"}
        _require(entries == {name: "file" for name in member_names},
                 f"selected package for {sdk_id} does not contain exactly its three package files")
        paths = {
            archive: Path(location["archive_path"]),
            f"{archive}.manifest.json": Path(location["manifest_path"]),
            f"{archive}.sha256": Path(location["checksum_path"]),
        }
        for name, path in paths.items():
            _require(path == package_dir / name,
                     f"selected package member path differs from its derived location for {sdk_id}")
            _canonical_existing(path, f"selected package member for {sdk_id}", directory=False)
        measured = {}
        for name, path in paths.items():
            limit = _STAGE.MAX_PAYLOAD if name == archive else _STAGE.MAX_METADATA
            measured[name] = _STAGE.measure_file(path, limit, f"selected SDK member {name}")
            selected_files[path] = (limit, measured[name])
        _require(measured[archive] == {
            "sha256": packages[sdk_id]["archive_sha256"],
            "size": packages[sdk_id]["archive_size"],
        }, f"representative package archive differs from the selector DTO for {sdk_id}")
        result[sdk_id] = {"location": location, "package_dir": package_dir,
                          "paths": paths, "members": measured}
    return result


def _overlaps(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents


def _validate_forbidden_prefixes(values: list[Path]) -> list[str]:
    _require(1 <= len(values) <= MAX_FORBIDDEN_PREFIXES,
             "at least one and at most 64 forbidden build prefixes are required")
    result = []
    for value in values:
        raw = str(value)
        _require(value.is_absolute() and ".." not in value.parts
                 and 0 < len(raw.encode("utf-8")) <= 4096
                 and "\n" not in raw and "\r" not in raw,
                 "forbidden build prefix must be bounded, normalized, and absolute")
        result.append(raw)
    _require(len(result) == len(set(result)), "forbidden build prefixes must be unique")
    return result


def _create_private_directory(path: Path, label: str) -> None:
    os.mkdir(path, mode=0o700)
    os.chmod(path, 0o700, follow_symlinks=False)
    metadata = path.lstat()
    _require(stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode)
             and metadata.st_uid == os.geteuid() and stat.S_IMODE(metadata.st_mode) == 0o700
             and _STAGE.path_is_canonical(path, must_exist=True),
             f"{label} is not a private canonical directory")


def _create_limited_file(path: Path):
    descriptor = os.open(path, CREATE_FLAGS, 0o600)
    metadata = os.fstat(descriptor)
    _require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
             and metadata.st_uid == os.geteuid(),
             "native CLI output is not an owned regular file")
    return os.fdopen(descriptor, "wb")


def _limit_native_output() -> None:
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_NATIVE_OUTPUT, MAX_NATIVE_OUTPUT))


def _native_command(args: argparse.Namespace, sdk_id: str, package: dict,
                    identity_ref: dict, output_path: Path, selected_files: dict
                    ) -> dict:
    stderr_path = output_path.with_suffix(output_path.suffix + ".stderr.log")
    _require(not os.path.lexists(output_path) and not os.path.lexists(stderr_path),
             "native SDK result paths are not fresh")
    _verify_measurements(selected_files)
    stdout_handle = _create_limited_file(output_path)
    stderr_handle = _create_limited_file(stderr_path)
    command = [str(args.aros), "sdk", "verify-package",
               "--identity", str(identity_ref["path"]),
               "--identity-sha256", identity_ref["sha256"],
               "--tree-sha256", package["tree_sha256"],
               "--package-dir", str(Path(package["package_dir"])),
               "--archive-sha256", package["archive_sha256"],
               "--archive-size", str(package["archive_size"])]
    for prefix in args._forbidden_strings:
        command.extend(("--forbidden-prefix", prefix))
    _require("--format" not in command, "SDK native verifier invocation must use its current default output")
    process = None
    try:
        process = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=stdout_handle, stderr=stderr_handle,
            close_fds=True, start_new_session=True, preexec_fn=_limit_native_output,
        )
        try:
            return_code = process.wait(timeout=NATIVE_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            raise AssemblyError(
                f"{sdk_id} native SDK verifier timed out; its owned process group was terminated; "
                f"diagnostics retained at {stderr_path}"
            ) from None
    finally:
        stdout_handle.close()
        stderr_handle.close()

    stdout_measurement = _STAGE.measure_file(
        output_path, MAX_NATIVE_OUTPUT, f"{sdk_id} native SDK result"
    )
    stderr_measurement = _STAGE.measure_file(
        stderr_path, MAX_NATIVE_OUTPUT, f"{sdk_id} native SDK diagnostics"
    )
    if return_code != 0:
        raise AssemblyError(
            f"{sdk_id} native SDK verifier failed with exit status {return_code}; "
            f"bounded diagnostics retained at {stderr_path}"
        )
    _require(stdout_measurement["size"] > 0,
             f"{sdk_id} native SDK verifier returned an empty result")
    raw_measurement, raw = _STAGE.read_bounded(
        output_path, MAX_NATIVE_OUTPUT, f"{sdk_id} native SDK result"
    )
    _require(raw_measurement == stdout_measurement,
             f"{sdk_id} native SDK result changed while being parsed")
    envelope = _STAGE.parse_json(raw, f"{sdk_id} native SDK result")
    envelope = _STAGE.exact_keys(envelope, {"schema", "operation", "assurance", "result"},
                                 f"{sdk_id} native SDK result envelope")
    _require(envelope["schema"] == "aros-sdk-local-stage-v2"
             and envelope["operation"] == "sdk.verify-package"
             and envelope["assurance"] == "local-byte-consistency-not-release-admission",
             f"{sdk_id} native SDK result schema, operation, or assurance differs")
    result = _STAGE.exact_keys(envelope["result"], {
        "identity", "archive_sha256", "archive_size", "tree_sha256",
    }, f"{sdk_id} native SDK verification result")
    _require(result["identity"] == identity_ref["identity"],
             f"{sdk_id} native verifier returned a different SDK identity")
    _require(_digest(result["archive_sha256"], f"{sdk_id} native archive digest")
             == package["archive_sha256"]
             and type(result["archive_size"]) is int
             and result["archive_size"] == package["archive_size"]
             and _digest(result["tree_sha256"], f"{sdk_id} native tree digest")
             == package["tree_sha256"],
             f"{sdk_id} native verifier result differs from the package selector DTO")
    selected_files[output_path] = (MAX_NATIVE_OUTPUT, stdout_measurement)
    selected_files[stderr_path] = (MAX_NATIVE_OUTPUT, stderr_measurement)
    return {
        "path": str(output_path), "sha256": stdout_measurement["sha256"],
        "size": stdout_measurement["size"],
        "diagnostics": {"path": str(stderr_path), "sha256": stderr_measurement["sha256"],
                        "size": stderr_measurement["size"]},
    }


def _copy_member(source: Path, destination: Path, expected: dict, limit: int) -> dict:
    _require(_STAGE.measure_file(source, limit, "selected source package member") == expected,
             "selected source package member changed before staging")
    source_fd = os.open(source, FILE_FLAGS | getattr(os, "O_NONBLOCK", 0))
    destination_fd = os.open(destination, CREATE_FLAGS, 0o600)
    digest = hashlib.sha256()
    size = 0
    try:
        source_before = os.fstat(source_fd)
        destination_before = os.fstat(destination_fd)
        _require(stat.S_ISREG(source_before.st_mode) and source_before.st_nlink == 1
                 and source_before.st_uid == os.geteuid()
                 and stat.S_ISREG(destination_before.st_mode) and destination_before.st_nlink == 1
                 and destination_before.st_uid == os.geteuid(),
                 "package staging source or destination is not an owned regular file")
        os.fchmod(destination_fd, 0o600)
        while True:
            block = os.read(source_fd, 1024 * 1024)
            if not block:
                break
            size += len(block)
            _require(size <= expected["size"], "source package member grew during streamed staging")
            digest.update(block)
            view = memoryview(block)
            while view:
                written = os.write(destination_fd, view)
                _require(written > 0, "staged package member write was incomplete")
                view = view[written:]
        os.fsync(destination_fd)
        source_after = os.fstat(source_fd)
        destination_after = os.fstat(destination_fd)
        _require(size == expected["size"] == source_before.st_size
                 and digest.hexdigest() == expected["sha256"]
                 and (source_before.st_dev, source_before.st_ino, source_before.st_mtime_ns,
                      source_before.st_ctime_ns) ==
                     (source_after.st_dev, source_after.st_ino, source_after.st_mtime_ns,
                      source_after.st_ctime_ns)
                 and stat.S_ISREG(destination_after.st_mode) and destination_after.st_nlink == 1,
                 "streamed source bytes differ from the native-verified package member")
    finally:
        os.close(source_fd)
        os.close(destination_fd)
    source_after = _STAGE.measure_file(source, limit, "source package member after staging")
    target_after = _STAGE.measure_file(destination, limit, "staged package member")
    _require(source_after == expected == target_after,
             "staged SDK package member is not byte-identical to its selected source")
    return target_after


def _stage_packages(package_sources: dict[str, dict], packages: dict[str, dict],
                    release_dir: Path) -> dict[str, dict]:
    _require(set(package_sources) == set(packages),
             "selected package sources differ from the exact SDK package set")
    names_by_sdk = {}
    folded = {}
    for sdk_id in sorted(package_sources):
        source = package_sources[sdk_id]
        archive = source["location"]["archive"]
        names = (archive, f"{archive}.manifest.json", f"{archive}.sha256")
        for name in names:
            _require(name.casefold() not in folded,
                     "SDK package copy names collide under case folding")
            folded[name.casefold()] = name
        names_by_sdk[sdk_id] = names

    staged = {}
    for sdk_id, source in sorted(package_sources.items()):
        for name in names_by_sdk[sdk_id]:
            limit = _STAGE.MAX_PAYLOAD if name.endswith(".tar.xz") else _STAGE.MAX_METADATA
            measured = _copy_member(source["paths"][name], release_dir / name,
                                    source["members"][name], limit)
            if name == source["location"]["archive"]:
                _require(measured["sha256"] == packages[sdk_id]["archive_sha256"]
                         and measured["size"] == packages[sdk_id]["archive_size"],
                         f"staged SDK archive differs from the package DTO for {sdk_id}")
            staged[name] = measured
    return staged


def _verify_staged(staged: dict[str, dict], release_dir: Path) -> None:
    expected_names = {name: "file" for name in staged}
    _require(_STAGE.directory_entries(release_dir, "staged SDK release directory") == expected_names,
             "staged SDK release inventory contains unexpected or missing members")
    for name, expected in staged.items():
        limit = _STAGE.MAX_PAYLOAD if name.endswith(".tar.xz") else _STAGE.MAX_METADATA
        _require(_STAGE.measure_file(release_dir / name, limit, "staged SDK member") == expected,
                 "staged SDK package member changed before assembly output")


def _new_root(args: argparse.Namespace, package_sources: dict) -> Path:
    root = args.root
    _require(root.is_absolute() and ".." not in root.parts and root.name not in ("", ".", ".."),
             "SDK staging root must be an absolute normalized path")
    _require(not os.path.lexists(root), "SDK staging root must be absent")
    parent = _canonical_existing(root.parent, "SDK staging root parent", directory=True)
    _require(parent.lstat().st_uid == os.geteuid(),
             "SDK staging root parent must be owned by the current user")
    protected = [args.aros, args.plan, args.inputs_dir, args.fragment, args.owner_root]
    protected.extend(source["package_dir"] for source in package_sources.values())
    for path in protected:
        _require(not _overlaps(root, path),
                 "SDK staging root overlaps a selected runtime, input, or package path")
    _require(not _overlaps(root, args.inputs_dir)
             and not _overlaps(root, args.owner_root),
             "SDK staging root overlaps selected source directories")
    _create_private_directory(root, "SDK staging root")
    native_dir = root / "native"
    release_dir = root / "release"
    _create_private_directory(native_dir, "SDK native result directory")
    _create_private_directory(release_dir, "SDK staged release directory")
    return root


def _check_forbidden_root(args: argparse.Namespace) -> list[str]:
    values = _validate_forbidden_prefixes(args.forbidden_prefix)
    args._forbidden_strings = values
    return values


def _same_selection(before: dict, after: dict, label: str) -> None:
    _require(before == after, f"SDK package selector result changed {label}")


def assemble(args: argparse.Namespace) -> dict:
    plan_sha = _digest(args.plan_sha256, "selected native plan digest")
    inputs_sha = _digest(args.inputs_sha256, "selected release-input digest")
    fragment_sha = _digest(args.fragment_sha256, "selected collector-fragment digest")
    runtime_sha = _digest(args.aros_sha256, "selected native CLI digest")
    args.plan_sha256, args.inputs_sha256 = plan_sha, inputs_sha
    args.fragment_sha256, args.aros_sha256 = fragment_sha, runtime_sha
    args._forbidden_strings = _check_forbidden_root(args)

    selected_before = _selector_result(args)
    packages, locations = _selector_packages(selected_before)
    selected_files: dict[Path, tuple[int, dict]] = {}
    snapshots: dict[Path, tuple[tuple[int, ...], dict[str, str]]] = {}
    plan, identities, source_context_sha256 = _load_bound_documents(
        args, selected_before, selected_files, snapshots
    )
    package_sources = _package_snapshots(packages, locations, selected_files, snapshots)

    for path in (args.plan, args.inputs_dir, args.owner_root):
        _require(not _overlaps(args.root, path),
                 "SDK staging root overlaps a selected source directory or plan")
    root = _new_root(args, package_sources)
    native_dir = root / "native"
    native_results = {}
    for sdk_id in sorted(packages):
        _require(sdk_id in identities and sdk_id in package_sources,
                 "selected SDK identity or representative package is missing")
        location = package_sources[sdk_id]["location"]
        package = dict(packages[sdk_id])
        package["package_dir"] = location["package_dir"]
        result_path = native_dir / f"verify-{sdk_id}.json"
        native_results[sdk_id] = _native_command(
            args, sdk_id, package, identities[sdk_id], result_path, selected_files
        )

    selected_after_native = _selector_result(args)
    _same_selection(selected_before, selected_after_native, "after native verification")
    _verify_measurements(selected_files)
    _verify_directories(snapshots)
    for sdk_id, source in package_sources.items():
        _require(_directory_snapshot(source["package_dir"], "representative package directory")
                 == snapshots[source["package_dir"]],
                 f"representative SDK package directory changed during native verification: {sdk_id}")

    staged = _stage_packages(package_sources, packages, root / "release")
    selected_before_output = _selector_result(args)
    _same_selection(selected_before, selected_before_output, "before the output barrier")
    _verify_measurements(selected_files)
    _verify_directories(snapshots)
    _verify_staged(staged, root / "release")
    _require(_STAGE.directory_entries(root, "SDK staging operation root") == {
        "native": "directory", "release": "directory",
    }, "SDK staging root contains unexpected entries")
    expected_native = {}
    for sdk_id in packages:
        expected_native[f"verify-{sdk_id}.json"] = "file"
        expected_native[f"verify-{sdk_id}.json.stderr.log"] = "file"
    _require(_STAGE.directory_entries(native_dir, "SDK native result directory") == expected_native,
             "SDK native output inventory differs from the selected SDK set")
    for selector in native_results.values():
        _require(_STAGE.measure_file(Path(selector["path"]), MAX_NATIVE_OUTPUT,
                                    "native SDK result selector") == {
                "sha256": selector["sha256"], "size": selector["size"],
            }
            and _STAGE.measure_file(Path(selector["diagnostics"]["path"]), MAX_NATIVE_OUTPUT,
                                    "native SDK diagnostics selector") == {
                "sha256": selector["diagnostics"]["sha256"],
                "size": selector["diagnostics"]["size"],
            }, "native SDK result or diagnostics changed before output")

    output_snapshots = {
        root: _directory_snapshot(root, "SDK staging operation root"),
        native_dir: _directory_snapshot(native_dir, "SDK native result directory"),
        root / "release": _directory_snapshot(root / "release", "SDK staged release directory"),
    }
    _require(output_snapshots[root][1] == {"native": "directory", "release": "directory"}
             and output_snapshots[native_dir][1] == expected_native
             and output_snapshots[root / "release"][1] == {
                 name: "file" for name in staged
             }, "SDK output directory snapshots differ from the selected inventory")
    _verify_measurements(selected_files)
    _verify_directories(snapshots)
    _verify_staged(staged, root / "release")
    for path, expected_snapshot in output_snapshots.items():
        _require(_directory_snapshot(path, f"SDK output directory {path.name}")
                 == expected_snapshot,
                 f"SDK output directory changed before assembly output: {path.name}")

    _require(len(staged) == 3 * len(packages),
             "staged SDK inventory is not exactly three members per selected SDK")
    package_sources_summary = {
        sdk_id: {
            "group_id": source["location"]["group_id"],
            "target_profile": source["location"]["target_profile"],
            "host": source["location"]["host"],
            "package_dir": str(source["package_dir"]),
            "archive": source["location"]["archive"],
        }
        for sdk_id, source in sorted(package_sources.items())
    }
    return {
        "schema": "aros-sdk-package-candidate-assembly-v2",
        "operation": "sdk-package-staging",
        "assurance": "sdk-package-staging-partial-no-admission",
        "staged_root": str(root / "release"),
        "bindings": {
            "aros_sha256": args.aros_sha256,
            "plan_sha256": args.plan_sha256,
            "inputs_sha256": args.inputs_sha256,
            "fragment_sha256": args.fragment_sha256,
            "source_context_sha256": source_context_sha256,
            "producer_commit": args.producer_commit,
            "tools_commit": args.tools_commit,
        },
        "sdk_count": len(packages),
        "sdk_packages": {sdk_id: packages[sdk_id] for sdk_id in sorted(packages)},
        "package_sources": package_sources_summary,
        "native_results": {sdk_id: native_results[sdk_id] for sdk_id in sorted(native_results)},
        "staged_inventory": {name: staged[name] for name in sorted(staged)},
        "scope": {
            "sdk_package_staging": True,
            "all_sdk_generations_executed": False,
            "complete_sdk_inventory": False,
            "release_admission": False,
            "publication": False,
        },
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--aros", type=Path, required=True)
    parser.add_argument("--aros-sha256", required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--plan-sha256", required=True)
    parser.add_argument("--inputs-dir", type=Path, required=True)
    parser.add_argument("--inputs-sha256", required=True)
    parser.add_argument("--producer-commit", required=True)
    parser.add_argument("--tools-commit", required=True)
    parser.add_argument("--fragment", type=Path, required=True)
    parser.add_argument("--fragment-sha256", required=True)
    parser.add_argument("--owner-root", type=Path, required=True)
    parser.add_argument("--forbidden-prefix", action="append", type=Path, default=[])
    parser.add_argument("--root", type=Path, required=True)
    return parser


def _reject_repeated_options(argv: list[str]) -> None:
    seen = set()
    for argument in argv:
        if not argument.startswith("--"):
            continue
        option = argument.split("=", 1)[0]
        if option == "--forbidden-prefix":
            continue
        _require(option not in seen, f"repeated command-line option: {option}")
        seen.add(option)


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    try:
        _reject_repeated_options(arguments)
        args = _parser().parse_args(arguments)
        result = assemble(args)
        sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=True, allow_nan=False) + "\n")
        return 0
    except SystemExit:
        raise
    except (_STAGE.StageError, _MATRIX.PlanError, AssemblyError, OSError,
            UnicodeError, RecursionError, ValueError, KeyError, TypeError) as error:
        sys.stderr.write(f"SDK package candidate assembly failed: {error}\n")
        return 1
    except Exception:
        sys.stderr.write("SDK package candidate assembly failed: closed byte boundary\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
