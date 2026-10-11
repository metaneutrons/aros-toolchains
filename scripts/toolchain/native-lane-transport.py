#!/usr/bin/env python3
"""Extract a retained native build ZIP after a trusted origin verification.

This helper checks byte relationships in a retained transport bundle. It does
not authenticate a signature, provider, job owner, build, or publication.
Retained paths are assumed to be quiescent and owned by the invoking user;
readback checks are not a hostile concurrent-writer isolation boundary.
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
import zipfile


_ORIGIN_PATH = Path(__file__).with_name("artifact-origin.py")
_ORIGIN_SPEC = importlib.util.spec_from_file_location("artifact_origin", _ORIGIN_PATH)
assert _ORIGIN_SPEC is not None and _ORIGIN_SPEC.loader is not None
origin = importlib.util.module_from_spec(_ORIGIN_SPEC)
_ORIGIN_SPEC.loader.exec_module(origin)

SCHEMA = "aros-toolchain-native-lane-transport-v2"
ASSURANCE = "transport-byte-readback-only"
RETAINED_NAMES = {"payload.zip", "origin.json", "origin.sigstore.json", "selection.json"}
EVIDENCE_NAMES = {
    "evidence/build-result.json",
    "evidence/environment.json",
    "evidence/environment-result.json",
    "evidence/package-result.json",
    "evidence/package-verify.json",
    "evidence/measurement.json",
}
OUTPUT_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)


def _require(condition: bool, message: str) -> None:
    origin.require(condition, message)


def _stat_identity(entry: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (entry.st_dev, entry.st_ino, entry.st_size, entry.st_mtime_ns,
            entry.st_ctime_ns, entry.st_uid, stat.S_IMODE(entry.st_mode))


def _inode_identity(entry: os.stat_result) -> tuple[int, int]:
    return entry.st_dev, entry.st_ino


def _directory_identity(entry: os.stat_result) -> tuple[int, int, int, int]:
    return entry.st_dev, entry.st_ino, entry.st_uid, stat.S_IMODE(entry.st_mode)


def _private_owned(entry: os.stat_result, *, directory: bool = False) -> bool:
    ordinary = stat.S_ISDIR(entry.st_mode) if directory else stat.S_ISREG(entry.st_mode)
    return ordinary and entry.st_uid == os.geteuid() and not (stat.S_IMODE(entry.st_mode) & 0o077)


def _validate_root(root: Path) -> tuple[dict[str, dict], dict[str, bytes], tuple, tuple[str, ...]]:
    _require(root.is_absolute() and ".." not in root.parts and root == root.resolve()
             and root.is_dir() and not root.is_symlink(),
             "retained directory must be an absolute canonical ordinary directory")
    before_root = root.lstat()
    _require(_private_owned(before_root, directory=True),
             "retained directory must be owner-only and owned by the current user")
    names = tuple(sorted(entry.name for entry in os.scandir(root)))
    _require(set(names) == RETAINED_NAMES and len(names) == len(RETAINED_NAMES),
             "retained directory must contain exactly the four transport files")

    measurements: dict[str, dict] = {}
    contents: dict[str, bytes] = {}
    for name in sorted(RETAINED_NAMES):
        path = root / name
        named_before = path.lstat()
        _require(_private_owned(named_before),
                 "retained inputs must be owner-only singly linked regular files")
        limit = origin.MAX_PAYLOAD if name == "payload.zip" else origin.MAX_METADATA
        measured, raw = origin.normalized_file(path, limit)
        named_after = path.lstat()
        _require(_stat_identity(named_before) == _stat_identity(named_after)
                 and _private_owned(named_after), "retained input changed while it was measured")
        measurements[name] = {**measured, "identity": _stat_identity(named_after)}
        if raw is not None:
            contents[name] = raw

    after_root = root.lstat()
    after_names = tuple(sorted(entry.name for entry in os.scandir(root)))
    _require(_stat_identity(before_root) == _stat_identity(after_root)
             and names == after_names and _private_owned(after_root, directory=True),
             "retained directory changed while it was measured")
    _require(set(contents) == {"origin.json", "origin.sigstore.json", "selection.json"},
             "retained metadata could not be read within its byte limit")
    return measurements, contents, _stat_identity(after_root), names


def _validate_identity(selection_raw: bytes, origin_raw: bytes) -> tuple[dict, dict, dict]:
    selected = origin.exact_keys(
        origin.parse_json(selection_raw),
        {"schema", "context", "selection", "job", "artifact", "proof"},
    )
    _require(selected["schema"] == origin.SELECTION_SCHEMA,
             "retained source selection schema differs")
    context = origin.validate_context(selected["context"])
    lane = origin.exact_keys(selected["selection"], {"role", "group", "host", "profile", "copy"})
    _require(origin.selection(argparse.Namespace(**lane)) == lane
             and lane["role"] == "build" and lane["copy"] in ("a", "b"),
             "retained lane is not a native build copy")

    planned_job = origin.exact_keys(selected["job"], {"id", "name"})
    _require(type(planned_job["id"]) is int and origin.positive(planned_job["id"]) == planned_job["id"]
             and isinstance(planned_job["name"], str) and 0 < len(planned_job["name"]) <= 256,
             "retained source job identity is invalid")
    artifact = _validate_artifact(selected["artifact"], origin.MAX_PAYLOAD)
    proof = _validate_artifact(selected["proof"], 2 * origin.MAX_METADATA)
    _require(artifact["id"] != proof["id"] and artifact["name"] != proof["name"],
             "retained payload and proof identities must be separate")

    signed = origin.exact_keys(
        origin.parse_json(origin_raw),
        {"schema", "context", "selection", "job", "artifact", "files"},
    )
    _require(signed["schema"] == origin.SCHEMA, "signed-origin schema differs")
    signed_context = origin.validate_context(signed["context"])
    _require(signed_context == context and signed["selection"] == lane,
             "signed origin does not join the retained context and lane selection")

    owner = origin.exact_keys(signed["job"], {"id", "check_run_id", "name"})
    _require(type(owner["id"]) is int and origin.positive(owner["id"]) == owner["id"]
             and type(owner["check_run_id"]) is int
             and origin.positive(owner["check_run_id"]) == owner["check_run_id"]
             and owner["id"] == planned_job["id"] and owner["name"] == planned_job["name"],
             "signed owner does not join the retained source job identity")
    signed_artifact = _validate_artifact(signed["artifact"], origin.MAX_PAYLOAD)
    _require(signed_artifact == artifact,
             "signed artifact does not join the retained payload identity")
    return selected, signed, signed_artifact


def _validate_artifact(value: object, size_limit: int) -> dict:
    item = origin.exact_keys(value, {"id", "name", "sha256", "size_in_bytes"})
    _require(type(item["id"]) is int and origin.positive(item["id"]) == item["id"]
             and type(item["size_in_bytes"]) is int and 0 < item["size_in_bytes"] <= size_limit
             and isinstance(item["name"], str) and bool(origin.SEGMENT.fullmatch(item["name"]))
             and isinstance(item["sha256"], str)
             and bool(re.fullmatch(r"[0-9a-f]{64}", item["sha256"])),
             "retained artifact identity is invalid")
    return item


def _closed_inventory(files: object) -> dict[str, dict]:
    _require(isinstance(files, dict), "signed native file inventory is invalid")
    origin.require_portable_inventory(files)
    candidates = [name for name in files if name.startswith("package/") and name.endswith(".tar.xz")]
    _require(len(candidates) == 1, "native inventory must contain one package archive")
    archive = candidates[0]
    basename = archive.removeprefix("package/")
    _require("/" not in basename and origin.portable_path(basename)
             and basename.endswith(".tar.xz") and basename[:-len(".tar.xz")],
             "native package archive name is not one portable basename")
    expected = set(EVIDENCE_NAMES)
    expected.update({archive, archive + ".manifest.json", archive + ".sha256", archive + ".spdx.json"})
    _require(set(files) == expected and len(files) == 10,
             "signed native inventory is not the exact ten-file lane closure")
    total = 0
    for name, value in files.items():
        measurement = origin.exact_keys(value, {"sha256", "size"})
        size = measurement["size"]
        sha256 = measurement["sha256"]
        _require(type(size) is int and size >= 0 and isinstance(sha256, str)
                 and bool(re.fullmatch(r"[0-9a-f]{64}", sha256)),
                 "signed native file measurement is invalid")
        if name == archive:
            _require(size <= origin.MAX_PAYLOAD,
                     "signed native package archive exceeds payload byte limit")
        else:
            _require(size <= origin.MAX_METADATA,
                     "signed native metadata member exceeds 16 MiB limit")
        total += size
        _require(total <= origin.MAX_PAYLOAD,
                 "signed native file inventory exceeds aggregate payload byte limit")
    return files


def _output_preflight(retained: Path, output: Path) -> tuple[Path, os.stat_result]:
    _require(output.is_absolute() and ".." not in output.parts and output.name not in ("", ".", ".."),
             "output directory must be a fresh absolute normalized path")
    _require(output != retained and output not in retained.parents and retained not in output.parents,
             "output and retained directories must not overlap")
    parent = output.parent
    _require(parent == parent.resolve() and parent.is_dir() and not parent.is_symlink(),
             "output parent must be an existing canonical directory")
    parent_before = parent.lstat()
    _require(stat.S_ISDIR(parent_before.st_mode), "output parent is not an ordinary directory")
    try:
        output.lstat()
    except FileNotFoundError:
        pass
    else:
        raise origin.OriginError("output directory must be fresh")
    return output, parent_before


def _verified_transport(retained: Path) -> tuple[dict, dict, dict, dict]:
    _require(isinstance(retained, Path) and retained.is_absolute() and ".." not in retained.parts,
             "retained directory must be absolute and normalized")
    inputs, contents, root_identity, names = _validate_root(retained)
    _, signed, artifact = _validate_identity(contents["selection.json"], contents["origin.json"])
    files = _closed_inventory(signed["files"])
    origin.verify_zip(retained / "payload.zip", files, artifact["sha256"], artifact["size_in_bytes"])
    return inputs, contents, {"signed": signed, "artifact": artifact, "files": files}, {
        "root_identity": root_identity, "names": names,
    }


def _result(output: Path, inputs: dict, output_measurements: dict[str, dict]) -> dict:
    measurement = output_measurements["evidence/measurement.json"]
    return {
        "schema": SCHEMA,
        "assurance": ASSURANCE,
        "package_dir": str(output / "package"),
        "measurement": str(output / "evidence/measurement.json"),
        "measurement_sha256": measurement["sha256"],
        "measurement_size": measurement["size"],
        "environment": str(output / "evidence/environment.json"),
        "origin_sha256": inputs["origin.json"]["sha256"],
        "selection_sha256": inputs["selection.json"]["sha256"],
        "raw_zip_sha256": inputs["payload.zip"]["sha256"],
        "output_files": {
            name: {"path": str(output / name), **output_measurements[name]}
            for name in sorted(output_measurements)
        },
    }


def verify_output(retained: Path, output: Path) -> dict:
    """Read back a prior output and retained transport without writing anything."""
    inputs_before, _, transport, retained_before = _verified_transport(retained)
    _require(output.is_absolute() and ".." not in output.parts and output == output.resolve()
             and output != retained and output not in retained.parents and retained not in output.parents,
             "verification output must be an absolute canonical non-overlapping directory")
    parent = output.parent
    _require(parent == parent.resolve() and parent.is_dir() and not parent.is_symlink(),
             "verification output parent must be canonical")
    root_before = output.lstat()
    _require(_private_owned(root_before, directory=True),
             "verification output root must be owner-only and owned by the current user")
    root_names = tuple(sorted(entry.name for entry in os.scandir(output)))
    _require(set(root_names) == {"package", "evidence"} and len(root_names) == 2,
             "verification output root must contain exactly package and evidence directories")
    directory_states = {}
    for folder in ("package", "evidence"):
        directory = output / folder
        directory_stat = directory.lstat()
        _require(_private_owned(directory_stat, directory=True),
                 "verification output directories must be owner-only ordinary directories")
        directory_states[folder] = _stat_identity(directory_stat)
        expected_names = {name.split("/", 1)[1] for name in transport["files"]
                          if name.startswith(folder + "/")}
        actual_names = tuple(sorted(entry.name for entry in os.scandir(directory)))
        _require(set(actual_names) == expected_names and len(actual_names) == len(expected_names),
                 "verification output file tree differs from the signed closure")

    output_measurements = {}
    for name, expected in transport["files"].items():
        path = output / name
        named = path.lstat()
        _require(_private_owned(named) and named.st_nlink == 1,
                 "verification output member must be an owner-only ordinary file")
        measured, _ = origin.normalized_file(path, origin.MAX_PAYLOAD)
        _require(measured == expected, "verification output bytes differ from the signed inventory")
        output_measurements[name] = measured

    # Recheck names and directory identities after every member has been read.
    root_after = output.lstat()
    root_names_after = tuple(sorted(entry.name for entry in os.scandir(output)))
    _require(_stat_identity(root_before) == _stat_identity(root_after)
             and root_names == root_names_after,
             "verification output root changed during readback")
    for folder, identity in directory_states.items():
        directory = output / folder
        current = directory.lstat()
        expected_names = {name.split("/", 1)[1] for name in transport["files"]
                          if name.startswith(folder + "/")}
        actual_names = tuple(sorted(entry.name for entry in os.scandir(directory)))
        _require(_stat_identity(current) == identity and set(actual_names) == expected_names
                 and len(actual_names) == len(expected_names),
                 "verification output directory changed during readback")

    inputs_after, _, _, retained_after = _verified_transport(retained)
    _require(inputs_before == inputs_after
             and retained_before["root_identity"] == retained_after["root_identity"]
             and retained_before["names"] == retained_after["names"],
             "retained transport identities changed during output readback")
    return _result(output, inputs_before, output_measurements)


def _create_directory(parent_fd: int, name: str) -> tuple[int, tuple[int, int]]:
    os.mkdir(name, mode=0o700, dir_fd=parent_fd)
    named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    identity = _inode_identity(named)
    os.chmod(name, 0o700, dir_fd=parent_fd, follow_symlinks=False)
    descriptor = os.open(name, DIR_FLAGS, dir_fd=parent_fd)
    opened = os.fstat(descriptor)
    _require(_inode_identity(opened) == identity and _private_owned(opened, directory=True),
             "created output directory is not private and ordinary")
    return descriptor, identity


def _write_member(archive: zipfile.ZipFile, member: zipfile.ZipInfo,
                  target_dir_fd: int, basename: str, expected: dict,
                  created_files: dict[tuple[str, str], tuple[int, int]], folder: str) -> dict:
    fd = os.open(basename, OUTPUT_FLAGS, 0o600, dir_fd=target_dir_fd)
    before = os.fstat(fd)
    created_files[(folder, basename)] = _inode_identity(before)
    try:
        os.fchmod(fd, 0o600)
        before = os.fstat(fd)
        _require(_private_owned(before), "created output file is not private and ordinary")
        digest = hashlib.sha256()
        size = 0
        with os.fdopen(fd, "wb") as target, archive.open(member, "r") as source:
            fd = -1
            for block in iter(lambda: source.read(1024 * 1024), b""):
                size += len(block)
                _require(size <= member.file_size and size <= expected["size"],
                         "decompressed member exceeded its signed size")
                digest.update(block)
                view = memoryview(block)
                while view:
                    written = target.write(view)
                    _require(written is not None and written > 0,
                             "output member write was incomplete")
                    view = view[written:]
            target.flush()
            os.fsync(target.fileno())
            after = os.fstat(target.fileno())
        named = os.stat(basename, dir_fd=target_dir_fd, follow_symlinks=False)
        _require(_private_owned(after) and after.st_nlink == 1
                 and _inode_identity(before) == _inode_identity(after) == _inode_identity(named)
                 and size == expected["size"] and digest.hexdigest() == expected["sha256"],
                 "decompressed member bytes differ from the signed inventory")
    finally:
        if fd >= 0:
            os.close(fd)
    return {"sha256": digest.hexdigest(), "size": size}


def _cleanup_output(parent_fd: int, root_name: str, root_fd: int | None,
                    root_identity: tuple[int, int] | None,
                    directory_identities: dict[str, tuple[int, int]],
                    file_identities: dict[tuple[str, str], tuple[int, int]]) -> bool:
    if root_fd is not None:
        dir_fds = {"package": None, "evidence": None}
        try:
            for name in ("package", "evidence"):
                try:
                    dir_fds[name] = os.open(name, DIR_FLAGS, dir_fd=root_fd)
                except FileNotFoundError:
                    continue
                except OSError:
                    return False
            for (folder, basename), identity in file_identities.items():
                directory_fd = dir_fds.get(folder)
                if directory_fd is None:
                    continue
                try:
                    current = os.stat(basename, dir_fd=directory_fd, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                except OSError:
                    return False
                if not (stat.S_ISREG(current.st_mode) and current.st_nlink == 1
                        and _inode_identity(current) == identity):
                    return False
                try:
                    os.unlink(basename, dir_fd=directory_fd)
                except OSError:
                    return False
        finally:
            for descriptor in dir_fds.values():
                if descriptor is not None:
                    os.close(descriptor)
        for name in ("evidence", "package"):
            identity = directory_identities.get(name)
            if identity is None:
                continue
            try:
                current = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            except OSError:
                return False
            if not (stat.S_ISDIR(current.st_mode) and _inode_identity(current) == identity):
                return False
            try:
                os.rmdir(name, dir_fd=root_fd)
            except OSError:
                return False
        try:
            if os.listdir(root_fd):
                return False
        except OSError:
            return False
    try:
        current_root = os.stat(root_name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    if not stat.S_ISDIR(current_root.st_mode) or root_identity is None \
            or _inode_identity(current_root) != root_identity:
        return False
    if root_fd is None:
        try:
            probe = os.open(root_name, DIR_FLAGS, dir_fd=parent_fd)
            try:
                if os.listdir(probe):
                    return False
            finally:
                os.close(probe)
        except OSError:
            return False
    try:
        os.rmdir(root_name, dir_fd=parent_fd)
        return True
    except OSError:
        return False


def extract(retained: Path, output: Path) -> dict:
    """Verify the retained joins and exact ZIP closure, then extract by streaming."""
    inputs_before, _, transport, retained_state_before = _verified_transport(retained)
    artifact = transport["artifact"]
    files = transport["files"]

    output, parent_before = _output_preflight(retained, output)
    parent_flags = DIR_FLAGS
    parent_fd = os.open(output.parent, parent_flags)
    root_fd: int | None = None
    child_fds: dict[str, int] = {}
    root_identity: tuple[int, int] | None = None
    directory_identities: dict[str, tuple[int, int]] = {}
    file_identities: dict[tuple[str, str], tuple[int, int]] = {}
    made_root = False
    try:
        parent_open = os.fstat(parent_fd)
        parent_named = output.parent.lstat()
        _require(_inode_identity(parent_open) == _inode_identity(parent_named)
                 and _directory_identity(parent_before) == _directory_identity(parent_named),
                 "output parent changed after preflight")
        try:
            os.mkdir(output.name, mode=0o700, dir_fd=parent_fd)
        except FileExistsError:
            raise origin.OriginError("output directory must remain fresh") from None
        made_root = True
        root_named = os.stat(output.name, dir_fd=parent_fd, follow_symlinks=False)
        root_identity = _inode_identity(root_named)
        os.chmod(output.name, 0o700, dir_fd=parent_fd, follow_symlinks=False)
        root_fd = os.open(output.name, DIR_FLAGS, dir_fd=parent_fd)
        root_open = os.fstat(root_fd)
        _require(_inode_identity(root_open) == root_identity and _private_owned(root_open, directory=True),
                 "output root is not an owner-only canonical directory")
        for name in ("package", "evidence"):
            child_fd, identity = _create_directory(root_fd, name)
            child_fds[name] = child_fd
            directory_identities[name] = identity

        output_measurements: dict[str, dict] = {}
        with zipfile.ZipFile(retained / "payload.zip", "r") as archive:
            members = {member.filename: member for member in archive.infolist()}
            _require(len(members) == len(files) and set(members) == set(files),
                     "payload member list changed after verification")
            for name in sorted(files):
                folder, basename = name.split("/", 1)
                output_measurements[name] = _write_member(
                    archive, members[name], child_fds[folder], basename,
                    files[name], file_identities, folder,
                )

        for folder in ("package", "evidence"):
            expected = {name.split("/", 1)[1] for name in files if name.startswith(folder + "/")}
            _require(set(os.listdir(child_fds[folder])) == expected,
                     "output directory contains an unexpected member")
        _require(set(os.listdir(root_fd)) == {"package", "evidence"},
                 "output root contains an unexpected directory entry")

        # Re-read every extracted file from disk and compare it to the signed inventory.
        for name, expected in files.items():
            output_path = output / name
            measured, _ = origin.normalized_file(output_path, origin.MAX_PAYLOAD)
            named = output_path.lstat()
            _require(measured == expected and _private_owned(named) and named.st_nlink == 1,
                     "extracted output readback differs from the signed inventory")
            output_measurements[name] = measured

        inputs_after, _, _, retained_state_after = _verified_transport(retained)
        _require(inputs_before == inputs_after
                 and retained_state_before == retained_state_after,
                 "retained transport identities changed during extraction")
        parent_final = output.parent.lstat()
        root_final = os.stat(output.name, dir_fd=parent_fd, follow_symlinks=False)
        _require(output.parent == output.parent.resolve()
                 and _directory_identity(parent_before) == _directory_identity(parent_final)
                 and _inode_identity(root_final) == root_identity
                 and _private_owned(root_final, directory=True),
                 "output parent or root changed before completion")
        for name, identity in directory_identities.items():
            current = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
            _require(_inode_identity(current) == identity and _private_owned(current, directory=True),
                     "output directory changed before completion")

        return _result(output, inputs_before, output_measurements)
    except BaseException as error:
        for descriptor in child_fds.values():
            try:
                os.close(descriptor)
            except OSError:
                pass
        child_fds.clear()
        cleaned = (_cleanup_output(parent_fd, output.name, root_fd, root_identity,
                                   directory_identities, file_identities) if made_root else True)
        if root_fd is not None:
            try:
                os.close(root_fd)
            except OSError:
                pass
            root_fd = None
        if not cleaned:
            raise origin.OriginError("transport failed; an incomplete owned output may need cleanup") from None
        if isinstance(error, origin.OriginError):
            raise
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        raise origin.OriginError("native transport extraction failed at a closed byte boundary") from None
    finally:
        for descriptor in child_fds.values():
            os.close(descriptor)
        if root_fd is not None:
            os.close(root_fd)
        os.close(parent_fd)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--retained-dir", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--output-dir", type=Path)
    mode.add_argument("--verify-output-dir", type=Path)
    try:
        args = parser.parse_args()
        result = (extract(args.retained_dir, args.output_dir) if args.output_dir is not None
                  else verify_output(args.retained_dir, args.verify_output_dir))
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except origin.OriginError as error:
        print(f"native lane transport rejected: {error}", file=sys.stderr)
        return 1
    except (OSError, ValueError, TypeError, KeyError, zipfile.BadZipFile):
        print("native lane transport rejected at a closed input/output boundary", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
