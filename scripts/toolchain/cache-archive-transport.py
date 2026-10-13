#!/usr/bin/env python3
"""Restore a byte-only, permission-preserving cache archive into a fresh tree.

This helper performs local transport checks only. It does not authenticate an
archive, inspect cache semantics, or contact a network service.
"""

from __future__ import annotations

import argparse
import ctypes
import gzip
import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
import re
import stat
import sys
import tarfile
from typing import BinaryIO


MAX_ARCHIVE_BYTES = 4 * 1024**3
MAX_MEMBERS = 200_000
MAX_TOTAL_FILE_BYTES = 8 * 1024**3
MAX_FILE_BYTES = 2 * 1024**3
MAX_PATH_BYTES = 4096
MAX_COMPONENT_BYTES = 255
MAX_EXTENSION_BYTES = 64 * 1024
MAX_DECOMPRESSED_TAR_BYTES = 10 * 1024**3
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")

OPEN_NOFOLLOW = getattr(os, "O_NOFOLLOW", None)
OPEN_DIRECTORY = getattr(os, "O_DIRECTORY", None)
DIR_FLAGS = os.O_RDONLY | (OPEN_DIRECTORY or 0) | (OPEN_NOFOLLOW or 0) | getattr(os, "O_CLOEXEC", 0)
FILE_FLAGS = (os.O_RDONLY | (OPEN_NOFOLLOW or 0) | getattr(os, "O_CLOEXEC", 0)
              | getattr(os, "O_NONBLOCK", 0))
OUTPUT_FLAGS = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | (OPEN_NOFOLLOW or 0)
                | getattr(os, "O_CLOEXEC", 0))


class TransportError(Exception):
    """A bounded local transport operation rejected its input."""


@dataclass(frozen=True)
class ArchiveMember:
    path: str
    kind: str
    mode: int
    size: int


@dataclass(frozen=True)
class ArchivePlan:
    members: tuple[ArchiveMember, ...]
    directories: tuple[tuple[str, int], ...]


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise TransportError(message)


def _stat_identity(entry: os.stat_result) -> tuple[int, int, int, int, int, int, int, int]:
    return (entry.st_dev, entry.st_ino, entry.st_size, entry.st_mtime_ns,
            entry.st_ctime_ns, entry.st_uid, stat.S_IMODE(entry.st_mode), entry.st_nlink)


def _open_directory_chain(path: Path, label: str) -> int:
    _require(type(OPEN_NOFOLLOW) is int and OPEN_NOFOLLOW != 0
             and type(OPEN_DIRECTORY) is int and OPEN_DIRECTORY != 0,
             "this platform lacks required no-follow directory open flags")
    _require(path.is_absolute() and ".." not in path.parts,
             f"{label} must be an absolute normalized directory")
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        raise TransportError(f"{label} does not exist as a canonical directory") from None
    _require(resolved == path, f"{label} must have no linked ancestry")

    current_fd = os.open(os.sep, DIR_FLAGS)
    try:
        for component in path.parts[1:]:
            next_fd = os.open(component, DIR_FLAGS, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        _require(stat.S_ISDIR(os.fstat(current_fd).st_mode), f"{label} is not a directory")
        return current_fd
    except Exception:
        os.close(current_fd)
        raise


def _archive_path_and_open(path_value: str) -> tuple[Path, int, int, str, os.stat_result]:
    try:
        raw_path = Path(path_value)
    except (TypeError, ValueError):
        raise TransportError("archive path is invalid") from None
    _require(".." not in raw_path.parts, "archive path must be normalized")
    if raw_path.is_absolute():
        archive_path = raw_path
    else:
        archive_path = Path.cwd().resolve() / raw_path
    try:
        archive_path = Path(os.path.abspath(archive_path))
    except (OSError, RuntimeError, ValueError):
        raise TransportError("archive path is invalid") from None
    _require(archive_path.name not in ("", ".", ".."), "archive path is invalid")

    parent_fd = _open_directory_chain(archive_path.parent, "archive parent")
    try:
        fd = os.open(archive_path.name, FILE_FLAGS, dir_fd=parent_fd)
    except OSError:
        os.close(parent_fd)
        raise TransportError("archive must be an accessible ordinary file") from None
    try:
        entry = os.fstat(fd)
        named = os.stat(archive_path.name, dir_fd=parent_fd, follow_symlinks=False)
        _require(stat.S_ISREG(entry.st_mode) and entry.st_nlink == 1,
                 "archive must be a singly linked regular file")
        _require(_stat_identity(entry) == _stat_identity(named),
                 "archive changed while it was opened")
        _require(0 < entry.st_size <= MAX_ARCHIVE_BYTES,
                 "archive exceeds its compressed byte limit")
        return archive_path, parent_fd, fd, archive_path.name, entry
    except Exception:
        os.close(fd)
        os.close(parent_fd)
        raise


def _output_location(output_value: str) -> tuple[Path, Path, int, str]:
    try:
        output = Path(output_value)
    except (TypeError, ValueError):
        raise TransportError("output path is invalid") from None
    _require(output.is_absolute() and ".." not in output.parts
             and output.name not in ("", ".", ".."),
             "output must be an absolute normalized fresh path")
    parent = output.parent
    parent_fd = _open_directory_chain(parent, "output parent")
    try:
        try:
            os.stat(output.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise TransportError("output directory must not already exist")
        return output, parent, parent_fd, output.name
    except Exception:
        os.close(parent_fd)
        raise


def _fd_hash(fd: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    entry = os.fstat(fd)
    while offset < entry.st_size:
        try:
            chunk = os.pread(fd, min(1024 * 1024, entry.st_size - offset), offset)
        except OSError:
            raise TransportError("archive could not be measured") from None
        _require(bool(chunk), "archive ended while it was measured")
        digest.update(chunk)
        offset += len(chunk)
    try:
        extra = os.pread(fd, 1, offset)
    except OSError:
        raise TransportError("archive could not be measured") from None
    _require(not extra, "archive grew while it was measured")
    return digest.hexdigest()


def _check_archive_stable(fd: int, parent_fd: int, name: str,
                          identity: os.stat_result) -> None:
    try:
        opened = os.fstat(fd)
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError:
        raise TransportError("archive changed during transport") from None
    _require(stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1
             and _stat_identity(opened) == _stat_identity(identity)
             and _stat_identity(named) == _stat_identity(identity),
             "archive changed during transport")


class _LimitedReader:
    """Limit the decompressed tar byte stream without buffering the archive."""

    def __init__(self, reader: BinaryIO, limit: int):
        self.reader = reader
        self.limit = limit
        self.total = 0

    def read(self, size: int = -1) -> bytes:
        _require(type(size) is int and size >= 0,
                 "archive parser requested an unbounded read")
        if size == 0:
            return b""
        remaining = self.limit - self.total
        if remaining <= 0:
            probe = self.reader.read(1)
            _require(not probe, "expanded tar stream exceeds its byte limit")
            return b""
        chunk = self.reader.read(min(size, remaining))
        self.total += len(chunk)
        return chunk


class _BoundedTarInfo(tarfile.TarInfo):
    """Reject oversized extension records before tarfile reads their bodies."""

    def _proc_member(self, archive: tarfile.TarFile) -> tarfile.TarInfo | None:
        extension_types = (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.SOLARIS_XHDTYPE,
                           tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK)
        if self.type in extension_types:
            _require(0 <= self.size <= MAX_EXTENSION_BYTES,
                     "archive extension record exceeds its byte limit")
        return super()._proc_member(archive)

    def _proc_gnusparse_01(self, next: tarfile.TarInfo, pax_headers: dict) -> None:
        raise TransportError("archive sparse-file encoding is not permitted")

    def _proc_gnusparse_00(self, next: tarfile.TarInfo, raw_headers: list) -> None:
        raise TransportError("archive sparse-file encoding is not permitted")

    def _proc_gnusparse_10(self, next: tarfile.TarInfo, pax_headers: dict,
                           archive: tarfile.TarFile) -> None:
        raise TransportError("archive sparse-file encoding is not permitted")


def _normalized_member_path(name: str, *, is_directory: bool) -> str:
    _require(isinstance(name, str) and "\x00" not in name and "\\" not in name,
             "archive member path is unsafe")
    try:
        raw_size = len(name.encode("utf-8", "strict"))
    except UnicodeError:
        raise TransportError("archive member path is not valid UTF-8") from None
    _require(raw_size <= MAX_PATH_BYTES, "archive member path exceeds its byte limit")
    _require(not name.startswith("/") and not re_drive_path(name),
             "archive member path must be relative")

    normalized = name
    if normalized in (".", "./"):
        _require(is_directory, "archive root entry must be a directory")
        return ""
    if normalized.startswith("./"):
        normalized = normalized[2:]
    if is_directory and normalized.endswith("/"):
        normalized = normalized[:-1]
    _require(bool(normalized) and not normalized.endswith("/"),
             "archive member path is empty or not normalized")
    parts = normalized.split("/")
    _require(all(part not in ("", ".", "..") for part in parts),
             "archive member path contains an unsafe component")
    for part in parts:
        try:
            component_size = len(part.encode("utf-8", "strict"))
        except UnicodeError:
            raise TransportError("archive member path is not valid UTF-8") from None
        _require(component_size <= MAX_COMPONENT_BYTES,
                 "archive member path component exceeds the filesystem limit")
    _require(len(normalized.encode("utf-8")) <= MAX_PATH_BYTES,
             "archive member path exceeds its byte limit")
    return normalized


def re_drive_path(value: str) -> bool:
    return len(value) >= 2 and value[0].isascii() and value[0].isalpha() and value[1] == ":"


def _member_record(member: tarfile.TarInfo) -> ArchiveMember:
    if member.type in (tarfile.REGTYPE, tarfile.AREGTYPE):
        kind = "file"
        is_directory = False
    elif member.type == tarfile.DIRTYPE:
        kind = "directory"
        is_directory = True
    else:
        raise TransportError("archive contains a non-file, non-directory member")

    mode = member.mode
    _require(type(mode) is int and mode >= 0 and mode & ~0o777 == 0,
             "archive member contains special or unsupported permission bits")
    size = member.size
    _require(type(size) is int and size >= 0, "archive member size is invalid")
    if kind == "file":
        _require(size <= MAX_FILE_BYTES, "archive member exceeds its file byte limit")
    else:
        _require(size == 0, "archive directory member must have no payload")
    return ArchiveMember(_normalized_member_path(member.name, is_directory=is_directory),
                         kind, mode, size)


def _plan_members(members: tuple[ArchiveMember, ...]) -> ArchivePlan:
    _require(len(members) <= MAX_MEMBERS, "archive exceeds its member count limit")
    by_path: dict[str, ArchiveMember] = {}
    total_file_bytes = 0
    root_mode: int | None = None
    for member in members:
        if member.path == "":
            _require(member.kind == "directory" and root_mode is None,
                     "archive contains an invalid or duplicate root entry")
            root_mode = member.mode
            continue
        _require(member.path not in by_path,
                 "archive contains duplicate or aliased member paths")
        by_path[member.path] = member
        if member.kind == "file":
            total_file_bytes += member.size
            _require(total_file_bytes <= MAX_TOTAL_FILE_BYTES,
                     "archive exceeds its total file byte limit")

    for path, member in by_path.items():
        components = path.split("/")
        for count in range(1, len(components)):
            ancestor = "/".join(components[:count])
            parent_member = by_path.get(ancestor)
            _require(parent_member is None or parent_member.kind == "directory",
                     "archive contains a file and a descendant at the same path")

    directory_modes: dict[str, int] = {}
    if root_mode is not None:
        directory_modes[""] = root_mode
    for path, member in by_path.items():
        parts = path.split("/")
        for count in range(1, len(parts)):
            directory_modes.setdefault("/".join(parts[:count]), 0o755)
        if member.kind == "directory":
            directory_modes[path] = member.mode
    if "" not in directory_modes:
        directory_modes[""] = 0o700
    return ArchivePlan(members, tuple(sorted(directory_modes.items(),
                                             key=lambda entry: (entry[0].count("/"), entry[0]))))


def _drain_tar_tail(archive: tarfile.TarFile) -> None:
    stream = archive.fileobj
    _require(stream.tell() >= archive.offset + tarfile.BLOCKSIZE,
             "archive has no tar end marker")
    while True:
        tail = stream.read(64 * 1024)
        if not tail:
            return
        _require(not any(tail), "archive contains data after its tar end marker")


def _read_tar_members(fd: int, *, materialize_stage_fd: int | None = None,
                      expected: ArchivePlan | None = None,
                      created_files: list[str] | None = None) -> tuple[ArchiveMember, ...]:
    duplicate_fd = os.dup(fd)
    raw: BinaryIO | None = None
    compressed: gzip.GzipFile | None = None
    try:
        os.lseek(duplicate_fd, 0, os.SEEK_SET)
        raw = os.fdopen(duplicate_fd, "rb", closefd=True)
        compressed = gzip.GzipFile(fileobj=raw, mode="rb")
        bounded = _LimitedReader(compressed, MAX_DECOMPRESSED_TAR_BYTES)
        parsed: list[ArchiveMember] = []
        total_file_bytes = 0
        with tarfile.open(fileobj=bounded, mode="r|", bufsize=64 * 1024,
                          tarinfo=_BoundedTarInfo) as archive:
            for tar_member in archive:
                record = _member_record(tar_member)
                if expected is None:
                    _require(len(parsed) < MAX_MEMBERS,
                             "archive exceeds its member count limit")
                    if record.kind == "file":
                        total_file_bytes += record.size
                        _require(total_file_bytes <= MAX_TOTAL_FILE_BYTES,
                                 "archive exceeds its total file byte limit")
                else:
                    index = len(parsed)
                    _require(index < len(expected.members)
                             and record == expected.members[index],
                             "archive changed between validation and materialization")
                    if record.kind == "file":
                        _write_member(archive, tar_member, record, materialize_stage_fd,
                                      created_files)
                parsed.append(record)
            _drain_tar_tail(archive)
        if expected is not None:
            _require(tuple(parsed) == expected.members,
                     "archive changed between validation and materialization")
        return tuple(parsed)
    except TransportError:
        raise
    except Exception:
        raise TransportError("archive is not a complete valid tar.gz stream") from None
    finally:
        if compressed is not None:
            try:
                compressed.close()
            except Exception:
                pass
        if raw is not None:
            raw.close()
        elif compressed is None:
            try:
                os.close(duplicate_fd)
            except OSError:
                pass


def _open_relative_directory(root_fd: int, relative: str) -> int:
    current_fd = os.dup(root_fd)
    if not relative:
        return current_fd
    try:
        for component in relative.split("/"):
            next_fd = os.open(component, DIR_FLAGS, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except Exception:
        os.close(current_fd)
        raise


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        try:
            written = os.write(fd, view)
        except OSError:
            raise TransportError("archive member could not be materialized") from None
        _require(written > 0, "archive member could not be materialized")
        view = view[written:]


def _write_member(archive: tarfile.TarFile, tar_member: tarfile.TarInfo,
                  record: ArchiveMember, stage_fd: int | None,
                  created_files: list[str] | None) -> None:
    _require(stage_fd is not None and created_files is not None,
             "internal materialization state is missing")
    components = record.path.split("/")
    parent_fd = _open_relative_directory(stage_fd, "/".join(components[:-1]))
    file_fd = -1
    try:
        file_fd = os.open(components[-1], OUTPUT_FLAGS, 0o600, dir_fd=parent_fd)
        created_files.append(record.path)
    except OSError:
        os.close(parent_fd)
        raise TransportError("archive member could not be materialized") from None
    os.close(parent_fd)

    source = archive.extractfile(tar_member)
    try:
        _require(source is not None, "archive file payload is unavailable")
        remaining = record.size
        while remaining:
            chunk = source.read(min(1024 * 1024, remaining))
            _require(bool(chunk), "archive file payload is truncated")
            _write_all(file_fd, chunk)
            remaining -= len(chunk)
        os.fchmod(file_fd, record.mode)
    except OSError:
        raise TransportError("archive member could not be materialized") from None
    finally:
        if source is not None:
            source.close()
        os.close(file_fd)


def _create_stage(parent_fd: int, output_name: str,
                  archive_name: str) -> tuple[str, int, os.stat_result]:
    import secrets

    for _ in range(64):
        name = f".cache-archive-transport-{secrets.token_hex(12)}"
        if name in (output_name, archive_name):
            continue
        try:
            os.mkdir(name, mode=0o700, dir_fd=parent_fd)
        except FileExistsError:
            continue
        except OSError:
            raise TransportError("private output staging directory could not be created") from None
        try:
            fd = os.open(name, DIR_FLAGS, dir_fd=parent_fd)
            entry = os.fstat(fd)
            _require(stat.S_ISDIR(entry.st_mode) and entry.st_uid == os.geteuid()
                     and stat.S_IMODE(entry.st_mode) == 0o700,
                     "private output staging directory has unexpected ownership or mode")
            return name, fd, entry
        except Exception:
            try:
                os.rmdir(name, dir_fd=parent_fd)
            except OSError:
                pass
            raise
    raise TransportError("private output staging directory could not be allocated")


def _stage_matches(parent_fd: int, name: str, identity: os.stat_result) -> bool:
    try:
        entry = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError:
        return False
    return (stat.S_ISDIR(entry.st_mode) and entry.st_dev == identity.st_dev
            and entry.st_ino == identity.st_ino and entry.st_uid == identity.st_uid)


def _cleanup_stage(parent_fd: int, name: str, stage_fd: int,
                   identity: os.stat_result, created_files: list[str],
                   created_directories: set[str]) -> None:
    if not _stage_matches(parent_fd, name, identity):
        return
    try:
        os.fchmod(stage_fd, 0o700)
    except OSError:
        return

    for relative in sorted(created_directories, key=lambda value: (value.count("/"), value)):
        directory_fd = -1
        try:
            directory_fd = _open_relative_directory(stage_fd, relative)
            os.fchmod(directory_fd, 0o700)
        except OSError:
            # A later directory removal will fail closed if the mode cannot be reset.
            pass
        finally:
            if directory_fd >= 0:
                os.close(directory_fd)
    for relative in reversed(created_files):
        try:
            parent = "/".join(relative.split("/")[:-1])
            leaf = relative.split("/")[-1]
            parent_fd_for_file = _open_relative_directory(stage_fd, parent)
            try:
                os.unlink(leaf, dir_fd=parent_fd_for_file)
            finally:
                os.close(parent_fd_for_file)
        except OSError:
            pass
    for relative in sorted(created_directories, key=lambda value: (-value.count("/"), value),
                           reverse=False):
        try:
            parent = "/".join(relative.split("/")[:-1])
            leaf = relative.split("/")[-1]
            parent_fd_for_dir = _open_relative_directory(stage_fd, parent)
            try:
                os.rmdir(leaf, dir_fd=parent_fd_for_dir)
            finally:
                os.close(parent_fd_for_dir)
        except OSError:
            pass
    try:
        os.rmdir(name, dir_fd=parent_fd)
    except OSError:
        pass


def _rename_noreplace(parent_fd: int, source: str, destination: str) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform.startswith("linux"):
        function = getattr(libc, "renameat2", None)
        flags = 1  # RENAME_NOREPLACE
    elif sys.platform == "darwin":
        function = getattr(libc, "renameatx_np", None)
        flags = 4  # RENAME_EXCL
    else:
        function = None
        flags = 0
    _require(function is not None,
             "atomic no-replace directory publication is unavailable on this platform")
    function.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                         ctypes.c_char_p, ctypes.c_uint)
    function.restype = ctypes.c_int
    result = function(parent_fd, os.fsencode(source), parent_fd,
                      os.fsencode(destination), flags)
    if result != 0:
        error_number = ctypes.get_errno()
        if error_number in (getattr(os, "EEXIST", 17), 17):
            raise TransportError("output directory appeared before publication")
        raise TransportError("validated output could not be atomically published")


def _materialize(fd: int, plan: ArchivePlan, stage_fd: int,
                 created_files: list[str], created_directories: set[str]) -> None:
    requested_directories = dict(plan.directories)
    planned_directories = (path for path in requested_directories if path)
    for relative in sorted(planned_directories, key=lambda value: (value.count("/"), value)):
        components = relative.split("/")
        parent_fd_for_dir = _open_relative_directory(stage_fd, "/".join(components[:-1]))
        try:
            os.mkdir(components[-1], mode=0o700, dir_fd=parent_fd_for_dir)
            created_directories.add(relative)
        except OSError:
            os.close(parent_fd_for_dir)
            raise TransportError("archive directories could not be materialized") from None
        os.close(parent_fd_for_dir)

    _read_tar_members(fd, materialize_stage_fd=stage_fd, expected=plan,
                      created_files=created_files)

    for relative, mode in sorted(
            requested_directories.items(),
            key=lambda entry: (-entry[0].count("/"), entry[0]), reverse=False):
        if not relative:
            continue
        directory_fd = -1
        try:
            directory_fd = _open_relative_directory(stage_fd, relative)
            os.fchmod(directory_fd, mode)
        except OSError:
            raise TransportError("archive directory mode could not be restored") from None
        finally:
            if directory_fd >= 0:
                os.close(directory_fd)


def unpack_archive(archive_value: str, expected_sha256: str, output_value: str) -> None:
    _require(isinstance(expected_sha256, str) and bool(HASH_RE.fullmatch(expected_sha256))
             and expected_sha256 != "0" * 64,
             "expected archive SHA-256 must be a nonzero lowercase hexadecimal digest")
    archive_path, archive_parent_fd, archive_fd, archive_name, archive_identity = \
        _archive_path_and_open(archive_value)
    output_parent_fd = -1
    stage_fd = -1
    stage_name = ""
    stage_identity: os.stat_result | None = None
    created_files: list[str] = []
    created_directories: set[str] = set()
    try:
        output_path, output_parent, output_parent_fd, output_name = _output_location(output_value)
        _require(archive_path != output_path and archive_path not in output_path.parents
                 and output_path not in archive_path.parents,
                 "archive and output paths must not overlap")
        _check_archive_stable(archive_fd, archive_parent_fd, archive_name, archive_identity)
        _require(_fd_hash(archive_fd) == expected_sha256,
                 "archive SHA-256 does not match the supplied digest")
        _check_archive_stable(archive_fd, archive_parent_fd, archive_name, archive_identity)

        members = _read_tar_members(archive_fd)
        plan = _plan_members(members)
        _check_archive_stable(archive_fd, archive_parent_fd, archive_name, archive_identity)
        _require(_fd_hash(archive_fd) == expected_sha256,
                 "archive changed after its full parse")

        stage_name, stage_fd, stage_identity = _create_stage(
            output_parent_fd, output_name, archive_name)
        _materialize(archive_fd, plan, stage_fd, created_files, created_directories)
        _check_archive_stable(archive_fd, archive_parent_fd, archive_name, archive_identity)
        _require(_fd_hash(archive_fd) == expected_sha256,
                 "archive changed during materialization")
        _check_archive_stable(archive_fd, archive_parent_fd, archive_name, archive_identity)
        try:
            parent_now = output_parent
            _require(parent_now.resolve(strict=True) == parent_now,
                     "output parent changed before publication")
            current_parent = os.stat(parent_now, follow_symlinks=False)
            _require((current_parent.st_dev, current_parent.st_ino)
                     == (os.fstat(output_parent_fd).st_dev, os.fstat(output_parent_fd).st_ino),
                     "output parent changed before publication")
        except OSError:
            raise TransportError("output parent changed before publication") from None
        _require(_stage_matches(output_parent_fd, stage_name, stage_identity),
                 "private output staging directory changed before publication")
        try:
            os.fchmod(stage_fd, dict(plan.directories)[""])
        except OSError:
            raise TransportError("published root directory mode could not be restored") from None
        _require(_stage_matches(output_parent_fd, stage_name, stage_identity),
                 "private output staging directory changed before publication")
        _rename_noreplace(output_parent_fd, stage_name, output_name)
    except BaseException:
        if stage_name and stage_fd >= 0 and stage_identity is not None and output_parent_fd >= 0:
            _cleanup_stage(output_parent_fd, stage_name, stage_fd, stage_identity,
                           created_files, created_directories)
        raise
    finally:
        if stage_fd >= 0:
            os.close(stage_fd)
        if output_parent_fd >= 0:
            os.close(output_parent_fd)
        os.close(archive_fd)
        os.close(archive_parent_fd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)

    class UniqueOption(argparse.Action):
        def __call__(self, parser, namespace, values, option_string=None):
            if getattr(namespace, self.dest, None) is not None:
                parser.error(f"{option_string} may be specified only once")
            setattr(namespace, self.dest, values)

    parser.add_argument("--archive", required=True, action=UniqueOption)
    parser.add_argument("--archive-sha256", required=True, action=UniqueOption)
    parser.add_argument("--output-dir", required=True, action=UniqueOption)
    args = parser.parse_args(argv)
    try:
        unpack_archive(args.archive, args.archive_sha256, args.output_dir)
    except TransportError as error:
        print(f"cache archive transport rejected: {error}", file=sys.stderr)
        return 2
    except (OSError, ValueError, RuntimeError):
        print("cache archive transport rejected: local file operation failed", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
