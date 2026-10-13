#!/usr/bin/env python3
"""Retain only the two bounded upstream config.log files from an SDK failure."""

from __future__ import annotations

import argparse
import os
import stat
import sys
from pathlib import Path


MAX_LOG_BYTES = 4 * 1024 * 1024
CAPTURES = (
    ("upstream-build", "config.log", "upstream-build-config.log"),
    ("upstream-build", "config", "config.log", "upstream-build-config-subdir-config.log"),
)


class RetentionError(Exception):
    """A requested log could not be safely retained."""


def _open_directory_component(parent_fd: int, name: str) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    return os.open(name, flags, dir_fd=parent_fd)


def _open_operation(path: str) -> int:
    if not os.path.isabs(path) or os.path.normpath(path) != path:
        raise RetentionError("operation directory must be a normalized absolute path")

    directory_fd = os.open("/", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        for component in Path(path).parts[1:]:
            if component in ("", ".", ".."):
                raise RetentionError("operation directory contains a noncanonical component")
            next_fd = _open_directory_component(directory_fd, component)
            os.close(directory_fd)
            directory_fd = next_fd
        return directory_fd
    except Exception:
        os.close(directory_fd)
        raise


def _open_optional_directory(parent_fd: int, name: str) -> int | None:
    try:
        return _open_directory_component(parent_fd, name)
    except FileNotFoundError:
        return None


def _read_optional_log(operation_fd: int, components: tuple[str, ...]) -> bytes | None:
    directory_fd = os.dup(operation_fd)
    try:
        for component in components[:-1]:
            child_fd = _open_optional_directory(directory_fd, component)
            if child_fd is None:
                return None
            os.close(directory_fd)
            directory_fd = child_fd

        try:
            source_fd = os.open(
                components[-1],
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
                dir_fd=directory_fd,
            )
        except FileNotFoundError:
            return None

        try:
            source_status = os.fstat(source_fd)
            if not stat.S_ISREG(source_status.st_mode):
                raise RetentionError(f"source is not a regular file: {'/'.join(components)}")
            if source_status.st_size > MAX_LOG_BYTES:
                raise RetentionError(f"source exceeds the 4 MiB limit: {'/'.join(components)}")

            content = bytearray()
            while len(content) <= MAX_LOG_BYTES:
                chunk = os.read(source_fd, min(65536, MAX_LOG_BYTES + 1 - len(content)))
                if not chunk:
                    break
                content.extend(chunk)
            if len(content) > MAX_LOG_BYTES:
                raise RetentionError(f"source exceeds the 4 MiB limit: {'/'.join(components)}")
            return bytes(content)
        finally:
            os.close(source_fd)
    finally:
        os.close(directory_fd)


def _reports_directory(operation_fd: int) -> int:
    try:
        os.mkdir("reports", mode=0o700, dir_fd=operation_fd)
    except FileExistsError:
        pass
    return _open_directory_component(operation_fd, "reports")


def _retain_one(reports_fd: int, name: str, content: bytes) -> tuple[int, int]:
    try:
        os.stat(name, dir_fd=reports_fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise RetentionError(f"output already exists: reports/{name}")

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    output_fd = os.open(name, flags, 0o600, dir_fd=reports_fd)
    output_status = None
    try:
        output_status = os.fstat(output_fd)
        if not stat.S_ISREG(output_status.st_mode):
            raise RetentionError(f"output is not a regular file: reports/{name}")
        offset = 0
        while offset < len(content):
            written = os.write(output_fd, content[offset:])
            if written <= 0:
                raise RetentionError(f"could not finish writing reports/{name}")
            offset += written
        os.fsync(output_fd)
        return output_status.st_dev, output_status.st_ino
    except Exception:
        try:
            if output_status is not None:
                current = os.stat(name, dir_fd=reports_fd, follow_symlinks=False)
                if (current.st_dev, current.st_ino) == (output_status.st_dev, output_status.st_ino):
                    os.unlink(name, dir_fd=reports_fd)
        except OSError:
            pass
        raise
    finally:
        os.close(output_fd)


def retain(operation_dir: str) -> int:
    operation_fd = _open_operation(operation_dir)
    try:
        captures = []
        for declaration in CAPTURES:
            *source_components, output_name = declaration
            content = _read_optional_log(operation_fd, tuple(source_components))
            if content is not None:
                captures.append((output_name, content))
        if not captures:
            return 0

        reports_fd = _reports_directory(operation_fd)
        created: list[tuple[str, int, int]] = []
        try:
            for output_name, content in captures:
                device, inode = _retain_one(reports_fd, output_name, content)
                created.append((output_name, device, inode))
        except Exception:
            for output_name, device, inode in reversed(created):
                try:
                    current = os.stat(output_name, dir_fd=reports_fd, follow_symlinks=False)
                    if (current.st_dev, current.st_ino) == (device, inode):
                        os.unlink(output_name, dir_fd=reports_fd)
                except OSError:
                    pass
            raise
        finally:
            os.close(reports_fd)
        return 0
    finally:
        os.close(operation_fd)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--operation-dir", required=True)
    args = parser.parse_args()
    try:
        return retain(args.operation_dir)
    except (OSError, RetentionError) as error:
        print(f"retain-sdk-config-logs: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
