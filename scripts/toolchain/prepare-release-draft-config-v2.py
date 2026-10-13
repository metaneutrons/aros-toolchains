#!/usr/bin/env python3
"""Prepare an inactive Release Please draft configuration adapter.

The committed release-please-config.json remains the source of package and
version strategy. This script only writes a copy with three root-level action
overrides. It does not calculate versions, access a provider, or create tags.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import selectors
import stat
import subprocess
import sys
import time
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = "release-please-config.json"
MAX_CONFIG_BYTES = 256 * 1024
GIT_TIMEOUT_SECONDS = 15


class PreparationError(Exception):
    """The committed configuration or output destination failed validation."""


class DuplicateKeyError(ValueError):
    """JSON input repeated an object key."""


def fail(message: str) -> None:
    raise PreparationError(message)


def _pairs_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError
        result[key] = value
    return result


def _reject_constant(_: str) -> None:
    raise ValueError


def _contains_package_override(value: Any, keys: set[str]) -> bool:
    if isinstance(value, dict):
        return bool(keys.intersection(value)) or any(
            _contains_package_override(nested, keys) for nested in value.values()
        )
    if isinstance(value, list):
        return any(_contains_package_override(nested, keys) for nested in value)
    return False


def _read_committed_config() -> bytes:
    command = ["git", "show", f"HEAD:{CONFIG_PATH}"]
    try:
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
        )
    except OSError:
        fail("committed Release Please configuration is unavailable")

    output = bytearray()
    selector = selectors.DefaultSelector()
    deadline = time.monotonic() + GIT_TIMEOUT_SECONDS
    try:
        assert process.stdout is not None
        os.set_blocking(process.stdout.fileno(), False)
        selector.register(process.stdout, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                fail("reading committed Release Please configuration timed out")
            if not selector.select(remaining):
                fail("reading committed Release Please configuration timed out")
            chunk = os.read(
                process.stdout.fileno(),
                min(65536, MAX_CONFIG_BYTES + 1 - len(output)),
            )
            if not chunk:
                selector.unregister(process.stdout)
                process.stdout.close()
                continue
            output.extend(chunk)
            if len(output) > MAX_CONFIG_BYTES:
                fail("committed Release Please configuration exceeds the size limit")
        try:
            return_code = process.wait(timeout=max(0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            fail("reading committed Release Please configuration timed out")
        if return_code != 0:
            fail("committed Release Please configuration is unavailable")
        return bytes(output)
    finally:
        selector.close()
        if process.poll() is None:
            process.kill()
        if process.stdout is not None:
            process.stdout.close()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def _parse_config(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_pairs_without_duplicates,
            parse_constant=_reject_constant,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        DuplicateKeyError,
        RecursionError,
        ValueError,
    ):
        fail("committed Release Please configuration is invalid JSON")
    if not isinstance(value, dict):
        fail("committed Release Please configuration must have an object root")

    if value.get("skip-github-release") is not True:
        fail("committed configuration must set skip-github-release to true")

    packages = value.get("packages")
    if not isinstance(packages, dict) or set(packages) != {"."}:
        fail("committed configuration must define only the root package")
    package = packages["."]
    if not isinstance(package, dict):
        fail("root package configuration must be an object")

    override_keys = {"skip-github-release", "draft", "force-tag-creation"}
    if _contains_package_override(package, override_keys):
        fail("package-level release overrides are unsupported")
    if "draft" in value and value["draft"] is not True:
        fail("committed draft setting conflicts with the adapter")
    if "force-tag-creation" in value and value["force-tag-creation"] is not False:
        fail("committed force-tag-creation setting conflicts with the adapter")

    result = dict(value)
    result["packages"] = dict(packages)
    result["skip-github-release"] = False
    result["draft"] = True
    result["force-tag-creation"] = False
    return result


def _open_parent_directory(path: Path) -> tuple[int, str]:
    absolute = Path(os.path.abspath(os.fspath(path)))
    if not absolute.name or absolute.name in {".", ".."}:
        fail("output path must name a file")
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        fail("output parent cannot be checked safely on this platform")

    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        descriptor = os.open(absolute.anchor, directory_flags)
    except OSError:
        fail("output parent directory cannot be opened safely")
    try:
        for component in absolute.parent.parts[1:]:
            next_descriptor = os.open(component, directory_flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor, absolute.name
    except OSError:
        os.close(descriptor)
        fail("output parent contains a linked or invalid directory component")


def _remove_created_file(parent: int, name: str, created: os.stat_result) -> None:
    try:
        current = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (current.st_dev, current.st_ino) == (created.st_dev, created.st_ino):
            os.unlink(name, dir_fd=parent)
    except OSError:
        pass


def _check_output_destination(path: Path) -> None:
    parent, name = _open_parent_directory(path)
    try:
        try:
            os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return
        except OSError:
            fail("output path cannot be inspected safely")
        fail("output already exists")
    finally:
        os.close(parent)


def _write_exclusive(path: Path, content: bytes) -> None:
    parent, name = _open_parent_directory(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    created: os.stat_result | None = None
    success = False
    try:
        try:
            descriptor = os.open(name, flags, 0o600, dir_fd=parent)
        except FileExistsError:
            fail("output already exists")
        except OSError:
            fail("output cannot be created exclusively")

        with os.fdopen(descriptor, "wb") as handle:
            created = os.fstat(handle.fileno())
            if not stat.S_ISREG(created.st_mode) or created.st_nlink != 1:
                fail("new output is not a singly-linked regular file")
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        success = True
    except OSError:
        fail("output could not be written safely")
    finally:
        if created is not None and not success:
            _remove_created_file(parent, name, created)
        os.close(parent)


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        _check_output_destination(args.output)
        candidate = _parse_config(_read_committed_config())
        _write_exclusive(args.output, (canonical_json(candidate) + "\n").encode("utf-8"))
    except PreparationError as error:
        print(f"release draft config preparation failed: {error}", file=sys.stderr)
        raise SystemExit(1) from None
    print("Prepared inactive Release Please draft configuration")


if __name__ == "__main__":
    main()
