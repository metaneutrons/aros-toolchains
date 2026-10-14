#!/usr/bin/env python3
"""Check the bounded V2 producer CLI interface of an independently selected runtime.

This preflight establishes only that the exact executable selected by SHA-256
reports the expected version and exposes the CLI options used by the V2
workflow. Runtime publication authenticity and producer semantics are separate
checks performed by their existing callers.
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
import tempfile
from typing import Any


HEX64 = re.compile(r"[0-9a-f]{64}\Z")
SEMVER = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\Z"
)
MAX_EXECUTABLE_BYTES = 1024 * 1024 * 1024
MAX_CHILD_OUTPUT_BYTES = 1024 * 1024
MAX_RECEIPT_BYTES = 64 * 1024
COMMAND_TIMEOUT_SECONDS = 5.0
FILE_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
OUTPUT_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
DIRECTORY_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) \
    | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)


class PreflightError(ValueError):
    """The selected runtime did not pass the bounded interface check."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise PreflightError(message)


def _interface(command: tuple[str, ...], *options: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    return command, tuple(sorted(set(options)))


# This is the declared critical native/V2 interface set, not a claim about
# every cache command exposed by the executable. Selectors and flags come from
# current preparation, native build/package, release assembly, full-readback,
# and qualification callers.
INTERFACES = (
    _interface(
        ("toolchain", "producer", "recipe"),
        "source-dir", "producer-dir", "tools-dir", "source-lock", "profiles", "output", "format",
    ),
    _interface(
        ("toolchain", "producer", "materialize-engine-free-source"),
        "source-dir", "source-commit", "source-tree", "recipe", "output-dir", "format",
    ),
    _interface(
        ("toolchain", "producer", "compare"),
        "left", "right", "output", "format",
    ),
    _interface(
        ("toolchain", "producer", "compatibility-host-tools"),
        "host",
    ),
    _interface(
        ("sdk", "verify-source"),
        "identity", "identity-sha256", "source-dir", "materialized-source-dir", "source-preset",
    ),
    _interface(
        ("sdk", "build"),
        "identity", "identity-sha256", "source-dir", "materialized-source-dir", "source-preset",
        "recipe", "source-lock", "profiles", "preset", "release-id", "host",
        "build-environment", "package-dir", "first-root", "second-root", "engine-work-dir",
        "helpers-dir", "cmake-program", "ninja-program", "upstream-source-dir",
        "upstream-build-dir", "python-cache-dir", "ports-lock", "ports-cache-dir",
        "ports-sources-dir", "python-environment-dir", "host-tools-dir", "host-tool",
        "cmake-build-dir", "c-fixture", "cxx-fixture", "standalone-output-dir", "reports-dir",
        "jobs", "timeout-seconds", "generation-record", "output-dir", "sdk-forbidden-prefix",
        "evidence-dir", "format",
    ),
    _interface(
        ("toolchain", "producer", "release-plan"),
        "directory", "inputs-sha256", "format",
    ),
    _interface(
        ("toolchain", "build"),
        "preset", "recipe", "source-dir", "producer-dir", "tools-dir", "work-dir",
        "output-dir", "cache-dir", "compiler-cache", "jobs", "timeout-seconds", "release-id", "format",
    ),
    _interface(
        ("toolchain", "producer", "environment"),
        "host", "output", "format",
    ),
    _interface(
        ("toolchain", "producer", "package"),
        "recipe", "source-lock", "profiles", "preset", "release-id", "host",
        "build-environment", "package-format", "forbidden-prefix", "build-result",
        "build-result-sha256", "build-work-dir", "input-dir", "output-dir", "format",
    ),
    _interface(
        ("toolchain", "producer", "verify-package"),
        "recipe", "source-lock", "profiles", "preset", "release-id", "host",
        "build-environment", "package-format", "input-dir", "forbidden-prefix",
        "package-measurement", "package-measurement-sha256",
        "executor-contract-sha256", "executor-binary-sha256", "format",
    ),
    _interface(
        ("sdk", "verify-package"),
        "identity", "identity-sha256", "tree-sha256", "package-dir", "archive-sha256",
        "archive-size", "forbidden-prefix",
    ),
    _interface(
        ("sdk", "sbom"),
        "identity", "identity-sha256", "tree-sha256", "package-dir", "archive-sha256",
        "archive-size", "forbidden-prefix", "output",
    ),
    _interface(
        ("toolchain", "producer", "index"),
        "directory", "release-id", "base-url", "release-format", "lane-inputs",
        "subject-manifest", "subject-manifest-sha256", "forbidden-prefix", "stage", "format",
    ),
    _interface(
        ("toolchain", "producer", "record-qualification"),
        "release-format", "forbidden-prefix", "release-dir", "inputs-sha256", "index-sha256",
        "selection", "selection-sha256", "subject-manifest", "subject-manifest-sha256",
        "source-repository", "source-workflow", "source-run-id", "source-run-attempt",
        "source-tag", "source-tag-object", "source-tag-commit", "attestation-repository",
        "attestation-workflow", "attestation-signer", "created-at", "expires-at", "output", "format",
    ),
    _interface(
        ("toolchain", "producer", "verify-qualification"),
        "forbidden-prefix", "directory", "release-id", "base-url", "inputs-sha256",
        "index-sha256", "selection", "selection-sha256", "subject-manifest",
        "subject-manifest-sha256", "qualification-evidence", "qualification-sha256",
        "policy", "policy-sha256", "format",
    ),
    _interface(
        ("toolchain", "producer", "verify-release-evidence"),
        "directory", "release-id", "base-url", "inputs-sha256", "index-sha256",
        "selection", "selection-sha256", "subject-manifest", "subject-manifest-sha256",
        "forbidden-prefix", "format",
    ),
)


def _normalized_path(raw: object, label: str) -> Path:
    _require(
        isinstance(raw, str) and 0 < len(raw.encode("utf-8")) <= 4096
        and "\n" not in raw and "\r" not in raw and "\0" not in raw,
        f"{label} path is not bounded",
    )
    _require(os.path.isabs(raw) and os.path.normpath(raw) == raw,
             f"{label} path must be absolute and normalized")
    path = Path(raw)
    _require(str(path) == raw and ".." not in path.parts,
             f"{label} path must not contain traversal or noncanonical components")
    return path


def _check_path_components(path: Path, label: str, *, must_exist: bool) -> None:
    _require(path.is_absolute() and ".." not in path.parts,
             f"{label} path must be absolute and normalized")
    try:
        resolved = path.resolve(strict=must_exist)
    except OSError as error:
        raise PreflightError(f"{label} path is unavailable") from error
    _require(resolved == path, f"{label} path has a linked or noncanonical component")
    if must_exist:
        for component in (path, *path.parents):
            try:
                metadata = component.lstat()
            except OSError as error:
                raise PreflightError(f"{label} path is unavailable") from error
            _require(not stat.S_ISLNK(metadata.st_mode),
                     f"{label} path has a linked component")


def _fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_nlink,
        metadata.st_uid, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns,
    )


def _hash_descriptor(descriptor: int, limit: int) -> tuple[str, os.stat_result]:
    try:
        before = os.fstat(descriptor)
    except OSError as error:
        raise PreflightError("selected executable descriptor is unavailable") from error
    _require(
        stat.S_ISREG(before.st_mode) and before.st_nlink == 1
        and 0 < before.st_size <= limit,
        "selected executable is not a bounded, singly linked regular file",
    )
    digest = hashlib.sha256()
    offset = 0
    while offset < before.st_size:
        try:
            block = os.pread(descriptor, min(1024 * 1024, before.st_size - offset), offset)
        except OSError as error:
            raise PreflightError("selected executable could not be measured") from error
        _require(bool(block), "selected executable changed while being measured")
        digest.update(block)
        offset += len(block)
        _require(offset <= limit, "selected executable exceeds its size limit")
    try:
        after = os.fstat(descriptor)
    except OSError as error:
        raise PreflightError("selected executable descriptor is unavailable") from error
    _require(_fingerprint(before) == _fingerprint(after) and offset == after.st_size,
             "selected executable changed while being measured")
    return digest.hexdigest(), after


def _descriptor_exec_path(descriptor: int, identity: tuple[int, ...]) -> str:
    for template in ("/proc/self/fd/{}", "/dev/fd/{}"):
        candidate = template.format(descriptor)
        try:
            metadata = os.stat(candidate)
        except OSError:
            continue
        if _fingerprint(metadata) == identity:
            return candidate
    raise PreflightError("platform does not expose the held executable descriptor for execution")


class HeldExecutable:
    def __init__(self, path: Path, expected_sha256: str):
        _check_path_components(path, "selected executable", must_exist=True)
        try:
            named = path.lstat()
        except OSError as error:
            raise PreflightError("selected executable is unavailable") from error
        _require(
            stat.S_ISREG(named.st_mode) and named.st_nlink == 1
            and bool(named.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)),
            "selected executable is not a singly linked executable regular file",
        )
        try:
            descriptor = os.open(path, FILE_FLAGS | getattr(os, "O_NONBLOCK", 0))
        except OSError as error:
            raise PreflightError("selected executable could not be opened without following links") from error
        try:
            opened = os.fstat(descriptor)
            _require(_fingerprint(named) == _fingerprint(opened),
                     "selected executable changed while being opened")
            measured_sha, measured_stat = _hash_descriptor(descriptor, MAX_EXECUTABLE_BYTES)
            _require(_fingerprint(opened) == _fingerprint(measured_stat),
                     "selected executable changed while being measured")
            _require(measured_sha == expected_sha256,
                     "selected executable bytes differ from the independent SHA-256 selector")
            self.path = path
            self.descriptor = descriptor
            self.sha256 = expected_sha256
            self.identity = _fingerprint(measured_stat)
            self.snapshot_dir: tempfile.TemporaryDirectory[str] | None = None
            if sys.platform == "darwin":
                self.exec_path = self._make_private_snapshot()
                self.execution_binding = "sha256-identical-private-temporary-copy"
            else:
                self.exec_path = _descriptor_exec_path(descriptor, self.identity)
                self.execution_binding = "held-file-descriptor"
        except BaseException:
            os.close(descriptor)
            snapshot_dir = getattr(self, "snapshot_dir", None)
            if snapshot_dir is not None:
                snapshot_dir.cleanup()
            raise

    def _make_private_snapshot(self) -> str:
        """Use a measured private copy where Darwin forbids exec via /dev/fd."""
        self.snapshot_dir = tempfile.TemporaryDirectory(prefix="aros-runtime-interface-")
        root = Path(self.snapshot_dir.name).resolve(strict=True)
        _check_path_components(root, "private executable snapshot directory", must_exist=True)
        root_metadata = root.lstat()
        _require(
            stat.S_ISDIR(root_metadata.st_mode) and root_metadata.st_uid == os.geteuid()
            and not (stat.S_IMODE(root_metadata.st_mode) & 0o077),
            "private executable snapshot directory is not an owned private directory",
        )
        snapshot = root / "aros"
        try:
            target_fd = os.open(snapshot, OUTPUT_FLAGS, 0o700)
        except OSError as error:
            raise PreflightError("private executable snapshot could not be created") from error
        digest = hashlib.sha256()
        offset = 0
        try:
            target_before = os.fstat(target_fd)
            _require(stat.S_ISREG(target_before.st_mode) and target_before.st_nlink == 1,
                     "private executable snapshot is not a singly linked regular file")
            while offset < self.identity[5]:
                try:
                    block = os.pread(self.descriptor, min(1024 * 1024, self.identity[5] - offset), offset)
                except OSError as error:
                    raise PreflightError("selected executable could not be copied from its held descriptor") from error
                _require(bool(block), "selected executable changed while creating its private snapshot")
                digest.update(block)
                view = memoryview(block)
                while view:
                    try:
                        written = os.write(target_fd, view)
                    except OSError as error:
                        raise PreflightError("private executable snapshot write failed") from error
                    _require(written > 0, "private executable snapshot write was incomplete")
                    view = view[written:]
                offset += len(block)
            os.fchmod(target_fd, 0o500)
            os.fsync(target_fd)
            target_after = os.fstat(target_fd)
            source_after = os.fstat(self.descriptor)
            _require(
                digest.hexdigest() == self.sha256 and offset == self.identity[5]
                and _fingerprint(source_after) == self.identity
                and stat.S_ISREG(target_after.st_mode) and target_after.st_nlink == 1
                and target_after.st_size == offset
                and bool(target_after.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)),
                "private executable snapshot differs from the held selected binary",
            )
            self.snapshot_identity = _fingerprint(target_after)
        finally:
            os.close(target_fd)
        return str(snapshot)

    def _verify_snapshot(self) -> None:
        _require(self.snapshot_dir is not None, "private executable snapshot is unavailable")
        snapshot = Path(self.exec_path)
        _check_path_components(snapshot, "private executable snapshot", must_exist=True)
        try:
            named = snapshot.lstat()
            descriptor = os.open(snapshot, FILE_FLAGS | getattr(os, "O_NONBLOCK", 0))
        except OSError as error:
            raise PreflightError("private executable snapshot is unavailable") from error
        try:
            opened = os.fstat(descriptor)
            _require(
                _fingerprint(named) == self.snapshot_identity == _fingerprint(opened)
                and stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1
                and bool(opened.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)),
                "private executable snapshot identity changed during the interface check",
            )
            digest, measured_stat = _hash_descriptor(descriptor, MAX_EXECUTABLE_BYTES)
            _require(
                digest == self.sha256 and _fingerprint(measured_stat) == self.snapshot_identity,
                "private executable snapshot SHA-256 or identity changed during the interface check",
            )
        finally:
            os.close(descriptor)

    def verify(self) -> None:
        _check_path_components(self.path, "selected executable", must_exist=True)
        try:
            named = self.path.lstat()
            opened = os.fstat(self.descriptor)
        except OSError as error:
            raise PreflightError("selected executable identity is unavailable") from error
        _require(
            _fingerprint(named) == self.identity == _fingerprint(opened)
            and stat.S_ISREG(named.st_mode) and named.st_nlink == 1,
            "selected executable identity changed during the interface check",
        )
        measured_sha, measured_stat = _hash_descriptor(self.descriptor, MAX_EXECUTABLE_BYTES)
        _require(
            measured_sha == self.sha256 and _fingerprint(measured_stat) == self.identity,
            "selected executable SHA-256 or identity changed during the interface check",
        )
        if self.snapshot_dir is not None:
            self._verify_snapshot()

    def close(self) -> None:
        try:
            os.close(self.descriptor)
        finally:
            if self.snapshot_dir is not None:
                self.snapshot_dir.cleanup()


def _limit_child() -> None:
    resource.setrlimit(resource.RLIMIT_FSIZE,
                       (MAX_CHILD_OUTPUT_BYTES, MAX_CHILD_OUTPUT_BYTES))
    resource.setrlimit(resource.RLIMIT_CPU, (5, 5))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


class AnchoredOutput:
    """Hold the receipt parent and require its absolute pathname to stay bound."""

    def __init__(self, raw: object, executable_path: Path):
        path = _normalized_path(raw, "receipt output")
        _require(path != executable_path, "receipt output aliases the selected executable")
        _require(path.name not in ("", ".", ".."), "receipt output must name a file")
        self.path = path
        self.name = path.name
        self.descriptors: list[int] = []
        self.identities: list[tuple[int, ...]] = []
        try:
            current = os.open(path.anchor, DIRECTORY_FLAGS)
            self.descriptors.append(current)
            root_metadata = os.fstat(current)
            _require(stat.S_ISDIR(root_metadata.st_mode),
                     "receipt output root is not an ordinary directory")
            self.identities.append(self._directory_identity(root_metadata))
            for component in path.parent.parts[1:]:
                try:
                    current = os.open(component, DIRECTORY_FLAGS, dir_fd=current)
                except OSError as error:
                    raise PreflightError(
                        "receipt output parent has a linked or unavailable component"
                    ) from error
                self.descriptors.append(current)
                metadata = os.fstat(current)
                _require(stat.S_ISDIR(metadata.st_mode),
                         "receipt output parent is not an ordinary directory")
                self.identities.append(self._directory_identity(metadata))
            self.verify_path()
            self.verify_absent()
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _directory_identity(metadata: os.stat_result) -> tuple[int, ...]:
        return metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid

    @property
    def descriptor(self) -> int:
        return self.descriptors[-1]

    def verify_path(self) -> None:
        """Rewalk with O_NOFOLLOW and compare every component to held identities."""
        transient: list[int] = []
        try:
            current = os.open(self.path.anchor, DIRECTORY_FLAGS)
            transient.append(current)
            metadata = os.fstat(current)
            _require(
                stat.S_ISDIR(metadata.st_mode)
                and self._directory_identity(metadata) == self.identities[0],
                "receipt output parent identity changed",
            )
            for index, component in enumerate(self.path.parent.parts[1:], start=1):
                try:
                    current = os.open(component, DIRECTORY_FLAGS, dir_fd=current)
                except OSError as error:
                    raise PreflightError("receipt output parent identity changed") from error
                transient.append(current)
                metadata = os.fstat(current)
                _require(
                    stat.S_ISDIR(metadata.st_mode)
                    and self._directory_identity(metadata) == self.identities[index],
                    "receipt output parent identity changed",
                )
        finally:
            for descriptor in reversed(transient):
                os.close(descriptor)
        for descriptor, identity in zip(self.descriptors, self.identities, strict=True):
            try:
                metadata = os.fstat(descriptor)
            except OSError as error:
                raise PreflightError("held receipt output parent is unavailable") from error
            _require(self._directory_identity(metadata) == identity,
                     "held receipt output parent identity changed")

    def verify_absent(self) -> None:
        self.verify_path()
        try:
            os.stat(self.name, dir_fd=self.descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return
        except OSError as error:
            raise PreflightError("receipt output could not be checked without following links") from error
        raise PreflightError("receipt output appeared before exclusive creation")

    def close(self) -> None:
        for descriptor in reversed(self.descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass
        self.descriptors.clear()
        self.identities.clear()


def _run_held(
    executable: HeldExecutable,
    destination: AnchoredOutput,
    arguments: tuple[str, ...],
    *,
    timeout: float,
) -> bytes:
    destination.verify_absent()
    executable.verify()
    environment = os.environ.copy()
    for variable in (
        "GOVERNANCE_TOKEN", "GH_TOKEN", "GITHUB_TOKEN", "GH_AUTH_TOKEN",
        "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL",
    ):
        environment.pop(variable, None)
    for variable in tuple(environment):
        if variable.startswith(("DYLD_", "LD_")):
            environment.pop(variable, None)
    timed_out = False
    return_code: int | None = None
    try:
        with tempfile.TemporaryFile(mode="w+b") as stdout_file, tempfile.TemporaryFile(mode="w+b") as stderr_file:
            try:
                process = subprocess.Popen(
                    [str(executable.path), *arguments],
                    executable=executable.exec_path,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    cwd="/",
                    env=environment,
                    close_fds=True,
                    pass_fds=(executable.descriptor,),
                    start_new_session=True,
                    preexec_fn=_limit_child,
                )
            except OSError as error:
                raise PreflightError("selected executable could not be started") from error
            try:
                return_code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
            stdout_size = os.fstat(stdout_file.fileno()).st_size
            stderr_size = os.fstat(stderr_file.fileno()).st_size
            if stdout_size >= MAX_CHILD_OUTPUT_BYTES or stderr_size >= MAX_CHILD_OUTPUT_BYTES:
                raise PreflightError("selected executable exceeded its bounded command-output limit")
            if timed_out:
                raise PreflightError("selected executable command exceeded its time limit")
            if stderr_size:
                raise PreflightError("selected executable command wrote stderr; diagnostics were suppressed")
            if return_code != 0:
                raise PreflightError("selected executable command failed; command output was suppressed")
            stdout_file.seek(0)
            raw = stdout_file.read(MAX_CHILD_OUTPUT_BYTES + 1)
            _require(len(raw) == stdout_size, "selected executable output changed while being read")
    finally:
        try:
            executable.verify()
        finally:
            destination.verify_absent()
    return raw


def _version_matches(raw: bytes, expected_version: str) -> bool:
    try:
        observed = raw.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError:
        return False
    return observed in {
        expected_version,
        f"aros {expected_version}",
        f"aros-tools {expected_version}",
    }


def _help_options(raw: bytes) -> set[str]:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise PreflightError("selected executable returned non-UTF-8 help output") from error
    options: set[str] = set()
    for line in text.splitlines():
        stripped = line.lstrip()
        if not stripped.startswith("-"):
            continue
        for match in re.finditer(r"--([A-Za-z0-9][A-Za-z0-9-]*)(?=$|[\s=,<])", stripped):
            options.add(match.group(1))
    return options


def _write_receipt(destination: AnchoredOutput, receipt: dict[str, Any]) -> None:
    raw = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    _require(0 < len(raw) <= MAX_RECEIPT_BYTES, "interface receipt exceeds its size limit")
    descriptor: int | None = None
    created_identity: tuple[int, ...] | None = None
    try:
        destination.verify_absent()
        descriptor = os.open(
            destination.name, OUTPUT_FLAGS, 0o600, dir_fd=destination.descriptor
        )
        metadata = os.fstat(descriptor)
        _require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1,
                 "exclusive receipt output is not a singly linked regular file")
        created_identity = _fingerprint(metadata)
        destination.verify_path()
        try:
            named = os.stat(destination.name, dir_fd=destination.descriptor,
                            follow_symlinks=False)
        except OSError as error:
            raise PreflightError("exclusive receipt output changed before writing") from error
        _require(
            stat.S_ISREG(named.st_mode) and named.st_nlink == 1
            and (named.st_dev, named.st_ino) == (metadata.st_dev, metadata.st_ino),
            "exclusive receipt output changed before writing",
        )
        os.fchmod(descriptor, 0o600)
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            _require(written > 0, "interface receipt write was incomplete")
            view = view[written:]
        os.fsync(descriptor)
        final_fd = os.fstat(descriptor)
        destination.verify_path()
        final_named = os.stat(destination.name, dir_fd=destination.descriptor,
                              follow_symlinks=False)
        _require(
            stat.S_ISREG(final_named.st_mode) and final_named.st_nlink == 1
            and (final_named.st_dev, final_named.st_ino) == (final_fd.st_dev, final_fd.st_ino)
            and final_fd.st_size == len(raw),
            "exclusive receipt output changed while being written",
        )
    except FileExistsError as error:
        raise PreflightError("receipt output appeared before exclusive creation") from error
    except BaseException as error:
        if descriptor is not None:
            try:
                opened = os.fstat(descriptor)
                current = os.stat(destination.name, dir_fd=destination.descriptor,
                                  follow_symlinks=False)
                if (
                    created_identity is not None
                    and _fingerprint(opened)[:5] == created_identity[:5]
                    and (current.st_dev, current.st_ino) == (opened.st_dev, opened.st_ino)
                ):
                    os.unlink(destination.name, dir_fd=destination.descriptor)
            except OSError:
                pass
        if isinstance(error, (PreflightError, KeyboardInterrupt, SystemExit)):
            raise
        if isinstance(error, FileExistsError):
            raise PreflightError("receipt output appeared before exclusive creation") from error
        raise PreflightError("interface receipt could not be written") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def preflight(
    *,
    aros: str,
    aros_sha256: str,
    expected_version: str,
    output: str,
    command_timeout: float = COMMAND_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    path = _normalized_path(aros, "selected executable")
    _require(HEX64.fullmatch(aros_sha256) is not None,
             "selected executable SHA-256 must be 64 lowercase hexadecimal characters")
    _require(SEMVER.fullmatch(expected_version) is not None,
             "expected version must be canonical semantic version syntax")
    _require(command_timeout > 0, "command time limit must be positive")
    destination = AnchoredOutput(output, path)
    executable: HeldExecutable | None = None
    try:
        executable = HeldExecutable(path, aros_sha256)
        version_raw = _run_held(
            executable, destination, ("--version",), timeout=command_timeout
        )
        _require(_version_matches(version_raw, expected_version),
                 "selected executable version differs from the expected version")
        checks: list[dict[str, Any]] = [
            {
                "kind": "version",
                "checked_selectors": {
                    "argv": ["--version"],
                    "expected_version": expected_version,
                },
                "result": "passed",
            }
        ]
        for command, required_options in INTERFACES:
            help_raw = _run_held(
                executable, destination, (*command, "--help"), timeout=command_timeout
            )
            observed_options = _help_options(help_raw)
            missing = sorted(set(required_options) - observed_options)
            _require(
                not missing,
                f"selected executable lacks required options for {' '.join(command)} help",
            )
            checks.append(
                {
                    "kind": "command-interface",
                    "checked_selectors": {
                        "command": list(command),
                        "required_options": list(required_options),
                    },
                    "result": "passed",
                }
            )
        executable.verify()
        receipt = {
            "schema": "aros-tools-runtime-interface-preflight-v1",
            "assurance": "interface-only-exact-selected-binary",
            "runtime": {
                "path": str(path),
                "sha256": executable.sha256,
                "version": expected_version,
                "execution_binding": executable.execution_binding,
                "file_identity": {
                    "device": executable.identity[0],
                    "inode": executable.identity[1],
                    "mode": executable.identity[2],
                    "size": executable.identity[5],
                    "mtime_ns": executable.identity[6],
                    "ctime_ns": executable.identity[7],
                },
            },
            "checks": checks,
            "limitations": [
                "does not authenticate published runtime provenance or authenticity",
                "does not establish V2 behavior, ABI compatibility, or qualification",
                "does not establish source commit, signatures, or release authority",
                "the caller must separately materialize and authenticate the runtime",
            ],
        }
        executable.verify()
        destination.verify_absent()
        _write_receipt(destination, receipt)
        return receipt
    finally:
        try:
            if executable is not None:
                executable.close()
        finally:
            destination.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--aros", required=True, help="absolute path to the selected executable")
    parser.add_argument("--aros-sha256", required=True, help="independently selected lowercase SHA-256")
    parser.add_argument("--expected-version", required=True, help="exact expected semantic version")
    parser.add_argument("--output", required=True, help="absent absolute receipt file")
    args = parser.parse_args(argv)
    try:
        receipt = preflight(
            aros=args.aros,
            aros_sha256=args.aros_sha256,
            expected_version=args.expected_version,
            output=args.output,
        )
    except (PreflightError, OSError, ValueError) as error:
        message = str(error) if isinstance(error, PreflightError) else "invalid preflight input or filesystem state"
        print(f"V2 runtime interface preflight: {message}", file=sys.stderr)
        return 1
    print("V2 runtime interface preflight passed; interface-only receipt written")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
