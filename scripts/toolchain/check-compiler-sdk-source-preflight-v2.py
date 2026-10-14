#!/usr/bin/env python3
"""Run bounded, non-publishing AROS-NX source-contract checks.

This preflight runs source-owned validation against one exact, clean AROS-NX
checkout. It is a development diagnostic only. It is not AROS-NX's protected
CI result, compiler qualification, native SDK generation, or release admission.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
from typing import Any


SCHEMA = "aros-compiler-sdk-source-preflight-v2"
ASSURANCE = "source-contract-preflight-only-not-ci-qualification-or-release-admission"
REPORT_NAME = "source-preflight-v2.json"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
MAX_JSON_BYTES = 1024 * 1024
MAX_GITHUB_OUTPUT_BYTES = 64 * 1024
CHECK_TIMEOUT_SECONDS = 300
FETCH_TIMEOUT_SECONDS = 90
GIT_TIMEOUT_SECONDS = 30
MAX_CHILD_LOG_BYTES = 1024 * 1024
MAX_SOURCE_FILE_BYTES = 16 * 1024 * 1024
MAX_PRODUCT_SOURCE_BYTES = 64 * 1024 * 1024
CHUNK_SIZE = 1024 * 1024


def _load_runtime_interface() -> Any:
    helper = Path(__file__).with_name("check-v2-runtime-interface.py")
    try:
        spec = importlib.util.spec_from_file_location("_aros_v2_runtime_interface", helper)
        if spec is None or spec.loader is None:
            raise OSError
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    except (ImportError, OSError, SyntaxError):
        raise RuntimeError("held executable support is unavailable") from None


RUNTIME_INTERFACE = _load_runtime_interface()

LIMITATIONS = [
    "does not replace AROS-NX protected CI or its selected product-host and preset jobs",
    "does not run the GCC libcody archive probe",
    "does not generate, execute, or qualify native SDK contents",
    "does not qualify compiler builds, publication, or release admission",
    "private child configuration directories do not sandbox trusted source processes from other local files",
]

CHECK_FILES = (
    "scripts/ci/ci_hygiene.py",
    "scripts/ci/locked_product_sources.py",
    "scripts/ci/product-sources.plan.json",
    "scripts/ci/product-sources.staging.json",
    "tools/crosstools/gnu/tests/test-header-closure.sh",
    "tools/crosstools/gnu/tests/test-release-layout.sh",
    "tools/crosstools/gnu/tests/test-zstd-closure.sh",
    "compiler/sdk/test_export.py",
    "compiler/sdk/export.py",
    "arch/riscv-esp32p4/native-sdk/test_export.py",
    "arch/riscv-esp32p4/native-sdk/export.py",
)

PRODUCT_ROLE = "product:chromium-zlib@da752eb2a3660cf1bf8dac620f6380b89dd953a7"
PRODUCT_FILENAME = "zlib.tar.gz"


class PreflightError(Exception):
    def __init__(self, step: str, reason: str, *, returncode: int | None = None):
        super().__init__(reason)
        self.step = step
        self.reason = reason
        self.returncode = returncode


def _duplicate_rejecting_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _safe_json(raw: bytes, label: str) -> Any:
    if len(raw) > MAX_JSON_BYTES:
        raise PreflightError(label, "selected JSON exceeds its size limit")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_duplicate_rejecting_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise PreflightError(label, "selected JSON is malformed") from None


def _auth_environment_name(name: str) -> bool:
    upper = name.upper()
    return (
        upper.startswith(
            (
                "GH_",
                "GITHUB",
                "ACTIONS_",
                "OIDC_",
                "GIT_",
                "AWS_",
                "AZURE_",
                "GOOGLE_",
                "GCP_",
                "CLOUDSDK_",
            )
        )
        or any(
            fragment in upper
            for fragment in (
                "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "AUTH", "API_KEY",
                "PRIVATE_KEY", "SIGNING_KEY",
            )
        )
        or upper.startswith(("LD_", "DYLD_"))
        or upper
        in {
            "SSH_AUTH_SOCK",
            "SSH_AGENT_PID",
            "PYTHONHOME",
            "PYTHONPATH",
            "PYTHONSTARTUP",
            "PYTHONUSERBASE",
            "PYTHONINSPECT",
            "PYTHONNOUSERSITE",
            "BASH_ENV",
            "ENV",
            "NETRC",
            "NETRC_FILE",
            "CURL_NETRC",
            "CURL_NETRC_FILE",
            "CREDENTIALSTORE",
            "CREDENTIAL_STORE",
            "KUBECONFIG",
            "DOCKER_AUTH_CONFIG",
        }
    )


def _child_environment() -> dict[str, str]:
    """Pass ordinary toolchain environment, never caller/provider credentials."""
    result = {name: value for name, value in os.environ.items() if not _auth_environment_name(name)}
    result.update(
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
        }
    )
    return result


def _absolute_directory(path_value: str, label: str) -> Path:
    path = Path(path_value)
    if not path.is_absolute():
        raise PreflightError("input-validation", f"{label} must be absolute")
    try:
        metadata = path.lstat()
    except OSError:
        raise PreflightError("input-validation", f"{label} is unavailable") from None
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise PreflightError("input-validation", f"{label} must be a real directory")
    try:
        return path.resolve(strict=True)
    except OSError:
        raise PreflightError("input-validation", f"{label} cannot be resolved") from None


def _absolute_path(path_value: str, label: str) -> Path:
    path = Path(path_value)
    if not path.is_absolute() or path.name in ("", ".", ".."):
        raise PreflightError("input-validation", f"{label} must be an absolute file path")
    try:
        parent = path.parent.resolve(strict=True)
        parent_metadata = parent.lstat()
    except OSError:
        raise PreflightError("input-validation", f"{label} parent is unavailable") from None
    if not stat.S_ISDIR(parent_metadata.st_mode) or stat.S_ISLNK(parent_metadata.st_mode):
        raise PreflightError("input-validation", f"{label} parent is not a real directory")
    return parent / path.name


def _absolute_file(
    path_value: str,
    label: str,
    *,
    maximum_size: int = MAX_SOURCE_FILE_BYTES,
) -> tuple[Path, int]:
    resolved = _absolute_path(path_value, label)
    return resolved, _open_regular(resolved, label, maximum_size=maximum_size)


def _absolute_new_directory(path_value: str) -> Path:
    path = Path(path_value)
    if not path.is_absolute() or path.name in ("", ".", ".."):
        raise PreflightError("input-validation", "output directory must be an absolute new child path")
    try:
        parent = path.parent.resolve(strict=True)
        parent_metadata = parent.lstat()
    except OSError:
        raise PreflightError("input-validation", "output parent must be an existing real directory") from None
    if not stat.S_ISDIR(parent_metadata.st_mode) or stat.S_ISLNK(parent_metadata.st_mode):
        raise PreflightError("input-validation", "output parent must be an existing real directory")
    target = parent / path.name
    try:
        target.lstat()
    except FileNotFoundError:
        return target
    except OSError:
        raise PreflightError("input-validation", "output path cannot be inspected safely") from None
    raise PreflightError("input-validation", "output path is already occupied")


def _inside(path: Path, directory: Path) -> bool:
    try:
        path.relative_to(directory)
        return True
    except ValueError:
        return False


def _open_regular(
    path: Path,
    label: str,
    *,
    maximum_size: int = MAX_SOURCE_FILE_BYTES,
) -> int:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    fd = -1
    try:
        fd = os.open(path, flags)
        metadata = os.fstat(fd)
    except OSError:
        if fd >= 0:
            os.close(fd)
        raise PreflightError("input-validation", f"{label} is not a readable regular file") from None
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size < 0
        or metadata.st_size > maximum_size
    ):
        os.close(fd)
        raise PreflightError("input-validation", f"{label} is not a bounded singly linked regular file")
    return fd


def _hash_fd(
    fd: int,
    label: str,
    *,
    maximum_size: int = MAX_SOURCE_FILE_BYTES,
) -> tuple[str, int, os.stat_result]:
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size < 0
            or before.st_size > maximum_size
        ):
            raise OSError
        os.lseek(fd, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = os.read(fd, CHUNK_SIZE)
            if not chunk:
                break
            size += len(chunk)
            if size > maximum_size:
                raise OSError
            digest.update(chunk)
        after = os.fstat(fd)
    except OSError:
        raise PreflightError(label, "selected file changed or became unreadable") from None
    if _stable_file_metadata(before) != _stable_file_metadata(after) or size != after.st_size:
        raise PreflightError(label, "selected file changed while being measured")
    return digest.hexdigest(), size, after


def _stable_file_metadata(metadata: os.stat_result) -> tuple[int, ...]:
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


def _verify_aros(executable: Any, step: str) -> None:
    try:
        executable.verify()
    except RUNTIME_INTERFACE.PreflightError:
        raise PreflightError(step, "aros executable no longer matches its selected SHA-256") from None


def _run_git(source: Path, arguments: list[str]) -> bytes:
    returncode, stdout, _stderr, failure, _elapsed_ms = _capture_child(
        ["git", "-c", "credential.helper=", "-c", "core.fsmonitor=false", *arguments],
        cwd=source,
        environment=_child_environment(),
        timeout=GIT_TIMEOUT_SECONDS,
        executable=None,
    )
    if failure is not None or returncode != 0:
        raise PreflightError("source-checkout", "local Git inspection failed")
    return stdout


def _source_snapshot(source: Path, expected_commit: str | None) -> tuple[str, str]:
    try:
        top = _run_git(source, ["rev-parse", "--show-toplevel"]).decode("utf-8").strip()
        head = _run_git(source, ["rev-parse", "--verify", "HEAD^{commit}"]).decode("ascii").strip()
        tree = _run_git(source, ["rev-parse", "--verify", "HEAD^{tree}"]).decode("ascii").strip()
        status = _run_git(source, ["status", "--porcelain=v1", "--untracked-files=all", "--ignore-submodules=none"])
    except UnicodeDecodeError:
        raise PreflightError("source-checkout", "local Git identity is malformed") from None
    try:
        resolved_top = Path(top).resolve(strict=True)
    except OSError:
        raise PreflightError("source-checkout", "source Git root is unavailable") from None
    if resolved_top != source:
        raise PreflightError("source-checkout", "source directory is not the selected Git worktree root")
    if not HEX40.fullmatch(head) or not HEX40.fullmatch(tree):
        raise PreflightError("source-checkout", "source Git identity is malformed")
    if expected_commit is not None and head != expected_commit:
        raise PreflightError("source-checkout", "source HEAD differs from the expected commit")
    if status:
        raise PreflightError("source-checkout", "source checkout is not clean")
    return head, tree


def _checked_source_file(source: Path, relative: str) -> Path:
    path = source / relative
    fd = _open_regular(path, f"source check {relative}")
    os.close(fd)
    return path


def _write_all(fd: int, raw: bytes) -> None:
    view = memoryview(raw)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("short write")
        view = view[written:]


class PrivateReport:
    def __init__(self, output: Path, initial: dict[str, Any]):
        try:
            os.mkdir(output, 0o700)
            metadata = output.lstat()
        except OSError:
            raise PreflightError("output-initialization", "private output directory could not be created") from None
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_mode & 0o077
        ):
            raise PreflightError("output-initialization", "output directory is not private")
        self.output = output
        self.path = output / REPORT_NAME
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            self.fd = os.open(self.path, flags, 0o600)
            self.metadata = os.fstat(self.fd)
        except OSError:
            raise PreflightError("output-initialization", "metadata report could not be created safely") from None
        if not stat.S_ISREG(self.metadata.st_mode) or self.metadata.st_mode & 0o077:
            os.close(self.fd)
            self.fd = -1
            raise PreflightError("output-initialization", "metadata report is not private")
        self.value = initial
        self.write()

    def write(self) -> None:
        try:
            current_path = self.path.lstat()
            current_fd = os.fstat(self.fd)
            if (
                stat.S_ISLNK(current_path.st_mode)
                or not stat.S_ISREG(current_path.st_mode)
                or (current_path.st_dev, current_path.st_ino)
                != (current_fd.st_dev, current_fd.st_ino)
                or current_fd.st_mode & 0o077
            ):
                raise OSError
            raw = (json.dumps(self.value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
            if len(raw) > MAX_JSON_BYTES:
                raise OSError
            os.lseek(self.fd, 0, os.SEEK_SET)
            os.ftruncate(self.fd, 0)
            _write_all(self.fd, raw)
            os.fsync(self.fd)
        except OSError:
            raise PreflightError("metadata-report", "private metadata report could not be retained") from None

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


def _create_private_child_directory(
    output: Path,
    name: str,
    *,
    step: str = "product-source-seed",
) -> Path:
    path = output / name
    try:
        os.mkdir(path, 0o700)
        metadata = path.lstat()
    except OSError:
        raise PreflightError(step, "private child directory could not be created") from None
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise PreflightError(step, "private child directory is not private")
    return path


def _create_child_environment(output: Path) -> tuple[Path, dict[str, str]]:
    home = _create_private_child_directory(output, "child-home", step="child-environment")
    directories = {
        "XDG_CONFIG_HOME": "xdg-config",
        "XDG_CACHE_HOME": "xdg-cache",
        "XDG_DATA_HOME": "xdg-data",
        "GH_CONFIG_DIR": "gh-config",
        "CURL_HOME": "curl-home",
    }
    paths: dict[str, Path] = {}
    try:
        for variable, name in directories.items():
            path = home / name
            os.mkdir(path, 0o700)
            metadata = path.lstat()
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                raise OSError
            paths[variable] = path
    except OSError:
        raise PreflightError("child-environment", "private child configuration could not be created") from None

    environment = _child_environment()
    environment["HOME"] = str(home)
    environment.update({name: str(path) for name, path in paths.items()})
    return home, environment


def _product_source_entry(source: Path) -> tuple[bytes, dict[str, Any]]:
    plan_path = _checked_source_file(source, "scripts/ci/product-sources.plan.json")
    plan_fd = _open_regular(plan_path, "product source plan")
    try:
        raw = bytearray()
        while len(raw) <= MAX_JSON_BYTES:
            chunk = os.read(plan_fd, min(CHUNK_SIZE, MAX_JSON_BYTES + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        if len(raw) > MAX_JSON_BYTES:
            raise PreflightError("product-source-seed", "product source plan exceeds its size limit")
    finally:
        os.close(plan_fd)
    plan = _safe_json(bytes(raw), "product-source-seed")
    if not isinstance(plan, dict) or set(plan) != {"schema", "entries"}:
        raise PreflightError("product-source-seed", "product source plan has an unexpected shape")
    entries = plan.get("entries")
    if plan.get("schema") != "aros-cache-source-fetch-plan-v1" or not isinstance(entries, list) or len(entries) != 1:
        raise PreflightError("product-source-seed", "product source plan is not the expected closed zlib selection")
    entry = entries[0]
    if not isinstance(entry, dict) or set(entry) != {
        "role", "filename", "candidates", "representation", "normalization", "integrity"
    }:
        raise PreflightError("product-source-seed", "product source entry has an unexpected shape")
    integrity = entry.get("integrity")
    candidates = entry.get("candidates")
    if (
        entry.get("role") != PRODUCT_ROLE
        or entry.get("filename") != PRODUCT_FILENAME
        or entry.get("representation") != "archive"
        or entry.get("normalization") != "canonical-tar-gzip-v1"
        or not isinstance(candidates, list)
        or not candidates
        or any(not isinstance(item, dict) or set(item) != {"url"} or not isinstance(item["url"], str) for item in candidates)
        or not isinstance(integrity, dict)
        or set(integrity) != {"kind", "sha256", "size"}
        or integrity.get("kind") != "locked"
        or not isinstance(integrity.get("sha256"), str)
        or not HEX64.fullmatch(integrity["sha256"])
        or type(integrity.get("size")) is not int
        or integrity["size"] <= 0
    ):
        raise PreflightError("product-source-seed", "product source entry is not the locked canonical zlib object")
    return bytes(raw), entry


def _copy_seed_to_cache(seed_fd: int, cache: Path, entry: dict[str, Any]) -> dict[str, Any]:
    expected = entry["integrity"]
    seed_sha, seed_size, initial_metadata = _hash_fd(
        seed_fd, "product-source-seed", maximum_size=MAX_PRODUCT_SOURCE_BYTES
    )
    if seed_sha != expected["sha256"] or seed_size != expected["size"]:
        raise PreflightError("product-source-seed", "provided source seed differs from the selected lock")
    destination = cache / entry["filename"]
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        destination_fd = os.open(destination, flags, 0o600)
    except OSError:
        raise PreflightError("product-source-seed", "locked source seed destination is unavailable") from None
    digest = hashlib.sha256()
    size = 0
    try:
        os.lseek(seed_fd, 0, os.SEEK_SET)
        while True:
            chunk = os.read(seed_fd, CHUNK_SIZE)
            if not chunk:
                break
            _write_all(destination_fd, chunk)
            digest.update(chunk)
            size += len(chunk)
        os.fsync(destination_fd)
        after_metadata = os.fstat(seed_fd)
        output_metadata = os.fstat(destination_fd)
    except OSError:
        raise PreflightError("product-source-seed", "source seed could not be copied safely") from None
    finally:
        os.close(destination_fd)
    copied_sha = digest.hexdigest()
    if (
        copied_sha != expected["sha256"]
        or size != expected["size"]
        or _stable_file_metadata(initial_metadata) != _stable_file_metadata(after_metadata)
        or output_metadata.st_size != expected["size"]
        or output_metadata.st_mode & 0o077
    ):
        raise PreflightError("product-source-seed", "copied source seed differs from the selected lock")
    return {"role": entry["role"], "filename": entry["filename"], "sha256": copied_sha, "size": size}


def _parse_hygiene_output(path: Path, expected_inode: tuple[int, int]) -> str:
    fd = -1
    try:
        metadata = path.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or (metadata.st_dev, metadata.st_ino) != expected_inode
            or metadata.st_size > MAX_GITHUB_OUTPUT_BYTES
        ):
            raise OSError
        fd = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_uid != os.geteuid()
            or opened.st_mode & 0o077
            or (opened.st_dev, opened.st_ino) != expected_inode
            or opened.st_size > MAX_GITHUB_OUTPUT_BYTES
        ):
            raise OSError
        chunks = bytearray()
        while len(chunks) <= MAX_GITHUB_OUTPUT_BYTES:
            chunk = os.read(fd, min(CHUNK_SIZE, MAX_GITHUB_OUTPUT_BYTES + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
        after = os.fstat(fd)
        final_path = path.lstat()
        if (
            len(chunks) > MAX_GITHUB_OUTPUT_BYTES
            or _stable_file_metadata(opened) != _stable_file_metadata(after)
            or stat.S_ISLNK(final_path.st_mode)
            or not stat.S_ISREG(final_path.st_mode)
            or (final_path.st_dev, final_path.st_ino) != expected_inode
        ):
            raise OSError
        raw = bytes(chunks)
    except OSError:
        raise PreflightError("hygiene-plan", "hygiene plan output is unsafe or unavailable") from None
    finally:
        if fd >= 0:
            os.close(fd)
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        raise PreflightError("hygiene-plan", "hygiene plan output is malformed") from None
    fields: dict[str, str] = {}
    for line in lines:
        if "=" not in line:
            raise PreflightError("hygiene-plan", "hygiene plan output is malformed")
        name, value = line.split("=", 1)
        if name not in {"scope", "matrix"} or name in fields:
            raise PreflightError("hygiene-plan", "hygiene plan output has unexpected fields")
        fields[name] = value
    if set(fields) != {"scope", "matrix"} or fields["scope"] not in {"none", "pull-request", "remaining", "full"}:
        raise PreflightError("hygiene-plan", "hygiene plan output has no valid scope")
    matrix = _safe_json(fields["matrix"].encode("utf-8"), "hygiene-plan")
    if not isinstance(matrix, dict) or set(matrix) != {"include"} or not isinstance(matrix["include"], list):
        raise PreflightError("hygiene-plan", "hygiene plan matrix is malformed")
    return fields["scope"]


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except OSError:
        pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def _capture_child(
    command: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    timeout: int,
    executable: Any | None,
) -> tuple[int | None, bytes, bytes, str | None, int]:
    started = time.monotonic()
    try:
        is_aros = executable is not None and command[0] == str(executable.path)
        process = subprocess.Popen(
            command,
            executable=executable.exec_path if is_aros else None,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            close_fds=True,
            pass_fds=(executable.descriptor,) if is_aros else (),
            start_new_session=True,
        )
    except OSError:
        return None, b"", b"", "process-start", int((time.monotonic() - started) * 1000)

    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    streams = {"stdout": process.stdout, "stderr": process.stderr}
    selector = selectors.DefaultSelector()
    deadline = started + timeout
    failure: str | None = None
    try:
        for name, stream in streams.items():
            assert stream is not None
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure = "timeout"
                _terminate_process_group(process)
                break
            events = selector.select(remaining)
            if not events:
                failure = "timeout"
                _terminate_process_group(process)
                break
            for key, _mask in events:
                name = key.data
                buffer = buffers[name]
                remaining_bytes = MAX_CHILD_LOG_BYTES - len(buffer)
                try:
                    chunk = os.read(key.fd, min(64 * 1024, remaining_bytes + 1))
                except OSError:
                    failure = "capture-error"
                    _terminate_process_group(process)
                    break
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                if len(chunk) > remaining_bytes:
                    buffer.extend(chunk[:remaining_bytes])
                    failure = "output-limit"
                    _terminate_process_group(process)
                    break
                buffer.extend(chunk)
            if failure is not None:
                break
        if failure is None:
            try:
                process.wait(timeout=max(0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                failure = "timeout"
                _terminate_process_group(process)
    finally:
        selector.close()
        for stream in streams.values():
            if stream is not None and not stream.closed:
                stream.close()
        if process.poll() is None:
            _terminate_process_group(process)
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()

    return (
        process.returncode,
        bytes(buffers["stdout"]),
        bytes(buffers["stderr"]),
        failure,
        int((time.monotonic() - started) * 1000),
    )


class Preflight:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.source = _absolute_directory(args.source_dir, "source directory")
        self.expected_commit = args.expected_commit
        if not HEX40.fullmatch(self.expected_commit):
            raise PreflightError("input-validation", "expected source commit must be a lowercase 40-digit SHA")
        self.aros_path = _absolute_path(args.aros, "aros executable")
        try:
            self.aros = RUNTIME_INTERFACE.HeldExecutable(self.aros_path, args.aros_sha256)
        except RUNTIME_INTERFACE.PreflightError:
            raise PreflightError(
                "input-validation", "aros executable is not the selected bounded SHA-256 file"
            ) from None
        _seed_path, self.seed_fd = _absolute_file(
            args.product_source_seed,
            "product source seed",
            maximum_size=MAX_PRODUCT_SOURCE_BYTES,
        )
        self.output = _absolute_new_directory(args.output_dir)
        if _inside(self.output, self.source) or _inside(self.source, self.output):
            raise PreflightError("input-validation", "private output must be disjoint from the source checkout")
        if _inside(self.output, self.aros_path.parent):
            raise PreflightError("input-validation", "private output must be outside the selected runtime")
        self.environment = _child_environment()
        self.report_writer: PrivateReport | None = None
        self.report: dict[str, Any] = {
            "schema": SCHEMA,
            "assurance": ASSURANCE,
            "status": "running",
            "source_commit": None,
            "source_tree": None,
            "aros_sha256": args.aros_sha256,
            "steps": [],
            "limitations": LIMITATIONS,
        }

    def close(self) -> None:
        if self.report_writer is not None:
            self.report_writer.close()
        self.aros.close()
        if self.seed_fd >= 0:
            os.close(self.seed_fd)
            self.seed_fd = -1

    def _persist(self) -> None:
        if self.report_writer is not None:
            self.report_writer.write()

    def _prepare_child_environment(self) -> None:
        _home, self.environment = _create_child_environment(self.output)
        self.report["child_environment"] = {
            "configuration": "private-empty-home-and-config-directories",
            "home": "child-home",
            "config_paths": [
                "child-home/xdg-config",
                "child-home/xdg-cache",
                "child-home/xdg-data",
                "child-home/gh-config",
                "child-home/curl-home",
            ],
            "os_sandbox": False,
        }
        self._persist()

    def _record(self, name: str, status: str, **metadata: Any) -> None:
        record = {"name": name, "status": status}
        record.update(metadata)
        self.report["steps"].append(record)
        self._persist()

    def _write_private_log(self, name: str, contents: bytes) -> str:
        if len(contents) > MAX_CHILD_LOG_BYTES or re.fullmatch(r"[a-z0-9-]+\.(?:stdout|stderr)\.log", name) is None:
            raise PreflightError("metadata-report", "bounded child log is invalid")
        path = self.output / name
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            fd = os.open(path, flags, 0o600)
        except OSError:
            raise PreflightError("metadata-report", "bounded child log could not be created safely") from None
        try:
            metadata = os.fstat(fd)
            os.fchmod(fd, 0o600)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_uid != os.geteuid()
                or metadata.st_mode & 0o077
            ):
                raise OSError
            _write_all(fd, contents)
            os.fsync(fd)
            final_fd = os.fstat(fd)
            final_path = path.lstat()
            if (
                not stat.S_ISREG(final_path.st_mode)
                or stat.S_ISLNK(final_path.st_mode)
                or final_path.st_nlink != 1
                or (final_fd.st_dev, final_fd.st_ino) != (final_path.st_dev, final_path.st_ino)
                or final_fd.st_size != len(contents)
                or final_fd.st_mode & 0o077
            ):
                raise OSError
        except OSError:
            raise PreflightError("metadata-report", "bounded child log could not be retained safely") from None
        finally:
            os.close(fd)
        return name

    def _run_child(
        self,
        name: str,
        command: list[str],
        *,
        environment: dict[str, str] | None = None,
        timeout: int = CHECK_TIMEOUT_SECONDS,
    ) -> None:
        stdout_log = f"{name}.stdout.log"
        stderr_log = f"{name}.stderr.log"
        record = {
            "name": name,
            "status": "running",
            "stdout_log": stdout_log,
            "stderr_log": stderr_log,
        }
        self.report["steps"].append(record)
        self._persist()
        selected_environment = self.environment if environment is None else environment
        is_aros = command[0] == str(self.aros_path)
        if is_aros:
            _verify_aros(self.aros, f"aros-executable-before-{name}")
        returncode, stdout, stderr, failure, elapsed_ms = _capture_child(
            command,
            cwd=self.source,
            environment=selected_environment,
            timeout=timeout,
            executable=self.aros if is_aros else None,
        )
        log_errors = []
        for log_name, contents in ((stdout_log, stdout), (stderr_log, stderr)):
            try:
                self._write_private_log(log_name, contents)
            except PreflightError:
                log_errors.append(log_name)
        if log_errors:
            record.update({"status": "failed", "failure": "log-retention", "elapsed_ms": elapsed_ms})
            if returncode is not None:
                record["returncode"] = returncode
            self._persist()
            raise PreflightError(name, "bounded child diagnostics could not be retained")
        record["elapsed_ms"] = elapsed_ms
        if returncode is not None:
            record["returncode"] = returncode
        if failure is not None:
            record.update({"status": "failed", "failure": failure})
            self._persist()
            reason = {
                "process-start": "checked source process could not start",
                "timeout": "checked source process exceeded its time limit",
                "output-limit": "checked source process exceeded its bounded log limit",
                "capture-error": "checked source process output could not be captured safely",
            }.get(failure, "checked source process failed")
            raise PreflightError(name, reason, returncode=returncode)
        if returncode != 0:
            record.update({"status": "failed", "failure": "nonzero-exit"})
            self._persist()
            raise PreflightError(name, "checked source process returned nonzero", returncode=returncode)
        record.update({"status": "passed", "returncode": 0})
        self._persist()
        _verify_aros(self.aros, f"aros-integrity-after-{name}")

    def _python(self, relative: str, *arguments: str) -> list[str]:
        _checked_source_file(self.source, relative)
        return [sys.executable, "-B", relative, *arguments]

    def _run_source_checks(self) -> None:
        for relative in CHECK_FILES:
            _checked_source_file(self.source, relative)

        self._run_child(
            "ci-contract-tests",
            [sys.executable, "-B", "-m", "unittest", "discover", "-s", "scripts/ci", "-p", "test_*.py", "-v"],
        )
        for step, relative in (
            ("gnu-header-closure", "tools/crosstools/gnu/tests/test-header-closure.sh"),
            ("gnu-release-layout", "tools/crosstools/gnu/tests/test-release-layout.sh"),
            ("gnu-zstd-closure", "tools/crosstools/gnu/tests/test-zstd-closure.sh"),
        ):
            self._run_child(step, ["sh", relative])

        hygiene_output = self.output / "ci-hygiene-plan.out"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            output_fd = os.open(hygiene_output, flags, 0o600)
            output_metadata = os.fstat(output_fd)
            os.close(output_fd)
        except OSError:
            raise PreflightError("hygiene-plan", "private hygiene output could not be created") from None
        hygiene_environment = dict(self.environment)
        hygiene_environment.update(
            {
                "GITHUB_EVENT_NAME": "workflow_dispatch",
                "GITHUB_SHA": self.expected_commit,
                "GITHUB_OUTPUT": str(hygiene_output),
            }
        )
        self._run_child(
            "hygiene-plan",
            self._python("scripts/ci/ci_hygiene.py", "plan"),
            environment=hygiene_environment,
        )
        self.report["hygiene_scope"] = _parse_hygiene_output(
            hygiene_output, (output_metadata.st_dev, output_metadata.st_ino)
        )
        try:
            hygiene_output.unlink()
        except OSError:
            raise PreflightError("hygiene-plan", "temporary hygiene output could not be removed") from None
        self._persist()

        self._run_child("hygiene-paths", self._python("scripts/ci/ci_hygiene.py", "paths"))
        self._run_child(
            "product-source-lock-validation",
            self._python("scripts/ci/locked_product_sources.py", "validate"),
        )
        self._run_child("llvm-sdk-exporter-tests", self._python("compiler/sdk/test_export.py"))
        self._run_child("llvm-sdk-export-check", self._python("compiler/sdk/export.py", "--check"))
        self._run_child(
            "native-sdk-exporter-tests",
            self._python("arch/riscv-esp32p4/native-sdk/test_export.py"),
        )
        self._run_child(
            "native-sdk-export-check",
            self._python("arch/riscv-esp32p4/native-sdk/export.py", "--check"),
        )

    def _run_locked_product_source_cache(self) -> None:
        plan_bytes, entry = _product_source_entry(self.source)
        seed_metadata = _copy_seed_to_cache(
            self.seed_fd,
            _create_private_child_directory(self.output, "product-source-cache"),
            entry,
        )
        cache = self.output / "product-source-cache"
        export = self.output / "product-source-export"
        plan = self.source / "scripts/ci/product-sources.plan.json"
        self.report["product_source"] = {
            "plan_sha256": hashlib.sha256(plan_bytes).hexdigest(),
            "integrity": "locked",
            "cache_seed": seed_metadata,
            "fetch_mode": "offline-cache-hit",
        }
        self._persist()
        self._run_child(
            "product-source-fetch-offline",
            [
                str(self.aros_path),
                "cache",
                "sources",
                "fetch",
                "--source-fetch-plan",
                str(plan),
                "--dir",
                str(cache),
                "--offline",
            ],
            timeout=FETCH_TIMEOUT_SECONDS,
        )
        self._run_child(
            "product-source-verify",
            [
                str(self.aros_path),
                "cache",
                "sources",
                "verify",
                "--source-fetch-plan",
                str(plan),
                "--dir",
                str(cache),
            ],
            timeout=FETCH_TIMEOUT_SECONDS,
        )
        self._run_child(
            "product-source-export",
            self._python(
                "scripts/ci/locked_product_sources.py",
                "export",
                "--cache",
                str(cache),
                "--output",
                str(export),
            ),
        )
        exported = export / entry["filename"]
        export_fd = _open_regular(exported, "exported locked product source")
        try:
            export_sha, export_size, _metadata = _hash_fd(export_fd, "exported locked product source")
        finally:
            os.close(export_fd)
        if export_sha != entry["integrity"]["sha256"] or export_size != entry["integrity"]["size"]:
            raise PreflightError("product-source-export", "exported product source differs from its lock")
        self.report["product_source"]["export_sha256"] = export_sha
        self.report["product_source"]["export_size"] = export_size
        self._persist()

    def execute(self) -> dict[str, Any]:
        head, tree = _source_snapshot(self.source, self.expected_commit)
        _verify_aros(self.aros, "aros-executable-initial")
        seed_sha, seed_size, _seed_stat = _hash_fd(
            self.seed_fd, "product-source-seed", maximum_size=MAX_PRODUCT_SOURCE_BYTES
        )
        if not HEX64.fullmatch(seed_sha) or seed_size <= 0:
            raise PreflightError("product-source-seed", "product source seed is empty or invalid")
        self.report["source_commit"] = head
        self.report["source_tree"] = tree
        self.report_writer = PrivateReport(self.output, self.report)

        failure: PreflightError | None = None
        try:
            self._prepare_child_environment()
            self._run_source_checks()
            self._run_locked_product_source_cache()
        except PreflightError as error:
            failure = error

        try:
            final_head, final_tree = _source_snapshot(self.source, self.expected_commit)
            if (final_head, final_tree) != (head, tree):
                raise PreflightError("source-checkout-final", "source identity changed during preflight")
            self._record("source-checkout-final", "passed")
        except PreflightError as error:
            self.report["steps"].append({"name": error.step, "status": "failed", "failure": "source-integrity"})
            if failure is None:
                failure = error

        try:
            _verify_aros(self.aros, "aros-executable-final")
            self._record("aros-executable-final", "passed")
        except PreflightError as error:
            self.report["steps"].append({"name": error.step, "status": "failed", "failure": "executable-integrity"})
            if failure is None:
                failure = error

        if failure is not None:
            self.report["status"] = "failed"
            self.report["failed_step"] = failure.step
            self.report["failure"] = failure.reason
            if failure.returncode is not None:
                self.report["failed_returncode"] = failure.returncode
        else:
            self.report["status"] = "passed"
        self._persist()
        return self.report


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--source-dir", required=True, help="absolute clean selected AROS-NX checkout")
    result.add_argument("--expected-commit", required=True, help="expected lowercase 40-digit source commit")
    result.add_argument("--output-dir", required=True, help="absent private output directory")
    result.add_argument("--aros", required=True, help="absolute selected aros CLI executable")
    result.add_argument("--aros-sha256", required=True, help="expected SHA-256 of the selected aros executable")
    result.add_argument(
        "--product-source-seed",
        required=True,
        help="explicit canonical locked zlib cache seed from the selected producer checkout",
    )
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    preflight: Preflight | None = None
    try:
        preflight = Preflight(args)
        report = preflight.execute()
        summary = {
            "schema": SCHEMA,
            "status": report["status"],
            "source_commit": report.get("source_commit"),
            "steps": len(report["steps"]),
            "report": REPORT_NAME,
        }
        print(json.dumps(summary, sort_keys=True))
        return 0 if report["status"] == "passed" else 1
    except PreflightError as error:
        summary = {"schema": SCHEMA, "status": "failed", "failed_step": error.step, "failure": error.reason}
        if error.returncode is not None:
            summary["failed_returncode"] = error.returncode
        print(json.dumps(summary, sort_keys=True))
        return 1
    except OSError:
        summary = {
            "schema": SCHEMA,
            "status": "failed",
            "failed_step": "local-io",
            "failure": "a required local file operation failed",
        }
        print(json.dumps(summary, sort_keys=True))
        return 1
    finally:
        if preflight is not None:
            preflight.close()


if __name__ == "__main__":
    raise SystemExit(main())
