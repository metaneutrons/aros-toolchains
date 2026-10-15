#!/usr/bin/env python3
"""Run the producer's bounded native-host prerequisite checks for one host.

The producer owns lane selection and host observations. This wrapper binds the
exact release-input collection, invokes only release-plan and host-preflight,
and retains bounded JSON and child diagnostics. It does not build a compiler
or make a qualification or release-admission claim.
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


SCHEMA = "aros-native-host-preflights-v2"
ASSURANCE = "host-prerequisites-only-not-configure-build-or-release-qualification"
REPORT_SCHEMA = "aros-native-host-preflight-v1"
REPORT_ASSURANCE = "host-prerequisites-only-not-configure-build-or-release-qualification"
INPUTS_NAME = "toolchain-release-inputs-v2.json"
SUMMARY_NAME = "native-host-preflights-v2.json"
MAX_INPUT_DOCUMENT_BYTES = 1024 * 1024
MAX_EXECUTABLE_BYTES = 1024 * 1024 * 1024
MAX_CHILD_LOG_BYTES = 1024 * 1024
MAX_JSON_BYTES = 1024 * 1024
MAX_MATRIX_BYTES = 64 * 1024
MAX_SELECTED_LANES = 128
PLAN_TIMEOUT_SECONDS = 60
HOST_PREFLIGHT_TIMEOUT_SECONDS = 180
MAX_RUN_SECONDS = 1800
CHUNK_SIZE = 64 * 1024
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


def _load_runtime_interface() -> Any:
    helper = Path(__file__).with_name("check-v2-runtime-interface.py")
    try:
        spec = importlib.util.spec_from_file_location("_aros_native_preflight_runtime", helper)
        if spec is None or spec.loader is None:
            raise OSError
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    except (ImportError, OSError, SyntaxError):
        raise RuntimeError("held executable support is unavailable") from None


RUNTIME_INTERFACE = _load_runtime_interface()


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


def _reject_json_constant(_value: str) -> None:
    raise ValueError("non-standard JSON number")


def _safe_json(raw: bytes, label: str) -> Any:
    if len(raw) > MAX_JSON_BYTES:
        raise PreflightError(label, "producer JSON exceeds its size limit")
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_duplicate_rejecting_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise PreflightError(label, "producer JSON is malformed") from None


def _fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
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


def _write_all(fd: int, raw: bytes) -> None:
    view = memoryview(raw)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("short write")
        view = view[written:]


def _absolute_directory(raw: str, label: str) -> Path:
    path = Path(raw)
    if not path.is_absolute() or ".." in path.parts:
        raise PreflightError("input-validation", f"{label} must be an absolute directory path")
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError:
        raise PreflightError("input-validation", f"{label} is unavailable") from None
    if stat.S_ISLNK(metadata.st_mode) or not resolved.is_dir():
        raise PreflightError("input-validation", f"{label} must be a real directory")
    return resolved


def _absolute_new_directory(raw: str) -> Path:
    path = Path(raw)
    if not path.is_absolute() or path.name in ("", ".", "..") or ".." in path.parts:
        raise PreflightError("input-validation", "output directory must be an absolute new child path")
    try:
        parent = path.parent.resolve(strict=True)
        metadata = parent.lstat()
    except OSError:
        raise PreflightError("input-validation", "output parent must be an existing real directory") from None
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise PreflightError("input-validation", "output parent must be an existing real directory")
    target = parent / path.name
    try:
        target.lstat()
    except FileNotFoundError:
        return target
    except OSError:
        raise PreflightError("input-validation", "output path cannot be inspected safely") from None
    raise PreflightError("input-validation", "output path is already occupied")


def _path_overlap(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents


def _valid_label(value: Any, label: str) -> str:
    if not isinstance(value, str) or not LABEL.fullmatch(value):
        raise PreflightError("release-plan", f"{label} is missing or malformed")
    return value


def _open_regular(path: Path, label: str, *, maximum_size: int) -> int:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    fd = -1
    try:
        named = path.lstat()
        fd = os.open(path, flags)
        opened = os.fstat(fd)
    except OSError:
        if fd >= 0:
            os.close(fd)
        raise PreflightError("input-validation", f"{label} is unavailable or linked") from None
    if (
        not stat.S_ISREG(opened.st_mode)
        or stat.S_ISLNK(named.st_mode)
        or opened.st_nlink != 1
        or _fingerprint(named) != _fingerprint(opened)
        or opened.st_size < 0
        or opened.st_size > maximum_size
    ):
        os.close(fd)
        raise PreflightError("input-validation", f"{label} is not a bounded singly linked regular file")
    return fd


def _hash_descriptor(fd: int, label: str, *, maximum_size: int) -> tuple[str, tuple[int, ...]]:
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size < 0
            or before.st_size > maximum_size
        ):
            raise OSError
        digest = hashlib.sha256()
        offset = 0
        while offset < before.st_size:
            chunk = os.pread(fd, min(CHUNK_SIZE, before.st_size - offset), offset)
            if not chunk:
                raise OSError
            digest.update(chunk)
            offset += len(chunk)
        after = os.fstat(fd)
    except OSError:
        raise PreflightError("input-integrity", f"{label} changed or became unreadable") from None
    if _fingerprint(before) != _fingerprint(after) or offset != after.st_size:
        raise PreflightError("input-integrity", f"{label} changed while being measured")
    return digest.hexdigest(), _fingerprint(after)


def _measure_file(
    path: Path,
    label: str,
    *,
    maximum_size: int = MAX_INPUT_DOCUMENT_BYTES,
) -> tuple[str, tuple[int, ...]]:
    fd = _open_regular(path, label, maximum_size=maximum_size)
    try:
        return _hash_descriptor(fd, label, maximum_size=maximum_size)
    finally:
        os.close(fd)


def _child_environment() -> dict[str, str]:
    allowed = (
        "PATH",
        "HOME",
        "TMPDIR",
        "TMP",
        "TEMP",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "RUSTUP_HOME",
        "CARGO_HOME",
        "DEVELOPER_DIR",
        "SDKROOT",
        "MACOSX_DEPLOYMENT_TARGET",
        "SYSTEMROOT",
        "WINDIR",
    )
    environment = {name: os.environ[name] for name in allowed if name in os.environ}
    environment.update(
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
        }
    )
    return environment


def _create_private_output(path: Path) -> None:
    try:
        os.mkdir(path, 0o700)
        metadata = path.lstat()
    except OSError:
        raise PreflightError("output-initialization", "private output directory could not be created") from None
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise PreflightError("output-initialization", "output directory is not private")


def _open_output(path: Path) -> int:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
        metadata = os.fstat(fd)
    except OSError:
        raise PreflightError("output-write", "bounded child log could not be created safely") from None
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != 0o600:
        os.close(fd)
        raise PreflightError("output-write", "child log is not a private regular file")
    return fd


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
    executable: Any,
    command: list[str],
    *,
    cwd: Path,
    stdout_path: Path,
    stderr_path: Path,
    timeout: float,
) -> tuple[int | None, bytes, bytes, str | None]:
    stdout_fd = _open_output(stdout_path)
    try:
        stderr_fd = _open_output(stderr_path)
    except BaseException:
        os.close(stdout_fd)
        raise
    files = {"stdout": stdout_fd, "stderr": stderr_fd}
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    started = time.monotonic()
    process: subprocess.Popen[bytes] | None = None
    selector = selectors.DefaultSelector()
    failure: str | None = None
    returncode: int | None = None
    deadline = started + timeout
    try:
        executable.verify()
        try:
            process = subprocess.Popen(
                command,
                executable=executable.exec_path,
                cwd=cwd,
                env=_child_environment(),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
                close_fds=True,
                pass_fds=(executable.descriptor,),
                start_new_session=True,
            )
        except OSError:
            failure = "process-start"
            return None, b"", b"", failure
        streams = {"stdout": process.stdout, "stderr": process.stderr}
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
                available = MAX_CHILD_LOG_BYTES - len(buffer)
                try:
                    chunk = os.read(key.fd, min(CHUNK_SIZE, available + 1))
                except OSError:
                    failure = "capture-error"
                    _terminate_process_group(process)
                    break
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                retained = chunk[:available]
                try:
                    if retained:
                        _write_all(files[name], retained)
                except OSError:
                    failure = "capture-error"
                    _terminate_process_group(process)
                    break
                buffer.extend(retained)
                if len(chunk) > available:
                    failure = "output-limit"
                    _terminate_process_group(process)
                    break
            if failure is not None:
                break
        if process.poll() is None:
            remaining = deadline - time.monotonic()
            try:
                returncode = process.wait(timeout=max(0.0, remaining))
            except subprocess.TimeoutExpired:
                failure = "timeout"
                _terminate_process_group(process)
                returncode = process.returncode
        else:
            returncode = process.returncode
    finally:
        try:
            selector.close()
        except OSError:
            pass
        if process is not None:
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        pass
        for fd in files.values():
            try:
                os.fsync(fd)
            except OSError:
                pass
            os.close(fd)
    return returncode, bytes(buffers["stdout"]), bytes(buffers["stderr"]), failure


def _input_reference(
    inputs_dir: Path,
    value: Any,
    label: str,
    seen_files: set[str],
) -> tuple[Path, str]:
    if not isinstance(value, dict) or not isinstance(value.get("file"), str):
        raise PreflightError("release-plan", f"{label} reference is missing or malformed")
    name = value["file"]
    if (
        not name
        or len(name.encode("utf-8", errors="surrogatepass")) > 128
        or name in {".", ".."}
        or "/" in name
        or "\\" in name
        or Path(name).name != name
        or any(ord(character) < 33 or ord(character) > 126 for character in name)
    ):
        raise PreflightError("release-plan", f"{label} reference escapes the inputs directory")
    if name in seen_files:
        raise PreflightError("release-plan", "release-plan documents contain duplicate file references")
    seen_files.add(name)
    claimed = value.get("sha256")
    if claimed is not None and (not isinstance(claimed, str) or not HEX64.fullmatch(claimed)):
        raise PreflightError("release-plan", f"{label} reference digest is malformed")
    path = inputs_dir / name
    digest, _identity = _measure_file(path, label)
    if claimed is not None and claimed != digest:
        raise PreflightError("input-integrity", f"{label} differs from the validated producer plan")
    return path, digest


def _selected_matrix(raw: str) -> tuple[list[dict[str, str]], str]:
    encoded = raw.encode("utf-8", errors="surrogatepass")
    if not encoded or len(encoded) > MAX_MATRIX_BYTES:
        raise PreflightError("selected-matrix", "selected host matrix exceeds its size limit")
    document = _safe_json(encoded, "selected-matrix")
    if not isinstance(document, dict) or set(document) != {"include"} or not isinstance(document["include"], list):
        raise PreflightError("selected-matrix", "selected host matrix has an unexpected shape")
    if len(document["include"]) > 1024:
        raise PreflightError("selected-matrix", "selected host matrix has too many lanes")
    lanes: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for item in document["include"]:
        if not isinstance(item, dict) or set(item) != {"group_id", "host", "profile", "runner"}:
            raise PreflightError("selected-matrix", "selected host matrix lane is malformed")
        group_id = _valid_label(item.get("group_id"), "selected matrix group id")
        host = _valid_label(item.get("host"), "selected matrix host")
        profile = _valid_label(item.get("profile"), "selected matrix profile")
        runner = _valid_label(item.get("runner"), "selected matrix runner")
        key = (group_id, host, profile)
        if key in seen:
            raise PreflightError("selected-matrix", "selected host matrix contains duplicate lanes")
        seen.add(key)
        lanes.append({"group_id": group_id, "host": host, "profile": profile, "runner": runner})
    return lanes, hashlib.sha256(encoded).hexdigest()


def _load_and_validate_plan(
    raw: bytes,
    inputs_dir: Path,
    inputs_sha256: str,
    host: str,
    requested: list[dict[str, str]],
) -> tuple[
    dict[str, Any],
    list[dict[str, str]],
    dict[str, dict[str, dict[str, Any]]],
    dict[str, dict[str, dict[str, Any]]],
]:
    plan = _safe_json(raw, "release-plan")
    if (
        not isinstance(plan, dict)
        or plan.get("schema") != "aros-toolchain-producer-stage-v2"
        or plan.get("operation") != "release-plan"
        or plan.get("assurance") != "input-binding-only"
        or plan.get("inputs_sha256") != inputs_sha256
        or not isinstance(plan.get("groups"), list)
        or not isinstance(plan.get("lanes"), list)
    ):
        raise PreflightError("release-plan", "producer returned an unexpected release-plan document")
    lanes = plan["lanes"]
    if type(plan.get("lane_count")) is not int or plan["lane_count"] != len(lanes):
        raise PreflightError("release-plan", "producer release-plan lane count is inconsistent")
    if len(lanes) > MAX_JSON_BYTES // 64:
        raise PreflightError("release-plan", "producer release-plan has too many lanes")

    groups: dict[str, dict[str, Any]] = {}
    seen_files: set[str] = set()
    group_docs: dict[str, dict[str, dict[str, Any]]] = {}
    for group in plan["groups"]:
        if not isinstance(group, dict):
            raise PreflightError("release-plan", "producer release-plan group is malformed")
        group_id = _valid_label(group.get("group_id"), "release-plan group id")
        if group_id in groups:
            raise PreflightError("release-plan", "producer release-plan contains duplicate group ids")
        groups[group_id] = group
        files: dict[str, Any] = {}
        for key in ("source_lock", "profiles"):
            path, digest = _input_reference(inputs_dir, group.get(key), f"{group_id} {key}", seen_files)
            files[key] = {"path": path, "sha256": digest}
        group_docs[group_id] = files

    requested_by_key = {
        (lane["group_id"], lane["host"], lane["profile"]): lane
        for lane in requested
        if lane["host"] == host
    }
    if not requested_by_key:
        raise PreflightError("selected-matrix", "selected host matrix does not contain the requested host")
    lane_keys: set[tuple[str, str, str]] = set()
    plan_lanes: dict[tuple[str, str, str], dict[str, str]] = {}
    for lane in lanes:
        if not isinstance(lane, dict):
            raise PreflightError("release-plan", "producer release-plan lane is malformed")
        lane_group = _valid_label(lane.get("group_id"), "release-plan lane group id")
        lane_host = _valid_label(lane.get("host"), "release-plan lane host")
        target_profile = _valid_label(lane.get("target_profile"), "release-plan target profile")
        key = (lane_group, lane_host, target_profile)
        if key in lane_keys:
            raise PreflightError("release-plan", "producer release-plan contains duplicate lanes")
        lane_keys.add(key)
        if lane_group not in groups:
            raise PreflightError("release-plan", "producer release-plan lane has no matching group")
        plan_lanes[key] = {"group_id": lane_group, "host": lane_host, "target_profile": target_profile}
    selected: list[dict[str, str]] = []
    selected_group_ids: set[str] = set()
    for key, matrix_lane in requested_by_key.items():
        lane = plan_lanes.get(key)
        if lane is None:
            raise PreflightError("release-plan", "selected matrix lane is unknown to the validated producer plan")
        selected_group_ids.add(lane["group_id"])
        selected.append({**lane, "runner": matrix_lane["runner"]})
    if len(selected) > MAX_SELECTED_LANES:
        raise PreflightError("release-plan", "producer selected-host lane count exceeds its limit")

    selected_groups = {group_id: group_docs[group_id] for group_id in selected_group_ids}
    return plan, selected, group_docs, selected_groups


def _input_snapshot_for_call(
    inputs_dir: Path,
    inputs_sha256: str,
    groups: dict[str, dict[str, dict[str, Any]]],
) -> dict[str, tuple[str, tuple[int, ...]]]:
    snapshot: dict[str, tuple[str, tuple[int, ...]]] = {}
    collection_path = inputs_dir / INPUTS_NAME
    collection_digest, collection_identity = _measure_file(collection_path, "release-input collection")
    if collection_digest != inputs_sha256:
        raise PreflightError("input-integrity", "release-input collection changed around a producer call")
    snapshot[str(collection_path)] = (collection_digest, collection_identity)
    for group in groups.values():
        for field in ("source_lock", "profiles"):
            path = group[field]["path"]
            digest, identity = _measure_file(path, f"selected {field}")
            if digest != group[field]["sha256"]:
                raise PreflightError("input-integrity", f"selected {field} differs from the validated producer plan")
            snapshot[str(path)] = (digest, identity)
    return snapshot


def _verify_input_snapshot(snapshot: dict[str, tuple[str, tuple[int, ...]]]) -> None:
    for path_text, expected in snapshot.items():
        digest, identity = _measure_file(Path(path_text), "selected release input")
        if (digest, identity) != expected:
            raise PreflightError("input-integrity", "selected release inputs changed around a producer call")


def _validate_host_report(
    raw: bytes,
    *,
    lane: dict[str, str],
    source_lock_sha256: str,
    profiles_sha256: str,
    python_dir: Path,
) -> None:
    report = _safe_json(raw, "host-preflight")
    if (
        not isinstance(report, dict)
        or report.get("schema") != REPORT_SCHEMA
        or report.get("assurance") != REPORT_ASSURANCE
        or not isinstance(report.get("inputs"), dict)
        or not isinstance(report.get("host_preflight"), dict)
        or not isinstance(report.get("python"), dict)
    ):
        raise PreflightError("host-preflight", "producer returned an unexpected host-preflight document")
    inputs = report["inputs"]
    observed = report["host_preflight"]
    python = report["python"]
    if (
        inputs.get("source_lock_sha256") != source_lock_sha256
        or inputs.get("profiles_sha256") != profiles_sha256
        or observed.get("host") != lane["host"]
        or observed.get("profile") != lane["target_profile"]
        or python.get("environment_dir") != str(python_dir)
        or not isinstance(python.get("packages"), list)
    ):
        raise PreflightError("host-preflight", "producer host-preflight report does not match its selected lane")


class Runner:
    def __init__(self, arguments: argparse.Namespace):
        self.inputs_dir = _absolute_directory(arguments.inputs_dir, "inputs directory")
        self.cache_dir = _absolute_directory(arguments.cache_dir, "cache directory")
        self.output = _absolute_new_directory(arguments.output_dir)
        self.host = _valid_label(arguments.host, "requested host")
        self.selected_matrix, self.selected_matrix_sha256 = _selected_matrix(arguments.selected_matrix)
        raw_aros = Path(arguments.aros)
        if not raw_aros.is_absolute() or ".." in raw_aros.parts:
            raise PreflightError("input-validation", "aros must be an absolute CLI path")
        try:
            self.aros_path = raw_aros.resolve(strict=True)
        except OSError:
            raise PreflightError("input-validation", "aros CLI is unavailable") from None
        if self.aros_path != raw_aros:
            raise PreflightError("input-validation", "aros CLI path must not use linked components")
        if _path_overlap(self.output, self.inputs_dir) or _path_overlap(self.output, self.cache_dir) or _path_overlap(
            self.output, self.aros_path
        ):
            raise PreflightError("input-validation", "output directory overlaps a selected input or tool")
        if _path_overlap(self.inputs_dir, self.cache_dir):
            raise PreflightError("input-validation", "inputs and cache directories overlap")
        if _path_overlap(self.aros_path, self.inputs_dir) or _path_overlap(self.aros_path, self.cache_dir):
            raise PreflightError("input-validation", "aros CLI overlaps selected input or cache data")

        collection_path = self.inputs_dir / INPUTS_NAME
        self.inputs_sha256, _identity = _measure_file(collection_path, "release-input collection")
        expected_aros_sha256 = arguments.aros_sha256
        if not isinstance(expected_aros_sha256, str) or not HEX64.fullmatch(expected_aros_sha256):
            raise PreflightError("input-validation", "aros SHA-256 selector is malformed")
        aros_sha256, _identity = _measure_file(
            self.aros_path,
            "aros CLI",
            maximum_size=MAX_EXECUTABLE_BYTES,
        )
        if aros_sha256 != expected_aros_sha256:
            raise PreflightError("input-validation", "aros CLI differs from its verified interface receipt")
        try:
            self.aros = RUNTIME_INTERFACE.HeldExecutable(self.aros_path, expected_aros_sha256)
        except RUNTIME_INTERFACE.PreflightError:
            raise PreflightError("input-validation", "aros CLI is not a stable executable") from None
        try:
            _create_private_output(self.output)
        except BaseException:
            self.aros.close()
            raise
        self.started = time.monotonic()
        self.summary: dict[str, Any] = {
            "schema": SCHEMA,
            "assurance": ASSURANCE,
            "status": "running",
            "host": self.host,
            "inputs_sha256": self.inputs_sha256,
            "aros_sha256": aros_sha256,
            "selected_matrix_sha256": self.selected_matrix_sha256,
            "selected_lanes": [],
        }

    def _write_summary(self) -> None:
        raw = (json.dumps(self.summary, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        if len(raw) > MAX_JSON_BYTES:
            raise PreflightError("summary-write", "native host preflight summary exceeds its size limit")
        path = self.output / SUMMARY_NAME
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
        fd = -1
        try:
            fd = os.open(path, flags, 0o600)
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise OSError
            os.fchmod(fd, 0o600)
            _write_all(fd, raw)
            os.fsync(fd)
        except OSError:
            raise PreflightError("summary-write", "native host preflight summary could not be retained") from None
        finally:
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass

    def _run_command(
        self,
        command: list[str],
        *,
        step: str,
        stdout_path: Path,
        stderr_path: Path,
        timeout: int,
        snapshot: dict[str, tuple[str, tuple[int, ...]]],
    ) -> bytes:
        if time.monotonic() - self.started > MAX_RUN_SECONDS:
            raise PreflightError(step, "native host preflight exceeded its total time limit")
        _verify_input_snapshot(snapshot)
        try:
            returncode, stdout, _stderr, failure = _capture_child(
                self.aros,
                command,
                cwd=self.inputs_dir,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
                timeout=timeout,
            )
        finally:
            try:
                self.aros.verify()
                _verify_input_snapshot(snapshot)
            except (RUNTIME_INTERFACE.PreflightError, PreflightError):
                raise PreflightError("input-integrity", "selected input or aros CLI changed around a producer call") from None
        if failure is not None:
            raise PreflightError(step, f"producer command failed: {failure}", returncode=returncode)
        if returncode != 0:
            raise PreflightError(step, "producer command returned a nonzero status", returncode=returncode)
        return stdout

    def run(self) -> int:
        self._write_summary()
        try:
            self._run()
        except PreflightError as error:
            self.summary["status"] = "failed"
            self.summary["failed_step"] = error.step
            self.summary["failure"] = error.reason
            if error.returncode is not None:
                self.summary["returncode"] = error.returncode
            self._write_summary()
            print(f"native host preflight failed: {error.step}", file=sys.stderr)
            return 1
        finally:
            self.aros.close()
        self.summary["status"] = "passed"
        self._write_summary()
        return 0

    def _run(self) -> None:
        initial_snapshot = _input_snapshot_for_call(self.inputs_dir, self.inputs_sha256, {})
        plan_stdout = self.output / "plan.stdout.log"
        plan_stderr = self.output / "plan.stderr.log"
        plan_raw = self._run_command(
            [
                str(self.aros_path),
                "toolchain",
                "producer",
                "release-plan",
                "--directory",
                str(self.inputs_dir),
                "--inputs-sha256",
                self.inputs_sha256,
                "--format",
                "json",
            ],
            step="release-plan",
            stdout_path=plan_stdout,
            stderr_path=plan_stderr,
            timeout=PLAN_TIMEOUT_SECONDS,
            snapshot=initial_snapshot,
        )
        plan, lanes, all_groups, lane_groups = _load_and_validate_plan(
            plan_raw, self.inputs_dir, self.inputs_sha256, self.host, self.selected_matrix
        )
        if set(lane_groups) != {lane["group_id"] for lane in lanes}:
            raise PreflightError("release-plan", "selected lanes have missing or ambiguous groups")

        # The producer response is kept byte-for-byte after strict JSON and
        # lane/group validation has succeeded.
        try:
            os.rename(plan_stdout, self.output / "validated-plan.json")
        except OSError:
            raise PreflightError("output-write", "validated release plan could not be retained") from None
        self.summary["selected_lanes"] = [
            {
                "group_id": lane["group_id"],
                "host": lane["host"],
                "target_profile": lane["target_profile"],
                "runner": lane["runner"],
                "status": "pending",
            }
            for lane in lanes
        ]
        self._write_summary()

        probe_snapshot = _input_snapshot_for_call(self.inputs_dir, self.inputs_sha256, all_groups)
        for index, lane in enumerate(lanes, start=1):
            group = lane_groups[lane["group_id"]]
            python_dir = self.output / f"python-{index}"
            try:
                python_dir.lstat()
            except FileNotFoundError:
                pass
            except OSError:
                raise PreflightError(f"host-preflight-{index}", "Python destination cannot be inspected safely") from None
            else:
                raise PreflightError(f"host-preflight-{index}", "Python destination is already occupied")

            stdout_path = self.output / f"stdout-{index}.log"
            stderr_path = self.output / f"stderr-{index}.log"
            summary_lane = self.summary["selected_lanes"][index - 1]
            summary_lane["report"] = f"report-{index}.json"
            summary_lane["stderr_log"] = stderr_path.name
            try:
                report_raw = self._run_command(
                    [
                        str(self.aros_path),
                        "toolchain",
                        "producer",
                        "host-preflight",
                        "--source-lock",
                        str(group["source_lock"]["path"]),
                        "--profiles",
                        str(group["profiles"]["path"]),
                        "--preset",
                        lane["target_profile"],
                        "--host",
                        lane["host"],
                        "--cache-dir",
                        str(self.cache_dir),
                        "--python-env-dir",
                        str(python_dir),
                    ],
                    step=f"host-preflight-{index}",
                    stdout_path=stdout_path,
                    stderr_path=stderr_path,
                    timeout=HOST_PREFLIGHT_TIMEOUT_SECONDS,
                    snapshot=probe_snapshot,
                )
                _validate_host_report(
                    report_raw,
                    lane=lane,
                    source_lock_sha256=group["source_lock"]["sha256"],
                    profiles_sha256=group["profiles"]["sha256"],
                    python_dir=python_dir,
                )
                try:
                    python_metadata = python_dir.lstat()
                except OSError:
                    raise PreflightError(
                        f"host-preflight-{index}", "producer Python environment is unavailable"
                    ) from None
                if (
                    not stat.S_ISDIR(python_metadata.st_mode)
                    or stat.S_ISLNK(python_metadata.st_mode)
                    or python_metadata.st_uid != os.geteuid()
                    or stat.S_IMODE(python_metadata.st_mode) != 0o700
                ):
                    raise PreflightError(
                        f"host-preflight-{index}", "producer Python environment is not private"
                    )
                os.rename(stdout_path, self.output / f"report-{index}.json")
            except PreflightError:
                summary_lane["status"] = "failed"
                self._write_summary()
                raise
            except OSError:
                summary_lane["status"] = "failed"
                self._write_summary()
                raise PreflightError(f"host-preflight-{index}", "validated host report could not be retained") from None
            summary_lane["status"] = "passed"
            self._write_summary()


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--aros", required=True, help="absolute selected aros CLI executable")
    parser.add_argument("--aros-sha256", required=True, help="SHA-256 from the verified runtime interface receipt")
    parser.add_argument("--selected-matrix", required=True, help="exact selected matrix JSON from preparation")
    parser.add_argument("--inputs-dir", required=True, help="absolute producer release-input directory")
    parser.add_argument("--cache-dir", required=True, help="absolute real source-cache directory")
    parser.add_argument("--host", required=True, help="native host selected by the workflow")
    parser.add_argument("--output-dir", required=True, help="absolute fresh evidence directory")
    return parser.parse_args()


def main() -> int:
    try:
        runner = Runner(_arguments())
    except PreflightError as error:
        print(f"native host preflight failed: {error.step}", file=sys.stderr)
        return 1
    return runner.run()


if __name__ == "__main__":
    raise SystemExit(main())
