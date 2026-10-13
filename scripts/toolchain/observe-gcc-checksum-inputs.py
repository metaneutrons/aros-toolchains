#!/usr/bin/env python3
"""Record GCC 16.2 cc1plus checksum inputs for diagnostic comparison only."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid


MAKE_VARIABLES = ("CXX_OBJS", "BACKEND", "CODYLIB", "LIBDEPS")
CHECKSUM_PREFIX_BYTES = 16
MAX_MAKE_OUTPUT_BYTES = 512 * 1024
MAX_INPUT_COUNT = 20_000
MAX_SMALL_TEXT_BYTES = 64 * 1024
SAFE_MAKE_WORD = re.compile(r"^[A-Za-z0-9._/+,-]+$")
EXPECTED_INPUT_SUFFIX = re.compile(r"(?:\.(?:o|obj|a|dylib|dll|lib)|\.so(?:\.[0-9]+)*)$")


class ObservationError(Exception):
    """An input could not be observed without making assumptions."""


class AllowedRoot:
    def __init__(self, index: int, argument: str):
        self.label = f"allowed-root-{index}"
        self.lexical = Path(os.path.abspath(argument))
        try:
            status = self.lexical.lstat()
        except OSError as error:
            raise ObservationError(f"{self.label} is missing or unreadable: {self.lexical}: {error}") from error
        if stat.S_ISLNK(status.st_mode):
            raise ObservationError(f"{self.label} must not be a symlink: {self.lexical}")
        if not stat.S_ISDIR(status.st_mode):
            raise ObservationError(f"{self.label} is not a directory: {self.lexical}")
        try:
            self.canonical = self.lexical.resolve(strict=True)
        except OSError as error:
            raise ObservationError(f"cannot resolve {self.label}: {error}") from error
        if self.canonical == Path(self.canonical.anchor):
            raise ObservationError(f"filesystem root is too broad for {self.label}: {self.canonical}")


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _validate_independent_roots(roots: list[AllowedRoot]) -> None:
    if not roots:
        raise ObservationError("at least one --allowed-root is required")
    for index, root in enumerate(roots):
        for other in roots[index + 1 :]:
            if _is_within(root.canonical, other.canonical) or _is_within(
                other.canonical, root.canonical
            ):
                raise ObservationError(
                    "allowed roots must be canonical, distinct, and non-overlapping: "
                    f"{root.label} and {other.label}"
                )
            if _is_within(root.lexical, other.lexical) or _is_within(
                other.lexical, root.lexical
            ):
                raise ObservationError(
                    "allowed root arguments overlap lexically: "
                    f"{root.label} and {other.label}"
                )


def _root_for_lexical_path(path: Path, roots: list[AllowedRoot], description: str) -> AllowedRoot:
    matches = [root for root in roots if _is_within(path, root.lexical)]
    if len(matches) != 1:
        if not matches:
            raise ObservationError(f"{description} is outside all --allowed-root paths: {path}")
        raise ObservationError(f"{description} has an ambiguous allowed root: {path}")
    return matches[0]


def _reject_symlink_components(root: AllowedRoot, path: Path, description: str) -> None:
    try:
        relative = path.relative_to(root.lexical)
    except ValueError as error:
        raise ObservationError(f"{description} is outside {root.label}: {path}") from error

    current = root.lexical
    for component in relative.parts:
        current = current / component
        try:
            status = current.lstat()
        except OSError as error:
            raise ObservationError(f"{description} is missing or unreadable: {current}: {error}") from error
        if stat.S_ISLNK(status.st_mode):
            raise ObservationError(f"{description} contains a symlink: {current}")


def _canonical_under_root(
    lexical_path: Path,
    root: AllowedRoot,
    description: str,
    *,
    expect_directory: bool = False,
) -> Path:
    _reject_symlink_components(root, lexical_path, description)
    try:
        canonical = lexical_path.resolve(strict=True)
    except OSError as error:
        raise ObservationError(f"{description} is missing or cannot be resolved: {lexical_path}: {error}") from error
    if not _is_within(canonical, root.canonical):
        raise ObservationError(f"{description} escapes {root.label} after canonicalization: {canonical}")
    try:
        status = canonical.stat()
    except OSError as error:
        raise ObservationError(f"{description} is unreadable: {canonical}: {error}") from error
    if expect_directory and not stat.S_ISDIR(status.st_mode):
        raise ObservationError(f"{description} is not a directory: {canonical}")
    if not expect_directory and not stat.S_ISREG(status.st_mode):
        raise ObservationError(f"{description} is not a regular file: {canonical}")
    return canonical


def _select_gcc_build_dir(argument: str, roots: list[AllowedRoot]) -> tuple[Path, Path, AllowedRoot]:
    lexical = Path(os.path.abspath(argument))
    root = _root_for_lexical_path(lexical, roots, "GCC build directory")
    canonical = _canonical_under_root(
        lexical,
        root,
        "GCC build directory",
        expect_directory=True,
    )
    return lexical, canonical, root


def _check_make_word(argument: str) -> None:
    if not argument or not SAFE_MAKE_WORD.fullmatch(argument):
        raise ObservationError(f"malformed or unsafe GCC checksum input word: {argument!r}")
    if not Path(argument).is_absolute() and argument.startswith("-"):
        raise ObservationError(f"GCC checksum input must be a file path, not an option: {argument!r}")
    if not EXPECTED_INPUT_SUFFIX.search(argument):
        raise ObservationError(f"unexpected GCC checksum input name: {argument!r}")


def _parse_make_output(output: bytes, marker: str) -> dict[str, list[str]]:
    if len(output) > MAX_MAKE_OUTPUT_BYTES:
        raise ObservationError("GNU make observer output exceeds the bounded limit")
    try:
        lines = output.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError as error:
        raise ObservationError("GNU make observer output is not valid UTF-8") from error

    values: dict[str, list[str]] = {}
    cursor = 0
    for variable in MAKE_VARIABLES:
        begin = f"__GCC_CHECKSUM_{marker}_{variable}_BEGIN__"
        end = f"__GCC_CHECKSUM_{marker}_{variable}_END__"
        if cursor >= len(lines) or lines[cursor] != begin:
            raise ObservationError(f"GNU make did not emit an unambiguous {variable} marker")
        cursor += 1
        if cursor >= len(lines):
            raise ObservationError(f"GNU make omitted the {variable} value")
        raw_value = lines[cursor]
        cursor += 1
        if cursor >= len(lines) or lines[cursor] != end:
            raise ObservationError(f"GNU make emitted a malformed or multi-line {variable} value")
        cursor += 1

        words = raw_value.split()
        if not words:
            raise ObservationError(f"GCC Makefile variable {variable} is empty")
        for word in words:
            _check_make_word(word)
        values[variable] = words

    if cursor != len(lines):
        raise ObservationError("GNU make emitted unexpected output while observing checksum inputs")
    if sum(len(words) for words in values.values()) + 1 > MAX_INPUT_COUNT:
        raise ObservationError("GCC checksum input list exceeds the bounded input count")
    return values


def _observer_makefile(marker: str, target: str) -> str:
    lines: list[str] = []
    for variable in MAKE_VARIABLES:
        lines.extend(
            (
                f"$(info __GCC_CHECKSUM_{marker}_{variable}_BEGIN__)",
                f"$(info $({variable}))",
                f"$(info __GCC_CHECKSUM_{marker}_{variable}_END__)",
            )
        )
    lines.extend((f".PHONY: {target}", f"{target}:", ""))
    return "\n".join(lines)


def _run_bounded(
    command: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
) -> tuple[int, bytes, bytes]:
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
    )
    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    output_by_stream = {process.stdout: bytearray(), process.stderr: bytearray()}
    limits = {process.stdout: MAX_MAKE_OUTPUT_BYTES, process.stderr: 64 * 1024}
    for stream in output_by_stream:
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ)

    deadline = time.monotonic() + 60
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ObservationError("GNU make checksum input observation timed out")
            ready = selector.select(remaining)
            for key, _ in ready:
                stream = key.fileobj
                try:
                    block = os.read(stream.fileno(), 64 * 1024)
                except OSError as error:
                    raise ObservationError(f"cannot read GNU make observer output: {error}") from error
                if not block:
                    selector.unregister(stream)
                    stream.close()
                    continue
                collected = output_by_stream[stream]
                collected.extend(block)
                if len(collected) > limits[stream]:
                    raise ObservationError("GNU make observer output exceeds the bounded limit")
        try:
            returncode = process.wait(timeout=max(0.1, deadline - time.monotonic()))
        except subprocess.TimeoutExpired as error:
            raise ObservationError("GNU make checksum input observation timed out") from error
        return returncode, bytes(output_by_stream[process.stdout]), bytes(output_by_stream[process.stderr])
    finally:
        selector.close()
        if process.poll() is None:
            process.kill()
            process.wait()
        for stream in output_by_stream:
            if not stream.closed:
                stream.close()


def _run_make_observer(
    gcc_dir: Path,
    roots: list[AllowedRoot],
    make_program: str,
) -> dict[str, list[str]]:
    make_path = shutil.which(make_program)
    if make_path is None:
        raise ObservationError(f"GNU make program was not found: {make_program}")

    temporary: tempfile.TemporaryDirectory[str] | None = None
    for parent_argument in (tempfile.gettempdir(), "/tmp", "/var/tmp"):
        parent = Path(parent_argument)
        try:
            parent_canonical = parent.resolve(strict=True)
        except OSError:
            continue
        if any(_is_within(parent_canonical, root.canonical) for root in roots):
            continue
        try:
            temporary = tempfile.TemporaryDirectory(prefix="gcc-checksum-observer-", dir=parent)
            break
        except OSError:
            continue
    if temporary is None:
        raise ObservationError("cannot create a temporary observer file outside all allowed roots")

    try:
        temporary_dir = Path(temporary.name).resolve(strict=True)
        if any(_is_within(temporary_dir, root.canonical) for root in roots):
            raise ObservationError("temporary observer directory overlaps an allowed root")

        marker = uuid.uuid4().hex
        target = f"__gcc_checksum_observer_{marker}"
        observer_path = Path(temporary.name) / f"observer-{marker}.mk"
        observer_path.write_text(_observer_makefile(marker, target), encoding="utf-8", newline="\n")

        environment = os.environ.copy()
        for name in ("MAKEFLAGS", "MFLAGS", "GNUMAKEFLAGS", "MAKEFILES", "MAKELEVEL", "MAKEOVERRIDES"):
            environment.pop(name, None)

        command = [
            make_path,
            "--no-print-directory",
            "--silent",
            "--no-builtin-rules",
            "--no-builtin-variables",
            "--just-print",
            "--old-file=Makefile",
            f"--old-file={observer_path}",
            "-f",
            "Makefile",
            "-f",
            str(observer_path),
            target,
        ]
        returncode, stdout, stderr = _run_bounded(command, cwd=gcc_dir, environment=environment)
        if returncode != 0:
            diagnostic = stderr.decode("utf-8", errors="replace").strip()
            raise ObservationError(
                f"GNU make checksum input observation failed with exit {returncode}"
                + (f": {diagnostic[:1000]}" if diagnostic else "")
            )
        if stderr:
            diagnostic = stderr.decode("utf-8", errors="replace").strip()
            raise ObservationError(
                "GNU make emitted stderr during checksum input observation"
                + (f": {diagnostic[:1000]}" if diagnostic else "")
            )
        return _parse_make_output(stdout, marker)
    finally:
        temporary.cleanup()


def _file_path_for_argument(
    argument: str,
    gcc_dir: Path,
    roots: list[AllowedRoot],
    description: str,
) -> tuple[Path, AllowedRoot, str]:
    argument_path = Path(argument)
    if argument_path.is_absolute():
        lexical = Path(argument_path.anchor)
        parts = argument_path.parts[1:]
    else:
        lexical = gcc_dir
        parts = argument_path.parts
    for index, component in enumerate(parts):
        if component == ".":
            continue
        if component == "..":
            lexical = lexical.parent
        else:
            lexical = lexical / component
        try:
            status = lexical.lstat()
        except OSError as error:
            raise ObservationError(
                f"{description} is missing or unreadable while resolving {argument!r}: {error}"
            ) from error
        if stat.S_ISLNK(status.st_mode):
            raise ObservationError(f"{description} path uses a symlink: {lexical}")
        if index + 1 < len(parts) and component != ".." and not stat.S_ISDIR(status.st_mode):
            raise ObservationError(f"{description} path traverses a non-directory: {lexical}")
    root = _root_for_lexical_path(lexical, roots, description)
    canonical = _canonical_under_root(lexical, root, description)
    relative = canonical.relative_to(root.canonical).as_posix()
    return canonical, root, relative


def _same_file_version(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev,
        left.st_ino,
        left.st_mode,
        left.st_size,
        left.st_mtime_ns,
        left.st_ctime_ns,
    ) == (
        right.st_dev,
        right.st_ino,
        right.st_mode,
        right.st_size,
        right.st_mtime_ns,
        right.st_ctime_ns,
    )


def _open_regular_file(path: Path, description: str) -> tuple[int, os.stat_result]:
    try:
        initial = path.lstat()
    except OSError as error:
        raise ObservationError(f"{description} is missing or unreadable: {path}: {error}") from error
    if stat.S_ISLNK(initial.st_mode):
        raise ObservationError(f"{description} is a symlink: {path}")
    if not stat.S_ISREG(initial.st_mode):
        raise ObservationError(f"{description} is not a regular file: {path}")
    if initial.st_size <= 0:
        raise ObservationError(f"{description} is empty: {path}")
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise ObservationError("this platform lacks O_NOFOLLOW; refusing to open observed inputs")
    try:
        descriptor = os.open(path, os.O_RDONLY | no_follow)
        opened = os.fstat(descriptor)
    except OSError as error:
        raise ObservationError(f"cannot open {description} without following links: {path}: {error}") from error
    if not stat.S_ISREG(opened.st_mode) or not _same_file_version(initial, opened):
        os.close(descriptor)
        raise ObservationError(f"{description} changed while it was opened: {path}")
    return descriptor, initial


def _hash_input(
    path: Path,
    description: str,
) -> dict[str, object]:
    descriptor, initial = _open_regular_file(path, description)
    full_hash = hashlib.sha256()
    suffix_sha256 = hashlib.sha256()
    read_size = 0
    try:
        with os.fdopen(descriptor, "rb", closefd=True) as source:
            offset = 0
            while True:
                block = source.read(1024 * 1024)
                if not block:
                    break
                full_hash.update(block)
                suffix_begin = max(0, CHECKSUM_PREFIX_BYTES - offset)
                if suffix_begin < len(block):
                    suffix = block[suffix_begin:]
                    suffix_sha256.update(suffix)
                read_size += len(block)
                offset += len(block)
            final = os.fstat(source.fileno())
    except OSError as error:
        raise ObservationError(f"cannot read {description}: {path}: {error}") from error
    try:
        path_status = path.lstat()
    except OSError as error:
        raise ObservationError(f"{description} changed or disappeared while being read: {path}: {error}") from error
    if not _same_file_version(initial, final) or not _same_file_version(initial, path_status):
        raise ObservationError(f"{description} changed while it was being read: {path}")
    if read_size != initial.st_size:
        raise ObservationError(f"{description} byte count changed while it was being read: {path}")
    suffix_size = max(0, initial.st_size - CHECKSUM_PREFIX_BYTES)
    return {
        "canonical_path": str(path),
        "size_bytes": initial.st_size,
        "sha256_full": full_hash.hexdigest(),
        "suffix_offset_bytes": CHECKSUM_PREFIX_BYTES,
        "suffix_size_bytes": suffix_size,
        "sha256_suffix": suffix_sha256.hexdigest(),
    }


def _read_bounded_text(path: Path, description: str, roots: list[AllowedRoot]) -> tuple[bytes, str, AllowedRoot, str]:
    root = _root_for_lexical_path(path, roots, description)
    canonical = _canonical_under_root(path, root, description)
    descriptor, initial = _open_regular_file(canonical, description)
    if initial.st_size > MAX_SMALL_TEXT_BYTES:
        os.close(descriptor)
        raise ObservationError(f"{description} exceeds {MAX_SMALL_TEXT_BYTES} bytes")
    try:
        with os.fdopen(descriptor, "rb", closefd=True) as source:
            raw = source.read(MAX_SMALL_TEXT_BYTES + 1)
            final = os.fstat(source.fileno())
    except OSError as error:
        raise ObservationError(f"cannot read {description}: {canonical}: {error}") from error
    try:
        path_status = canonical.lstat()
    except OSError as error:
        raise ObservationError(f"{description} changed or disappeared while being read: {canonical}: {error}") from error
    if not _same_file_version(initial, final) or not _same_file_version(initial, path_status):
        raise ObservationError(f"{description} changed while it was being read: {canonical}")
    if len(raw) != initial.st_size:
        raise ObservationError(f"{description} exceeded its bounded read or changed: {canonical}")
    if b"\x00" in raw:
        raise ObservationError(f"{description} contains NUL bytes: {canonical}")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ObservationError(f"{description} is not valid UTF-8: {canonical}") from error
    relative = canonical.relative_to(root.canonical).as_posix()
    return raw, text, root, relative


def _small_text_record(
    raw: bytes,
    text: str,
    path: Path,
    root: AllowedRoot,
    relative: str,
) -> dict[str, object]:
    return {
        "allowed_root": root.label,
        "relative_path": relative,
        "canonical_path": str(path),
        "size_bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "raw_text": text,
    }


def observe(
    gcc_build_dir: str,
    allowed_root_args: list[str],
    make_program: str = "make",
) -> dict[str, object]:
    roots = [AllowedRoot(index, argument) for index, argument in enumerate(allowed_root_args, start=1)]
    _validate_independent_roots(roots)
    gcc_lexical, gcc_canonical, gcc_root = _select_gcc_build_dir(gcc_build_dir, roots)

    makefile_lexical = gcc_lexical / "Makefile"
    makefile = _canonical_under_root(makefile_lexical, gcc_root, "generated GCC Makefile")
    variables = _run_make_observer(gcc_canonical, roots, make_program)

    checksum_path = gcc_lexical / "checksum-options"
    checksum_raw, checksum_text, checksum_root, checksum_relative = _read_bounded_text(
        checksum_path,
        "checksum-options",
        roots,
    )
    checksum_canonical = checksum_path.resolve(strict=True)

    input_records: list[dict[str, object]] = []
    ordinal = 0
    for variable in MAKE_VARIABLES:
        for argument in variables[variable]:
            path, root, relative = _file_path_for_argument(
                argument,
                gcc_lexical,
                roots,
                f"{variable} input {argument!r}",
            )
            record = _hash_input(path, f"{variable} input {argument!r}")
            record.update(
                {
                    "ordinal": ordinal,
                    "source_variable": variable,
                    "argument": argument,
                    "allowed_root": root.label,
                    "relative_path": relative,
                }
            )
            input_records.append(record)
            ordinal += 1

    checksum_record = _hash_input(checksum_canonical, "checksum-options input")
    checksum_record.update(
        {
            "ordinal": ordinal,
            "source_variable": "checksum-options",
            "argument": "checksum-options",
            "allowed_root": checksum_root.label,
            "relative_path": checksum_relative,
        }
    )
    input_records.append(checksum_record)

    checksum_source_lexical = gcc_lexical / "cc1plus-checksum.cc"
    try:
        checksum_source_lexical.lstat()
    except FileNotFoundError:
        checksum_source_record: dict[str, object] | None = None
    except OSError as error:
        raise ObservationError(f"cannot inspect cc1plus-checksum.cc: {error}") from error
    else:
        checksum_source_raw, checksum_source_text, checksum_source_root, checksum_source_relative = (
            _read_bounded_text(
                checksum_source_lexical,
                "cc1plus-checksum.cc",
                roots,
            )
        )
        checksum_source_canonical = checksum_source_lexical.resolve(strict=True)
        checksum_source_record = _small_text_record(
            checksum_source_raw,
            checksum_source_text,
            checksum_source_canonical,
            checksum_source_root,
            checksum_source_relative,
        )

    return {
        "schema": "gcc-checksum-input-observation-v1",
        "scope": "diagnostic-only",
        "gcc_build_dir": {
            "allowed_root": gcc_root.label,
            "relative_path": gcc_canonical.relative_to(gcc_root.canonical).as_posix(),
            "canonical_path": str(gcc_canonical),
        },
        "allowed_roots": [
            {"label": root.label, "canonical_path": str(root.canonical)} for root in roots
        ],
        "generated_makefile": str(makefile),
        "make_variables": variables,
        "inputs": input_records,
        "checksum_options_raw_text": _small_text_record(
            checksum_raw,
            checksum_text,
            checksum_canonical,
            checksum_root,
            checksum_relative,
        ),
        "cc1plus_checksum_cc": checksum_source_record,
    }


def _output_path(argument: str, roots: list[AllowedRoot]) -> Path:
    lexical = Path(os.path.abspath(argument))
    try:
        parent = lexical.parent.resolve(strict=True)
    except OSError as error:
        raise ObservationError(f"output parent does not exist or cannot be resolved: {error}") from error
    target = parent / lexical.name
    if any(_is_within(target, root.canonical) for root in roots):
        raise ObservationError("--output must be outside all allowed roots")
    if lexical.exists() or lexical.is_symlink():
        raise ObservationError(f"--output already exists: {lexical}")
    return target


def _write_output(path: Path, payload: bytes) -> None:
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | no_follow,
            0o600,
        )
    except FileExistsError as error:
        raise ObservationError(f"--output already exists: {path}") from error
    except OSError as error:
        raise ObservationError(f"cannot create --output {path}: {error}") from error
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as destination:
            destination.write(payload)
            destination.flush()
            os.fsync(destination.fileno())
    except OSError as error:
        try:
            path.unlink()
        except OSError:
            pass
        raise ObservationError(f"cannot write --output {path}: {error}") from error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gcc-build-dir", required=True, help="exact generated GCC gcc/ build directory")
    parser.add_argument(
        "--allowed-root",
        action="append",
        required=True,
        help="canonical filesystem root permitted to contain observed inputs; repeat as needed",
    )
    parser.add_argument("--output", help="new JSON output file outside every allowed root; default: stdout")
    parser.add_argument(
        "--make-program",
        default="make",
        help="GNU make executable to use (default: make from PATH)",
    )
    args = parser.parse_args(argv)

    try:
        roots = [AllowedRoot(index, argument) for index, argument in enumerate(args.allowed_root, start=1)]
        _validate_independent_roots(roots)
        output_path = _output_path(args.output, roots) if args.output else None
        observation = observe(args.gcc_build_dir, args.allowed_root, args.make_program)
        payload = (json.dumps(observation, ensure_ascii=False, indent=2, sort_keys=False) + "\n").encode(
            "utf-8"
        )
        if output_path is None:
            sys.stdout.buffer.write(payload)
        else:
            _write_output(output_path, payload)
    except (ObservationError, OSError, ValueError) as error:
        print(f"observe-gcc-checksum-inputs: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
