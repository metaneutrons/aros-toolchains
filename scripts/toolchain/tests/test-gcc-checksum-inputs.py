#!/usr/bin/env python3
"""Diagnostic-only regressions for the GCC checksum input observer."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
OBSERVER = REPOSITORY_ROOT / "scripts/toolchain/observe-gcc-checksum-inputs.py"


def _write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def _snapshot(root: Path) -> dict[str, tuple[object, ...]]:
    snapshot: dict[str, tuple[object, ...]] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        status = path.lstat()
        common = (status.st_mode, status.st_size, status.st_mtime_ns, status.st_ctime_ns)
        if path.is_symlink():
            snapshot[relative] = ("symlink", os.readlink(path), *common)
        elif path.is_dir():
            snapshot[relative] = ("directory", *common)
        elif path.is_file():
            snapshot[relative] = (
                "file",
                hashlib.sha256(path.read_bytes()).hexdigest(),
                *common,
            )
        else:
            snapshot[relative] = ("other", *common)
    return snapshot


class GccChecksumInputsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="gcc-checksum-inputs-test-")
        self.base = Path(self.temporary.name)
        self.native_root = self.base / "native-lifecycle"
        self.static_root = self.base / "static-dependencies"
        self.gcc_dir = self.native_root / "build/bin/host/gcc/gcc"
        self.allowed_roots = (self.native_root, self.static_root)

        _write(self.gcc_dir / "cp/cp-lang.o", b"cp-language-object-prefix" + bytes(range(32)))
        _write(self.gcc_dir / "c-family/stub-objc.o", b"objc-object-prefix" + bytes(range(64)))
        _write(self.gcc_dir / "backend/simple-diagnostic-path.o", b"backend-object-prefix" + bytes(range(17)))
        _write(self.gcc_dir / "libbackend.a", b"backend-archive-prefix" + bytes(range(45)))
        _write(self.gcc_dir / "main.o", b"main-object-prefix" + bytes(range(21)))
        _write(self.gcc_dir / "libcommon.a", b"common-archive-prefix" + bytes(range(19)))
        _write(self.native_root / "build/bin/host/gcc/libcpp/libcpp.a", b"cpp-archive-prefix" + bytes(range(23)))
        _write(self.native_root / "build/bin/host/gcc/libcody/libcody.a", b"cody-archive-prefix" + bytes(range(27)))
        _write(self.static_root / "libdecnumber.a", b"decnumber-archive-prefix" + bytes(range(29)))
        self.checksum_options = b"ld -first-option -second-option\r\n"
        _write(self.gcc_dir / "checksum-options", self.checksum_options)
        self.checksum_source = b'#include "config.h"\nunsigned char checksum[16] = { 0 };\n'
        _write(self.gcc_dir / "cc1plus-checksum.cc", self.checksum_source)
        self.write_makefile(
            "CXX_OBJS = cp/cp-lang.o c-family/stub-objc.o\n"
            "BACKEND = backend/simple-diagnostic-path.o libbackend.a main.o ../libcpp/libcpp.a\n"
            "CODYLIB = ../libcody/libcody.a\n"
            "LIBDEPS = libcommon.a ../libcpp/libcpp.a ../../../../../../static-dependencies/libdecnumber.a\n"
            ".PHONY: all\n"
            "all:\n"
            "\tprintf 'must not run\\n' > build-recipe-ran\n"
            ".PHONY: force-makefile-remake\n"
            "force-makefile-remake:\n"
            "Makefile: force-makefile-remake\n"
            "\tprintf 'must not remake\\n' > makefile-remake-ran\n"
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_makefile(self, content: str) -> None:
        path = self.gcc_dir / "Makefile"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def run_observer(
        self,
        *,
        output: Path | None = None,
        make_program: Path | None = None,
        allowed_roots: tuple[Path, ...] | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        command = [
            sys.executable,
            str(OBSERVER),
            "--gcc-build-dir",
            str(self.gcc_dir),
        ]
        for root in allowed_roots or self.allowed_roots:
            command.extend(("--allowed-root", str(root)))
        if output is not None:
            command.extend(("--output", str(output)))
        if make_program is not None:
            command.extend(("--make-program", str(make_program)))
        return subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)

    def snapshot_roots(self) -> dict[str, dict[str, tuple[object, ...]]]:
        return {str(root): _snapshot(root) for root in self.allowed_roots}

    def assert_rejected_without_tree_change(self, expected_message: str, **kwargs: object) -> None:
        before = self.snapshot_roots()
        result = self.run_observer(**kwargs)
        self.assertNotEqual(result.returncode, 0, result.stdout.decode("utf-8", errors="replace"))
        self.assertIn(expected_message, result.stderr.decode("utf-8", errors="replace"))
        self.assertEqual(before, self.snapshot_roots())

    def test_observes_ordered_inputs_and_preserves_fixture(self) -> None:
        before = self.snapshot_roots()
        result = self.run_observer()
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", errors="replace"))
        self.assertEqual(result.stderr, b"")
        observation = json.loads(result.stdout)

        expected_arguments = [
            "cp/cp-lang.o",
            "c-family/stub-objc.o",
            "backend/simple-diagnostic-path.o",
            "libbackend.a",
            "main.o",
            "../libcpp/libcpp.a",
            "../libcody/libcody.a",
            "libcommon.a",
            "../libcpp/libcpp.a",
            "../../../../../../static-dependencies/libdecnumber.a",
            "checksum-options",
        ]
        records = observation["inputs"]
        self.assertEqual([record["argument"] for record in records], expected_arguments)
        self.assertEqual(observation["scope"], "diagnostic-only")
        self.assertEqual(observation["allowed_roots"][0]["label"], "allowed-root-1")
        self.assertEqual(records[9]["allowed_root"], "allowed-root-2")

        source_bytes = [
            (self.gcc_dir / "cp/cp-lang.o").read_bytes(),
            (self.gcc_dir / "c-family/stub-objc.o").read_bytes(),
            (self.gcc_dir / "backend/simple-diagnostic-path.o").read_bytes(),
            (self.gcc_dir / "libbackend.a").read_bytes(),
            (self.gcc_dir / "main.o").read_bytes(),
            (self.native_root / "build/bin/host/gcc/libcpp/libcpp.a").read_bytes(),
            (self.native_root / "build/bin/host/gcc/libcody/libcody.a").read_bytes(),
            (self.gcc_dir / "libcommon.a").read_bytes(),
            (self.native_root / "build/bin/host/gcc/libcpp/libcpp.a").read_bytes(),
            (self.static_root / "libdecnumber.a").read_bytes(),
            self.checksum_options,
        ]
        for record, content in zip(records, source_bytes, strict=True):
            self.assertEqual(record["size_bytes"], len(content))
            self.assertEqual(record["sha256_full"], hashlib.sha256(content).hexdigest())
            self.assertEqual(
                record["sha256_suffix"],
                hashlib.sha256(content[16:]).hexdigest(),
            )
            self.assertEqual(record["suffix_offset_bytes"], 16)
        self.assertEqual(observation["checksum_options_raw_text"]["raw_text"], self.checksum_options.decode())
        self.assertEqual(observation["cc1plus_checksum_cc"]["raw_text"], self.checksum_source.decode())
        self.assertFalse((self.gcc_dir / "build-recipe-ran").exists())
        self.assertFalse((self.gcc_dir / "makefile-remake-ran").exists())
        self.assertEqual(before, self.snapshot_roots())

    def test_output_file_is_created_once_and_existing_output_is_preserved(self) -> None:
        output = self.base / "evidence/gcc-checksum-inputs.json"
        output.parent.mkdir(parents=True)
        first = self.run_observer(output=output)
        self.assertEqual(first.returncode, 0, first.stderr.decode("utf-8", errors="replace"))
        parsed = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(parsed["schema"], "gcc-checksum-input-observation-v1")
        original = output.read_bytes()
        self.assert_rejected_without_tree_change("already exists", output=output)
        self.assertEqual(output.read_bytes(), original)

    def test_missing_input_is_rejected(self) -> None:
        self.write_makefile(
            "CXX_OBJS = cp/missing.o\n"
            "BACKEND = backend/simple-diagnostic-path.o\n"
            "CODYLIB = ../libcody/libcody.a\n"
            "LIBDEPS = libcommon.a\n"
        )
        self.assert_rejected_without_tree_change("missing or unreadable")

    def test_input_outside_all_allowed_roots_is_rejected(self) -> None:
        outside = self.base / "outside.o"
        _write(outside, b"outside-object-prefix-and-suffix")
        self.write_makefile(
            "CXX_OBJS = ../../../../../../outside.o\n"
            "BACKEND = backend/simple-diagnostic-path.o\n"
            "CODYLIB = ../libcody/libcody.a\n"
            "LIBDEPS = libcommon.a\n"
        )
        self.assert_rejected_without_tree_change("outside all --allowed-root")

    def test_symlink_input_is_rejected(self) -> None:
        link = self.gcc_dir / "cp/linked.o"
        link.symlink_to(self.gcc_dir / "cp/cp-lang.o")
        self.write_makefile(
            "CXX_OBJS = cp/linked.o\n"
            "BACKEND = backend/simple-diagnostic-path.o\n"
            "CODYLIB = ../libcody/libcody.a\n"
            "LIBDEPS = libcommon.a\n"
        )
        self.assert_rejected_without_tree_change("uses a symlink")

    def test_malformed_make_variable_list_is_rejected(self) -> None:
        self.write_makefile(
            "CXX_OBJS = cp/cp-lang.o -lnot-a-file\n"
            "BACKEND = backend/simple-diagnostic-path.o\n"
            "CODYLIB = ../libcody/libcody.a\n"
            "LIBDEPS = libcommon.a\n"
        )
        self.assert_rejected_without_tree_change("must be a file path")

    def test_multiline_make_variable_value_is_rejected(self) -> None:
        # GNU make emits expanded lists on one line; an embedded newline is not
        # representable as an input path and must fail the marker framing.
        self.write_makefile(
            "define CXX_OBJS\n"
            "cp/cp-lang.o\n"
            "c-family/stub-objc.o\n"
            "endef\n"
            "BACKEND = backend/simple-diagnostic-path.o\n"
            "CODYLIB = ../libcody/libcody.a\n"
            "LIBDEPS = libcommon.a\n"
        )
        self.assert_rejected_without_tree_change("malformed or multi-line")

    def test_failed_make_is_rejected(self) -> None:
        fake_bin = self.base / "fake-bin"
        fake_make = fake_bin / "make"
        _write(fake_make, b"#!/bin/sh\nexit 23\n")
        fake_make.chmod(0o755)
        self.assert_rejected_without_tree_change("exit 23", make_program=fake_make)

    def test_filesystem_root_is_rejected_as_an_allowed_root(self) -> None:
        self.assert_rejected_without_tree_change(
            "filesystem root is too broad",
            allowed_roots=(Path("/"),),
        )

    def test_overlapping_allowed_roots_are_rejected(self) -> None:
        self.assert_rejected_without_tree_change(
            "must be canonical, distinct, and non-overlapping",
            allowed_roots=(self.native_root, self.native_root / "build"),
        )


if __name__ == "__main__":
    unittest.main()
