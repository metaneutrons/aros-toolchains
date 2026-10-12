#!/usr/bin/env python3
"""Offline tests for byte-only cache archive transport."""

from __future__ import annotations

import hashlib
import gzip
import importlib.util
import io
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "cache-archive-transport.py"
SPEC = importlib.util.spec_from_file_location("cache_archive_transport", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
transport = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = transport
SPEC.loader.exec_module(transport)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def archive_bytes(entries: list[tuple[str, str, bytes, int, str]]) -> bytes:
    """Entry tuples are name, kind, payload, mode, and optional link target."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz", format=tarfile.PAX_FORMAT) as archive:
        for name, kind, payload, mode, target in entries:
            member = tarfile.TarInfo(name)
            member.mode = mode
            if kind == "directory":
                member.type = tarfile.DIRTYPE
                member.size = 0
                archive.addfile(member)
            elif kind == "file":
                member.type = tarfile.REGTYPE
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))
            elif kind == "symlink":
                member.type = tarfile.SYMTYPE
                member.linkname = target
                archive.addfile(member)
            elif kind == "hardlink":
                member.type = tarfile.LNKTYPE
                member.linkname = target
                archive.addfile(member)
            elif kind == "fifo":
                member.type = tarfile.FIFOTYPE
                archive.addfile(member)
            elif kind == "device":
                member.type = tarfile.CHRTYPE
                member.devmajor = 1
                member.devminor = 3
                archive.addfile(member)
            else:
                raise AssertionError(f"unknown test member kind: {kind}")
    return buffer.getvalue()


def entry(name: str, kind: str, payload: bytes = b"", mode: int = 0o644,
          target: str = "") -> tuple[str, str, bytes, int, str]:
    return name, kind, payload, mode, target


def sparse_archive_bytes() -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz", format=tarfile.PAX_FORMAT) as archive:
        member = tarfile.TarInfo("sparse-file")
        member.mode = 0o644
        member.size = 1
        member.pax_headers = {
            "GNU.sparse.major": "1",
            "GNU.sparse.minor": "0",
            "GNU.sparse.realsize": "1",
        }
        archive.addfile(member, io.BytesIO(b"x"))
    return buffer.getvalue()


class CacheArchiveTransportTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="cache-archive-transport-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()

    def write_archive(self, raw: bytes, name: str = "cache.tar.gz") -> Path:
        path = self.base / name
        path.write_bytes(raw)
        return path

    def unpack(self, raw: bytes, *, output_name: str = "restored") -> Path:
        archive = self.write_archive(raw)
        output = self.base / output_name
        transport.unpack_archive(str(archive), sha256(raw), str(output))
        return output

    def assert_rejected(self, raw: bytes, *, output_name: str = "restored",
                        digest: str | None = None) -> None:
        archive = self.write_archive(raw)
        output = self.base / output_name
        with self.assertRaises(transport.TransportError):
            transport.unpack_archive(str(archive), sha256(raw) if digest is None else digest,
                                     str(output))
        self.assertFalse(output.exists(), "rejected archives must not publish a partial tree")

    @staticmethod
    def inventory(root: Path) -> dict[str, tuple[str, int, bytes | None]]:
        result: dict[str, tuple[str, int, bytes | None]] = {
            ".": ("directory", stat.S_IMODE(root.lstat().st_mode), None),
        }
        for current, directories, files in os.walk(root):
            current_path = Path(current)
            for name in directories:
                path = current_path / name
                result[path.relative_to(root).as_posix()] = (
                    "directory", stat.S_IMODE(path.lstat().st_mode), None)
            for name in files:
                path = current_path / name
                result[path.relative_to(root).as_posix()] = (
                    "file", stat.S_IMODE(path.lstat().st_mode), path.read_bytes())
        return result

    def test_round_trip_preserves_cargo_cache_bytes_modes_and_empty_directories(self) -> None:
        entries = [
            entry(".", "directory", mode=0o755),
            entry("registry", "directory", mode=0o700),
            entry("registry/index", "directory", mode=0o755),
            entry("registry/index/.cache", "directory", mode=0o700),
            entry("registry/index/.cache/ab", "directory", mode=0o755),
            entry("registry/index/empty", "directory", mode=0o700),
            entry("registry/bin", "directory", mode=0o700),
            entry("registry/index/config.json", "file", b"index config\n", 0o644),
            entry("registry/index/.cache/ab/cdef", "file", b"cache metadata\n", 0o444),
            entry("registry/src/config.json", "file", b"source config\n", 0o644),
            entry("registry/bin/cargo-wrapper", "file", b"#!/bin/sh\nexit 0\n", 0o755),
        ]
        output = self.unpack(archive_bytes(entries))
        expected = {
            ".": ("directory", 0o755, None),
            "registry": ("directory", 0o700, None),
            "registry/index": ("directory", 0o755, None),
            "registry/index/.cache": ("directory", 0o700, None),
            "registry/index/.cache/ab": ("directory", 0o755, None),
            "registry/index/empty": ("directory", 0o700, None),
            "registry/bin": ("directory", 0o700, None),
            "registry/index/config.json": ("file", 0o644, b"index config\n"),
            "registry/index/.cache/ab/cdef": ("file", 0o444, b"cache metadata\n"),
            "registry/src": ("directory", 0o755, None),
            "registry/src/config.json": ("file", 0o644, b"source config\n"),
            "registry/bin/cargo-wrapper": ("file", 0o755, b"#!/bin/sh\nexit 0\n"),
        }
        actual = self.inventory(output)
        self.assertEqual(actual, expected)

        # ZIP artifacts retain file paths and bytes, but this model applies the
        # common 0755/0644 modes and omits empty directories.
        zip_like = {}
        for path, (kind, mode, data) in actual.items():
            if path == "registry/index/empty":
                continue
            if kind == "directory":
                zip_like[path] = (kind, 0o755, None)
            else:
                zip_like[path] = (kind, 0o644, data)
        self.assertEqual(set(zip_like), set(actual) - {"registry/index/empty"})
        for path, (kind, _mode, data) in zip_like.items():
            self.assertEqual((kind, data), (actual[path][0], actual[path][2]))
        self.assertNotEqual(zip_like, actual)

    def test_native_tar_c_command_round_trip_keeps_modes_and_empty_directories(self) -> None:
        source = self.base / "source-tree"
        source.mkdir(mode=0o755)
        os.chmod(source, 0o755)
        (source / "bin").mkdir(mode=0o755)
        os.chmod(source / "bin", 0o755)
        (source / "empty-cache-dir").mkdir(mode=0o700)
        os.chmod(source / "empty-cache-dir", 0o700)
        (source / "readonly").write_bytes(b"read-only cache metadata\n")
        os.chmod(source / "readonly", 0o444)
        (source / "bin" / "tool").write_bytes(b"#!/bin/sh\nexit 0\n")
        os.chmod(source / "bin" / "tool", 0o755)

        archive = self.base / "native-tar.tar.gz"
        environment = os.environ.copy()
        environment["COPYFILE_DISABLE"] = "1"
        packed = subprocess.run(
            ["tar", "-czf", str(archive), "-C", str(source), "."],
            check=False, capture_output=True, text=True, timeout=20, env=environment,
        )
        self.assertEqual(packed.returncode, 0, packed.stderr)
        output = self.base / "native-tar-output"
        transport.unpack_archive(str(archive), sha256(archive.read_bytes()), str(output))
        self.assertEqual(self.inventory(output), {
            ".": ("directory", 0o755, None),
            "bin": ("directory", 0o755, None),
            "empty-cache-dir": ("directory", 0o700, None),
            "readonly": ("file", 0o444, b"read-only cache metadata\n"),
            "bin/tool": ("file", 0o755, b"#!/bin/sh\nexit 0\n"),
        })

    def test_without_explicit_root_entry_uses_private_root_mode(self) -> None:
        output = self.unpack(archive_bytes([entry("empty", "directory", mode=0o755)]))
        self.assertEqual(stat.S_IMODE(output.lstat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((output / "empty").lstat().st_mode), 0o755)

    def test_cli_process_unpacks_and_rejects_zero_digest(self) -> None:
        raw = archive_bytes([entry("payload", "file", b"cli bytes\n", 0o644)])
        archive = self.write_archive(raw)
        output = self.base / "cli-output"
        positive = subprocess.run(
            [sys.executable, "-B", str(SCRIPT), "--archive", str(archive),
             "--archive-sha256", sha256(raw), "--output-dir", str(output)],
            check=False, capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(positive.returncode, 0, positive.stderr)
        self.assertEqual((output / "payload").read_bytes(), b"cli bytes\n")

        rejected_output = self.base / "cli-rejected"
        negative = subprocess.run(
            [sys.executable, "-B", str(SCRIPT), "--archive", str(archive),
             "--archive-sha256", "0" * 64, "--output-dir", str(rejected_output)],
            check=False, capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(negative.returncode, 2)
        self.assertFalse(rejected_output.exists())
        self.assertNotIn(str(archive), negative.stderr)
        self.assertNotIn("token", negative.stderr.lower())

        duplicate_cases = [
            (["--archive", str(archive), "--archive", str(archive)],
             ["--archive-sha256", sha256(raw), "--output-dir", str(self.base / "dup-archive")]),
            (["--archive-sha256", sha256(raw), "--archive-sha256", sha256(raw)],
             ["--archive", str(archive), "--output-dir", str(self.base / "dup-sha")]),
            (["--output-dir", str(self.base / "dup-output"), "--output-dir",
              str(self.base / "dup-output")],
             ["--archive", str(archive), "--archive-sha256", sha256(raw)]),
        ]
        for repeated, remaining in duplicate_cases:
            duplicate = subprocess.run(
                [sys.executable, "-B", str(SCRIPT), *repeated, *remaining],
                check=False, capture_output=True, text=True, timeout=20,
            )
            self.assertEqual(duplicate.returncode, 2)
            self.assertIn("only once", duplicate.stderr)
        for output_name in ("dup-archive", "dup-sha", "dup-output"):
            self.assertFalse((self.base / output_name).exists())

    def test_rejects_invalid_or_zero_digest_without_output(self) -> None:
        raw = archive_bytes([entry("payload", "file", b"x")])
        archive = self.write_archive(raw)
        for index, digest in enumerate(("0" * 64, "g" * 64, "A" * 64, "a" * 63)):
            with self.subTest(digest=digest[:8]):
                output = self.base / f"bad-digest-{index}"
                with self.assertRaises(transport.TransportError):
                    transport.unpack_archive(str(archive), digest, str(output))
                self.assertFalse(output.exists())

    def test_rejects_corrupt_gzip_before_publication(self) -> None:
        raw = bytearray(archive_bytes([entry("payload", "file", b"valid tar payload")]))
        raw[-8] ^= 0x01
        self.assert_rejected(bytes(raw))

    def test_rejects_archive_without_a_tar_end_marker(self) -> None:
        complete = gzip.decompress(archive_bytes([entry("payload", "file", b"payload")]))
        incomplete = gzip.compress(complete.rstrip(b"\x00"), mtime=0)
        self.assert_rejected(incomplete)

    def test_enforces_archive_member_path_and_expansion_bounds(self) -> None:
        normal = archive_bytes([entry("payload", "file", b"abc")])
        long_name = archive_bytes([entry("l" * 120, "file", b"x")])
        cases = [
            ("archive bytes", "MAX_ARCHIVE_BYTES", len(normal) - 1, normal),
            ("member count", "MAX_MEMBERS", 0, normal),
            ("file bytes", "MAX_FILE_BYTES", 2, normal),
            ("aggregate bytes", "MAX_TOTAL_FILE_BYTES", 2, normal),
            ("path bytes", "MAX_PATH_BYTES", 3, normal),
            ("decompressed stream", "MAX_DECOMPRESSED_TAR_BYTES", 100, normal),
            ("extension header", "MAX_EXTENSION_BYTES", 8, long_name),
        ]
        for index, (label, constant, bound, raw) in enumerate(cases):
            with self.subTest(limit=label), mock.patch.object(transport, constant, bound):
                self.assert_rejected(raw, output_name=f"bounded-{index}")

    def test_rejects_unsafe_and_aliased_paths_without_writing_outside(self) -> None:
        bad_archives = {
            "traversal": [entry("safe-first", "file", b"must remain staged"),
                           entry("../escaped", "file", b"outside")],
            "double-traversal": [entry(f"../../{self.base.name}-parent-escaped",
                                        "file", b"outside")],
            "absolute": [entry("/tmp/escaped", "file", b"outside")],
            "windows-drive": [entry("C:/escaped", "file", b"outside")],
            "backslash": [entry("folder\\escaped", "file", b"outside")],
            "dot-component": [entry("safe/./escaped", "file", b"outside")],
            "duplicate-alias": [entry("./same", "file", b"first"),
                                 entry("same", "file", b"second")],
            "duplicate-directory-alias": [entry("dir/", "directory", mode=0o755),
                                           entry("dir", "directory", mode=0o755)],
            "file-parent-conflict": [entry("node", "file", b"file"),
                                     entry("node/child", "file", b"child")],
        }
        outside = self.base / "escaped"
        parent_outside = self.base.parent / f"{self.base.name}-parent-escaped"
        self.assertFalse(outside.exists())
        self.assertFalse(parent_outside.exists())
        for index, (label, entries) in enumerate(bad_archives.items()):
            with self.subTest(case=label):
                self.assert_rejected(archive_bytes(entries), output_name=f"unsafe-{index}")
        self.assertFalse(outside.exists())
        self.assertFalse(parent_outside.exists())

    def test_rejects_links_devices_fifo_and_special_mode_bits(self) -> None:
        cases = [
            ("symlink", [entry("link", "symlink", mode=0o777, target="../../outside")]),
            ("hardlink", [entry("link", "hardlink", mode=0o644, target="target")]),
            ("device", [entry("device", "device", mode=0o600)]),
            ("fifo", [entry("pipe", "fifo", mode=0o600)]),
            ("setuid", [entry("setuid", "file", b"x", 0o4755)]),
            ("setgid", [entry("setgid", "file", b"x", 0o2755)]),
            ("sticky", [entry("sticky", "directory", mode=0o1755)]),
        ]
        for index, (label, entries) in enumerate(cases):
            with self.subTest(case=label):
                self.assert_rejected(archive_bytes(entries), output_name=f"special-{index}")
        self.assert_rejected(sparse_archive_bytes(), output_name="sparse")

    def test_rejects_singly_linked_and_nofollow_archive_violations(self) -> None:
        raw = archive_bytes([entry("payload", "file", b"x")])
        archive = self.write_archive(raw)
        second_link = self.base / "second-link.tar.gz"
        os.link(archive, second_link)
        output = self.base / "linked-input"
        with self.assertRaises(transport.TransportError):
            transport.unpack_archive(str(archive), sha256(raw), str(output))
        self.assertFalse(output.exists())

        symlink = self.base / "archive-link.tar.gz"
        symlink.symlink_to(second_link)
        output_link = self.base / "symlink-input"
        with self.assertRaises(transport.TransportError):
            transport.unpack_archive(str(symlink), sha256(raw), str(output_link))
        self.assertFalse(output_link.exists())

    def test_rejects_linked_output_parent_and_existing_output(self) -> None:
        raw = archive_bytes([entry("payload", "file", b"x")])
        archive = self.write_archive(raw)
        real_parent = self.base / "real-parent"
        real_parent.mkdir()
        alias = self.base / "parent-alias"
        alias.symlink_to(real_parent, target_is_directory=True)
        with self.assertRaises(transport.TransportError):
            transport.unpack_archive(str(archive), sha256(raw), str(alias / "new-output"))
        self.assertFalse((real_parent / "new-output").exists())

        existing = self.base / "existing"
        existing.mkdir()
        sentinel = existing / "sentinel"
        sentinel.write_bytes(b"keep")
        with self.assertRaises(transport.TransportError):
            transport.unpack_archive(str(archive), sha256(raw), str(existing))
        self.assertEqual(sentinel.read_bytes(), b"keep")

    def test_cli_rejects_fifo_archive_without_waiting_for_a_writer(self) -> None:
        fifo = self.base / "not-an-archive"
        os.mkfifo(fifo)
        output = self.base / "fifo-output"
        result = subprocess.run(
            [sys.executable, "-B", str(SCRIPT), "--archive", str(fifo),
             "--archive-sha256", "1" * 64, "--output-dir", str(output)],
            check=False, capture_output=True, text=True, timeout=5,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("regular file", result.stderr)
        self.assertFalse(output.exists())

    def test_fails_closed_when_required_nofollow_flags_are_unavailable(self) -> None:
        raw = archive_bytes([entry("payload", "file", b"x")])
        archive = self.write_archive(raw)
        for index, flag in enumerate(("OPEN_NOFOLLOW", "OPEN_DIRECTORY")):
            with self.subTest(flag=flag), mock.patch.object(transport, flag, None):
                output = self.base / f"no-flags-{index}"
                with self.assertRaises(transport.TransportError):
                    transport.unpack_archive(str(archive), sha256(raw), str(output))
                self.assertFalse(output.exists())

    def test_rejects_output_archive_overlap(self) -> None:
        raw = archive_bytes([entry("payload", "file", b"x")])
        archive = self.write_archive(raw, "overlap")
        with self.assertRaises(transport.TransportError):
            transport.unpack_archive(str(archive), sha256(raw), str(archive))
        self.assertEqual(archive.read_bytes(), raw)


if __name__ == "__main__":
    unittest.main()
