#!/usr/bin/env python3
"""Focused offline tests for the inactive bounded start ZIP reader."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import stat
import struct
import subprocess
import tempfile
import unittest
import urllib.request
import warnings
import zipfile
import zlib
from unittest import mock


SOURCE_ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = SOURCE_ROOT / "scripts/toolchain/compiler-sdk-start-artifact-v2.py"
SPEC = importlib.util.spec_from_file_location("compiler_sdk_start_artifact_v2", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
reader = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reader)

RECORD_NAME = reader.RECORD_BASENAME
BUNDLE_NAME = reader.BUNDLE_BASENAME
RECORD_BYTES = b'{"schema":"offline-start-fixture","ok":true}\n'
BUNDLE_BYTES = b'{"mediaType":"synthetic-signature-bundle"}\n'


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def zip_bytes(entries: list[tuple[str, bytes, int, int | None]]) -> bytes:
    output = io.BytesIO()
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message=r"Duplicate name:.*", category=UserWarning)
        with zipfile.ZipFile(output, "w") as handle:
            for name, raw, compression, mode in entries:
                info = zipfile.ZipInfo(name)
                info.compress_type = compression
                if mode is not None:
                    info.create_system = 3
                    info.external_attr = mode << 16
                handle.writestr(info, raw)
    return output.getvalue()


class NonSeekableBytesIO(io.BytesIO):
    def seekable(self) -> bool:
        return False

    def seek(self, offset: int, whence: int = 0) -> int:
        raise io.UnsupportedOperation("fixture output is non-seekable")


def data_descriptor_zip_bytes() -> bytes:
    output = NonSeekableBytesIO()
    with zipfile.ZipFile(output, "w") as handle:
        for name, raw, compression, mode in standard_entries(zipfile.ZIP_DEFLATED):
            info = zipfile.ZipInfo(name)
            info.compress_type = compression
            if mode is not None:
                info.create_system = 3
                info.external_attr = mode << 16
            handle.writestr(info, raw)
    return output.getvalue()


def force_zip64_zip_bytes() -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as handle:
        record = zipfile.ZipInfo(RECORD_NAME)
        record.compress_type = zipfile.ZIP_DEFLATED
        with handle.open(record, "w", force_zip64=True) as stream:
            stream.write(RECORD_BYTES)
        handle.writestr(BUNDLE_NAME, BUNDLE_BYTES)
    return output.getvalue()


def dos_directory_zip_bytes() -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as handle:
        directory = zipfile.ZipInfo(RECORD_NAME)
        directory.create_system = 0
        directory.external_attr = 0x10
        handle.writestr(directory, RECORD_BYTES)
        handle.writestr(BUNDLE_NAME, BUNDLE_BYTES)
    return output.getvalue()


def standard_entries(compression: int = zipfile.ZIP_STORED) -> list[tuple[str, bytes, int, int | None]]:
    return [(RECORD_NAME, RECORD_BYTES, compression, None),
            (BUNDLE_NAME, BUNDLE_BYTES, compression, None)]


def entry_offsets(raw: bytes, name: str) -> tuple[int, int]:
    """Return local and central header offsets for a single ASCII ZIP member."""
    with zipfile.ZipFile(io.BytesIO(raw)) as handle:
        selected = [item for item in handle.infolist() if item.filename == name]
        if len(selected) != 1:
            raise AssertionError(f"fixture member selection is ambiguous: {name}")
        local_offset = selected[0].header_offset

    wanted = name.encode("ascii")
    central_offset = 0
    matches = []
    while True:
        offset = raw.find(b"PK\x01\x02", central_offset)
        if offset < 0:
            break
        name_length, extra_length, comment_length = struct.unpack_from("<HHH", raw, offset + 28)
        current = raw[offset + 46:offset + 46 + name_length]
        if current == wanted:
            matches.append(offset)
        central_offset = offset + 46 + name_length + extra_length + comment_length
    if len(matches) != 1:
        raise AssertionError(f"fixture central member selection is ambiguous: {name}")
    return local_offset, matches[0]


def patch_member(raw: bytes, name: str, *, flags: int | None = None,
                 compression: int | None = None,
                 uncompressed_size: int | None = None,
                 crc: int | None = None) -> bytes:
    data = bytearray(raw)
    local, central = entry_offsets(raw, name)
    if flags is not None:
        struct.pack_into("<H", data, local + 6, flags)
        struct.pack_into("<H", data, central + 8, flags)
    if compression is not None:
        struct.pack_into("<H", data, local + 8, compression)
        struct.pack_into("<H", data, central + 10, compression)
    if uncompressed_size is not None:
        struct.pack_into("<I", data, local + 22, uncompressed_size)
        struct.pack_into("<I", data, central + 24, uncompressed_size)
    if crc is not None:
        struct.pack_into("<I", data, local + 14, crc)
        struct.pack_into("<I", data, central + 16, crc)
    return bytes(data)


def patch_local_fields(raw: bytes, name: str, *, crc: int | None = None,
                      compressed_size: int | None = None,
                      uncompressed_size: int | None = None) -> bytes:
    data = bytearray(raw)
    local, _ = entry_offsets(raw, name)
    if crc is not None:
        struct.pack_into("<I", data, local + 14, crc)
    if compressed_size is not None:
        struct.pack_into("<I", data, local + 18, compressed_size)
    if uncompressed_size is not None:
        struct.pack_into("<I", data, local + 22, uncompressed_size)
    return bytes(data)


def patch_local_zip64_uncompressed_size(raw: bytes, name: str, value: int) -> bytes:
    data = bytearray(raw)
    local, _ = entry_offsets(raw, name)
    name_length, extra_length = struct.unpack_from("<HH", raw, local + 26)
    cursor = local + 30 + name_length
    end = cursor + extra_length
    while cursor < end:
        field_id, field_size = struct.unpack_from("<HH", raw, cursor)
        field_start = cursor + 4
        field_end = field_start + field_size
        if field_id == 0x0001:
            struct.pack_into("<Q", data, field_start, value)
            return bytes(data)
        cursor = field_end
    raise AssertionError("fixture has no local ZIP64 extra field")


def corrupt_member_data(raw: bytes, name: str) -> bytes:
    data = bytearray(raw)
    local, _ = entry_offsets(raw, name)
    name_length, extra_length = struct.unpack_from("<HH", raw, local + 26)
    data_offset = local + 30 + name_length + extra_length
    data[data_offset] ^= 0x01
    return bytes(data)


def patch_nul_member_name(raw: bytes, original_name: str, nul_name: str) -> bytes:
    original = original_name.encode("ascii")
    replacement = nul_name.encode("ascii")
    if len(original) != len(replacement) or raw.count(original) != 2:
        raise AssertionError("fixture NUL-name replacement is not length-preserving")
    return raw.replace(original, replacement)


class StartArchiveReaderTests(unittest.TestCase):
    def fixture(self, root: Path, raw: bytes, name: str = "start.zip") -> Path:
        root = root.resolve()
        path = root / name
        path.write_bytes(raw)
        return path

    def read_raw(self, archive: Path, raw: bytes) -> dict[str, bytes]:
        return reader.read_start_archive(archive, sha256(raw), len(raw))

    def test_reads_exact_members_from_real_stored_and_deflated_archives(self) -> None:
        expected = {RECORD_NAME: RECORD_BYTES, BUNDLE_NAME: BUNDLE_BYTES}
        with tempfile.TemporaryDirectory(prefix="start-artifact-reader-") as temporary:
            root = Path(temporary).resolve()
            for codec in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                with self.subTest(codec=codec):
                    raw = zip_bytes(standard_entries(codec))
                    archive = self.fixture(root, raw, f"codec-{codec}.zip")
                    self.assertEqual(self.read_raw(archive, raw), expected)

    def test_accepts_data_descriptor_and_local_zip64_extra_fields(self) -> None:
        expected = {RECORD_NAME: RECORD_BYTES, BUNDLE_NAME: BUNDLE_BYTES}
        with tempfile.TemporaryDirectory(prefix="start-artifact-zip-variants-") as temporary:
            root = Path(temporary).resolve()
            descriptor_archive = data_descriptor_zip_bytes()
            with zipfile.ZipFile(io.BytesIO(descriptor_archive)) as handle:
                self.assertTrue(all(item.flag_bits & 0x0008 for item in handle.infolist()))
            path = self.fixture(root, descriptor_archive, "data-descriptor.zip")
            self.assertEqual(self.read_raw(path, descriptor_archive), expected)

            zip64_archive = force_zip64_zip_bytes()
            with zipfile.ZipFile(io.BytesIO(zip64_archive)) as handle:
                record = next(item for item in handle.infolist() if item.filename == RECORD_NAME)
                local_offset = record.header_offset
                name_length, extra_length = struct.unpack_from("<HH", zip64_archive, local_offset + 26)
                extra_offset = local_offset + 30 + name_length
                self.assertGreater(extra_length, 0)
                self.assertEqual(struct.unpack_from("<H", zip64_archive, extra_offset)[0], 0x0001)
            path = self.fixture(root, zip64_archive, "force-zip64.zip")
            self.assertEqual(self.read_raw(path, zip64_archive), expected)

    def test_archive_digest_size_and_pins_are_independent_explicit_and_exact(self) -> None:
        raw = zip_bytes(standard_entries())
        with tempfile.TemporaryDirectory(prefix="start-artifact-pins-") as temporary:
            archive = self.fixture(Path(temporary).resolve(), raw)
            with self.assertRaises(reader.StartError):
                reader.read_start_archive(archive, "0" * 64, len(raw))
            with self.assertRaises(reader.StartError):
                reader.read_start_archive(archive, sha256(raw), len(raw) + 1)
            for bad_digest in ("A" * 64, "0" * 63, "" ):
                with self.subTest(digest=bad_digest), self.assertRaises(reader.StartError):
                    reader.read_start_archive(archive, bad_digest, len(raw))
            for bad_size in (True, False, 0, -1, reader.MAX_ARCHIVE + 1):
                with self.subTest(size=bad_size), self.assertRaises(reader.StartError):
                    reader.read_start_archive(archive, sha256(raw), bad_size)

    def test_fixed_member_size_boundaries_are_inclusive_and_oversize_is_rejected_pre_read(self) -> None:
        with tempfile.TemporaryDirectory(prefix="start-artifact-member-limits-") as temporary:
            root = Path(temporary).resolve()
            record = b"r" * 7
            bundle = b"b" * 11
            raw = zip_bytes([(RECORD_NAME, record, zipfile.ZIP_DEFLATED, None),
                             (BUNDLE_NAME, bundle, zipfile.ZIP_STORED, None)])
            archive = self.fixture(root, raw, "at-boundary.zip")
            with mock.patch.multiple(reader, MAX_RECORD=len(record), MAX_BUNDLE=len(bundle)):
                self.assertEqual(self.read_raw(archive, raw),
                                 {RECORD_NAME: record, BUNDLE_NAME: bundle})

            for name, contents, limit_name in (
                    (RECORD_NAME, b"r" * 8, "MAX_RECORD"),
                    (BUNDLE_NAME, b"b" * 12, "MAX_BUNDLE")):
                with self.subTest(member=name):
                    entries = [(RECORD_NAME, RECORD_BYTES, zipfile.ZIP_STORED, None),
                               (BUNDLE_NAME, BUNDLE_BYTES, zipfile.ZIP_STORED, None)]
                    entries[0 if name == RECORD_NAME else 1] = (
                        name, contents, zipfile.ZIP_STORED, None)
                    too_large = zip_bytes(entries)
                    oversized_archive = self.fixture(root, too_large, f"oversize-{name}.zip")
                    limit = len(contents) - 1
                    patcher = mock.patch.object(reader, limit_name, limit)
                    with patcher, mock.patch.object(
                            zipfile.ZipFile, "open",
                            side_effect=AssertionError("oversized member was read")):
                        with self.assertRaises(reader.StartError):
                            self.read_raw(oversized_archive, too_large)

    def test_compressed_archive_cap_is_applied_to_pin_and_bounded_file_read(self) -> None:
        raw = zip_bytes(standard_entries())
        with tempfile.TemporaryDirectory(prefix="start-artifact-archive-limit-") as temporary:
            archive = self.fixture(Path(temporary).resolve(), raw)
            with mock.patch.object(reader, "MAX_ARCHIVE", len(raw) - 1), \
                    mock.patch.object(reader.zipfile, "ZipFile") as zip_parse:
                with self.assertRaises(reader.StartError):
                    reader.read_start_archive(archive, sha256(raw), len(raw) - 2)
                zip_parse.assert_not_called()

    def test_rejects_unknown_duplicate_traversal_nul_link_directory_encryption_codec_and_crc(self) -> None:
        base = standard_entries()
        cases: dict[str, bytes] = {
            "unknown": zip_bytes([("unexpected.json", RECORD_BYTES, zipfile.ZIP_STORED, None),
                                  (BUNDLE_NAME, BUNDLE_BYTES, zipfile.ZIP_STORED, None)]),
            "extra": zip_bytes(base + [("extra.json", b"extra", zipfile.ZIP_STORED, None)]),
            "duplicate": zip_bytes([(RECORD_NAME, RECORD_BYTES, zipfile.ZIP_STORED, None),
                                     (RECORD_NAME, b"duplicate", zipfile.ZIP_STORED, None)]),
            "traversal": zip_bytes([("../" + RECORD_NAME, RECORD_BYTES, zipfile.ZIP_STORED, None),
                                    (BUNDLE_NAME, BUNDLE_BYTES, zipfile.ZIP_STORED, None)]),
            "symlink": zip_bytes([(RECORD_NAME, RECORD_BYTES, zipfile.ZIP_STORED,
                                   stat.S_IFLNK | 0o777),
                                  (BUNDLE_NAME, BUNDLE_BYTES, zipfile.ZIP_STORED, None)]),
            "directory_mode": zip_bytes([(RECORD_NAME, RECORD_BYTES, zipfile.ZIP_STORED,
                                          stat.S_IFDIR | 0o755),
                                         (BUNDLE_NAME, BUNDLE_BYTES, zipfile.ZIP_STORED, None)]),
            "directory_name": zip_bytes([(RECORD_NAME + "/", RECORD_BYTES, zipfile.ZIP_STORED,
                                          stat.S_IFDIR | 0o755),
                                         (BUNDLE_NAME, BUNDLE_BYTES, zipfile.ZIP_STORED, None)]),
            "dos_directory_attribute": dos_directory_zip_bytes(),
            "empty_member": zip_bytes([(RECORD_NAME, b"", zipfile.ZIP_STORED, None),
                                        (BUNDLE_NAME, BUNDLE_BYTES, zipfile.ZIP_STORED, None)]),
        }
        nul_original = RECORD_NAME + "xy"
        nul_replacement = RECORD_NAME + "\x00x"
        cases["nul"] = patch_nul_member_name(
            zip_bytes([(nul_original, RECORD_BYTES, zipfile.ZIP_STORED, None),
                       (BUNDLE_NAME, BUNDLE_BYTES, zipfile.ZIP_STORED, None)]),
            nul_original, nul_replacement)
        for label, flags in (("encrypted", 0x0001),
                             ("strong_encryption", 0x0040),
                             ("masked_header", 0x2000)):
            cases[label] = patch_member(zip_bytes(base), RECORD_NAME, flags=flags)
        for label, field_offset, value in (("local_encryption_mismatch", 6, 0x0001),
                                           ("local_codec_mismatch", 8, zipfile.ZIP_DEFLATED)):
            data = bytearray(zip_bytes(base))
            local, _ = entry_offsets(data, RECORD_NAME)
            struct.pack_into("<H", data, local + field_offset, value)
            cases[label] = bytes(data)
        cases["unsupported_codec"] = patch_member(zip_bytes(base), RECORD_NAME, compression=99)
        cases["crc"] = corrupt_member_data(zip_bytes(base), RECORD_NAME)
        cases["malformed"] = b"not a ZIP archive"

        with tempfile.TemporaryDirectory(prefix="start-artifact-invalid-") as temporary:
            root = Path(temporary).resolve()
            for label, raw in cases.items():
                with self.subTest(case=label):
                    archive = self.fixture(root, raw, f"{label}.zip")
                    with self.assertRaises(reader.StartError):
                        self.read_raw(archive, raw)

    def test_deflate_output_after_matching_declared_prefix_crc_is_rejected(self) -> None:
        prefix = b"declared-prefix"
        complete = prefix + b"UNDECLARED-TAIL"
        raw = zip_bytes([(RECORD_NAME, complete, zipfile.ZIP_DEFLATED, None),
                         (BUNDLE_NAME, BUNDLE_BYTES, zipfile.ZIP_DEFLATED, None)])
        short_declaration = patch_member(
            raw, RECORD_NAME, uncompressed_size=len(prefix), crc=zlib.crc32(prefix) & 0xFFFFFFFF)
        with tempfile.TemporaryDirectory(prefix="start-artifact-declared-length-") as temporary:
            archive = self.fixture(Path(temporary).resolve(), short_declaration)
            with self.assertRaises(reader.StartError):
                self.read_raw(archive, short_declaration)

    def test_local_crc_and_size_fields_must_match_central_metadata(self) -> None:
        raw = zip_bytes(standard_entries())
        cases = {
            "local_crc": patch_local_fields(
                raw, RECORD_NAME, crc=(zlib.crc32(RECORD_BYTES) ^ 0x01) & 0xFFFFFFFF),
            "local_uncompressed_size": patch_local_fields(
                raw, RECORD_NAME, uncompressed_size=len(RECORD_BYTES) - 1),
            "local_compressed_size": patch_local_fields(
                raw, RECORD_NAME, compressed_size=len(RECORD_BYTES) - 1),
        }
        with tempfile.TemporaryDirectory(prefix="start-artifact-local-fields-") as temporary:
            root = Path(temporary).resolve()
            for label, mutated in cases.items():
                with self.subTest(field=label):
                    archive = self.fixture(root, mutated, f"{label}.zip")
                    with self.assertRaises(reader.StartError):
                        self.read_raw(archive, mutated)

    def test_local_zip64_size_values_must_match_central_metadata(self) -> None:
        valid_zip64 = force_zip64_zip_bytes()
        mutated = patch_local_zip64_uncompressed_size(
            valid_zip64, RECORD_NAME, len(RECORD_BYTES) + 1)
        with tempfile.TemporaryDirectory(prefix="start-artifact-local-zip64-") as temporary:
            archive = self.fixture(Path(temporary).resolve(), mutated)
            with self.assertRaises(reader.StartError):
                self.read_raw(archive, mutated)

    def test_archive_must_be_a_singly_linked_regular_file(self) -> None:
        raw = zip_bytes(standard_entries())
        with tempfile.TemporaryDirectory(prefix="start-artifact-file-kind-") as temporary:
            root = Path(temporary).resolve()
            target = self.fixture(root, raw, "source.zip")
            linked = root / "linked.zip"
            linked.symlink_to(target)
            with self.assertRaises(reader.StartError):
                self.read_raw(linked, raw)

            hardlink = root / "hardlink.zip"
            os.link(target, hardlink)
            with self.assertRaises(reader.StartError):
                self.read_raw(target, raw)

    def test_reader_has_no_output_extraction_provider_or_mutation_side_effects(self) -> None:
        raw = zip_bytes(standard_entries())
        with tempfile.TemporaryDirectory(prefix="start-artifact-pure-read-") as temporary:
            root = Path(temporary).resolve()
            archive = self.fixture(root, raw)
            before_names = set(root.iterdir())
            before_bytes = archive.read_bytes()
            with mock.patch.object(Path, "write_bytes", side_effect=AssertionError("file write")), \
                    mock.patch.object(Path, "mkdir", side_effect=AssertionError("directory creation")), \
                    mock.patch.object(zipfile.ZipFile, "extractall",
                                      side_effect=AssertionError("archive extraction")), \
                    mock.patch.object(subprocess, "run", side_effect=AssertionError("provider process")), \
                    mock.patch.object(urllib.request, "urlopen",
                                      side_effect=AssertionError("network request")), \
                    mock.patch.object(os, "replace", side_effect=AssertionError("file replacement")), \
                    mock.patch.object(os, "rename", side_effect=AssertionError("file rename")), \
                    redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                result = self.read_raw(archive, raw)
            self.assertEqual(result, {RECORD_NAME: RECORD_BYTES, BUNDLE_NAME: BUNDLE_BYTES})
            self.assertEqual(set(root.iterdir()), before_names)
            self.assertEqual(archive.read_bytes(), before_bytes)


if __name__ == "__main__":
    unittest.main()
