#!/usr/bin/env python3
"""Read the two bounded members of an inactive compiler/SDK start ZIP.

This helper is a closed byte-transport reader only. It does not authenticate a
signature, validate a start record, select provider or artifact metadata, or
establish job ownership or qualification. The caller must stage the archive
quiescently. The existing file reader detects ordinary identity changes while
reading, but this helper makes no atomicity, race-resistance, or sandbox claim.
It is not registered with a workflow or production entry point.
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
from pathlib import Path
import re
import stat
import struct
import sys
import zipfile
import zlib


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def _load_sealer():
    path = HERE / "seal-compiler-sdk-start-v2.py"
    spec = importlib.util.spec_from_file_location("start_artifact_sealer_constants", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load the local start transport sealer")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SEALER = _load_sealer()
RECORD_BASENAME = SEALER.RECORD_BASENAME
BUNDLE_BASENAME = SEALER.BUNDLE_BASENAME
MAX_RECORD = SEALER.MAX_RECORD
MAX_BUNDLE = SEALER.MAX_BUNDLE
MAX_ARCHIVE = MAX_RECORD + MAX_BUNDLE + 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
READ_CHUNK = 64 * 1024
LOCAL_FILE_HEADER = struct.Struct("<IHHHHHIIIHH")
LOCAL_FILE_SIGNATURE = 0x04034B50


class StartError(ValueError):
    """The start archive did not pass the bounded closed transport boundary."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise StartError(message)


def _compressed_payload(raw: bytes, member: zipfile.ZipInfo) -> memoryview:
    """Locate a member's compressed bytes after ZipFile.open validates its header."""
    offset = member.header_offset
    require(type(offset) is int and 0 <= offset <= len(raw) - LOCAL_FILE_HEADER.size,
            "start ZIP local header offset is outside the captured archive")
    try:
        header = LOCAL_FILE_HEADER.unpack_from(raw, offset)
    except struct.error:
        raise StartError("start ZIP local header is truncated") from None
    (signature, _version, local_flags, local_compression, _mtime, _mdate, local_crc,
     local_compressed_size, local_file_size, name_length, extra_length) = header
    require(signature == LOCAL_FILE_SIGNATURE,
            "start ZIP member does not point to a local file header")
    # The only accepted names are short fixed ASCII basenames. Extra fields may
    # include ZIP64 local sizes; parse their bounded TLVs and resolve size
    # sentinels only when the local header requires it.
    encoded_name = member.filename.encode("utf-8" if member.flag_bits & 0x0800 else "cp437")
    require(name_length == len(encoded_name) and name_length <= 1024,
            "start ZIP local member name length differs")
    name_start = offset + LOCAL_FILE_HEADER.size
    name_end = name_start + name_length
    data_start = name_end + extra_length
    data_end = data_start + member.compress_size
    require(data_start <= len(raw) and data_end <= len(raw)
            and raw[name_start:name_end] == encoded_name,
            "start ZIP compressed member span is outside the captured archive")

    require(local_flags == member.flag_bits and local_compression == member.compress_type,
            "start ZIP local flags or compression method differ from central metadata")

    zip64_payloads = []
    extra_cursor = name_end
    while extra_cursor < data_start:
        require(data_start - extra_cursor >= 4,
                "start ZIP local extra field header is truncated")
        field_id, field_size = struct.unpack_from("<HH", raw, extra_cursor)
        field_start = extra_cursor + 4
        field_end = field_start + field_size
        require(field_end <= data_start,
                "start ZIP local extra field exceeds its declared span")
        if field_id == 0x0001:
            zip64_payloads.append((field_start, field_size))
        extra_cursor = field_end

    # With a data descriptor, local numeric fields may be placeholders: use
    # central metadata and verify the complete member bytes below. Without
    # that flag, local metadata must agree with the central directory,
    # resolving only the ZIP64 sentinel fields as specified.
    if not (local_flags & 0x0008):
        require(local_crc == member.CRC,
                "start ZIP local CRC differs from central metadata")
        needs_uncompressed = local_file_size == 0xFFFFFFFF
        needs_compressed = local_compressed_size == 0xFFFFFFFF
        if needs_uncompressed or needs_compressed:
            require(len(zip64_payloads) == 1,
                    "start ZIP local ZIP64 size field is missing or duplicated")
            zip64_start, zip64_size = zip64_payloads[0]
            expected_zip64_size = 8 * (int(needs_uncompressed) + int(needs_compressed))
            require(zip64_size == expected_zip64_size,
                    "start ZIP local ZIP64 size field is truncated or malformed")
            cursor = zip64_start
            if needs_uncompressed:
                local_file_size = struct.unpack_from("<Q", raw, cursor)[0]
                cursor += 8
            if needs_compressed:
                local_compressed_size = struct.unpack_from("<Q", raw, cursor)[0]
        require(local_file_size == member.file_size
                and local_compressed_size == member.compress_size,
                "start ZIP local sizes differ from central metadata")
    return memoryview(raw)[data_start:data_end]


def _read_member(raw: bytes, handle: zipfile.ZipFile, member: zipfile.ZipInfo,
                 name: str, prior_total: int) -> tuple[bytes, int]:
    # Opening invokes ZipFile's local-header, filename, compression and
    # overlap checks. ZipExtFile clips reads to the central uncompressed size,
    # so its returned bytes are not used as proof of the complete DEFLATE
    # stream; the exact compressed span is checked independently below.
    with handle.open(member, "r"):
        pass
    compressed = _compressed_payload(raw, member)
    limit = {RECORD_BASENAME: MAX_RECORD, BUNDLE_BASENAME: MAX_BUNDLE}[name]

    if member.compress_type == zipfile.ZIP_STORED:
        require(len(compressed) == member.file_size,
                "stored start ZIP member compressed and declared lengths differ")
        contents = compressed.tobytes()
        actual_size = len(contents)
        crc = zlib.crc32(contents) & 0xFFFFFFFF
    else:
        inflater = zlib.decompressobj(-zlib.MAX_WBITS)
        chunks = []
        actual_size = 0
        crc = 0
        position = 0
        while position < len(compressed):
            end = min(position + READ_CHUNK, len(compressed))
            pending = compressed[position:end].tobytes()
            position = end
            while pending:
                before = pending
                remaining = min(member.file_size - actual_size,
                                limit - actual_size,
                                MAX_RECORD + MAX_BUNDLE - prior_total - actual_size)
                block = inflater.decompress(pending, min(READ_CHUNK, remaining + 1))
                pending = inflater.unconsumed_tail
                if block:
                    actual_size += len(block)
                    require(actual_size <= member.file_size and actual_size <= limit
                            and prior_total + actual_size <= MAX_RECORD + MAX_BUNDLE,
                            "deflated start ZIP member exceeds its bounded declared size")
                    crc = zlib.crc32(block, crc) & 0xFFFFFFFF
                    chunks.append(block)
                if inflater.eof:
                    require(not inflater.unused_data and not pending and position == len(compressed),
                            "deflated start ZIP member has trailing compressed data")
                    break
                require(not pending or len(pending) < len(before) or block,
                        "deflated start ZIP member made no bounded decompression progress")
            if inflater.eof:
                break
        require(inflater.eof and not inflater.unused_data and not inflater.unconsumed_tail,
                "deflated start ZIP member is truncated or has unconsumed data")
        contents = b"".join(chunks)

    require(actual_size == member.file_size and crc == member.CRC,
            "start ZIP member full length or CRC differs from its metadata")
    require(prior_total + actual_size <= MAX_RECORD + MAX_BUNDLE,
            "start ZIP members exceed their aggregate decompressed byte limit")
    return contents, prior_total + actual_size


def read_start_archive(archive: Path, expected_sha256: str,
                       expected_size: int) -> dict[str, bytes]:
    """Return exact record and bundle bytes from a digest-pinned ZIP capture.

    ``archive`` must be a caller-owned, singly linked regular file. The file is
    read once through the existing bounded owned-file reader; its captured
    bytes are hashed and then passed directly to the ZIP parser.
    """
    require(isinstance(archive, Path), "start archive path must be a pathlib.Path")
    require(type(expected_sha256) is str and SHA256.fullmatch(expected_sha256) is not None,
            "expected archive digest must be lowercase SHA-256")
    require(type(expected_size) is int and 0 < expected_size <= MAX_ARCHIVE,
            "expected archive size must be a positive in-limit integer")

    try:
        measured, raw, _ = SEALER.RECORD._read_owned(
            archive, MAX_ARCHIVE, "start artifact archive", retain=True)
    except (SEALER.RECORD.AdapterError, OSError):
        raise StartError("start archive is not a stable caller-owned bounded regular file") from None
    require(raw is not None and len(raw) == expected_size
            and measured["size"] == expected_size
            and measured["sha256"] == expected_sha256
            and hashlib.sha256(raw).hexdigest() == expected_sha256,
            "start archive bytes differ from the independently pinned digest or size")

    expected_limits = {RECORD_BASENAME: MAX_RECORD, BUNDLE_BASENAME: MAX_BUNDLE}
    try:
        with zipfile.ZipFile(io.BytesIO(raw), "r") as handle:
            members = handle.infolist()
            require(len(members) == 2,
                    "start ZIP must contain exactly the sealed record and bundle")

            selected = {}
            for member in members:
                name = member.filename
                original_name = member.orig_filename
                require(type(name) is str and type(original_name) is str
                        and original_name == name and "\x00" not in original_name,
                        "start ZIP contains a malformed member name")
                require(name in expected_limits and name not in selected,
                        "start ZIP contains a duplicate or unexpected member")

                mode = member.external_attr >> 16
                require(stat.S_IFMT(mode) in (0, stat.S_IFREG)
                        and not member.is_dir()
                        and not (member.external_attr & 0x10)
                        and not (member.flag_bits & (0x0001 | 0x0040 | 0x2000)),
                        "start ZIP member is not an ordinary unencrypted file")
                require(member.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED),
                        "start ZIP member uses an unsupported compression method")
                require(type(member.file_size) is int
                        and 0 < member.file_size <= expected_limits[name],
                        "start ZIP member has an empty or oversized declared length")
                require(type(member.compress_size) is int
                        and 0 < member.compress_size <= MAX_ARCHIVE,
                        "start ZIP member has an invalid compressed length")
                require(type(member.CRC) is int and 0 <= member.CRC <= 0xFFFFFFFF,
                        "start ZIP member CRC metadata is invalid")
                selected[name] = member

            require(set(selected) == set(expected_limits),
                    "start ZIP must contain exactly the sealed record and bundle")
            declared_total = sum(member.file_size for member in selected.values())
            compressed_total = sum(member.compress_size for member in selected.values())
            require(declared_total <= MAX_RECORD + MAX_BUNDLE
                    and compressed_total <= expected_size,
                    "start ZIP declared member lengths exceed their aggregate limit")

            contents: dict[str, bytes] = {}
            actual_total = 0
            for name in (RECORD_BASENAME, BUNDLE_BASENAME):
                member = selected[name]
                contents[name], actual_total = _read_member(
                    raw, handle, member, name, actual_total)
            return contents
    except StartError:
        raise
    except (zipfile.BadZipFile, zipfile.LargeZipFile, EOFError, NotImplementedError,
            RuntimeError, zlib.error, struct.error, UnicodeError, OSError,
            ValueError, KeyError, IndexError):
        raise StartError("start ZIP is malformed or member data failed integrity checks") from None
