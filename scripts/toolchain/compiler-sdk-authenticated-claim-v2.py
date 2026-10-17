#!/usr/bin/env python3
"""Inactive authenticated-start to claim-upload boundary; never dispatches.

The caller must first materialize the authentic published runtime in private,
quiescent staging. This component binds its runtime evidence to the signed
start, authenticates the executing dispatcher and its causal edge, and uploads
only a claim derived from the authenticated record/bundle bytes. The closed CLI
can retain those exact uploaded claim bytes and a canonical receipt after
confirmed upload and readback, but it never dispatches, signs, or activates.

No workflow calls this component. A future caller remains responsible for
independently selecting the source-context file; this CLI validates its bounded
JSON shape but does not prove selector independence or native authority. Output
parents must already be caller-owned, mode-0700 private directories that remain
quiescent and trusted during the operation. ACL and same-UID races are outside
this boundary. An uncertain upload is never retried, and a late failure can
leave an uploaded asset, partial outputs, or even a complete canonical receipt.
Callers must require exit status zero; every output from a nonzero invocation
is unusable, and file presence alone never proves retention success. Token
provenance is also the trusted caller's responsibility, not proven by a nonempty
GH_TOKEN. Runtime evidence is verified after dispatcher authentication and before
upload. Provider qualification and native release gates remain separate.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


SPEC = importlib.util.spec_from_file_location(
    "authenticated_claim_dispatcher", Path(__file__).with_name("compiler-sdk-dispatcher-auth-v2.py"))
AUTH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUTH)
START = AUTH.START
UPLOAD = AUTH.UPLOAD
CLAIM = AUTH.CLAIM


def _authenticate_and_upload(record_path: Path, bundle_path: Path, source_context: dict, *,
                             runtime_lock: Path, runtime_directory: Path,
                             runtime_interface: Path, runtime_host: str,
                             expected_record_sha256: str | None = None,
                             expected_bundle_sha256: str | None = None) -> tuple[dict, bytes]:
    """Authenticate and upload once; return receipt and exact uploaded bytes."""
    source = START.ORIGIN.validate_context(source_context)
    raw = START.ADMISSION.read_regular_file(record_path, "selected start record", START.MAX_RECORD)
    bundle = START.ADMISSION.read_regular_file(bundle_path, "selected start bundle", START.MAX_BUNDLE)
    START.require((expected_record_sha256 is None) == (expected_bundle_sha256 is None),
                  "paired caller byte pins are required")
    record_pin = (hashlib.sha256(raw).hexdigest() if expected_record_sha256 is None
                  else expected_record_sha256)
    bundle_pin = (hashlib.sha256(bundle).hexdigest() if expected_bundle_sha256 is None
                  else expected_bundle_sha256)
    START.require(type(record_pin) is str and START.ADMISSION.SHA256.fullmatch(record_pin) is not None
                  and type(bundle_pin) is str and START.ADMISSION.SHA256.fullmatch(bundle_pin) is not None,
                  "caller byte pins are not canonical SHA-256 digests")
    START.require(hashlib.sha256(raw).hexdigest() == record_pin
                  and hashlib.sha256(bundle).hexdigest() == bundle_pin,
                  "selected start bytes differ from the caller's exact byte pins")
    identity = AUTH.authenticate_dispatcher(source)
    selection = {"runtime_lock": runtime_lock, "runtime_directory": runtime_directory,
                 "runtime_interface": runtime_interface, "runtime_host": runtime_host,
                 "expected_record_sha256": record_pin,
                 "expected_bundle_sha256": bundle_pin}
    record = START.verify_start(record_path, bundle_path, source, **selection)
    START.require(record == START.validate_start(
        START.ADMISSION.parse_json(raw, "selected start record"), source),
        "authenticated start differs from the selected claim input")
    claim_selection = {"source_context": source, "dispatcher_context": identity["context"],
                       "dispatcher_job": identity["job"], "dispatcher_event": identity["event"],
                       "trigger_context": identity["trigger_context"]}
    claim = CLAIM.claim_bytes(raw, bundle, **claim_selection)
    START.require(AUTH.authenticate_dispatcher(source) == identity,
                  "dispatcher identity changed before claim upload")
    START.require(START.verify_start(record_path, bundle_path, source, **selection) == record,
                  "authenticated start changed before claim upload")
    asset = UPLOAD.upload_claim_once(claim, raw, bundle, **claim_selection)
    receipt = {"schema": "aros-toolchains-authenticated-claim-upload-v2",
               "assurance": "authenticated-claim-upload-only-not-native-dispatch",
               "dispatcher": identity, "claim": asset}
    return receipt, claim


def authenticate_and_upload(record_path: Path, bundle_path: Path, source_context: dict, *,
                            runtime_lock: Path, runtime_directory: Path,
                            runtime_interface: Path, runtime_host: str) -> dict:
    """One upload after original identity, signed bytes and runtime joins pass."""
    receipt, _ = _authenticate_and_upload(
        record_path, bundle_path, source_context, runtime_lock=runtime_lock,
        runtime_directory=runtime_directory, runtime_interface=runtime_interface,
        runtime_host=runtime_host)
    return receipt


def _absolute_path(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _check_private_output_parent(path: Path) -> None:
    try:
        metadata = path.parent.stat(follow_symlinks=False)
    except OSError:
        START.require(False, "output parent is unavailable")
    START.require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == os.getuid()
                  and stat.S_IMODE(metadata.st_mode) == 0o700,
                  "output parent must be an existing caller-owned mode-0700 directory")


def _check_written_file(path: Path, expected: bytes, label: str) -> None:
    actual = START.ADMISSION.read_regular_file(path, label, START.MAX_RECORD)
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError:
        START.require(False, f"{label} readback is unavailable")
    START.require(actual == expected and stat.S_ISREG(metadata.st_mode)
                  and metadata.st_nlink == 1 and metadata.st_uid == os.getuid()
                  and stat.S_IMODE(metadata.st_mode) == 0o600,
                  f"{label} readback differs from the exact private output")


def _retain_cli(args: argparse.Namespace) -> None:
    START.require(os.environ.get("GH_HOST") == "github.com"
                  and bool(os.environ.get("GH_TOKEN")),
                  "authenticated claim CLI requires GH_HOST=github.com and GH_TOKEN")

    record_path = _absolute_path(args.record)
    bundle_path = _absolute_path(args.bundle)
    context_path = _absolute_path(args.source_context)
    claim_output = _absolute_path(args.claim_output)
    receipt_output = _absolute_path(args.output)

    raw = START.ADMISSION.read_regular_file(record_path, "selected start record", START.MAX_RECORD)
    bundle = START.ADMISSION.read_regular_file(bundle_path, "selected start bundle", START.MAX_BUNDLE)
    context_raw = START.ADMISSION.read_regular_file(
        context_path, "independently selected source context", START.MAX_RECORD)
    context_value = START.ADMISSION.parse_json(context_raw, "source context", maximum=START.MAX_RECORD)
    source = START.ORIGIN.validate_context(context_value)

    for pin, label in ((args.expected_record_sha256, "record"),
                       (args.expected_bundle_sha256, "bundle")):
        START.require(type(pin) is str and re.fullmatch(r"[0-9a-f]{64}", pin) is not None,
                      f"expected {label} digest is not lowercase SHA-256")
    START.require(hashlib.sha256(raw).hexdigest() == args.expected_record_sha256
                  and hashlib.sha256(bundle).hexdigest() == args.expected_bundle_sha256,
                  "selected start bytes differ from the explicit byte pins")

    START.require(claim_output.name == CLAIM.CLAIM_NAME,
                  "claim output must use the fixed claim filename")
    START.require(claim_output != receipt_output,
                  "claim and receipt outputs must be distinct normalized paths")

    # Check both destinations and their immediate private parents before the
    # first provider call. Directories are a trusted, quiescent caller premise.
    for destination in (claim_output, receipt_output):
        START.ADMISSION._check_output_destination(destination, existing=False)
        _check_private_output_parent(destination)

    receipt, claim_raw = _authenticate_and_upload(
        record_path, bundle_path, source,
        runtime_lock=args.runtime_lock,
        runtime_directory=args.runtime_directory,
        runtime_interface=args.runtime_interface,
        runtime_host=args.runtime_host,
        expected_record_sha256=args.expected_record_sha256,
        expected_bundle_sha256=args.expected_bundle_sha256,
    )

    asset = receipt.get("claim") if type(receipt) is dict else None
    START.require(type(asset) is dict and set(asset) == {"id", "name", "size", "sha256"}
                  and type(asset.get("id")) is int and asset["id"] > 0
                  and asset.get("name") == CLAIM.CLAIM_NAME
                  and type(asset.get("size")) is int and asset["size"] == len(claim_raw)
                  and asset.get("sha256") == hashlib.sha256(claim_raw).hexdigest(),
                  "uploaded asset metadata differs from the exact retained claim bytes")

    def require_inputs_unchanged() -> None:
        START.require(START.ADMISSION.read_regular_file(
            record_path, "selected start record", START.MAX_RECORD) == raw
            and START.ADMISSION.read_regular_file(
                bundle_path, "selected start bundle", START.MAX_BUNDLE) == bundle
            and START.ADMISSION.read_regular_file(
                context_path, "independently selected source context", START.MAX_RECORD) == context_raw,
            "selected record, bundle or source-context bytes changed during retention")

    require_inputs_unchanged()
    START.ADMISSION._write_exclusive(claim_output, claim_raw)
    _check_written_file(claim_output, claim_raw, "retained claim")
    require_inputs_unchanged()

    receipt_raw = (START.ADMISSION.canonical_json(receipt) + "\n").encode("ascii")
    START.require(0 < len(receipt_raw) <= START.MAX_RECORD,
                  "canonical receipt exceeds its metadata limit")
    START.ADMISSION._write_exclusive(receipt_output, receipt_raw)
    _check_written_file(receipt_output, receipt_raw, "retained receipt")
    require_inputs_unchanged()
    _check_written_file(claim_output, claim_raw, "final retained claim")
    _check_written_file(receipt_output, receipt_raw, "final retained receipt")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--record", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--source-context", type=Path, required=True)
    parser.add_argument("--expected-record-sha256", required=True)
    parser.add_argument("--expected-bundle-sha256", required=True)
    parser.add_argument("--runtime-lock", type=Path, required=True)
    parser.add_argument("--runtime-directory", type=Path, required=True)
    parser.add_argument("--runtime-interface", type=Path, required=True)
    parser.add_argument("--runtime-host", choices=("linux-x86_64",), required=True)
    parser.add_argument("--claim-output", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True,
                        help="exclusive canonical receipt output")
    args = parser.parse_args(argv)
    try:
        _retain_cli(args)
    except (START.StartError, START.ADMISSION.AdmissionError, START.ORIGIN.OriginError,
            START.RUNTIME.RuntimeError, START.INTERFACE.PreflightError,
            OSError, subprocess.TimeoutExpired, ValueError, KeyError, TypeError,
            RecursionError, OverflowError):
        # Provider exceptions can contain transport details. Emit only a
        # controlled status; after upload, any partial local state is unusable.
        print("authenticated claim retention failed; any upload or partial output is unusable",
              file=sys.stderr)
        return 1
    print("authenticated claim retained; no dispatch or activation performed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
