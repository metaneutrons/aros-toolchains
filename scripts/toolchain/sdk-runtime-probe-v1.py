#!/usr/bin/env python3
"""Replay an unchanged, receipt-bound SDK consumer on a PC AROS test image."""

import argparse
import base64
import hashlib
import importlib.util
import os
import re
import secrets
import selectors
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

spec = importlib.util.spec_from_file_location("origin", Path(__file__).with_name("artifact-origin.py"))
origin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(origin)

ProbeError = origin.OriginError
canon = origin.canonical
SCHEMA = "aros-sdk-runtime-consumer-v1"
MAX_ELF = 2 * 1024**2
MAX_ISO = 4 * 1024**3
MAX_SERIAL = 256 * 1024


def elf(raw):
    origin.require(len(raw) >= 52 and raw[:4] == b"\x7fELF" and raw[5] == 1, "expected a little-endian ELF")
    elf_class = raw[4]
    origin.require(elf_class == 1 or (elf_class == 2 and len(raw) >= 64), "truncated ELF header")
    return {"class": elf_class, "machine": int.from_bytes(raw[18:20], "little")}


def retain(operation: Path, family: str, receipt_sha256: str) -> dict:
    """Bind the exact bytes produced by the native C link to the SDK generation record."""
    operation = operation.resolve(strict=True)
    if family == "llvm":
        root = operation / "reports/llvm-sdk-links"
        receipt = root / "receipt/llvm-sdk-links.receipt.json"
        member_key, name, binary = "members", "links/original-c.elf", root / "links/original-c.elf"
        schema = "aros-llvm-sdk-link-receipt-v1"
    elif family == "gnu":
        root = operation / "reports/native-sdk-links"
        receipt = root / "native-sdk-links.receipt.json"
        member_key, name, binary = "outputs", "original-c", root / "original-c.elf"
        schema = "aros-native-sdk-link-receipt-v1"
    else:
        raise ProbeError("unknown native SDK generation family")
    measured, raw = origin.normalized_file(receipt, origin.MAX_METADATA)
    origin.require(measured["sha256"] == receipt_sha256, "native link receipt digest differs")
    document = origin.parse_json(raw)
    origin.require(document["schema"] == schema, "unexpected native link receipt schema")
    member = document[member_key][name]
    retain_bytes = member["size"] <= MAX_ELF
    measured, raw = origin.normalized_file(
        binary, origin.MAX_METADATA if retain_bytes else origin.MAX_PAYLOAD
    )
    origin.require(
        measured == {"size": member["size"], "sha256": member["sha256"]},
        "original-c.elf differs from native receipt",
    )
    result = {
        "schema": SCHEMA,
        "family": family,
        "receipt_sha256": receipt_sha256,
        "binary_sha256": measured["sha256"],
        "binary_size": measured["size"],
    }
    if retain_bytes:
        return {
            **result,
            "status": "retained",
            "elf": elf(raw),
            "binary_base64": base64.b64encode(raw).decode(),
        }
    return {**result, "status": "unavailable", "reason": "consumer-exceeds-2MiB-retention-cap"}


def previous_consumer(report, expected_sha):
    measured, raw = origin.normalized_file(report.resolve(), origin.MAX_METADATA)
    origin.require(measured["sha256"] == expected_sha, "previous report digest differs")
    row = origin.parse_json(raw)["targets"]["pc-x86_64"]["consumer"]
    origin.require(row["schema"] == SCHEMA and row["status"] == "retained", "previous consumer unavailable")
    binary = base64.b64decode(row["binary_base64"], validate=True)
    origin.require(
        len(binary) == row["binary_size"] <= MAX_ELF
        and hashlib.sha256(binary).hexdigest() == row["binary_sha256"],
        "consumer bytes differ",
    )
    origin.require(elf(binary) == {"class": 2, "machine": 62}, "expected a PC x86-64 consumer")
    return row["binary_sha256"], binary


def copy_image(source, dest, expected_sha):
    digest = hashlib.sha256()
    size = 0
    with source.open("rb") as src, dest.open("xb") as out:
        while block := src.read(1024**2):
            size += len(block)
            origin.require(size <= MAX_ISO, "boot image exceeds 4 GiB")
            digest.update(block)
            out.write(block)
    origin.require(digest.hexdigest() == expected_sha, "ISO digest differs")


def xorriso(*arguments, timeout=120):
    return subprocess.run(
        ["xorriso", *map(str, arguments), "-end"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def stage_iso(root, image, binary, nonce):
    startup = root / "Startup-Sequence"
    extract = ("-osirrox", "on", "-indev")
    read = xorriso(*extract, image, "-extract", "/S/Startup-Sequence", startup)
    if (
        read.returncode
        or not startup.is_file()
        or not re.search(rb'(?im)^\s*Execute\s+"?S:User-Startup\b', startup.read_bytes())
    ):
        return None
    guest = root / "SDKReuseProbe"
    guest.write_bytes(binary)
    guest.chmod(0o755)
    script = root / "User-Startup"
    script.write_text(
        f"""FailAt 255
Echo "AROS-SDK-RUNTIME:{nonce}:START" >DEBUG:
C:SDKReuseProbe
If $RC EQ 0 VAL
    Echo "AROS-SDK-RUNTIME:{nonce}:PASS" >DEBUG:
Else
    Echo "AROS-SDK-RUNTIME:{nonce}:FAIL" >DEBUG:
EndIf
""",
        encoding="ascii",
    )
    # The AROS debug handler writes to the kernel debug console (serial on these images).
    # Startup-Sequence mounts Devs:DOSDrivers before it executes User-Startup.
    debug_member = "/Devs/DOSDrivers/DEBUG"
    mount = root / "DEBUG"
    xorriso(*extract, image, "-extract", debug_member, mount)
    mount_mapping = []
    if not mount.is_file():
        mount.write_text(
            "Handler = debug-handler\nPriority = 5\nGlobVec = -1\nStartup = 0\n", encoding="ascii"
        )
        mount_mapping = ["-map", mount, debug_member]
    staged = root / "guest.iso"
    result = xorriso(
        "-indev",
        image,
        "-outdev",
        staged,
        "-boot_image",
        "any",
        "replay",
        "-overwrite",
        "on",
        "-map",
        guest,
        "/C/SDKReuseProbe",
        "-map",
        script,
        "/S/User-Startup",
        *mount_mapping,
        "-commit",
    )
    origin.require(
        result.returncode == 0,
        "failed to stage the test image: " + result.stderr.decode(errors="replace")[-700:],
    )
    embedded = root / "embedded"
    check = xorriso(*extract, staged, "-extract", "/C/SDKReuseProbe", embedded)
    origin.require(
        check.returncode == 0 and embedded.read_bytes() == binary, "embedded guest consumer differs"
    )
    return staged


def serial_result(serial, nonce):
    """Match complete serial lines in order; a partial line cannot decide a replay."""
    prefix = f"AROS-SDK-RUNTIME:{nonce}:".encode()
    started = False
    for line in serial.split(b"\n")[:-1]:
        line = line.rstrip(b"\r")
        if line == prefix + b"START":
            started = True
        elif started and line in (prefix + b"PASS", prefix + b"FAIL"):
            return "passed" if line == prefix + b"PASS" else "failed"
    return None


def boot(image, nonce, timeout):
    command = [
        "qemu-system-x86_64",
        "-machine",
        "q35,accel=tcg",
        "-cpu",
        "qemu64",
        "-m",
        "512",
        "-display",
        "none",
        "-no-reboot",
        "-nic",
        "none",
        "-monitor",
        "none",
        "-serial",
        "stdio",
        "-boot",
        "order=d",
        "-cdrom",
        str(image),
    ]
    serial = bytearray()
    deadline = time.monotonic() + timeout
    with (
        subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
        ) as proc,
        selectors.DefaultSelector() as selector,
    ):
        selector.register(proc.stdout, selectors.EVENT_READ)
        try:
            while time.monotonic() < deadline:
                if not selector.select(max(0, deadline - time.monotonic())):
                    break
                chunk = os.read(proc.stdout.fileno(), 8192)
                if not chunk:
                    return {"status": "error", "reason": "QEMU exited before a guest result"}
                serial.extend(chunk)
                origin.require(len(serial) <= MAX_SERIAL, "serial log exceeds the measurement limit")
                status = serial_result(serial, nonce)
                if status:
                    return {"status": status, "serial_sha256": hashlib.sha256(serial).hexdigest()}
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
    return {"status": "timeout", "serial_sha256": hashlib.sha256(serial).hexdigest()}


def replay(report, report_sha256, iso, iso_sha256, target="pc-x86_64", timeout=90):
    if target != "pc-x86_64":
        return {"status": "unsupported", "reason": "no guest runner for this target"}
    origin.require(1 <= timeout <= 300, "choose a guest timeout of 1 to 300 seconds")
    digest, binary = previous_consumer(report, report_sha256)
    evidence = {
        "target": target,
        "report_sha256": report_sha256,
        "binary_sha256": digest,
        "iso_sha256": iso_sha256,
    }
    with tempfile.TemporaryDirectory(prefix="aros-sdk-replay-") as temporary:
        root = Path(temporary)
        snapshot = root / "input.iso"
        copy_image(iso, snapshot, iso_sha256)
        if not all(shutil.which(tool) for tool in ("xorriso", "qemu-system-x86_64")):
            return {**evidence, "status": "unsupported", "reason": "xorriso or QEMU unavailable"}
        nonce = secrets.token_hex(12)
        staged = stage_iso(root, snapshot, binary, nonce)
        if staged is None:
            return {
                **evidence,
                "status": "unsupported",
                "reason": "AROS CD with a User-Startup hook required",
            }
        return {**evidence, **boot(staged, nonce, timeout)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["replay"])
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--report-sha256", required=True)
    parser.add_argument("--iso", type=Path, required=True)
    parser.add_argument("--iso-sha256", required=True)
    parser.add_argument("--timeout", type=int, default=90)
    args = parser.parse_args()
    try:
        result = replay(args.report, args.report_sha256, args.iso, args.iso_sha256, timeout=args.timeout)
        sys.stdout.buffer.write(canon(result))
        sys.exit(0 if result["status"] == "passed" else 1)
    except (ProbeError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        sys.exit(f"SDK guest replay failed: {exc}")
