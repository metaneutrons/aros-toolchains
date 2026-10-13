#!/usr/bin/env python3
"""Offline contracts for the released aros-tools runtime lock."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
from pathlib import Path
import hashlib
import io
import stat
import subprocess
import sys
import tarfile
import tempfile


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts" / "toolchain" / "materialize-aros-tools-runtime.py"
LOCK = ROOT / "toolchains" / "aros-tools-runtime-v1.json"

spec = importlib.util.spec_from_file_location("aros_tools_runtime", SCRIPT)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)

lock = json.loads(LOCK.read_text(encoding="utf-8"))
module.validate_lock(lock)
HOST = "linux-x86_64"

for host in ("linux-x86_64", "linux-aarch64", "macos-aarch64"):
    assert lock["hosts"][host]["target"] == module.HOST_TARGETS[host]

bad = copy.deepcopy(lock)
bad["hosts"]["macos-aarch64"] = bad["hosts"]["linux-aarch64"]
try:
    module.validate_lock(bad)
except module.RuntimeError as error:
    assert "target" in str(error) or "reuses asset" in str(error)
else:
    raise AssertionError("runtime lock accepted a duplicate host asset closure")

bad = copy.deepcopy(lock)
bad["hosts"]["linux-x86_64"]["archive"]["sha256"] = "0" * 63
try:
    module.validate_lock(bad)
except module.RuntimeError as error:
    assert "sha256" in str(error)
else:
    raise AssertionError("runtime lock accepted a malformed archive digest")


with tempfile.TemporaryDirectory() as temporary_name:
    temporary = Path(temporary_name)
    target = module.HOST_TARGETS["linux-x86_64"]
    manifest = {
        "version": "0.0.0",
        "target": target,
        "files": [],
    }
    payloads = {}
    for path, (mode, _) in module.EXPECTED_FILES.items():
        content = f"fixture:{path}\n".encode("utf-8")
        payloads[path] = content
        manifest["files"].append(
            {
                "path": path,
                "mode": mode,
                "sha256": hashlib.sha256(content).hexdigest(),
                "size": len(content),
            }
        )
    archive = temporary / "runtime.tar.gz"
    root = f"aros-tools-v0.0.0-{target}"
    with tarfile.open(archive, "w:gz") as package:
        for name in (root, f"{root}/bin"):
            entry = tarfile.TarInfo(name)
            entry.type = tarfile.DIRTYPE
            entry.mode = 0o755
            package.addfile(entry)
        for path, content in payloads.items():
            entry = tarfile.TarInfo(f"{root}/{path}")
            entry.size = len(content)
            entry.mode = int(module.EXPECTED_FILES[path][0], 8)
            package.addfile(entry, io.BytesIO(content))
    destination = temporary / "runtime"
    module.safe_extract(archive, manifest, destination)
    assert (destination / "bin" / "aros").read_bytes() == payloads["bin/aros"]

    unsafe = temporary / "unsafe.tar.gz"
    with tarfile.open(unsafe, "w:gz") as package:
        entry = tarfile.TarInfo("../escape")
        entry.size = 1
        package.addfile(entry, io.BytesIO(b"x"))
    try:
        module.safe_extract(unsafe, manifest, temporary / "unsafe-runtime")
    except module.RuntimeError as error:
        assert "unsafe" in str(error)
    else:
        raise AssertionError("runtime extraction accepted a parent-directory escape")


def write_fixture_lock(path: Path, fixture_lock: dict) -> None:
    path.write_bytes(module.canonical_json(fixture_lock) + b"\n")


def write_fixture_receipt(
    directory: Path,
    lock_path: Path,
    fixture_lock: dict,
    manifest: dict,
    manifest_bytes: bytes,
) -> None:
    receipt = module.receipt(
        lock_path, fixture_lock, HOST, manifest, hashlib.sha256(manifest_bytes).hexdigest()
    )
    (directory / ".aros-tools-runtime-receipt-v1.json").write_bytes(
        module.canonical_json(receipt) + b"\n"
    )


def make_runtime(directory: Path) -> tuple[dict[str, bytes], Path, dict]:
    directory.mkdir()
    fixture_lock = copy.deepcopy(lock)
    entry = fixture_lock["hosts"][HOST]
    lock_path = directory.parent / f"{directory.name}-runtime-lock.json"
    payloads: dict[str, bytes] = {}
    files = []
    for path, (mode, _) in module.EXPECTED_FILES.items():
        content = f"signed fixture:{path}\n".encode("utf-8")
        payloads[path] = content
        files.append(
            {
                "path": path,
                "mode": mode,
                "sha256": hashlib.sha256(content).hexdigest(),
                "size": len(content),
            }
        )
    manifest = {
        "schema": 1,
        "package": "aros-tools",
        "version": lock["version"],
        "target": entry["target"],
        "source_commit": lock["source_commit"],
        "source_date_epoch": lock["source_date_epoch"],
        "archive": entry["archive"]["name"],
        "archive_sha256": entry["archive"]["sha256"],
        "archive_size": entry["archive"]["size"],
        "files": files,
    }
    manifest_bytes = module.canonical_json(manifest) + b"\n"
    entry["manifest"]["sha256"] = hashlib.sha256(manifest_bytes).hexdigest()
    entry["manifest"]["size"] = len(manifest_bytes)
    module.validate_lock(fixture_lock)
    write_fixture_lock(lock_path, fixture_lock)
    manifest_path = directory / ".aros-tools-runtime-manifest.json"
    manifest_path.write_bytes(manifest_bytes)
    write_fixture_receipt(directory, lock_path, fixture_lock, manifest, manifest_bytes)
    for path, content in payloads.items():
        target_path = directory / path
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_bytes(content)
        target_path.chmod(0o644)
    return payloads, lock_path, fixture_lock


def runtime_command(
    command: str, directory: Path, lock_path: Path
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            command,
            "--lock",
            str(lock_path),
            "--host",
            HOST,
            "--directory",
            str(directory),
        ],
        check=False,
        capture_output=True,
        text=True,
    )


def mode_snapshot(paths: list[Path]) -> dict[str, tuple[int, int, int, str]]:
    snapshot: dict[str, tuple[int, int, int, str]] = {}
    for path in paths:
        state = path.lstat()
        if stat.S_ISREG(state.st_mode):
            digest = hashlib.sha256()
            with path.open("rb") as handle:
                for block in iter(lambda: handle.read(64 * 1024), b""):
                    digest.update(block)
            content = digest.hexdigest()
        elif stat.S_ISLNK(state.st_mode):
            content = os.readlink(path)
        else:
            content = ""
        snapshot[str(path)] = (
            stat.S_IFMT(state.st_mode) | stat.S_IMODE(state.st_mode),
            state.st_nlink,
            state.st_size,
            content,
        )
    return snapshot


with tempfile.TemporaryDirectory() as temporary_name:
    temporary = Path(temporary_name)
    runtime = temporary / "runtime"
    _, lock_path, _ = make_runtime(runtime)
    restored = runtime_command("restore-artifact-modes", runtime, lock_path)
    assert restored.returncode == 0, restored.stderr
    assert runtime_command("verify", runtime, lock_path).returncode == 0
    for path, (_, native) in module.EXPECTED_FILES.items():
        expected_mode = 0o755 if native else 0o644
        assert stat.S_IMODE((runtime / path).stat().st_mode) == expected_mode


with tempfile.TemporaryDirectory() as temporary_name:
    temporary = Path(temporary_name)
    runtime = temporary / "runtime"
    _, lock_path, _ = make_runtime(runtime)
    strict = runtime_command("verify", runtime, lock_path)
    assert strict.returncode != 0
    assert "mode" in strict.stderr


for probe in (
    "invalid-bytes", "extra-file", "malformed-receipt", "bad-manifest-mode",
    "resealed-manifest-payload", "oversized-manifest", "oversized-receipt",
    "wrong-manifest-size", "file-symlink", "hardlink",
):
    with tempfile.TemporaryDirectory() as temporary_name:
        temporary = Path(temporary_name)
        runtime = temporary / "runtime"
        payloads, lock_path, fixture_lock = make_runtime(runtime)
        sentinel = temporary / "sentinel"
        sentinel.write_bytes(b"sentinel remains untouched\n")
        sentinel.chmod(0o600)
        watched = [path for path in runtime.rglob("*")] + [sentinel]

        if probe == "invalid-bytes":
            target = runtime / "bin/aros"
            target.write_bytes(b"x" + payloads["bin/aros"][1:])
        elif probe == "extra-file":
            target = runtime / "bin/unexpected"
            target.write_bytes(b"extra")
            target.chmod(0o600)
            watched.append(target)
        elif probe == "malformed-receipt":
            (runtime / ".aros-tools-runtime-receipt-v1.json").write_bytes(b"{ malformed\n")
        elif probe == "bad-manifest-mode":
            manifest_path = runtime / ".aros-tools-runtime-manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            next(item for item in manifest["files"] if item["path"] == "bin/aros")["mode"] = "0644"
            manifest_bytes = module.canonical_json(manifest) + b"\n"
            manifest_path.write_bytes(manifest_bytes)
            fixture_lock["hosts"][HOST]["manifest"]["sha256"] = hashlib.sha256(manifest_bytes).hexdigest()
            fixture_lock["hosts"][HOST]["manifest"]["size"] = len(manifest_bytes)
            write_fixture_lock(lock_path, fixture_lock)
            write_fixture_receipt(runtime, lock_path, fixture_lock, manifest, manifest_bytes)
        elif probe == "resealed-manifest-payload":
            target = runtime / "bin/aros"
            forged_bytes = b"forged fixture:" + payloads["bin/aros"][len(b"signed fixture:"):]
            target.write_bytes(forged_bytes)
            manifest_path = runtime / ".aros-tools-runtime-manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            details = next(item for item in manifest["files"] if item["path"] == "bin/aros")
            details["sha256"] = hashlib.sha256(forged_bytes).hexdigest()
            details["size"] = len(forged_bytes)
            manifest_bytes = module.canonical_json(manifest) + b"\n"
            manifest_path.write_bytes(manifest_bytes)
            # Reseal the receipt while leaving the independent lock asset digest intact.
            write_fixture_receipt(runtime, lock_path, fixture_lock, manifest, manifest_bytes)
        elif probe == "oversized-manifest":
            manifest_path = runtime / ".aros-tools-runtime-manifest.json"
            with manifest_path.open("r+b") as handle:
                handle.truncate(module.MAX_METADATA_SIZE + 1)
            fixture_lock["hosts"][HOST]["manifest"]["size"] = module.MAX_METADATA_SIZE + 1
            write_fixture_lock(lock_path, fixture_lock)
        elif probe == "oversized-receipt":
            receipt_path = runtime / ".aros-tools-runtime-receipt-v1.json"
            with receipt_path.open("r+b") as handle:
                handle.truncate(module.MAX_METADATA_SIZE + 1)
        elif probe == "wrong-manifest-size":
            fixture_lock["hosts"][HOST]["manifest"]["size"] += 1
            write_fixture_lock(lock_path, fixture_lock)
        elif probe == "file-symlink":
            target = runtime / "bin/aros"
            target.unlink()
            target.symlink_to(sentinel)
        elif probe == "hardlink":
            target = runtime / "bin/aros"
            target.unlink()
            sentinel.write_bytes(payloads["bin/aros"])
            sentinel.chmod(0o600)
            os.link(sentinel, target)

        before = mode_snapshot(watched)
        result = runtime_command("restore-artifact-modes", runtime, lock_path)
        assert result.returncode != 0, f"restore unexpectedly accepted {probe}"
        if probe == "oversized-manifest":
            assert "size limit" in result.stderr
        elif probe == "oversized-receipt":
            assert "size limit" in result.stderr
        elif probe == "wrong-manifest-size":
            assert "size differs from runtime lock" in result.stderr
        assert mode_snapshot(watched) == before, f"restore changed modes or links for {probe}"


with tempfile.TemporaryDirectory() as temporary_name:
    temporary = Path(temporary_name)
    runtime = temporary / "runtime"
    _, lock_path, _ = make_runtime(runtime)
    external_bin = temporary / "external-bin"
    os.replace(runtime / "bin", external_bin)
    (runtime / "bin").symlink_to(external_bin, target_is_directory=True)
    sentinel = temporary / "sentinel"
    sentinel.write_bytes(b"sentinel remains untouched\n")
    sentinel.chmod(0o600)
    watched = [path for path in external_bin.iterdir()] + [runtime / "bin", sentinel]
    before = mode_snapshot(watched)
    result = runtime_command("restore-artifact-modes", runtime, lock_path)
    assert result.returncode != 0, "restore unexpectedly accepted a symlinked bin directory"
    assert mode_snapshot(watched) == before, "restore followed the symlinked bin directory"


with tempfile.TemporaryDirectory() as temporary_name:
    temporary = Path(temporary_name)
    runtime = temporary / "runtime"
    _, lock_path, _ = make_runtime(runtime)
    root_symlink = temporary / "runtime-link"
    root_symlink.symlink_to(runtime, target_is_directory=True)
    sentinel = temporary / "sentinel"
    sentinel.write_bytes(b"sentinel remains untouched\n")
    sentinel.chmod(0o600)
    watched = list(runtime.rglob("*")) + [root_symlink, sentinel]
    before = mode_snapshot(watched)
    for command, expected_error in (
        ("restore-artifact-modes", "without following symlinks"),
        ("verify", "requires a real directory"),
    ):
        result = runtime_command(command, root_symlink, lock_path)
        assert result.returncode != 0, f"{command} unexpectedly accepted a symlinked runtime root"
        assert expected_error in result.stderr
        assert mode_snapshot(watched) == before, f"{command} changed the runtime referent or sentinel"


with tempfile.TemporaryDirectory() as temporary_name:
    temporary = Path(temporary_name)
    runtime = temporary / "runtime"
    _, lock_path, _ = make_runtime(runtime)
    watched = list(runtime.rglob("*"))
    before = mode_snapshot(watched)
    verify_extracted = module.verify_extracted

    def injected_verify(*_args) -> None:
        raise module.RuntimeError("injected post-mutation verification failure")

    module.verify_extracted = injected_verify
    try:
        module.restore_artifact_modes(lock_path, HOST, runtime)
    except module.RuntimeError as error:
        assert "injected post-mutation" in str(error)
    else:
        raise AssertionError("mode restoration ignored an injected verification failure")
    finally:
        module.verify_extracted = verify_extracted
    assert mode_snapshot(watched) == before, "restore did not roll back after post-mutation failure"


with tempfile.TemporaryDirectory() as temporary_name:
    temporary = Path(temporary_name)
    runtime = temporary / "runtime"
    _, lock_path, _ = make_runtime(runtime)
    original_fchmod = os.fchmod
    fchmod_calls = [0]

    def injected_fchmod(fd: int, mode: int) -> None:
        fchmod_calls[0] += 1
        if fchmod_calls[0] in {2, 3}:
            raise OSError("injected fchmod failure")
        original_fchmod(fd, mode)

    os.fchmod = injected_fchmod
    try:
        module.restore_artifact_modes(lock_path, HOST, runtime)
    except module.RuntimeError as error:
        assert "rollback also failed" in str(error)
        assert "injected fchmod failure" in str(error)
    else:
        raise AssertionError("restore suppressed an injected rollback failure")
    finally:
        os.fchmod = original_fchmod

print("released aros-tools runtime lock contract passed")
