#!/usr/bin/env python3
"""Offline contracts for the released aros-tools runtime lock."""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import hashlib
import io
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

print("released aros-tools runtime lock contract passed")
