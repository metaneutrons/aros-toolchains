#!/usr/bin/env python3
"""Focused contract test for the locked host Python runtime helper."""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tarfile
import tempfile


SOURCE_ROOT = Path(__file__).resolve().parents[3]
PRODUCER = SOURCE_ROOT / "scripts/toolchain/producer.py"
HELPER = SOURCE_ROOT / "scripts/toolchain/host-python-env.py"
OFFLINE_FETCH = SOURCE_ROOT / "scripts/toolchain/offline-fetch.py"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_source_archive(path: Path, root: str, files: dict[str, str]) -> None:
    directories = {root}
    for relative in files:
        parent = PurePosixPath(relative).parent
        while str(parent) not in {"", "."}:
            directories.add(f"{root}/{parent.as_posix()}")
            parent = parent.parent
    with tarfile.open(path, "w:gz") as archive:
        for directory in sorted(directories):
            info = tarfile.TarInfo(directory)
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            info.mtime = 0
            archive.addfile(info)
        for relative, content in sorted(files.items()):
            encoded = content.encode("utf-8")
            info = tarfile.TarInfo(f"{root}/{relative}")
            info.size = len(encoded)
            info.mode = 0o644
            info.mtime = 0
            archive.addfile(info, io.BytesIO(encoded))


def run(arguments: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(arguments, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and result.returncode != 0:
        raise AssertionError(
            f"command failed ({result.returncode}): {' '.join(arguments)}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="aros-host-python-env-test-") as temporary:
        root = Path(temporary)
        cache = root / "cache"
        cache.mkdir()
        llvm = cache / "llvm-11.0.0.src.tar.xz"
        llvm.write_bytes(b"fixture llvm source\n")
        mako = cache / "mako-1.3.10.tar.gz"
        markupsafe = cache / "markupsafe-3.0.2.tar.gz"
        write_source_archive(
            mako,
            "mako-1.3.10",
            {
                "mako/__init__.py": "__version__ = '1.3.10'\n",
                "mako/template.py": (
                    "import markupsafe\n"
                    "class Template:\n"
                    "    def __init__(self, value):\n"
                    "        self.value = value\n"
                    "    def render(self):\n"
                    "        assert markupsafe.__version__ == '3.0.2'\n"
                    "        return self.value\n"
                ),
            },
        )
        write_source_archive(
            markupsafe,
            "markupsafe-3.0.2",
            {"src/markupsafe/__init__.py": "__version__ = '3.0.2'\n"},
        )
        lock = {
            "schema": "aros-toolchain-source-lock-v2",
            "family": "llvm",
            "version": "11.0.0",
            "sources": [
                {
                    "component": "llvm",
                    "version": "11.0.0",
                    "purpose": "toolchain-component",
                    "filename": llvm.name,
                    "url": "https://example.invalid/llvm-11.0.0.src.tar.xz",
                    "sha256": sha256(llvm),
                    "size": llvm.stat().st_size,
                }
            ],
            "host_python_packages": [
                {
                    "name": "mako",
                    "version": "1.3.10",
                    "filename": mako.name,
                    "url": "https://example.invalid/mako-1.3.10.tar.gz",
                    "sha256": sha256(mako),
                    "size": mako.stat().st_size,
                    "source_root": "mako-1.3.10",
                    "python_path": ".",
                },
                {
                    "name": "markupsafe",
                    "version": "3.0.2",
                    "filename": markupsafe.name,
                    "url": "https://example.invalid/markupsafe-3.0.2.tar.gz",
                    "sha256": sha256(markupsafe),
                    "size": markupsafe.stat().st_size,
                    "source_root": "markupsafe-3.0.2",
                    "python_path": "src",
                },
            ],
        }
        lock_path = root / "lock.json"
        lock_path.write_text(json.dumps(lock, sort_keys=True), encoding="utf-8")

        run([
            sys.executable,
            str(PRODUCER),
            "prefetch",
            "--lock",
            str(lock_path),
            "--destination",
            str(cache),
            "--offline",
        ])
        index = json.loads((cache / "sources.verified.json").read_text(encoding="utf-8"))
        assert [item["filename"] for item in index["sources"]] == sorted(
            (llvm.name, mako.name, markupsafe.name)
        )

        upstream_fetch = root / "upstream-fetch.sh"
        upstream_fetch.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
        upstream_fetch.chmod(0o755)
        usage = root / "source-usage.log"
        fetch_environment = os.environ.copy()
        fetch_environment.update(
            {
                "AROS_VERIFIED_SOURCE_INDEX": str(cache / "sources.verified.json"),
                "AROS_VERIFIED_SOURCE_USAGE": str(usage),
                "AROS_UPSTREAM_FETCH": str(upstream_fetch),
            }
        )
        fetched = subprocess.run(
            [
                sys.executable,
                str(OFFLINE_FETCH),
                "-a",
                "llvm-11.0.0.src",
                "-l",
                str(cache),
                "-s",
                "tar.xz",
            ],
            env=fetch_environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        assert fetched.returncode == 0, fetched.stderr
        assert usage.read_text(encoding="utf-8") == f"{llvm.name}\n"
        run(
            [
                sys.executable,
                str(PRODUCER),
                "verify-source-usage",
                "--lock",
                str(lock_path),
                "--usage",
                str(usage),
            ]
        )
        usage.write_text("", encoding="utf-8")
        missing_usage = run(
            [
                sys.executable,
                str(PRODUCER),
                "verify-source-usage",
                "--lock",
                str(lock_path),
                "--usage",
                str(usage),
            ],
            check=False,
        )
        assert missing_usage.returncode != 0
        assert "locked sources were not consumed" in missing_usage.stderr
        usage.write_text(f"{llvm.name}\nnot-locked.tar.xz\n", encoding="utf-8")
        unexpected_usage = run(
            [
                sys.executable,
                str(PRODUCER),
                "verify-source-usage",
                "--lock",
                str(lock_path),
                "--usage",
                str(usage),
            ],
            check=False,
        )
        assert unexpected_usage.returncode != 0
        assert "unlocked sources were consumed" in unexpected_usage.stderr

        command = [
            sys.executable,
            "-B",
            str(HELPER),
            "--lock",
            str(lock_path),
            "--cache",
            str(cache),
            "--work-dir",
            str(root / "environment"),
            "--",
            sys.executable,
            "-s",
            "-B",
            "-c",
            "import mako, markupsafe; print(mako.__version__, markupsafe.__version__)",
        ]
        result = run(command)
        assert "1.3.10 3.0.2" in result.stdout
        assert "verified locked host Python runtime" in result.stdout

        reused = run(command, check=False)
        assert reused.returncode != 0
        assert "refusing to reuse host Python work directory" in reused.stderr

        mako.write_bytes(b"tampered\n")
        work_dir_index = command.index("--work-dir")
        tampered_command = [
            *command[: work_dir_index + 1],
            str(root / "tampered-environment"),
            *command[work_dir_index + 2 :],
        ]
        tampered = run(tampered_command, check=False)
        assert tampered.returncode != 0
        assert "size mismatch" in tampered.stderr or "SHA-256 mismatch" in tampered.stderr

        invalid_lock = dict(lock)
        invalid_lock.pop("host_python_packages")
        invalid_lock_path = root / "invalid-lock.json"
        invalid_lock_path.write_text(json.dumps(invalid_lock, sort_keys=True), encoding="utf-8")
        invalid = run(
            [
                sys.executable,
                str(PRODUCER),
                "prefetch",
                "--lock",
                str(invalid_lock_path),
                "--destination",
                str(root / "invalid-cache"),
                "--offline",
            ],
            check=False,
        )
        assert invalid.returncode != 0
        assert "unexpected or missing fields" in invalid.stderr

    print("host Python environment contract test passed")


if __name__ == "__main__":
    main()
