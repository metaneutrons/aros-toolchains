#!/usr/bin/env python3
"""Run a command with the lock-owned host Python template runtime."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tarfile

import producer


EXPECTED_PACKAGES = frozenset(("mako", "markupsafe"))


def die(message: str) -> None:
    raise SystemExit(f"host Python environment: {message}")


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _safe_extract(archive: Path, destination: Path, source_root: str) -> None:
    with tarfile.open(archive, "r:*") as source:
        members = source.getmembers()
        for member in members:
            relative = PurePosixPath(member.name)
            if (
                relative.is_absolute()
                or not relative.parts
                or ".." in relative.parts
                or relative.parts[0] != source_root
            ):
                die(f"unsafe archive member in {archive.name}: {member.name!r}")
            if not (member.isdir() or member.isfile()):
                die(f"unsupported archive member in {archive.name}: {member.name!r}")
        source.extractall(destination)


def _prepare_package(package: dict, cache: Path, destination: Path) -> Path:
    archive = (cache / package["filename"]).resolve()
    if not _inside(archive, cache) or archive.parent != cache or not archive.is_file():
        die(f"verified archive is absent or unsafe: {package['filename']}")
    producer.verify_source(archive, package)

    source_root = destination / package["source_root"]
    if source_root.exists() or source_root.is_symlink():
        die(f"host Python extraction root already exists: {source_root}")
    _safe_extract(archive, destination, package["source_root"])
    if not source_root.is_dir() or source_root.is_symlink():
        die(f"archive did not create its declared source root: {source_root}")

    python_root = (source_root / package["python_path"]).resolve()
    source_root_resolved = source_root.resolve()
    if not _inside(python_root, source_root_resolved) or not python_root.is_dir():
        die(f"archive lacks its declared Python import root: {python_root}")
    return python_root


def _verify_runtime(environment: dict[str, str], packages: list[dict], roots: dict[str, Path]) -> None:
    expected = {
        package["name"]: {
            "version": package["version"],
            "root": str(roots[package["name"]]),
        }
        for package in packages
    }
    probe = r'''
import importlib
import json
from pathlib import Path
import sys
import warnings

warnings.filterwarnings("ignore", category=UserWarning)
expected = json.loads(sys.argv[1])
for name, details in expected.items():
    module = importlib.import_module(name)
    actual_version = getattr(module, "__version__", None)
    if actual_version != details["version"]:
        raise SystemExit(f"{name} version {actual_version!r} != {details['version']!r}")
    module_path = Path(module.__file__).resolve()
    root = Path(details["root"]).resolve()
    try:
        module_path.relative_to(root)
    except ValueError:
        raise SystemExit(f"{name} imported from outside the locked root: {module_path}")
# Importing Mako's template implementation after the path and version check
# ensures its MarkupSafe dependency is the already verified module above.
from mako.template import Template
if Template("locked runtime").render() != "locked runtime":
    raise SystemExit("Mako template rendering did not produce the expected result")
'''
    result = subprocess.run(
        [sys.executable, "-s", "-B", "-c", probe, json.dumps(expected, sort_keys=True)],
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        output = (result.stdout + result.stderr).strip()
        die(f"locked Mako runtime validation failed ({result.returncode}): {output}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("a command is required after --")

    lock = producer.read_json(args.lock.resolve())
    producer.validate_source_lock(lock)
    packages = sorted(producer.validate_host_python_packages(lock), key=lambda package: package["name"])
    if {package["name"] for package in packages} != EXPECTED_PACKAGES:
        die("host Python lock must contain exactly mako and markupsafe")

    cache = args.cache.resolve()
    if not cache.is_dir():
        die(f"verified source cache is absent: {cache}")
    work_dir = args.work_dir.resolve()
    if work_dir.exists():
        die(f"refusing to reuse host Python work directory: {work_dir}")
    work_dir.mkdir(parents=True)

    roots = {
        package["name"]: _prepare_package(package, cache, work_dir)
        for package in packages
    }
    environment = dict(os.environ)
    environment.pop("PYTHONHOME", None)
    environment["PYTHON"] = sys.executable
    environment["PYTHONPATH"] = os.pathsep.join(str(roots[package["name"]]) for package in packages)
    environment["PYTHONNOUSERSITE"] = "1"
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONHASHSEED"] = "0"
    _verify_runtime(environment, packages, roots)
    print(
        "verified locked host Python runtime: "
        + ", ".join(f"{package['name']} {package['version']}" for package in packages)
    )
    try:
        return subprocess.run(command, env=environment).returncode
    except OSError as exc:
        die(f"cannot execute {' '.join(command)!r}: {exc}")


if __name__ == "__main__":
    raise SystemExit(main())
