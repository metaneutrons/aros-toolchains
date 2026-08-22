#!/usr/bin/env python3
"""Fail-closed producer for reproducible AROS cross-toolchain releases."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import posixpath
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

SOURCE_SCHEMA = "aros-ng-toolchain-source-lock-v1"
PROFILE_SCHEMA = "aros-ng-toolchain-profiles-v1"
MANIFEST_SCHEMA = 1
SUPPORTED_HOSTS = {
    "linux-x86_64",
    "linux-aarch64",
    "macos-x86_64",
    "macos-aarch64",
}
BUILTINS_BY_PROFILE = {
    "pc-x86_64": ("x86_64", "i386"),
    "arm-raspi": ("armhf",),
    "rpi-aarch64": ("aarch64",),
}
TRIPLE_BY_PROFILE = {
    "pc-x86_64": "x86_64-unknown-aros",
    "arm-raspi": "arm-unknown-aros",
    "rpi-aarch64": "aarch64-unknown-aros",
}
REQUIRED_TOOLS = (
    "clang",
    "clang++",
    "ld.lld",
    "llvm-ar",
    "llvm-ranlib",
    "llvm-nm",
    "llvm-strip",
    "llvm-objcopy",
    "llvm-objdump",
)
COMPLETE_V1_MATRIX = {
    (host, profile)
    for host in SUPPORTED_HOSTS
    for profile in TRIPLE_BY_PROFILE
}


def fail(message: str) -> "None":
    raise SystemExit(f"toolchain producer: {message}")


def json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    ).encode("utf-8")


def read_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot read JSON {path}: {exc}")
    if not isinstance(value, dict):
        fail(f"{path} must contain a JSON object")
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def files_equal(left: Path, right: Path) -> bool:
    if not left.is_file() or not right.is_file() or left.stat().st_size != right.stat().st_size:
        return False
    with left.open("rb") as left_stream, right.open("rb") as right_stream:
        while True:
            left_chunk = left_stream.read(1024 * 1024)
            right_chunk = right_stream.read(1024 * 1024)
            if left_chunk != right_chunk:
                return False
            if not left_chunk:
                return True


def canonical_asset_name(llvm_version: str, host: str, target_profile: str) -> str:
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", llvm_version):
        fail(f"unsupported v1 LLVM version: {llvm_version!r}")
    if host not in SUPPORTED_HOSTS:
        fail(f"unsupported v1 release host: {host}")
    if target_profile not in TRIPLE_BY_PROFILE:
        fail(f"unsupported v1 target profile: {target_profile}")
    return f"aros-toolchain-v1-llvm{llvm_version}-{host}-{target_profile}.tar.xz"


def validate_manifest(manifest: dict, context: str = "toolchain manifest") -> None:
    required = {
        "schema": int,
        "release_id": str,
        "host": str,
        "target_profile": str,
        "target_triple": str,
        "tree_sha256": str,
        "llvm_version": str,
        "recipe_sha256": str,
        "source_lock_sha256": str,
        "profiles_sha256": str,
        "source_commit": str,
        "source_date_epoch": int,
        "capabilities": list,
        "build_environment": dict,
        "files": list,
    }
    for field, field_type in required.items():
        value = manifest.get(field)
        if type(value) is not field_type or (field_type is str and not value):
            fail(f"{context} has invalid or missing {field}")
    if manifest["schema"] != MANIFEST_SCHEMA:
        fail(f"unsupported {context} schema: {manifest['schema']!r}")
    if manifest["host"] not in SUPPORTED_HOSTS:
        fail(f"{context} has unsupported host: {manifest['host']}")
    expected_triple = TRIPLE_BY_PROFILE.get(manifest["target_profile"])
    if expected_triple is None or manifest["target_triple"] != expected_triple:
        fail(
            f"{context} has inconsistent target profile/triple: "
            f"{manifest['target_profile']}/{manifest['target_triple']}"
        )
    digest = manifest["tree_sha256"]
    for field in (
        "tree_sha256",
        "recipe_sha256",
        "source_lock_sha256",
        "profiles_sha256",
    ):
        digest = manifest[field]
        if len(digest) != 64 or any(
            character not in "0123456789abcdef" for character in digest
        ):
            fail(f"{context} has invalid {field}")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", manifest["llvm_version"]):
        fail(f"{context} has invalid llvm_version")
    if len(manifest["source_commit"]) != 40 or any(
        character not in "0123456789abcdef" for character in manifest["source_commit"]
    ):
        fail(f"{context} has invalid source_commit")
    if type(manifest["source_date_epoch"]) is not int or manifest["source_date_epoch"] < 0:
        fail(f"{context} has invalid source_date_epoch")
    capabilities = manifest["capabilities"]
    if not capabilities or any(not isinstance(value, str) or not value for value in capabilities):
        fail(f"{context} has invalid capabilities")
    if len(capabilities) != len(set(capabilities)):
        fail(f"{context} has duplicate capabilities")
    files = manifest["files"]
    if not files:
        fail(f"{context} has an empty file inventory")
    previous_path = None
    for entry in files:
        if not isinstance(entry, dict):
            fail(f"{context} has a non-object file entry")
        path = entry.get("path")
        mode = entry.get("mode")
        entry_type = entry.get("type")
        if (
            not isinstance(path, str)
            or not path
            or PurePosixPath(path).is_absolute()
            or ".." in PurePosixPath(path).parts
            or PurePosixPath(path).as_posix() != path
            or path == "toolchain-manifest.json"
        ):
            fail(f"{context} has an unsafe inventory path: {path!r}")
        if previous_path is not None and path <= previous_path:
            fail(f"{context} file inventory is not strictly path-sorted")
        previous_path = path
        if not isinstance(mode, str) or not re.fullmatch(r"[0-7]{4}", mode):
            fail(f"{context} has invalid mode for {path}")
        if entry_type == "directory":
            expected_keys = {"path", "mode", "type"}
            if mode != "0755":
                fail(f"{context} has invalid directory mode for {path}")
        elif entry_type == "symlink":
            expected_keys = {"path", "mode", "type", "target"}
            target = entry.get("target")
            if mode != "0777" or not isinstance(target, str) or not target or os.path.isabs(target):
                fail(f"{context} has invalid symlink entry for {path}")
            resolved_target = PurePosixPath(
                posixpath.normpath(str(PurePosixPath(path).parent / target))
            )
            if resolved_target.is_absolute() or ".." in resolved_target.parts:
                fail(f"{context} has escaping symlink entry for {path}")
        elif entry_type == "file":
            expected_keys = {"path", "mode", "type", "sha256", "size"}
            file_digest = entry.get("sha256")
            if (
                not isinstance(file_digest, str)
                or len(file_digest) != 64
                or any(character not in "0123456789abcdef" for character in file_digest)
                or type(entry.get("size")) is not int
                or entry["size"] < 0
                or mode not in {"0644", "0755"}
            ):
                fail(f"{context} has invalid file entry for {path}")
        else:
            fail(f"{context} has unsupported inventory type for {path}: {entry_type!r}")
        if set(entry) != expected_keys:
            fail(f"{context} has unexpected inventory fields for {path}")


def validate_source_lock(lock: dict) -> list[dict]:
    if set(lock) != {"schema", "family", "version", "sources", "host_python_packages"}:
        fail("source lock has unexpected or missing fields")
    if lock.get("schema") != SOURCE_SCHEMA or lock.get("family") != "llvm":
        fail("unsupported source-lock schema or family")
    if not isinstance(lock.get("version"), str) or not re.fullmatch(
        r"[0-9]+\.[0-9]+\.[0-9]+", lock["version"]
    ):
        fail("source lock has an invalid LLVM version")
    sources = lock.get("sources")
    if not isinstance(sources, list) or not sources:
        fail("source lock contains no sources")
    seen: set[str] = set()
    for source in sources:
        if not isinstance(source, dict):
            fail("source entry is not an object")
        if set(source) != {"component", "filename", "url", "sha256", "size"}:
            fail("source entry has unexpected or missing fields")
        component = source.get("component")
        filename = source.get("filename")
        checksum = source.get("sha256")
        url = source.get("url")
        size = source.get("size")
        if not isinstance(component, str) or not re.fullmatch(r"[A-Za-z0-9+._-]+", component):
            fail(f"invalid source component: {component!r}")
        if not isinstance(filename, str) or Path(filename).name != filename:
            fail(f"unsafe source filename: {filename!r}")
        if filename in seen:
            fail(f"duplicate source filename: {filename}")
        seen.add(filename)
        if not isinstance(checksum, str) or len(checksum) != 64 or any(
            c not in "0123456789abcdef" for c in checksum
        ):
            fail(f"invalid SHA-256 for {filename}")
        if not isinstance(url, str) or not url.startswith("https://"):
            fail(f"source URL must use HTTPS: {filename}")
        if not isinstance(size, int) or size <= 0:
            fail(f"invalid size for {filename}")

    for package in validate_host_python_packages(lock):
        if package["filename"] in seen:
            fail(f"duplicate source filename: {package['filename']}")
    return sources


def validate_host_python_packages(lock: dict) -> list[dict]:
    packages = lock.get("host_python_packages")
    if not isinstance(packages, list) or not packages:
        fail("source lock contains no host Python packages")
    names: set[str] = set()
    filenames: set[str] = set()
    roots: set[str] = set()
    for package in packages:
        if not isinstance(package, dict):
            fail("host Python package entry is not an object")
        if set(package) != {
            "name",
            "version",
            "filename",
            "url",
            "sha256",
            "size",
            "source_root",
            "python_path",
        }:
            fail("host Python package entry has unexpected or missing fields")
        name = package.get("name")
        version = package.get("version")
        filename = package.get("filename")
        url = package.get("url")
        checksum = package.get("sha256")
        size = package.get("size")
        source_root = package.get("source_root")
        python_path = package.get("python_path")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9+._-]+", name):
            fail(f"invalid host Python package name: {name!r}")
        if name in names:
            fail(f"duplicate host Python package name: {name}")
        names.add(name)
        if not isinstance(version, str) or not re.fullmatch(r"[A-Za-z0-9+._-]+", version):
            fail(f"invalid host Python package version for {name}: {version!r}")
        if not isinstance(filename, str) or Path(filename).name != filename:
            fail(f"unsafe host Python package filename: {filename!r}")
        if filename in filenames:
            fail(f"duplicate host Python package filename: {filename}")
        filenames.add(filename)
        if not isinstance(url, str) or not url.startswith("https://"):
            fail(f"host Python package URL must use HTTPS: {filename}")
        if not isinstance(checksum, str) or len(checksum) != 64 or any(
            character not in "0123456789abcdef" for character in checksum
        ):
            fail(f"invalid SHA-256 for host Python package {filename}")
        if not isinstance(size, int) or size <= 0:
            fail(f"invalid size for host Python package {filename}")
        if not isinstance(source_root, str):
            fail(f"invalid host Python source root for {name}: {source_root!r}")
        source_root_path = PurePosixPath(source_root)
        if (
            source_root_path.is_absolute()
            or len(source_root_path.parts) != 1
            or source_root_path.parts[0] in {"", ".", ".."}
        ):
            fail(f"unsafe host Python source root for {name}: {source_root!r}")
        if source_root in roots:
            fail(f"duplicate host Python source root: {source_root}")
        roots.add(source_root)
        if not isinstance(python_path, str):
            fail(f"invalid host Python import path for {name}: {python_path!r}")
        python_path_value = PurePosixPath(python_path)
        if (
            python_path_value.is_absolute()
            or ".." in python_path_value.parts
            or (python_path != "." and not python_path_value.parts)
        ):
            fail(f"unsafe host Python import path for {name}: {python_path!r}")
    return packages


def validate_recipe(recipe: dict, context: str = "toolchain recipe") -> None:
    if recipe.get("schema") != "aros-ng-toolchain-recipe-v1":
        fail(f"{context} has an unsupported schema")
    for field, length in (
        ("source_commit", 40),
        ("source_tree", 40),
        ("source_lock_sha256", 64),
        ("profiles_sha256", 64),
        ("recipe_sha256", 64),
    ):
        value = recipe.get(field)
        if not isinstance(value, str) or len(value) != length or any(
            character not in "0123456789abcdef" for character in value
        ):
            fail(f"{context} has invalid {field}")
    if type(recipe.get("source_date_epoch")) is not int or recipe["source_date_epoch"] < 0:
        fail(f"{context} has invalid source_date_epoch")
    if not isinstance(recipe.get("patches"), list):
        fail(f"{context} has invalid patches")
    material = dict(recipe)
    claimed_digest = material.pop("recipe_sha256")
    actual_digest = hashlib.sha256(json_bytes(material)).hexdigest()
    if actual_digest != claimed_digest:
        fail(f"{context} digest mismatch: {actual_digest} != {claimed_digest}")


def required_paths(llvm_version: str, target_profile: str) -> list[str]:
    paths = [f"bin/{tool}" for tool in REQUIRED_TOOLS]
    paths.extend(
        [
            "include/c++/v1/vector",
            "lib/libc++.a",
            "lib/libc++abi.a",
            "lib/libunwind.a",
            "toolchain-manifest.json",
        ]
    )
    for architecture in BUILTINS_BY_PROFILE[target_profile]:
        paths.append(
            f"lib/clang/{llvm_version}/lib/aros/"
            f"libclang_rt.builtins-{architecture}.a"
        )
    return paths


def verify_source(path: Path, source: dict) -> None:
    actual_size = path.stat().st_size
    if actual_size != source["size"]:
        fail(f"size mismatch for {path.name}: {actual_size} != {source['size']}")
    actual_hash = sha256_file(path)
    if actual_hash != source["sha256"]:
        fail(f"SHA-256 mismatch for {path.name}: {actual_hash} != {source['sha256']}")


def command_prefetch(args: argparse.Namespace) -> None:
    lock_path = args.lock.resolve()
    lock = read_json(lock_path)
    sources = [*validate_source_lock(lock), *validate_host_python_packages(lock)]
    destination = args.destination.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    verified = []
    for source in sources:
        target = destination / source["filename"]
        if not target.exists():
            if args.offline:
                fail(f"offline source is missing: {target}")
            temporary = target.with_name(target.name + f".tmp-{os.getpid()}")
            try:
                request = urllib.request.Request(
                    source["url"], headers={"User-Agent": "AROS-NG-toolchain-producer/1"}
                )
                with urllib.request.urlopen(request, timeout=60) as response, temporary.open(
                    "wb"
                ) as output:
                    shutil.copyfileobj(response, output, 1024 * 1024)
                verify_source(temporary, source)
                os.replace(temporary, target)
            finally:
                temporary.unlink(missing_ok=True)
        verify_source(target, source)
        verified.append(
            {
                "filename": source["filename"],
                "sha256": source["sha256"],
                "size": source["size"],
            }
        )
        print(f"verified {source['filename']} {source['sha256']}")
    index = {
        "schema": "aros-ng-toolchain-verified-sources-v1",
        "lock_sha256": sha256_file(lock_path),
        "sources": sorted(verified, key=lambda item: item["filename"]),
    }
    output = args.index or destination / "sources.verified.json"
    output.write_bytes(json_bytes(index))


def git(source_root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(source_root), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    return result.stdout.strip()


def command_recipe(args: argparse.Namespace) -> None:
    root = args.source_root.resolve()
    if not args.allow_dirty:
        dirty = git(root, "status", "--porcelain", "--untracked-files=all")
        if dirty:
            fail("source tree is dirty; release recipes require a clean commit")
    commit = git(root, "rev-parse", "HEAD")
    tree = git(root, "rev-parse", "HEAD^{tree}")
    lock = args.lock.resolve()
    profiles = args.profiles.resolve()
    lock_data = read_json(lock)
    sources = validate_source_lock(lock_data)
    profile_data = read_json(profiles)
    if profile_data.get("schema") != PROFILE_SCHEMA:
        fail("unsupported profile schema")
    patches = []
    for source in sources:
        patch = root / "tools" / "crosstools" / "llvm" / (
            source["filename"].removesuffix(".tar.xz") + "-aros.diff"
        )
        if not patch.is_file():
            fail(f"required AROS patch is missing: {patch}")
        patches.append(
            {"path": patch.relative_to(root).as_posix(), "sha256": sha256_file(patch)}
        )
    epoch = int(git(root, "show", "-s", "--format=%ct", commit))
    material = {
        "schema": "aros-ng-toolchain-recipe-v1",
        "source_commit": commit,
        "source_tree": tree,
        "source_date_epoch": epoch,
        "source_lock_sha256": sha256_file(lock),
        "profiles_sha256": sha256_file(profiles),
        "patches": sorted(patches, key=lambda item: item["path"]),
    }
    material["recipe_sha256"] = hashlib.sha256(json_bytes(material)).hexdigest()
    validate_recipe(material)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(material, sort_keys=True, indent=2) + "\n")
    print(material["recipe_sha256"])


def command_verify_checkout(args: argparse.Namespace) -> None:
    root = args.source_root.resolve()
    recipe = read_json(args.recipe)
    validate_recipe(recipe)
    if sha256_file(args.lock) != recipe["source_lock_sha256"]:
        fail("source lock differs from checkout recipe")
    if sha256_file(args.profiles) != recipe["profiles_sha256"]:
        fail("target profiles differ from checkout recipe")
    dirty = git(root, "status", "--porcelain", "--untracked-files=no")
    if dirty:
        fail("tracked source tree differs from HEAD")
    actual_commit = git(root, "rev-parse", "HEAD")
    actual_tree = git(root, "rev-parse", "HEAD^{tree}")
    if actual_commit != recipe["source_commit"]:
        fail(
            f"checkout commit differs from recipe: "
            f"{actual_commit} != {recipe['source_commit']}"
        )
    if actual_tree != recipe["source_tree"]:
        fail(f"checkout tree differs from recipe: {actual_tree} != {recipe['source_tree']}")
    print(f"verified checkout {actual_commit} {actual_tree}")


def profile_by_name(path: Path, name: str) -> tuple[dict, dict]:
    data = read_json(path)
    if data.get("schema") != PROFILE_SCHEMA or not isinstance(data.get("profiles"), list):
        fail("unsupported profile document")
    matches = [profile for profile in data["profiles"] if profile.get("name") == name]
    if len(matches) != 1:
        fail(f"profile {name!r} is missing or ambiguous")
    return data, matches[0]


def normalized_mode(path: Path) -> int:
    mode = stat.S_IMODE(path.lstat().st_mode)
    if path.is_symlink():
        return 0o777
    if path.is_dir():
        return 0o755
    return 0o755 if mode & 0o111 else 0o644


def normalize_tree(root: Path, epoch: int) -> None:
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix(), reverse=True):
        if path.name == ".DS_Store" or path.name.startswith(".installflag-"):
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path)
            else:
                path.unlink()
            continue
        if path.is_symlink():
            target = os.readlink(path)
            if os.path.isabs(target):
                fail(f"absolute symlink is not relocatable: {path} -> {target}")
            resolved = (path.parent / target).resolve(strict=False)
            try:
                common = os.path.commonpath((str(root.resolve()), str(resolved)))
            except ValueError:
                common = ""
            if common != str(root.resolve()):
                fail(f"symlink escapes the toolchain root: {path} -> {target}")
        else:
            os.chmod(path, normalized_mode(path))
        try:
            os.utime(path, (epoch, epoch), follow_symlinks=False)
        except (NotImplementedError, PermissionError):
            pass
    os.chmod(root, 0o755)
    os.utime(root, (epoch, epoch))


def scan_prefixes(root: Path, forbidden: list[str]) -> None:
    needles = [(item, item.encode()) for item in forbidden if item and os.path.isabs(item)]
    if not needles:
        return
    findings = []
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if not path.is_file() or path.is_symlink():
            continue
        try:
            with path.open("rb") as stream:
                overlap = b""
                while chunk := stream.read(1024 * 1024):
                    content = overlap + chunk
                    for label, needle in needles:
                        if needle in content:
                            findings.append(f"{path.relative_to(root)} contains {label}")
                    if findings:
                        break
                    keep = max((len(needle) for _, needle in needles), default=1) - 1
                    overlap = content[-keep:] if keep else b""
        except OSError as exc:
            fail(f"cannot scan {path}: {exc}")
        if len(findings) >= 20:
            break
    if findings:
        fail("non-relocatable build prefixes found:\n  " + "\n  ".join(findings))


def tree_inventory(root: Path) -> tuple[list[dict], str]:
    inventory = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        if relative == "toolchain-manifest.json":
            continue
        entry: dict = {"path": relative, "mode": f"{normalized_mode(path):04o}"}
        if path.is_symlink():
            entry.update({"type": "symlink", "target": os.readlink(path)})
        elif path.is_dir():
            entry["type"] = "directory"
        elif path.is_file():
            entry.update({"type": "file", "sha256": sha256_file(path), "size": path.stat().st_size})
        else:
            fail(f"unsupported filesystem entry in toolchain: {path}")
        inventory.append(entry)
    digest = hashlib.sha256()
    for entry in inventory:
        digest.update(json_bytes(entry))
    return inventory, digest.hexdigest()


def add_tar_entry(archive: tarfile.TarFile, root: Path, path: Path, epoch: int) -> None:
    relative = path.relative_to(root).as_posix() if path != root else ""
    name = "toolchain" + (f"/{relative}" if relative else "")
    info = tarfile.TarInfo(name)
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.mtime = epoch
    info.mode = normalized_mode(path)
    if path.is_symlink():
        info.type = tarfile.SYMTYPE
        info.linkname = os.readlink(path)
        archive.addfile(info)
    elif path.is_dir():
        info.type = tarfile.DIRTYPE
        archive.addfile(info)
    elif path.is_file():
        info.type = tarfile.REGTYPE
        info.size = path.stat().st_size
        with path.open("rb") as stream:
            archive.addfile(info, stream)
    else:
        fail(f"cannot archive special file: {path}")


def write_spdx(path: Path, manifest: dict, lock: dict) -> None:
    epoch = dt.datetime.fromtimestamp(manifest["source_date_epoch"], dt.timezone.utc)
    packages = [
        {
            "SPDXID": "SPDXRef-Package-AROSToolchain",
            "name": f"AROS-NG {manifest['target_profile']} toolchain",
            "versionInfo": manifest["release_id"],
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "checksums": [{"algorithm": "SHA256", "checksumValue": manifest["tree_sha256"]}],
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
        }
    ]
    relationships = []
    for index, source in enumerate(validate_source_lock(lock), start=1):
        identifier = f"SPDXRef-Source-{index}"
        packages.append(
            {
                "SPDXID": identifier,
                "name": source["component"],
                "versionInfo": lock["version"],
                "downloadLocation": source["url"],
                "filesAnalyzed": False,
                "checksums": [{"algorithm": "SHA256", "checksumValue": source["sha256"]}],
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "copyrightText": "NOASSERTION",
            }
        )
        relationships.append(
            {
                "spdxElementId": "SPDXRef-Package-AROSToolchain",
                "relationshipType": "GENERATED_FROM",
                "relatedSpdxElement": identifier,
            }
        )
    for index, package in enumerate(validate_host_python_packages(lock), start=1):
        identifier = f"SPDXRef-HostPython-{index}"
        packages.append(
            {
                "SPDXID": identifier,
                "name": package["name"],
                "versionInfo": package["version"],
                "downloadLocation": package["url"],
                "filesAnalyzed": False,
                "checksums": [{"algorithm": "SHA256", "checksumValue": package["sha256"]}],
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "copyrightText": "NOASSERTION",
            }
        )
        relationships.append(
            {
                "spdxElementId": identifier,
                "relationshipType": "BUILD_DEPENDENCY_OF",
                "relatedSpdxElement": "SPDXRef-Package-AROSToolchain",
            }
        )
    document = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"AROS-NG-toolchain-{manifest['tree_sha256'][:16]}",
        "documentNamespace": f"https://github.com/metaneutrons/AROS-NG/toolchain/{manifest['tree_sha256']}",
        "creationInfo": {
            "created": epoch.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "creators": ["Tool: AROS-NG-toolchain-producer-1"],
        },
        "documentDescribes": ["SPDXRef-Package-AROSToolchain"],
        "packages": packages,
        "relationships": relationships,
    }
    path.write_text(json.dumps(document, sort_keys=True, indent=2) + "\n")


def command_package(args: argparse.Namespace) -> None:
    source = args.root.resolve()
    if not source.is_dir():
        fail(f"toolchain root does not exist: {source}")
    recipe = read_json(args.recipe)
    validate_recipe(recipe)
    build_environment = read_json(args.build_environment) if args.build_environment else {}
    lock = read_json(args.lock)
    validate_source_lock(lock)
    _, profile = profile_by_name(args.profiles, args.target_profile)
    if sha256_file(args.lock) != recipe["source_lock_sha256"]:
        fail("source lock does not match the release recipe")
    if sha256_file(args.profiles) != recipe["profiles_sha256"]:
        fail("target profiles do not match the release recipe")
    expected_asset_name = canonical_asset_name(lock["version"], args.host, args.target_profile)
    if args.asset_name != expected_asset_name:
        fail(f"non-canonical asset name: {args.asset_name!r}; expected {expected_asset_name!r}")
    for suffix in ("", ".sha256", ".manifest.json", ".spdx.json"):
        output_path = args.output_dir / f"{args.asset_name}{suffix}"
        if output_path.exists():
            fail(f"refusing to replace existing release output: {output_path}")
    epoch = int(recipe["source_date_epoch"])
    args.output_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="aros-toolchain-package-") as temporary:
        staging = Path(temporary) / "toolchain"
        shutil.copytree(source, staging, symlinks=True)
        normalize_tree(staging, epoch)
        scan_prefixes(staging, [str(path) for path in args.forbid_prefix])
        inventory, tree_hash = tree_inventory(staging)
        manifest = {
            "schema": MANIFEST_SCHEMA,
            "release_id": args.release_id,
            "host": args.host,
            "target_profile": args.target_profile,
            "target_triple": profile["target_triple"],
            "tree_sha256": tree_hash,
            "llvm_version": lock["version"],
            "recipe_sha256": recipe["recipe_sha256"],
            "source_lock_sha256": recipe["source_lock_sha256"],
            "profiles_sha256": recipe["profiles_sha256"],
            "source_commit": recipe["source_commit"],
            "source_date_epoch": epoch,
            "capabilities": profile.get("capabilities", []),
            "build_environment": build_environment,
            "files": inventory,
        }
        validate_manifest(manifest)
        manifest_path = staging / "toolchain-manifest.json"
        manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
        os.chmod(manifest_path, 0o644)
        os.utime(manifest_path, (epoch, epoch))
        archive_path = args.output_dir / args.asset_name
        with tarfile.open(archive_path, "w:xz", format=tarfile.PAX_FORMAT, preset=9) as archive:
            add_tar_entry(archive, staging, staging, epoch)
            for path in sorted(staging.rglob("*"), key=lambda item: item.relative_to(staging).as_posix()):
                add_tar_entry(archive, staging, path, epoch)
        archive_hash = sha256_file(archive_path)
        (args.output_dir / f"{args.asset_name}.sha256").write_text(
            f"{archive_hash}  {args.asset_name}\n"
        )
        shutil.copy2(manifest_path, args.output_dir / f"{args.asset_name}.manifest.json")
        write_spdx(args.output_dir / f"{args.asset_name}.spdx.json", manifest, lock)
        print(archive_hash)


def safe_extract(archive_path: Path, destination: Path) -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive_path, "r:xz") as archive:
        members = archive.getmembers()
        for member in members:
            pure = PurePosixPath(member.name)
            if pure.is_absolute() or ".." in pure.parts or not pure.parts or pure.parts[0] != "toolchain":
                fail(f"unsafe archive member: {member.name}")
            if not (member.isdir() or member.isfile() or member.issym()):
                fail(f"unsupported archive member type: {member.name}")
            if member.issym() or member.islnk():
                link = PurePosixPath(member.linkname)
                resolved = PurePosixPath(posixpath.normpath(str(pure.parent / link)))
                if link.is_absolute() or not resolved.parts or resolved.parts[0] != "toolchain" or ".." in resolved.parts:
                    fail(f"unsafe archive link: {member.name} -> {member.linkname}")
        archive.extractall(destination)
    return destination / "toolchain"


def executable(root: Path, name: str) -> Path:
    candidates = [root / "bin" / name, root / "bin" / f"{name}.exe"]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    fail(f"required executable is absent: bin/{name}")


def run_probe(
    root: Path, triple: str, target_profile: str, fixtures: Path, output: Path
) -> tuple[str, str]:
    clang = executable(root, "clang")
    clangxx = executable(root, "clang++")
    for tool in REQUIRED_TOOLS[2:]:
        executable(root, tool)
    subprocess.run([str(clang), "--version"], check=True, stdout=subprocess.PIPE)
    c_object = output / "smoke-c.o"
    cxx_object = output / "smoke-cxx.o"
    common = [f"--target={triple}", "-ffreestanding", "-fno-ident", "-g0", "-c"]
    subprocess.run([str(clang), *common, str(fixtures / "smoke.c"), "-o", str(c_object)], check=True)
    subprocess.run(
        [str(clangxx), *common, "-nostdinc++", str(fixtures / "smoke.cpp"), "-o", str(cxx_object)],
        check=True,
    )
    if not (root / "include" / "c++" / "v1" / "vector").is_file():
        fail("libc++ header include/c++/v1/vector is absent")
    for library in ("libc++.a", "libc++abi.a", "libunwind.a"):
        if not (root / "lib" / library).is_file():
            fail(f"target runtime is absent: lib/{library}")
    builtins = BUILTINS_BY_PROFILE.get(target_profile)
    if not builtins:
        fail(f"no compiler-rt contract exists for profile {target_profile}")
    for architecture in builtins:
        pattern = f"lib/clang/*/lib/aros/libclang_rt.builtins-{architecture}.a"
        if not any(root.glob(pattern)):
            fail(f"target compiler-rt builtins are absent: {pattern}")
    return sha256_file(c_object), sha256_file(cxx_object)


def verify_tree(root: Path, manifest: dict) -> None:
    inventory, tree_hash = tree_inventory(root)
    if tree_hash != manifest.get("tree_sha256"):
        fail(f"tree digest mismatch: {tree_hash} != {manifest.get('tree_sha256')}")
    if inventory != manifest.get("files"):
        fail("canonical file inventory differs from toolchain manifest")


def command_verify(args: argparse.Namespace) -> None:
    fixtures = args.fixtures.resolve()
    with tempfile.TemporaryDirectory(prefix="aros-toolchain-relocate-a-") as a_temp, tempfile.TemporaryDirectory(
        prefix="aros-toolchain-relocate-b-longer-path-"
    ) as b_temp:
        roots = [
            safe_extract(args.archive.resolve(), Path(a_temp) / "one"),
            safe_extract(args.archive.resolve(), Path(b_temp) / "nested" / "two"),
        ]
        object_hashes = []
        for index, root in enumerate(roots):
            manifest = read_json(root / "toolchain-manifest.json")
            validate_manifest(manifest, "internal toolchain manifest")
            if args.host and manifest.get("host") != args.host:
                fail("host does not match internal manifest")
            if args.target_profile and manifest.get("target_profile") != args.target_profile:
                fail("target profile does not match internal manifest")
            verify_tree(root, manifest)
            scan_prefixes(root, [str(path) for path in args.forbid_prefix])
            probe_output = Path(a_temp if index == 0 else b_temp) / "objects"
            probe_output.mkdir()
            object_hashes.append(
                run_probe(
                    root,
                    manifest["target_triple"],
                    manifest["target_profile"],
                    fixtures,
                    probe_output,
                )
            )
        if object_hashes[0] != object_hashes[1]:
            fail("relocation probe objects differ between extraction roots")
    print("two-root relocation probe passed")


def command_compare(args: argparse.Namespace) -> None:
    if not args.left.is_file() or not args.right.is_file():
        fail(f"comparison archive is absent: {args.left} or {args.right}")
    left_hash = sha256_file(args.left)
    right_hash = sha256_file(args.right)
    if left_hash != right_hash or not files_equal(args.left, args.right):
        fail(f"independent archives differ: {left_hash} != {right_hash}")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for suffix in ("", ".sha256", ".manifest.json", ".spdx.json"):
        left = args.left.with_name(args.left.name + suffix)
        right = args.right.with_name(args.right.name + suffix)
        if not left.is_file() or not right.is_file():
            fail(f"comparison support file is absent: {left} or {right}")
        if sha256_file(left) != sha256_file(right) or not files_equal(left, right):
            fail(f"independent release files differ: {left.name}")
        shutil.copy2(left, args.output_dir / left.name)
    print(left_hash)


def command_index(args: argparse.Namespace) -> None:
    directory = args.directory.resolve()
    base_url = args.base_url.rstrip("/")
    if not base_url.startswith("https://"):
        fail("release base URL must use HTTPS")
    manifests = sorted(directory.glob("*.tar.xz.manifest.json"))
    if not manifests:
        fail("no verified release manifests found")
    assets = []
    checksum_lines = []
    release_id = None
    matrix_entries = set()
    llvm_versions = set()
    recipe_digests = set()
    source_lock_digests = set()
    profiles_digests = set()
    for manifest_path in manifests:
        manifest = read_json(manifest_path)
        validate_manifest(manifest, str(manifest_path))
        release_id = release_id or manifest["release_id"]
        if manifest["release_id"] != release_id:
            fail("mixed release IDs in publish directory")
        asset_name = manifest_path.name.removesuffix(".manifest.json")
        expected_asset_name = canonical_asset_name(
            str(manifest.get("llvm_version", "")),
            manifest["host"],
            manifest["target_profile"],
        )
        if asset_name != expected_asset_name:
            fail(f"non-canonical release asset: {asset_name}; expected {expected_asset_name}")
        asset_path = directory / asset_name
        if not asset_path.is_file():
            fail(f"release archive is absent: {asset_path}")
        checksum = sha256_file(asset_path)
        sidecar = directory / f"{asset_name}.sha256"
        spdx = directory / f"{asset_name}.spdx.json"
        if not sidecar.is_file() or sidecar.read_text(encoding="utf-8") != f"{checksum}  {asset_name}\n":
            fail(f"invalid or missing archive checksum sidecar: {sidecar}")
        if not spdx.is_file():
            fail(f"release SBOM is absent: {spdx}")
        matrix_entry = (manifest["host"], manifest["target_profile"])
        if matrix_entry in matrix_entries:
            fail(f"duplicate release matrix entry: {matrix_entry[0]}/{matrix_entry[1]}")
        matrix_entries.add(matrix_entry)
        llvm_versions.add(manifest.get("llvm_version"))
        recipe_digests.add(manifest.get("recipe_sha256"))
        source_lock_digests.add(manifest.get("source_lock_sha256"))
        profiles_digests.add(manifest.get("profiles_sha256"))
        assets.append(
            {
                "asset": asset_name,
                "sha256": checksum,
                "size": asset_path.stat().st_size,
                "host": manifest["host"],
                "target_profile": manifest["target_profile"],
                "target_triple": manifest["target_triple"],
                "tree_sha256": manifest["tree_sha256"],
                "llvm_version": manifest.get("llvm_version"),
                "enabled": True,
                "strip_components": 1,
                "required_paths": required_paths(
                    manifest["llvm_version"], manifest["target_profile"]
                ),
            }
        )
    if len(llvm_versions) != 1:
        fail("mixed LLVM versions in publish directory")
    if args.require_complete_v1 and matrix_entries != COMPLETE_V1_MATRIX:
        missing = sorted(COMPLETE_V1_MATRIX - matrix_entries)
        extra = sorted(matrix_entries - COMPLETE_V1_MATRIX)
        fail(f"incomplete v1 release matrix; missing={missing}, extra={extra}")
    if len(recipe_digests) != 1 or len(source_lock_digests) != 1 or len(profiles_digests) != 1:
        fail("mixed or missing recipe input digests in publish directory")
    if args.require_complete_v1:
        recipe_path = directory / "toolchain-recipe-v1.json"
        recipe = read_json(recipe_path)
        validate_recipe(recipe, str(recipe_path))
        if recipe_digests != {recipe["recipe_sha256"]}:
            fail("published recipe does not match artifact manifests")
        source_locks = sorted(directory.glob("*.sources.json"))
        if len(source_locks) != 1 or source_lock_digests != {sha256_file(source_locks[0])}:
            fail("published source lock does not match artifact manifests")
        profiles_path = directory / "profiles-v1.json"
        if not profiles_path.is_file() or profiles_digests != {sha256_file(profiles_path)}:
            fail("published profiles do not match artifact manifests")
    index = {
        "schema": 1,
        "release_id": release_id,
        "base_url": base_url,
        "artifacts": assets,
    }
    (directory / "toolchain-index-v1.json").write_text(json.dumps(index, sort_keys=True, indent=2) + "\n")
    for path in sorted(directory.iterdir(), key=lambda item: item.name):
        if path.is_file() and path.name != "SHA256SUMS":
            checksum_lines.append(f"{sha256_file(path)}  {path.name}")
    (directory / "SHA256SUMS").write_text("\n".join(sorted(checksum_lines)) + "\n")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    prefetch = commands.add_parser("prefetch")
    prefetch.add_argument("--lock", type=Path, required=True)
    prefetch.add_argument("--destination", type=Path, required=True)
    prefetch.add_argument("--index", type=Path)
    prefetch.add_argument("--offline", action="store_true")
    prefetch.set_defaults(function=command_prefetch)
    recipe = commands.add_parser("recipe")
    recipe.add_argument("--source-root", type=Path, required=True)
    recipe.add_argument("--lock", type=Path, required=True)
    recipe.add_argument("--profiles", type=Path, required=True)
    recipe.add_argument("--output", type=Path, required=True)
    recipe.add_argument("--allow-dirty", action="store_true")
    recipe.set_defaults(function=command_recipe)
    checkout = commands.add_parser("verify-checkout")
    checkout.add_argument("--source-root", type=Path, required=True)
    checkout.add_argument("--recipe", type=Path, required=True)
    checkout.add_argument("--lock", type=Path, required=True)
    checkout.add_argument("--profiles", type=Path, required=True)
    checkout.set_defaults(function=command_verify_checkout)
    package = commands.add_parser("package")
    package.add_argument("--root", type=Path, required=True)
    package.add_argument("--recipe", type=Path, required=True)
    package.add_argument("--lock", type=Path, required=True)
    package.add_argument("--profiles", type=Path, required=True)
    package.add_argument("--release-id", required=True)
    package.add_argument("--host", required=True)
    package.add_argument("--target-profile", required=True)
    package.add_argument("--asset-name", required=True)
    package.add_argument("--output-dir", type=Path, required=True)
    package.add_argument("--build-environment", type=Path)
    package.add_argument("--forbid-prefix", type=Path, action="append", default=[])
    package.set_defaults(function=command_package)
    verify = commands.add_parser("verify")
    verify.add_argument("--archive", type=Path, required=True)
    verify.add_argument("--fixtures", type=Path, required=True)
    verify.add_argument("--host")
    verify.add_argument("--target-profile")
    verify.add_argument("--forbid-prefix", type=Path, action="append", default=[])
    verify.set_defaults(function=command_verify)
    compare = commands.add_parser("compare")
    compare.add_argument("--left", type=Path, required=True)
    compare.add_argument("--right", type=Path, required=True)
    compare.add_argument("--output-dir", type=Path, required=True)
    compare.set_defaults(function=command_compare)
    index = commands.add_parser("index")
    index.add_argument("--directory", type=Path, required=True)
    index.add_argument("--base-url", required=True)
    index.add_argument("--require-complete-v1", action="store_true")
    index.set_defaults(function=command_index)
    return root


def main() -> None:
    args = parser().parse_args()
    args.function(args)


if __name__ == "__main__":
    main()
