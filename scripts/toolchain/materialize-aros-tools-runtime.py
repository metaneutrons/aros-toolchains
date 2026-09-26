#!/usr/bin/env python3
"""Materialise a locked, attestable aros-tools GitHub Release runtime.

The toolchain producer deliberately consumes released aros-tools executables,
not an arbitrary source checkout or a locally built Cargo target directory.
This bootstrap validates the release API object, annotated Git tag, signed
archive and manifest, GitHub provenance, and extracted file inventory before
making a runtime available to the producer.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from typing import Any


HOST_TARGETS = {
    "linux-x86_64": "x86_64-unknown-linux-gnu",
    "linux-aarch64": "aarch64-unknown-linux-gnu",
    "macos-aarch64": "aarch64-apple-darwin",
}
EXPECTED_FILES = {
    "LICENSE": ("0644", False),
    "README.md": ("0644", False),
    "bin/aros": ("0755", True),
    "bin/aros-ahi-runner": ("0755", True),
    "bin/aros-collect": ("0755", True),
    "bin/aros-fetch": ("0755", True),
    "bin/aros-genmodule": ("0755", True),
    "bin/aros-romtool": ("0755", True),
    "bin/aros-transpiler": ("0755", True),
    "bin/aros-verify": ("0755", True),
}
ASSET_FIELDS = {"name", "sha256", "size"}


class RuntimeError(Exception):
    """An untrusted runtime input failed a closed-world contract."""


def fail(message: str) -> None:
    raise RuntimeError(message)


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot read JSON {path}: {exc}")


def require_exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        observed = sorted(value) if isinstance(value, dict) else type(value).__name__
        fail(f"{label} must contain exactly {sorted(expected)}, got {observed}")
    return value


def require_hex(value: Any, length: int, label: str) -> str:
    if not isinstance(value, str) or len(value) != length or any(c not in "0123456789abcdef" for c in value):
        fail(f"{label} must be {length} lowercase hexadecimal characters")
    return value


def require_name(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "/" in value or "\\" in value or value in {".", ".."}:
        fail(f"{label} must be a non-empty basename")
    return value


def validate_asset(value: Any, label: str) -> dict[str, Any]:
    asset = require_exact_keys(value, ASSET_FIELDS, label)
    require_name(asset["name"], f"{label}.name")
    require_hex(asset["sha256"], 64, f"{label}.sha256")
    if not isinstance(asset["size"], int) or isinstance(asset["size"], bool) or asset["size"] <= 0:
        fail(f"{label}.size must be a positive integer")
    return asset


def validate_lock(value: Any) -> dict[str, Any]:
    top = require_exact_keys(
        value,
        {
            "schema", "repository", "release_id", "version", "tag", "tag_object",
            "source_commit", "source_tree", "source_date_epoch", "signer_workflow",
            "certificate_identity", "certificate_oidc_issuer", "hosts",
        },
        "runtime lock",
    )
    if top["schema"] != "aros-tools-runtime-v1":
        fail("unsupported runtime lock schema")
    if not isinstance(top["repository"], str) or top["repository"].count("/") != 1:
        fail("runtime lock repository must be an OWNER/REPO name")
    if not isinstance(top["release_id"], int) or top["release_id"] <= 0:
        fail("runtime lock release_id must be a positive integer")
    if not isinstance(top["version"], str) or not top["version"]:
        fail("runtime lock version must be non-empty")
    if top["tag"] != f"v{top['version']}":
        fail("runtime lock tag must be the exact vVERSION tag")
    require_hex(top["tag_object"], 40, "runtime lock tag_object")
    require_hex(top["source_commit"], 40, "runtime lock source_commit")
    require_hex(top["source_tree"], 40, "runtime lock source_tree")
    if not isinstance(top["source_date_epoch"], int) or top["source_date_epoch"] <= 0:
        fail("runtime lock source_date_epoch must be a positive integer")
    expected_workflow = f"{top['repository']}/.github/workflows/release.yml"
    if top["signer_workflow"] != expected_workflow:
        fail("runtime lock signer_workflow must be its canonical release workflow")
    expected_identity = f"https://github.com/{expected_workflow}@refs/tags/{top['tag']}"
    if top["certificate_identity"] != expected_identity:
        fail("runtime lock certificate_identity must bind the exact release tag")
    if top["certificate_oidc_issuer"] != "https://token.actions.githubusercontent.com":
        fail("runtime lock certificate_oidc_issuer must be GitHub Actions")
    hosts = top["hosts"]
    if not isinstance(hosts, dict) or set(hosts) != set(HOST_TARGETS):
        fail(f"runtime lock hosts must be exactly {sorted(HOST_TARGETS)}")
    seen_names: set[str] = set()
    for host, target in HOST_TARGETS.items():
        entry = require_exact_keys(
            hosts[host], {"target", "archive", "manifest", "archive_bundle", "manifest_bundle"}, host
        )
        if entry["target"] != target:
            fail(f"runtime lock {host} target must be {target}")
        for field in ("archive", "manifest", "archive_bundle", "manifest_bundle"):
            asset = validate_asset(entry[field], f"{host}.{field}")
            if asset["name"] in seen_names:
                fail(f"runtime lock reuses asset name {asset['name']}")
            seen_names.add(asset["name"])
        archive = entry["archive"]["name"]
        if archive != f"aros-tools-{top['tag']}-{target}.tar.gz":
            fail(f"runtime lock {host} archive does not match version and target")
        if entry["manifest"]["name"] != f"{archive}.manifest.json":
            fail(f"runtime lock {host} manifest name is not archive-bound")
        if entry["archive_bundle"]["name"] != f"{archive}.sigstore.json":
            fail(f"runtime lock {host} archive bundle name is not archive-bound")
        if entry["manifest_bundle"]["name"] != f"{archive}.manifest.json.sigstore.json":
            fail(f"runtime lock {host} manifest bundle name is not manifest-bound")
    return top


def run(command: list[str], label: str, *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, cwd=cwd, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError:
        fail(f"{label} requires executable {command[0]!r}")
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.strip() or exc.stdout.strip() or f"exit status {exc.returncode}"
        fail(f"{label} failed: {detail}")


def require_release_identity(lock: dict[str, Any]) -> dict[str, Any]:
    result = run(["gh", "api", f"repos/{lock['repository']}/releases/{lock['release_id']}"], "GitHub release lookup")
    try:
        release = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        fail(f"GitHub release lookup returned invalid JSON: {exc}")
    if not isinstance(release, dict):
        fail("GitHub release lookup did not return an object")
    expected = {
        "id": lock["release_id"], "tag_name": lock["tag"], "draft": False,
        "prerelease": False, "immutable": True,
    }
    for field, wanted in expected.items():
        if release.get(field) != wanted:
            fail(f"GitHub release {field} differs from runtime lock: {release.get(field)!r} != {wanted!r}")
    assets = release.get("assets")
    if not isinstance(assets, list):
        fail("GitHub release assets must be an array")
    expected_assets = {
        asset["name"]: asset
        for host in lock["hosts"].values()
        for asset in (host["archive"], host["manifest"], host["archive_bundle"], host["manifest_bundle"])
    }
    actual_assets: dict[str, dict[str, Any]] = {}
    for asset in assets:
        if isinstance(asset, dict) and isinstance(asset.get("name"), str) and asset["name"] in expected_assets:
            if asset["name"] in actual_assets:
                fail(f"GitHub release has duplicate locked asset {asset['name']}")
            actual_assets[asset["name"]] = asset
    if set(actual_assets) != set(expected_assets):
        fail("GitHub release asset set does not contain every locked runtime asset exactly once")
    for name, expected_asset in expected_assets.items():
        actual = actual_assets[name]
        if actual.get("size") != expected_asset["size"]:
            fail(f"GitHub release asset size differs for {name}")
        if actual.get("digest") != f"sha256:{expected_asset['sha256']}":
            fail(f"GitHub release asset digest differs for {name}")
        if not isinstance(actual.get("id"), int) or actual["id"] <= 0:
            fail(f"GitHub release asset id is invalid for {name}")
    return actual_assets


def require_git_identity(lock: dict[str, Any]) -> None:
    remote = f"https://github.com/{lock['repository']}.git"
    result = run(
        ["git", "ls-remote", "--tags", remote, f"refs/tags/{lock['tag']}", f"refs/tags/{lock['tag']}^{{}}"],
        "annotated tag lookup",
    )
    identities: dict[str, str] = {}
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) == 2:
            identities[fields[1]] = fields[0]
    if identities.get(f"refs/tags/{lock['tag']}") != lock["tag_object"]:
        fail("remote annotated tag object differs from runtime lock")
    if identities.get(f"refs/tags/{lock['tag']}^{{}}") != lock["source_commit"]:
        fail("remote annotated tag target differs from runtime lock")
    result = run(["gh", "api", f"repos/{lock['repository']}/git/commits/{lock['source_commit']}"], "GitHub commit lookup")
    try:
        commit = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        fail(f"GitHub commit lookup returned invalid JSON: {exc}")
    if not isinstance(commit, dict) or commit.get("tree", {}).get("sha") != lock["source_tree"]:
        fail("GitHub source tree differs from runtime lock")
    date = commit.get("committer", {}).get("date")
    if not isinstance(date, str):
        fail("GitHub source commit lacks a committer date")
    try:
        observed_epoch = int(dt.datetime.fromisoformat(date.replace("Z", "+00:00")).timestamp())
    except ValueError as exc:
        fail(f"GitHub source committer date is invalid: {exc}")
    if observed_epoch != lock["source_date_epoch"]:
        fail("GitHub source committer date differs from runtime lock")


def download_asset(lock: dict[str, Any], asset: dict[str, Any], asset_id: int, directory: Path) -> Path:
    target = directory / asset["name"]
    command = [
        "gh", "api", "-H", "Accept: application/octet-stream",
        f"repos/{lock['repository']}/releases/assets/{asset_id}",
    ]
    try:
        with target.open("xb") as output:
            result = subprocess.run(command, check=False, stdout=output, stderr=subprocess.PIPE, text=True)
    except FileNotFoundError:
        fail(f"download {asset['name']} requires executable 'gh'")
    if result.returncode != 0:
        target.unlink(missing_ok=True)
        detail = result.stderr.strip() or f"exit status {result.returncode}"
        fail(f"download {asset['name']} failed: {detail}")
    if not target.is_file() or target.is_symlink():
        fail(f"downloaded runtime asset is not a regular file: {asset['name']}")
    if target.stat().st_size != asset["size"] or sha256_file(target) != asset["sha256"]:
        fail(f"downloaded runtime asset checksum or size differs: {asset['name']}")
    return target


def verify_signature(lock: dict[str, Any], subject: Path, bundle: Path) -> None:
    run(
        [
            "cosign", "verify-blob", "--bundle", str(bundle), "--certificate-identity", lock["certificate_identity"],
            "--certificate-oidc-issuer", lock["certificate_oidc_issuer"], str(subject),
        ],
        f"Sigstore bundle verification for {subject.name}",
    )


def verify_attestation(lock: dict[str, Any], subject: Path) -> None:
    run(
        [
            "gh", "attestation", "verify", str(subject), "--repo", lock["repository"],
            "--signer-workflow", lock["signer_workflow"], "--source-ref", f"refs/tags/{lock['tag']}",
            "--source-digest", lock["source_commit"], "--deny-self-hosted-runners",
        ],
        f"GitHub provenance verification for {subject.name}",
    )


def validate_manifest(lock: dict[str, Any], host: str, manifest_path: Path) -> dict[str, Any]:
    manifest = read_json(manifest_path)
    expected_keys = {
        "schema", "package", "version", "target", "source_commit", "source_date_epoch",
        "archive", "archive_sha256", "archive_size", "files",
    }
    value = require_exact_keys(manifest, expected_keys, "released runtime manifest")
    entry = lock["hosts"][host]
    expected = {
        "schema": 1,
        "package": "aros-tools",
        "version": lock["version"],
        "target": entry["target"],
        "source_commit": lock["source_commit"],
        "source_date_epoch": lock["source_date_epoch"],
        "archive": entry["archive"]["name"],
        "archive_sha256": entry["archive"]["sha256"],
        "archive_size": entry["archive"]["size"],
    }
    for field, wanted in expected.items():
        if value.get(field) != wanted:
            fail(f"released runtime manifest {field} differs from runtime lock")
    files = value["files"]
    if not isinstance(files, list) or len(files) != len(EXPECTED_FILES):
        fail("released runtime manifest must declare the exact runtime file inventory")
    observed: dict[str, dict[str, Any]] = {}
    for item in files:
        file = require_exact_keys(item, {"path", "mode", "sha256", "size"}, "released runtime file")
        path = file["path"]
        if path not in EXPECTED_FILES or path in observed:
            fail(f"released runtime manifest has unknown or duplicate file {path!r}")
        expected_mode, _ = EXPECTED_FILES[path]
        if file["mode"] != expected_mode:
            fail(f"released runtime manifest mode differs for {path}")
        require_hex(file["sha256"], 64, f"released runtime file SHA-256 for {path}")
        if not isinstance(file["size"], int) or isinstance(file["size"], bool) or file["size"] <= 0:
            fail(f"released runtime manifest size is invalid for {path}")
        observed[path] = file
    if set(observed) != set(EXPECTED_FILES):
        fail("released runtime manifest file set differs from expected runtime inventory")
    return value


def safe_extract(archive: Path, manifest: dict[str, Any], destination: Path) -> None:
    files = {item["path"]: item for item in manifest["files"]}
    archive_root = f"aros-tools-v{manifest['version']}-{manifest['target']}"
    temporary = destination.parent / f".{destination.name}.partial"
    if destination.exists() or temporary.exists():
        fail(f"runtime destination must not exist: {destination}")
    temporary.mkdir(parents=True)
    try:
        with tarfile.open(archive, "r:gz") as package:
            members = package.getmembers()
            observed: set[str] = set()
            for member in members:
                name = member.name
                pure = PurePosixPath(name)
                if pure.is_absolute() or ".." in pure.parts or not pure.parts or pure.parts[0] != archive_root:
                    fail(f"released runtime archive has an unsafe root or member {name!r}")
                payload = PurePosixPath(*pure.parts[1:]).as_posix()
                if payload in {".", ""}:
                    if not member.isdir() or name.rstrip("/") != archive_root:
                        fail("released runtime archive root must be its one canonical directory")
                    continue
                if payload == "bin":
                    if not member.isdir() or name.rstrip("/") != f"{archive_root}/bin":
                        fail("released runtime archive bin member must be a directory")
                    continue
                if payload not in files or not member.isfile() or payload in observed:
                    fail(f"released runtime archive has undeclared, duplicate or non-file member {name!r}")
                observed.add(payload)
                details = files[payload]
                target = temporary.joinpath(*PurePosixPath(payload).parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                source = package.extractfile(member)
                if source is None:
                    fail(f"cannot read released runtime archive member {payload!r}")
                with target.open("xb") as output:
                    shutil.copyfileobj(source, output)
                expected_mode = int(details["mode"], 8)
                os.chmod(target, expected_mode)
                if target.stat().st_size != details["size"] or sha256_file(target) != details["sha256"]:
                    fail(f"extracted runtime file checksum or size differs: {payload}")
                if stat.S_IMODE(target.stat().st_mode) != expected_mode:
                    fail(f"extracted runtime file mode differs: {payload}")
            if observed != set(files):
                fail("released runtime archive does not contain the complete manifest inventory")
        os.replace(temporary, destination)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def receipt(
    lock_path: Path, lock: dict[str, Any], host: str, manifest: dict[str, Any], manifest_sha256: str
) -> dict[str, Any]:
    return {
        "schema": "aros-tools-runtime-receipt-v1",
        "runtime_lock_sha256": sha256_file(lock_path),
        "host": host,
        "repository": lock["repository"],
        "release_id": lock["release_id"],
        "tag": lock["tag"],
        "tag_object": lock["tag_object"],
        "source_commit": lock["source_commit"],
        "source_tree": lock["source_tree"],
        "source_date_epoch": lock["source_date_epoch"],
        "archive": manifest["archive"],
        "archive_sha256": manifest["archive_sha256"],
        "manifest_sha256": manifest_sha256,
    }


def materialize(lock_path: Path, host: str, destination: Path) -> None:
    lock = validate_lock(read_json(lock_path))
    if host not in HOST_TARGETS:
        fail(f"unsupported runtime host {host!r}")
    release_assets = require_release_identity(lock)
    require_git_identity(lock)
    with tempfile.TemporaryDirectory(prefix="aros-tools-runtime-") as temporary_name:
        temporary = Path(temporary_name)
        entry = lock["hosts"][host]
        downloaded: dict[str, Path] = {}
        for field in ("archive", "manifest", "archive_bundle", "manifest_bundle"):
            asset = entry[field]
            downloaded[field] = download_asset(lock, asset, release_assets[asset["name"]]["id"], temporary)
        verify_signature(lock, downloaded["archive"], downloaded["archive_bundle"])
        verify_signature(lock, downloaded["manifest"], downloaded["manifest_bundle"])
        verify_attestation(lock, downloaded["archive"])
        verify_attestation(lock, downloaded["manifest"])
        manifest = validate_manifest(lock, host, downloaded["manifest"])
        safe_extract(downloaded["archive"], manifest, destination)
        shutil.copyfile(downloaded["manifest"], destination / ".aros-tools-runtime-manifest.json")
        data = receipt(lock_path, lock, host, manifest, sha256_file(downloaded["manifest"]))
        (destination / ".aros-tools-runtime-receipt-v1.json").write_bytes(canonical_json(data) + b"\n")
    verify_extracted(lock_path, host, destination)
    print(destination)


def verify_extracted(lock_path: Path, host: str, directory: Path) -> None:
    lock = validate_lock(read_json(lock_path))
    if host not in HOST_TARGETS or not directory.is_dir() or directory.is_symlink():
        fail("runtime verification requires a real directory for a supported host")
    manifest_path = directory / ".aros-tools-runtime-manifest.json"
    receipt_path = directory / ".aros-tools-runtime-receipt-v1.json"
    manifest = validate_manifest(lock, host, manifest_path)
    expected_receipt = receipt(lock_path, lock, host, manifest, sha256_file(manifest_path))
    if read_json(receipt_path) != expected_receipt:
        fail("runtime receipt differs from locked release identity")
    expected_paths = set(EXPECTED_FILES) | {".aros-tools-runtime-manifest.json", ".aros-tools-runtime-receipt-v1.json"}
    observed_paths: set[str] = set()
    observed_directories: set[str] = set()
    for path in directory.rglob("*"):
        relative = path.relative_to(directory).as_posix()
        if path.is_dir():
            observed_directories.add(relative)
            continue
        if path.is_symlink() or not path.is_file():
            fail(f"runtime contains a non-regular file: {relative}")
        observed_paths.add(relative)
    if observed_paths != expected_paths:
        fail("runtime extracted file set differs from the expected closure")
    if observed_directories != {"bin"}:
        fail("runtime extracted directory set differs from the expected closure")
    for item in manifest["files"]:
        path = directory / item["path"]
        if path.stat().st_size != item["size"] or sha256_file(path) != item["sha256"]:
            fail(f"runtime file differs from signed manifest: {item['path']}")
        if stat.S_IMODE(path.stat().st_mode) != int(item["mode"], 8):
            fail(f"runtime file mode differs from signed manifest: {item['path']}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate", help="validate the immutable runtime lock")
    validate.add_argument("--lock", type=Path, required=True)
    fetch = commands.add_parser("materialize", help="download, verify and extract one host runtime")
    fetch.add_argument("--lock", type=Path, required=True)
    fetch.add_argument("--host", choices=sorted(HOST_TARGETS), required=True)
    fetch.add_argument("--destination", type=Path, required=True)
    verify = commands.add_parser("verify", help="verify a previously materialised runtime without network access")
    verify.add_argument("--lock", type=Path, required=True)
    verify.add_argument("--host", choices=sorted(HOST_TARGETS), required=True)
    verify.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "validate":
            validate_lock(read_json(args.lock))
            print(sha256_file(args.lock))
        elif args.command == "materialize":
            materialize(args.lock.resolve(), args.host, args.destination.resolve())
        else:
            verify_extracted(args.lock.resolve(), args.host, args.directory.resolve())
            print(args.directory.resolve())
    except RuntimeError as exc:
        print(f"aros-tools runtime bootstrap: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
