#!/usr/bin/env python3
"""Predict SDK input equality from committed trees and the admitted native release plan."""

import argparse
import hashlib
import importlib.util
import subprocess
import sys
import tomllib
from pathlib import Path

spec = importlib.util.spec_from_file_location("origin", Path(__file__).with_name("artifact-origin.py"))
origin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(origin)

# Exact bookkeeping files outside the SDK build. Unclassified files, file modes,
# submodule gitlinks and previously unseen generators contribute to the guard.
DOCUMENTATION = {
    "README.md",
    "CHANGELOG.md",
    "toolchains/README.md",
    "toolchains/compiler-sdk-ci-v2.md",
    "docs/README.md",
    "docs/plans/split-compiler-sdk-qualification.md",
}
PINNED_WORKFLOWS = {
    ".github/workflows/" + name + ".yml"
    for name in (
        "ci",
        "toolchain-release",
        "toolchain-compilers-v2",
        "toolchain-v2-inputs",
        "toolchain-compatibility-replay",
    )
}


def checksum(value):
    return hashlib.sha256(origin.canonical(value)).hexdigest()


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args], timeout=120)


def entries(repo):
    records = {}
    for row in git(repo, "ls-tree", "-rz", "--full-tree", "HEAD").split(b"\0"):
        if row:
            mode_type_oid, path = row.split(b"\t", 1)
            records[path.decode()] = mode_type_oid.decode()
    return records


def read_json(path):
    return origin.parse_json(origin.normalized_file(path.resolve(), origin.MAX_METADATA)[1])


def committed(repo, path):
    return git(repo, "show", "HEAD:" + path)


def read_selected(inputs, ref):
    origin.require(origin.portable_path(ref["file"]), "invalid prepared input path")
    measured, raw = origin.normalized_file(inputs / ref["file"], origin.MAX_METADATA)
    origin.require(measured["sha256"] == ref["sha256"], "SDK identity differs from prepared plan")
    return origin.parse_json(raw)


def source_components(source, plan):
    source_files = entries(source)
    config = tomllib.loads(committed(source, "aros-targets.toml").decode())
    targets = {row["name"]: row for row in config["targets"]}
    declarations = {}
    covered = set()
    for sdk in plan["sdks"]:
        target = targets[sdk["source_preset"]]
        contract_path = target.get("sdk_consumer_contract") or target["native_consumer_contract"]
        contract = origin.parse_json(committed(source, contract_path))
        paths = {item["path"] for item in contract["inputs"]} | {contract_path}
        covered.update(paths)
        # aros-targets.toml is shared. Include its non-target settings and the
        # selected target below. Hash the complete committed contents of every
        # other declared file, including its mode.
        declarations[sdk["id"]] = {
            "target": target,
            "files": {path: source_files[path] for path in sorted(paths - {"aros-targets.toml"})},
        }
    projected = covered | DOCUMENTATION | {"aros-targets.toml"}
    selected_targets = {sdk["source_preset"] for sdk in plan["sdks"]}
    shared_source = checksum(
        {
            "other_targets": {k: v for k, v in targets.items() if k not in selected_targets},
            "common_config": {k: v for k, v in config.items() if k != "targets"},
            "unclassified": {p: v for p, v in source_files.items() if p not in projected},
        }
    )
    return shared_source, declarations


def producer_digest(producer, src_sha):
    producer_files = entries(producer)
    # A pin bump changes these specific declarations as well as the source
    # checkout. Substitute the selected pin here because the source contents
    # themselves have already been measured. Other bytes remain significant.
    structured_pins = {
        "toolchains/compiler-sdk-ci-selection-v2.json": "source_commit",
        "toolchains/compatibility-ports-sdk-v3.json": "upstream_commit",
        "toolchains/profiles-sdk-gnu-v2.json": "upstream_commit",
        "toolchains/profiles-sdk-llvm-v2.json": "upstream_commit",
    }
    for path in producer_files.keys() & (PINNED_WORKFLOWS | structured_pins.keys()):
        raw = committed(producer, path)
        if path in structured_pins:
            data = origin.parse_json(raw)
            key = structured_pins[path]
            if data.get(key) == src_sha:
                data[key] = "<selected-source>"
            normalized = origin.canonical(data)
        else:
            normalized = raw.replace(src_sha.encode(), b"<selected-source>")
        producer_files[path] = (producer_files[path].split()[0], hashlib.sha256(normalized).hexdigest())
    return checksum({p: v for p, v in producer_files.items() if p not in DOCUMENTATION})


def compiler_archives(manifest):
    lanes = {}
    for entry in manifest["comparisons"].values():
        members = origin.parse_json(entry["receipt_json"].encode())["members"]
        # The archive is the compiler payload. The adjacent manifest, SBOM and
        # transport receipts include provenance specific to its producer run.
        (archive,) = [m for m in members if m["name"].endswith(".tar.xz")]
        lanes[(entry["group_id"], entry["target_profile"], entry["host"])] = archive["sha256"]
    return lanes


def compute(inputs, manifest_path, source, producer):
    manifest = read_json(manifest_path)
    inputs = inputs.resolve()
    plan = read_json(inputs / "plan.json")
    release = read_json(inputs / "toolchain-release-inputs-v2.json")
    src_sha = git(source, "rev-parse", "HEAD").decode().strip()
    producer_sha = git(producer, "rev-parse", "HEAD").decode().strip()
    origin.require(
        release["producer_commit"] == producer_sha == manifest["context"]["producer_commit"],
        "producer checkout differs from the admitted compiler run",
    )
    shared_source, declarations = source_components(source, plan)
    shared_producer = producer_digest(producer, src_sha)
    lanes = compiler_archives(manifest)
    result = {}
    for sdk in plan["sdks"]:
        sdk_id = sdk["id"]
        identity = read_selected(inputs, sdk["identity"])
        origin.require(
            identity["source"]["commit"] == src_sha, "SDK source checkout differs from prepared identity"
        )
        compiler = [
            (r["group_id"], r["profile"], r["host"])
            for r in plan["sdk_generation_lanes"]
            if r["sdk_id"] == sdk_id
        ]
        origin.require(compiler, f"{sdk_id} has no compiler generation lanes")
        components = {
            "shared_source": shared_source,
            "producer": shared_producer,
            "contract": checksum(declarations[sdk_id]),
            "tools": release["tools_commit"],
            "identity": checksum({k: v for k, v in identity.items() if k != "source"}),
            "compiler": checksum([(key, lanes[key]) for key in sorted(compiler)]),
        }
        result[sdk_id] = {
            "input_sha256": checksum({"format": 1, "components": components}),
            "components": components,
        }
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("--inputs-dir", "--compiler-manifest", "--source-dir", "--producer-dir"):
        parser.add_argument(flag, type=Path, required=True)
    args = parser.parse_args()
    try:
        sys.stdout.buffer.write(
            origin.canonical(
                compute(args.inputs_dir, args.compiler_manifest, args.source_dir, args.producer_dir)
            )
        )
    except (origin.OriginError, OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as exc:
        sys.exit(f"SDK input fingerprint failed: {exc}")
