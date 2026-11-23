#!/usr/bin/env python3
"""Stage the compiler run manifest of the split qualification.

The compiler qualification run ends with one payload that the SDK run later
reads across the run boundary (docs/plans/split-compiler-sdk-qualification.md,
D2 and D6). This script copies only bytes that the compiler candidate assembly
summary already binds by digest, plus the run context and the compiler owner
collector fragment, into a fresh payload directory and writes one canonical
manifest over them. It does not authenticate owners, record an origin, sign,
upload or admit anything; the owning job does that separately.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
SCHEMA = "aros-toolchain-compiler-run-manifest-v2"
SUMMARY_SCHEMA = "aros-toolchain-compiler-candidate-assembly-v2"
SUMMARY_ASSURANCE = "compiler-candidate-byte-assembly-partial-no-admission"
COMPILER_WORKFLOW = ".github/workflows/toolchain-compilers-v2.yml"
MAX_DOCUMENT = 16 * 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
ASSET = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,254}\Z")


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path.name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_ORIGIN = _load("compiler_manifest_origin", HERE / "artifact-origin.py")


class ManifestError(ValueError):
    """The compiler run manifest boundary rejected its inputs."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ManifestError(message)


def canonical(value: object) -> bytes:
    return _ORIGIN.canonical(value)


def read_exact(path: Path, expected_sha256: str, label: str) -> bytes:
    require(path.is_absolute() and path == path.resolve() and path.is_file()
            and not path.is_symlink(), f"{label} is not a canonical regular file")
    raw = path.read_bytes()
    require(len(raw) <= MAX_DOCUMENT, f"{label} exceeds its size bound")
    require(hashlib.sha256(raw).hexdigest() == expected_sha256,
            f"{label} bytes differ from their selected digest")
    return raw


def parse(raw: bytes, label: str) -> dict:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ManifestError(f"{label} is not UTF-8 JSON") from None
    require(isinstance(value, dict), f"{label} must be a JSON object")
    return value


def selector(value: object, label: str) -> tuple[Path, str]:
    require(isinstance(value, dict) and set(value) == {"path", "sha256", "size"},
            f"{label} selector is malformed")
    require(isinstance(value["path"], str) and isinstance(value["sha256"], str)
            and SHA256.fullmatch(value["sha256"]) is not None
            and type(value["size"]) is int and value["size"] >= 0,
            f"{label} selector is malformed")
    return Path(value["path"]), value["sha256"]


def stage(args: argparse.Namespace) -> dict:
    output = args.output_dir
    require(output.is_absolute() and not os.path.lexists(output)
            and output.parent == output.parent.resolve() and output.parent.is_dir(),
            "payload directory must be absent with a canonical parent")

    context_raw = read_exact(args.context, args.context_sha256, "run context")
    context = _ORIGIN.validate_context(parse(context_raw, "run context"))
    require(context_raw == canonical(context), "run context is not canonical JSON")
    require(context["workflow"] == COMPILER_WORKFLOW,
            "run context does not name the compiler qualification workflow")

    summary_raw = read_exact(args.summary, args.summary_sha256, "assembly summary")
    summary = parse(summary_raw, "assembly summary")
    require(set(summary) == {"schema", "assurance", "bindings", "staged_inventory",
                             "artifacts", "scope"},
            "assembly summary has unexpected or missing keys")
    require(summary["schema"] == SUMMARY_SCHEMA and summary["assurance"] == SUMMARY_ASSURANCE,
            "assembly summary schema or assurance differs")
    require(summary["scope"] == {"compiler_only": True, "sdk_included": False,
                                 "admission": False, "publication": False},
            "assembly summary scope differs")
    bindings = summary["bindings"]
    require(isinstance(bindings, dict)
            and bindings.get("source_context_sha256") == args.context_sha256
            and bindings.get("producer_commit") == context["producer_commit"]
            and bindings.get("fragment_sha256") == args.fragment_sha256,
            "assembly summary is not bound to this run context and owner fragment")

    artifacts = summary["artifacts"]
    require(isinstance(artifacts, dict)
            and set(artifacts) == {"compiler_index_lanes", "compiler_evidence_fragment",
                                   "comparisons", "native_verifications"},
            "assembly summary artifacts are malformed")
    files: dict[str, tuple[Path, str]] = {
        "context.json": (args.context, args.context_sha256),
        "assembly-summary.json": (args.summary, args.summary_sha256),
        "compiler-owner-fragment.json": (args.fragment, args.fragment_sha256),
        "compiler-index-lanes.json": selector(artifacts["compiler_index_lanes"], "index lanes"),
        "compiler-evidence-fragment.json": selector(artifacts["compiler_evidence_fragment"],
                                                    "evidence fragment"),
    }
    comparisons = artifacts["comparisons"]
    require(isinstance(comparisons, dict) and 0 < len(comparisons) <= 64,
            "assembly summary lists no comparison receipts")
    for asset in sorted(comparisons):
        require(isinstance(asset, str) and ASSET.fullmatch(asset) is not None,
                "comparison asset name is not portable")
        files[f"comparisons/{asset}.json"] = selector(comparisons[asset], f"{asset} comparison")

    contents: dict[str, bytes] = {}
    for name, (path, sha256) in files.items():
        contents[name] = read_exact(path, sha256, name)
    manifest = {
        "schema": SCHEMA,
        "context": context,
        "bindings": bindings,
        "comparison_assets": sorted(comparisons),
        "files": {name: {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}
                  for name, raw in sorted(contents.items())},
        "scope": {"release_admission": False, "publication": False},
    }
    os.mkdir(output, 0o700)
    os.mkdir(output / "comparisons", 0o700)
    for name, raw in contents.items():
        with (output / name).open("xb") as handle:
            handle.write(raw)
    manifest_raw = canonical(manifest)
    with (output / "manifest.json").open("xb") as handle:
        handle.write(manifest_raw)
    return {"manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
            "file_count": len(contents) + 1}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ("context", "summary", "fragment"):
        parser.add_argument(f"--{name}", type=Path, required=True)
        parser.add_argument(f"--{name}-sha256", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    arguments = sys.argv[1:] if argv is None else argv
    names = [value.split("=", 1)[0] for value in arguments if value.startswith("--")]
    if len(names) != len(set(names)):
        sys.stderr.write("compiler run manifest failed: repeated command-line option\n")
        return 2
    args = parser.parse_args(arguments)
    try:
        for name in ("context_sha256", "summary_sha256", "fragment_sha256"):
            require(SHA256.fullmatch(getattr(args, name)) is not None, f"{name} is not a digest")
        result = stage(args)
    except (ManifestError, _ORIGIN.OriginError, OSError) as error:
        sys.stderr.write(f"compiler run manifest failed: {error}\n")
        return 2
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
