#!/usr/bin/env python3
"""Match the SDK run's inputs and native release plan to its authenticated compiler manifest."""

import argparse
import importlib.util
import os
from pathlib import Path
import subprocess
import sys


spec = importlib.util.spec_from_file_location(
    "compiler_manifest_reader", Path(__file__).with_name("read-compiler-run-manifest-v2.py"))
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)
origin = reader.origin


def lane_coordinates(rows):
    return sorted((row["group_id"], row["host"], row["target_profile"]) for row in rows)


def admit(args):
    summary = reader.read_verified_summary(args.manifest, args.summary_sha256)
    bindings = summary["bindings"]
    origin.require(bindings["producer_commit"] == os.environ.get("GITHUB_SHA")
                   and bindings["release_id"] == args.release_id and bindings["tools_commit"] == args.tools_commit,
                   "SDK producer commit, release ID or tools commit differs from the compiler manifest")

    # Match the same Linux runtime used for compiler assembly before executing it.
    runtime, _ = origin.normalized_file(args.aros, origin.MAX_PAYLOAD)
    origin.require(runtime["sha256"] == bindings["aros_sha256"],
                   "SDK runtime differs from the compiler manifest")
    inputs = args.inputs_dir / "toolchain-release-inputs-v2.json"
    inputs_hash, _ = origin.normalized_file(inputs, origin.MAX_METADATA)
    origin.require(inputs_hash["sha256"] == bindings["inputs_sha256"],
                   "SDK release inputs differ from the compiler manifest")
    plan_path = args.inputs_dir / "plan.json"
    plan_hash, plan_bytes = origin.normalized_file(plan_path, origin.MAX_METADATA)
    origin.require(plan_hash["sha256"] == bindings["plan_sha256"],
                   "SDK matrix plan differs from the compiler manifest")
    result = subprocess.run(
        [str(args.aros), "toolchain", "producer", "release-plan", "--directory", str(args.inputs_dir),
         "--inputs-sha256", inputs_hash["sha256"], "--format", "json"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, check=True, timeout=300)
    origin.require(result.stdout == plan_bytes, "regenerated SDK release plan differs from the selected plan")

    plan = origin.parse_json(plan_bytes)
    origin.require(plan["schema"] == "aros-toolchain-producer-stage-v2" and plan["operation"] == "release-plan"
                   and plan["producer_commit"] == bindings["producer_commit"]
                   and plan["tools_commit"] == bindings["tools_commit"] and plan["inputs_sha256"] == inputs_hash["sha256"],
                   "regenerated release plan has different input bindings")
    lanes = lane_coordinates(plan["lanes"])
    origin.require(lanes and len(set(lanes)) == len(lanes) == plan["lane_count"]
                   and lanes == lane_coordinates(summary["comparisons"].values()),
                   "regenerated compiler lanes differ from the manifest comparison set")


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for flag in ("--manifest", "--aros", "--inputs-dir"):
        parser.add_argument(flag, type=Path, required=True)
    for flag in ("--summary-sha256", "--release-id", "--tools-commit"):
        parser.add_argument(flag, required=True)
    try:
        admit(parser.parse_args())
        return 0
    except origin.OriginError as error:
        print(f"SDK manifest admission failed: {error}", file=sys.stderr)
    except (ValueError, TypeError, KeyError, OSError, subprocess.SubprocessError):
        print("SDK manifest admission failed while reading inputs or regenerating the plan", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
