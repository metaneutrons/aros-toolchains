#!/usr/bin/env python3
"""Predict reusability before SDK generation and score it against the verified SDK trees."""

import argparse
import importlib.util
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


baseline = load("sdk_baseline", "read-sdk-reuse-baseline.py")
abi = load("sdk_abi", "sdk-abi-surface.py")
runtime = load("sdk_runtime", "sdk-runtime-probe-v1.py")
origin = baseline.origin
PLAN = "aros-sdk-reuse-prediction-v1"


def read(path, expected=None):
    measured, raw = origin.normalized_file(path, origin.MAX_METADATA)
    origin.require(expected is None or measured["sha256"] == expected, f"{path.name} digest differs")
    return origin.parse_json(raw), measured["sha256"]


def digest(value):
    origin.require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value), "invalid SHA-256")
    return value


def predict(args):
    context = origin.context_from_environment(origin.SPLIT_SDK_WORKFLOW)
    compiler, _ = read(args.compiler_manifest, args.compiler_summary_sha256)
    origin.require_split_contexts(compiler["context"], context)
    inputs, _ = read(args.inputs)
    prior, prior_sha = read(args.baseline)
    targets = {}
    for sdk_id, current in inputs.items():
        fingerprint = digest(current["input_sha256"])
        previous = prior["targets"].get(sdk_id) if prior else None
        if previous is None:
            prediction = "no-baseline"
        elif previous["input_sha256"] == fingerprint:
            prediction = "reuse-candidate"
        else:
            prediction = "build"
        components = current["components"]
        changed = sorted(k for k in components if previous and components[k] != previous["components"].get(k))
        targets[sdk_id] = {
            "input_sha256": fingerprint,
            "components": components,
            "changed_inputs": changed,
            "prediction": prediction,
        }
    origin.require(targets, "empty SDK prediction")
    return {
        "schema": PLAN,
        "context": context,
        "compiler_manifest_sha256": digest(compiler["manifest_sha256"]),
        "baseline_sha256": prior_sha,
        "baseline_context": prior["context"] if prior else None,
        "targets": targets,
    }


def outcome(prediction, same_tree):
    if prediction == "no-baseline":
        return "first-observation"
    if prediction == "reuse-candidate":
        return "confirmed-reuse" if same_tree else "false-reuse"
    origin.require(prediction == "build", "invalid SDK prediction")
    return "conservative-build" if same_tree else "confirmed-build"


def capture(args):
    """Collect the representative Linux generation, before its working tree disappears."""
    selections = (args.lane / "sdk-selections.jsonl").read_bytes().splitlines()
    args.output.mkdir()
    for line in selections:
        sdk_id = origin.parse_json(line)["id"]
        origin.require(re.fullmatch(r"[a-z0-9][a-z0-9_-]*", sdk_id), "invalid SDK id")
        operation = args.lane / ("sdk-" + sdk_id)
        generation, generation_sha = read(operation / "generation.json")
        identity = generation["identity"]
        origin.require(identity["sdk_id"] == sdk_id, "SDK identity differs from lane")
        family, link_root, driver = {
            "aros-llvm-sdk-generation-record-v1": ("llvm", "llvm-sdk-links", "bin/clang"),
            "aros-sdk-generation-record-v1": ("gnu", "native-sdk-links", "riscv-aros-gcc"),
        }[generation["schema"]]
        receipt = digest(generation["sdk_link_receipt_sha256"])
        sdk_root = operation / "reports" / link_root / "relocated-sdk"
        data = {
            "identity": identity,
            "tree_sha256": digest(generation["sdk_inventory_sha256"]),
            "generation_record_sha256": generation_sha,
            "sdk_link_receipt_sha256": receipt,
            "surface": abi.capture(sdk_root, operation / "first" / driver, identity),
            "consumer": runtime.retain(operation, family, receipt),
        }
        with (args.output / (sdk_id + ".json")).open("xb") as handle:
            handle.write(origin.canonical(data))


def measured_surfaces(directory, evidence, rows, attempt):
    claims = [claim for claim in evidence["sdk_generations"] if claim["host"] == "linux-x86_64"]
    by_sdk = {claim["sdk_id"]: claim for claim in claims}
    origin.require(
        len(by_sdk) == len(claims) and by_sdk.keys() == rows.keys(),
        "representative Linux generation matrix differs",
    )
    surfaces = {}
    for path in directory.glob("*/*.json"):
        entry, _ = read(path)
        sdk_id = entry["identity"]["sdk_id"]
        origin.require(
            sdk_id in rows and path.stem == sdk_id and sdk_id not in surfaces,
            "unexpected or duplicate SDK ABI artifact",
        )
        row, claim = rows[sdk_id], by_sdk[sdk_id]
        artifact = f"sdk-surface-{claim['group_id']}-{claim['target_profile']}-{attempt}"
        origin.require(
            path.parent.name == artifact, "SDK ABI artifact differs from the native generation lane"
        )
        origin.require(
            entry["identity"] == row["identity"]
            and entry["tree_sha256"] == row["tree_sha256"]
            and entry["generation_record_sha256"] == claim["generation_record_sha256"]
            and entry["sdk_link_receipt_sha256"]
            == entry["consumer"]["receipt_sha256"]
            == claim["sdk_link_receipt_sha256"],
            "SDK ABI measurement differs from final native evidence",
        )
        surfaces[sdk_id] = entry
    origin.require(surfaces.keys() == rows.keys(), "missing SDK ABI measurement")
    return surfaces


def observe(args):
    plan, _ = read(args.plan, args.plan_sha256)
    context = origin.context_from_environment(origin.SPLIT_SDK_WORKFLOW)
    origin.require(plan["schema"] == PLAN and plan["context"] == context, "SDK prediction run differs")
    prior, _ = read(args.baseline, plan["baseline_sha256"])
    evidence, evidence_sha = read(args.evidence)
    origin.require(
        evidence["operation"] == "verify-release-evidence", "expected final native release evidence"
    )
    rows = {row["sdk_id"]: row for row in evidence["sdks"]}
    origin.require(
        len(rows) == len(evidence["sdks"]) == evidence["sdk_count"] and rows.keys() == plan["targets"].keys(),
        "final SDK products differ from prediction",
    )
    surfaces = measured_surfaces(args.surfaces, evidence, rows, context["run_attempt"])
    targets = {}
    for sdk_id, row in rows.items():
        prediction = plan["targets"][sdk_id]
        tree = digest(row["tree_sha256"])
        previous = prior["targets"].get(sdk_id) if prior else None
        origin.require(
            (previous is None) == (prediction["prediction"] == "no-baseline"),
            "SDK baseline differs from the pre-build decision",
        )
        surface = surfaces[sdk_id]["surface"]
        previous_tree = previous["tree_sha256"] if previous else None
        targets[sdk_id] = {
            **prediction,
            "source_commit": row["identity"]["source"]["commit"],
            "tree_sha256": tree,
            "archive_sha256": digest(row["archive_sha256"]),
            "previous_source_commit": previous["source_commit"] if previous else None,
            "previous_tree_sha256": previous_tree,
            "previous_archive_sha256": previous["archive_sha256"] if previous else None,
            "outcome": outcome(prediction["prediction"], tree == previous_tree),
            "surface": surface,
            "abi": abi.compare_surfaces(previous["surface"] if previous else None, surface),
            "consumer": surfaces[sdk_id]["consumer"],
            "runtime": {"status": "not-run", "reason": "SDK qualification has no bootable OS image"},
        }
    return {
        "schema": baseline.SCHEMA,
        "context": context,
        "mode": "observe-only",
        "targets": targets,
        "compiler_manifest_sha256": plan["compiler_manifest_sha256"],
        "baseline_context": plan["baseline_context"],
        "baseline_sha256": plan["baseline_sha256"],
        "final_evidence_sha256": evidence_sha,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)
    lane = commands.add_parser("capture")
    lane.add_argument("--lane", type=Path, required=True)
    lane.add_argument("--output", type=Path, required=True)
    plan = commands.add_parser("predict")
    plan.add_argument("--inputs", type=Path, required=True)
    plan.add_argument("--compiler-manifest", type=Path, required=True)
    plan.add_argument("--compiler-summary-sha256", required=True)
    observed = commands.add_parser("observe")
    observed.add_argument("--plan", type=Path, required=True)
    observed.add_argument("--plan-sha256", required=True)
    observed.add_argument("--evidence", type=Path, required=True)
    observed.add_argument("--surfaces", type=Path, required=True)
    for child in (plan, observed):
        child.add_argument("--baseline", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "capture":
        capture(args)
        return
    result = predict(args) if args.command == "predict" else observe(args)
    encoded = origin.canonical(result)
    origin.require(
        len(encoded) <= origin.MAX_METADATA, "SDK observation exceeds the signed baseline size limit"
    )
    sys.stdout.buffer.write(encoded)


if __name__ == "__main__":
    try:
        main()
    except (
        origin.OriginError,
        runtime.ProbeError,
        OSError,
        ValueError,
        TypeError,
        KeyError,
        subprocess.SubprocessError,
    ) as exc:
        sys.exit(f"SDK reuse observation failed: {exc}")
