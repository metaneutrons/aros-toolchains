#!/usr/bin/env python3
"""Bind the assembled candidate's compiler evidence to the authenticated manifest."""

import argparse
import importlib.util
from pathlib import Path
import sys

spec = importlib.util.spec_from_file_location(
    "compiler_manifest_reader", Path(__file__).with_name("read-compiler-run-manifest-v2.py"))
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)
origin = reader.origin


def verify(args):
    summary = reader.read_verified_summary(args.manifest, args.summary_sha256)
    origin.require(summary["manifest_sha256"] == args.manifest_sha256, "selected compiler manifest digest differs")
    _, raw = origin.normalized_file(args.compiler_evidence, origin.MAX_METADATA)
    evidence = origin.parse_json(raw)
    origin.require(evidence["schema"] == "aros-toolchain-compiler-evidence-fragment-v1",
                   "unexpected compiler evidence schema")

    # The readback fragment contains paths on this runner. All portable bindings
    # (including the original compiler context, runtime and plan) must match.
    bindings = dict(evidence["bindings"])
    expected = dict(summary["bindings"])
    bindings.pop("fragment_sha256")
    expected.pop("fragment_sha256")
    origin.require(bindings == expected, "assembled compiler bindings differ from the signed manifest")
    comparisons = summary["comparisons"]
    origin.require(evidence["assets"].keys() == comparisons.keys(), "assembled compiler asset set differs")
    reports = args.compiler_evidence.parent / "reports"
    receipt_hashes = {}
    for asset, lane in evidence["assets"].items():
        signed = comparisons[asset]
        origin.require(all(lane[key] == signed[key] for key in ("group_id", "host", "target_profile")),
                       f"{asset}: compiler lane differs")
        origin.require(reader.owner_identities(lane["builds"]) == signed["owners"],
                       f"{asset}: compiler owner identity differs")
        selected = lane["comparison"]["selectedFile"]
        receipt = Path(selected["path"])
        origin.require(receipt.parent == reports, f"{asset}: receipt is outside the candidate reports")
        measured, raw = origin.normalized_file(receipt, origin.MAX_METADATA)
        origin.require(measured["sha256"] == selected["sha256"] == signed["receipt_sha256"]
                       and raw == signed["receipt_json"].encode(), f"{asset}: compiler receipt differs")
        receipt_hashes[asset] = measured["sha256"]

    _, raw = origin.normalized_file(args.candidate_summary, origin.MAX_METADATA)
    candidate = origin.parse_json(raw)
    origin.require(candidate["bindings"]["compiler_source_context_sha256"] == bindings["source_context_sha256"],
                   "combined candidate selects a different compiler context")
    return {"manifest_sha256": summary["manifest_sha256"], "compiler_context": summary["context"],
            "sdk_context_sha256": candidate["bindings"]["source_context_sha256"],
            "index_sha256": candidate["outputs"]["index"]["sha256"],
            "subjects_sha256": candidate["outputs"]["subject_manifest"]["sha256"], "receipts": receipt_hashes}


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--summary-sha256", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--compiler-evidence", type=Path, required=True)
    parser.add_argument("--candidate-summary", type=Path, required=True)
    try:
        sys.stdout.buffer.write(origin.canonical(verify(parser.parse_args())))
        return 0
    except (origin.OriginError, OSError, ValueError, TypeError, KeyError) as error:
        print(f"compiler receipt verification failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
