#!/usr/bin/env python3
"""Join one authenticated compiler summary to an SDK-lane owner readback.

The compiler manifest reader is the authority for the summary schema, receipt
bytes and owner identity fields.  This adapter only selects the requested
lane, joins both authenticated owner transports to those identities, checks
their exact package members, and copies the original receipt.  It never runs
the producer comparison command.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
from pathlib import Path
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "compiler_manifest_consumer_reader", HERE / "read-compiler-run-manifest-v2.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("compiler manifest reader is unavailable")
READER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(READER)
ORIGIN = READER.origin
OriginError = ORIGIN.OriginError
TRANSPORT_SPEC = importlib.util.spec_from_file_location(
    "compiler_manifest_consumer_native_transport", HERE / "native-lane-transport.py"
)
if TRANSPORT_SPEC is None or TRANSPORT_SPEC.loader is None:
    raise RuntimeError("native transport helper is unavailable")
TRANSPORT = importlib.util.module_from_spec(TRANSPORT_SPEC)
TRANSPORT_SPEC.loader.exec_module(TRANSPORT)


def metadata(path):
    _, raw = ORIGIN.normalized_file(path, ORIGIN.MAX_METADATA)
    return ORIGIN.parse_json(raw)


def verify_owner(root, selection, expected, context, lane, copy, members):
    """Join the authenticated owner and its materialized package to the signed receipt."""
    transport = root / "transport"
    selected, _ = ORIGIN.normalized_file(selection, ORIGIN.MAX_METADATA)
    ORIGIN.require(selected["sha256"] == expected["selection_sha256"],
                   f"compiler {copy} selection differs from the manifest")
    verified = TRANSPORT.verify_output(transport, root / "payload")
    ORIGIN.require(verified == metadata(root / "transport-result.json"),
                   f"compiler {copy} transport result changed after readback")
    record = metadata(transport / "origin.json")
    ORIGIN.require(record["context"] == context and record["selection"] == dict(lane, role="build", copy=copy),
                   f"compiler {copy} source context or lane differs from the manifest")
    ORIGIN.require(record["job"]["id"] == expected["original_job_id"],
                   f"compiler {copy} owner job differs from the manifest")
    signature, _ = ORIGIN.normalized_file(transport / "origin.sigstore.json", ORIGIN.MAX_METADATA)
    ORIGIN.require(verified["selection_sha256"] == selected["sha256"]
                   and verified["origin_sha256"] == expected["origin_sha256"]
                   and verified["raw_zip_sha256"] == expected["payload_zip_sha256"]
                   and signature["sha256"] == expected["origin_sigstore_sha256"],
                   f"compiler {copy} transport identity differs from the manifest")
    measured = [
        {"name": name.removeprefix("package/"), "sha256": item["sha256"], "size": item["size"]}
        for name, item in sorted(verified["output_files"].items()) if name.startswith("package/")
    ]
    ORIGIN.require(measured == members, f"compiler {copy} package member differs from the signed receipt")


def consume(args):
    summary = READER.read_verified_summary(args.manifest, args.manifest_sha256)
    context = summary["context"]
    ORIGIN.require(context["workflow"] == args.source_workflow and context["source_ref"] == args.source_ref,
                   "compiler manifest context differs from the selected source workflow/ref")
    matches = [entry for entry in summary["comparisons"].values()
               if (entry["group_id"], entry["host"], entry["target_profile"])
               == (args.group, args.host, args.profile)]
    ORIGIN.require(len(matches) == 1, "compiler manifest must select exactly one requested lane")
    comparison = matches[0]
    raw = comparison["receipt_json"].encode()
    ORIGIN.require(hashlib.sha256(raw).hexdigest() == comparison["receipt_sha256"],
                   "compiler receipt digest differs")
    members = ORIGIN.parse_json(raw)["members"]
    lane = {"group": args.group, "host": args.host, "profile": args.profile}
    for copy, root, selection in (("a", args.owner_a_root, args.owner_a_selection),
                                  ("b", args.owner_b_root, args.owner_b_selection)):
        verify_owner(root, selection, comparison["owners"][copy], context, lane, copy, members)

    output = args.receipt_output
    ORIGIN.require(output.parent == output.parent.resolve(), "receipt output parent must be canonical")
    with output.open("xb") as stream:
        stream.write(raw)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    result.add_argument("--manifest", required=True, type=Path)
    result.add_argument("--manifest-sha256", required=True)
    result.add_argument("--group", required=True)
    result.add_argument("--host", required=True)
    result.add_argument("--profile", required=True)
    result.add_argument("--source-workflow", required=True)
    result.add_argument("--source-ref", required=True)
    result.add_argument("--owner-a-selection", required=True, type=Path)
    result.add_argument("--owner-b-selection", required=True, type=Path)
    result.add_argument("--owner-a-root", required=True, type=Path)
    result.add_argument("--owner-b-root", required=True, type=Path)
    result.add_argument("--receipt-output", required=True, type=Path)
    return result


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    flags = [value.split("=", 1)[0] for value in arguments if value.startswith("--")]
    if len(flags) != len(set(flags)):
        print("compiler manifest consumption failed: repeated command-line option",
              file=sys.stderr)
        return 2
    try:
        args = parser().parse_args(arguments)
        consume(args)
        return 0
    except (OriginError, TRANSPORT.origin.OriginError) as error:
        print(f"compiler manifest consumption failed: {error}", file=sys.stderr)
    except (OSError, ValueError, TypeError, KeyError, UnicodeError):
        print("compiler manifest consumption failed at a closed byte boundary",
              file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
