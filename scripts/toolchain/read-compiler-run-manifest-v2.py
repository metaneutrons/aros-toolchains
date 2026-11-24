#!/usr/bin/env python3
"""Read a prior compiler run manifest from the SDK workflow.

Select the successful assembly job and its payload/proof independently. The
signed origin supplies the manifest.json digest on first read. Pass that digest
again with --manifest-sha256 when a later step already knows the selection.
The JSON result contains the authenticated bindings, A/B owner identities and receipts.
The receipt_json string preserves the exact UTF-8 bytes covered by receipt_sha256.
SDK preparation must still match its plan, inputs, runtime and freshness policy.
"""

import argparse
from contextlib import redirect_stdout
import hashlib
import importlib.util
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import zipfile


spec = importlib.util.spec_from_file_location(
    "compiler_manifest_selector", Path(__file__).with_name("select-owner-artifacts-v2.py"))
selector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(selector)
origin = selector.artifact_origin
require = origin.require
OriginError = origin.OriginError

ASSEMBLY_JOB = "Assemble and compare compiler candidates"
MANIFEST_SCHEMA = "aros-toolchain-compiler-run-manifest-v2"
DOCUMENTS = {"context.json", "assembly-summary.json", "compiler-owner-fragment.json",
             "compiler-index-lanes.json", "compiler-evidence-fragment.json"}


def read_member(archive, name):
    member = archive.getinfo(name)
    require(member.file_size <= origin.MAX_METADATA, "manifest member exceeds its byte limit")
    return archive.read(member)


def comparison(raw, asset, receipt_sha256):
    receipt = origin.parse_json(raw)
    origin.exact_keys(receipt, {"schema", "operation", "byte_identical", "members", "package_set_sha256"})
    require(type(receipt["schema"]) is int and receipt["schema"] == 1
            and receipt["operation"] == "compare" and receipt["byte_identical"] is True,
            "A/B receipt does not confirm byte identity")
    members = receipt["members"]
    names = [asset + suffix for suffix in ("", ".manifest.json", ".sha256", ".spdx.json")]
    require(isinstance(members, list) and len(members) == len(names),
            "A/B receipt has an unexpected package inventory")
    for member, name in zip(members, names):
        origin.exact_keys(member, {"name", "size", "sha256"})
        require(member["name"] == name and type(member["size"]) is int and member["size"] >= 0
                and isinstance(member["sha256"], str) and re.fullmatch(r"[a-f0-9]{64}", member["sha256"]),
                "A/B receipt member differs from the selected asset")
    require(hashlib.sha256(origin.canonical(members)).hexdigest() == receipt["package_set_sha256"],
            "A/B receipt package set digest differs")
    return {"receipt_sha256": receipt_sha256, "receipt_json": raw.decode("utf-8")}


def read_inventory(archive, manifest):
    assets = manifest["comparison_assets"]
    require(isinstance(assets, list) and 0 < len(assets) <= 64
            and all(isinstance(a, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,254}", a)
                    for a in assets) and assets == sorted(set(assets)),
            "compiler manifest comparison assets are invalid")
    receipt_paths = {f"comparisons/{asset}.json": asset for asset in assets}
    files = origin.exact_keys(manifest["files"], DOCUMENTS | receipt_paths.keys())
    require(sorted(archive.namelist()) == sorted([*files, "manifest.json"]),
            "compiler manifest ZIP inventory differs")
    comparisons = {}
    evidence = None
    for name, measurement in files.items():
        origin.exact_keys(measurement, {"sha256", "size"})
        raw = read_member(archive, name)
        is_receipt = name in receipt_paths
        require(type(measurement["size"]) is int and len(raw) == measurement["size"]
                and hashlib.sha256(raw).hexdigest() == measurement["sha256"],
                "A/B receipt digest or size differs" if is_receipt else "manifest member digest or size differs")
        if is_receipt:
            asset = receipt_paths[name]
            comparisons[asset] = comparison(raw, asset, measurement["sha256"])
        elif name == "compiler-evidence-fragment.json":
            evidence = origin.parse_json(raw)
    return files, comparisons, evidence


def owner_identities(builds):
    """Keep portable owner identities from the signed evidence, excluding runner paths."""
    require(isinstance(builds, list) and len(builds) == 2, "compiler lane must name two owners")
    identities = {}
    for build in builds:
        copy = build["copy"]
        require(copy in ("a", "b") and copy not in identities, "compiler lane repeats an owner copy")
        job = build["original_job_id"]
        require(type(job) is int and origin.positive(job) == job, "compiler owner job ID is invalid")
        identity = {"original_job_id": job}
        for key in ("selection_sha256", "payload_zip_sha256", "origin_sha256", "origin_sigstore_sha256"):
            value = build[key]
            require(isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value),
                    "compiler owner digest is invalid")
            identity[key] = value
        identities[copy] = identity
    require(identities["a"]["original_job_id"] != identities["b"]["original_job_id"],
            "compiler A/B copies must have distinct owner jobs")
    return identities


def read_manifest(payload: Path, expected_sha256: str, context: dict) -> dict:
    """Decode a verified transport with an independently authenticated manifest digest."""
    with zipfile.ZipFile(payload) as archive:
        raw = read_member(archive, "manifest.json")
        require(hashlib.sha256(raw).hexdigest() == expected_sha256, "compiler manifest digest differs")
        manifest = origin.parse_json(raw)
        origin.exact_keys(manifest, {"schema", "context", "bindings", "comparison_assets", "files", "scope"})
        require(manifest["schema"] == MANIFEST_SCHEMA
                and manifest["scope"] == {"release_admission": False, "publication": False},
                "compiler manifest schema or scope differs")
        require(origin.validate_context(manifest["context"]) == context
                and context["workflow"] == origin.SPLIT_COMPILER_WORKFLOW,
                "compiler manifest context differs from the selected compiler run")

        files, comparisons, evidence = read_inventory(archive, manifest)
        bindings = manifest["bindings"]
        require(isinstance(bindings, dict) and bindings.get("producer_commit") == context["producer_commit"]
                and bindings.get("source_context_sha256") == files["context.json"]["sha256"]
                == hashlib.sha256(origin.canonical(context)).hexdigest()
                and bindings.get("fragment_sha256") == files["compiler-owner-fragment.json"]["sha256"],
                "compiler manifest bindings differ")
        require(isinstance(evidence, dict) and evidence.get("bindings") == bindings,
                "compiler evidence bindings differ from the manifest")
        lanes = origin.exact_keys(evidence["assets"], set(comparisons))
        for asset, result in comparisons.items():
            lane = lanes[asset]
            require(lane["comparison"]["selectedFile"]["sha256"] == result["receipt_sha256"],
                    "A/B receipt digest differs from the selected compiler lane")
            result["group_id"] = lane["group_id"]
            result["host"] = lane["host"]
            result["target_profile"] = lane["target_profile"]
            result["owners"] = owner_identities(lane["builds"])
    return {"manifest_sha256": expected_sha256, "context": context,
            "bindings": bindings, "comparisons": comparisons}


def read_from_compiler_run(args):
    caller = origin.context_from_environment(origin.SPLIT_SDK_WORKFLOW)
    source = dict(caller, workflow=origin.SPLIT_COMPILER_WORKFLOW,
                  run_id=args.compiler_run_id, run_attempt=args.compiler_run_attempt)
    origin.require_split_contexts(source, caller)
    origin.require_split_events(origin.observe_run_event(source, require_success=True),
                                origin.observe_run_event(caller))
    suffix = f'{source["run_id"]}-{source["run_attempt"]}'
    with tempfile.TemporaryDirectory(prefix="aros-compiler-manifest-") as directory:
        root = Path(directory).resolve()
        context_file = root / "context.json"
        context_bytes = origin.canonical(source)
        context_file.write_bytes(context_bytes)
        selection = selector.select_owner_artifacts(argparse.Namespace(
            source_context=context_file, source_context_sha256=hashlib.sha256(context_bytes).hexdigest(),
            job_name=ASSEMBLY_JOB, payload_name=f"compiler-manifest-v2-{suffix}",
            proof_name=f"compiler-manifest-v2-proof-{suffix}", role="comparison", group="compilers",
            host="linux-x86_64", profile="manifest", copy="none"))
        selection_file = root / "selection.json"
        selection_file.write_bytes(origin.canonical(selection))
        transport = root / "verified"
        with redirect_stdout(sys.stderr):
            origin.verify_source(argparse.Namespace(
                workflow=origin.SPLIT_SDK_WORKFLOW, job_name=args.job_name, source_selection=selection_file,
                origin=None, bundle=None, verified_output_dir=transport), caller)
        record = origin.parse_json((transport / "origin.json").read_bytes())
        signed_digest = record["files"]["manifest.json"]["sha256"]
        require(args.manifest_sha256 is None or args.manifest_sha256 == signed_digest,
                "selected compiler manifest digest differs from signed origin")
        return read_manifest(transport / "payload.zip", signed_digest, source)


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--compiler-run-id", required=True, type=origin.positive)
    parser.add_argument("--compiler-run-attempt", required=True, type=origin.positive)
    parser.add_argument("--job-name", required=True, help="Exact executing SDK reader job name")
    parser.add_argument("--manifest-sha256", help="Independently selected digest of manifest.json")
    try:
        flags = [value.split("=", 1)[0] for value in sys.argv[1:] if value.startswith("--")]
        require(len(flags) == len(set(flags)), "duplicate argument selector")
        args = parser.parse_args()
        require(args.manifest_sha256 is None or re.fullmatch(r"[a-f0-9]{64}", args.manifest_sha256),
                "invalid compiler manifest digest")
        result = read_from_compiler_run(args)
        sys.stdout.buffer.write(origin.canonical(result))
        return 0
    except OriginError as error:
        print(f"compiler manifest read failed: {error}", file=sys.stderr)
    except (OSError, ValueError, TypeError, KeyError, zipfile.BadZipFile, subprocess.TimeoutExpired):
        print("compiler manifest read failed at the provider or payload boundary", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
