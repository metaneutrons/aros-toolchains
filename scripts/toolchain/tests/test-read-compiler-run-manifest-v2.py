#!/usr/bin/env python3
"""Regression tests for the authenticated compiler-run manifest reader."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock
import zipfile


SCRIPT = Path(__file__).resolve().parents[1] / "read-compiler-run-manifest-v2.py"
PAYLOAD = Path(__file__).resolve().parent / "fixtures" / "compiler-run-manifest-v2-payload.zip"
SPEC = importlib.util.spec_from_file_location("read_compiler_run_manifest_v2", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
reader = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reader)

MANIFEST_SHA256 = "2c743dce32680b0451caf78ce1828294061a3143f75e2d04914771cff52d3eb6"
PAYLOAD_SHA256 = "861478668203a56b693933467d540b38a5fbe9b0be7d40960d5aa73a84f11ddb"
SOURCE_CONTEXT = {
    "producer_commit": "dcf601b337dbcacb246c6bc459042a31519fb258",
    "repository": "metaneutrons/aros-toolchains",
    "repository_id": 1389046806,
    "run_attempt": 1,
    "run_id": 45351030854,
    "source_ref": "refs/heads/main",
    "workflow": ".github/workflows/toolchain-compilers-v2.yml",
}
CALLER_CONTEXT = {
    **SOURCE_CONTEXT,
    "run_id": 45351030855,
    "workflow": ".github/workflows/toolchain-sdk-v2.yml",
}
CALLER_JOB_NAME = "Read compiler manifest"


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def read_zip_member(path: Path, name: str) -> bytes:
    with zipfile.ZipFile(path) as archive:
        return archive.read(name)


class CompilerRunManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.assertTrue(PAYLOAD.is_file(), f"missing checked-in fixture: {PAYLOAD}")
        self.manifest = json.loads(read_zip_member(PAYLOAD, "manifest.json"))
        self.assets = self.manifest["comparison_assets"]

    def test_original_fixture_is_closed_and_contains_twelve_receipts(self) -> None:
        self.assertEqual(sha256(PAYLOAD.read_bytes()), PAYLOAD_SHA256)
        self.assertEqual(self.manifest["context"], SOURCE_CONTEXT)
        self.assertEqual(len(self.assets), 12)
        with zipfile.ZipFile(PAYLOAD) as archive:
            self.assertEqual(len(archive.namelist()), 18)
            self.assertEqual(
                set(archive.namelist()),
                {"manifest.json", "context.json", "assembly-summary.json",
                 "compiler-owner-fragment.json", "compiler-index-lanes.json",
                 "compiler-evidence-fragment.json",
                 *(f"comparisons/{asset}.json" for asset in self.assets)},
            )

    def test_reads_manifest_bindings_and_all_twelve_receipts_and_lanes(self) -> None:
        summary = reader.read_manifest(PAYLOAD, MANIFEST_SHA256, SOURCE_CONTEXT)

        self.assertEqual(set(summary), {"manifest_sha256", "context", "bindings", "comparisons"})
        self.assertEqual(summary["manifest_sha256"], MANIFEST_SHA256)
        self.assertEqual(summary["context"], SOURCE_CONTEXT)
        self.assertEqual(summary["bindings"], self.manifest["bindings"])
        self.assertEqual(set(summary["comparisons"]), set(self.assets))
        self.assertEqual(len(summary["comparisons"]), 12)
        jobs = set()
        for asset in self.assets:
            receipt_raw = read_zip_member(PAYLOAD, f"comparisons/{asset}.json")
            entry = summary["comparisons"][asset]
            self.assertEqual(entry["receipt_sha256"], sha256(receipt_raw))
            self.assertEqual(json.loads(entry["receipt_json"]), json.loads(receipt_raw))
            self.assertEqual(sha256(entry["receipt_json"].encode()), entry["receipt_sha256"])
            self.assertIsInstance(entry["group_id"], str)
            self.assertIsInstance(entry["host"], str)
            self.assertIsInstance(entry["target_profile"], str)
            self.assertEqual(set(entry["owners"]), {"a", "b"})

            self.assertEqual(set(entry["owners"]), {"a", "b"})
            jobs.update(owner["original_job_id"] for owner in entry["owners"].values())
        self.assertEqual(len(jobs), 24)

    def test_wrong_manifest_digest_is_rejected_as_manifest_failure(self) -> None:
        with self.assertRaisesRegex(reader.OriginError, r"(?i)manifest"):
            reader.read_manifest(PAYLOAD, "0" * 64, SOURCE_CONTEXT)

    def test_replacing_one_receipt_with_another_genuine_receipt_is_rejected(self) -> None:
        replaced_asset, source_asset = self.assets[0], self.assets[2]
        with tempfile.TemporaryDirectory(prefix="compiler-manifest-receipt-") as directory:
            replacement = Path(directory) / "payload.zip"
            with zipfile.ZipFile(PAYLOAD) as source, zipfile.ZipFile(replacement, "w") as target:
                replacement_name = f"comparisons/{replaced_asset}.json"
                source_name = f"comparisons/{source_asset}.json"
                genuine_other_receipt = source.read(source_name)
                self.assertEqual(len(source.read(replacement_name)), len(genuine_other_receipt))
                self.assertNotEqual(source.read(replacement_name), genuine_other_receipt)
                for member in source.infolist():
                    raw = source.read(member)
                    if member.filename == replacement_name:
                        raw = genuine_other_receipt
                    target.writestr(member, raw)

            self.assertEqual(read_zip_member(replacement, "manifest.json"),
                             read_zip_member(PAYLOAD, "manifest.json"))
            with self.assertRaisesRegex(reader.OriginError, r"(?i)receipt"):
                reader.read_manifest(replacement, MANIFEST_SHA256, SOURCE_CONTEXT)

class CompilerManifestSourceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.args = argparse.Namespace(
            compiler_run_id=SOURCE_CONTEXT["run_id"], compiler_run_attempt=SOURCE_CONTEXT["run_attempt"],
            job_name=CALLER_JOB_NAME, manifest_sha256=None)
        self.enterContext(mock.patch.object(reader.origin, "context_from_environment", return_value=CALLER_CONTEXT))
        self.events = self.enterContext(mock.patch.object(
            reader.origin, "observe_run_event", return_value="workflow_dispatch"))
        self.enterContext(mock.patch.object(
            reader.selector, "select_owner_artifacts", side_effect=self.select_manifest))
        self.verify = self.enterContext(mock.patch.object(
            reader.origin, "verify_source", side_effect=self.retain_verified_payload))
        self.decode = self.enterContext(mock.patch.object(reader, "read_manifest", wraps=reader.read_manifest))

    def select_manifest(self, args):
        self.assertEqual(args.source_context.read_bytes(), reader.origin.canonical(SOURCE_CONTEXT))
        self.assertEqual(args.source_context_sha256, sha256(args.source_context.read_bytes()))
        self.assertEqual(args.job_name, reader.ASSEMBLY_JOB)
        self.assertEqual(args.payload_name, "compiler-manifest-v2-45351030854-1")
        self.assertEqual(args.proof_name, "compiler-manifest-v2-proof-45351030854-1")
        self.assertEqual((args.role, args.group, args.host, args.profile, args.copy),
                         ("comparison", "compilers", "linux-x86_64", "manifest", "none"))
        return {"test_selection": args.payload_name}

    def retain_verified_payload(self, args, caller):
        self.assertEqual(caller, CALLER_CONTEXT)
        self.assertEqual(args.workflow, CALLER_CONTEXT["workflow"])
        self.assertEqual(args.job_name, CALLER_JOB_NAME)
        self.assertEqual(json.loads(args.source_selection.read_bytes()),
                         {"test_selection": "compiler-manifest-v2-45351030854-1"})
        root = args.verified_output_dir
        root.mkdir(mode=0o700)
        shutil.copyfile(PAYLOAD, root / "payload.zip")
        (root / "origin.json").write_bytes(reader.origin.canonical({
            "files": {"manifest.json": {"sha256": MANIFEST_SHA256}},
        }))

    def test_reads_only_after_authenticating_the_selected_source(self) -> None:
        result = reader.read_from_compiler_run(self.args)
        self.assertEqual(result["manifest_sha256"], MANIFEST_SHA256)
        self.assertEqual(result["context"], SOURCE_CONTEXT)
        self.assertEqual(len(result["comparisons"]), 12)
        self.assertEqual(self.events.call_args_list,
                         [mock.call(SOURCE_CONTEXT, require_success=True), mock.call(CALLER_CONTEXT)])
        self.verify.assert_called_once()

    def test_wrong_optional_pin_stops_before_decode(self) -> None:
        self.args.manifest_sha256 = "0" * 64
        with self.assertRaisesRegex(reader.OriginError, "manifest digest differs from signed origin"):
            reader.read_from_compiler_run(self.args)
        self.decode.assert_not_called()

    def test_failed_signature_stops_before_decode(self) -> None:
        self.verify.side_effect = reader.OriginError("signature verification failed")
        with self.assertRaisesRegex(reader.OriginError, "signature verification failed"):
            reader.read_from_compiler_run(self.args)
        self.decode.assert_not_called()


if __name__ == "__main__":
    unittest.main()
