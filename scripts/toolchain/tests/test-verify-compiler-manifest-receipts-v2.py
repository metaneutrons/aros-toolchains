#!/usr/bin/env python3
"""Replay all signed comparison receipts at the final candidate boundary."""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

HERE = Path(__file__).resolve().parent
PAYLOAD = HERE / "fixtures/compiler-run-manifest-v2-payload.zip"
MANIFEST_SHA = "2c743dce32680b0451caf78ce1828294061a3143f75e2d04914771cff52d3eb6"
spec = importlib.util.spec_from_file_location("receipts", HERE.parent / "verify-compiler-manifest-receipts-v2.py")
receipts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(receipts)


class CandidateReceiptTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name).resolve()
        reports = root / "reports"
        reports.mkdir()
        with zipfile.ZipFile(PAYLOAD) as archive:
            context = json.loads(archive.read("context.json"))
            self.evidence = json.loads(archive.read("compiler-evidence-fragment.json"))
            for asset, lane in self.evidence["assets"].items():
                path = reports / (asset + ".json")
                path.write_bytes(archive.read("comparisons/" + asset + ".json"))
                lane["comparison"]["selectedFile"]["path"] = str(path)

        summary = receipts.reader.read_manifest(PAYLOAD, MANIFEST_SHA, context)
        summary_path = root / "manifest.json"
        summary_path.write_bytes(receipts.origin.canonical(summary))
        self.args = argparse.Namespace(
            manifest=summary_path, manifest_sha256=MANIFEST_SHA,
            summary_sha256=hashlib.sha256(summary_path.read_bytes()).hexdigest(),
            compiler_evidence=root / "compiler-evidence-fragment.json", candidate_summary=root / "combined.json")
        self.args.candidate_summary.write_bytes(receipts.origin.canonical({
            "bindings": {"source_context_sha256": "2" * 64,
                         "compiler_source_context_sha256": summary["bindings"]["source_context_sha256"]},
            "outputs": {"index": {"sha256": "3" * 64}, "subject_manifest": {"sha256": "4" * 64}}}))
        self.lane = next(iter(self.evidence["assets"].values()))
        self.evidence["bindings"]["fragment_sha256"] = "1" * 64

    def verify(self):
        self.args.compiler_evidence.write_bytes(receipts.origin.canonical(self.evidence))
        return receipts.verify(self.args)

    def test_accepts_twelve_receipts_with_relocated_readback(self):
        result = self.verify()
        self.assertEqual(result["manifest_sha256"], MANIFEST_SHA)
        self.assertEqual(len(result["receipts"]), 12)

    def test_rejects_substituted_owner(self):
        self.lane["builds"][1]["selection_sha256"] = "0" * 64
        with self.assertRaisesRegex(receipts.reader.OriginError, "owner identity"):
            self.verify()

    def test_rejects_substituted_receipt_even_with_updated_selector(self):
        selected = self.lane["comparison"]["selectedFile"]
        data = b"{}\n"
        Path(selected["path"]).write_bytes(data)
        selected["sha256"] = hashlib.sha256(data).hexdigest()
        with self.assertRaisesRegex(receipts.reader.OriginError, "receipt differs"):
            self.verify()

    def test_rejects_different_compiler_context(self):
        self.evidence["bindings"]["source_context_sha256"] = "0" * 64
        with self.assertRaisesRegex(receipts.reader.OriginError, "bindings differ"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
