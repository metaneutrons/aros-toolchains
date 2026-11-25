#!/usr/bin/env python3
"""Focused receipt/retention tests; no fake guest execution is asserted."""

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("runtime", HERE / "sdk-runtime-probe-v1.py")
runtime = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(runtime)


def elf64(payload: bytes = b"") -> bytes:
    header = bytearray(64)
    header[:4] = b"\x7fELF"
    header[4:6] = bytes((2, 1))
    header[18:20] = (62).to_bytes(2, "little")
    return bytes(header) + payload


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="sdk-runtime-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.op = self.root / "operation"
        self.llvm = self.op / "reports/llvm-sdk-links"
        self.gnu = self.op / "reports/native-sdk-links"
        (self.llvm / "receipt").mkdir(parents=True)
        (self.llvm / "links").mkdir()
        (self.gnu).mkdir(parents=True)
        self.binary = elf64(b"old SDK consumer")
        (self.llvm / "links/original-c.elf").write_bytes(self.binary)
        (self.gnu / "original-c.elf").write_bytes(self.binary)
        sha = hashlib.sha256(self.binary).hexdigest()
        size = len(self.binary)
        llvm_receipt = {
            "schema": "aros-llvm-sdk-link-receipt-v1",
            "assurance": "local-links-not-generation-authentication-or-release-admission",
            "members": {"links/original-c.elf": {"sha256": sha, "size": size}},
        }
        gnu_receipt = {
            "schema": "aros-native-sdk-link-receipt-v1",
            "qualification": "local-links-not-release-admission",
            "outputs": {"original-c": {"sha256": sha, "size": size}},
        }
        (self.llvm / "receipt/llvm-sdk-links.receipt.json").write_bytes(runtime.canon(llvm_receipt))
        (self.gnu / "native-sdk-links.receipt.json").write_bytes(runtime.canon(gnu_receipt))

    def test_retain_matches_actual_llvm_and_gnu_layouts(self):
        for family, receipt in (
            ("llvm", self.llvm / "receipt/llvm-sdk-links.receipt.json"),
            ("gnu", self.gnu / "native-sdk-links.receipt.json"),
        ):
            expected = hashlib.sha256(receipt.read_bytes()).hexdigest()
            result = runtime.retain(self.op, family, expected)
            self.assertEqual(result["status"], "retained")
            self.assertEqual(result["binary_size"], len(self.binary))
            self.assertEqual(result["binary_sha256"], hashlib.sha256(self.binary).hexdigest())
            self.assertNotIn("operation", result)
            self.assertEqual(runtime.elf(self.binary)["machine"], 62)

    def test_receipt_digest_and_member_mutation_are_rejected(self):
        receipt = self.llvm / "receipt/llvm-sdk-links.receipt.json"
        with self.assertRaisesRegex(runtime.ProbeError, "receipt digest"):
            runtime.retain(self.op, "llvm", "0" * 64)
        document = json.loads(receipt.read_text())
        document["members"]["links/original-c.elf"]["sha256"] = "f" * 64
        receipt.write_bytes(runtime.canon(document))
        with self.assertRaisesRegex(runtime.ProbeError, "original-c.elf"):
            runtime.retain(self.op, "llvm", hashlib.sha256(receipt.read_bytes()).hexdigest())

    def test_large_real_consumer_is_unavailable_without_base64(self):
        data = elf64(b"x" * (runtime.MAX_ELF + 1))
        binary = self.gnu / "original-c.elf"
        binary.write_bytes(data)
        sha = hashlib.sha256(data).hexdigest()
        receipt = {
            "schema": "aros-native-sdk-link-receipt-v1",
            "qualification": "local-links-not-release-admission",
            "outputs": {"original-c": {"sha256": sha, "size": len(data)}},
        }
        receipt_path = self.gnu / "native-sdk-links.receipt.json"
        receipt_path.write_bytes(runtime.canon(receipt))
        result = runtime.retain(self.op, "gnu", hashlib.sha256(receipt_path.read_bytes()).hexdigest())
        self.assertEqual(result["status"], "unavailable")
        self.assertNotIn("binary_base64", result)

    def test_guest_result_requires_two_complete_lines_and_the_current_nonce(self):
        start = b"AROS-SDK-RUNTIME:abc:START\r\n"
        passed = b"AROS-SDK-RUNTIME:abc:PASS\r\n"
        failed = b"AROS-SDK-RUNTIME:abc:FAIL\r\n"
        self.assertEqual(runtime.serial_result(start + passed + b"partial", "abc"), "passed")
        self.assertEqual(runtime.serial_result(start + failed, "abc"), "failed")
        for log in (
            passed,
            start + passed.rstrip(),
            start + b"Echo " + passed,
            start + passed.replace(b"abc", b"def"),
        ):
            self.assertIsNone(runtime.serial_result(log, "abc"))

    def test_replay_rejects_substituted_report_and_image(self):
        receipt = self.llvm / "receipt/llvm-sdk-links.receipt.json"
        consumer = runtime.retain(self.op, "llvm", hashlib.sha256(receipt.read_bytes()).hexdigest())
        report, iso = self.root / "report.json", self.root / "candidate.iso"
        report.write_bytes(runtime.canon({"targets": {"pc-x86_64": {"consumer": consumer}}}))
        report_sha = hashlib.sha256(report.read_bytes()).hexdigest()
        iso.write_bytes(b"substituted")
        with self.assertRaisesRegex(runtime.ProbeError, "report digest"):
            runtime.replay(report, "f" * 64, iso, "f" * 64)
        with self.assertRaisesRegex(runtime.ProbeError, "ISO digest"):
            runtime.replay(report, report_sha, iso, "f" * 64)

    def test_replay_rejects_non_iso_as_unsupported_without_guest_claim(self):
        retained = runtime.retain(
            self.op,
            "llvm",
            hashlib.sha256((self.llvm / "receipt/llvm-sdk-links.receipt.json").read_bytes()).hexdigest(),
        )
        report = self.root / "report.json"
        report.write_bytes(runtime.canon({"targets": {"pc-x86_64": {"consumer": retained}}}))
        image = self.root / "not-an-iso"
        image.write_bytes(b"not an ISO")
        result = runtime.replay(
            report,
            hashlib.sha256(report.read_bytes()).hexdigest(),
            image,
            hashlib.sha256(image.read_bytes()).hexdigest(),
            timeout=1,
        )
        self.assertEqual(result["status"], "unsupported")
        self.assertNotEqual(result["status"], "passed")


if __name__ == "__main__":
    unittest.main()
