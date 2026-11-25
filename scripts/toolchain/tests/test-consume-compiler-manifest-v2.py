#!/usr/bin/env python3
"""Offline joins and substitution counterprobes for the SDK manifest consumer."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts/toolchain/consume-compiler-manifest-v2.py"
SPEC = importlib.util.spec_from_file_location("consume_compiler_manifest", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
consumer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(consumer)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


class Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.context = {
            "repository": "metaneutrons/aros-toolchains",
            "repository_id": 1389046806,
            "producer_commit": "a" * 40,
            "source_ref": "refs/heads/main",
            "workflow": ".github/workflows/toolchain-compilers-v2.yml",
            "run_id": 45351030854,
            "run_attempt": 1,
        }
        self.group, self.host, self.profile = "gnu-rv32", "linux-x86_64", "release"
        self.asset = "compiler-linux-x86_64-release.tar.xz"
        self.package_members = {
            self.asset: b"archive-bytes",
            self.asset + ".manifest.json": b"manifest-bytes",
            self.asset + ".sha256": b"checksum-bytes",
            self.asset + ".spdx.json": b"spdx-bytes",
        }
        members = [
            {"name": name, "size": len(raw), "sha256": digest(raw)}
            for name, raw in self.package_members.items()
        ]
        self.receipt = {
            "schema": 1, "operation": "compare", "byte_identical": True,
            "members": members,
            "package_set_sha256": digest(canonical(members)),
        }
        receipt_raw = canonical(self.receipt)
        self.selections = {}
        self.transport_results = {}
        owners = {}
        for copy, job_id in (("a", 7001), ("b", 7002)):
            selection = self.root / f"selection-{copy}.json"
            selection.write_bytes(f"selection-{copy}".encode())
            self.selections[copy] = selection
            owner_root = self.root / f"owner-{copy}"
            transport = owner_root / "transport"
            package = owner_root / "payload/package"
            evidence = owner_root / "payload/evidence"
            package.mkdir(parents=True)
            evidence.mkdir()
            (transport).mkdir()
            (transport / "selection.json").write_bytes(selection.read_bytes())
            origin = {
                "schema": "aros-toolchain-artifact-origin-v1",
                "context": self.context,
                "selection": {"role": "build", "group": self.group,
                               "host": self.host, "profile": self.profile, "copy": copy},
                "job": {"id": job_id, "check_run_id": job_id + 10, "name": "native"},
                "artifact": {}, "files": {},
            }
            origin_raw = canonical(origin)
            (transport / "origin.json").write_bytes(origin_raw)
            signature_raw = f"signature-{copy}".encode()
            (transport / "origin.sigstore.json").write_bytes(signature_raw)
            (transport / "payload.zip").write_bytes(f"zip-{copy}".encode())
            output_files = {}
            for name, raw in self.package_members.items():
                path = package / name
                path.write_bytes(raw)
                output_files[f"package/{name}"] = {
                    "path": str(path), "sha256": digest(raw), "size": len(raw),
                }
            environment = evidence / "environment.json"
            measurement = evidence / "measurement.json"
            environment.write_bytes(b"environment")
            measurement.write_bytes(b"measurement")
            output_files["evidence/environment.json"] = {
                "path": str(environment), "sha256": digest(environment.read_bytes()),
                "size": environment.stat().st_size,
            }
            output_files["evidence/measurement.json"] = {
                "path": str(measurement), "sha256": digest(measurement.read_bytes()),
                "size": measurement.stat().st_size,
            }
            owners[copy] = {
                "original_job_id": job_id,
                "selection_sha256": digest(selection.read_bytes()),
                "payload_zip_sha256": digest(f"zip-{copy}".encode()),
                "origin_sha256": digest(origin_raw),
                "origin_sigstore_sha256": digest(signature_raw),
            }
            result = {
                "schema": "aros-toolchain-native-lane-transport-v2",
                "assurance": "transport-byte-readback-only",
                "package_dir": str(package),
                "measurement": str(measurement),
                "measurement_sha256": digest(measurement.read_bytes()),
                "measurement_size": measurement.stat().st_size,
                "environment": str(environment),
                "origin_sha256": owners[copy]["origin_sha256"],
                "selection_sha256": owners[copy]["selection_sha256"],
                "raw_zip_sha256": owners[copy]["payload_zip_sha256"],
                "output_files": output_files,
            }
            (owner_root / "transport-result.json").write_bytes(canonical(result))
            self.transport_results[copy] = result
        self.summary = {
            "manifest_sha256": "b" * 64,
            "context": self.context,
            "bindings": {},
            "comparisons": {
                self.asset: {
                    "receipt_sha256": digest(receipt_raw),
                    "receipt_json": receipt_raw.decode(),
                    "group_id": self.group, "host": self.host,
                    "target_profile": self.profile, "owners": owners,
                }
            },
        }
        self.summary_path = self.root / "summary.json"
        self.summary_path.write_bytes(canonical(self.summary))
        self.summary_sha256 = digest(self.summary_path.read_bytes())

    def args(self, *, output_name: str = "comparison.json"):
        return type("Args", (), {
            "manifest": self.summary_path,
            "manifest_sha256": self.summary_sha256,
            "group": self.group, "host": self.host, "profile": self.profile,
            "source_workflow": self.context["workflow"],
            "source_ref": self.context["source_ref"],
            "owner_a_selection": self.selections["a"],
            "owner_b_selection": self.selections["b"],
            "owner_a_root": self.root / "owner-a",
            "owner_b_root": self.root / "owner-b",
            "receipt_output": self.root / output_name,
        })()


class ConsumerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="compiler-manifest-consumer-")
        self.fixture = Fixture(Path(self.temporary.name).resolve())
        self.transport = mock.patch.object(
            consumer.TRANSPORT, "verify_output",
            side_effect=lambda retained, output: self.fixture.transport_results[retained.parent.name[-1]],
        )
        self.transport_mock = self.transport.start()

    def tearDown(self) -> None:
        self.transport.stop()
        self.temporary.cleanup()

    def test_joins_both_owner_transports_and_retains_original_receipt(self) -> None:
        args = self.fixture.args()
        consumer.consume(args)
        self.assertEqual(args.receipt_output.read_bytes(),
                         self.fixture.summary["comparisons"][self.fixture.asset]["receipt_json"].encode())
        self.assertEqual(self.transport_mock.call_count, 2)

    def test_rejects_owner_selection_substitution(self) -> None:
        self.fixture.selections["a"].write_bytes(b"substituted-selection")
        with self.assertRaisesRegex(consumer.OriginError, "selection differs"):
            consumer.consume(self.fixture.args())

    def test_rejects_package_member_substitution(self) -> None:
        result = self.fixture.transport_results["b"]
        result["output_files"][f"package/{self.fixture.asset}"]["sha256"] = "0" * 64
        (self.fixture.root / "owner-b/transport-result.json").write_bytes(canonical(result))
        with self.assertRaisesRegex(consumer.OriginError, "package member differs"):
            consumer.consume(self.fixture.args(output_name="substituted.json"))

    def test_rejects_owner_job_substitution(self) -> None:
        origin_path = self.fixture.root / "owner-b/transport/origin.json"
        origin = json.loads(origin_path.read_bytes())
        origin["job"]["id"] = 9999
        origin_path.write_bytes(canonical(origin))
        with self.assertRaisesRegex(consumer.OriginError, "owner job differs"):
            consumer.consume(self.fixture.args(output_name="job-substitution.json"))

    def test_rejects_ambiguous_lane_selection(self) -> None:
        extra = dict(self.fixture.summary["comparisons"][self.fixture.asset])
        self.fixture.summary["comparisons"]["other.tar.xz"] = extra
        self.fixture.summary_path.write_bytes(canonical(self.fixture.summary))
        self.fixture.summary_sha256 = digest(self.fixture.summary_path.read_bytes())
        with self.assertRaisesRegex(consumer.OriginError, "exactly one"):
            consumer.consume(self.fixture.args(output_name="ambiguous.json"))


if __name__ == "__main__":
    unittest.main()
