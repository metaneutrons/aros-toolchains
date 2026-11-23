"""Contract tests for the compiler run manifest staging of the split qualification."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "stage-compiler-run-manifest-v2.py"
COMPILER_WORKFLOW = ".github/workflows/toolchain-compilers-v2.yml"


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode() + b"\n"


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


class Fixture:
    def __init__(self, base: Path, *, workflow: str = COMPILER_WORKFLOW) -> None:
        self.base = base.resolve()
        self.context = {
            "repository": "example/project", "repository_id": 7, "producer_commit": "a" * 40,
            "source_ref": "refs/heads/main", "workflow": workflow,
            "run_id": 10, "run_attempt": 1,
        }
        self.context_path = self.write("context.json", canonical(self.context))
        self.fragment_path = self.write("owners/selection-fragment.json", b'{"fragment":1}\n')
        self.lanes_path = self.write("stage/compiler-index-lanes.json", b'{"lanes":{}}\n')
        self.evidence_path = self.write("stage/compiler-evidence-fragment.json", b'{"assets":{}}\n')
        self.receipts = {
            "asset-a.tar.xz": self.write("stage/reports/lane-a.json", b'{"receipt":"a"}\n'),
            "asset-b.tar.xz": self.write("stage/reports/lane-b.json", b'{"receipt":"b"}\n'),
        }
        self.summary = {
            "schema": "aros-toolchain-compiler-candidate-assembly-v2",
            "assurance": "compiler-candidate-byte-assembly-partial-no-admission",
            "bindings": {
                "aros_sha256": "1" * 64, "plan_sha256": "2" * 64, "inputs_sha256": "3" * 64,
                "fragment_sha256": sha(self.fragment_path.read_bytes()),
                "required_paths_sha256": "4" * 64,
                "source_context_sha256": sha(self.context_path.read_bytes()),
                "producer_commit": "a" * 40, "tools_commit": "b" * 40, "release_id": "toolchain-dev-x",
            },
            "staged_inventory": {},
            "artifacts": {
                "compiler_index_lanes": self.selector(self.lanes_path),
                "compiler_evidence_fragment": self.selector(self.evidence_path),
                "comparisons": {asset: self.selector(path) for asset, path in self.receipts.items()},
                "native_verifications": {},
            },
            "scope": {"compiler_only": True, "sdk_included": False,
                      "admission": False, "publication": False},
        }
        self.write_summary()

    def write(self, name: str, raw: bytes) -> Path:
        path = self.base / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        return path

    @staticmethod
    def selector(path: Path) -> dict:
        raw = path.read_bytes()
        return {"path": str(path), "sha256": sha(raw), "size": len(raw)}

    def write_summary(self) -> None:
        self.summary_path = self.write("summary.json", canonical(self.summary))

    def run(self, output: Path, **replace: str) -> subprocess.CompletedProcess[str]:
        arguments = {
            "--context": str(self.context_path), "--context-sha256": sha(self.context_path.read_bytes()),
            "--summary": str(self.summary_path), "--summary-sha256": sha(self.summary_path.read_bytes()),
            "--fragment": str(self.fragment_path), "--fragment-sha256": sha(self.fragment_path.read_bytes()),
            "--output-dir": str(output),
        }
        arguments.update(replace)
        flat = [item for pair in arguments.items() for item in pair]
        return subprocess.run([sys.executable, "-B", str(SCRIPT), *flat],
                              capture_output=True, text=True, check=False)


class CompilerRunManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="compiler-run-manifest.")
        self.base = Path(self.temporary.name).resolve()
        self.fixture = Fixture(self.base / "fixture")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def assert_rejected(self, result: subprocess.CompletedProcess[str], message: str,
                        output: Path) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(result.stdout, "")
        self.assertIn("compiler run manifest failed:", result.stderr)
        self.assertIn(message, result.stderr)
        self.assertFalse(output.exists())

    def test_stages_every_bound_file_under_one_manifest(self) -> None:
        output = self.base / "payload"
        result = self.fixture.run(output)
        self.assertEqual(result.returncode, 0, result.stderr)
        manifest_raw = (output / "manifest.json").read_bytes()
        self.assertEqual(json.loads(result.stdout)["manifest_sha256"], sha(manifest_raw))
        manifest = json.loads(manifest_raw)
        self.assertEqual(manifest["schema"], "aros-toolchain-compiler-run-manifest-v2")
        self.assertEqual(manifest["context"], self.fixture.context)
        self.assertEqual(manifest["bindings"], self.fixture.summary["bindings"])
        self.assertEqual(manifest["comparison_assets"], sorted(self.fixture.receipts))
        self.assertEqual(manifest["scope"], {"release_admission": False, "publication": False})
        expected = {"context.json", "assembly-summary.json", "compiler-owner-fragment.json",
                    "compiler-index-lanes.json", "compiler-evidence-fragment.json",
                    *(f"comparisons/{asset}.json" for asset in self.fixture.receipts)}
        self.assertEqual(set(manifest["files"]), expected)
        for name, measured in manifest["files"].items():
            raw = (output / name).read_bytes()
            self.assertEqual(measured, {"sha256": sha(raw), "size": len(raw)})
        self.assertEqual((output / "comparisons" / "asset-a.tar.xz.json").read_bytes(),
                         self.fixture.receipts["asset-a.tar.xz"].read_bytes())

    def test_changed_bound_bytes_are_rejected(self) -> None:
        for name, path in (("receipt", self.fixture.receipts["asset-b.tar.xz"]),
                           ("lanes", self.fixture.lanes_path),
                           ("evidence", self.fixture.evidence_path)):
            with self.subTest(file=name):
                original = path.read_bytes()
                path.write_bytes(original + b" ")
                output = self.base / f"payload-{name}"
                self.assert_rejected(self.fixture.run(output), "differ from their selected digest",
                                     output)
                path.write_bytes(original)

    def test_selected_digests_are_bound(self) -> None:
        for option, message in (("--context-sha256", "differ from their selected digest"),
                                ("--summary-sha256", "differ from their selected digest"),
                                ("--fragment-sha256", "not bound to this run context")):
            with self.subTest(option=option):
                output = self.base / f"payload{option}"
                self.assert_rejected(self.fixture.run(output, **{option: "0" * 64}), message, output)

    def test_summary_must_bind_this_context_and_fragment(self) -> None:
        for field in ("source_context_sha256", "fragment_sha256"):
            with self.subTest(field=field):
                fixture = Fixture(self.base / f"fixture-{field}")
                fixture.summary["bindings"][field] = "9" * 64
                fixture.write_summary()
                output = self.base / f"payload-{field}"
                self.assert_rejected(fixture.run(output), "not bound to this run context", output)

    def test_only_the_compiler_workflow_context_is_admitted(self) -> None:
        fixture = Fixture(self.base / "legacy", workflow=".github/workflows/toolchain-release.yml")
        output = self.base / "payload-legacy"
        self.assert_rejected(fixture.run(output), "compiler qualification workflow", output)

    def test_summary_scope_schema_and_receipts_are_closed(self) -> None:
        cases = {
            "scope": ("scope", {"compiler_only": True, "sdk_included": True,
                                "admission": False, "publication": False}),
            "schema": ("schema", "other"),
        }
        for name, (field, value) in cases.items():
            with self.subTest(case=name):
                fixture = Fixture(self.base / f"closed-{name}")
                fixture.summary[field] = value
                fixture.write_summary()
                output = self.base / f"payload-closed-{name}"
                result = fixture.run(output)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(output.exists())
        fixture = Fixture(self.base / "no-receipts")
        fixture.summary["artifacts"]["comparisons"] = {}
        fixture.write_summary()
        output = self.base / "payload-no-receipts"
        self.assert_rejected(fixture.run(output), "no comparison receipts", output)

    def test_existing_output_and_repeated_options_are_rejected(self) -> None:
        output = self.base / "existing"
        output.mkdir()
        result = self.fixture.run(output)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must be absent", result.stderr)
        repeated = subprocess.run([sys.executable, "-B", str(SCRIPT), "--context", "a", "--context", "b"],
                                  capture_output=True, text=True, check=False)
        self.assertEqual(repeated.returncode, 2)
        self.assertIn("repeated command-line option", repeated.stderr)


if __name__ == "__main__":
    unittest.main()
