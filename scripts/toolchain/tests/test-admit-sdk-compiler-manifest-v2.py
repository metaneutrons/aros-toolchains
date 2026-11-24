#!/usr/bin/env python3
"""Offline admission and manifest-artifact freshness tests."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile


ROOT = Path(__file__).resolve().parents[3]
TOOLCHAIN = ROOT / "scripts" / "toolchain"
SCRIPT = TOOLCHAIN / "admit-sdk-compiler-manifest-v2.py"
READER_SCRIPT = TOOLCHAIN / "read-compiler-run-manifest-v2.py"
PAYLOAD = Path(__file__).resolve().parent / "fixtures" / "compiler-run-manifest-v2-payload.zip"


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


reader = load("admission_reader_fixture", READER_SCRIPT)

PRODUCER = "dcf601b337dbcacb246c6bc459042a31519fb258"
TOOLS = "b9acfa76b893d580b1b36fd5a303f7cb4c478743"
RELEASE = "toolchain-dev-dcf601b337db"


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def provider_artifact(*, created_at: str, updated_at: str | None = None) -> dict:
    context = {
        "repository": "metaneutrons/aros-toolchains",
        "repository_id": 1389046806,
        "producer_commit": PRODUCER,
        "source_ref": "refs/heads/main",
        "workflow": ".github/workflows/toolchain-compilers-v2.yml",
        "run_id": 45351030854,
        "run_attempt": 1,
    }
    artifact = {
        "id": 14967727018,
        "name": "compiler-manifest-v2-45351030854-1",
        "digest": "sha256:" + "1" * 64,
        "expired": False,
        "size_in_bytes": 32284,
        "created_at": created_at,
        "workflow_run": {
            "id": context["run_id"],
            "repository_id": context["repository_id"],
            "head_repository_id": context["repository_id"],
            "head_sha": context["producer_commit"],
        },
    }
    if updated_at is not None:
        artifact["updated_at"] = updated_at
    return artifact


class ManifestFreshnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.context = {
            "repository": "metaneutrons/aros-toolchains",
            "repository_id": 1389046806,
            "producer_commit": PRODUCER,
            "source_ref": "refs/heads/main",
            "workflow": ".github/workflows/toolchain-compilers-v2.yml",
            "run_id": 45351030854,
            "run_attempt": 1,
        }
        self.selection = {
            "artifact": {
                "id": 14967727018,
                "name": "compiler-manifest-v2-45351030854-1",
                "sha256": "1" * 64,
                "size_in_bytes": 32284,
            }
        }

    def test_exactly_thirteen_days_is_rejected(self) -> None:
        created = "2027-01-15T08:00:00Z"
        created_epoch = 1_800_000_000
        item = provider_artifact(created_at=created)
        with mock.patch.object(reader.origin, "gh_json", return_value=item), mock.patch.object(
            reader.time, "time", return_value=created_epoch + 13 * 24 * 60 * 60
        ):
            with self.assertRaisesRegex(reader.OriginError, "13 days old or older"):
                reader.require_fresh_manifest_artifact(self.context, self.selection)

    def test_recent_run_update_cannot_refresh_an_old_manifest_artifact(self) -> None:
        item = provider_artifact(
            created_at="2027-01-01T08:00:00Z",
            updated_at="2027-01-15T08:00:00Z",
        )
        with mock.patch.object(reader.origin, "gh_json", return_value=item), mock.patch.object(
            reader.time, "time", return_value=1_800_000_000
        ):
            with self.assertRaisesRegex(reader.OriginError, "13 days old or older"):
                reader.require_fresh_manifest_artifact(self.context, self.selection)


class AdmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="sdk-manifest-admission-")
        self.root = Path(self.temporary.name).resolve()
        self.inputs = self.root / "inputs"
        self.inputs.mkdir()
        self.summary_path = self.root / "manifest.json"
        self.runtime = self.root / "aros"
        self.runtime.write_text(
            "#!/usr/bin/env python3\n"
            "from pathlib import Path\n"
            "import sys\n"
            "directory = Path(sys.argv[sys.argv.index('--directory') + 1])\n"
            "sys.stdout.buffer.write((directory / 'plan.json').read_bytes())\n",
            encoding="utf-8",
        )
        self.runtime.chmod(self.runtime.stat().st_mode | stat.S_IXUSR)
        with zipfile.ZipFile(PAYLOAD) as archive:
            self.manifest = json.loads(archive.read("manifest.json"))
        summary = reader.read_manifest(PAYLOAD, digest(self._member("manifest.json")),
                                       self.manifest["context"])
        lanes = sorted(
            {
                (entry["group_id"], entry["host"], entry["target_profile"])
                for entry in summary["comparisons"].values()
            }
        )
        collection = canonical({
            "schema": "aros-toolchain-release-inputs-v2",
            "producer_commit": PRODUCER,
            "tools_commit": TOOLS,
            "hosts": ["linux-aarch64", "linux-x86_64", "macos-aarch64"],
            "groups": [],
            "sdks": [],
        })
        self.inputs_file = self.inputs / "toolchain-release-inputs-v2.json"
        self.inputs_file.write_bytes(collection)
        inputs_sha = digest(collection)
        plan = {
            "schema": "aros-toolchain-producer-stage-v2",
            "operation": "release-plan",
            "inputs_sha256": inputs_sha,
            "producer_commit": PRODUCER,
            "tools_commit": TOOLS,
            "lane_count": len(lanes),
            "lanes": [
                {"group_id": group, "host": host, "target_profile": profile}
                for group, host, profile in lanes
            ],
        }
        plan_raw = canonical(plan)
        (self.inputs / "plan.json").write_bytes(plan_raw)
        bindings = summary["bindings"]
        bindings.update({
            "aros_sha256": digest(self.runtime.read_bytes()),
            "inputs_sha256": inputs_sha,
            "plan_sha256": digest(plan_raw),
            "producer_commit": PRODUCER,
            "release_id": RELEASE,
            "tools_commit": TOOLS,
        })
        self.summary_path.write_bytes(canonical(summary))
        self.summary_sha256 = digest(self.summary_path.read_bytes())

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _member(self, name: str) -> bytes:
        with zipfile.ZipFile(PAYLOAD) as archive:
            return archive.read(name)

    def run_admission(self, summary_path: Path | None = None) -> subprocess.CompletedProcess[str]:
        path = summary_path or self.summary_path
        environment = os.environ.copy()
        environment["GITHUB_SHA"] = PRODUCER
        return subprocess.run(
            [
                sys.executable,
                "-B",
                str(SCRIPT),
                "--manifest",
                str(path),
                "--summary-sha256",
                digest(path.read_bytes()),
                "--aros",
                str(self.runtime),
                "--inputs-dir",
                str(self.inputs),
                "--release-id",
                RELEASE,
                "--tools-commit",
                TOOLS,
            ],
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_real_manifest_fixture_admits_regenerated_plan(self) -> None:
        result = self.run_admission()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")

    def test_independent_sdk_bindings_must_match(self) -> None:
        summary = json.loads(self.summary_path.read_bytes())
        altered_path = self.root / "different-binding.json"
        for key, diagnostic in (
            ("producer_commit", "producer commit"), ("release_id", "release ID"),
            ("tools_commit", "tools commit"), ("aros_sha256", "runtime"),
            ("inputs_sha256", "release inputs"), ("plan_sha256", "matrix plan"),
        ):
            with self.subTest(key=key):
                altered = dict(summary, bindings=dict(summary["bindings"], **{key: "0" * 64}))
                altered_path.write_bytes(canonical(altered))
                result = self.run_admission(altered_path)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(diagnostic, result.stderr)

    def test_manifest_lane_graph_must_match_regenerated_plan(self) -> None:
        altered = json.loads(self.summary_path.read_bytes())
        first = next(iter(altered["comparisons"].values()))
        first["target_profile"] = "not-in-plan"
        altered_path = self.root / "altered-manifest.json"
        altered_path.write_bytes(canonical(altered))
        result = self.run_admission(altered_path)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("compiler lanes", result.stderr)


if __name__ == "__main__":
    unittest.main()
