#!/usr/bin/env python3
"""Focused orchestration tests for native producer host preflights."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
PREFLIGHT = ROOT / "scripts/toolchain/check-native-host-preflights-v2.py"
MAX_LOG_BYTES = 1024 * 1024


class NativeHostPreflightFixture:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.inputs = self.root / "inputs"
        self.inputs.mkdir()
        self.cache = self.root / "cache"
        self.cache.mkdir()
        self.output = self.root / "output"
        self.runtime = self.root / "runtime"
        self.runtime.mkdir()
        self.aros = self.runtime / "aros"
        self.configuration = self.root / "fake-cli.json"
        self.calls = self.root / "calls.jsonl"
        (self.inputs / "toolchain-release-inputs-v2.json").write_bytes(b"fixture release input collection\n")
        self.documents: dict[str, bytes] = {}
        self.groups = [
            self._add_group("fixture-llvm", "llvm-lock.json", "llvm-profiles.json"),
            self._add_group("fixture-gnu", "gnu-lock.json", "gnu-profiles.json"),
        ]
        self.lanes = [
            {"group_id": "fixture-llvm", "host": "macos-aarch64", "target_profile": "llvm-rv32"},
            {"group_id": "fixture-llvm", "host": "linux-x86_64", "target_profile": "llvm-linux"},
            {"group_id": "fixture-gnu", "host": "macos-aarch64", "target_profile": "gnu-rv32"},
            {"group_id": "fixture-llvm", "host": "macos-aarch64", "target_profile": "llvm-rv64"},
        ]
        self.matrix_lanes = list(self.lanes)
        self.behavior: dict[str, object] = {}
        self._write_fake_cli()
        self.write_configuration()

    def _add_group(self, group_id: str, lock_name: str, profiles_name: str) -> dict[str, object]:
        lock = (json.dumps({"group": group_id, "kind": "source-lock"}) + "\n").encode()
        profiles = (json.dumps({"group": group_id, "kind": "profiles"}) + "\n").encode()
        (self.inputs / lock_name).write_bytes(lock)
        (self.inputs / profiles_name).write_bytes(profiles)
        self.documents[lock_name] = lock
        self.documents[profiles_name] = profiles
        return {
            "group_id": group_id,
            "source_lock": {"file": lock_name, "sha256": hashlib.sha256(lock).hexdigest()},
            "profiles": {"file": profiles_name, "sha256": hashlib.sha256(profiles).hexdigest()},
        }

    def plan(self) -> dict[str, object]:
        return {
            "schema": "aros-toolchain-producer-stage-v2",
            "operation": "release-plan",
            "release_format": "family-v2",
            "assurance": "input-binding-only",
            "inputs_sha256": "0" * 64,
            "groups": list(self.groups),
            "lanes": list(self.lanes),
            "lane_count": len(self.lanes),
        }

    def write_configuration(self, *, plan: dict[str, object] | None = None) -> None:
        self.configuration.write_text(
            json.dumps(
                {
                    "plan": plan if plan is not None else self.plan(),
                    "behavior": self.behavior,
                    "call_log": str(self.calls),
                    "mutation_file": str(self.inputs / "llvm-lock.json"),
                }
            ),
            encoding="utf-8",
        )

    def selected_matrix(self, lanes: list[dict[str, str]] | None = None) -> dict[str, object]:
        source = lanes if lanes is not None else self.matrix_lanes
        return {
            "include": [
                {
                    "group_id": lane["group_id"],
                    "host": lane["host"],
                    "profile": lane["target_profile"],
                    "runner": "macos-15" if lane["host"] == "macos-aarch64" else "ubuntu-24.04",
                }
                for lane in source
            ]
        }

    def _write_fake_cli(self) -> None:
        body = f'''#!/usr/bin/env python3
import hashlib
import json
import os
from pathlib import Path
import sys
import time

config_path = Path({str(self.configuration)!r})
config = json.loads(config_path.read_text(encoding="utf-8"))
behavior = config.get("behavior", {{}})
args = sys.argv[1:]
with Path(config["call_log"]).open("a", encoding="utf-8") as calls:
    calls.write(json.dumps({{"argv": args, "has_auth_env": any(name in os.environ for name in ("GH_TOKEN", "GITHUB_TOKEN", "API_KEY", "PYTHONPATH"))}}) + "\\n")

def option(name):
    return args[args.index(name) + 1]

if args[:3] == ["toolchain", "producer", "release-plan"]:
    if behavior.get("plan_exit"):
        print("plan stdout diagnostic")
        print("plan stderr diagnostic", file=sys.stderr)
        raise SystemExit(int(behavior["plan_exit"]))
    plan = dict(config["plan"])
    plan["inputs_sha256"] = option("--inputs-sha256")
    if behavior.get("mutate_input_on_plan"):
        Path(config["mutation_file"]).write_bytes(b"changed during release-plan\\n")
    raw = (json.dumps(plan, separators=(",", ":")) + "\\n").encode()
    if behavior.get("oversized_plan"):
        sys.stdout.buffer.write(b"x" * (1024 * 1024 + 4096))
        raise SystemExit(0)
    os.write(1, raw)
    if behavior.get("close_streams_before_exit"):
        os.close(1)
        os.close(2)
        time.sleep(float(behavior.get("close_delay", 0.1)))
        os._exit(0)
elif args[:3] == ["toolchain", "producer", "host-preflight"]:
    if behavior.get("probe_exit"):
        print("probe stdout diagnostic")
        print("probe stderr diagnostic", file=sys.stderr)
        raise SystemExit(int(behavior["probe_exit"]))
    if behavior.get("oversized_probe"):
        sys.stdout.buffer.write(b"x" * (1024 * 1024 + 4096))
        raise SystemExit(0)
    if behavior.get("mutate_input_on_probe"):
        Path(config["mutation_file"]).write_bytes(b"changed during host-preflight\\n")
    source_lock = Path(option("--source-lock"))
    profiles = Path(option("--profiles"))
    python_dir = Path(option("--python-env-dir"))
    python_dir.mkdir(mode=0o700)
    report = {{
        "schema": "aros-native-host-preflight-v1",
        "assurance": "host-prerequisites-only-not-configure-build-or-release-qualification",
        "inputs": {{
            "source_lock_sha256": hashlib.sha256(source_lock.read_bytes()).hexdigest(),
            "profiles_sha256": hashlib.sha256(profiles.read_bytes()).hexdigest(),
        }},
        "host_preflight": {{"host": option("--host"), "profile": option("--preset")}},
        "python": {{"environment_dir": str(python_dir), "packages": []}},
    }}
    sys.stdout.write(json.dumps(report, separators=(",", ":")) + "\\n")
else:
    print("unexpected command", file=sys.stderr)
    raise SystemExit(90)
'''
        self.aros.write_text(body, encoding="utf-8")
        self.aros.chmod(0o755)

    def invoke(
        self,
        *,
        host: str = "macos-aarch64",
        output: Path | None = None,
        selected_matrix: dict[str, object] | None = None,
        aros_sha256: str | None = None,
    ):
        environment = os.environ.copy()
        environment.update(
            {
                "GH_TOKEN": "fixture-secret-token",
                "GITHUB_TOKEN": "fixture-secret-github-token",
                "API_KEY": "fixture-secret-api-key",
                "PYTHONPATH": "/fixture/python-injection",
            }
        )
        return subprocess.run(
            [
                sys.executable,
                "-B",
                str(PREFLIGHT),
                "--aros",
                str(self.aros.resolve()),
                "--aros-sha256",
                aros_sha256 or hashlib.sha256(self.aros.read_bytes()).hexdigest(),
                "--selected-matrix",
                json.dumps(selected_matrix or self.selected_matrix(), separators=(",", ":")),
                "--inputs-dir",
                str(self.inputs.resolve()),
                "--cache-dir",
                str(self.cache.resolve()),
                "--host",
                host,
                "--output-dir",
                str((output or self.output).resolve()),
            ],
            capture_output=True,
            text=True,
            timeout=20,
            env=environment,
            check=False,
        )

    def call_records(self) -> list[dict[str, object]]:
        if not self.calls.exists():
            return []
        return [json.loads(line) for line in self.calls.read_text(encoding="utf-8").splitlines()]

    def summary(self, output: Path | None = None) -> dict[str, object]:
        return json.loads(((output or self.output) / "native-host-preflights-v2.json").read_text(encoding="utf-8"))


class NativeHostPreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="aros-native-host-preflight-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()

    def make_fixture(self) -> NativeHostPreflightFixture:
        return NativeHostPreflightFixture(self.root)

    def test_selects_only_requested_host_lanes_and_uses_exact_producer_commands(self) -> None:
        fixture = self.make_fixture()
        result = fixture.invoke()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        summary = fixture.summary()
        self.assertEqual(summary["schema"], "aros-native-host-preflights-v2")
        self.assertEqual(
            summary["assurance"],
            "host-prerequisites-only-not-configure-build-or-release-qualification",
        )
        self.assertEqual(summary["status"], "passed")
        self.assertEqual(
            [lane["target_profile"] for lane in summary["selected_lanes"]],
            ["llvm-rv32", "gnu-rv32", "llvm-rv64"],
        )
        calls = fixture.call_records()
        self.assertEqual(len(calls), 4)
        self.assertTrue(all(call["has_auth_env"] is False for call in calls))
        self.assertEqual(
            calls[0]["argv"],
            [
                "toolchain",
                "producer",
                "release-plan",
                "--directory",
                str(fixture.inputs),
                "--inputs-sha256",
                hashlib.sha256((fixture.inputs / "toolchain-release-inputs-v2.json").read_bytes()).hexdigest(),
                "--format",
                "json",
            ],
        )
        expected = [
            ("fixture-llvm", "llvm-rv32", "llvm-lock.json", "llvm-profiles.json"),
            ("fixture-gnu", "gnu-rv32", "gnu-lock.json", "gnu-profiles.json"),
            ("fixture-llvm", "llvm-rv64", "llvm-lock.json", "llvm-profiles.json"),
        ]
        for index, (record, (group_id, profile, lock, profiles)) in enumerate(zip(calls[1:], expected), start=1):
            self.assertEqual(
                record["argv"],
                [
                    "toolchain",
                    "producer",
                    "host-preflight",
                    "--source-lock",
                    str(fixture.inputs / lock),
                    "--profiles",
                    str(fixture.inputs / profiles),
                    "--preset",
                    profile,
                    "--host",
                    "macos-aarch64",
                    "--cache-dir",
                    str(fixture.cache),
                    "--python-env-dir",
                    str(fixture.output / f"python-{index}"),
                ],
            )
            lane = summary["selected_lanes"][index - 1]
            self.assertEqual(lane["group_id"], group_id)
            self.assertEqual(lane["status"], "passed")
            report_path = fixture.output / f"report-{index}.json"
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(report["host_preflight"]["profile"], profile)
            self.assertTrue((fixture.output / f"stderr-{index}.log").is_file())
            self.assertEqual(stat.S_IMODE(report_path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE((fixture.output / f"stderr-{index}.log").stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE((fixture.output / f"python-{index}").stat().st_mode), 0o700)
        self.assertTrue((fixture.output / "validated-plan.json").is_file())
        self.assertFalse((fixture.output / "plan.stdout.log").exists())
        self.assertTrue((fixture.output / "plan.stderr.log").is_file())
        self.assertEqual(stat.S_IMODE(fixture.output.stat().st_mode), 0o700)
        self.assertNotIn("fixture-secret-token", result.stdout + result.stderr)

    def test_waits_for_cli_exit_after_both_streams_close(self) -> None:
        fixture = self.make_fixture()
        fixture.behavior["close_streams_before_exit"] = True
        fixture.behavior["close_delay"] = 0.1
        fixture.write_configuration()

        result = fixture.invoke()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(fixture.summary()["status"], "passed")

    def test_requested_host_absent_from_selected_matrix_fails_without_probe_calls(self) -> None:
        fixture = self.make_fixture()
        result = fixture.invoke(host="linux-aarch64")

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(fixture.summary()["failed_step"], "selected-matrix")
        self.assertEqual(fixture.summary()["selected_lanes"], [])
        self.assertEqual(len(fixture.call_records()), 1)
        self.assertTrue((fixture.output / "plan.stdout.log").is_file())
        self.assertFalse((fixture.output / "validated-plan.json").exists())

    def test_rejects_missing_and_ambiguous_groups_and_duplicate_lanes(self) -> None:
        cases = []
        missing = self.make_fixture()
        missing.lanes[0]["group_id"] = "not-in-groups"
        missing.write_configuration()
        cases.append(missing)

        ambiguous_root = self.root / "ambiguous"
        ambiguous_root.mkdir()
        ambiguous = NativeHostPreflightFixture(ambiguous_root)
        ambiguous.groups.append(dict(ambiguous.groups[0]))
        ambiguous.write_configuration()
        cases.append(ambiguous)

        duplicate_root = self.root / "duplicate"
        duplicate_root.mkdir()
        duplicate = NativeHostPreflightFixture(duplicate_root)
        duplicate.lanes.append(dict(duplicate.lanes[0]))
        duplicate.write_configuration()
        cases.append(duplicate)

        for fixture in cases:
            with self.subTest(root=fixture.root.name):
                result = fixture.invoke()
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(fixture.summary()["status"], "failed")
                self.assertEqual(len(fixture.call_records()), 1)

    def test_selected_matrix_subset_limits_host_preflights(self) -> None:
        fixture = self.make_fixture()
        selected = fixture.selected_matrix(fixture.matrix_lanes[:2])
        result = fixture.invoke(selected_matrix=selected)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            [lane["target_profile"] for lane in fixture.summary()["selected_lanes"]],
            ["llvm-rv32"],
        )
        self.assertEqual(len(fixture.call_records()), 2)

    def test_selected_matrix_lane_omitted_by_plan_fails_before_any_probe(self) -> None:
        fixture = self.make_fixture()
        plan = fixture.plan()
        plan["lanes"] = [lane for lane in plan["lanes"] if lane["target_profile"] != "gnu-rv32"]
        plan["lane_count"] = len(plan["lanes"])
        fixture.write_configuration(plan=plan)

        result = fixture.invoke()

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(fixture.summary()["failed_step"], "release-plan")
        self.assertEqual(len(fixture.call_records()), 1)

    def test_wrong_runtime_sha_fails_before_cli_invocation(self) -> None:
        fixture = self.make_fixture()
        result = fixture.invoke(aros_sha256="0" * 64)

        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(fixture.output.exists())
        self.assertEqual(fixture.call_records(), [])

    def test_rejects_path_traversal_from_plan(self) -> None:
        fixture = self.make_fixture()
        plan = fixture.plan()
        plan["groups"][0]["source_lock"]["file"] = "../outside-lock.json"
        fixture.write_configuration(plan=plan)

        result = fixture.invoke()

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(fixture.summary()["failed_step"], "release-plan")
        self.assertEqual(len(fixture.call_records()), 1)
        self.assertFalse((fixture.output / "validated-plan.json").exists())

    def test_cli_nonzero_retains_bounded_stdout_and_stderr(self) -> None:
        fixture = self.make_fixture()
        fixture.behavior["plan_exit"] = 17
        fixture.write_configuration()

        result = fixture.invoke()

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(fixture.summary()["failed_step"], "release-plan")
        self.assertIn("plan stdout diagnostic", (fixture.output / "plan.stdout.log").read_text())
        self.assertIn("plan stderr diagnostic", (fixture.output / "plan.stderr.log").read_text())
        self.assertLessEqual((fixture.output / "plan.stdout.log").stat().st_size, MAX_LOG_BYTES)
        self.assertLessEqual((fixture.output / "plan.stderr.log").stat().st_size, MAX_LOG_BYTES)

    def test_probe_rejection_retains_both_streams_and_marks_lane_failed(self) -> None:
        fixture = self.make_fixture()
        fixture.behavior["probe_exit"] = 23
        fixture.write_configuration()

        result = fixture.invoke()

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(fixture.summary()["failed_step"], "host-preflight-1")
        self.assertEqual(fixture.summary()["selected_lanes"][0]["status"], "failed")
        self.assertIn("probe stdout diagnostic", (fixture.output / "stdout-1.log").read_text())
        self.assertIn("probe stderr diagnostic", (fixture.output / "stderr-1.log").read_text())
        self.assertFalse((fixture.output / "report-1.json").exists())

    def test_oversized_child_stdout_is_capped(self) -> None:
        fixture = self.make_fixture()
        fixture.behavior["oversized_probe"] = True
        fixture.write_configuration()

        result = fixture.invoke()

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(fixture.summary()["failed_step"], "host-preflight-1")
        self.assertEqual((fixture.output / "stdout-1.log").stat().st_size, MAX_LOG_BYTES)
        self.assertLessEqual((fixture.output / "stderr-1.log").stat().st_size, MAX_LOG_BYTES)

    def test_input_mutation_during_release_plan_is_rejected(self) -> None:
        fixture = self.make_fixture()
        fixture.behavior["mutate_input_on_plan"] = True
        fixture.write_configuration()

        result = fixture.invoke()

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(fixture.summary()["failed_step"], "input-integrity")
        self.assertEqual(len(fixture.call_records()), 1)
        self.assertTrue((fixture.output / "plan.stdout.log").is_file())
        self.assertFalse((fixture.output / "validated-plan.json").exists())

    def test_input_mutation_during_host_preflight_is_rejected(self) -> None:
        fixture = self.make_fixture()
        fixture.behavior["mutate_input_on_probe"] = True
        fixture.write_configuration()

        result = fixture.invoke()

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(fixture.summary()["failed_step"], "input-integrity")
        self.assertEqual(fixture.summary()["selected_lanes"][0]["status"], "failed")
        self.assertTrue((fixture.output / "stdout-1.log").is_file())
        self.assertTrue((fixture.output / "stderr-1.log").is_file())
        self.assertFalse((fixture.output / "report-1.json").exists())

    def test_existing_or_overlapping_output_is_rejected(self) -> None:
        fixture = self.make_fixture()
        fixture.output.mkdir()
        marker = fixture.output / "keep.txt"
        marker.write_text("preserve", encoding="utf-8")
        result = fixture.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(marker.read_text(encoding="utf-8"), "preserve")
        self.assertEqual(fixture.call_records(), [])

        second_root = self.root / "overlap-case"
        second_root.mkdir()
        overlapping = NativeHostPreflightFixture(second_root)
        overlap_output = overlapping.inputs / "new-output"
        result = overlapping.invoke(output=overlap_output)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(overlap_output.exists())
        self.assertEqual(overlapping.call_records(), [])


if __name__ == "__main__":
    unittest.main()
