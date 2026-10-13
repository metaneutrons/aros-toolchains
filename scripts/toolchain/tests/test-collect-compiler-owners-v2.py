"""Process-boundary tests for the authenticated compiler-owner collector.

The Bash wrapper, selector, jq, and shell utilities are real. The native CLI,
owner matrix, artifact selection, owner reader, and transport remeasurement are
subprocess fixtures. These tests do not establish provider authentication,
native compiler execution, package qualification, release admission, or
publication.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "collect-compiler-owners-v2.sh"
SOURCE_WORKFLOW = ".github/workflows/native-compiler.yml"
WORKFLOW = ".github/workflows/collect-compiler-owners.yml"
SOURCE_REF = "refs/heads/main"
PRODUCER = "a" * 40
TOOLS = "b" * 40
RELEASE_ID = "r2026.10"
HOSTS = ("linux-aarch64", "linux-x86_64", "macos-aarch64")
LANES = (("group-alpha", "alpha-one"), ("group-alpha", "alpha-two"),
         ("group-beta", "beta-one"), ("group-beta", "beta-two"))


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def owner_id(group: str, host: str, profile: str, copy: str) -> str:
    raw = b"\0".join(item.encode() for item in (group, host, profile, copy)) + b"\0"
    return sha256(raw)


FAKE_AROS = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

args = sys.argv[1:]
with open(os.environ["FAKE_LOG"], "a", encoding="utf-8") as stream:
    stream.write(json.dumps({"stage": "aros", "args": args}, separators=(",", ":")) + "\n")
if args[:3] != ["toolchain", "producer", "release-plan"]:
    raise SystemExit("unexpected fake AROS invocation")
if os.environ.get("FAKE_AROS_FAIL") == "1":
    raise SystemExit(41)
sys.stdout.buffer.write(Path(os.environ["FAKE_PLAN_FILE"]).read_bytes())
'''


FAKE_MATRIX = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

args = sys.argv[1:]
with open(os.environ["FAKE_LOG"], "a", encoding="utf-8") as stream:
    stream.write(json.dumps({"stage": "matrix", "args": args}, separators=(",", ":")) + "\n")
if os.environ.get("FAKE_MATRIX_FAIL") == "1":
    raise SystemExit(42)
value = json.loads(Path(os.environ["FAKE_MATRIX_FILE"]).read_text(encoding="utf-8"))
value["plan_sha256"] = args[args.index("--plan-sha256") + 1]
mode = os.environ.get("FAKE_MATRIX_MODE")
if mode == "wrong-schema":
    value["schema"] = "aros-compiler-owner-matrix-unqualified-v2"
elif mode == "missing-owner":
    value["owners"].pop()
elif mode == "duplicate-owner":
    value["owners"].append(dict(value["owners"][0]))
sys.stdout.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
'''


FAKE_SELECTOR = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

args = sys.argv[1:]
def option(name):
    return args[args.index(name) + 1]
context_path = Path(option("--source-context"))
context = json.loads(context_path.read_text(encoding="utf-8"))
selection = {"role": option("--role"), "group": option("--group"),
             "host": option("--host"), "profile": option("--profile"),
             "copy": option("--copy")}
with open(os.environ["FAKE_LOG"], "a", encoding="utf-8") as stream:
    stream.write(json.dumps({"stage": "selector", "args": args}, separators=(",", ":")) + "\n")
mode = os.environ.get("FAKE_SELECTOR_MODE")
if mode == "fail":
    raise SystemExit(43)
if mode == "copy-swap":
    selection["copy"] = "b" if selection["copy"] == "a" else "a"
matrix = json.loads(Path(os.environ["FAKE_MATRIX_FILE"]).read_text(encoding="utf-8"))
job_name = option("--job-name")
index = next(i for i, owner in enumerate(matrix["owners"]) if owner["job_name"] == job_name)
result = {
    "schema": "aros-toolchain-artifact-selection-v1", "context": context,
    "selection": selection,
    "job": {"id": 1000 + index, "name": job_name},
    "artifact": {"id": 2000 + index, "name": option("--payload-name")},
    "proof": {"id": 3000 + index, "name": option("--proof-name")},
}
sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
if mode == "change-context":
    with context_path.open("ab") as stream:
        stream.write(b" \n")
'''


FAKE_READER = r'''#!/usr/bin/env bash
set -euo pipefail
python3 - "$@" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import sys

args = sys.argv[1:]
def option(name):
    return args[args.index(name) + 1]
def record(stage):
    with open(os.environ["FAKE_LOG"], "a", encoding="utf-8") as stream:
        stream.write(json.dumps({"stage": stage, "args": args}, separators=(",", ":")) + "\n")
def sha(raw):
    return hashlib.sha256(raw).hexdigest()

selection_path = Path(option("--source-selection"))
selection = json.loads(selection_path.read_text(encoding="utf-8"))
mode = os.environ.get("FAKE_READER_MODE")
record("reader")
if mode in ("auth-fail", "native-bad-result"):
    raise SystemExit(44)
root = Path(option("--root"))
payload = root / "payload"
package = payload / "package"
evidence = payload / "evidence"
transport_dir = root / "transport"
for directory in (package, evidence, transport_dir):
    directory.mkdir(parents=True)
measurement = evidence / "measurement.json"
environment = evidence / "environment.json"
measurement.write_bytes(b'{"original":"authenticated measurement bytes"}\n')
environment.write_bytes(b'{"original":"authenticated environment bytes"}\n')
(transport_dir / "payload.index").write_bytes(b"synthetic retained original-owner bytes\n")
transport = {
    "schema": "aros-toolchain-native-lane-transport-v2",
    "assurance": "transport-byte-readback-only",
    "files": {"payload.index": {
        "sha256": sha((transport_dir / "payload.index").read_bytes()),
        "size": (transport_dir / "payload.index").stat().st_size,
    }},
}
(root / "transport-result.json").write_text(
    json.dumps(transport, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")

source_selection_sha = sha(selection_path.read_bytes())
environment_sha = sha(environment.read_bytes())
measurement_sha = sha(measurement.read_bytes())
observation = {
    "schema": "aros-toolchain-original-owner-observation-v2",
    "assurance": "authenticated-original-job-and-native-byte-readback-only",
    "scope": {"original_owner_job_observation": True, "native_package_byte_readback": True,
              "independently_executed_collector": False, "release_admission": False,
              "publication": False},
    "current_workflow": option("--workflow"), "current_job_name": option("--job-name"),
    "source_workflow": option("--source-workflow"), "source_ref": option("--source-ref"),
    "group": option("--group"), "host": option("--host"),
    "target_profile": option("--preset"), "copy": option("--copy"),
    "release_id": option("--release-id"), "reader_runtime_sha256": option("--aros-sha256"),
    "recipe_file_sha256": option("--recipe-file-sha256"),
    "source_lock_sha256": option("--source-lock-sha256"),
    "profiles_sha256": option("--profiles-sha256"),
    "source_selection_sha256": source_selection_sha,
    "build_result_sha256": "1" * 64, "environment_sha256": environment_sha,
    "measurement_sha256": measurement_sha,
    "executor_contract_id": "aros-toolchain-producer-v1",
    "executor_contract_sha256": "2" * 64, "executor_binary_sha256": "3" * 64,
    "original_identity": {"recipe_self_sha256": "4" * 64,
                          "source_commit": "5" * 40, "producer_commit": "a" * 40,
                          "tools_commit": "b" * 40, "host": option("--host"),
                          "target_profile": option("--preset")},
    "transport": transport, "native": {"fixture": "native reader output"},
}
if mode == "current-owner":
    observation["current_job_name"] = "unexpected owner"
elif mode == "bad-observation":
    observation["release_id"] = "wrong-release"
(root / "observation.json").write_text(
    json.dumps(observation, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")

if mode in ("change-runtime", "change-reference", "mutate-prior-selection", "mutate-prior-observation"):
    log_path = Path(os.environ["FAKE_LOG"])
    events = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    if mode == "change-runtime":
        path = Path(os.environ["FAKE_RUNTIME_FILE"])
        with path.open("ab") as stream:
            stream.write(b"runtime changed during owner readback\n")
    elif mode == "change-reference":
        path = Path(option("--recipe"))
        with path.open("ab") as stream:
            stream.write(b"reference changed during owner readback\n")
    elif sum(event["stage"] == "reader" for event in events) == 2:
        first_reader = next(event for event in events if event["stage"] == "reader")
        first_args = first_reader["args"]
        if mode == "mutate-prior-selection":
            path = Path(first_args[first_args.index("--source-selection") + 1])
        else:
            first_root = Path(first_args[first_args.index("--root") + 1])
            path = first_root / "observation.json"
        with path.open("ab") as stream:
            stream.write(b" \n")
PY
'''


FAKE_TRANSPORT = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

args = sys.argv[1:]
def option(name):
    return args[args.index(name) + 1]
with open(os.environ["FAKE_LOG"], "a", encoding="utf-8") as stream:
    stream.write(json.dumps({"stage": "transport", "args": args}, separators=(",", ":")) + "\n")
retained = Path(option("--retained-dir"))
root = retained.parent
value = json.loads((root / "transport-result.json").read_text(encoding="utf-8"))
if os.environ.get("FAKE_TRANSPORT_MODE") == "changed-reverification":
    value["files"]["payload.index"]["sha256"] = "f" * 64
sys.stdout.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
if os.environ.get("FAKE_TRANSPORT_MODE") == "mutate-prior-transport":
    log_path = Path(os.environ["FAKE_LOG"])
    events = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    if sum(event["stage"] == "transport" for event in events) == 24:
        first = next(event for event in events if event["stage"] == "transport")
        first_root = Path(first["args"][first["args"].index("--retained-dir") + 1]).parent
        with (first_root / "transport-result.json").open("ab") as stream:
            stream.write(b" \n")
'''


class CollectCompilerOwnersProcessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        for program in ("jq", "shasum", "python3", "bash"):
            if not shutil.which(program):
                raise RuntimeError(f"process tests require {program}")

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="collect-compiler-owners-v2-")
        self.base = Path(self.temporary.name).resolve()
        self.wrapper_dir = self.base / "scripts" / "toolchain"
        self.wrapper_dir.mkdir(parents=True)
        self.script = self.wrapper_dir / SCRIPT.name
        shutil.copy2(SCRIPT, self.script)
        shutil.copy2(SCRIPT.with_name("artifact-origin.py"), self.wrapper_dir / "artifact-origin.py")
        self._write(self.wrapper_dir / "compiler-owner-matrix-v2.py", FAKE_MATRIX, executable=True)
        self._write(self.wrapper_dir / "select-owner-artifacts-v2.py", FAKE_SELECTOR, executable=True)
        self._write(self.wrapper_dir / "read-native-owner-v2.sh", FAKE_READER, executable=True)
        self._write(self.wrapper_dir / "native-lane-transport.py", FAKE_TRANSPORT, executable=True)
        self.log = self.base / "calls.jsonl"
        self.runtime = self.base / "bin" / "aros-fixture"
        self.runtime.parent.mkdir()
        self._write(self.runtime, FAKE_AROS, executable=True)
        self.inputs = self.base / "inputs"
        self.inputs.mkdir()
        self.collection = self.inputs / "toolchain-release-inputs-v2.json"
        self.collection.write_bytes(b'{"fixture":"compiler release inputs"}\n')
        self.references: dict[str, dict[str, dict[str, str]]] = {}
        for group in ("group-alpha", "group-beta"):
            self.references[group] = {}
            for kind in ("recipe", "source_lock", "profiles"):
                filename = f"{group}-{kind}.json"
                raw = canonical_json({"fixture": filename})
                (self.inputs / filename).write_bytes(raw)
                self.references[group][kind] = {"file": filename, "sha256": sha256(raw)}
        self.context = self.base / "source-context.json"
        self.context.write_bytes(canonical_json({
            "repository": "example/aros", "repository_id": 987,
            "producer_commit": PRODUCER, "source_ref": SOURCE_REF,
            "workflow": SOURCE_WORKFLOW, "run_id": 321, "run_attempt": 2,
        }))
        self.plan = self.base / "plan.json"
        self.plan.write_bytes(b'{"fixture":"native release plan"}\n')
        self.matrix_file = self.base / "matrix.json"
        self.matrix_file.write_bytes(canonical_json(self.matrix()))
        self.operations = self.base / "operations"
        self.operations.mkdir()
        self.root = self.operations / "collection"
        self.env = os.environ.copy()
        self.env.update({
            "FAKE_LOG": str(self.log), "FAKE_PLAN_FILE": str(self.plan),
            "FAKE_MATRIX_FILE": str(self.matrix_file), "FAKE_RUNTIME_FILE": str(self.runtime),
        })

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _write(path: Path, contents: str, *, executable: bool = False) -> None:
        path.write_text(contents, encoding="utf-8")
        if executable:
            path.chmod(0o755)

    def matrix(self) -> dict:
        owners = []
        lanes = []
        for group, profile in LANES:
            refs = self.references[group]
            for host in HOSTS:
                lane = {"group_id": group, "host": host, "target_profile": profile}
                lanes.append(lane)
                for copy in ("a", "b"):
                    identity = owner_id(group, host, profile, copy)
                    owners.append({
                        "owner_id": identity, "group_id": group, "host": host,
                        "profile": profile, "copy": copy,
                        "job_name": f"Native compiler ({group}, {host}, {profile}, {copy})",
                        "payload_name": f"native-v2-{identity}-321-2",
                        "proof_name": f"native-v2-proof-{identity}-321-2",
                        "recipe": refs["recipe"], "source_lock": refs["source_lock"],
                        "profiles": refs["profiles"],
                    })
        owners.sort(key=lambda row: (row["group_id"], row["host"], row["profile"], row["copy"]))
        lanes.sort(key=lambda row: (row["group_id"], row["host"], row["target_profile"]))
        return {
            "schema": "aros-compiler-owner-matrix-v2", "assurance": "owner-selection-only",
            "plan_sha256": "1" * 64,
            "inputs_sha256": sha256(self.collection.read_bytes()),
            "source_context_sha256": sha256(self.context.read_bytes()),
            "producer_commit": PRODUCER, "tools_commit": TOOLS,
            "owners": owners, "expected_compiler_lanes": lanes,
        }

    def arguments(self) -> list[str]:
        return [
            "--aros", str(self.runtime), "--aros-sha256", sha256(self.runtime.read_bytes()),
            "--inputs-dir", str(self.inputs), "--inputs-sha256", sha256(self.collection.read_bytes()),
            "--producer-commit", PRODUCER, "--tools-commit", TOOLS,
            "--source-context", str(self.context), "--source-context-sha256", sha256(self.context.read_bytes()),
            "--source-workflow", SOURCE_WORKFLOW, "--source-ref", SOURCE_REF,
            "--workflow", WORKFLOW, "--job-name", "Compiler owner collection",
            "--release-id", RELEASE_ID,
            "--forbidden-prefix", "/tmp/forbidden-build-root",
            "--root", str(self.root),
        ]

    def run_wrapper(self, extra: list[str] | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["/bin/bash", str(self.script), *self.arguments(), *(extra or [])],
                              capture_output=True, text=True, check=False, env=self.env)

    def stages(self) -> list[dict]:
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]

    def assert_no_fragment(self, result: subprocess.CompletedProcess[str]) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse((self.root / "selection-fragment.json").exists())

    def test_complete_24_owner_collection_preserves_full_dtos_for_three_hosts(self) -> None:
        result = self.run_wrapper(["--same-attempt", "--forbidden-prefix", "/var/forbidden"])
        self.assertEqual(result.returncode, 0, result.stderr)
        fragment = json.loads((self.root / "selection-fragment.json").read_text(encoding="utf-8"))
        self.assertEqual(fragment["schema"], "aros-compiler-build-selection-fragment-v2")
        self.assertEqual(fragment["assurance"], "authenticated-original-owner-selection-only")
        self.assertEqual(fragment["owner_count"], 24)
        self.assertEqual(len(fragment["expected_compiler_lanes"]), 12)
        self.assertEqual(len(fragment["compiler_builds"]), 24)
        self.assertEqual({row["host"] for row in fragment["compiler_builds"]}, set(HOSTS))
        self.assertEqual({row["copy"] for row in fragment["compiler_builds"]}, {"a", "b"})
        self.assertEqual(fragment["expected_compiler_lanes"], self.matrix()["expected_compiler_lanes"])
        for row in fragment["compiler_builds"]:
            self.assertEqual(set(row), {
                "group_id", "host", "target_profile", "copy", "package_dir", "measurement",
                "executor", "environment", "observation",
            })
            self.assertEqual(set(row["measurement"]), {"path", "sha256"})
            self.assertEqual(set(row["environment"]), {"path", "sha256"})
            self.assertEqual(set(row["executor"]), {"contract_sha256", "binary_sha256"})
            self.assertEqual(set(row["observation"]), {"path", "sha256"})
            self.assertTrue(row["package_dir"].startswith(str(self.root / "owners")))
            self.assertTrue(row["measurement"]["path"].endswith("/payload/evidence/measurement.json"))
            self.assertTrue(row["environment"]["path"].endswith("/payload/evidence/environment.json"))
            self.assertTrue(row["observation"]["path"].endswith("/readback/observation.json"))
            self.assertRegex(row["measurement"]["sha256"], r"^[0-9a-f]{64}$")
            self.assertRegex(row["environment"]["sha256"], r"^[0-9a-f]{64}$")
            self.assertRegex(row["observation"]["sha256"], r"^[0-9a-f]{64}$")
        self.assertIs(fragment["release_admission"], False)
        self.assertIs(fragment["publication"], False)
        stages = self.stages()
        self.assertEqual([entry["stage"] for entry in stages[:2]], ["aros", "matrix"])
        self.assertEqual(sum(entry["stage"] == "selector" for entry in stages), 24)
        readers = [entry for entry in stages if entry["stage"] == "reader"]
        self.assertEqual(len(readers), 24)
        self.assertTrue(all("--same-attempt" in entry["args"] for entry in readers))
        self.assertEqual(sum(entry["stage"] == "transport" for entry in stages), 24)
        self.assertEqual(list(self.operations.glob(".compiler-owner-collection-v2.*")), [])

    def test_invalid_collection_stops_before_cli_or_root(self) -> None:
        arguments = self.arguments()
        arguments[arguments.index("--inputs-sha256") + 1] = "f" * 64
        result = subprocess.run(["/bin/bash", str(self.script), *arguments], capture_output=True,
                                text=True, check=False, env=self.env)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.stages(), [])
        self.assertFalse(self.root.exists())

    def test_invalid_cli_duplicate_release_and_missing_prefix_stop_before_cli(self) -> None:
        cases = (
            ["--workflow", WORKFLOW],
            ["--release-id", "../bad"],
        )
        for extra in cases:
            with self.subTest(extra=extra):
                self.tearDown(); self.setUp()
                result = self.run_wrapper(extra)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.stages(), [])
                self.assertFalse(self.root.exists())
        self.tearDown(); self.setUp()
        args = self.arguments()
        del args[args.index("--forbidden-prefix") : args.index("--forbidden-prefix") + 2]
        result = subprocess.run(["/bin/bash", str(self.script), *args], capture_output=True,
                                text=True, check=False, env=self.env)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.stages(), [])
        self.assertFalse(self.root.exists())

    def test_matrix_missing_duplicate_or_wrong_schema_is_rejected_before_root(self) -> None:
        for mode in ("missing-owner", "duplicate-owner", "wrong-schema"):
            with self.subTest(mode=mode):
                self.tearDown(); self.setUp()
                self.env["FAKE_MATRIX_MODE"] = mode
                result = self.run_wrapper()
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual([item["stage"] for item in self.stages()], ["aros", "matrix"])
                self.assertFalse(self.root.exists())

    def test_native_authentication_failure_stops_without_fragment(self) -> None:
        self.env["FAKE_READER_MODE"] = "auth-fail"
        result = self.run_wrapper()
        self.assert_no_fragment(result)
        self.assertEqual(sum(item["stage"] == "reader" for item in self.stages()), 1)
        self.assertEqual(sum(item["stage"] == "transport" for item in self.stages()), 0)

    def test_selector_copy_swap_is_rejected_without_fragment(self) -> None:
        self.env["FAKE_SELECTOR_MODE"] = "copy-swap"
        result = self.run_wrapper()
        self.assert_no_fragment(result)
        self.assertEqual(sum(item["stage"] == "reader" for item in self.stages()), 0)

    def test_current_owner_and_native_bad_result_are_rejected(self) -> None:
        for mode in ("current-owner", "native-bad-result", "bad-observation"):
            with self.subTest(mode=mode):
                self.tearDown(); self.setUp()
                self.env["FAKE_READER_MODE"] = mode
                result = self.run_wrapper()
                self.assert_no_fragment(result)
                self.assertEqual(sum(item["stage"] == "transport" for item in self.stages()), 0)

    def test_changed_plan_bound_reference_is_rejected(self) -> None:
        self.env["FAKE_READER_MODE"] = "change-reference"
        result = self.run_wrapper()
        self.assert_no_fragment(result)
        self.assertIn("reference changed", result.stderr)

    def test_runtime_and_context_changes_are_rejected(self) -> None:
        self.env["FAKE_READER_MODE"] = "change-runtime"
        result = self.run_wrapper()
        self.assert_no_fragment(result)
        self.assertIn("runtime changed", result.stderr)
        self.tearDown(); self.setUp()
        self.env["FAKE_SELECTOR_MODE"] = "change-context"
        result = self.run_wrapper()
        self.assert_no_fragment(result)
        self.assertIn("source context changed", result.stderr)

    def test_later_owner_mutations_of_prior_selection_observation_and_transport_are_rejected(self) -> None:
        cases = (
            ("mutate-prior-selection", None,
             "original owner selection changed before fragment generation", 24),
            ("mutate-prior-observation", None,
             "original owner observation changed before fragment generation", 24),
            (None, "mutate-prior-transport",
             "original owner transport result changed before fragment generation", 24),
        )
        for reader_mode, transport_mode, message, transport_count in cases:
            with self.subTest(reader_mode=reader_mode, transport_mode=transport_mode):
                self.tearDown(); self.setUp()
                if reader_mode:
                    self.env["FAKE_READER_MODE"] = reader_mode
                if transport_mode:
                    self.env["FAKE_TRANSPORT_MODE"] = transport_mode
                result = self.run_wrapper()
                self.assert_no_fragment(result)
                self.assertIn(message, result.stderr)
                self.assertEqual(sum(item["stage"] == "reader" for item in self.stages()), 24)
                self.assertEqual(sum(item["stage"] == "transport" for item in self.stages()), transport_count)

    def test_reverification_mismatch_is_rejected_without_fragment(self) -> None:
        self.env["FAKE_TRANSPORT_MODE"] = "changed-reverification"
        result = self.run_wrapper()
        self.assert_no_fragment(result)
        self.assertEqual(sum(item["stage"] == "transport" for item in self.stages()), 1)


if __name__ == "__main__":
    unittest.main()
