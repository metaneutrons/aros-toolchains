"""Bounded process tests for the metadata-only SDK-owner collector adapter.

The wrapper and shell tools are real. Native AROS, owner-matrix derivation,
provider selection, owner reads, and transport remeasurement are subprocess
fixtures; these tests make no native qualification or provider-authentication
claim.
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


SCRIPT = Path(__file__).resolve().parents[1] / "collect-sdk-owners-v2.sh"
SOURCE_WORKFLOW = ".github/workflows/sdk-owner.yml"
WORKFLOW = ".github/workflows/collect-sdk-owners.yml"
SOURCE_REF = "refs/heads/main"
PRODUCER = "a" * 40
TOOLS = "b" * 40
HOSTS = ("linux-aarch64", "linux-x86_64", "macos-aarch64")
SDK_IDS = ("sdk-a", "sdk-b", "sdk-c", "sdk-d")


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


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
    value["schema"] = "aros-sdk-owner-matrix-unqualified-v2"
elif mode == "wrong-digest":
    value["inputs_sha256"] = "f" * 64
sys.stdout.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
'''


FAKE_SELECTOR = r'''#!/usr/bin/env python3
import hashlib
import json
import os
from pathlib import Path
import sys

args = sys.argv[1:]
def option(name):
    return args[args.index(name) + 1]
context_path = Path(option("--source-context"))
context = json.loads(context_path.read_text(encoding="utf-8"))
selection = {
    "role": option("--role"), "group": option("--group"), "host": option("--host"),
    "profile": option("--profile"), "copy": option("--copy"),
}
row = {"stage": "selector", "args": args}
with open(os.environ["FAKE_LOG"], "a", encoding="utf-8") as stream:
    stream.write(json.dumps(row, separators=(",", ":")) + "\n")
if os.environ.get("FAKE_SELECTOR_MODE") == "fail":
    raise SystemExit(43)
if os.environ.get("FAKE_SELECTOR_MODE") == "wrong-selection":
    selection["copy"] = "a"
result = {
    "schema": "aros-toolchain-artifact-selection-v1", "context": context,
    "selection": selection, "job": {"id": 101, "name": option("--job-name")},
    "artifact": {"id": 201, "name": option("--payload-name")},
    "proof": {"id": 202, "name": option("--proof-name")},
}
sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
if os.environ.get("FAKE_SELECTOR_MODE") == "change-context":
    with context_path.open("ab") as stream:
        stream.write(b"changed after selection\n")
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

selection_path = Path(option("--source-selection"))
selection = json.loads(selection_path.read_text(encoding="utf-8"))
mode = os.environ.get("FAKE_READER_MODE")
record("reader")
if mode == "auth-fail":
    raise SystemExit(44)
root = Path(option("--root"))
payload = root / "payload"
payload.mkdir(parents=True)
(root / "transport").mkdir()
sdk_ids = json.loads(option("--sdk-ids"))
group, host = option("--group"), option("--host")
profile, family = option("--preset"), option("--compiler-family")
selection_sha = hashlib.sha256(selection_path.read_bytes()).hexdigest()
generations = []
for sdk_id in sdk_ids:
    product = payload / ("sdk-" + sdk_id)
    for relative in ("package", "compatibility"):
        (product / relative).mkdir(parents=True)
    (product / "generation.json").write_text("{}\n", encoding="utf-8")
    (product / "compatibility-inputs.json").write_text("{}\n", encoding="utf-8")
    generations.append({
        "sdk_id": sdk_id, "group_id": group, "target_profile": profile, "host": host,
        "package_dir": str(product / "package"),
        "record": {"path": str(product / "generation.json"), "sha256": "c" * 64},
        "compatibility": {
            "directory": str(product / "compatibility"),
            "inputs": {"path": str(product / "compatibility-inputs.json"), "sha256": "d" * 64},
            "manifest_sha256": "e" * 64, "native_sdk_required": family == "gnu",
        },
    })
if mode == "missing-tuple":
    generations.pop()
elif mode == "duplicate-tuple":
    generations.append(dict(generations[0]))
elif mode == "changed-tuple":
    generations[0]["host"] = "wrong-host"
elif mode == "swapped-tuple":
    generations[0]["sdk_id"] = "sdk-b" if generations[0]["sdk_id"] == "sdk-a" else "sdk-a"
transport = {
    "schema": "aros-sdk-owner-transport-v2", "assurance": "transport-byte-readback-only",
    "owner_role": "sdk", "selection_sha256": selection_sha,
    "origin_sha256": "a" * 64, "raw_zip_sha256": "b" * 64,
    "sdk_generations": generations,
}
(root / "transport-result.json").write_text(
    json.dumps(transport, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
independent = {
    "sdk_ids": sdk_ids, "group": group, "profile": profile, "host": host,
    "compiler_family": family, "owner_role": "sdk",
}
if mode == "current-selector":
    independent["group"] = "wrong-group"
readback = {
    "schema": "aros-sdk-owner-readback-v2",
    "assurance": "authenticated-transport-and-sdk-payload-readback-only",
    "source_workflow": option("--source-workflow"), "source_ref": option("--source-ref"),
    "source_producer_commit": option("--source-producer-commit"),
    "source_selection_sha256": option("--source-selection-sha256"),
    "independent_selection": independent, "sdk_owner_transport": transport,
}
(root / "readback.json").write_text(
    json.dumps(readback, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
if mode in ("mutate-prior-selection", "mutate-prior-readback"):
    log_path = Path(os.environ["FAKE_LOG"])
    events = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    if sum(event["stage"] == "reader" for event in events) == 2:
        first_reader = next(event for event in events if event["stage"] == "reader")
        first_root = Path(first_reader["args"][first_reader["args"].index("--root") + 1])
        target = (first_root.parent / "selection.json" if mode == "mutate-prior-selection"
                  else first_root / "readback.json")
        with target.open("ab") as stream:
            stream.write(b" \n")
if mode == "change-runtime":
    runtime = Path(os.environ["FAKE_RUNTIME_FILE"])
    runtime.write_bytes(runtime.read_bytes() + b"changed during readback\n")
if mode == "change-matrix":
    matrix = Path(option("--root")).parent.parent.parent / "matrix.json"
    with matrix.open("ab") as stream:
        stream.write(b" ")
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
root = Path(option("--retained-dir")).parent
value = json.loads((root / "transport-result.json").read_text(encoding="utf-8"))
mode = os.environ.get("FAKE_TRANSPORT_MODE")
if mode == "changed-reverification":
    value["sdk_generations"][0]["group_id"] = "changed-group"
sys.stdout.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
if mode == "mutate-prior-transport-result":
    log_path = Path(os.environ["FAKE_LOG"])
    events = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    if sum(event["stage"] == "transport" for event in events) == 12:
        earlier = [event for event in events if event["stage"] == "transport"][0]
        earlier_root = Path(earlier["args"][earlier["args"].index("--retained-dir") + 1]).parent
        with (earlier_root / "transport-result.json").open("ab") as stream:
            stream.write(b" \n")
'''


class CollectSdkOwnersProcessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        for program in ("jq", "shasum", "python3", "bash"):
            if not shutil.which(program):
                raise RuntimeError(f"process tests require {program}")

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="collect-sdk-owners-v2-")
        self.base = Path(self.temporary.name).resolve()
        self.wrapper_dir = self.base / "scripts" / "toolchain"
        self.wrapper_dir.mkdir(parents=True)
        self.script = self.wrapper_dir / SCRIPT.name
        shutil.copy2(SCRIPT, self.script)
        shutil.copy2(SCRIPT.with_name("artifact-origin.py"), self.wrapper_dir / "artifact-origin.py")
        self._write(self.wrapper_dir / "sdk-owner-matrix-v2.py", FAKE_MATRIX, executable=True)
        self._write(self.wrapper_dir / "select-owner-artifacts-v2.py", FAKE_SELECTOR, executable=True)
        self._write(self.wrapper_dir / "read-sdk-owner-v2.sh", FAKE_READER, executable=True)
        self._write(self.wrapper_dir / "sdk-owner-transport-v2.py", FAKE_TRANSPORT, executable=True)

        self.log = self.base / "calls.jsonl"
        self.runtime = self.base / "bin" / "aros-fixture"
        self.runtime.parent.mkdir()
        self._write(self.runtime, FAKE_AROS, executable=True)
        self.inputs = self.base / "inputs"
        self.inputs.mkdir()
        self.collection = self.inputs / "toolchain-release-inputs-v2.json"
        self.collection.write_bytes(b'{"fixture":"release inputs"}\n')
        self.context = self.base / "source-context.json"
        self.context.write_bytes(canonical_json({
            "repository": "example/aros-tools", "repository_id": 123,
            "producer_commit": PRODUCER, "source_ref": SOURCE_REF,
            "workflow": SOURCE_WORKFLOW, "run_id": 456, "run_attempt": 1,
        }))
        self.plan = self.base / "plan.json"
        self.plan.write_bytes(b'{"native":"release plan fixture"}\n')
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

    def _write(self, path: Path, content: str, *, executable: bool = False) -> Path:
        path.write_text(content, encoding="utf-8")
        if executable:
            path.chmod(0o755)
        return path

    def matrix(self) -> dict:
        owners = []
        expected = []
        for index, sdk_id in enumerate(SDK_IDS):
            group = f"group-{index}"
            family = "gnu" if index % 2 == 0 else "llvm"
            for host in HOSTS:
                owner_id = sha256(f"{group}/{host}".encode())
                owners.append({
                    "owner_id": owner_id, "group_id": group, "host": host,
                    "profile": "release", "compiler_family": family, "sdk_ids": [sdk_id],
                    "job_name": f"SDK owner {group} {host}",
                    "payload_name": f"payload-{owner_id[:12]}",
                    "proof_name": f"proof-{owner_id[:12]}",
                })
                expected.append({"sdk_id": sdk_id, "group_id": group,
                                 "target_profile": "release", "host": host})
        owners.sort(key=lambda item: (item["group_id"], item["host"]))
        expected.sort(key=lambda item: (item["sdk_id"], item["group_id"],
                                        item["target_profile"], item["host"]))
        return {
            "schema": "aros-sdk-owner-matrix-v2", "assurance": "owner-selection-only",
            "plan_sha256": "1" * 64, "inputs_sha256": sha256(self.collection.read_bytes()),
            "source_context_sha256": sha256(self.context.read_bytes()),
            "producer_commit": PRODUCER, "tools_commit": TOOLS,
            "owners": owners, "expected_sdk_generations": expected,
        }

    def arguments(self) -> list[str]:
        return [
            "--aros", str(self.runtime), "--aros-sha256", sha256(self.runtime.read_bytes()),
            "--inputs-dir", str(self.inputs), "--inputs-sha256", sha256(self.collection.read_bytes()),
            "--producer-commit", PRODUCER, "--tools-commit", TOOLS,
            "--source-context", str(self.context), "--source-context-sha256", sha256(self.context.read_bytes()),
            "--source-workflow", SOURCE_WORKFLOW, "--source-ref", SOURCE_REF,
            "--workflow", WORKFLOW, "--job-name", "SDK owner collection",
            "--root", str(self.root),
        ]

    def run_wrapper(self, extra: list[str] | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["/bin/bash", str(self.script), *self.arguments(), *(extra or [])],
                              capture_output=True, text=True, check=False, env=self.env)

    def stages(self) -> list[dict]:
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]

    def test_complete_three_host_collection_rejoins_all_native_sdk_tuples(self) -> None:
        result = self.run_wrapper(["--same-attempt"])
        self.assertEqual(result.returncode, 0, result.stderr)
        fragment = json.loads((self.root / "selection-fragment.json").read_text(encoding="utf-8"))
        self.assertEqual(fragment["schema"], "aros-sdk-generation-selection-fragment-v2")
        self.assertEqual(fragment["assurance"], "authenticated-owner-transport-selection-only")
        self.assertEqual(fragment["owner_count"], 12)
        self.assertEqual(fragment["sdk_generation_count"], 12)
        self.assertEqual({item["host"] for item in fragment["sdk_generations"]}, set(HOSTS))
        self.assertEqual({item["sdk_id"] for item in fragment["sdk_generations"]}, set(SDK_IDS))
        expected_rows = []
        for owner in self.matrix()["owners"]:
            path = self.root / "owners" / owner["owner_id"] / "readback" / "readback.json"
            readback = json.loads(path.read_text(encoding="utf-8"))
            expected_rows.extend(readback["sdk_owner_transport"]["sdk_generations"])
        expected_rows.sort(key=lambda item: (item["sdk_id"], item["group_id"],
                                             item["target_profile"], item["host"]))
        self.assertEqual(fragment["sdk_generations"], expected_rows)
        self.assertTrue(all(set(row) == {
            "sdk_id", "group_id", "target_profile", "host", "package_dir", "record", "compatibility"
        } for row in fragment["sdk_generations"]))
        self.assertTrue(all(set(row["record"]) == {"path", "sha256"} for row in fragment["sdk_generations"]))
        self.assertTrue(all(set(row["compatibility"]) == {
            "directory", "inputs", "manifest_sha256", "native_sdk_required"
        } and set(row["compatibility"]["inputs"]) == {"path", "sha256"}
            for row in fragment["sdk_generations"]))
        self.assertEqual({owner["compiler_family"] for owner in self.matrix()["owners"]}, {"gnu", "llvm"})
        self.assertIs(fragment["release_admission"], False)
        self.assertIs(fragment["publication"], False)
        stages = self.stages()
        self.assertEqual(stages[0]["stage"], "aros")
        self.assertEqual(stages[1]["stage"], "matrix")
        self.assertEqual(sum(item["stage"] == "selector" for item in stages), 12)
        readers = [item for item in stages if item["stage"] == "reader"]
        self.assertEqual(len(readers), 12)
        self.assertTrue(all("--same-attempt" in item["args"] for item in readers))
        self.assertEqual(sum(item["stage"] == "transport" for item in stages), 12)
        self.assertTrue(all("--owner-role" in item["args"] for item in stages if item["stage"] == "transport"))
        self.assertEqual(list(self.operations.glob(".sdk-owner-collection-v2.*")), [])

    def test_native_authentication_failure_stops_before_later_owners_and_fragment(self) -> None:
        self.env["FAKE_READER_MODE"] = "auth-fail"
        result = self.run_wrapper()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "selection-fragment.json").exists())
        stages = self.stages()
        self.assertEqual(sum(item["stage"] == "reader" for item in stages), 1)
        self.assertEqual(sum(item["stage"] == "transport" for item in stages), 0)

    def test_invalid_input_digest_stops_before_cli_provider_and_root(self) -> None:
        arguments = self.arguments()
        arguments[arguments.index("--inputs-sha256") + 1] = "f" * 64
        result = subprocess.run(["/bin/bash", str(self.script), *arguments], capture_output=True,
                                text=True, check=False, env=self.env)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.stages(), [])
        self.assertFalse(self.root.exists())
        self.assertEqual(list(self.operations.iterdir()), [])

    def test_duplicate_cli_selector_stops_before_cli_and_root(self) -> None:
        result = self.run_wrapper(["--inputs-dir", str(self.inputs)])
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.stages(), [])
        self.assertFalse(self.root.exists())

    def test_noncanonical_inputs_path_stops_before_cli_and_root(self) -> None:
        arguments = self.arguments()
        arguments[arguments.index("--inputs-dir") + 1] = str(self.inputs / ".." / self.inputs.name)
        result = subprocess.run(["/bin/bash", str(self.script), *arguments], capture_output=True,
                                text=True, check=False, env=self.env)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.stages(), [])
        self.assertFalse(self.root.exists())

    def test_same_matrix_fields_with_unqualified_schema_are_rejected_before_root(self) -> None:
        self.env["FAKE_MATRIX_MODE"] = "wrong-schema"
        result = self.run_wrapper()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([item["stage"] for item in self.stages()], ["aros", "matrix"])
        self.assertFalse(self.root.exists())
        self.assertEqual(list(self.operations.iterdir()), [])

    def test_matrix_digest_mismatch_is_rejected_before_root(self) -> None:
        self.env["FAKE_MATRIX_MODE"] = "wrong-digest"
        result = self.run_wrapper()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([item["stage"] for item in self.stages()], ["aros", "matrix"])
        self.assertFalse(self.root.exists())

    def test_invalid_independent_current_selector_stops_before_transport(self) -> None:
        self.env["FAKE_READER_MODE"] = "current-selector"
        result = self.run_wrapper()
        self.assertNotEqual(result.returncode, 0)
        stages = self.stages()
        self.assertEqual(sum(item["stage"] == "reader" for item in stages), 1)
        self.assertEqual(sum(item["stage"] == "transport" for item in stages), 0)
        self.assertFalse((self.root / "selection-fragment.json").exists())

    def test_missing_duplicate_and_changed_readback_tuples_are_rejected(self) -> None:
        for mode in ("missing-tuple", "duplicate-tuple", "changed-tuple", "swapped-tuple"):
            with self.subTest(mode=mode):
                self.tearDown()
                self.setUp()
                self.env["FAKE_READER_MODE"] = mode
                result = self.run_wrapper()
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertFalse((self.root / "selection-fragment.json").exists())
                self.assertEqual(sum(item["stage"] == "transport" for item in self.stages()), 0)

    def test_runtime_mutation_during_readback_prevents_fragment(self) -> None:
        self.env["FAKE_READER_MODE"] = "change-runtime"
        result = self.run_wrapper()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "selection-fragment.json").exists())
        self.assertEqual(sum(item["stage"] == "reader" for item in self.stages()), 1)

    def test_context_mutation_during_selection_prevents_fragment(self) -> None:
        self.env["FAKE_SELECTOR_MODE"] = "change-context"
        result = self.run_wrapper()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "selection-fragment.json").exists())
        self.assertEqual(sum(item["stage"] == "reader" for item in self.stages()), 1)

    def test_later_owner_mutating_each_prior_metadata_file_prevents_fragment(self) -> None:
        cases = (
            ("mutate-prior-selection", None,
             "owner selection changed before fragment generation", 12),
            ("mutate-prior-readback", None,
             "owner readback changed before fragment generation", 12),
            (None, "mutate-prior-transport-result",
             "owner transport result changed before fragment generation", 12),
        )
        for reader_mode, transport_mode, error, transport_count in cases:
            with self.subTest(reader_mode=reader_mode, transport_mode=transport_mode):
                self.tearDown()
                self.setUp()
                if reader_mode is not None:
                    self.env["FAKE_READER_MODE"] = reader_mode
                if transport_mode is not None:
                    self.env["FAKE_TRANSPORT_MODE"] = transport_mode
                result = self.run_wrapper()
                self.assertNotEqual(result.returncode, 0, result.stderr)
                self.assertFalse((self.root / "selection-fragment.json").exists())
                self.assertEqual(sum(item["stage"] == "reader" for item in self.stages()), 12)
                self.assertEqual(sum(item["stage"] == "transport" for item in self.stages()), transport_count)
                self.assertIn(error, result.stderr)

    def test_matrix_mutation_before_fragment_is_detected(self) -> None:
        self.env["FAKE_READER_MODE"] = "change-matrix"
        result = self.run_wrapper()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "selection-fragment.json").exists())

    def test_transport_remeasurement_mismatch_prevents_fragment(self) -> None:
        self.env["FAKE_TRANSPORT_MODE"] = "changed-reverification"
        result = self.run_wrapper()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "selection-fragment.json").exists())


if __name__ == "__main__":
    unittest.main()
