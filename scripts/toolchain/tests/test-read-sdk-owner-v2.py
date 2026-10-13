#!/usr/bin/env python3
"""Offline process-boundary tests for the authenticated SDK owner reader.

The wrapper, Bash, jq, shasum, and cmp are real. The origin and SDK transport
helpers are synthetic subprocess fixtures. These tests make no real provider,
signature, SDK, or release-qualification claims.
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


SCRIPT = Path(__file__).resolve().parents[1] / "read-sdk-owner-v2.sh"
WORKFLOW = ".github/workflows/read-sdk.yml"
SOURCE_WORKFLOW = ".github/workflows/build-sdk.yml"
SOURCE_REF = "refs/heads/main"
PRODUCER = "a" * 40
GROUP = "rv32"
PROFILE = "release"
HOST = "linux-aarch64"


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


FAKE_ORIGIN = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys


def record(stage, args):
    with open(os.environ["FAKE_STAGE_LOG"], "a", encoding="utf-8") as stream:
        stream.write(json.dumps({"stage": stage, "args": args}, separators=(",", ":")) + "\n")


def option(name):
    for index, value in enumerate(sys.argv[1:]):
        if value == name and index + 2 < len(sys.argv):
            return sys.argv[index + 2]
    raise SystemExit("fixture origin missing " + name)


args = sys.argv[1:]
record("origin", args)
if not args or args[0] != "verify-source":
    raise SystemExit("fixture origin received a non-verification operation")
if os.environ.get("FAKE_ORIGIN_MODE") == "fail":
    print("synthetic authentication failure", file=sys.stderr)
    raise SystemExit(41)

selection = Path(option("--source-selection"))
retained = Path(option("--verified-output-dir"))
retained.mkdir()
(retained / "fixture-owner-bytes").write_bytes(b"synthetic retained transport\n")
if os.environ.get("FAKE_ORIGIN_MODE") == "change-selection":
    with selection.open("ab") as stream:
        stream.write(b"changed after synthetic authentication\n")
print("synthetic authenticated-source placeholder")
'''


FAKE_TRANSPORT = r'''#!/usr/bin/env python3
import hashlib
import json
import os
from pathlib import Path
import sys


def record(stage, args):
    with open(os.environ["FAKE_STAGE_LOG"], "a", encoding="utf-8") as stream:
        stream.write(json.dumps({"stage": stage, "args": args}, separators=(",", ":")) + "\n")


def option(name):
    for index, value in enumerate(sys.argv[1:]):
        if value == name and index + 2 < len(sys.argv):
            return sys.argv[index + 2]
    raise SystemExit("fixture transport missing " + name)


args = sys.argv[1:]
retained = Path(option("--retained-dir"))
owner_role = option("--owner-role") if "--owner-role" in args else "diagnostic"
if "--output-dir" in args:
    record("extract", args)
    if os.environ.get("FAKE_TRANSPORT_MODE") == "extract-failure":
        raise SystemExit(51)
    output = Path(option("--output-dir"))
    output.mkdir(mode=0o700)
    sdk_ids = json.loads(option("--sdk-ids"))
    group = option("--group")
    profile = option("--profile")
    host = option("--host")
    family = option("--compiler-family")
    selection_path = Path(os.environ["FAKE_SELECTION_FILE"])
    products = []
    for sdk_id in sdk_ids:
        products.append({
            "sdk_id": sdk_id,
            "group_id": group,
            "target_profile": profile,
            "host": host,
            "package_dir": str(output / ("sdk-" + sdk_id) / "package"),
            "record": {"path": str(output / ("sdk-" + sdk_id) / "generation.json"), "sha256": "c" * 64},
            "compatibility": {"directory": str(output / ("sdk-" + sdk_id) / "compatibility"),
                              "manifest_sha256": "d" * 64,
                              "inputs": {"path": str(output / ("sdk-" + sdk_id) / "compatibility-inputs.json"),
                                         "sha256": "e" * 64},
                              "native_sdk_required": family == "gnu"},
        })
    result = {
        "schema": "aros-sdk-owner-transport-v2",
        "assurance": "transport-byte-readback-only",
        "origin_sha256": "a" * 64,
        "selection_sha256": hashlib.sha256(selection_path.read_bytes()).hexdigest(),
        "raw_zip_sha256": "b" * 64,
        "sdk_generations": products,
    }
    if owner_role != "diagnostic":
        result["owner_role"] = owner_role
    mode = os.environ.get("FAKE_TRANSPORT_MODE")
    if mode == "wrong-record-path":
        products[0]["record"]["path"] = str(output / ("sdk-" + sdk_ids[0]) / "package" / "generation.json")
    elif mode == "wrong-native-policy":
        products[0]["compatibility"]["native_sdk_required"] = family != "gnu"
    elif mode == "spoofed-owner-role":
        result["owner_role"] = "diagnostic"
    encoded = json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n"
    Path(os.environ["FAKE_TRANSPORT_RESULT"]).write_text(encoded, encoding="utf-8")
    if os.environ.get("FAKE_TRANSPORT_MODE") == "change-selection-extract":
        with selection_path.open("ab") as stream:
            stream.write(b"changed during synthetic extraction\n")
    sys.stdout.write(encoded)
elif "--verify-output-dir" in args:
    record("readback", args)
    if os.environ.get("FAKE_TRANSPORT_MODE") == "readback-failure":
        raise SystemExit(52)
    encoded = Path(os.environ["FAKE_TRANSPORT_RESULT"]).read_text(encoding="utf-8")
    if os.environ.get("FAKE_TRANSPORT_MODE") == "readback-mismatch":
        value = json.loads(encoded)
        value["raw_zip_sha256"] = "f" * 64
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    sys.stdout.write(encoded)
else:
    raise SystemExit("fixture transport received an unexpected operation")
'''


class ReadSdkOwnerProcessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="read-sdk-owner-v2-")
        self.base = Path(self.temporary.name).resolve()
        self.bin = self.base / "scripts" / "toolchain"
        self.bin.mkdir(parents=True)
        self.script = self.bin / SCRIPT.name
        shutil.copy2(SCRIPT, self.script)
        (self.bin / "artifact-origin.py").write_text(FAKE_ORIGIN, encoding="utf-8")
        (self.bin / "sdk-owner-transport-v2.py").write_text(FAKE_TRANSPORT, encoding="utf-8")
        self.selection_path = self.base / "selection.json"
        self.log = self.base / "stages.jsonl"
        self.transport_result = self.base / "transport-result-state.json"
        self.root = self.base / "operation"
        self.write_selection()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def selection(self, *, workflow: str = SOURCE_WORKFLOW, ref: str = SOURCE_REF,
                  producer: str = PRODUCER, lane: dict | None = None) -> dict:
        return {
            "schema": "aros-toolchain-artifact-selection-v1",
            "context": {
                "repository": "example/aros",
                "repository_id": 123,
                "producer_commit": producer,
                "source_ref": ref,
                "workflow": workflow,
                "run_id": 456,
                "run_attempt": 1,
            },
            "selection": lane or {
                "role": "diagnostic", "group": GROUP, "host": HOST,
                "profile": PROFILE, "copy": "none",
            },
            "job": {"id": 12, "name": "sdk owner"},
            "artifact": {"id": 34, "name": "sdk-payload", "sha256": "a" * 64,
                         "size_in_bytes": 100},
            "proof": {"id": 35, "name": "sdk-proof", "sha256": "b" * 64,
                       "size_in_bytes": 50},
        }

    def write_selection(self, **kwargs: object) -> str:
        raw = canonical_json(self.selection(**kwargs))
        self.selection_path.write_bytes(raw)
        return sha256(raw)

    def base_args(self, *, sdk_ids: list[str] | None = None, family: str = "gnu",
                  digest: str | None = None, owner_role: str | None = None) -> list[str]:
        selection_sha = self.selection_path.read_bytes()
        digest = sha256(selection_sha) if digest is None else digest
        sdk_ids = ["sdk-a"] if sdk_ids is None else sdk_ids
        args = [
            "--source-selection", str(self.selection_path),
            "--source-selection-sha256", digest,
            "--source-producer-commit", PRODUCER,
            "--source-workflow", SOURCE_WORKFLOW,
            "--source-ref", SOURCE_REF,
            "--workflow", WORKFLOW,
            "--job-name", "SDK owner reader",
            "--sdk-ids", json.dumps(sdk_ids, separators=(",", ":")),
            "--group", GROUP,
            "--preset", PROFILE,
            "--host", HOST,
            "--compiler-family", family,
            "--root", str(self.root),
        ]
        if owner_role is not None:
            args.extend(["--owner-role", owner_role])
        return args

    def run_reader(self, args: list[str], *, origin_mode: str = "success",
                   transport_mode: str = "success") -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env.update({
            "FAKE_STAGE_LOG": str(self.log),
            "FAKE_SELECTION_FILE": str(self.selection_path),
            "FAKE_TRANSPORT_RESULT": str(self.transport_result),
            "FAKE_ORIGIN_MODE": origin_mode,
            "FAKE_TRANSPORT_MODE": transport_mode,
        })
        return subprocess.run(["/bin/bash", str(self.script), *args],
                              capture_output=True, text=True, check=False, env=env)

    def stages(self) -> list[dict]:
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]

    def reject_before_root(self, args: list[str]) -> None:
        result = self.run_reader(args)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse(self.root.exists())
        self.assertEqual(self.stages(), [])

    def test_valid_gnu_and_llvm_orders_authentication_before_payload_and_wraps_readback(self) -> None:
        cases = (("gnu", ["sdk-a"], False),
                 ("llvm", ["a+b", "sdk-name", "sdk.name", "sdk_name"], True))
        for index, (family, sdk_ids, same_attempt) in enumerate(cases):
            with self.subTest(family=family):
                if index:
                    self.root = self.base / f"operation-{index}"
                    self.log = self.base / f"stages-{index}.jsonl"
                    self.transport_result = self.base / f"transport-result-state-{index}.json"
                args = self.base_args(sdk_ids=sdk_ids, family=family)
                if same_attempt:
                    args.append("--same-attempt")
                result = self.run_reader(args)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual([item["stage"] for item in self.stages()],
                                 ["origin", "extract", "readback"])
                origin_args = self.stages()[0]["args"]
                self.assertEqual(origin_args[0], "verify-source")
                self.assertIn("--workflow", origin_args)
                self.assertIn("--job-name", origin_args)
                self.assertIn("--verified-output-dir", origin_args)
                self.assertEqual("--same-attempt" in origin_args, same_attempt)
                extraction = self.stages()[1]["args"]
                self.assertIn("--owner-role", extraction)
                self.assertEqual(extraction[extraction.index("--owner-role") + 1], "diagnostic")
                readback_args = self.stages()[2]["args"]
                self.assertIn("--owner-role", readback_args)
                self.assertEqual(readback_args[readback_args.index("--owner-role") + 1], "diagnostic")
                self.assertEqual(extraction[extraction.index("--sdk-ids") + 1],
                                 json.dumps(sdk_ids, separators=(",", ":")))
                wrapper = json.loads((self.root / "readback.json").read_text(encoding="utf-8"))
                self.assertEqual(set(wrapper), {
                    "schema", "assurance", "source_workflow", "source_ref",
                    "source_producer_commit", "source_selection_sha256",
                    "independent_selection", "sdk_owner_transport",
                })
                self.assertEqual(wrapper["schema"], "aros-sdk-owner-readback-v2")
                self.assertEqual(wrapper["assurance"],
                                 "authenticated-transport-and-sdk-payload-readback-only")
                self.assertEqual(wrapper["source_selection_sha256"],
                                 sha256(self.selection_path.read_bytes()))
                self.assertEqual(wrapper["independent_selection"], {
                    "sdk_ids": sdk_ids, "group": GROUP, "profile": PROFILE,
                    "host": HOST, "compiler_family": family,
                })
                self.assertNotIn("owner_role", wrapper["independent_selection"])
                self.assertEqual([item["sdk_id"] for item in
                                  wrapper["sdk_owner_transport"]["sdk_generations"]], sdk_ids)
                self.assertEqual((self.root.stat().st_mode & 0o777), 0o700)

    def test_sdk_owner_role_reaches_both_transport_processes_and_wrapper(self) -> None:
        self.write_selection(lane={"role": "sdk", "group": GROUP, "host": HOST,
                                   "profile": PROFILE, "copy": "none"})
        result = self.run_reader(self.base_args(owner_role="sdk"))
        self.assertEqual(result.returncode, 0, result.stderr)
        stages = self.stages()
        self.assertEqual([item["stage"] for item in stages], ["origin", "extract", "readback"])
        for stage in stages[1:]:
            args = stage["args"]
            self.assertIn("--owner-role", args)
            self.assertEqual(args[args.index("--owner-role") + 1], "sdk")
        wrapper = json.loads((self.root / "readback.json").read_text(encoding="utf-8"))
        self.assertEqual(wrapper["independent_selection"]["owner_role"], "sdk")
        self.assertEqual(wrapper["sdk_owner_transport"]["owner_role"], "sdk")

    def test_source_and_independent_owner_role_mismatches_fail_before_root_or_authentication(self) -> None:
        sdk_lane = {"role": "sdk", "group": GROUP, "host": HOST,
                    "profile": PROFILE, "copy": "none"}
        self.write_selection(lane=sdk_lane)
        self.reject_before_root(self.base_args())
        self.reject_before_root(self.base_args(owner_role="diagnostic"))
        self.write_selection()
        self.reject_before_root(self.base_args(owner_role="sdk"))

    def test_wrong_source_lane_and_digest_reject_before_operation_creation(self) -> None:
        self.write_selection(workflow=".github/workflows/other.yml")
        self.reject_before_root(self.base_args())
        self.write_selection(ref="refs/tags/v1.0.0")
        self.reject_before_root(self.base_args())
        self.write_selection(producer="b" * 40)
        self.reject_before_root(self.base_args())
        self.write_selection(lane={"role": "build", "group": GROUP, "host": HOST,
                                   "profile": PROFILE, "copy": "a"})
        self.reject_before_root(self.base_args())
        self.write_selection()
        self.reject_before_root(self.base_args(digest="f" * 64))

    def test_invalid_selectors_sdk_grammar_unknown_and_duplicate_flags_reject_early(self) -> None:
        for key, value in (("--group", "../escape"), ("--preset", ".."),
                           ("--host", "linux-riscv64"), ("--compiler-family", "other")):
            with self.subTest(key=key):
                args = self.base_args()
                args[args.index(key) + 1] = value
                self.reject_before_root(args)
        args = self.base_args()
        args[args.index("--source-ref") + 1] = "refs/heads/topic..name"
        self.reject_before_root(args)
        for sdk_ids in (["SDK-A"], ["sdk/a"], ["sdk space"], ["."], [".."],
                        ["sdk-b", "sdk-a"], ["sdk-a", "sdk-a"], [],
                        ["x" * 97], [f"sdk-{index:02d}" for index in range(33)]):
            with self.subTest(sdk_ids=sdk_ids[:2]):
                self.reject_before_root(self.base_args(sdk_ids=sdk_ids))
        args = self.base_args() + ["--unrecognized", "x"]
        self.reject_before_root(args)
        self.reject_before_root(self.base_args(owner_role="other"))
        args = self.base_args() + ["--group", GROUP]
        self.reject_before_root(args)
        args = self.base_args()
        args[args.index("--group") + 1] = ""
        self.reject_before_root(args)
        args = self.base_args() + ["--same-attempt", "--same-attempt"]
        self.reject_before_root(args)
        args = self.base_args()
        args[args.index("--job-name") + 1] = "line one\nline two"
        self.reject_before_root(args)

    def test_existing_root_is_preserved_and_origin_failure_prevents_extraction(self) -> None:
        self.root.mkdir()
        sentinel = self.root / "sentinel"
        sentinel.write_bytes(b"preserve me")
        result = self.run_reader(self.base_args())
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(sentinel.read_bytes(), b"preserve me")
        self.assertEqual(self.stages(), [])
        shutil.rmtree(self.root)
        self.root = self.base / "operation-after-origin-failure"
        result = self.run_reader(self.base_args(), origin_mode="fail")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([item["stage"] for item in self.stages()], ["origin"])
        self.assertFalse((self.root / "readback.json").exists())

    def test_extraction_readback_failure_and_result_mismatch_never_write_wrapper(self) -> None:
        cases = (("extract-failure", ["origin", "extract"]),
                 ("readback-failure", ["origin", "extract", "readback"]),
                 ("readback-mismatch", ["origin", "extract", "readback"]))
        for index, (mode, expected_stages) in enumerate(cases):
            with self.subTest(mode=mode):
                self.root = self.base / f"failure-{index}"
                self.log = self.base / f"failure-stages-{index}.jsonl"
                self.transport_result = self.base / f"failure-result-{index}.json"
                result = self.run_reader(self.base_args(), transport_mode=mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual([item["stage"] for item in self.stages()], expected_stages)
                self.assertFalse((self.root / "readback.json").exists())

    def test_sdk_result_with_spoofed_owner_role_never_writes_wrapper(self) -> None:
        self.write_selection(lane={"role": "sdk", "group": GROUP, "host": HOST,
                                   "profile": PROFILE, "copy": "none"})
        result = self.run_reader(self.base_args(owner_role="sdk"),
                                 transport_mode="spoofed-owner-role")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([item["stage"] for item in self.stages()],
                         ["origin", "extract", "readback"])
        self.assertFalse((self.root / "readback.json").exists())

    def test_identical_readback_with_wrong_record_path_or_native_policy_rejects(self) -> None:
        for index, mode in enumerate(("wrong-record-path", "wrong-native-policy")):
            with self.subTest(mode=mode):
                self.root = self.base / f"bad-join-{index}"
                self.log = self.base / f"bad-join-stages-{index}.jsonl"
                self.transport_result = self.base / f"bad-join-result-{index}.json"
                result = self.run_reader(self.base_args(), transport_mode=mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual([item["stage"] for item in self.stages()],
                                 ["origin", "extract", "readback"])
                extracted = (self.root / "transport-result.json").read_bytes()
                verified = (self.root / "transport-readback.json").read_bytes()
                self.assertEqual(extracted, verified)
                self.assertFalse((self.root / "readback.json").exists())

    def test_selection_changes_during_origin_or_extraction_reject_and_retain_diagnostics(self) -> None:
        result = self.run_reader(self.base_args(), origin_mode="change-selection")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([item["stage"] for item in self.stages()], ["origin"])
        self.assertTrue((self.root / "origin-verification.log").exists())
        self.assertFalse((self.root / "readback.json").exists())

        self.root = self.base / "operation-change-extract"
        self.log = self.base / "stages-change-extract.jsonl"
        self.transport_result = self.base / "result-change-extract.json"
        self.write_selection()
        result = self.run_reader(self.base_args(), transport_mode="change-selection-extract")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([item["stage"] for item in self.stages()],
                         ["origin", "extract", "readback"])
        self.assertTrue((self.root / "transport-result.json").exists())
        self.assertTrue((self.root / "transport-readback.json").exists())
        self.assertFalse((self.root / "readback.json").exists())


if __name__ == "__main__":
    unittest.main()
