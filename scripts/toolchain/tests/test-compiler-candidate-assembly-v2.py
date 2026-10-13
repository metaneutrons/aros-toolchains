"""Process-boundary tests for compiler candidate assembly.

The retained original-owner bundles and extracted payloads use the real
native-lane transport implementation. Only the native ``aros`` executable is
substituted. These tests establish closure and process behavior, not provider
signature authenticity, independent compiler execution, qualification,
admission, signing, or publication.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


TOOLCHAIN = Path(__file__).resolve().parents[1]
SCRIPT = TOOLCHAIN / "assemble-compiler-candidate-v2.py"
RELEASE_MATRIX_TEST = Path(__file__).with_name("test-release-matrix-v2.py")
TRANSPORT_TEST = Path(__file__).with_name("test-native-lane-transport.py")
REQUIRED_HELPER = TOOLCHAIN / "required-compiler-payload-v2.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


assembler = load_module("compiler_candidate_assembly_under_test", SCRIPT)
release_tests = load_module("compiler_candidate_release_test_helpers", RELEASE_MATRIX_TEST)
transport_tests = load_module("compiler_candidate_transport_test_helpers", TRANSPORT_TEST)
required_helper = load_module("compiler_candidate_required_payload_helper", REQUIRED_HELPER)
transport = transport_tests.transport
origin = transport.origin

HOSTS = tuple(assembler._MATRIX.ACTIVE_HOSTS)
PRODUCER = "a" * 40
TOOLS = "b" * 40
SOURCE_COMMIT = "c" * 40
SOURCE_TREE = "d" * 40
GROUP = "compiler-family"
PROFILES = ("-generic", "debug")
RELEASE_ID = "r2026-10"
WORKFLOW = ".github/workflows/compiler-candidate-assembly.yml"
SOURCE_WORKFLOW = ".github/workflows/native-compiler.yml"
SOURCE_REF = "refs/heads/main"
JOB_NAME = "Compiler candidate assembly"
TREE_SHA = "e" * 64
CONTRACT_SHA = "f" * 64
BINARY_SHA = "1" * 64
FINISHED_RECEIPT_SHA = "2" * 64
RAW_PAYLOAD_SHA = "3" * 64


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8") + b"\n"


def file_measurement(path: Path) -> dict:
    raw = path.read_bytes()
    return {"sha256": digest(raw), "size": len(raw)}


def owner_job_name(host: str, profile: str, copy_id: str) -> str:
    return f"Native compiler ({GROUP}, {host}, {profile}, {copy_id})"


FAKE_AROS = r'''#!/usr/bin/env python3
import hashlib
import json
import os
from pathlib import Path
import sys

args = sys.argv[1:]
def option(name):
    for item in args:
        if item.startswith(name + "="):
            return item.split("=", 1)[1]
    try:
        return args[args.index(name) + 1]
    except (ValueError, IndexError):
        raise SystemExit("missing native option " + name)
def sha(raw):
    return hashlib.sha256(raw).hexdigest()
def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                        ensure_ascii=False, allow_nan=False) + "\n").encode()
def record():
    with open(os.environ["FAKE_AROS_LOG"], "a", encoding="utf-8") as stream:
        stream.write(json.dumps(args, separators=(",", ":")) + "\n")

record()
if args[:3] == ["toolchain", "producer", "verify-package"]:
    if os.environ.get("FAKE_FAIL_VERIFY") == "1":
        raise SystemExit(31)
    package = Path(option("--input-dir"))
    profile = option("--preset")
    environment = Path(option("--build-environment"))
    measurement = Path(option("--package-measurement"))
    if not profile.startswith("-") and not profile:
        raise SystemExit("invalid test profile")
    if not any(value.startswith("--preset=") for value in args):
        raise SystemExit("profile must use equals-form CLI syntax")
    if option("--package-format") != "family-v2":
        raise SystemExit("wrong package family")
    if sha(measurement.read_bytes()) != option("--package-measurement-sha256"):
        raise SystemExit("measurement selector differs")
    if not environment.is_file():
        raise SystemExit("environment input is missing")
    observation = json.loads((package.parent.parent / "observation.json").read_bytes())
    result = observation["native"]
    mode = os.environ.get("FAKE_VERIFY_MODE", "")
    if mode == "archive-substitution":
        result["sha256"] = "9" * 64
    elif mode == "receipt-substitution":
        result["finished_candidate"]["finished_receipt_sha256"] = "8" * 64
    elif mode == "measurement-substitution":
        result["finished_candidate"]["measurement_sha256"] = "7" * 64
    elif mode == "build-result-substitution":
        result["finished_candidate"]["build_result_sha256"] = "6" * 64
    elif mode == "late-observation-mutation":
        observation_path = package.parent.parent / "observation.json"
        with observation_path.open("ab") as stream:
            stream.write(b" \n")
    elif mode == "late-transport-mutation":
        retained = package.parent.parent / "transport" / "payload.zip"
        with retained.open("ab") as stream:
            stream.write(b"late transport mutation")
    sys.stdout.buffer.write(canonical(result))
    raise SystemExit(0)

if args[:3] == ["toolchain", "producer", "compare"]:
    if os.environ.get("FAKE_FAIL_COMPARE") == "1":
        raise SystemExit(32)
    left = Path(option("--left"))
    right = Path(option("--right"))
    report_path = Path(option("--output"))
    def members(package):
        return [{"name": path.name, "sha256": file_measure(path)["sha256"],
                 "size": file_measure(path)["size"]}
                for path in sorted(package.iterdir())]
    def file_measure(path):
        raw = path.read_bytes()
        return {"sha256": sha(raw), "size": len(raw)}
    left_members = members(left)
    right_members = members(right)
    if left_members != right_members:
        raise SystemExit("fixture packages differ")
    report_members = copy_members = left_members
    mode = os.environ.get("FAKE_COMPARE_MODE", "")
    if mode == "report-member-substitution":
        report_members = [dict(item) for item in left_members]
        report_members[0]["sha256"] = "5" * 64
    package_set_sha = sha(canonical(report_members))
    report = {"schema": 1, "operation": "compare", "byte_identical": True,
              "package_set_sha256": package_set_sha, "members": report_members}
    if mode == "boolean-receipt-schema":
        report["schema"] = True
    report_raw = canonical(report)
    report_path.write_bytes(report_raw)
    receipt_sha = sha(report_raw)
    if mode == "response-receipt-sha-substitution":
        receipt_sha = "4" * 64
    output = {"schema": "aros-toolchain-producer-stage-v1", "operation": "compare",
              "byte_identical": True, "receipt": str(report_path),
              "receipt_sha256": receipt_sha, "package_set_sha256": package_set_sha,
              "members": report_members}
    sys.stdout.buffer.write(canonical(output))
    raise SystemExit(0)

raise SystemExit("unexpected native producer command: " + " ".join(args[:3]))
'''


class Fixture:
    def __init__(self, base: Path) -> None:
        self.base = base.resolve()
        self.inputs = self.base / "inputs"
        self.inputs.mkdir(mode=0o700)
        self.owner_root = self.base / "compiler-owners"
        (self.owner_root / "owners").mkdir(parents=True, mode=0o700)
        os.chmod(self.owner_root, 0o700)
        os.chmod(self.owner_root / "owners", 0o700)
        self.context = {
            "repository": "example/project", "repository_id": 7890,
            "producer_commit": PRODUCER, "source_ref": SOURCE_REF,
            "workflow": SOURCE_WORKFLOW, "run_id": 321456, "run_attempt": 2,
        }
        self.context_raw = origin.canonical(self.context)
        self.context_sha = digest(self.context_raw)
        self._make_plan_and_inputs()
        self._make_native_executable()
        self._write_matrix()
        self._make_owners()
        self._write_fragment()
        self._write_required_paths()

    def _make_plan_and_inputs(self) -> None:
        reference_docs = {}
        for name, content in (
            ("recipe.json", {"schema": "aros-toolchain-recipe-v2", "source_commit": SOURCE_COMMIT}),
            ("source-lock.json", {"schema": "fixture-source-lock-v1"}),
            ("profiles.json", {"schema": "fixture-profiles-v1", "profiles": list(PROFILES)}),
        ):
            raw = canonical(content)
            (self.inputs / name).write_bytes(raw)
            os.chmod(self.inputs / name, 0o600)
            reference_docs[name] = {"file": name, "sha256": digest(raw)}
        self.group = {
            "group_id": GROUP, "source_commit": SOURCE_COMMIT,
            "source_tree": SOURCE_TREE, "upstream_commit": SOURCE_COMMIT,
            "recipe": reference_docs["recipe.json"],
            "source_lock": reference_docs["source-lock.json"],
            "profiles": reference_docs["profiles.json"],
        }
        self.lanes = [
            {"group_id": GROUP, "host": host, "target_profile": profile}
            for profile in PROFILES for host in HOSTS
        ]
        self.collection = {
            "schema": "aros-toolchain-release-inputs-v2", "producer_commit": PRODUCER,
            "tools_commit": TOOLS, "hosts": list(HOSTS),
            "groups": [{"id": GROUP, "recipe": self.group["recipe"],
                        "source_lock": self.group["source_lock"],
                        "profiles": self.group["profiles"]}],
            "sdks": [],
        }
        collection_raw = canonical(self.collection)
        self.collection_path = self.inputs / "toolchain-release-inputs-v2.json"
        self.collection_path.write_bytes(collection_raw)
        os.chmod(self.collection_path, 0o600)
        self.inputs_sha = digest(collection_raw)
        self.plan = {
            "schema": "aros-toolchain-producer-stage-v2", "operation": "release-plan",
            "release_format": "family-v2", "assurance": "input-binding-only",
            "inputs_sha256": self.inputs_sha, "producer_commit": PRODUCER,
            "tools_commit": TOOLS, "hosts": list(HOSTS), "groups": [self.group],
            "lane_count": len(self.lanes), "lanes": self.lanes,
            "sdks": [], "sdk_count": 0,
        }
        self.plan_raw = canonical(self.plan)
        self.plan_path = self.base / "native-plan.json"
        self.plan_path.write_bytes(self.plan_raw)
        os.chmod(self.plan_path, 0o600)
        self.plan_sha = digest(self.plan_raw)

    def _make_native_executable(self) -> None:
        self.aros = self.base / "fake-aros"
        self.aros.write_text(FAKE_AROS, encoding="utf-8")
        os.chmod(self.aros, 0o700)
        self.aros_sha = digest(self.aros.read_bytes())
        self.log = self.base / "native.log"

    def _write_matrix(self) -> None:
        owners = []
        for lane in sorted(self.lanes, key=lambda item: (
                item["group_id"], item["host"], item["target_profile"])):
            for copy_id in ("a", "b"):
                key = (GROUP, lane["host"], lane["target_profile"], copy_id)
                owner_id = assembler._COMPILER_MATRIX._owner_id(*key)
                owners.append({
                    "owner_id": owner_id, "group_id": GROUP, "host": lane["host"],
                    "profile": lane["target_profile"], "copy": copy_id,
                    "job_name": owner_job_name(lane["host"], lane["target_profile"], copy_id),
                    "payload_name": f"native-v2-{owner_id}-{self.context['run_id']}-{self.context['run_attempt']}",
                    "proof_name": f"native-v2-proof-{owner_id}-{self.context['run_id']}-{self.context['run_attempt']}",
                    "recipe": self.group["recipe"], "source_lock": self.group["source_lock"],
                    "profiles": self.group["profiles"],
                })
        self.matrix = {
            "schema": "aros-compiler-owner-matrix-v2", "assurance": "owner-selection-only",
            "plan_sha256": self.plan_sha, "inputs_sha256": self.inputs_sha,
            "source_context_sha256": self.context_sha, "producer_commit": PRODUCER,
            "tools_commit": TOOLS, "owners": owners,
            "expected_compiler_lanes": sorted(self.lanes, key=lambda item: (
                item["group_id"], item["host"], item["target_profile"])),
        }
        matrix_path = self.owner_root / "matrix.json"
        matrix_path.write_bytes(canonical(self.matrix))
        os.chmod(matrix_path, 0o600)

    def _make_owner(self, lane: dict, copy_id: str, job_id: int) -> dict:
        key = (GROUP, lane["host"], lane["target_profile"], copy_id)
        owner = next(item for item in self.matrix["owners"] if
                     (item["group_id"], item["host"], item["profile"], item["copy"]) == key)
        owner_dir = self.owner_root / "owners" / owner["owner_id"]
        readback = owner_dir / "readback"
        owner_dir.mkdir(mode=0o700)
        readback.mkdir(mode=0o700)

        lane_value = lane["target_profile"]
        archive = f"compiler-{lane['host']}-{lane_value}.tar.xz"
        archive_bytes = f"synthetic compiler archive for {lane['host']} {lane_value}\n".encode()
        package_manifest = {
            "schema": 2, "release_id": RELEASE_ID, "host": lane["host"],
            "target_profile": lane_value, "recipe_sha256": self.group["recipe"]["sha256"],
            "source_lock_sha256": self.group["source_lock"]["sha256"],
            "profiles_sha256": self.group["profiles"]["sha256"],
            "source_commit": SOURCE_COMMIT, "producer_commit": PRODUCER,
            "tools_commit": TOOLS, "tree_sha256": TREE_SHA,
        }
        members = transport_tests.lane_members()
        for name in list(members):
            if name.startswith("package/"):
                del members[name]
        members[f"package/{archive}"] = archive_bytes
        members[f"package/{archive}.manifest.json"] = canonical(package_manifest)
        members[f"package/{archive}.sha256"] = f"{digest(archive_bytes)}  {archive}\n".encode()
        members[f"package/{archive}.spdx.json"] = canonical({
            "spdxVersion": "SPDX-2.3", "name": archive,
        })
        environment_raw = canonical({
            "schema": "fixture-build-environment-v1", "host": lane["host"],
            "target_profile": lane_value, "build_directory": f"/build/{lane['host']}",
        })
        measurement_raw = canonical({
            "schema": "fixture-portable-measurement-v1", "host": lane["host"],
            "target_profile": lane_value,
        })
        build_result_raw = canonical({
            "schema": "aros-toolchain-result-v1", "operation": "build",
            "qualification": "local-only", "commit_state": "committed",
        })
        members["evidence/environment.json"] = environment_raw
        members["evidence/measurement.json"] = measurement_raw
        members["evidence/build-result.json"] = build_result_raw
        lane_selection = {
            "role": "build", "group": GROUP, "host": lane["host"],
            "profile": lane_value, "copy": copy_id,
        }
        retained = readback / "transport"
        bundle = transport_tests.make_bundle(
            retained, member_data=members, selected_lane=lane_selection,
            origin_lane=lane_selection,
            selected_job={"id": job_id, "name": owner["job_name"]},
            selected_context=self.context, origin_context=self.context,
        )
        selection = bundle["selection"]
        selection["artifact"]["id"] = 710000 + job_id
        selection["artifact"]["name"] = owner["payload_name"]
        selection["proof"]["id"] = 720000 + job_id
        selection["proof"]["name"] = owner["proof_name"]
        signed = bundle["signed"]
        signed["artifact"] = copy.deepcopy(selection["artifact"])
        selection_raw = origin.canonical(selection)
        (retained / "selection.json").write_bytes(selection_raw)
        (retained / "origin.json").write_bytes(origin.canonical(signed))
        os.chmod(retained / "selection.json", 0o600)
        os.chmod(retained / "origin.json", 0o600)
        owner_selection = owner_dir / "selection.json"
        owner_selection.write_bytes(selection_raw)
        os.chmod(owner_selection, 0o600)

        payload = readback / "payload"
        transport_result = transport.extract(retained, payload)
        transport_raw = origin.canonical(transport_result)
        (readback / "transport-result.json").write_bytes(transport_raw)
        (readback / "transport-readback.json").write_bytes(transport_raw)
        (readback / "transport-reverification.json").write_bytes(transport_raw)
        (readback / "origin-verification.log").write_bytes(
            b"Synthetic authenticated original-owner fixture; signature not verified.\n"
        )

        environment_path = payload / "evidence" / "environment.json"
        environment_path.write_bytes(environment_raw)
        measurement_path = payload / "evidence" / "measurement.json"
        measurement_path.write_bytes(measurement_raw)
        build_result_path = payload / "evidence" / "build-result.json"
        build_result_path.write_bytes(build_result_raw)
        for path in (environment_path, measurement_path, build_result_path):
            os.chmod(path, 0o600)

        environment_sha = digest(environment_raw)
        measurement_sha = digest(measurement_path.read_bytes())
        build_result_sha = digest(build_result_raw)
        package_path = payload / "package" / archive
        native_result = {
            "schema": "aros-toolchain-producer-stage-v1", "operation": "verify-package",
            "sha256": digest(package_path.read_bytes()), "size": package_path.stat().st_size,
            "manifest": package_manifest,
            "finished_candidate": {
                "schema": "aros-toolchain-portable-package-readback-v2",
                "assurance": "portable-byte-readback-only",
                "measurement_sha256": measurement_sha,
                "build_result_sha256": build_result_sha,
                "package_tree_sha256": TREE_SHA,
                "finished_receipt_sha256": FINISHED_RECEIPT_SHA,
                "raw_payload_sha256": RAW_PAYLOAD_SHA,
            },
        }
        identity = {
            "recipe_self_sha256": self.group["recipe"]["sha256"],
            "source_commit": SOURCE_COMMIT, "producer_commit": PRODUCER,
            "tools_commit": TOOLS, "host": lane["host"], "target_profile": lane_value,
        }
        expectations = {
            "build_result_sha256": build_result_sha,
            **identity,
            "executor_contract_id": "aros-toolchain-producer-v1",
            "executor_contract_sha256": CONTRACT_SHA,
            "executor_binary_sha256": BINARY_SHA,
        }
        (readback / "original-expectations.json").write_bytes(canonical(expectations))
        (readback / "native-verification.json").write_bytes(origin.canonical(native_result))
        os.chmod(readback / "original-expectations.json", 0o600)
        os.chmod(readback / "native-verification.json", 0o600)

        observation = {
            "schema": "aros-toolchain-original-owner-observation-v2",
            "assurance": "authenticated-original-job-and-native-byte-readback-only",
            "scope": {
                "original_owner_job_observation": True, "native_package_byte_readback": True,
                "independently_executed_collector": False,
                "release_admission": False, "publication": False,
            },
            "current_workflow": WORKFLOW, "current_job_name": JOB_NAME,
            "source_workflow": SOURCE_WORKFLOW, "source_ref": SOURCE_REF,
            "group": GROUP, "host": lane["host"], "target_profile": lane_value,
            "copy": copy_id, "release_id": RELEASE_ID, "reader_runtime_sha256": self.aros_sha,
            "recipe_file_sha256": self.group["recipe"]["sha256"],
            "source_lock_sha256": self.group["source_lock"]["sha256"],
            "profiles_sha256": self.group["profiles"]["sha256"],
            "source_selection_sha256": digest(selection_raw),
            "build_result_sha256": build_result_sha,
            "environment_sha256": environment_sha, "measurement_sha256": measurement_sha,
            "executor_contract_id": "aros-toolchain-producer-v1",
            "executor_contract_sha256": CONTRACT_SHA,
            "executor_binary_sha256": BINARY_SHA,
            "original_identity": identity,
            "transport": transport_result, "native": native_result,
        }
        observation_path = readback / "observation.json"
        observation_path.write_bytes(origin.canonical(observation))
        os.chmod(observation_path, 0o600)
        # The native CLI recomputes the outer package digest, while the exact
        # four-file shape/name is selected from this real transport output.
        return {
            "group_id": GROUP, "host": lane["host"], "target_profile": lane_value,
            "copy": copy_id, "package_dir": str(payload / "package"),
            "measurement": {"path": str(measurement_path), "sha256": measurement_sha},
            "environment": {"path": str(environment_path), "sha256": environment_sha},
            "executor": {"contract_sha256": CONTRACT_SHA, "binary_sha256": BINARY_SHA},
            "observation": {"path": str(observation_path), "sha256": digest(observation_path.read_bytes())},
        }

    def _make_owners(self) -> None:
        self.rows = []
        for index, lane in enumerate(sorted(self.lanes, key=lambda item: (
                item["group_id"], item["host"], item["target_profile"]))):
            for copy_index, copy_id in enumerate(("a", "b")):
                self.rows.append(self._make_owner(lane, copy_id, 910000 + index * 2 + copy_index))

    def _write_fragment(self) -> None:
        expected_lanes = sorted(self.lanes, key=lambda item: (
            item["group_id"], item["host"], item["target_profile"]))
        self.fragment = {
            "schema": "aros-compiler-build-selection-fragment-v2",
            "assurance": "authenticated-original-owner-selection-only",
            "runtime_sha256": self.aros_sha, "plan_sha256": self.plan_sha,
            "inputs_sha256": self.inputs_sha, "source_context_sha256": self.context_sha,
            "source_producer_commit": PRODUCER, "source_workflow": SOURCE_WORKFLOW,
            "source_ref": SOURCE_REF, "producer_commit": PRODUCER, "tools_commit": TOOLS,
            "workflow": WORKFLOW, "job_name": JOB_NAME, "release_id": RELEASE_ID,
            "owner_count": len(self.rows), "expected_compiler_lanes": expected_lanes,
            "compiler_builds": self.rows,
            "release_admission": False, "publication": False,
        }
        self.fragment_path = self.owner_root / "selection-fragment.json"
        self.fragment_path.write_bytes(canonical(self.fragment))
        os.chmod(self.fragment_path, 0o600)

    def _save_fragment(self) -> None:
        self.fragment_path.write_bytes(canonical(self.fragment))
        os.chmod(self.fragment_path, 0o600)

    def _write_required_paths(self) -> None:
        policy = {
            "schema": required_helper.POLICY_SCHEMA,
            "groups": [{
                "group_id": GROUP,
                "source_lock_sha256": self.group["source_lock"]["sha256"],
                "profiles_sha256": self.group["profiles"]["sha256"],
                "profiles": {profile: sorted([f"include/{profile}/compiler.h"])
                             for profile in PROFILES},
            }],
        }
        policy_raw = canonical(policy)
        selection = required_helper.select_required_payload(
            raw_policy=policy_raw, expected_policy_sha256=digest(policy_raw),
            raw_plan=self.plan_raw, plan_sha256=self.plan_sha,
            inputs_sha256=self.inputs_sha, producer_commit=PRODUCER, tools_commit=TOOLS,
        )
        self.required_path = self.base / "required-paths.json"
        self.required_path.write_bytes(canonical(selection))
        os.chmod(self.required_path, 0o600)
        self.required_sha = digest(self.required_path.read_bytes())

    def args(self, root: Path) -> list[str]:
        return [
            sys.executable, "-B", str(SCRIPT), "--aros", str(self.aros),
            "--aros-sha256", self.aros_sha, "--plan", str(self.plan_path),
            "--plan-sha256", self.plan_sha, "--inputs-dir", str(self.inputs),
            "--inputs-sha256", self.inputs_sha, "--producer-commit", PRODUCER,
            "--tools-commit", TOOLS, "--fragment", str(self.fragment_path),
            "--fragment-sha256", digest(self.fragment_path.read_bytes()),
            "--owner-root", str(self.owner_root), "--required-paths", str(self.required_path),
            "--required-paths-sha256", self.required_sha,
            "--release-id", RELEASE_ID, "--forbidden-prefix", "/tmp/compiler-build",
            "--root", str(root),
        ]

    def run(self, root: Path, **environment: str) -> subprocess.CompletedProcess[str]:
        child_environment = dict(os.environ)
        child_environment["PYTHONDONTWRITEBYTECODE"] = "1"
        child_environment["FAKE_AROS_LOG"] = str(self.log)
        child_environment.update(environment)
        return subprocess.run(self.args(root), capture_output=True, text=True,
                              env=child_environment, check=False, timeout=120)


class CompilerCandidateAssemblyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="compiler-candidate-assembly-v2.")
        self.base = Path(self.temporary.name).resolve()
        self.fixture = Fixture(self.base)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def assert_rejected(self, result: subprocess.CompletedProcess[str], root: Path,
                        *, release_absent: bool = True) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(result.stdout, "")
        self.assertIn("compiler candidate assembly failed:", result.stderr)
        if release_absent:
            self.assertFalse((root / "release").exists())

    def test_full_generic_three_host_matrix_reverifies_compares_and_stages_only_a(self) -> None:
        root = self.base / "operation"
        result = self.fixture.run(root)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertEqual(len(result.stdout.splitlines()), 1)
        summary = json.loads(result.stdout)
        self.assertEqual(summary["schema"], "aros-toolchain-compiler-candidate-assembly-v2")
        self.assertEqual(summary["assurance"], "compiler-candidate-byte-assembly-partial-no-admission")
        self.assertEqual(summary["scope"], {
            "compiler_only": True, "sdk_included": False,
            "admission": False, "publication": False,
        })
        self.assertEqual(len(summary["staged_inventory"]), 4 * len(HOSTS) * len(PROFILES))
        self.assertEqual(len(summary["artifacts"]["comparisons"]), len(HOSTS) * len(PROFILES))
        self.assertEqual(len(summary["artifacts"]["native_verifications"]), len(HOSTS) * len(PROFILES))

        index_doc = json.loads((root / "compiler-index-lanes.json").read_bytes())
        self.assertEqual(index_doc["schema"], "aros-toolchain-index-lanes-v1")
        self.assertEqual(len(index_doc["lanes"]), len(HOSTS) * len(PROFILES))
        self.assertEqual(set(index_doc["lanes"]), set(summary["artifacts"]["comparisons"]))
        for asset, lane in index_doc["lanes"].items():
            self.assertEqual(lane["required_paths"], [
                f"include/{lane['build_environment']['target_profile']}/compiler.h"
            ])

        evidence = json.loads((root / "compiler-evidence-fragment.json").read_bytes())
        self.assertEqual(evidence["assurance"], "partial-compiler-candidate-assembly-no-admission")
        self.assertFalse(evidence["complete"])
        self.assertFalse(evidence["admission"])
        self.assertFalse(evidence["publication"])
        self.assertEqual(set(evidence["assets"]), set(index_doc["lanes"]))
        for asset, entry in evidence["assets"].items():
            self.assertEqual([build["copy"] for build in entry["builds"]], ["a", "b"])
            self.assertNotEqual(entry["builds"][0]["original_job_id"],
                                entry["builds"][1]["original_job_id"])
            comparison = entry["comparison"]["selectedFile"]
            self.assertEqual(digest(Path(comparison["path"]).read_bytes()), comparison["sha256"])
            self.assertEqual(
                summary["artifacts"]["comparisons"][asset]["sha256"], comparison["sha256"]
            )
        for name, measurement in summary["staged_inventory"].items():
            source_candidates = [Path(row["package_dir"]) / name
                                 for row in self.fixture.rows if row["copy"] == "a"]
            sources = [path for path in source_candidates if path.exists()]
            self.assertEqual(len(sources), 1)
            self.assertEqual(file_measurement(root / "release" / name), measurement)
            self.assertEqual((root / "release" / name).read_bytes(), sources[0].read_bytes())
        calls = [json.loads(line) for line in self.fixture.log.read_text().splitlines()]
        self.assertEqual(sum(call[:3] == ["toolchain", "producer", "verify-package"]
                             for call in calls), 2 * len(HOSTS) * len(PROFILES))
        self.assertEqual(sum(call[:3] == ["toolchain", "producer", "compare"]
                             for call in calls), len(HOSTS) * len(PROFILES))
        verify_calls = [call for call in calls
                        if call[:3] == ["toolchain", "producer", "verify-package"]]
        self.assertTrue(all(any(item.startswith("--preset=-generic") for item in call)
                            for call in verify_calls if "-generic" in " ".join(call)))
        self.assertTrue(all("--executor-contract-sha256" in call and
                            "--executor-binary-sha256" in call and
                            "--package-measurement-sha256" in call
                            for call in verify_calls))

    def test_existing_output_root_is_not_overwritten(self) -> None:
        root = self.base / "occupied"
        root.mkdir()
        marker = root / "user-data"
        marker.write_bytes(b"preserve")
        result = self.fixture.run(root)
        self.assert_rejected(result, root, release_absent=False)
        self.assertEqual(marker.read_bytes(), b"preserve")

    def test_duplicate_cli_selector_is_rejected_before_output_mutation(self) -> None:
        root = self.base / "duplicate-selector"
        arguments = self.fixture.args(root)
        arguments.extend(("--aros-sha256", self.fixture.aros_sha))
        result = subprocess.run(arguments, capture_output=True, text=True, check=False, timeout=120)
        self.assert_rejected(result, root)
        self.assertIn("repeated command-line option", result.stderr)
        self.assertFalse(root.exists())

    def test_native_output_limit_is_enforced_by_the_real_child(self) -> None:
        executable = self.base / "limited-native"
        executable.write_text(
            "#!/usr/bin/env python3\nimport json, os\n"
            "size = int(os.environ.get('PROBE_OUTPUT_SIZE', '8'))\n"
            "raw = json.dumps({'value': 'x' * size}).encode()\n"
            "while raw:\n    raw = raw[os.write(1, raw):]\n"
        )
        executable.chmod(0o700)
        selected_files = {}
        assembler._record_file(executable, assembler.MAX_RUNTIME, "probe runtime", selected_files)
        output = self.base / "bounded-positive.json"
        result = assembler._run_native({"aros": executable}, output, [], "bounded probe", selected_files)
        self.assertEqual(result["result"], {"value": "x" * 8})
        oversized = self.base / "bounded-negative.json"
        with mock.patch.dict(os.environ, {"PROBE_OUTPUT_SIZE": str(2 * assembler.MAX_NATIVE_RESULT)}):
            with self.assertRaisesRegex(assembler.AssemblyError, "native CLI failed with exit status"):
                assembler._run_native({"aros": executable}, oversized, [], "oversized probe", selected_files)
        self.assertLessEqual(oversized.stat().st_size, assembler.MAX_NATIVE_RESULT)
        self.assertTrue(oversized.with_suffix(".json.stderr.log").is_file())

    def test_native_timeout_terminates_the_owned_child_and_retains_diagnostics(self) -> None:
        executable = self.base / "timeout-native"
        executable.write_text("#!/usr/bin/env python3\nimport time\ntime.sleep(10)\n")
        executable.chmod(0o700)
        selected_files = {}
        assembler._record_file(executable, assembler.MAX_RUNTIME, "timeout runtime", selected_files)
        output = self.base / "timeout-result.json"
        with mock.patch.object(assembler, "NATIVE_TIMEOUT_SECONDS", 0.1):
            with self.assertRaisesRegex(assembler.AssemblyError, "owned process group was terminated"):
                assembler._run_native({"aros": executable}, output, [], "timeout probe", selected_files)
        self.assertTrue(output.is_file())
        self.assertTrue(output.with_suffix(".json.stderr.log").is_file())

    def test_owned_output_cannot_change_before_its_first_recorded_baseline(self) -> None:
        for target in ("compiler-index-lanes.json", "compiler-evidence-fragment.json"):
            with self.subTest(target=target), tempfile.TemporaryDirectory(prefix="compiler-owned-output.") as temporary:
                fixture = Fixture(Path(temporary).resolve())
                root = fixture.base / "operation"
                arguments = assembler._parser().parse_args(fixture.args(root)[3:])
                original_write = assembler._write_owned

                def mutate_after_write(path, raw, label):
                    selector = original_write(path, raw, label)
                    if path.name == target:
                        with path.open("ab") as output:
                            output.write(b" ")
                    return selector

                with mock.patch.dict(os.environ, {"FAKE_AROS_LOG": str(fixture.log)}):
                    with mock.patch.object(assembler, "_write_owned", side_effect=mutate_after_write):
                        with self.assertRaisesRegex(assembler.AssemblyError, "changed after.*owned write"):
                            assembler.assemble(arguments)
                self.assertTrue((root / "release").is_dir())

    def test_native_report_schema_does_not_accept_a_boolean_as_integer_one(self) -> None:
        root = self.base / "boolean-report-schema"
        result = self.fixture.run(root, FAKE_COMPARE_MODE="boolean-receipt-schema")
        self.assert_rejected(result, root)
        self.assertIn("native comparison receipt schema", result.stderr)

    def test_missing_or_swapped_owner_rows_and_self_owner_matrix_are_rejected(self) -> None:
        root = self.base / "missing"
        self.fixture.fragment["compiler_builds"].pop()
        self.fixture.fragment["owner_count"] -= 1
        self.fixture._write_fragment()
        self.assert_rejected(self.fixture.run(root), root)

        with tempfile.TemporaryDirectory(prefix="compiler-owner-swap.") as temporary:
            fixture = Fixture(Path(temporary).resolve())
            fixture.fragment["compiler_builds"][0], fixture.fragment["compiler_builds"][1] = (
                fixture.fragment["compiler_builds"][1], fixture.fragment["compiler_builds"][0])
            fixture._write_fragment()
            root2 = fixture.base / "swapped"
            self.assert_rejected(fixture.run(root2), root2)

        with tempfile.TemporaryDirectory(prefix="compiler-self-owner.") as temporary:
            fixture = Fixture(Path(temporary).resolve())
            fixture.matrix["owners"][0]["job_name"] = JOB_NAME
            (fixture.owner_root / "matrix.json").write_bytes(canonical(fixture.matrix))
            os.chmod(fixture.owner_root / "matrix.json", 0o600)
            root3 = fixture.base / "self-owner"
            self.assert_rejected(fixture.run(root3), root3)

    def test_plan_source_ref_environment_and_native_digest_drift_are_rejected(self) -> None:
        root = self.base / "source-ref-drift"
        self.fixture.fragment["source_ref"] = "refs/heads/forged"
        self.fixture._save_fragment()
        self.assert_rejected(self.fixture.run(root), root)

        with tempfile.TemporaryDirectory(prefix="compiler-input-drift.") as temporary:
            fixture = Fixture(Path(temporary).resolve())
            (fixture.inputs / "source-lock.json").write_bytes(b"changed source-lock\n")
            root2 = fixture.base / "input-drift"
            self.assert_rejected(fixture.run(root2), root2)

        with tempfile.TemporaryDirectory(prefix="compiler-environment-drift.") as temporary:
            fixture = Fixture(Path(temporary).resolve())
            environment = Path(fixture.rows[0]["environment"]["path"])
            environment.write_bytes(b'{"host":"changed"}\n')
            root3 = fixture.base / "environment-drift"
            self.assert_rejected(fixture.run(root3), root3)

        with tempfile.TemporaryDirectory(prefix="compiler-runtime-drift.") as temporary:
            fixture = Fixture(Path(temporary).resolve())
            root4 = fixture.base / "runtime-drift"
            result = fixture.run(root4, **{"FAKE_VERIFY_MODE": "archive-substitution"})
            self.assert_rejected(result, root4)

    def test_native_verify_and_compare_failures_leave_no_staged_release(self) -> None:
        root = self.base / "verify-failure"
        self.assert_rejected(self.fixture.run(root, FAKE_FAIL_VERIFY="1"), root)
        self.assertTrue(root.is_dir())
        self.assertFalse((root / "release").exists())

        with tempfile.TemporaryDirectory(prefix="compiler-compare-failure.") as temporary:
            fixture = Fixture(Path(temporary).resolve())
            root2 = fixture.base / "compare-failure"
            result = fixture.run(root2, FAKE_FAIL_COMPARE="1")
            self.assert_rejected(result, root2)
            self.assertTrue(root2.is_dir(), result.stderr)
            self.assertFalse((root2 / "release").exists())

    def test_native_archive_receipt_measurement_and_compare_receipt_substitution_fail(self) -> None:
        for mode in ("archive-substitution", "receipt-substitution", "measurement-substitution",
                     "build-result-substitution"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix="compiler-verify-substitution.") as temporary:
                fixture = Fixture(Path(temporary).resolve())
                root = fixture.base / "result"
                self.assert_rejected(fixture.run(root, FAKE_VERIFY_MODE=mode), root)

        with tempfile.TemporaryDirectory(prefix="compiler-compare-substitution.") as temporary:
            fixture = Fixture(Path(temporary).resolve())
            root = fixture.base / "result"
            self.assert_rejected(
                fixture.run(root, FAKE_COMPARE_MODE="report-member-substitution"), root
            )

        with tempfile.TemporaryDirectory(prefix="compiler-receipt-sha-substitution.") as temporary:
            fixture = Fixture(Path(temporary).resolve())
            root = fixture.base / "result"
            self.assert_rejected(
                fixture.run(root, FAKE_COMPARE_MODE="response-receipt-sha-substitution"), root
            )

    def test_late_original_observation_or_transport_mutation_blocks_success(self) -> None:
        root = self.base / "late-observation"
        self.assert_rejected(
            self.fixture.run(root, FAKE_VERIFY_MODE="late-observation-mutation"), root
        )

        with tempfile.TemporaryDirectory(prefix="compiler-late-transport.") as temporary:
            fixture = Fixture(Path(temporary).resolve())
            root2 = fixture.base / "late-transport"
            self.assert_rejected(
                fixture.run(root2, FAKE_VERIFY_MODE="late-transport-mutation"), root2,
                release_absent=False,
            )
            self.assertTrue(root2.is_dir())
            self.assertEqual(len(list((root2 / "release").iterdir())),
                             4 * len(HOSTS) * len(PROFILES))


if __name__ == "__main__":
    unittest.main()
