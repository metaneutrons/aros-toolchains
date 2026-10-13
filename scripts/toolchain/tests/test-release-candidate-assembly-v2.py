#!/usr/bin/env python3
"""Focused tests for shared native family-v2 pre-index candidate assembly.

The compiler and SDK retained owner bundles are produced by the existing
synthetic transport fixtures. Their signatures are not authentic; the native
CLI subprocess is a bounded fake that exercises the real process boundary.
"""

from __future__ import annotations

import ast
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


sys.dont_write_bytecode = True
TOOLCHAIN = Path(__file__).resolve().parents[1]
SCRIPT = TOOLCHAIN / "assemble-release-candidate-v2.py"
COMPILER_TEST_PATH = Path(__file__).with_name("test-compiler-candidate-assembly-v2.py")
SDK_SELECTOR_TEST_PATH = Path(__file__).with_name("test-sdk-package-inputs-v2.py")


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


compiler_tests = load_module("combined_candidate_compiler_fixtures", COMPILER_TEST_PATH)
sdk_selector_tests = load_module("combined_candidate_sdk_fixtures", SDK_SELECTOR_TEST_PATH)
compiler = compiler_tests.assembler
sdk_fixture_module = sdk_selector_tests
sdk_assembly = load_module("combined_candidate_sdk_assembly", TOOLCHAIN / "assemble-sdk-candidate-v2.py")
combined = load_module("combined_candidate_assembly_under_test", SCRIPT)

PRODUCER = compiler_tests.PRODUCER
TOOLS = compiler_tests.TOOLS
GROUP = compiler_tests.GROUP
RELEASE_ID = compiler_tests.RELEASE_ID
HOSTS = tuple(compiler._MATRIX.ACTIVE_HOSTS)
# SDK compiler profiles use the same lanes but their native identifier grammar
# does not admit the leading dash used by the compiler-only generic fixture.
compiler_tests.PROFILES = ("generic", "debug")
SDK_SPECS = (("sdk-a", GROUP, "generic"), ("sdk-b", GROUP, "debug"))
MANIFEST_NAME = "toolchain-manifest-v2.schema.json"
TREE_NAME = "tree-digest-v1.fixture.json"
BASE_URL = "https://release.example.invalid/aros/family"


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8") + b"\n"


def _combined_fake_aros() -> str:
    original = compiler_tests.FAKE_AROS
    marker = 'raise SystemExit("unexpected native producer command: " + " ".join(args[:3]))'
    assert original.count(marker) == 1
    additions = r'''
mode = os.environ.get("FAKE_MODE", "")

def mutate_selected_path(env_name, data=b"late mutation\n"):
    target = os.environ.get(env_name)
    if target:
        Path(target).write_bytes(data)

if args[:2] == ["sdk", "verify-package"]:
    identity_path = Path(option("--identity"))
    identity = json.loads(identity_path.read_bytes())
    result = {
        "identity": identity,
        "archive_sha256": option("--archive-sha256"),
        "archive_size": int(option("--archive-size")),
        "tree_sha256": option("--tree-sha256"),
    }
    envelope = {"schema": "aros-sdk-local-stage-v2", "operation": "sdk.verify-package",
                "assurance": "local-byte-consistency-not-release-admission", "result": result}
    sys.stdout.buffer.write(canonical(envelope))
    raise SystemExit(0)

if args[:2] == ["sdk", "sbom"]:
    if mode == "sbom-failure":
        sys.stderr.write("bounded synthetic SBOM failure\n")
        raise SystemExit(23)
    if mode == "oversized-native-output":
        sys.stdout.buffer.write(b"x" * (4 * 1024 * 1024 + 1024))
        sys.stdout.buffer.flush()
        raise SystemExit(0)
    identity_path = Path(option("--identity"))
    identity = json.loads(identity_path.read_bytes())
    output = Path(option("--output"))
    sbom = {"spdxVersion": "SPDX-2.3", "name": identity["sdk_id"],
            "packages": [{"name": identity["sdk_id"]}]}
    raw = canonical(sbom)
    output.write_bytes(raw)
    result_path = str(output)
    result_sha = sha(raw)
    if mode == "sbom-substitute-path":
        result_path = str(output.parent / "substituted.spdx.json")
    elif mode == "sbom-substitute-hash":
        result_sha = "9" * 64
    if mode == "late-owner-transport-mutation":
        mutate_selected_path("FAKE_LATE_TRANSPORT")
    elif mode == "late-compiler-output-mutation":
        mutate_selected_path("FAKE_LATE_COMPILER_OUTPUT")
    elif mode == "late-sdk-output-mutation":
        mutate_selected_path("FAKE_LATE_SDK_OUTPUT")
    elif mode == "late-runtime-mutation":
        mutate_selected_path("FAKE_AROS_RUNTIME")
    envelope = {
        "schema": "aros-sdk-local-stage-v2", "operation": "sdk.sbom",
        "assurance": "local-byte-consistency-not-release-admission",
        "result": {"output": result_path, "sha256": result_sha, "size": len(raw)},
    }
    sys.stdout.buffer.write(canonical(envelope))
    raise SystemExit(0)

if args[:3] == ["toolchain", "producer", "index"]:
    if mode == "index-failure":
        sys.stderr.write("bounded synthetic index failure\n")
        raise SystemExit(24)
    directory = Path(option("--directory"))
    lane_path = Path(option("--lane-inputs"))
    subject_path = Path(option("--subject-manifest"))
    lanes = json.loads(lane_path.read_bytes())
    if lanes.get("schema") != "aros-toolchain-index-lanes-v1" or set(lanes) != {"schema", "lanes", "sdks"}:
        raise SystemExit("invalid combined lane DTO")
    index_path = directory / "toolchain-index-v2.json"
    index_raw = canonical({"schema": "fixture-native-family-index-v2",
                           "release_id": option("--release-id")})
    index_path.write_bytes(index_raw)
    subject_lines = [path.name.encode("utf-8") for path in sorted(directory.iterdir())]
    subject_raw = b"\n".join(subject_lines) + b"\n"
    subject_path.write_bytes(subject_raw)
    reported_index = str(index_path)
    reported_sha = sha(index_raw)
    if mode == "index-substitute-path":
        reported_index = str(directory / "substituted-index.json")
    elif mode == "index-substitute-hash":
        reported_sha = "8" * 64
    result = {
        "schema": "aros-toolchain-producer-stage-v2", "operation": "index",
        "release_format": "family-v2", "stage": "pre-attestation",
        "release_id": option("--release-id"), "index": reported_index,
        "index_sha256": reported_sha, "subject_manifest": str(subject_path),
        "subject_manifest_sha256": sha(subject_raw), "subject_manifest_size": len(subject_raw),
        "subject_count": len(subject_lines), "inventory_count": len(subject_lines) + 2,
        "lane_count": len(lanes["lanes"]), "sdk_count": len(lanes["sdks"]),
    }
    if mode == "index-boolean-count":
        result["lane_count"] = True
    if mode == "late-source-context-mutation":
        mutate_selected_path("FAKE_LATE_SOURCE_CONTEXT")
    sys.stdout.buffer.write(canonical(result))
    raise SystemExit(0)

'''
    return original.replace(marker, additions + "\n" + marker)


class CombinedFixture:
    def __init__(self, base: Path, *, source_ref: str = compiler_tests.SOURCE_REF) -> None:
        self.base = base.resolve()
        self.base.mkdir(parents=True, exist_ok=True)
        self.fake_source = _combined_fake_aros()
        self.compiler_fixture = None
        original_make_plan = compiler_tests.Fixture._make_plan_and_inputs
        original_make_native = compiler_tests.Fixture._make_native_executable

        def make_plan_and_inputs(fixture):
            original_make_plan(fixture)
            lock_raw = canonical({"family": "llvm"})
            lock_path = fixture.inputs / fixture.group["source_lock"]["file"]
            lock_path.write_bytes(lock_raw)
            fixture.group["source_lock"]["sha256"] = digest(lock_raw)
            fixture.collection["groups"][0]["source_lock"] = copy.deepcopy(
                fixture.group["source_lock"]
            )
            collection_raw = canonical(fixture.collection)
            fixture.collection_path.write_bytes(collection_raw)
            fixture.inputs_sha = digest(collection_raw)
            fixture.plan["groups"] = [copy.deepcopy(fixture.group)]
            fixture.plan["inputs_sha256"] = fixture.inputs_sha
            fixture.plan_raw = canonical(fixture.plan)
            fixture.plan_path.write_bytes(fixture.plan_raw)
            fixture.plan_sha = digest(fixture.plan_raw)

        def make_native(fixture):
            fixture.aros = fixture.base / "fake-aros"
            fixture.aros.write_text(self.fake_source, encoding="utf-8")
            fixture.aros.chmod(0o700)
            fixture.aros_sha = digest(fixture.aros.read_bytes())
            fixture.log = fixture.base / "native.log"

        with (mock.patch.object(compiler_tests.Fixture, "_make_plan_and_inputs",
                                make_plan_and_inputs),
              mock.patch.object(compiler_tests.Fixture, "_make_native_executable", make_native)):
            (self.base / "owners").mkdir(mode=0o700)
            self.compiler_fixture = compiler_tests.Fixture(
                self.base / "owners", source_ref=source_ref
            )
        assert self.compiler_fixture is not None
        self._make_sdk_fixture()
        self._join_input_collection()
        self._make_support()

    def _make_sdk_fixture(self) -> None:
        sdk_fixture_module.SDK_SPECS = SDK_SPECS
        compiler_fixture = self.compiler_fixture

        def make_plan(fixture):
            group = copy.deepcopy(compiler_fixture.group)
            for reference in (group["recipe"], group["source_lock"], group["profiles"]):
                src = compiler_fixture.inputs / reference["file"]
                (fixture.inputs / reference["file"]).write_bytes(src.read_bytes())
            sdks = []
            for index, (sdk_id, group_id, profile) in enumerate(SDK_SPECS):
                identity_path = fixture.inputs / f"{sdk_id}-identity.json"
                raw_identity = sdk_fixture_module.stage.canonical_json(
                    fixture.identities[sdk_id]
                )
                identity_path.write_bytes(raw_identity)
                sdks.append({
                    "id": sdk_id,
                    "identity": {"file": identity_path.name, "sha256": digest(raw_identity)},
                    "source_preset": f"source-{index}",
                    "compiler_profiles": [{"group_id": group_id, "profile": profile}],
                })
            lanes = copy.deepcopy(compiler_fixture.lanes)
            group_projection = [{
                "id": group["group_id"], "recipe": group["recipe"],
                "source_lock": group["source_lock"], "profiles": group["profiles"],
            }]
            collection = {
                "schema": "aros-toolchain-release-inputs-v2",
                "producer_commit": PRODUCER, "tools_commit": TOOLS,
                "hosts": list(HOSTS), "groups": group_projection, "sdks": sdks,
            }
            collection_raw = canonical(collection)
            fixture.collection = fixture.inputs / "toolchain-release-inputs-v2.json"
            fixture.collection.write_bytes(collection_raw)
            fixture.inputs_sha256 = digest(collection_raw)
            plan = {
                "schema": "aros-toolchain-producer-stage-v2", "operation": "release-plan",
                "release_format": "family-v2", "assurance": "input-binding-only",
                "inputs_sha256": fixture.inputs_sha256, "producer_commit": PRODUCER,
                "tools_commit": TOOLS, "hosts": list(HOSTS), "groups": [group],
                "lane_count": len(lanes), "lanes": lanes, "sdks": sdks,
                "sdk_count": len(sdks),
            }
            return sdk_fixture_module.stage.canonical_json(plan)

        with mock.patch.object(sdk_fixture_module.Fixture, "_make_plan", make_plan):
            (self.base / "sdk-owners").mkdir(mode=0o700)
            self.sdk_fixture = sdk_fixture_module.Fixture(self.base / "sdk-owners")

    def _join_input_collection(self) -> None:
        compiler_fixture = self.compiler_fixture
        sdk_fixture = self.sdk_fixture
        plan = copy.deepcopy(compiler_fixture.plan)
        sdk_plan = json.loads(sdk_fixture.plan)
        sdks = sdk_plan["sdks"]
        for sdk in sdks:
            identity_path = sdk_fixture.inputs / sdk["identity"]["file"]
            target = compiler_fixture.inputs / identity_path.name
            target.write_bytes(identity_path.read_bytes())
        collection = copy.deepcopy(compiler_fixture.collection)
        collection["sdks"] = sdks
        collection_raw = canonical(collection)
        compiler_fixture.collection_path.write_bytes(collection_raw)
        compiler_fixture.collection = collection
        compiler_fixture.inputs_sha = digest(collection_raw)
        plan["inputs_sha256"] = compiler_fixture.inputs_sha
        plan["sdks"] = sdks
        plan["sdk_count"] = len(sdks)
        compiler_fixture.plan = plan
        compiler_fixture.plan_raw = canonical(plan)
        compiler_fixture.plan_path.write_bytes(compiler_fixture.plan_raw)
        compiler_fixture.plan_sha = digest(compiler_fixture.plan_raw)

        matrix = copy.deepcopy(compiler_fixture.matrix)
        matrix["plan_sha256"] = compiler_fixture.plan_sha
        matrix["inputs_sha256"] = compiler_fixture.inputs_sha
        (compiler_fixture.owner_root / "matrix.json").write_bytes(canonical(matrix))
        compiler_fixture.matrix = matrix
        compiler_fixture.fragment["plan_sha256"] = compiler_fixture.plan_sha
        compiler_fixture.fragment["inputs_sha256"] = compiler_fixture.inputs_sha
        compiler_fixture._save_fragment()
        compiler_fixture._write_required_paths()

        sdk_fixture.plan = compiler_fixture.plan_raw
        sdk_fixture.plan_sha256 = compiler_fixture.plan_sha
        sdk_fixture.inputs_sha256 = compiler_fixture.inputs_sha
        sdk_fixture.fragment["plan_sha256"] = compiler_fixture.plan_sha
        sdk_fixture.fragment["inputs_sha256"] = compiler_fixture.inputs_sha
        sdk_fixture.fragment["source_context_sha256"] = compiler_fixture.context_sha
        sdk_fixture.fragment["source_producer_commit"] = compiler_fixture.context["producer_commit"]
        sdk_fixture.fragment["source_workflow"] = compiler_fixture.context["workflow"]
        sdk_fixture.fragment["source_ref"] = compiler_fixture.context["source_ref"]
        sdk_fixture.fragment["aros_sha256"] = compiler_fixture.aros_sha
        sdk_fixture.write_fragment()

    def _make_support(self) -> None:
        self.support = self.base / "tools" / "crates" / "aros-common" / "tests" / "fixtures"
        self.support.mkdir(parents=True)
        self.manifest_schema = self.support / MANIFEST_NAME
        self.tree_fixture = self.support / TREE_NAME
        self.manifest_schema.write_bytes(canonical({"$schema": "fixture-manifest-v2"}))
        self.tree_fixture.write_bytes(canonical({"schema": "fixture-tree-digest-v1"}))
        (self.support / "unselected-fixture.json").write_bytes(b"extra committed fixture\n")
        self.manifest_sha = digest(self.manifest_schema.read_bytes())
        self.tree_sha = digest(self.tree_fixture.read_bytes())

    def command(self, root: Path) -> list[str]:
        compiler_fixture = self.compiler_fixture
        sdk_fixture = self.sdk_fixture
        return [
            sys.executable, "-B", str(SCRIPT),
            "--aros", str(compiler_fixture.aros), "--aros-sha256", compiler_fixture.aros_sha,
            "--plan", str(compiler_fixture.plan_path), "--plan-sha256", compiler_fixture.plan_sha,
            "--inputs-dir", str(compiler_fixture.inputs), "--inputs-sha256", compiler_fixture.inputs_sha,
            "--producer-commit", PRODUCER, "--tools-commit", TOOLS,
            "--source-context", str(compiler_fixture.context_path),
            "--source-context-sha256", compiler_fixture.context_sha,
            "--compiler-fragment", str(compiler_fixture.fragment_path),
            "--compiler-fragment-sha256", digest(compiler_fixture.fragment_path.read_bytes()),
            "--compiler-owner-root", str(compiler_fixture.owner_root),
            "--sdk-fragment", str(sdk_fixture.fragment_path),
            "--sdk-fragment-sha256", digest(sdk_fixture.fragment_path.read_bytes()),
            "--sdk-owner-root", str(sdk_fixture.owner_root),
            "--required-paths", str(compiler_fixture.required_path),
            "--required-paths-sha256", compiler_fixture.required_sha,
            "--support-dir", str(self.support),
            "--manifest-schema-sha256", self.manifest_sha,
            "--tree-fixture-sha256", self.tree_sha,
            "--release-id", RELEASE_ID, "--base-url", BASE_URL,
            "--forbidden-prefix", "/synthetic/build-root-a",
            "--forbidden-prefix", "/synthetic/build-root-b",
            "--root", str(root),
        ]

    def run(self, root: Path, *, mode: str = "", extra: list[str] | None = None,
            provider_responses: list[dict] | None = None,
            replace: dict[str, str] | None = None,
            environment: dict[str, str] | None = None,
            ) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ)
        env.update(compiler_tests.provider_environment(
            self.compiler_fixture.base, self.compiler_fixture.context,
            responses=provider_responses,
        ))
        env.update({
            "PYTHONDONTWRITEBYTECODE": "1",
            "FAKE_AROS_LOG": str(self.compiler_fixture.log),
            "FAKE_MODE": mode,
            "FAKE_OPERATION_ROOT": str(root),
            "FAKE_AROS_RUNTIME": str(self.compiler_fixture.aros),
            "FAKE_LATE_SOURCE_CONTEXT": str(self.compiler_fixture.context_path),
        })
        env.update(environment or {})
        first_row = self.compiler_fixture.rows[0]
        observation = Path(first_row["observation"]["path"])
        env["FAKE_LATE_TRANSPORT"] = str(observation.parent / "transport" / "payload.zip")
        env["FAKE_LATE_COMPILER_OUTPUT"] = str(root / "compiler-stage" / "compiler-index-lanes.json")
        env["FAKE_LATE_SDK_OUTPUT"] = str(root / "sdk-stage" / "native" / "verify-sdk-a.json")
        arguments = self.command(root)
        for option, value in (replace or {}).items():
            arguments[arguments.index(option) + 1] = value
        return subprocess.run([*arguments, *(extra or [])], capture_output=True,
                              text=True, env=env, check=False, timeout=240)


class ReleaseCandidateAssemblyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="release-candidate-assembly-v2.")
        self.base = Path(self.temporary.name).resolve()
        self.fixture = CombinedFixture(self.base / "fixture")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def assert_failed(self, result: subprocess.CompletedProcess[str], *, prefix: str =
                      "release candidate pre-index assembly failed:") -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(result.stdout, "")
        self.assertIn(prefix, result.stderr)

    def test_complete_native_plan_assembles_one_shared_preindex_inventory(self) -> None:
        root = self.base / "candidate"
        result = self.fixture.run(root)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        summary = json.loads(result.stdout)
        self.assertEqual(summary["schema"], "aros-toolchain-release-candidate-assembly-v2")
        self.assertEqual(summary["operation"], "shared-native-pre-index-inventory")
        self.assertEqual(summary["assurance"], "complete-native-pre-index-inventory-no-admission")
        self.assertEqual(summary["stage"], "pre-attestation")
        self.assertEqual(summary["release_format"], "family-v2")
        self.assertEqual(summary["scope"], {
            "sdk_factory_execution_complete": False,
            "release_admission": False, "publication": False,
        })
        self.assertEqual(summary["counts"]["lane_count"], len(compiler._MATRIX.ACTIVE_HOSTS) * 2)
        self.assertEqual(summary["counts"]["sdk_count"], 2)
        inventory = summary["release_inventory"]
        release = root / "release"
        self.assertEqual({path.name for path in release.iterdir()}, set(inventory))
        self.assertIn("toolchain-index-v2.json", inventory)
        self.assertIn("toolchain-release-inputs-v2.json", inventory)
        self.assertIn(MANIFEST_NAME, inventory)
        self.assertIn(TREE_NAME, inventory)
        self.assertEqual(len(summary["outputs"]["sdk_sboms"]), 2)
        self.assertEqual((root / "compiler-stage" / "compiler-index-lanes.json").exists(), True)
        combined_lanes = json.loads(Path(summary["outputs"]["lane_inputs"]["path"]).read_bytes())
        self.assertEqual(set(combined_lanes), {"schema", "lanes", "sdks"})
        self.assertEqual(combined_lanes["schema"], "aros-toolchain-index-lanes-v1")
        self.assertEqual(len(combined_lanes["lanes"]), summary["counts"]["lane_count"])
        self.assertEqual(set(combined_lanes["sdks"]), {"sdk-a", "sdk-b"})
        self.assertFalse(any(path.name in {"plan.json", "matrix.json"} for path in release.iterdir()))
        for name, expected in inventory.items():
            raw = (release / name).read_bytes()
            self.assertEqual({"sha256": digest(raw), "size": len(raw)}, expected)
        for selector in (summary["outputs"]["index"], summary["outputs"]["lane_inputs"],
                         summary["outputs"]["subject_manifest"],
                         summary["outputs"]["native_index_result"]):
            path = Path(selector["path"])
            self.assertEqual({"sha256": digest(path.read_bytes()), "size": path.stat().st_size},
                             {"sha256": selector["sha256"], "size": selector["size"]})
        sdk_calls = [json.loads(line) for line in self.fixture.compiler_fixture.log.read_text().splitlines()]
        sbom_calls = [args for args in sdk_calls if args[:2] == ["sdk", "sbom"]]
        index_calls = [args for args in sdk_calls if args[:3] == ["toolchain", "producer", "index"]]
        self.assertEqual(len(sbom_calls), 2)
        self.assertEqual(len(index_calls), 1)
        self.assertNotIn("--format", sbom_calls[0])
        self.assertIn("--stage", index_calls[0])
        self.assertEqual(index_calls[0][index_calls[0].index("--stage") + 1], "pre-attestation")
        self.assertEqual(index_calls[0][index_calls[0].index("--format") + 1], "json")

    def test_tag_push_and_manual_tag_dispatch_use_the_exact_provider_event(self) -> None:
        fixture = CombinedFixture(self.base / "tag-events", source_ref=compiler_tests.TAG_REF)
        for index, event in enumerate(("push", "workflow_dispatch")):
            with self.subTest(event=event):
                context = fixture.compiler_fixture.context
                responses = [compiler_tests.provider_run(context, event)] * 2
                result = fixture.run(
                    self.base / f"tag-event-{index}", provider_responses=responses
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(len(result.stdout.splitlines()), 1)
                summary = json.loads(result.stdout)
                self.assertEqual(
                    summary["schema"], "aros-toolchain-release-candidate-assembly-v2"
                )

    def test_changed_provider_event_fails_at_the_final_output_barrier(self) -> None:
        fixture = CombinedFixture(
            self.base / "fixture-provider-drift", source_ref=compiler_tests.TAG_REF
        )
        context = fixture.compiler_fixture.context
        result = fixture.run(
            self.base / "changed-provider-event",
            provider_responses=[
                compiler_tests.provider_run(context, "workflow_dispatch"),
                compiler_tests.provider_run(context, "workflow_dispatch"),
                compiler_tests.provider_run(context, "workflow_dispatch"),
                compiler_tests.provider_run(context, "push"),
            ],
        )
        self.assert_failed(result)
        self.assertIn("source run event changed during combined assembly", result.stderr)
        self.assertEqual(
            fixture.compiler_fixture.log.parent.joinpath("fake-gh-events").read_text().splitlines(),
            ["workflow_dispatch", "workflow_dispatch", "workflow_dispatch", "push"],
        )
        self.assertTrue((self.base / "changed-provider-event").is_dir())

    def test_provider_failure_and_identity_mismatch_fail_before_root_creation(self) -> None:
        root = self.base / "provider-failure"
        failed = self.fixture.run(root, environment={"FAKE_GH_FAIL": "1"})
        self.assert_failed(failed)
        self.assertFalse(root.exists())

        context = self.fixture.compiler_fixture.context
        wrong_identity = compiler_tests.provider_run(context)
        wrong_identity["id"] += 1
        mismatch_root = self.base / "provider-identity-mismatch"
        mismatch = self.fixture.run(
            mismatch_root, provider_responses=[wrong_identity]
        )
        self.assert_failed(mismatch)
        self.assertFalse(mismatch_root.exists())

    def test_source_context_digest_and_late_mutation_fail_without_json(self) -> None:
        wrong_digest_root = self.base / "source-context-digest-mismatch"
        wrong_digest = self.fixture.run(
            wrong_digest_root, replace={"--source-context-sha256": "0" * 64}
        )
        self.assert_failed(wrong_digest)
        self.assertFalse(wrong_digest_root.exists())

        fixture = CombinedFixture(self.base / "fixture-source-context-mutation")
        mutation_root = self.base / "source-context-mutation"
        changed = fixture.run(mutation_root, mode="late-source-context-mutation")
        self.assert_failed(changed)
        self.assertIn("source-context.json", changed.stderr)
        self.assertTrue(mutation_root.is_dir())
        self.assertTrue((mutation_root / "compiler-stage").is_dir())

    def test_preserves_existing_root_rejects_duplicate_scalars_and_binds_support(self) -> None:
        existing = self.base / "existing"
        existing.mkdir()
        sentinel = existing / "sentinel"
        sentinel.write_bytes(b"preserve me")
        result = self.fixture.run(existing)
        self.assert_failed(result)
        self.assertEqual(sentinel.read_bytes(), b"preserve me")

        duplicate_root = self.base / "duplicate-option"
        command = self.fixture.command(duplicate_root)
        command.extend(["--base-url", BASE_URL])
        duplicate = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assert_failed(duplicate)
        self.assertFalse(duplicate_root.exists())

        support_root = self.base / "wrong-support-digest"
        wrong_digest = subprocess.run(
            [*self.fixture.command(support_root), "--manifest-schema-sha256", "0" * 64],
            capture_output=True, text=True, check=False,
        )
        self.assert_failed(wrong_digest)
        self.assertFalse(support_root.exists())

    def test_missing_and_extra_package_members_fail_before_a_success_summary(self) -> None:
        compiler_row = self.fixture.compiler_fixture.rows[0]
        compiler_payload = Path(compiler_row["observation"]["path"]).parent / "payload" / "package"
        archive = next(compiler_payload.glob("*.tar.xz"))
        archive.unlink()
        missing = self.fixture.run(self.base / "missing-package")
        self.assert_failed(missing)
        self.assertFalse((self.base / "missing-package").exists())

        extra_fixture = CombinedFixture(self.base / "fixture-extra-package")
        sdk_source = next(iter(extra_fixture.sdk_fixture.rows))
        sdk_package_dir = Path(sdk_source["package_dir"])
        (sdk_package_dir / "unexpected-extra.bin").write_bytes(b"unexpected\n")
        extra = extra_fixture.run(self.base / "extra-package")
        self.assert_failed(extra)

    def test_casefold_collision_rejected_by_the_shared_copy_boundary(self) -> None:
        source = self.base / "one.tar.xz"
        source.write_bytes(b"selected bytes\n")
        release = self.base / "copy-target"
        release.mkdir()
        claimed = {"one.tar.xz": "One.tar.xz"}
        with self.assertRaises(combined.AssemblyError):
            combined._copy_to_release(source, release / "one.tar.xz",
                                      {"sha256": digest(source.read_bytes()),
                                       "size": source.stat().st_size},
                                      release, claimed, {})
        self.assertEqual(list(release.iterdir()), [])

    def test_native_sbom_and_index_failures_or_substitutions_are_closed(self) -> None:
        for mode in ("sbom-failure", "sbom-substitute-path", "sbom-substitute-hash",
                     "index-failure", "index-substitute-path", "index-substitute-hash",
                     "index-boolean-count"):
            with self.subTest(mode=mode):
                root = self.base / f"reject-{mode}"
                result = self.fixture.run(root, mode=mode)
                self.assert_failed(result)
                self.assertTrue(root.exists(), "partial stages remain available for diagnosis")
                self.assertFalse((root / "release" / "checksums.sha256").exists())
                self.assertFalse((root / "release" / "provenance.json").exists())

    def test_late_original_transport_and_held_stage_output_mutations_fail(self) -> None:
        for mode in ("late-owner-transport-mutation", "late-compiler-output-mutation",
                     "late-sdk-output-mutation"):
            with self.subTest(mode=mode):
                fixture = CombinedFixture(self.base / f"fixture-{mode}")
                result = fixture.run(self.base / f"reject-{mode}", mode=mode)
                self.assert_failed(result)

    def test_runtime_mutation_during_native_sbom_is_detected(self) -> None:
        fixture = CombinedFixture(self.base / "fixture-runtime")
        result = fixture.run(self.base / "reject-runtime", mode="late-runtime-mutation")
        self.assert_failed(result)

    def test_native_child_output_is_file_bounded(self) -> None:
        root = self.base / "bounded-output"
        result = self.fixture.run(root, mode="oversized-native-output")
        self.assert_failed(result)
        native_results = list((root / "native").glob("sbom-*.json"))
        self.assertTrue(native_results)
        self.assertLessEqual(native_results[0].stat().st_size, combined.MAX_NATIVE_OUTPUT)


if __name__ == "__main__":
    unittest.main()
