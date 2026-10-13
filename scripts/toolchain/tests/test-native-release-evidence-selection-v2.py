#!/usr/bin/env python3
"""Process tests for the pure native release-evidence DTO selector.

All compiler records and SDK signatures are synthetic. Success means only that
the selector joins the declared byte evidence into the closed Rust DTO; it
does not mean a real signature, compiler execution, package, or native index
was authenticated or verified.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


TOOLCHAIN = Path(__file__).resolve().parents[1]
SCRIPT = TOOLCHAIN / "select-native-release-evidence-v2.py"
SELECTOR_SPEC = importlib.util.spec_from_file_location(
    "native_release_evidence_selector_under_test", SCRIPT
)
assert SELECTOR_SPEC is not None and SELECTOR_SPEC.loader is not None
selector = importlib.util.module_from_spec(SELECTOR_SPEC)
sys.modules[SELECTOR_SPEC.name] = selector
SELECTOR_SPEC.loader.exec_module(selector)

SDK_TEST_PATH = Path(__file__).with_name("test-sdk-package-inputs-v2.py")
SDK_TEST_SPEC = importlib.util.spec_from_file_location(
    "native_release_evidence_sdk_fixture", SDK_TEST_PATH
)
assert SDK_TEST_SPEC is not None and SDK_TEST_SPEC.loader is not None
sdk_tests = importlib.util.module_from_spec(SDK_TEST_SPEC)
sys.modules[SDK_TEST_SPEC.name] = sdk_tests
SDK_TEST_SPEC.loader.exec_module(sdk_tests)
COMPILER_TEST_PATH = Path(__file__).with_name("test-compiler-candidate-assembly-v2.py")
COMPILER_TEST_SPEC = importlib.util.spec_from_file_location(
    "native_release_evidence_compiler_fixtures", COMPILER_TEST_PATH
)
assert COMPILER_TEST_SPEC is not None and COMPILER_TEST_SPEC.loader is not None
compiler_tests = importlib.util.module_from_spec(COMPILER_TEST_SPEC)
sys.modules[COMPILER_TEST_SPEC.name] = compiler_tests
COMPILER_TEST_SPEC.loader.exec_module(compiler_tests)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8") + b"\n"


def write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    if path.is_file():
        os.chmod(path, 0o600)


def measured(path: Path) -> dict:
    raw = path.read_bytes()
    return {"sha256": digest(raw), "size": len(raw)}


class Fixture:
    def __init__(self, base: Path, *, source_ref: str = "refs/heads/main") -> None:
        self.base = base.resolve()
        self.sdk = sdk_tests.Fixture(self.base)
        self._bind_valid_plan_documents()
        self.source_context = {
            "repository": "example/project", "repository_id": 7890,
            "producer_commit": sdk_tests.PRODUCER, "source_ref": source_ref,
            "workflow": self.sdk.fragment["source_workflow"],
            "run_id": 321456, "run_attempt": 2,
        }
        self.source_context_raw = canonical(self.source_context)
        self.source_context_sha256 = digest(self.source_context_raw)
        self.source_context_path = self.base / "source-context.json"
        write(self.source_context_path, self.source_context_raw)
        self.sdk.fragment["source_context_sha256"] = self.source_context_sha256
        self.sdk.fragment["source_producer_commit"] = self.source_context["producer_commit"]
        self.sdk.fragment["source_workflow"] = self.source_context["workflow"]
        self.sdk.fragment["source_ref"] = self.source_context["source_ref"]
        self.sdk.write_fragment()
        compiler_tests.install_fake_gh(self.base)
        self.compiler_root = self.base / "compiler-candidate"
        self.compiler_root.mkdir(mode=0o700)
        self.native_dir = self.compiler_root / "native"
        self.native_dir.mkdir(mode=0o700)
        self.reports_dir = self.compiler_root / "reports"
        self.reports_dir.mkdir(mode=0o700)
        self._write_compiler_candidate()
        self.index_path = self.base / "pre-index.json"
        write(self.index_path, canonical(self.index))

    def _bind_valid_plan_documents(self) -> None:
        stage = sdk_tests.stage
        plan = json.loads(self.sdk.plan)
        collection = json.loads(self.sdk.collection.read_bytes())
        for group in plan["groups"]:
            for field in ("recipe", "profiles"):
                document = {
                    "schema": f"fixture-{field}-v1",
                    "group_id": group["group_id"],
                    "profiles": [lane["target_profile"] for lane in plan["lanes"]
                                 if lane["group_id"] == group["group_id"]],
                }
                raw = canonical(document)
                write(self.sdk.inputs / group[field]["file"], raw)
                group[field]["sha256"] = digest(raw)
        collection["groups"] = [
            {"id": group["group_id"], "recipe": group["recipe"],
             "source_lock": group["source_lock"], "profiles": group["profiles"]}
            for group in plan["groups"]
        ]
        collection_raw = canonical(collection)
        write(self.sdk.collection, collection_raw)
        plan["inputs_sha256"] = digest(collection_raw)
        plan_raw = canonical(plan)
        write(self.sdk.plan_path, plan_raw)
        self.sdk.collection_raw = collection_raw
        self.sdk.inputs_sha256 = digest(collection_raw)
        self.sdk.plan = plan_raw
        self.sdk.plan_sha256 = digest(plan_raw)
        self.sdk.fragment["plan_sha256"] = self.sdk.plan_sha256
        self.sdk.fragment["inputs_sha256"] = self.sdk.inputs_sha256
        self.sdk.write_fragment()
        self.plan = plan

    def _write_compiler_candidate(self) -> None:
        source_context_sha = self.sdk.fragment["source_context_sha256"]
        runtime_sha = self.sdk.fragment["aros_sha256"]
        release_id = "fixture-release-2026"
        bindings = {
            "aros_sha256": runtime_sha,
            "plan_sha256": self.sdk.plan_sha256,
            "inputs_sha256": self.sdk.inputs_sha256,
            "fragment_sha256": "1" * 64,
            "required_paths_sha256": "2" * 64,
            "source_context_sha256": source_context_sha,
            "producer_commit": sdk_tests.PRODUCER,
            "tools_commit": sdk_tests.TOOLS,
            "release_id": release_id,
        }
        compiler_assets = {}
        compiler_lanes = {}
        index_artifacts = []

        for lane_index, lane in enumerate(self.plan["lanes"]):
            key = (lane["group_id"], lane["host"], lane["target_profile"])
            asset = f"candidate-{key[0]}-{key[1]}-{key[2]}.tar.xz"
            archive_raw = f"synthetic archive bytes for {key!r}\n".encode()
            archive_sha = digest(archive_raw)
            group = next(item for item in self.plan["groups"]
                         if item["group_id"] == lane["group_id"])
            artifact = {
                "group_id": lane["group_id"], "asset": asset,
                "sha256": archive_sha, "size": len(archive_raw),
                "host": lane["host"], "target_profile": lane["target_profile"],
                "target_triple": "i686-aros", "source_commit": group["source_commit"],
                "compiler": {"family": "synthetic-fixture"},
                "tree_sha256": sdk_tests.TREE_DIGEST, "enabled": True,
                "strip_components": 1, "required_paths": ["bin/compiler"],
            }
            index_artifacts.append(artifact)

            environment = {"CC": "fixture-compiler", "LANE": asset}
            compiler_lanes[asset] = {
                "build_environment": environment,
                "required_paths": artifact["required_paths"],
            }
            builds = []
            for copy_index, copy_id in enumerate(("a", "b")):
                owner = self.compiler_root / "owners" / f"owner-{lane_index}-{copy_id}"
                readback = owner / "readback"
                payload = readback / "payload"
                evidence_dir = payload / "evidence"
                package_dir = payload / "package"
                transport_dir = readback / "transport"
                evidence_dir.mkdir(parents=True, mode=0o700)
                package_dir.mkdir(mode=0o700)
                transport_dir.mkdir(mode=0o700)
                write(package_dir / asset, archive_raw)
                manifest = {
                    "schema": 2, "release_id": release_id, "host": lane["host"],
                    "target_profile": lane["target_profile"],
                    "source_commit": group["source_commit"],
                    "producer_commit": sdk_tests.PRODUCER, "tools_commit": sdk_tests.TOOLS,
                    "source_lock_sha256": group["source_lock"]["sha256"],
                    "profiles_sha256": group["profiles"]["sha256"],
                    "tree_sha256": sdk_tests.TREE_DIGEST,
                }
                write(package_dir / f"{asset}.manifest.json", canonical(manifest))
                write(package_dir / f"{asset}.sha256",
                      f"{archive_sha}  {asset}\n".encode())
                write(package_dir / f"{asset}.spdx.json",
                      canonical({"spdxVersion": "SPDX-2.3", "name": asset}))

                build_result_raw = canonical({"fixture": "build-result", "copy": copy_id})
                environment_raw = canonical(environment)
                measurement_raw = canonical({"fixture": "measurement", "copy": copy_id})
                write(evidence_dir / "build-result.json", build_result_raw)
                write(evidence_dir / "environment.json", environment_raw)
                write(evidence_dir / "measurement.json", measurement_raw)
                write(evidence_dir / "environment-result.json", canonical({"ok": True}))
                write(evidence_dir / "package-result.json", canonical({"ok": True}))
                write(evidence_dir / "package-verify.json", canonical({"ok": True}))

                transport_bytes = {
                    "origin.json": canonical({"fixture": "origin", "copy": copy_id}),
                    "selection.json": canonical({"fixture": "selection", "copy": copy_id}),
                    "payload.zip": f"synthetic retained payload {copy_id}\n".encode(),
                    "origin.sigstore.json": canonical({"fixture": "synthetic signature"}),
                }
                for name, raw in transport_bytes.items():
                    write(transport_dir / name, raw)

                contract_sha = f"{lane_index + 1:064x}"
                binary_sha = f"{lane_index + 101:064x}"
                job_id = 50_000 + lane_index * 2 + copy_index
                original_native = {
                    "schema": "aros-toolchain-producer-stage-v1",
                    "operation": "verify-package", "sha256": archive_sha,
                    "size": len(archive_raw), "manifest": manifest,
                }
                observation = {
                    "schema": "aros-toolchain-original-owner-observation-v2",
                    "group": lane["group_id"], "host": lane["host"],
                    "target_profile": lane["target_profile"], "copy": copy_id,
                    "release_id": release_id, "reader_runtime_sha256": runtime_sha,
                    "recipe_file_sha256": group["recipe"]["sha256"],
                    "source_lock_sha256": group["source_lock"]["sha256"],
                    "profiles_sha256": group["profiles"]["sha256"],
                    "source_selection_sha256": digest(transport_bytes["selection.json"]),
                    "build_result_sha256": digest(build_result_raw),
                    "environment_sha256": digest(environment_raw),
                    "measurement_sha256": digest(measurement_raw),
                    "executor_contract_sha256": contract_sha,
                    "executor_binary_sha256": binary_sha,
                    "original_identity": {
                        "source_commit": group["source_commit"],
                        "producer_commit": sdk_tests.PRODUCER,
                        "tools_commit": sdk_tests.TOOLS,
                        "host": lane["host"], "target_profile": lane["target_profile"],
                    },
                    "transport": {
                        "origin_sha256": digest(transport_bytes["origin.json"]),
                        "selection_sha256": digest(transport_bytes["selection.json"]),
                        "raw_zip_sha256": digest(transport_bytes["payload.zip"]),
                    },
                    "native": original_native,
                }
                write(readback / "observation.json", canonical(observation))
                write(readback / "native-verification.json", canonical(original_native))

                fresh_native_path = self.native_dir / f"verify-{lane_index}-{copy_id}.json"
                write(fresh_native_path, canonical(original_native))
                builds.append({
                    "copy": copy_id, "original_job_id": job_id,
                    "origin_sha256": digest(transport_bytes["origin.json"]),
                    "selection_sha256": digest(transport_bytes["selection.json"]),
                    "payload_zip_sha256": digest(transport_bytes["payload.zip"]),
                    "origin_sigstore_sha256": digest(transport_bytes["origin.sigstore.json"]),
                    "package": {"directory": str(package_dir), "archive": archive_sha,
                                "archive_sha256": archive_sha,
                                "archive_size": len(archive_raw)},
                    "measurement": {"path": str(evidence_dir / "measurement.json"),
                                    "sha256": digest(measurement_raw)},
                    "executor": {"contract_sha256": contract_sha,
                                 "binary_sha256": binary_sha},
                    "build_result_sha256": digest(build_result_raw),
                    "original_observation": {
                        "path": str(readback / "observation.json"),
                        "sha256": digest(canonical(observation)),
                    },
                    "original_native_verification": {
                        "path": str(readback / "native-verification.json"),
                        "sha256": digest(canonical(original_native)),
                    },
                    "native_verification": {
                        "path": str(fresh_native_path),
                        "sha256": digest(canonical(original_native)),
                    },
                })

            comparison_path = self.reports_dir / f"compare-{lane_index}.json"
            comparison_raw = canonical({
                "schema": 1, "operation": "compare", "byte_identical": True,
            })
            write(comparison_path, comparison_raw)
            compiler_assets[asset] = {
                "group_id": lane["group_id"], "host": lane["host"],
                "target_profile": lane["target_profile"], "builds": builds,
                "comparison": {"selectedFile": {
                    "path": str(comparison_path), "sha256": digest(comparison_raw),
                }},
            }

        self.evidence_path = self.compiler_root / "compiler-evidence-fragment.json"
        self.lanes_path = self.compiler_root / "compiler-index-lanes.json"
        self.evidence = {
            "schema": "aros-toolchain-compiler-evidence-fragment-v1",
            "assurance": "partial-compiler-candidate-assembly-no-admission",
            "complete": False, "admission": False, "publication": False,
            "bindings": bindings, "assets": compiler_assets,
        }
        self.lanes_doc = {"schema": "aros-toolchain-index-lanes-v1",
                          "lanes": compiler_lanes}
        write(self.evidence_path, canonical(self.evidence))
        write(self.lanes_path, canonical(self.lanes_doc))
        self.index = {
            "schema": 2, "release_id": release_id,
            "base_url": "https://example.invalid/toolchains/fixture-release-2026",
            "inputs_sha256": self.sdk.inputs_sha256,
            "producer_commit": sdk_tests.PRODUCER, "tools_commit": sdk_tests.TOOLS,
            "artifacts": index_artifacts,
        }

    def arguments(self) -> list[str]:
        return [
            sys.executable, "-B", str(SCRIPT),
            "--plan", str(self.sdk.plan_path), "--plan-sha256", self.sdk.plan_sha256,
            "--inputs-dir", str(self.sdk.inputs), "--inputs-sha256", self.sdk.inputs_sha256,
            "--producer-commit", sdk_tests.PRODUCER, "--tools-commit", sdk_tests.TOOLS,
            "--source-context", str(self.source_context_path),
            "--source-context-sha256", self.source_context_sha256,
            "--compiler-lanes", str(self.lanes_path),
            "--compiler-lanes-sha256", digest(self.lanes_path.read_bytes()),
            "--compiler-evidence", str(self.evidence_path),
            "--compiler-evidence-sha256", digest(self.evidence_path.read_bytes()),
            "--sdk-fragment", str(self.sdk.fragment_path),
            "--sdk-fragment-sha256", digest(self.sdk.fragment_path.read_bytes()),
            "--sdk-owner-root", str(self.sdk.owner_root),
            "--index", str(self.index_path), "--index-sha256", digest(self.index_path.read_bytes()),
        ]

    def run(self, *, extra: list[str] | None = None,
            replace: dict[str, str] | None = None,
            environment: dict[str, str] | None = None,
            provider_responses: list[dict] | None = None) -> subprocess.CompletedProcess[str]:
        arguments = self.arguments()
        for option, value in (replace or {}).items():
            arguments[arguments.index(option) + 1] = value
        child_environment = dict(os.environ)
        child_environment.update(compiler_tests.provider_environment(
            self.base, self.source_context, responses=provider_responses,
        ))
        child_environment.update(environment or {})
        return subprocess.run([*arguments, *(extra or [])], capture_output=True,
                              text=True, check=False, env=child_environment)

    def run_mutating_after_final_sdk_selection(self, path: Path) -> subprocess.CompletedProcess[str]:
        hook_dir = self.base / "site-hook"
        hook_dir.mkdir(mode=0o700)
        hook_source = '''\
import importlib.util
import os
from pathlib import Path

_spec_from_file_location = importlib.util.spec_from_file_location
def _hooked_spec(name, *args, **kwargs):
    spec = _spec_from_file_location(name, *args, **kwargs)
    if name == "native_release_evidence_sdk_selector":
        loader = spec.loader
        _exec_module = loader.exec_module
        def _hooked_exec(module):
            _exec_module(module)
            _select = module.select
            calls = [0]
            def _select_then_mutate(*args, **kwargs):
                result = _select(*args, **kwargs)
                calls[0] += 1
                if calls[0] == 2:
                    selected = Path(os.environ["NATIVE_EVIDENCE_MUTATE_PATH"])
                    selected.write_bytes(selected.read_bytes() + b"changed-after-selection")
                return result
            module.select = _select_then_mutate
        loader.exec_module = _hooked_exec
    return spec
importlib.util.spec_from_file_location = _hooked_spec
'''
        write(hook_dir / "sitecustomize.py", hook_source.encode())
        environment = dict(os.environ)
        environment["PYTHONPATH"] = os.pathsep.join(
            item for item in (str(hook_dir), environment.get("PYTHONPATH", "")) if item
        )
        environment["NATIVE_EVIDENCE_MUTATE_PATH"] = str(path)
        return self.run(environment=environment)


class NativeReleaseEvidenceSelectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="native-release-evidence-v2.")
        self.fixture = Fixture(Path(self.temporary.name))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def assert_rejected(self, *, extra: list[str] | None = None,
                        replace: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        result = self.fixture.run(extra=extra, replace=replace)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(result.stdout, "")
        self.assertIn("native release evidence selection failed:", result.stderr)
        return result

    def test_emits_exact_native_dto_from_closed_evidence(self) -> None:
        result = self.fixture.run()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(result.stdout.splitlines()), 1)
        selection = json.loads(result.stdout)
        self.assertEqual(set(selection), {
            "schema", "lanes", "sdk_packages", "sdk_generations",
        })
        self.assertEqual(selection["schema"], "aros-toolchain-release-evidence-selection-v2")
        self.assertEqual(set(selection["sdk_packages"]), {sdk["id"] for sdk in self.fixture.plan["sdks"]})
        for package in selection["sdk_packages"].values():
            self.assertEqual(set(package), {"tree_sha256", "archive_sha256", "archive_size"})
        self.assertEqual(selection["sdk_generations"], self.fixture.sdk.fragment["sdk_generations"])
        for generation in selection["sdk_generations"]:
            self.assertEqual(set(generation), {
                "sdk_id", "group_id", "target_profile", "host", "package_dir", "record",
                "compatibility",
            })
            self.assertEqual(set(generation["record"]), {"path", "sha256"})
            self.assertEqual(set(generation["compatibility"]), {
                "directory", "inputs", "manifest_sha256", "native_sdk_required",
            })
        self.assertEqual(set(selection["lanes"]), set(self.fixture.evidence["assets"]))
        for lane in selection["lanes"].values():
            self.assertEqual(set(lane), {
                "build_environment", "required_paths", "builds", "comparison", "compatibility",
            } | ({"llvm_sdk_id"} if "llvm_sdk_id" in lane else set()))
            self.assertEqual(len(lane["builds"]), 2)
            for build in lane["builds"]:
                self.assertEqual(set(build), {"package_dir", "measurement", "executor"})
                self.assertEqual(set(build["measurement"]), {"path", "sha256"})
                self.assertEqual(set(build["executor"]), {"contract_sha256", "binary_sha256"})
        self.assertNotIn("assurance", selection)
        for lane_key, lane in selection["lanes"].items():
            evidence = self.fixture.evidence["assets"][lane_key]
            group_id = evidence["group_id"]
            if group_id == "group-a":
                self.assertNotIn("llvm_sdk_id", lane)
                self.assertTrue(lane["compatibility"]["native_sdk_required"])
            else:
                self.assertEqual(lane["llvm_sdk_id"], "sdk-b")
                self.assertFalse(lane["compatibility"]["native_sdk_required"])

    def test_tag_push_and_manual_tag_dispatch_use_the_provider_event(self) -> None:
        for index, event in enumerate(("push", "workflow_dispatch")):
            with self.subTest(event=event):
                base = self.fixture.base / f"tag-event-{index}"
                base.mkdir()
                fixture = Fixture(base, source_ref=compiler_tests.TAG_REF)
                responses = [compiler_tests.provider_run(fixture.source_context, event)] * 2
                result = fixture.run(provider_responses=responses)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(len(result.stdout.splitlines()), 1)
                self.assertEqual(
                    json.loads(result.stdout)["schema"],
                    "aros-toolchain-release-evidence-selection-v2",
                )

    def test_provider_failure_and_identity_mismatch_emit_no_json(self) -> None:
        failed = self.fixture.run(environment={"FAKE_GH_FAIL": "1"})
        self.assertNotEqual(failed.returncode, 0, failed.stdout)
        self.assertEqual(failed.stdout, "")
        self.assertIn("native release evidence selection failed:", failed.stderr)

        wrong_identity = compiler_tests.provider_run(self.fixture.source_context)
        wrong_identity["run_attempt"] += 1
        mismatch = self.fixture.run(provider_responses=[wrong_identity])
        self.assertNotEqual(mismatch.returncode, 0, mismatch.stdout)
        self.assertEqual(mismatch.stdout, "")
        self.assertIn("native release evidence selection failed:", mismatch.stderr)

    def test_context_digest_and_sdk_source_selectors_are_bound(self) -> None:
        result = self.fixture.run(replace={"--source-context-sha256": "0" * 64})
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(result.stdout, "")
        self.assertIn("native release evidence selection failed:", result.stderr)

        for field, value in (
            ("source_workflow", ".github/workflows/other.yml"),
            ("source_ref", "refs/heads/other"),
            ("source_producer_commit", "f" * 40),
        ):
            with self.subTest(field=field):
                base = self.fixture.base / f"sdk-context-{field}"
                base.mkdir()
                fixture = Fixture(base)
                fixture.sdk.fragment[field] = value
                fixture.sdk.write_fragment()
                result = fixture.run()
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertEqual(result.stdout, "")
                self.assertIn("native release evidence selection failed:", result.stderr)

    def test_changed_provider_event_fails_at_the_final_evidence_barrier(self) -> None:
        result = self.fixture.run(provider_responses=[
            compiler_tests.provider_run(self.fixture.source_context, "workflow_dispatch"),
            compiler_tests.provider_run(self.fixture.source_context, "push"),
        ])
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(result.stdout, "")
        self.assertIn("source run event changed", result.stderr)

    def test_rejects_duplicate_cli_options_before_selecting(self) -> None:
        self.assert_rejected(extra=["--plan", str(self.fixture.sdk.plan_path)])

    def test_rejects_symlinked_evidence_path(self) -> None:
        alias = self.fixture.base / "compiler-evidence-link.json"
        alias.symlink_to(self.fixture.evidence_path)
        self.assert_rejected(replace={"--compiler-evidence": str(alias)})

    def test_rejects_symlinked_sdk_owner_root(self) -> None:
        alias = self.fixture.base / "sdk-owner-root-link"
        alias.symlink_to(self.fixture.sdk.owner_root, target_is_directory=True)
        self.assert_rejected(replace={"--sdk-owner-root": str(alias)})

    def test_rejects_duplicate_json_and_unbound_input_references(self) -> None:
        raw = self.fixture.evidence_path.read_bytes()
        duplicate = raw.replace(b'{"admission":', b'{"admission":false,"admission":', 1)
        write(self.fixture.evidence_path, duplicate)
        self.assert_rejected()

        self.fixture = Fixture(Path(tempfile.mkdtemp(prefix="missing-input-ref.")))
        self.addCleanup(lambda path=self.fixture.base: shutil.rmtree(path))
        plan = json.loads(self.fixture.sdk.plan)
        collection = json.loads(self.fixture.sdk.collection.read_bytes())
        recipe_name = "missing-recipe-input.json"
        plan["groups"][0]["recipe"]["file"] = recipe_name
        collection["groups"][0]["recipe"]["file"] = recipe_name
        collection_raw = canonical(collection)
        write(self.fixture.sdk.collection, collection_raw)
        plan["inputs_sha256"] = digest(collection_raw)
        plan_raw = canonical(plan)
        write(self.fixture.sdk.plan_path, plan_raw)
        self.fixture.sdk.inputs_sha256 = digest(collection_raw)
        self.fixture.sdk.plan_sha256 = digest(plan_raw)
        self.fixture.sdk.plan = plan_raw
        self.fixture.sdk.fragment["inputs_sha256"] = self.fixture.sdk.inputs_sha256
        self.fixture.sdk.fragment["plan_sha256"] = self.fixture.sdk.plan_sha256
        self.fixture.sdk.write_fragment()
        self.assert_rejected()

    def test_rejects_copy_swap_and_duplicate_original_job_ids(self) -> None:
        evidence = json.loads(self.fixture.evidence_path.read_bytes())
        asset = next(iter(evidence["assets"]))
        evidence["assets"][asset]["builds"].reverse()
        write(self.fixture.evidence_path, canonical(evidence))
        self.assert_rejected()

        evidence = json.loads(self.fixture.evidence_path.read_bytes())
        evidence["assets"][asset]["builds"].reverse()
        evidence["assets"][asset]["builds"][1]["original_job_id"] = evidence["assets"][asset]["builds"][0]["original_job_id"]
        write(self.fixture.evidence_path, canonical(evidence))
        self.assert_rejected()

    def test_rejects_forged_missing_or_unknown_index_asset_coverage(self) -> None:
        for mutate in ("forged", "missing", "unknown", "disabled"):
            with self.subTest(mutate=mutate):
                self.fixture = Fixture(Path(tempfile.mkdtemp(prefix=f"index-{mutate}.")))
                self.addCleanup(lambda path=self.fixture.base: shutil.rmtree(path))
                index = json.loads(self.fixture.index_path.read_bytes())
                if mutate == "forged":
                    index["artifacts"][0]["inputs_sha256"] = "f" * 64
                elif mutate == "missing":
                    index["artifacts"].pop()
                elif mutate == "unknown":
                    index["artifacts"][0]["asset"] = "unknown-asset.tar.xz"
                else:
                    index["artifacts"][0]["enabled"] = False
                write(self.fixture.index_path, canonical(index))
                self.assert_rejected()

    def test_rejects_measurement_comparison_and_raw_digest_mismatches(self) -> None:
        evidence = json.loads(self.fixture.evidence_path.read_bytes())
        asset = next(iter(evidence["assets"]))
        evidence["assets"][asset]["comparison"]["selectedFile"]["sha256"] = "9" * 64
        write(self.fixture.evidence_path, canonical(evidence))
        self.assert_rejected()

        self.fixture = Fixture(Path(tempfile.mkdtemp(prefix="measurement-digest.")))
        self.addCleanup(lambda path=self.fixture.base: shutil.rmtree(path))
        evidence = json.loads(self.fixture.evidence_path.read_bytes())
        asset = next(iter(evidence["assets"]))
        evidence["assets"][asset]["builds"][0]["measurement"]["sha256"] = "8" * 64
        write(self.fixture.evidence_path, canonical(evidence))
        self.assert_rejected()

    def test_rejects_input_comparison_sdk_record_and_source_context_changes_at_final_barrier(
            self) -> None:
        targets = (
            self.fixture.sdk.inputs / self.fixture.plan["groups"][0]["recipe"]["file"],
            Path(next(iter(self.fixture.evidence["assets"].values()))["comparison"][
                "selectedFile"]["path"]),
            Path(self.fixture.sdk.fragment["sdk_generations"][0]["record"]["path"]),
            self.fixture.source_context_path,
        )
        for target_index, target in enumerate(targets):
            with self.subTest(target=target.name):
                if target_index:
                    self.fixture = Fixture(Path(tempfile.mkdtemp(
                        prefix=f"final-barrier-{target_index}.")))
                    self.addCleanup(lambda path=self.fixture.base: shutil.rmtree(path))
                    targets = (
                        self.fixture.sdk.inputs
                        / self.fixture.plan["groups"][0]["recipe"]["file"],
                        Path(next(iter(self.fixture.evidence["assets"].values()))["comparison"][
                            "selectedFile"]["path"]),
                        Path(self.fixture.sdk.fragment["sdk_generations"][0]["record"]["path"]),
                        self.fixture.source_context_path,
                    )
                    target = targets[target_index]
                result = self.fixture.run_mutating_after_final_sdk_selection(target)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertEqual(result.stdout, "")
                self.assertIn("native release evidence selection failed:", result.stderr)

    def test_rejects_wrong_family_policy_and_unbound_sdk_fragment(self) -> None:
        fragment = self.fixture.sdk.fragment
        fragment["sdk_generations"][0]["compatibility"]["native_sdk_required"] = not fragment[
            "sdk_generations"][0]["compatibility"]["native_sdk_required"]
        self.fixture.sdk.write_fragment()
        self.assert_rejected()

        self.fixture = Fixture(Path(tempfile.mkdtemp(prefix="sdk-context-mismatch.")))
        self.addCleanup(lambda path=self.fixture.base: shutil.rmtree(path))
        self.fixture.sdk.fragment["source_context_sha256"] = "9" * 64
        self.fixture.sdk.write_fragment()
        self.assert_rejected()

    def test_rejects_missing_or_ambiguous_source_declared_sdk_binding(self) -> None:
        lane = self.fixture.plan["lanes"][0]
        self.assertEqual(selector._expected_sdk_for_lane(self.fixture.plan, (
            lane["group_id"], lane["host"], lane["target_profile"],
        ))["id"], "sdk-a")
        no_binding = json.loads(json.dumps(self.fixture.plan))
        for sdk in no_binding["sdks"]:
            sdk["compiler_profiles"] = []
        with self.assertRaises(selector.SelectionError):
            selector._expected_sdk_for_lane(no_binding, (
                lane["group_id"], lane["host"], lane["target_profile"],
            ))
        ambiguous = json.loads(json.dumps(self.fixture.plan))
        ambiguous["sdks"][1]["compiler_profiles"].append(
            dict(ambiguous["sdks"][0]["compiler_profiles"][0])
        )
        with self.assertRaises(selector.SelectionError):
            selector._expected_sdk_for_lane(ambiguous, (
                lane["group_id"], lane["host"], lane["target_profile"],
            ))


if __name__ == "__main__":
    unittest.main()
