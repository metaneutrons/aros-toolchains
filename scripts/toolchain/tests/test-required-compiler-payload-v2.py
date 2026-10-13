#!/usr/bin/env python3
"""Offline contract tests for required compiler payload path selection."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import inspect
import json
import os
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts/toolchain/required-compiler-payload-v2.py"
RELEASE_TESTS = ROOT / "scripts/toolchain/tests/test-release-matrix-v2.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


payload = load_module("required_compiler_payload_v2", SCRIPT)
release_tests = load_module("release_matrix_test_fixtures", RELEASE_TESTS)

ACTIVE_HOSTS = ("linux-aarch64", "linux-x86_64", "macos-aarch64")
INPUTS_SHA256 = release_tests.INPUTS_SHA256
PRODUCER_COMMIT = release_tests.PRODUCER_COMMIT
TOOLS_COMMIT = release_tests.TOOLS_COMMIT
PROFILES_BY_GROUP = {
    "family-alpha": ["alpha-one", "alpha-two"],
    "family-beta": ["beta-one", "beta-two"],
}


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def compact(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def native_plan() -> dict[str, object]:
    return release_tests.owner_plan(copy.deepcopy(PROFILES_BY_GROUP))


def required_policy(plan: dict[str, object] | None = None) -> dict[str, object]:
    selected_plan = native_plan() if plan is None else plan
    groups = []
    for group in selected_plan["groups"]:
        profile_ids = sorted(
            {
                lane["target_profile"]
                for lane in selected_plan["lanes"]
                if lane["group_id"] == group["group_id"]
            }
        )
        profiles = {
            profile: sorted(
                [
                    f"include/{profile}/compiler.h",
                    f"lib/{profile}/libgcc.a",
                ]
            )
            for profile in profile_ids
        }
        groups.append(
            {
                "group_id": group["group_id"],
                "source_lock_sha256": group["source_lock"]["sha256"],
                "profiles_sha256": group["profiles"]["sha256"],
                "profiles": profiles,
            }
        )
    return {"schema": payload.POLICY_SCHEMA, "groups": groups}


class RequiredCompilerPayloadTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="required-compiler-payload-v2.")
        self.root = Path(self.temporary.name).resolve()
        self.serial = 0
        self.plan = native_plan()
        self.raw_plan = release_tests.plan_bytes(self.plan)
        self.policy = required_policy(self.plan)
        self.raw_policy = compact(self.policy)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def select(
        self,
        *,
        policy: dict[str, object] | None = None,
        raw_policy: bytes | None = None,
        raw_plan: bytes | None = None,
        expected_policy_sha256: str | None = None,
        plan_sha256: str | None = None,
        inputs_sha256: str = INPUTS_SHA256,
        producer_commit: str = PRODUCER_COMMIT,
        tools_commit: str = TOOLS_COMMIT,
    ) -> dict[str, object]:
        selected_policy = self.raw_policy if policy is None and raw_policy is None else raw_policy
        if selected_policy is None:
            selected_policy = compact(policy)
        selected_raw_plan = self.raw_plan if raw_plan is None else raw_plan
        return payload.select_required_payload(
            raw_policy=selected_policy,
            expected_policy_sha256=(
                expected_policy_sha256 or digest(selected_policy)
            ),
            raw_plan=selected_raw_plan,
            plan_sha256=plan_sha256 or digest(selected_raw_plan),
            inputs_sha256=inputs_sha256,
            producer_commit=producer_commit,
            tools_commit=tools_commit,
        )

    def write_cli_inputs(
        self,
        raw_policy: bytes | None = None,
        raw_plan: bytes | None = None,
        *,
        policy_path: Path | None = None,
        plan_path: Path | None = None,
    ) -> tuple[Path, Path, bytes, bytes]:
        self.serial += 1
        policy_raw = self.raw_policy if raw_policy is None else raw_policy
        plan_raw = self.raw_plan if raw_plan is None else raw_plan
        selected_policy_path = policy_path or self.root / f"policy-{self.serial}.json"
        selected_plan_path = plan_path or self.root / f"plan-{self.serial}.json"
        if policy_path is None:
            selected_policy_path.write_bytes(policy_raw)
        if plan_path is None:
            selected_plan_path.write_bytes(plan_raw)
        return selected_policy_path, selected_plan_path, policy_raw, plan_raw

    def run_cli(
        self,
        raw_policy: bytes | None = None,
        raw_plan: bytes | None = None,
        *,
        policy_path: Path | None = None,
        plan_path: Path | None = None,
        policy_sha256: str | None = None,
        plan_sha256: str | None = None,
        inputs_sha256: str = INPUTS_SHA256,
        producer_commit: str = PRODUCER_COMMIT,
        tools_commit: str = TOOLS_COMMIT,
    ) -> subprocess.CompletedProcess[str]:
        selected_policy_path, selected_plan_path, policy_raw, plan_raw = self.write_cli_inputs(
            raw_policy,
            raw_plan,
            policy_path=policy_path,
            plan_path=plan_path,
        )
        arguments = [
            sys.executable,
            "-B",
            str(SCRIPT),
            "--policy",
            str(selected_policy_path),
            "--policy-sha256",
            policy_sha256 or digest(policy_raw),
            "--plan",
            str(selected_plan_path),
            "--plan-sha256",
            plan_sha256 or digest(plan_raw),
            "--inputs-sha256",
            inputs_sha256,
            "--producer-commit",
            producer_commit,
            "--tools-commit",
            tools_commit,
        ]
        return subprocess.run(arguments, capture_output=True, text=True, check=False)

    def assert_rejected(self, *args: object, **kwargs: object) -> None:
        result = self.run_cli(*args, **kwargs)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(result.stdout, "")
        self.assertIn("required payload selection failed:", result.stderr)

    def test_full_bound_plan_selects_four_profiles_across_three_hosts(self) -> None:
        result = self.select()
        self.assertEqual(
            set(result),
            {
                "schema",
                "assurance",
                "selected_policy_sha256",
                "plan_sha256",
                "inputs_sha256",
                "producer_commit",
                "tools_commit",
                "selections",
            },
        )
        self.assertEqual(result["schema"], payload.RESULT_SCHEMA)
        self.assertEqual(result["assurance"], "required-path-selection-only")
        self.assertEqual(result["selected_policy_sha256"], digest(self.raw_policy))
        self.assertEqual(result["plan_sha256"], digest(self.raw_plan))
        selections = result["selections"]
        self.assertEqual(len(selections), 12)
        self.assertEqual(
            {(item["group_id"], item["target_profile"]) for item in selections},
            {
                (group_id, profile)
                for group_id, profile_ids in PROFILES_BY_GROUP.items()
                for profile in profile_ids
            },
        )
        self.assertEqual({item["host"] for item in selections}, set(ACTIVE_HOSTS))
        self.assertTrue(
            all(item["required_paths"] == sorted(item["required_paths"]) for item in selections)
        )

    def test_process_cli_emits_one_compact_json_result_without_writing_files(self) -> None:
        before = set(self.root.iterdir())
        result = self.run_cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertEqual(len(result.stdout.splitlines()), 1)
        self.assertNotIn(" ", result.stdout)
        self.assertEqual(set(self.root.iterdir()), before | {
            self.root / "policy-1.json",
            self.root / "plan-1.json",
        })
        selected = json.loads(result.stdout)
        self.assertEqual(selected["assurance"], "required-path-selection-only")
        self.assertEqual(len(selected["selections"]), 12)

    def test_cli_remains_read_only_without_python_bytecode_flags(self) -> None:
        isolated = self.root / "selector"
        isolated.mkdir()
        shutil.copyfile(SCRIPT, isolated / SCRIPT.name)
        shutil.copyfile(SCRIPT.with_name("select-release-matrix-v2.py"),
                        isolated / "select-release-matrix-v2.py")
        policy_path, plan_path, _, _ = self.write_cli_inputs()
        environment = dict(os.environ)
        environment.pop("PYTHONDONTWRITEBYTECODE", None)
        args = [sys.executable, str(isolated / SCRIPT.name),
                "--policy", str(policy_path), "--policy-sha256", digest(self.raw_policy),
                "--plan", str(plan_path), "--plan-sha256", digest(self.raw_plan),
                "--inputs-sha256", INPUTS_SHA256, "--producer-commit", PRODUCER_COMMIT,
                "--tools-commit", TOOLS_COMMIT]
        result = subprocess.run(args, capture_output=True, text=True, env=environment)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(set(item.name for item in isolated.iterdir()),
                         {SCRIPT.name, "select-release-matrix-v2.py"})

    def test_oversized_json_integer_uses_stable_failure_without_stdout(self) -> None:
        raw = b'{"schema":"invalid","number":' + b'9' * 5000 + b'}'
        result = self.run_cli(raw_policy=raw)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("required payload selection failed:", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_missing_or_extra_policy_groups_are_rejected(self) -> None:
        for change in ("missing", "extra"):
            with self.subTest(change=change):
                policy = copy.deepcopy(self.policy)
                if change == "missing":
                    policy["groups"].pop()
                else:
                    policy["groups"].append(
                        {
                            "group_id": "family-extra",
                            "source_lock_sha256": "a" * 64,
                            "profiles_sha256": "b" * 64,
                            "profiles": {"extra-profile": ["lib/extra.a"]},
                        }
                    )
                with self.assertRaises((payload.PolicyError, payload.release_matrix.PlanError)):
                    self.select(policy=policy)

    def test_missing_or_extra_profiles_are_rejected(self) -> None:
        for change in ("missing", "extra"):
            with self.subTest(change=change):
                policy = copy.deepcopy(self.policy)
                profiles = policy["groups"][0]["profiles"]
                if change == "missing":
                    del profiles["alpha-one"]
                else:
                    profiles["unselected-profile"] = ["lib/unselected.a"]
                with self.assertRaises(payload.PolicyError):
                    self.select(policy=policy)

    def test_policy_lock_profiles_policy_and_plan_digests_are_independent(self) -> None:
        for field in ("source_lock_sha256", "profiles_sha256"):
            with self.subTest(field=field):
                policy = copy.deepcopy(self.policy)
                policy["groups"][0][field] = "0" * 64
                with self.assertRaises(payload.PolicyError):
                    self.select(policy=policy)

        with self.assertRaises(payload.PolicyError):
            self.select(expected_policy_sha256="0" * 64)
        with self.assertRaises(payload.release_matrix.PlanError):
            self.select(plan_sha256="0" * 64)
        for field, value in (
            ("inputs_sha256", "e" * 64),
            ("producer_commit", "f" * 40),
            ("tools_commit", "9" * 40),
        ):
            with self.subTest(field=field):
                with self.assertRaises(payload.release_matrix.PlanError):
                    self.select(**{field: value})

    def test_plan_native_bound_identity_mismatch_is_rejected(self) -> None:
        changed = native_plan()
        changed["inputs_sha256"] = "e" * 64
        changed_raw = release_tests.plan_bytes(changed)
        with self.assertRaises(payload.release_matrix.PlanError):
            self.select(raw_plan=changed_raw)

        with self.assertRaises(payload.release_matrix.PlanError):
            self.select(raw_plan=changed_raw, plan_sha256=digest(self.raw_plan))

        result = self.run_cli(raw_plan=changed_raw)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_api_does_not_accept_a_separately_mutable_plan_object(self) -> None:
        self.assertNotIn("native_plan", inspect.signature(payload.select_required_payload).parameters)
        with self.assertRaises(TypeError):
            payload.select_required_payload(
                raw_policy=self.raw_policy,
                expected_policy_sha256=digest(self.raw_policy),
                raw_plan=self.raw_plan,
                native_plan=self.plan,
                plan_sha256=digest(self.raw_plan),
                inputs_sha256=INPUTS_SHA256,
                producer_commit=PRODUCER_COMMIT,
                tools_commit=TOOLS_COMMIT,
            )

    def test_empty_duplicate_unsafe_directory_and_unsorted_paths_are_rejected(self) -> None:
        probes = (
            [],
            [""],
            ["lib/same.a", "lib/same.a"],
            ["/absolute/file"],
            ["../escape"],
            ["include//header.h"],
            ["include/header.h/"],
            ["lib/*.a"],
            ["lib/a.a", "include/b.h"],
        )
        for paths in probes:
            with self.subTest(paths=paths):
                policy = copy.deepcopy(self.policy)
                policy["groups"][0]["profiles"]["alpha-one"] = paths
                with self.assertRaises(payload.PolicyError):
                    self.select(policy=policy)

    def test_unknown_fields_duplicate_json_keys_and_nonfinite_values_are_rejected(self) -> None:
        for mutate in ("top", "group"):
            with self.subTest(mutate=mutate):
                policy = copy.deepcopy(self.policy)
                target = policy if mutate == "top" else policy["groups"][0]
                target["unexpected"] = True
                with self.assertRaises(payload.PolicyError):
                    self.select(policy=policy)

        for raw in (
            b'{"schema":"aros-toolchain-required-payload-v1","schema":"aros-toolchain-required-payload-v1","groups":[]}',
            b'{"schema":"aros-toolchain-required-payload-v1","groups":[],"n":NaN}',
        ):
            with self.subTest(raw=raw):
                result = self.run_cli(raw_policy=raw)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")

        duplicate_profile = (
            b'{"schema":"aros-toolchain-required-payload-v1","groups":['
            b'{"group_id":"family-alpha","source_lock_sha256":"'
            + b"a" * 64
            + b'","profiles_sha256":"'
            + b"b" * 64
            + b'","profiles":{"alpha-one":["lib/a.a"],"alpha-one":["lib/b.a"]}}]}'
        )
        result = self.run_cli(raw_policy=duplicate_profile)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_policy_size_and_collection_limits_are_enforced(self) -> None:
        too_many_paths = copy.deepcopy(self.policy)
        too_many_paths["groups"][0]["profiles"]["alpha-one"] = [
            f"lib/file-{index:03d}.a" for index in range(257)
        ]
        with self.assertRaises(payload.PolicyError):
            self.select(policy=too_many_paths)

        result = self.run_cli(raw_policy=b" " * (payload.MAX_POLICY_BYTES + 1))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_symlink_policy_file_and_symlink_plan_parent_are_rejected(self) -> None:
        real_policy = self.root / "real-policy.json"
        real_policy.write_bytes(self.raw_policy)
        policy_link = self.root / "policy-link.json"
        policy_link.symlink_to(real_policy)
        self.assert_rejected(policy_path=policy_link)

        real_parent = self.root / "real-parent"
        real_parent.mkdir()
        plan_file = real_parent / "plan.json"
        plan_file.write_bytes(self.raw_plan)
        linked_parent = self.root / "linked-parent"
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        self.assert_rejected(plan_path=linked_parent / "plan.json")


if __name__ == "__main__":
    unittest.main()
