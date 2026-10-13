"""Contract tests for the bounded SDK owner selector."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts/toolchain/sdk-owner-matrix-v2.py"
ACTION = ROOT / ".github/actions/retain-sdk-owner-payload-v2/action.yml"
RELEASE_MATRIX_TEST = ROOT / "scripts/toolchain/tests/test-release-matrix-v2.py"
PRODUCER_COMMIT = "a" * 40
TOOLS_COMMIT = "b" * 40
INPUTS_SHA256 = "d" * 64
SOURCE_REF = "refs/heads/main"
TAG_REF = "refs/tags/v2.4.0"
SOURCE_WORKFLOW = ".github/workflows/toolchain-release.yml"


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _compact(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _load_release_fixture():
    spec = importlib.util.spec_from_file_location("release_matrix_test_fixture", RELEASE_MATRIX_TEST)
    if spec is None or spec.loader is None:
        raise RuntimeError("release matrix fixture is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


release_fixture = _load_release_fixture()


def _load_owner_selector():
    spec = importlib.util.spec_from_file_location("sdk_owner_matrix_v2_test_module", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("SDK owner selector is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _full_mixed_plan() -> dict:
    plan = release_fixture.owner_plan()
    sdk_specs = (
        ("sdk-alpha-one", "family-alpha", "alpha-one"),
        ("sdk-alpha-two", "family-alpha", "alpha-two"),
        ("sdk-beta-one", "family-beta", "beta-one"),
        ("sdk-beta-two", "family-beta", "beta-two"),
    )
    sdks = []
    for sdk_id, group_id, profile in sdk_specs:
        identity_file = f"{sdk_id}-identity.json"
        sdks.append({
            "id": sdk_id,
            "identity": {"file": identity_file, "sha256": _sha(identity_file.encode())},
            "source_preset": "default",
            "compiler_profiles": [{"group_id": group_id, "profile": profile}],
        })
    plan["sdks"] = sorted(sdks, key=lambda sdk: sdk["id"])
    plan["sdk_count"] = len(sdks)
    return plan


class SdkOwnerMatrixV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="sdk-owner-matrix-v2.")
        self.root = Path(self.temporary.name).resolve()
        self.inputs = self.root / "inputs"
        self.inputs.mkdir()
        self.plan_path = self.root / "plan.json"
        self.context_path = self.root / "source-context.json"
        self.plan = _full_mixed_plan()
        self.families = {"family-alpha": "gnu", "family-beta": "llvm"}
        for group in self.plan["groups"]:
            group_id = group["group_id"]
            raw_lock = _compact({"family": self.families[group_id]})
            (self.inputs / group["source_lock"]["file"]).write_bytes(raw_lock)
            group["source_lock"]["sha256"] = _sha(raw_lock)
        self.context = {
            "repository": "example/toolchains",
            "repository_id": 1234,
            "producer_commit": PRODUCER_COMMIT,
            "source_ref": SOURCE_REF,
            "workflow": SOURCE_WORKFLOW,
            "run_id": 123456,
            "run_attempt": 2,
        }
        self.context_raw = json.dumps(
            self.context, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8") + b"\n"
        self.context_path.write_bytes(self.context_raw)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def set_source_ref(self, source_ref: str) -> None:
        self.context["source_ref"] = source_ref
        self.context_raw = json.dumps(
            self.context, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8") + b"\n"
        self.context_path.write_bytes(self.context_raw)

    def write_plan(self, plan: dict | None = None) -> bytes:
        raw = _compact(plan if plan is not None else self.plan)
        self.plan_path.write_bytes(raw)
        return raw

    def arguments(self, raw: bytes | None = None) -> list[str]:
        raw = raw if raw is not None else self.write_plan()
        return [
            sys.executable,
            "-B",
            str(SCRIPT),
            "--plan", str(self.plan_path),
            "--plan-sha256", _sha(raw),
            "--inputs-dir", str(self.inputs),
            "--inputs-sha256", INPUTS_SHA256,
            "--producer-commit", PRODUCER_COMMIT,
            "--tools-commit", TOOLS_COMMIT,
            "--source-context", str(self.context_path),
            "--source-context-sha256", _sha(self.context_raw),
            "--source-workflow", SOURCE_WORKFLOW,
            "--source-ref", self.context["source_ref"],
        ]

    def run_cli(self, raw: bytes | None = None, *, timeout: float = 10,
                arguments: list[str] | None = None) -> subprocess.CompletedProcess[str]:
        command = arguments if arguments is not None else self.arguments(raw)
        return subprocess.run(command, capture_output=True, text=True, check=False, timeout=timeout)

    def assert_rejected(self, result: subprocess.CompletedProcess[str]) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(result.stdout, "")
        self.assertIn("SDK owner matrix selection failed:", result.stderr)

    def test_full_mixed_plan_selects_four_sdk_owners_across_all_hosts(self) -> None:
        raw = self.write_plan()
        result = self.run_cli(raw)
        self.assertEqual(result.returncode, 0, result.stderr)
        wrapper = json.loads(result.stdout)
        self.assertEqual(
            set(wrapper),
            {
                "schema", "assurance", "plan_sha256", "inputs_sha256",
                "source_context_sha256", "producer_commit", "tools_commit",
                "owners", "expected_sdk_generations",
            },
        )
        self.assertEqual(wrapper["schema"], "aros-sdk-owner-matrix-v2")
        self.assertEqual(wrapper["assurance"], "owner-selection-only")
        self.assertEqual(wrapper["plan_sha256"], _sha(raw))
        self.assertEqual(wrapper["source_context_sha256"], _sha(self.context_raw))
        self.assertEqual(len(wrapper["owners"]), 12)
        self.assertEqual(len(wrapper["expected_sdk_generations"]), 12)
        self.assertEqual(
            {owner["compiler_family"] for owner in wrapper["owners"]}, {"gnu", "llvm"}
        )
        self.assertEqual(
            [(owner["group_id"], owner["host"], owner["profile"])
             for owner in wrapper["owners"]],
            sorted((owner["group_id"], owner["host"], owner["profile"])
                   for owner in wrapper["owners"]),
        )
        self.assertEqual(
            [(item["sdk_id"], item["group_id"], item["target_profile"], item["host"])
             for item in wrapper["expected_sdk_generations"]],
            sorted((item["sdk_id"], item["group_id"], item["target_profile"], item["host"])
                   for item in wrapper["expected_sdk_generations"]),
        )

        action = ACTION.read_text(encoding="utf-8")
        self.assertIn("printf '%s\\0' \"$SDK_OWNER_ROLE\" \"$SDK_IDS\" \"$SDK_GROUP\" \"$SDK_HOST\" \"$SDK_PRESET\"", action)
        for owner in wrapper["owners"]:
            self.assertEqual(
                set(owner),
                {"owner_id", "group_id", "host", "profile", "compiler_family",
                 "sdk_ids", "job_name", "payload_name", "proof_name"},
            )
            sdk_ids_json = json.dumps(owner["sdk_ids"], separators=(",", ":"), ensure_ascii=True)
            shell_hash = subprocess.run(
                ["bash", "-c",
                 'printf "%s\\0" "$1" "$2" "$3" "$4" "$5" | shasum -a 256 | awk \'{print $1}\'',
                 "sdk-owner-action-formula", "sdk", sdk_ids_json, owner["group_id"],
                 owner["host"], owner["profile"]],
                capture_output=True, text=True, check=True,
            ).stdout.strip()
            self.assertEqual(owner["owner_id"], shell_hash)
            self.assertEqual(
                owner["job_name"],
                f"SDK from owned compilers ({owner['group_id']}, {owner['host']}, {owner['profile']})",
            )
            self.assertEqual(
                owner["payload_name"],
                f"sdk-v2-{owner['owner_id']}-{self.context['run_id']}-{self.context['run_attempt']}",
            )
            self.assertEqual(
                owner["proof_name"],
                f"sdk-v2-proof-{owner['owner_id']}-{self.context['run_id']}-{self.context['run_attempt']}",
            )

        expected_canonical = json.dumps(wrapper, sort_keys=True, separators=(",", ":"),
                                        ensure_ascii=True) + "\n"
        self.assertEqual(result.stdout, expected_canonical)

    def test_branch_and_tag_contexts_select_the_existing_complete_projection_routes(self) -> None:
        module = _load_owner_selector()
        original_project = module.release_matrix.project
        for source_ref, expected_event, expected_full_qualification in (
            (SOURCE_REF, "workflow_dispatch", True),
            (TAG_REF, "push", False),
        ):
            with self.subTest(source_ref=source_ref):
                self.set_source_ref(source_ref)
                raw = self.write_plan()
                selected_route = {}

                def capture_project(**kwargs):
                    selected_route.update({
                        "event": kwargs["event"], "scope": kwargs["scope"],
                        "full_qualification": kwargs["full_qualification"],
                    })
                    return original_project(**kwargs)

                module.release_matrix.project = capture_project
                try:
                    command = self.arguments(raw)
                    result = module.select(module._parser().parse_args(command[3:]))
                finally:
                    module.release_matrix.project = original_project
                self.assertEqual(len(result["owners"]), 12)
                self.assertEqual(selected_route, {
                    "event": expected_event, "scope": "full",
                    "full_qualification": expected_full_qualification,
                })

    def test_unrecognized_source_ref_is_rejected_without_stdout(self) -> None:
        self.set_source_ref("refs/pull/17/merge")
        self.assert_rejected(self.run_cli())
        module = _load_owner_selector()
        with self.assertRaises(module.artifact_origin.OriginError):
            module._projection_route("refs/pull/17/merge")

    def test_two_sdk_ids_sharing_one_compiler_lane_form_one_owner_per_host(self) -> None:
        plan = _full_mixed_plan()
        for group in plan["groups"]:
            raw_lock = (self.inputs / group["source_lock"]["file"]).read_bytes()
            group["source_lock"]["sha256"] = _sha(raw_lock)
        sdk_by_id = {sdk["id"]: sdk for sdk in plan["sdks"]}
        sdk_by_id["sdk-alpha-two"]["compiler_profiles"] = [
            {"group_id": "family-alpha", "profile": "alpha-one"}
        ]
        result = self.run_cli(self.write_plan(plan))
        self.assertEqual(result.returncode, 0, result.stderr)
        wrapper = json.loads(result.stdout)

        shared_owners = [
            owner for owner in wrapper["owners"]
            if owner["group_id"] == "family-alpha" and owner["profile"] == "alpha-one"
        ]
        self.assertEqual(len(shared_owners), 3)
        self.assertEqual(len({owner["owner_id"] for owner in shared_owners}), 3)
        self.assertEqual({owner["host"] for owner in shared_owners}, set(plan["hosts"]))

        action = ACTION.read_text(encoding="utf-8")
        self.assertIn("printf '%s\\0' \"$SDK_OWNER_ROLE\" \"$SDK_IDS\" \"$SDK_GROUP\" \"$SDK_HOST\" \"$SDK_PRESET\"", action)
        for owner in shared_owners:
            self.assertEqual(owner["sdk_ids"], ["sdk-alpha-one", "sdk-alpha-two"])
            sdk_ids_json = json.dumps(owner["sdk_ids"], separators=(",", ":"), ensure_ascii=True)
            shell_hash = subprocess.run(
                ["bash", "-c",
                 'printf "%s\\0" "$1" "$2" "$3" "$4" "$5" | shasum -a 256 | awk \'{print $1}\'',
                 "sdk-owner-action-formula", "sdk", sdk_ids_json, owner["group_id"],
                 owner["host"], owner["profile"]],
                capture_output=True, text=True, check=True,
            ).stdout.strip()
            self.assertEqual(owner["owner_id"], shell_hash)

        shared_generations = [
            generation for generation in wrapper["expected_sdk_generations"]
            if generation["group_id"] == "family-alpha"
            and generation["target_profile"] == "alpha-one"
        ]
        for host in plan["hosts"]:
            on_host = [item for item in shared_generations if item["host"] == host]
            self.assertEqual(
                [(item["sdk_id"], item["group_id"], item["target_profile"], item["host"])
                 for item in on_host],
                [
                    ("sdk-alpha-one", "family-alpha", "alpha-one", host),
                    ("sdk-alpha-two", "family-alpha", "alpha-one", host),
                ],
            )

    def test_changed_plan_digest_is_rejected_without_stdout(self) -> None:
        raw = self.write_plan()
        arguments = self.arguments(raw)
        digest_index = arguments.index("--plan-sha256") + 1
        arguments[digest_index] = "f" * 64
        self.assert_rejected(self.run_cli(arguments=arguments))

    def test_plan_missing_one_required_host_is_rejected(self) -> None:
        plan = _full_mixed_plan()
        plan["lanes"] = [
            lane for lane in plan["lanes"]
            if not (lane["group_id"] == "family-alpha"
                    and lane["target_profile"] == "alpha-one"
                    and lane["host"] == "macos-aarch64")
        ]
        plan["lane_count"] = len(plan["lanes"])
        self.assert_rejected(self.run_cli(self.write_plan(plan)))

    def test_source_context_must_match_selected_workflow_and_ref(self) -> None:
        raw = self.write_plan()
        arguments = self.arguments(raw)
        arguments[arguments.index("--source-ref") + 1] = "refs/heads/other"
        self.assert_rejected(self.run_cli(arguments=arguments))

    def test_changed_source_context_digest_is_rejected(self) -> None:
        raw = self.write_plan()
        arguments = self.arguments(raw)
        digest_index = arguments.index("--source-context-sha256") + 1
        arguments[digest_index] = "e" * 64
        self.assert_rejected(self.run_cli(arguments=arguments))

    def test_digest_bound_source_lock_family_is_required(self) -> None:
        self.write_plan()
        lock_path = self.inputs / self.plan["groups"][0]["source_lock"]["file"]
        lock_path.write_bytes(_compact({"family": "llvm"}))
        self.assert_rejected(self.run_cli())

    def test_source_lock_symlink_is_rejected(self) -> None:
        raw = self.write_plan()
        lock_path = self.inputs / self.plan["groups"][0]["source_lock"]["file"]
        target = self.inputs / "real-lock.json"
        target.write_bytes(lock_path.read_bytes())
        lock_path.unlink()
        lock_path.symlink_to(target.name)
        self.assert_rejected(self.run_cli(raw))

    def test_hard_linked_source_lock_is_rejected(self) -> None:
        raw = self.write_plan()
        lock_path = self.inputs / self.plan["groups"][0]["source_lock"]["file"]
        target = self.inputs / "second-link.json"
        os.link(lock_path, target)
        self.assert_rejected(self.run_cli(raw))

    def test_duplicate_json_field_and_duplicate_sdk_identity_are_rejected(self) -> None:
        raw = self.write_plan()
        duplicate_field = raw.replace(b'"operation":"release-plan"',
                                      b'"operation":"release-plan","operation":"release-plan"', 1)
        self.plan_path.write_bytes(duplicate_field)
        self.assert_rejected(self.run_cli(duplicate_field))

        plan = _full_mixed_plan()
        plan["sdks"].append(dict(plan["sdks"][-1]))
        plan["sdk_count"] = len(plan["sdks"])
        self.assert_rejected(self.run_cli(self.write_plan(plan)))

    def test_repeated_option_is_rejected_before_opening_selected_inputs(self) -> None:
        fifo = self.root / "input-must-not-be-opened.fifo"
        os.mkfifo(fifo)
        raw = self.write_plan()
        arguments = self.arguments(raw)
        arguments[arguments.index("--plan") + 1] = str(fifo)
        arguments.extend(("--plan", str(fifo)))
        result = self.run_cli(arguments=arguments, timeout=3)
        self.assert_rejected(result)
        self.assertIn("repeated command-line option", result.stderr)


if __name__ == "__main__":
    unittest.main()
