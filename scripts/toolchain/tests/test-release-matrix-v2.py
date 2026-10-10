#!/usr/bin/env python3
"""Unit tests for the family-v2 workflow matrix adapter.

These tests exercise only the bounded JSON adapter. They do not invoke the
native producer, compile toolchains, or contact a provider.
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


ADAPTER = Path(__file__).resolve().parents[1] / "release-matrix-v2.py"
SPEC = importlib.util.spec_from_file_location("release_matrix_v2", ADAPTER)
assert SPEC is not None and SPEC.loader is not None
matrix = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = matrix
SPEC.loader.exec_module(matrix)


HOSTS = {
    "linux-aarch64": "ubuntu-24.04-arm",
    "linux-x86_64": "ubuntu-24.04",
    "macos-aarch64": "macos-15",
}
GROUPS = {
    "gnu-rv32": ["rv32-esp32p4"],
    "llvm": ["arm-raspi", "pc-x86_64", "rpi-aarch64"],
}
INPUTS_SHA256 = "d" * 64
PRODUCER_COMMIT = "a" * 40
TOOLS_COMMIT = "b" * 40
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
POLICY_FILE = REPOSITORY_ROOT / "toolchains" / "family-release-policy-v2.json"
ACTION_DIRECTORY = REPOSITORY_ROOT / ".github" / "actions" / "project-family-release-plan"
ACTION_FILE = ACTION_DIRECTORY / "action.yml"


def doc_ref(filename: str, marker: str) -> dict[str, str]:
    return {"file": filename, "sha256": marker * 64}


def policy_fixture() -> dict:
    return {
        "schema": "aros-toolchain-workflow-policy-v2",
        "hosts": copy.deepcopy(HOSTS),
        "groups": copy.deepcopy(GROUPS),
    }


def plan_fixture() -> dict:
    group_specs = (
        ("gnu-rv32", "1", "2", "3", "a", "b", "c"),
        ("llvm", "4", "5", "6", "d", "e", "f"),
    )
    groups = []
    for group_id, source, tree, upstream, recipe, source_lock, profiles in group_specs:
        groups.append({
            "group_id": group_id,
            "source_commit": source.lower() * 40,
            "source_tree": tree.lower() * 40,
            "upstream_commit": upstream.lower() * 40,
            "recipe": doc_ref(f"{group_id}-recipe.json", recipe.lower()),
            "source_lock": doc_ref(f"{group_id}-sources.json", source_lock.lower()),
            "profiles": doc_ref(f"{group_id}-profiles.json", profiles.lower()),
        })

    lanes = [
        {"group_id": group_id, "host": host, "target_profile": profile}
        for group_id, profiles in GROUPS.items()
        for host in HOSTS
        for profile in profiles
    ]
    return {
        "schema": "aros-toolchain-producer-stage-v2",
        "operation": "release-plan",
        "release_format": "family-v2",
        "assurance": "input-binding-only",
        "inputs_sha256": INPUTS_SHA256,
        "producer_commit": PRODUCER_COMMIT,
        "tools_commit": TOOLS_COMMIT,
        "hosts": list(HOSTS),
        "groups": groups,
        "lane_count": len(lanes),
        "lanes": lanes,
    }


def extract_run_script(action_file: Path) -> str:
    """Read the single YAML literal run block using its indentation boundary."""
    lines = action_file.read_text(encoding="utf-8").splitlines()
    run_index = next(index for index, line in enumerate(lines) if line.strip() == "run: |")
    run_indent = len(lines[run_index]) - len(lines[run_index].lstrip())
    block = []
    for line in lines[run_index + 1:]:
        if line.strip() and len(line) - len(line.lstrip()) <= run_indent:
            break
        block.append(line)
    indents = [
        len(line) - len(line.lstrip())
        for line in block
        if line.strip()
    ]
    if not indents:
        raise AssertionError(f"empty run block in {action_file}")
    block_indent = min(indents)
    return "\n".join(line[block_indent:] if line.strip() else "" for line in block) + "\n"


def project(plan: dict | None = None, policy: dict | None = None, *, scope: str = "all") -> dict:
    return matrix.project(
        plan if plan is not None else plan_fixture(),
        policy if policy is not None else policy_fixture(),
        inputs_sha256=INPUTS_SHA256,
        producer_commit=PRODUCER_COMMIT,
        tools_commit=TOOLS_COMMIT,
        scope=scope,
    )


class ReleaseMatrixTests(unittest.TestCase):
    def assert_contract_error(self, plan: dict | None = None, policy: dict | None = None,
                              *, scope: str = "all") -> None:
        with self.assertRaises(matrix.ContractError):
            project(plan, policy, scope=scope)

    def test_projects_the_complete_reviewed_matrix(self) -> None:
        result = project()
        self.assertEqual(set(result), {
            "schema", "assurance", "scope", "complete_lane_count",
            "selected_lane_count", "build_count", "host_matrix",
            "group_matrix", "verify_matrix", "build_matrix",
        })
        self.assertEqual(result["schema"], "aros-toolchain-workflow-matrix-v2")
        self.assertEqual(result["assurance"], "scheduling-only")
        self.assertEqual(result["scope"], "all")
        self.assertEqual(result["complete_lane_count"], 12)
        self.assertEqual(result["selected_lane_count"], 12)
        self.assertEqual(result["build_count"], 24)

        expected_hosts = [
            {"host": host, "runner": runner}
            for host, runner in sorted(HOSTS.items())
        ]
        self.assertEqual(result["host_matrix"], {"include": expected_hosts})
        self.assertEqual(
            result["group_matrix"],
            {"include": sorted(plan_fixture()["groups"], key=lambda item: item["group_id"])},
        )

        groups = {item["group_id"]: item for item in plan_fixture()["groups"]}
        expected_verify = []
        for group_id, profiles in sorted(GROUPS.items()):
            for host in sorted(HOSTS):
                for profile in sorted(profiles):
                    group = groups[group_id]
                    expected_verify.append({
                        "group_id": group_id,
                        "host": host,
                        "runner": HOSTS[host],
                        "profile": profile,
                        "source_commit": group["source_commit"],
                        "source_tree": group["source_tree"],
                        "upstream_commit": group["upstream_commit"],
                        "recipe": group["recipe"],
                        "source_lock": group["source_lock"],
                        "profiles": group["profiles"],
                    })
        self.assertEqual(result["verify_matrix"], {"include": expected_verify})
        expected_build = [
            {**lane, "copy": copy_name}
            for lane in expected_verify
            for copy_name in ("a", "b")
        ]
        self.assertEqual(result["build_matrix"], {"include": expected_build})

    def test_committed_policy_is_the_exact_four_profile_three_host_scope(self) -> None:
        expected = {
            "schema": "aros-toolchain-workflow-policy-v2",
            "hosts": {
                "linux-aarch64": "ubuntu-24.04-arm",
                "linux-x86_64": "ubuntu-24.04",
                "macos-aarch64": "macos-15",
            },
            "groups": {
                "gnu-rv32": ["rv32-esp32p4"],
                "llvm": ["arm-raspi", "pc-x86_64", "rpi-aarch64"],
            },
        }
        committed = json.loads(POLICY_FILE.read_text(encoding="utf-8"))
        self.assertEqual(committed, expected)
        self.assertEqual(policy_fixture(), expected)
        self.assertEqual(len(expected["hosts"]), 3)
        self.assertEqual(sum(len(profiles) for profiles in expected["groups"].values()), 4)

    def test_scope_selects_only_allowed_hosts_and_lanes(self) -> None:
        for scope, expected_hosts, expected_lanes in (
            ("linux", {"linux-aarch64", "linux-x86_64"}, 8),
            ("linux-x86_64", {"linux-x86_64"}, 4),
        ):
            with self.subTest(scope=scope):
                result = project(scope=scope)
                self.assertEqual(result["scope"], scope)
                self.assertEqual(result["complete_lane_count"], 12)
                self.assertEqual(result["selected_lane_count"], expected_lanes)
                self.assertEqual(result["build_count"], expected_lanes * 2)
                self.assertEqual(
                    {item["host"] for item in result["host_matrix"]["include"]},
                    expected_hosts,
                )
                self.assertEqual(
                    {item["host"] for item in result["verify_matrix"]["include"]},
                    expected_hosts,
                )
                self.assertEqual(len(result["verify_matrix"]["include"]), expected_lanes)
                self.assertEqual(len(result["build_matrix"]["include"]), expected_lanes * 2)

    def test_scope_rejects_unknown_values(self) -> None:
        with self.assertRaises(matrix.ContractError):
            project(scope="macos-aarch64")

    def test_independent_input_digest_and_commit_bindings(self) -> None:
        base_plan = plan_fixture()
        for key, value in (
            ("inputs_sha256", "e" * 64),
            ("producer_commit", "c" * 40),
            ("tools_commit", "f" * 40),
        ):
            with self.subTest(key=key):
                plan = copy.deepcopy(base_plan)
                plan[key] = value
                self.assert_contract_error(plan)

        for argument, value in (
            ("inputs_sha256", "e" * 64),
            ("producer_commit", "c" * 40),
            ("tools_commit", "f" * 40),
        ):
            with self.subTest(argument=argument):
                kwargs = {
                    "inputs_sha256": INPUTS_SHA256,
                    "producer_commit": PRODUCER_COMMIT,
                    "tools_commit": TOOLS_COMMIT,
                    "scope": "all",
                }
                kwargs[argument] = value
                with self.assertRaises(matrix.ContractError):
                    matrix.project(plan_fixture(), policy_fixture(), **kwargs)

    def test_rejects_malformed_group_object_identifiers(self) -> None:
        for key, value in (
            ("source_commit", "A" * 40),
            ("source_tree", "g" * 40),
            ("upstream_commit", "a" * 39),
        ):
            with self.subTest(key=key):
                plan = plan_fixture()
                plan["groups"][0][key] = value
                self.assert_contract_error(plan)

    def test_rejects_wrong_plan_identity_assurance_and_unknown_fields(self) -> None:
        for key, value in (
            ("schema", "aros-toolchain-producer-stage-v1"),
            ("operation", "build"),
            ("release_format", "legacy"),
            ("assurance", "verified-build"),
        ):
            with self.subTest(key=key):
                plan = plan_fixture()
                plan[key] = value
                self.assert_contract_error(plan)

        plan = plan_fixture()
        plan["unexpected"] = True
        self.assert_contract_error(plan)

        plan = plan_fixture()
        plan["groups"][0]["unexpected"] = True
        self.assert_contract_error(plan)

        plan = plan_fixture()
        plan["lanes"][0]["unexpected"] = True
        self.assert_contract_error(plan)

    def test_rejects_missing_duplicate_and_extra_lanes(self) -> None:
        plan = plan_fixture()
        plan["lanes"].pop()
        plan["lane_count"] -= 1
        self.assert_contract_error(plan)

        plan = plan_fixture()
        plan["lanes"].append(copy.deepcopy(plan["lanes"][0]))
        plan["lane_count"] += 1
        self.assert_contract_error(plan)

        plan = plan_fixture()
        plan["lanes"].append({
            "group_id": "gnu-rv32",
            "host": "linux-x86_64",
            "target_profile": "rv64-unreviewed",
        })
        plan["lane_count"] += 1
        self.assert_contract_error(plan)

    def test_rejects_unreviewed_hosts_profiles_and_policy_extensions(self) -> None:
        for host in ("linux-rv64", "macos-x86_64"):
            with self.subTest(host=host):
                plan = plan_fixture()
                plan["hosts"].append(host)
                plan["lanes"].append({
                    "group_id": "gnu-rv32",
                    "host": host,
                    "target_profile": "rv32-esp32p4",
                })
                plan["lane_count"] += 1
                self.assert_contract_error(plan)

        plan = plan_fixture()
        plan["lanes"][0]["target_profile"] = "pc-rv64"
        self.assert_contract_error(plan)

        policy = policy_fixture()
        policy["hosts"]["linux-rv64"] = "ubuntu-24.04"
        self.assert_contract_error(policy=policy)

        policy = policy_fixture()
        policy["groups"]["llvm"].append("macos-x86_64")
        self.assert_contract_error(policy=policy)

    def test_policy_rejects_unsafe_runner_labels(self) -> None:
        for label in ("", "bad runner", "ubuntu-24.04\nrun: echo", "$" + "{{ secrets.RUNNER }}", 7):
            with self.subTest(label=label):
                policy = policy_fixture()
                policy["hosts"]["linux-aarch64"] = label
                self.assert_contract_error(policy=policy)

    def test_rejects_malformed_policy_schema_hosts_and_groups(self) -> None:
        malformed = []
        policy = policy_fixture()
        policy["schema"] = "aros-toolchain-workflow-policy-v1"
        malformed.append(policy)
        policy = policy_fixture()
        policy["unexpected"] = "field"
        malformed.append(policy)
        policy = policy_fixture()
        policy["hosts"]["linux-x86_64"] = ""
        malformed.append(policy)
        policy = policy_fixture()
        policy["groups"]["gnu-rv32"] = "rv32-esp32p4"
        malformed.append(policy)
        policy = policy_fixture()
        policy["groups"]["llvm"].append("pc-x86_64")
        malformed.append(policy)
        policy = policy_fixture()
        del policy["groups"]["gnu-rv32"]
        malformed.append(policy)
        for index, policy in enumerate(malformed):
            with self.subTest(policy_case=index):
                self.assert_contract_error(policy=policy)

    def test_rejects_unsafe_or_duplicate_document_references(self) -> None:
        for unsafe in ("../recipe.json", "dir/recipe.json", ".", "", "recipe\\name.json"):
            with self.subTest(filename=unsafe):
                plan = plan_fixture()
                plan["groups"][0]["recipe"]["file"] = unsafe
                self.assert_contract_error(plan)

        plan = plan_fixture()
        plan["groups"][0]["source_lock"]["file"] = plan["groups"][0]["recipe"]["file"]
        self.assert_contract_error(plan)

        plan = plan_fixture()
        plan["groups"][1]["profiles"]["file"] = plan["groups"][0]["profiles"]["file"]
        self.assert_contract_error(plan)

        plan = plan_fixture()
        plan["groups"][0]["recipe"]["sha256"] = "A" * 64
        self.assert_contract_error(plan)

    def test_rejects_boolean_lane_count_and_malformed_counts(self) -> None:
        for value in (True, False, 12.0, "12", 0, -1):
            with self.subTest(value=value):
                plan = plan_fixture()
                plan["lane_count"] = value
                self.assert_contract_error(plan)

    def test_output_is_stable_when_input_arrays_are_reordered(self) -> None:
        original = plan_fixture()
        reordered = copy.deepcopy(original)
        reordered["hosts"].reverse()
        reordered["groups"].reverse()
        reordered["lanes"].reverse()
        reordered_policy = policy_fixture()
        reordered_policy["hosts"] = dict(reversed(list(reordered_policy["hosts"].items())))
        reordered_policy["groups"] = dict(reversed(list(reordered_policy["groups"].items())))
        for profile_list in reordered_policy["groups"].values():
            profile_list.reverse()
        self.assertEqual(project(original), project(reordered, reordered_policy))


class ReadJsonTests(unittest.TestCase):
    def test_reads_a_regular_absolute_json_file_and_checks_digest(self) -> None:
        payload = b'{"ok":true}\n'
        with tempfile.TemporaryDirectory(prefix="release-matrix-json-test.") as directory:
            path = Path(directory) / "input.json"
            path.write_bytes(payload)
            expected = hashlib.sha256(payload).hexdigest()
            self.assertEqual(matrix.read_json(path, expected_sha256=expected), {"ok": True})
            with self.assertRaises(matrix.ContractError):
                matrix.read_json(path, expected_sha256="0" * 64)
            with self.assertRaises(matrix.ContractError):
                matrix.read_json(path, expected_sha256="not-a-sha256")

    def test_pinned_policy_digest_rejects_a_changed_runner_map(self) -> None:
        with tempfile.TemporaryDirectory(prefix="release-matrix-policy-test.") as directory:
            path = Path(directory) / "policy.json"
            original = json.dumps(policy_fixture(), separators=(",", ":")).encode("utf-8")
            path.write_bytes(original)
            pinned_digest = hashlib.sha256(original).hexdigest()
            self.assertEqual(
                matrix.read_json(path, expected_sha256=pinned_digest),
                policy_fixture(),
            )

            changed = policy_fixture()
            changed["hosts"]["linux-aarch64"] = "macos-15"
            path.write_text(json.dumps(changed, separators=(",", ":")), encoding="utf-8")
            with self.assertRaises(matrix.ContractError):
                matrix.read_json(path, expected_sha256=pinned_digest)

    def test_rejects_relative_paths_duplicate_keys_and_nonfinite_numbers(self) -> None:
        with tempfile.TemporaryDirectory(prefix="release-matrix-json-test.") as directory:
            path = Path(directory) / "input.json"
            path.write_text('{"key":1,"key":2}', encoding="utf-8")
            with self.assertRaises(matrix.ContractError):
                matrix.read_json(path)
            path.write_text('{"value":NaN}', encoding="utf-8")
            with self.assertRaises(matrix.ContractError):
                matrix.read_json(path)
            with self.assertRaises(matrix.ContractError):
                matrix.read_json(Path(os.path.relpath(path)))

    def test_rejects_oversized_files_and_symlinks(self) -> None:
        with tempfile.TemporaryDirectory(prefix="release-matrix-json-test.") as directory:
            root = Path(directory)
            path = root / "input.json"
            path.write_bytes(b" " * (1024 * 1024 + 1))
            with self.assertRaises(matrix.ContractError):
                matrix.read_json(path)

            target = root / "target.json"
            target.write_text("{}", encoding="utf-8")
            link = root / "link.json"
            try:
                link.symlink_to(target)
            except (NotImplementedError, OSError):
                self.skipTest("symlinks are unavailable on this filesystem")
            with self.assertRaises((matrix.ContractError, OSError)):
                matrix.read_json(link)

            with self.assertRaises(matrix.ContractError):
                matrix.read_json(root)


class NativePlanTests(unittest.TestCase):
    @staticmethod
    def executable(directory: Path, source: str) -> Path:
        path = directory / "fake-aros"
        path.write_text("#!/usr/bin/env python3\n" + source, encoding="utf-8")
        path.chmod(0o700)
        return path

    def test_calls_native_command_with_the_exact_bound_arguments(self) -> None:
        with tempfile.TemporaryDirectory(prefix="release-matrix-native-test.") as temporary:
            root = Path(temporary).resolve()
            executable = self.executable(
                root,
                "import json, sys\nprint(json.dumps(sys.argv[1:]))\n",
            )
            directory = root / "collection"
            result = matrix.native_plan(executable, directory, INPUTS_SHA256)
            self.assertEqual(result, [
                "--diagnostic-format=json",
                "toolchain",
                "producer",
                "release-plan",
                "--directory",
                str(directory),
                "--inputs-sha256",
                INPUTS_SHA256,
                "--format",
                "json",
            ])

    def test_rejects_a_nonzero_native_exit(self) -> None:
        with tempfile.TemporaryDirectory(prefix="release-matrix-native-test.") as temporary:
            root = Path(temporary).resolve()
            executable = self.executable(root, "import sys\nsys.exit(7)\n")
            with self.assertRaises(matrix.ContractError):
                matrix.native_plan(executable, root / "collection", INPUTS_SHA256)


class CompositeActionTests(unittest.TestCase):
    @staticmethod
    def executable(directory: Path, source: str) -> Path:
        path = directory / "fake-aros"
        path.write_text("#!/usr/bin/env python3\n" + source, encoding="utf-8")
        path.chmod(0o700)
        return path

    def test_actual_composite_run_writes_seven_outputs_and_rejects_failures(self) -> None:
        action_script = extract_run_script(ACTION_FILE)
        with tempfile.TemporaryDirectory(prefix="release-matrix-action-test.") as temporary:
            root = Path(temporary).resolve()
            native_plan_json = json.dumps(plan_fixture(), separators=(",", ":"))
            fake = self.executable(root, f"print({native_plan_json!r})\n")
            policy_path = root / "policy.json"
            policy_bytes = json.dumps(policy_fixture(), separators=(",", ":")).encode("utf-8")
            policy_path.write_bytes(policy_bytes)
            policy_digest = hashlib.sha256(policy_bytes).hexdigest()

            def action_environment(output_path: Path) -> dict[str, str]:
                environment = os.environ.copy()
                environment.update({
                    "GITHUB_ACTION_PATH": str(ACTION_DIRECTORY.resolve()),
                    "GITHUB_OUTPUT": str(output_path),
                    "MATRIX_AROS": str(fake),
                    "MATRIX_DIRECTORY": str(root / "staged-inputs"),
                    "MATRIX_INPUTS_SHA256": INPUTS_SHA256,
                    "MATRIX_PRODUCER_COMMIT": PRODUCER_COMMIT,
                    "MATRIX_TOOLS_COMMIT": TOOLS_COMMIT,
                    "MATRIX_POLICY": str(policy_path),
                    "MATRIX_POLICY_SHA256": policy_digest,
                    "MATRIX_SCOPE": "all",
                })
                return environment

            def run_action(output_path: Path) -> subprocess.CompletedProcess:
                return subprocess.run(
                    ["bash", "-c", action_script],
                    env=action_environment(output_path),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=30,
                    check=False,
                )

            success_output = root / "successful-output"
            result = run_action(success_output)
            self.assertEqual(result.returncode, 0, result.stderr)
            values = dict(
                line.split("=", 1)
                for line in success_output.read_text(encoding="utf-8").splitlines()
            )
            expected_keys = {
                "host_matrix", "group_matrix", "build_matrix", "verify_matrix",
                "complete_lane_count", "selected_lane_count", "build_count",
            }
            self.assertEqual(set(values), expected_keys)
            self.assertEqual(len(values), 7)
            self.assertEqual(len(json.loads(values["host_matrix"])["include"]), 3)
            self.assertEqual(len(json.loads(values["group_matrix"])["include"]), 2)
            self.assertEqual(len(json.loads(values["verify_matrix"])["include"]), 12)
            self.assertEqual(len(json.loads(values["build_matrix"])["include"]), 24)
            self.assertEqual(values["complete_lane_count"], "12")
            self.assertEqual(values["selected_lane_count"], "12")
            self.assertEqual(values["build_count"], "24")

            changed_policy = copy.deepcopy(policy_fixture())
            changed_policy["hosts"]["linux-aarch64"] = "macos-15"
            policy_path.write_text(
                json.dumps(changed_policy, separators=(",", ":")),
                encoding="utf-8",
            )
            changed_policy_output = root / "changed-policy-output"
            self.assertFalse(changed_policy_output.exists())
            result = run_action(changed_policy_output)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(changed_policy_output.exists())

            policy_path.write_bytes(policy_bytes)
            fake.write_text("#!/usr/bin/env python3\nimport sys\nsys.exit(7)\n", encoding="utf-8")
            fake.chmod(0o700)
            native_failure_output = root / "native-failure-output"
            self.assertFalse(native_failure_output.exists())
            result = run_action(native_failure_output)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(native_failure_output.exists())


if __name__ == "__main__":
    unittest.main()
