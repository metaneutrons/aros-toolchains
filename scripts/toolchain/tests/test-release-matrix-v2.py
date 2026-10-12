"""Contract tests for the bounded release-plan scheduling projection.

Fixtures have the producer release-plan shape. They demonstrate scheduling
only; this test helper does not parse or authenticate collection documents.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "select-release-matrix-v2.py"
ACTIVE_HOSTS = ("linux-aarch64", "linux-x86_64", "macos-aarch64")
INPUTS_SHA256 = "d" * 64
PRODUCER_COMMIT = "a" * 40
TOOLS_COMMIT = "b" * 40
SDK_PROFILE_ID = re.compile(r"[a-z0-9](?:[-_a-z0-9]{0,126}[a-z0-9])?\Z")


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def owner_plan(profiles_by_group: dict[str, list[str]] | None = None) -> dict[str, object]:
    if profiles_by_group is None:
        profiles_by_group = {
            "family-alpha": ["alpha-one", "alpha-two"],
            "family-beta": ["beta-one", "beta-two"],
        }
    groups: list[dict[str, object]] = []
    lanes: list[dict[str, str]] = []
    sdks: list[dict[str, object]] = []
    for index, (group_id, profile_ids) in enumerate(sorted(profiles_by_group.items())):
        source_commit = f"{index + 1:040x}"
        group: dict[str, object] = {
            "group_id": group_id,
            "source_commit": source_commit,
            "source_tree": f"{index + 11:040x}",
            "upstream_commit": source_commit,
        }
        for reference_name in ("recipe", "source_lock", "profiles"):
            filename = f"{group_id}-{reference_name.replace('_', '-')}.json"
            group[reference_name] = {"file": filename, "sha256": _digest(filename)}
        groups.append(group)
        for profile in profile_ids:
            for host in ACTIVE_HOSTS:
                lanes.append({"group_id": group_id, "host": host, "target_profile": profile})
        sdk_profiles = [profile for profile in profile_ids if SDK_PROFILE_ID.fullmatch(profile)]
        if sdk_profiles:
            sdk_id = f"sdk-{group_id}"
            identity_file = f"{sdk_id}-identity.json"
            sdks.append(
                {
                    "id": sdk_id,
                    "identity": {"file": identity_file, "sha256": _digest(identity_file)},
                    "source_preset": f"source-{group_id}",
                    "compiler_profiles": [
                        {"group_id": group_id, "profile": profile}
                        for profile in sorted(sdk_profiles)
                    ],
                }
            )
    return {
        "schema": "aros-toolchain-producer-stage-v2",
        "operation": "release-plan",
        "release_format": "family-v2",
        "assurance": "input-binding-only",
        "inputs_sha256": INPUTS_SHA256,
        "producer_commit": PRODUCER_COMMIT,
        "tools_commit": TOOLS_COMMIT,
        "hosts": list(ACTIVE_HOSTS),
        "groups": groups,
        "lane_count": len(lanes),
        "lanes": lanes,
        "sdk_count": len(sdks),
        "sdks": sdks,
    }


def plan_bytes(plan: dict[str, object]) -> bytes:
    return json.dumps(plan, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


class ReleaseMatrixV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="release-matrix-v2.")
        self.root = Path(self.temporary.name)
        self.serial = 0

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_cli(
        self,
        raw: bytes,
        *,
        event: str = "push",
        scope: str = "full",
        diagnostic_group: str | None = None,
        github_output: Path | None = None,
        plan_path: Path | None = None,
        plan_sha256: str | None = None,
        inputs_sha256: str = INPUTS_SHA256,
        producer_commit: str = PRODUCER_COMMIT,
        tools_commit: str = TOOLS_COMMIT,
    ) -> subprocess.CompletedProcess[str]:
        self.serial += 1
        if plan_path is None:
            plan_path = self.root / f"plan-{self.serial}.json"
            plan_path.write_bytes(raw)
        arguments = [
            sys.executable,
            "-B",
            str(SCRIPT),
            "--plan",
            str(plan_path),
            "--plan-sha256",
            plan_sha256 or hashlib.sha256(raw).hexdigest(),
            "--inputs-sha256",
            inputs_sha256,
            "--producer-commit",
            producer_commit,
            "--tools-commit",
            tools_commit,
            "--event",
            event,
            "--scope",
            scope,
        ]
        if diagnostic_group is not None:
            arguments.extend(("--diagnostic-group", diagnostic_group))
        if github_output is not None:
            arguments.extend(("--github-output", str(github_output)))
        return subprocess.run(arguments, capture_output=True, text=True, check=False)

    def assert_rejected(self, raw: bytes, **kwargs: object) -> subprocess.CompletedProcess[str]:
        result = self.run_cli(raw, **kwargs)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(result.stdout, "")
        self.assertIn("release matrix selection failed:", result.stderr)
        return result

    def test_full_owner_plan_projects_a_and_b_for_every_actual_lane(self) -> None:
        raw = plan_bytes(owner_plan())
        result = self.run_cli(raw)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(result.stdout.splitlines()), 1)
        self.assertNotIn(" ", result.stdout)
        projection = json.loads(result.stdout)
        self.assertEqual(
            set(projection),
            {
                "schema",
                "assurance",
                "inputs_sha256",
                "plan_sha256",
                "producer_commit",
                "tools_commit",
                "event",
                "scope",
                "complete_selection",
                "host_matrix",
                "verify_matrix",
                "build_matrix",
                "sdk_matrix",
                "build_count",
                "lane_count",
                "sdk_count",
            },
        )
        self.assertEqual(projection["assurance"], "scheduling-only")
        self.assertTrue(projection["complete_selection"])
        self.assertEqual(projection["lane_count"], 12)
        self.assertEqual(projection["build_count"], 24)
        self.assertEqual(len(projection["host_matrix"]["include"]), 3)
        self.assertEqual(len(projection["verify_matrix"]["include"]), 12)
        self.assertEqual(len(projection["build_matrix"]["include"]), 24)
        self.assertEqual(projection["sdk_count"], 2)
        self.assertEqual(
            projection["sdk_matrix"]["include"],
            owner_plan()["sdks"],
        )
        self.assertEqual(
            [entry["copy"] for entry in projection["build_matrix"]["include"][:4]],
            ["a", "b", "a", "b"],
        )
        self.assertEqual(projection["plan_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertNotIn("qualified", projection)
        self.assertNotIn("passed", projection)

    def test_github_output_contains_only_compact_matrices_counts_and_bindings(self) -> None:
        raw = plan_bytes(owner_plan())
        destination = self.root / "github-output"
        destination.write_bytes(b"existing=value\n")
        result = self.run_cli(raw, github_output=destination)
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = destination.read_text(encoding="utf-8").splitlines()
        self.assertEqual(lines[0], "existing=value")
        outputs = dict(line.split("=", 1) for line in lines[1:])
        self.assertEqual(
            set(outputs),
            {
                "host_matrix",
                "verify_matrix",
                "build_matrix",
                "sdk_matrix",
                "lane_count",
                "build_count",
                "sdk_count",
                "plan_sha256",
                "inputs_sha256",
                "producer_commit",
                "tools_commit",
            },
        )
        self.assertEqual(len(outputs["build_matrix"].splitlines()), 1)
        self.assertEqual(json.loads(outputs["verify_matrix"])["include"].__len__(), 12)
        self.assertEqual(outputs["lane_count"], "12")
        self.assertEqual(outputs["build_count"], "24")
        self.assertEqual(outputs["sdk_count"], "2")
        self.assertEqual(len(json.loads(outputs["sdk_matrix"])["include"]), 2)

    def test_manual_linux_scopes_are_subsets_and_profile_changes_are_derived(self) -> None:
        raw = plan_bytes(owner_plan())
        linux = self.run_cli(raw, event="workflow_dispatch", scope="linux")
        self.assertEqual(linux.returncode, 0, linux.stderr)
        linux_projection = json.loads(linux.stdout)
        self.assertFalse(linux_projection["complete_selection"])
        self.assertEqual(linux_projection["lane_count"], 8)
        self.assertEqual(linux_projection["build_count"], 16)
        self.assertEqual(
            {entry["host"] for entry in linux_projection["verify_matrix"]["include"]},
            {"linux-aarch64", "linux-x86_64"},
        )

        x86 = self.run_cli(raw, event="workflow_dispatch", scope="linux-x86_64")
        self.assertEqual(x86.returncode, 0, x86.stderr)
        x86_projection = json.loads(x86.stdout)
        self.assertEqual(x86_projection["lane_count"], 4)
        self.assertEqual(x86_projection["build_count"], 8)
        self.assertEqual(
            {entry["host"] for entry in x86_projection["verify_matrix"]["include"]},
            {"linux-x86_64"},
        )
        self.assertEqual(linux_projection["sdk_matrix"], x86_projection["sdk_matrix"])
        self.assertEqual(linux_projection["sdk_count"], x86_projection["sdk_count"])

        changed_profiles = owner_plan(
            {
                "family-alpha": ["alpha-one", "alpha-two", "alpha-three"],
                "family-beta": ["beta-one", "beta-two"],
            }
        )
        changed = self.run_cli(plan_bytes(changed_profiles))
        self.assertEqual(changed.returncode, 0, changed.stderr)
        changed_projection = json.loads(changed.stdout)
        self.assertEqual(changed_projection["lane_count"], 15)
        self.assertEqual(changed_projection["build_count"], 30)

        native_profile_names = owner_plan(
            {
                "family-alpha": ["gnu_riscv32", "pc-x86_64"],
                "family-beta": ["rpi.aarch64", "x86_64"],
            }
        )
        native = self.run_cli(plan_bytes(native_profile_names))
        self.assertEqual(native.returncode, 0, native.stderr)

    def test_manual_diagnostic_group_narrows_scheduling_and_keeps_sdk_identity(self) -> None:
        plan = owner_plan(
            {
                "gnu": ["gnu_riscv32"],
                "llvm": ["llvm_riscv32"],
            }
        )
        raw = plan_bytes(plan)
        full = self.run_cli(raw)
        self.assertEqual(full.returncode, 0, full.stderr)
        full_projection = json.loads(full.stdout)
        self.assertEqual(len(full_projection["host_matrix"]["include"]), 3)
        self.assertEqual(full_projection["lane_count"], 6)
        self.assertEqual(full_projection["build_count"], 12)
        self.assertEqual(full_projection["sdk_count"], 2)

        diagnostic = self.run_cli(
            raw,
            event="workflow_dispatch",
            scope="linux-x86_64",
            diagnostic_group="gnu",
        )
        self.assertEqual(diagnostic.returncode, 0, diagnostic.stderr)
        projection = json.loads(diagnostic.stdout)
        self.assertFalse(projection["complete_selection"])
        self.assertEqual(projection["diagnostic_group"], "gnu")
        self.assertEqual(projection["host_matrix"]["include"], [
            {"host": "linux-x86_64", "runner": "ubuntu-24.04"}
        ])
        self.assertEqual(
            projection["verify_matrix"]["include"],
            [
                {
                    "group_id": "gnu",
                    "host": "linux-x86_64",
                    "runner": "ubuntu-24.04",
                    "profile": "gnu_riscv32",
                }
            ],
        )
        self.assertEqual(projection["lane_count"], 1)
        self.assertEqual(projection["build_count"], 2)
        self.assertEqual(
            [entry["copy"] for entry in projection["build_matrix"]["include"]],
            ["a", "b"],
        )
        self.assertEqual(projection["sdk_count"], 1)
        self.assertEqual(
            projection["sdk_matrix"]["include"],
            [plan["sdks"][0]],  # SDK identity and all compiler bindings remain intact.
        )

    def test_diagnostic_group_rejections_preserve_github_output(self) -> None:
        raw = plan_bytes(owner_plan())
        rejected_requests = (
            {"event": "push", "scope": "full", "diagnostic_group": "family-alpha"},
            {
                "event": "workflow_dispatch",
                "scope": "full",
                "diagnostic_group": "family-alpha",
            },
            {
                "event": "workflow_dispatch",
                "scope": "linux-x86_64",
                "diagnostic_group": "missing-group",
            },
            {
                "event": "workflow_dispatch",
                "scope": "linux-x86_64",
                "diagnostic_group": "../family-alpha",
            },
        )
        for request in rejected_requests:
            with self.subTest(request=request):
                destination = self.root / f"github-output-{self.serial + 1}"
                destination.write_bytes(b"prior=content\n")
                self.assert_rejected(raw, github_output=destination, **request)
                self.assertEqual(destination.read_bytes(), b"prior=content\n")

        malformed_unselected = owner_plan()
        malformed_unselected["groups"][1]["source_lock"]["sha256"] = "invalid"  # type: ignore[index]
        destination = self.root / f"github-output-{self.serial + 1}"
        destination.write_bytes(b"prior=content\n")
        self.assert_rejected(
            plan_bytes(malformed_unselected),
            event="workflow_dispatch",
            scope="linux-x86_64",
            diagnostic_group="family-alpha",
            github_output=destination,
        )
        self.assertEqual(destination.read_bytes(), b"prior=content\n")

    def test_group_diagnostic_preserves_shared_sdk_compiler_bindings(self) -> None:
        plan = owner_plan({"gnu": ["gnu_riscv32"], "llvm": ["llvm_riscv32"]})
        shared = plan["sdks"][0]
        shared["compiler_profiles"].extend(plan["sdks"][1]["compiler_profiles"])
        plan["sdks"] = [shared]
        plan["sdk_count"] = 1
        result = self.run_cli(
            plan_bytes(plan),
            event="workflow_dispatch",
            scope="linux-x86_64",
            diagnostic_group="gnu",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        projection = json.loads(result.stdout)
        self.assertFalse(projection["complete_selection"])
        self.assertEqual(projection["lane_count"], 1)
        self.assertEqual(projection["sdk_matrix"]["include"], [shared])
        self.assertEqual(len(projection["sdk_matrix"]["include"][0]["compiler_profiles"]), 2)

    def test_rejects_duplicate_unknown_and_incorrectly_bound_json(self) -> None:
        duplicate = b'{"schema":"aros-toolchain-producer-stage-v2","schema":"aros-toolchain-producer-stage-v2"}'
        self.assert_rejected(duplicate)

        plan = owner_plan()
        plan["unexpected"] = "field"
        self.assert_rejected(plan_bytes(plan))

        plan = owner_plan()
        plan["inputs_sha256"] = "e" * 64
        self.assert_rejected(plan_bytes(plan))
        self.assert_rejected(plan_bytes(owner_plan()), inputs_sha256="e" * 64)
        self.assert_rejected(plan_bytes(owner_plan()), plan_sha256="e" * 64)
        self.assert_rejected(plan_bytes(owner_plan()), producer_commit="f" * 40)
        self.assert_rejected(plan_bytes(owner_plan()), tools_commit="f" * 40)

        plan = owner_plan()
        plan["groups"][0]["untrusted"] = "field"  # type: ignore[index]
        self.assert_rejected(plan_bytes(plan))

        plan = owner_plan()
        plan["groups"][1]["group_id"] = plan["groups"][0]["group_id"]  # type: ignore[index]
        self.assert_rejected(plan_bytes(plan))

        plan = owner_plan()
        plan["groups"][0]["source_commit"] = "f" * 40  # type: ignore[index]
        self.assert_rejected(plan_bytes(plan))

    def test_rejects_invalid_sdk_count_fields_references_and_profile_joins(self) -> None:
        plan = owner_plan()
        plan["sdk_count"] = True
        self.assert_rejected(plan_bytes(plan))

        plan = owner_plan()
        plan["sdk_count"] = 1
        self.assert_rejected(plan_bytes(plan))

        plan = owner_plan()
        plan["sdks"][0]["unexpected"] = "field"  # type: ignore[index]
        self.assert_rejected(plan_bytes(plan))

        plan = owner_plan()
        plan["sdks"][0]["source_preset"] = "../unsafe"  # type: ignore[index]
        self.assert_rejected(plan_bytes(plan))

        plan = owner_plan()
        plan["sdks"][0]["identity"]["file"] = plan["groups"][0]["recipe"]["file"]  # type: ignore[index]
        self.assert_rejected(plan_bytes(plan))

        plan = owner_plan()
        plan["sdks"][0]["identity"]["sha256"] = "invalid"  # type: ignore[index]
        self.assert_rejected(plan_bytes(plan))

        plan = owner_plan()
        plan["sdks"][0]["compiler_profiles"][0]["group_id"] = "unknown-group"  # type: ignore[index]
        self.assert_rejected(plan_bytes(plan))

        plan = owner_plan()
        plan["sdks"][0]["compiler_profiles"][0]["profile"] = "unknown-profile"  # type: ignore[index]
        self.assert_rejected(plan_bytes(plan))

        plan = owner_plan()
        duplicate = dict(plan["sdks"][0]["compiler_profiles"][0])  # type: ignore[index]
        plan["sdks"][0]["compiler_profiles"].append(duplicate)  # type: ignore[index]
        self.assert_rejected(plan_bytes(plan))

        plan = owner_plan()
        plan["sdks"][0]["compiler_profiles"].reverse()  # type: ignore[index]
        self.assert_rejected(plan_bytes(plan))

        plan = owner_plan()
        plan["sdks"].reverse()  # type: ignore[union-attr]
        self.assert_rejected(plan_bytes(plan))

        plan = owner_plan()
        plan["sdks"][0]["id"] = "SDK-UPPER"  # type: ignore[index]
        self.assert_rejected(plan_bytes(plan))

        plan = owner_plan()
        plan["sdks"][0]["compiler_profiles"] = []  # type: ignore[index]
        self.assert_rejected(plan_bytes(plan))

        plan = owner_plan()
        plan["sdks"][0]["compiler_profiles"] = [
            {"group_id": "family-alpha", "profile": "alpha-one"}
            for _ in range(65)
        ]  # type: ignore[index]
        self.assert_rejected(plan_bytes(plan))

    def test_empty_sdk_selection_is_a_valid_closed_projection(self) -> None:
        plan = owner_plan()
        plan["sdks"] = []
        plan["sdk_count"] = 0
        result = self.run_cli(plan_bytes(plan))
        self.assertEqual(result.returncode, 0, result.stderr)
        projection = json.loads(result.stdout)
        self.assertEqual(projection["sdk_count"], 0)
        self.assertEqual(projection["sdk_matrix"], {"include": []})

    def test_rejects_lane_group_count_host_order_and_profile_violations(self) -> None:
        plan = owner_plan()
        plan["hosts"] = ["linux-x86_64", "linux-aarch64", "macos-aarch64"]
        self.assert_rejected(plan_bytes(plan))

        plan = owner_plan()
        plan["groups"].reverse()  # type: ignore[union-attr]
        self.assert_rejected(plan_bytes(plan))

        plan = owner_plan()
        plan["lanes"][0]["group_id"] = "unknown-family"  # type: ignore[index]
        self.assert_rejected(plan_bytes(plan))

        plan = owner_plan()
        del plan["lanes"][0]  # type: ignore[index]
        plan["lane_count"] = len(plan["lanes"])  # type: ignore[arg-type]
        self.assert_rejected(plan_bytes(plan))

        plan = owner_plan()
        plan["lanes"].append(dict(plan["lanes"][0]))  # type: ignore[union-attr,index]
        plan["lane_count"] = len(plan["lanes"])  # type: ignore[arg-type]
        self.assert_rejected(plan_bytes(plan))

        plan = owner_plan()
        plan["lanes"][0]["host"], plan["lanes"][1]["host"] = (  # type: ignore[index]
            plan["lanes"][1]["host"],
            plan["lanes"][0]["host"],
        )
        self.assert_rejected(plan_bytes(plan))

        plan = owner_plan()
        plan["lane_count"] = True
        self.assert_rejected(plan_bytes(plan))

        plan = owner_plan()
        plan["lanes"][6]["target_profile"] = "alpha-one"  # type: ignore[index]
        self.assert_rejected(plan_bytes(plan))

        plan = owner_plan()
        plan["lanes"] = plan["lanes"][:6]  # type: ignore[index]
        plan["lane_count"] = len(plan["lanes"])  # type: ignore[arg-type]
        self.assert_rejected(plan_bytes(plan))

        profiles = {"family-alpha": [f"alpha-{index:02d}" for index in range(43)], "family-beta": ["beta-one"]}
        self.assert_rejected(plan_bytes(owner_plan(profiles)))

    def test_rejects_scope_mismatches_and_oversize_plan(self) -> None:
        raw = plan_bytes(owner_plan())
        self.assert_rejected(raw, event="workflow_dispatch", scope="full")
        self.assert_rejected(raw, event="push", scope="linux")
        self.assert_rejected(b" " * (1024 * 1024 + 1))

    def test_plan_and_github_output_are_opened_without_following_symlinks(self) -> None:
        raw = plan_bytes(owner_plan())
        target = self.root / "target-plan.json"
        target.write_bytes(raw)
        plan_link = self.root / "plan-link.json"
        plan_link.symlink_to(target)
        result = self.run_cli(raw, plan_path=plan_link)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

        output_target = self.root / "real-output"
        output_target.write_bytes(b"unchanged\n")
        output_link = self.root / "output-link"
        output_link.symlink_to(output_target)
        result = self.run_cli(raw, github_output=output_link)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertEqual(output_target.read_bytes(), b"unchanged\n")

    def test_validation_failure_leaves_github_output_unchanged(self) -> None:
        plan = owner_plan()
        plan["lane_count"] = 99
        destination = self.root / "github-output"
        destination.write_bytes(b"prior=content\n")
        result = self.run_cli(plan_bytes(plan), github_output=destination)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertEqual(destination.read_bytes(), b"prior=content\n")

    def test_github_output_cannot_alias_the_retained_plan(self) -> None:
        raw = plan_bytes(owner_plan())
        selected = self.root / "selected-plan.json"
        selected.write_bytes(raw)
        alias = self.root / "output-hardlink"
        os.link(selected, alias)
        for destination in (selected, alias):
            result = self.run_cli(raw, plan_path=selected, github_output=destination)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must not alias the selected plan", result.stderr)
            self.assertEqual(result.stdout, "")
            self.assertEqual(selected.read_bytes(), raw)
            self.assertEqual(alias.read_bytes(), raw)


if __name__ == "__main__":
    unittest.main()
