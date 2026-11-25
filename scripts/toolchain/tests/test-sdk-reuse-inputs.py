"""Focused offline contract tests for sdk-reuse-inputs.py."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts/toolchain/sdk-reuse-inputs.py"
SPEC = importlib.util.spec_from_file_location("sdk_reuse_inputs", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
SDK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SDK)


def run(*args: str, cwd: Path) -> None:
    subprocess.run(args, cwd=cwd, check=True, capture_output=True)


class Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.source = self.root / "source"
        self.producer = self.root / "producer"
        self.inputs = self.root / "inputs"
        self.source.mkdir()
        self.producer.mkdir()
        self.inputs.mkdir()
        for repo in (self.source, self.producer):
            run("git", "init", "-q", cwd=repo)
            run("git", "config", "user.email", "test@example.invalid", cwd=repo)
            run("git", "config", "user.name", "SDK test", cwd=repo)
        self.manifest_path = self.root / "compiler-manifest.json"
        self._write_source()
        self._write_producer()
        self._write_inputs()
        self._commit(self.source, "source baseline")
        self._commit(self.producer, "producer baseline")
        self._write_manifest()

    def _write(self, path: Path, value: str | bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(value, bytes):
            path.write_bytes(value)
        else:
            path.write_text(value, encoding="utf-8")

    def _write_source(self) -> None:
        self._write(
            self.source / "aros-targets.toml",
            """\
[host_compiler]
version = "1"

[[targets]]
name = "target-a"
sdk_consumer_contract = "contracts/a.json"
abi = "a"

[[targets]]
name = "target-b"
sdk_consumer_contract = "contracts/b.json"
abi = "b"
""",
        )
        self._write(self.source / "src/a.c", "int a = 1;\n")
        self._write(self.source / "src/b.c", "int b = 1;\n")
        self._write(self.source / "gen/a.py", "print('a')\n")
        self._write(self.source / "gen/b.py", "print('b')\n")
        self._write(self.source / "README.md", "documentation\n")
        for target, source, generator in (("a", "src/a.c", "gen/a.py"), ("b", "src/b.c", "gen/b.py")):
            document = {
                "schema": "test-sdk-contract-v1",
                "profile": f"profile-{target}",
                "target": {"target_triple": f"{target}-unknown", "abi": target},
                "inputs": [{"path": "aros-targets.toml"}, {"path": source}, {"path": generator}],
                "host_make_variables": {"linux-x86_64": {"TARGET_FLAGS": f"-{target}"}},
            }
            self._write(self.source / f"contracts/{target}.json", json.dumps(document, sort_keys=True))

    def _write_producer(self) -> None:
        self._write(self.producer / "unclassified.py", "print('unknown')\n")
        self._write(self.producer / "docs/README.md", "producer documentation\n")

    def _write_inputs(self) -> None:
        sdks = []
        generation = []
        for target in ("a", "b"):
            sdk = {
                "id": f"sdk-{target}",
                "source_preset": f"target-{target}",
                "identity": {"file": f"identity-{target}.json", "sha256": "0" * 64},
                "compiler_profiles": [{"group_id": f"group-{target}", "profile": f"profile-{target}"}],
            }
            sdks.append(sdk)
            generation.append(
                {
                    "sdk_id": sdk["id"],
                    "group_id": f"group-{target}",
                    "profile": f"profile-{target}",
                    "host": "linux-x86_64",
                }
            )
            self._write(
                self.inputs / f"identity-{target}.json",
                json.dumps(
                    {
                        "sdk_id": sdk["id"],
                        "source": {
                            "commit": "old",
                            "git_tree": "old",
                            "content_sha256": "3" * 64,
                            "contract_sha256": "4" * 64,
                        },
                        "target": {"target_triple": f"{target}-unknown", "abi": target},
                    },
                    sort_keys=True,
                ),
            )
        plan = {"sdks": sdks, "sdk_generation_lanes": generation}
        release = {"tools_commit": "a" * 40}
        self._write(self.inputs / "plan.json", json.dumps(plan, sort_keys=True))
        self._write(self.inputs / "toolchain-release-inputs-v2.json", json.dumps(release, sort_keys=True))

    def _write_manifest(self, *, package_delta: str = "", provenance_delta: str = "") -> None:
        comparisons = {}
        for target in ("a", "b"):
            profile = f"profile-{target}"
            package_hash = hashlib.sha256(
                (profile + (package_delta if target == "a" else "")).encode()
            ).hexdigest()
            manifest_hash = hashlib.sha256(("manifest-" + profile).encode()).hexdigest()
            receipt = {
                "schema": 1,
                "operation": "compare",
                "byte_identical": True,
                "members": [
                    {"name": f"compiler-{profile}.tar.xz", "sha256": package_hash, "size": 11},
                    {"name": f"compiler-{profile}.tar.xz.manifest.json", "sha256": manifest_hash, "size": 12},
                ],
            }
            comparisons[profile] = {
                "group_id": f"group-{target}",
                "host": "linux-x86_64",
                "target_profile": profile,
                "receipt_json": json.dumps(receipt),
                "receipt_sha256": "1" * 64,
                "owners": {
                    "a": {"original_job_id": 1, "origin_sha256": provenance_delta + "2" * 63},
                    "b": {"original_job_id": 2, "origin_sha256": "3" * 64},
                },
            }
        manifest = {
            "manifest_sha256": "4" * 64,
            "bindings": {"inputs_sha256": "5" * 64, "tools_commit": "a" * 40, "run_id": 123},
            "comparisons": comparisons,
        }
        self.manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")

    def _commit(self, repo: Path, message: str) -> None:
        run("git", "add", ".", cwd=repo)
        run("git", "commit", "-qm", message, cwd=repo)

    def fingerprint(self) -> dict[str, dict]:
        def head(repo):
            return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()

        def update(path, function):
            value = json.loads(path.read_bytes())
            function(value)
            path.write_text(json.dumps(value))

        update(
            self.inputs / "toolchain-release-inputs-v2.json",
            lambda d: d.update(producer_commit=head(self.producer)),
        )
        update(self.manifest_path, lambda d: d.update(context={"producer_commit": head(self.producer)}))
        for path in self.inputs.glob("identity-*.json"):
            update(
                path, lambda d: d["source"].update(commit=head(self.source), content_sha256=head(self.source))
            )
        plan_path = self.inputs / "plan.json"
        plan = json.loads(plan_path.read_bytes())
        for row in plan["sdks"]:
            ref = row["identity"]
            ref["sha256"] = hashlib.sha256((self.inputs / ref["file"]).read_bytes()).hexdigest()
        plan_path.write_text(json.dumps(plan))
        return SDK.compute(self.inputs, self.manifest_path, self.source, self.producer)


class TestSdkReuseInputs(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.fixture = Fixture(Path(temporary.name).resolve())

    def test_contract_returns_every_planned_sdk_without_host_paths(self) -> None:
        result = self.fixture.fingerprint()
        self.assertEqual(set(result), {"sdk-a", "sdk-b"})
        for record in result.values():
            self.assertRegex(record["input_sha256"], r"^[0-9a-f]{64}$")
            self.assertIn("contract", record["components"])
            self.assertNotIn(str(self.fixture.root), json.dumps(record))

    def test_documentation_change_and_its_source_pin_are_reusable(self) -> None:
        def pin_source():
            sha = SDK.git(self.fixture.source, "rev-parse", "HEAD").decode().strip()
            self.fixture._write(
                self.fixture.producer / "toolchains/compiler-sdk-ci-selection-v2.json",
                json.dumps({"source_commit": sha}),
            )
            self.fixture._write(self.fixture.producer / ".github/workflows/ci.yml", f"source: {sha}\n")

        pin_source()
        self.fixture._commit(self.fixture.producer, "pin baseline")
        before = self.fixture.fingerprint()
        self.fixture._write(self.fixture.source / "README.md", "new explanation\n")
        self.fixture._commit(self.fixture.source, "docs: clarify")
        self.fixture._write(self.fixture.producer / "docs/README.md", "new explanation\n")
        pin_source()
        self.fixture._commit(self.fixture.producer, "pin documentation update")
        after = self.fixture.fingerprint()
        self.assertEqual(before["sdk-a"]["input_sha256"], after["sdk-a"]["input_sha256"])
        self.assertEqual(before["sdk-b"]["input_sha256"], after["sdk-b"]["input_sha256"])

    def test_uncommitted_worktree_bytes_are_not_used(self) -> None:
        before = self.fixture.fingerprint()
        self.fixture._write(self.fixture.source / "src/a.c", "int a = 999;\n")
        after = self.fixture.fingerprint()
        self.assertEqual(before["sdk-a"]["input_sha256"], after["sdk-a"]["input_sha256"])

    def test_target_build_and_abi_changes_are_independent(self) -> None:
        before = self.fixture.fingerprint()
        self.fixture._write(self.fixture.source / "src/a.c", "int a = 2;\n")
        self.fixture._commit(self.fixture.source, "build: change A")
        changed = self.fixture.fingerprint()
        self.assertNotEqual(before["sdk-a"]["input_sha256"], changed["sdk-a"]["input_sha256"])
        self.assertEqual(before["sdk-b"]["input_sha256"], changed["sdk-b"]["input_sha256"])

        self.fixture._write(
            self.fixture.source / "aros-targets.toml",
            self.fixture.source.joinpath("aros-targets.toml").read_text().replace('abi = "a"', 'abi = "a2"'),
        )
        self.fixture._commit(self.fixture.source, "abi: change A")
        abi_changed = self.fixture.fingerprint()
        self.assertNotEqual(changed["sdk-a"]["input_sha256"], abi_changed["sdk-a"]["input_sha256"])
        self.assertEqual(changed["sdk-b"]["input_sha256"], abi_changed["sdk-b"]["input_sha256"])

    def test_new_declared_input_changes_only_its_sdk(self) -> None:
        before = self.fixture.fingerprint()
        self.fixture._write(self.fixture.source / "src/a-extra.h", "#define A_EXTRA 1\n")
        contract = json.loads((self.fixture.source / "contracts/a.json").read_text())
        contract["inputs"].append({"path": "src/a-extra.h"})
        self.fixture._write(self.fixture.source / "contracts/a.json", json.dumps(contract, sort_keys=True))
        self.fixture._commit(self.fixture.source, "build: add A input")
        after = self.fixture.fingerprint()
        self.assertNotEqual(before["sdk-a"]["input_sha256"], after["sdk-a"]["input_sha256"])
        self.assertEqual(before["sdk-b"]["input_sha256"], after["sdk-b"]["input_sha256"])

    def test_unknown_build_file_rebuilds_all_conservatively(self) -> None:
        before = self.fixture.fingerprint()
        self.fixture._write(self.fixture.source / "new-generator.c", "int generated;\n")
        self.fixture._commit(self.fixture.source, "build: add unclassified generator")
        after = self.fixture.fingerprint()
        for sdk_id in ("sdk-a", "sdk-b"):
            self.assertNotEqual(before[sdk_id]["input_sha256"], after[sdk_id]["input_sha256"])
            self.assertNotEqual(
                before[sdk_id]["components"]["shared_source"], after[sdk_id]["components"]["shared_source"]
            )

    def test_compiler_payload_changes_but_owner_provenance_does_not(self) -> None:
        before = self.fixture.fingerprint()
        self.fixture._write_manifest(provenance_delta="f")
        provenance = self.fixture.fingerprint()
        self.assertEqual(before["sdk-a"]["input_sha256"], provenance["sdk-a"]["input_sha256"])
        self.fixture._write_manifest(package_delta="changed", provenance_delta="f")
        payload = self.fixture.fingerprint()
        self.assertNotEqual(provenance["sdk-a"]["input_sha256"], payload["sdk-a"]["input_sha256"])
        self.assertEqual(provenance["sdk-b"]["input_sha256"], payload["sdk-b"]["input_sha256"])


if __name__ == "__main__":
    unittest.main()
