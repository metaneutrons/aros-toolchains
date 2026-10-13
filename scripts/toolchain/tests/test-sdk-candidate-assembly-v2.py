#!/usr/bin/env python3
"""Focused SDK package-staging tests with synthetic native/authentication inputs.

The owner-transport fixture reuses the retained-transport test helpers, whose
signature bytes are deliberately fake. The fake native executable exercises
the subprocess boundary; these tests do not claim Sigstore or native release
authentication.
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


sys.dont_write_bytecode = True
SCRIPT = Path(__file__).resolve().parents[1] / "assemble-sdk-candidate-v2.py"
SPEC = importlib.util.spec_from_file_location("sdk_candidate_assembly_v2", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
assembly = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = assembly
SPEC.loader.exec_module(assembly)
SELECTOR_TEST_PATH = Path(__file__).resolve().with_name("test-sdk-package-inputs-v2.py")
SELECTOR_TEST_SPEC = importlib.util.spec_from_file_location(
    "sdk_candidate_assembly_selector_fixture", SELECTOR_TEST_PATH
)
assert SELECTOR_TEST_SPEC is not None and SELECTOR_TEST_SPEC.loader is not None
selector_fixture_module = importlib.util.module_from_spec(SELECTOR_TEST_SPEC)
sys.modules[SELECTOR_TEST_SPEC.name] = selector_fixture_module
SELECTOR_TEST_SPEC.loader.exec_module(selector_fixture_module)
stage = assembly._STAGE


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


class Fixture:
    def __init__(self, base: Path, *, mode: str = "success") -> None:
        self.base = base.resolve()
        self.base.mkdir(parents=True, exist_ok=True)
        self.inputs_fixture_root = self.base / "authenticated-owner-fixture"
        self.inputs_fixture_root.mkdir()
        self.selected = selector_fixture_module.Fixture(self.inputs_fixture_root)
        self._complete_group_documents()
        self.aros = self.base / "fake-aros"
        self.config_path = self.base / "fake-aros-config.json"
        self.argv_log = self.base / "fake-aros-argv.jsonl"
        self.mode = mode
        self.identity_to_mutate = self.selected.inputs / "sdk-b-identity.json"
        self.mutation_targets = []
        for host in assembly._MATRIX.ACTIVE_HOSTS:
            self.mutation_targets.append({
                "archive": str(self.selected.archive_paths[("sdk-b", host)]),
                "manifest": str(self.selected.manifest_paths[("sdk-b", host)]),
                "checksum": str(self.selected.checksum_paths[("sdk-b", host)]),
                "lane": str(self.selected.lane_paths[("sdk-b", host)]),
            })
        self.root = self.base / "sdk-candidate"
        self._write_native()
        self.selected.fragment["aros_sha256"] = digest(self.aros.read_bytes())
        self.selected.write_fragment()

    def _complete_group_documents(self) -> None:
        plan = json.loads(self.selected.plan)
        collection = json.loads(self.selected.collection.read_bytes())
        for group in plan["groups"]:
            for field in ("recipe", "profiles"):
                reference = group[field]
                raw = stage.canonical_json({"group_id": group["group_id"], "document": field})
                (self.selected.inputs / reference["file"]).write_bytes(raw)
                reference["sha256"] = digest(raw)
        collection["groups"] = [{
            "id": group["group_id"], "recipe": group["recipe"],
            "source_lock": group["source_lock"], "profiles": group["profiles"],
        } for group in plan["groups"]]
        collection_raw = stage.canonical_json(collection)
        self.selected.collection.write_bytes(collection_raw)
        self.selected.inputs_sha256 = digest(collection_raw)
        plan["inputs_sha256"] = self.selected.inputs_sha256
        self.selected.plan = stage.canonical_json(plan)
        self.selected.plan_path.write_bytes(self.selected.plan)
        self.selected.plan_sha256 = digest(self.selected.plan)
        self.selected.fragment["inputs_sha256"] = self.selected.inputs_sha256
        self.selected.fragment["plan_sha256"] = self.selected.plan_sha256
        self.selected.write_fragment()

    def _write_native(self) -> None:
        config = {
            "mode": self.mode,
            "argv_log": str(self.argv_log),
            "identity_to_mutate": str(self.identity_to_mutate),
            "mutation_targets": self.mutation_targets,
        }
        self.config_path.write_text(json.dumps(config), encoding="utf-8")
        source = f'''#!{sys.executable}
import hashlib, json, os, sys
from pathlib import Path

config = json.loads(Path({str(self.config_path)!r}).read_text())
args = sys.argv[1:]
with open(config["argv_log"], "a", encoding="utf-8") as log:
    log.write(json.dumps(args, separators=(",", ":")) + "\\n")
if args[:2] != ["sdk", "verify-package"] or "--format" in args:
    print("unexpected native command", file=sys.stderr)
    raise SystemExit(91)
def option(name):
    return args[args.index(name) + 1]
identity_path = Path(option("--identity"))
identity = json.loads(identity_path.read_text())
package_dir = Path(option("--package-dir"))
sdk_id = identity["sdk_id"]
mode = config["mode"]
if mode == "native-failure":
    print("synthetic native verifier diagnostic", file=sys.stderr)
    raise SystemExit(17)
if mode == "oversized-stdout":
    sys.stdout.buffer.write(b"x" * {assembly.MAX_NATIVE_OUTPUT + 1024})
    sys.stdout.buffer.flush()
    raise SystemExit(0)
if mode == "oversized-stderr":
    sys.stderr.buffer.write(b"y" * {assembly.MAX_NATIVE_OUTPUT + 1024})
    sys.stderr.buffer.flush()
if mode == "mutate-identity" and sdk_id == "sdk-b":
    config_identity = Path(config["identity_to_mutate"])
    config_identity.write_bytes(b"{{}}\\n")
if mode == "mutate-all-hosts" and sdk_id == "sdk-b":
    for target in config["mutation_targets"]:
        archive = Path(target["archive"])
        manifest = Path(target["manifest"])
        checksum = Path(target["checksum"])
        lane_path = Path(target["lane"])
        archive_bytes = b"coherent forged archive bytes\\n"
        archive.write_bytes(archive_bytes)
        document = json.loads(manifest.read_bytes())
        document["tree_sha256"] = "9" * 64
        manifest_bytes = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode() + b"\\n"
        manifest.write_bytes(manifest_bytes)
        checksum_bytes = (hashlib.sha256(archive_bytes).hexdigest() + "  " + archive.name + "\\n").encode()
        checksum.write_bytes(checksum_bytes)
        lane = json.loads(lane_path.read_bytes())
        lane["files"]["package/" + archive.name] = {{"sha256":hashlib.sha256(archive_bytes).hexdigest(),"size":len(archive_bytes)}}
        lane["files"]["package/" + manifest.name] = {{"sha256":hashlib.sha256(manifest_bytes).hexdigest(),"size":len(manifest_bytes)}}
        lane["files"]["package/" + checksum.name] = {{"sha256":hashlib.sha256(checksum_bytes).hexdigest(),"size":len(checksum_bytes)}}
        lane_path.write_bytes(json.dumps(lane, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode() + b"\\n")
result = {{
    "identity": identity,
    "archive_sha256": option("--archive-sha256"),
    "archive_size": int(option("--archive-size")),
    "tree_sha256": option("--tree-sha256"),
}}
if mode == "wrong-identity":
    result["identity"] = dict(identity, sdk_id="substituted-sdk")
elif mode == "missing-identity":
    del result["identity"]
elif mode == "wrong-digest":
    result["archive_sha256"] = "0" * 64
elif mode == "missing-tree":
    del result["tree_sha256"]
envelope = {{
    "schema":"aros-sdk-local-stage-v2",
    "operation":"sdk.verify-package",
    "assurance":"local-byte-consistency-not-release-admission",
    "result":result,
}}
if mode == "extra-result-field":
    envelope["unexpected"] = True
sys.stdout.write(json.dumps(envelope, sort_keys=True, separators=(",", ":")) + "\\n")
'''
        self.aros.write_text(source, encoding="utf-8")
        self.aros.chmod(0o755)

    def command(self) -> list[str]:
        return [
            sys.executable, "-B", str(SCRIPT),
            "--aros", str(self.aros), "--aros-sha256", digest(self.aros.read_bytes()),
            "--plan", str(self.selected.plan_path), "--plan-sha256", self.selected.plan_sha256,
            "--inputs-dir", str(self.selected.inputs), "--inputs-sha256", self.selected.inputs_sha256,
            "--producer-commit", selector_fixture_module.PRODUCER,
            "--tools-commit", selector_fixture_module.TOOLS,
            "--fragment", str(self.selected.fragment_path),
            "--fragment-sha256", digest(self.selected.fragment_path.read_bytes()),
            "--owner-root", str(self.selected.owner_root),
            "--forbidden-prefix", "/synthetic/build-root-a",
            "--forbidden-prefix", "/synthetic/build-root-b",
            "--root", str(self.root),
        ]

    def run(self, extra: list[str] | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run([*self.command(), *(extra or [])], capture_output=True,
                              text=True, check=False)


class SdkCandidateAssemblyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="sdk-candidate-assembly.")
        self.base = Path(self.temporary.name).resolve()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def make_fixture(self, name: str, *, mode: str = "success") -> Fixture:
        fixture = Fixture(self.base / name, mode=mode)
        return fixture

    def assert_rejected(self, fixture: Fixture, extra: list[str] | None = None
                        ) -> subprocess.CompletedProcess[str]:
        result = fixture.run(extra)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(result.stdout, "")
        self.assertIn("SDK package candidate assembly failed:", result.stderr)
        return result

    def test_stages_measured_three_member_packages_after_native_verify(self) -> None:
        fixture = self.make_fixture("positive")
        result = fixture.run()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(result.stdout.splitlines()), 1)
        output = json.loads(result.stdout)
        self.assertEqual(output["schema"], "aros-sdk-package-candidate-assembly-v2")
        self.assertEqual(output["operation"], "sdk-package-staging")
        self.assertEqual(output["assurance"], "sdk-package-staging-partial-no-admission")
        self.assertEqual(output["staged_root"], str(fixture.root / "release"))
        self.assertEqual(output["sdk_count"], 2)
        self.assertEqual(set(output["sdk_packages"]), {"sdk-a", "sdk-b"})
        self.assertEqual(output["bindings"]["aros_sha256"], digest(fixture.aros.read_bytes()))
        self.assertEqual(output["bindings"]["source_context_sha256"], "8" * 64)
        self.assertFalse(output["scope"]["all_sdk_generations_executed"])
        self.assertFalse(output["scope"]["complete_sdk_inventory"])
        self.assertFalse(output["scope"]["release_admission"])
        self.assertFalse(output["scope"]["publication"])
        self.assertEqual(len(output["staged_inventory"]), 6)
        self.assertEqual(set(output["native_results"]), {"sdk-a", "sdk-b"})
        for name, expected in output["staged_inventory"].items():
            path = fixture.root / "release" / name
            self.assertTrue(path.is_file())
            self.assertEqual(path.read_bytes(), next(
                source.read_bytes()
                for sdk_source in fixture.selected.archive_paths.values()
                for source in [sdk_source]
                if source.name == name
            ) if name.endswith(".tar.xz") else self._find_sidecar(fixture, name).read_bytes())
            self.assertEqual(assembly._STAGE.measure_file(path, assembly._STAGE.MAX_PAYLOAD,
                                                          "test staged file"), expected)
        log_rows = [json.loads(line) for line in fixture.argv_log.read_text().splitlines()]
        self.assertEqual(len(log_rows), 2)
        for args in log_rows:
            self.assertEqual(args[:2], ["sdk", "verify-package"])
            self.assertNotIn("--format", args)
            self.assertEqual([args[index + 1] for index, item in enumerate(args)
                              if item == "--forbidden-prefix"],
                             ["/synthetic/build-root-a", "/synthetic/build-root-b"])
        for native in output["native_results"].values():
            self.assertEqual(assembly._STAGE.measure_file(
                Path(native["path"]), assembly.MAX_NATIVE_OUTPUT, "test native result"),
                {"sha256": native["sha256"], "size": native["size"]})

    @staticmethod
    def _find_sidecar(fixture: Fixture, name: str) -> Path:
        for path in [*fixture.selected.manifest_paths.values(),
                     *fixture.selected.checksum_paths.values()]:
            if path.name == name:
                return path
        raise AssertionError(f"no original package member named {name}")

    def test_rejects_native_result_contract_failures_without_summary(self) -> None:
        for mode in ("wrong-identity", "missing-identity", "wrong-digest", "missing-tree",
                     "extra-result-field"):
            with self.subTest(mode=mode):
                fixture = self.make_fixture(mode, mode=mode)
                self.assert_rejected(fixture)

    def test_native_failure_keeps_bounded_diagnostics_without_summary(self) -> None:
        fixture = self.make_fixture("native-failure", mode="native-failure")
        self.assert_rejected(fixture)
        diagnostics = fixture.root / "native" / "verify-sdk-a.json.stderr.log"
        self.assertTrue(diagnostics.is_file())
        self.assertIn(b"synthetic native verifier diagnostic", diagnostics.read_bytes())

    def test_rejects_duplicate_options_but_allows_repeated_forbidden_prefix(self) -> None:
        fixture = self.make_fixture("duplicate-option")
        self.assert_rejected(fixture, ["--plan", str(fixture.selected.plan_path)])

    def test_rejects_original_identity_and_coherent_all_host_package_mutation(self) -> None:
        identity_fixture = self.make_fixture("mutated-identity", mode="mutate-identity")
        self.assert_rejected(identity_fixture)

        package_fixture = self.make_fixture("mutated-package", mode="mutate-all-hosts")
        self.assert_rejected(package_fixture)
        self.assertEqual(list((package_fixture.root / "release").iterdir()), [])

    def test_rejects_oversized_native_stdout_and_stderr_without_summary(self) -> None:
        for mode in ("oversized-stdout", "oversized-stderr"):
            with self.subTest(mode=mode):
                fixture = self.make_fixture(mode, mode=mode)
                self.assert_rejected(fixture)
                output = fixture.root / "native" / "verify-sdk-a.json"
                stderr = fixture.root / "native" / "verify-sdk-a.json.stderr.log"
                self.assertLessEqual(output.stat().st_size, assembly.MAX_NATIVE_OUTPUT)
                self.assertLessEqual(stderr.stat().st_size, assembly.MAX_NATIVE_OUTPUT)

    def test_rejects_casefold_copy_collision_before_writing_members(self) -> None:
        fixture = self.make_fixture("copy-collision")
        selected = assembly._selector_result(argparse_namespace(fixture))
        packages, locations = assembly._selector_packages(selected)
        source_a = assembly._package_snapshots(
            {"sdk-a": packages["sdk-a"]}, {"sdk-a": locations["sdk-a"]}, {}, {}
        )["sdk-a"]
        source_b = copy.deepcopy(source_a)
        source_b["location"]["sdk_id"] = "sdk-b"
        package_sources = {"sdk-a": source_a, "sdk-b": source_b}
        release_dir = fixture.base / "collision-release"
        release_dir.mkdir(mode=0o700)
        with self.assertRaisesRegex(assembly.AssemblyError, "collide under case folding"):
            assembly._stage_packages(package_sources, packages, release_dir)
        self.assertEqual(list(release_dir.iterdir()), [])


def argparse_namespace(fixture: Fixture):
    return assembly._parser().parse_args(fixture.command()[3:])


if __name__ == "__main__":
    unittest.main()
