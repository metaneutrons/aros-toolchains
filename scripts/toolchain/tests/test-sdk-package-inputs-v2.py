#!/usr/bin/env python3
"""Focused byte-selection tests; fixtures are synthetic and unauthenticated."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


sys.dont_write_bytecode = True
SCRIPT = Path(__file__).resolve().parents[1] / "select-sdk-package-inputs-v2.py"
SPEC = importlib.util.spec_from_file_location("sdk_package_inputs_v2", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
selector = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = selector
SPEC.loader.exec_module(selector)
stage = selector._STAGE
TRANSPORT_TEST_PATH = Path(__file__).resolve().with_name("test-sdk-owner-transport-v2.py")
TRANSPORT_TEST_SPEC = importlib.util.spec_from_file_location(
    "sdk_package_inputs_transport_fixture", TRANSPORT_TEST_PATH
)
assert TRANSPORT_TEST_SPEC is not None and TRANSPORT_TEST_SPEC.loader is not None
transport_fixture = importlib.util.module_from_spec(TRANSPORT_TEST_SPEC)
sys.modules[TRANSPORT_TEST_SPEC.name] = transport_fixture
TRANSPORT_TEST_SPEC.loader.exec_module(transport_fixture)
HOSTS = tuple(selector._MATRIX.ACTIVE_HOSTS)
PRODUCER = "a" * 40
TOOLS = "b" * 40
TREE_DIGEST = "6" * 64
SDK_SPECS = (("sdk-a", "group-a", "release"), ("sdk-b", "group-b", "debug"))


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def measurement(raw: bytes) -> dict:
    return {"sha256": digest(raw), "size": len(raw)}


def identity(sdk_id: str, *, stack: str = "m68k") -> dict:
    return {
        "sdk_id": sdk_id,
        "version": "1.2.3",
        "target": {"target_triple": "i686-aros", "abi": {"stack": stack}},
        "source": {
            "commit": "c" * 40,
            "git_tree": "d" * 40,
            "content_sha256": "e" * 64,
            "contract_sha256": "f" * 64,
        },
        "source_date_epoch": 1710000000,
    }


class Fixture:
    def __init__(self, base: Path) -> None:
        self.base = base.resolve()
        self.inputs = self.base / "inputs"
        self.inputs.mkdir()
        self.owner_root = self.base / "owners-root"
        self.owner_root.mkdir()
        (self.owner_root / "owners").mkdir()
        (self.owner_root / "matrix.json").write_bytes(b"synthetic retained matrix\n")
        self.collection = self.inputs / "toolchain-release-inputs-v2.json"
        self.identities = {sdk_id: identity(sdk_id) for sdk_id, _, _ in SDK_SPECS}
        self.plan = self._make_plan()
        self.plan_path = self.base / "native-plan.json"
        self.plan_path.write_bytes(self.plan)
        self.plan_sha256 = digest(self.plan)
        self.rows = []
        self.archive_paths: dict[tuple[str, str], Path] = {}
        self.lane_paths: dict[tuple[str, str], Path] = {}
        self.manifest_paths: dict[tuple[str, str], Path] = {}
        self.checksum_paths: dict[tuple[str, str], Path] = {}
        for sdk_id, group, profile in SDK_SPECS:
            for host_index, host in enumerate(HOSTS):
                self.rows.append(self._make_owner_payload(
                    sdk_id, group, profile, host, host_index
                ))
        self.rows.sort(key=self._tuple_key)
        self.owner_transports = self._owner_transport_bindings()
        self.fragment = self._make_fragment()
        self.fragment_path = self.owner_root / "selection-fragment.json"
        self.write_fragment()

    def _make_plan(self) -> bytes:
        groups = []
        lanes = []
        for index, (group, profile) in enumerate((
            ("group-a", "release"), ("group-b", "debug")
        )):
            group_value = {
                "group_id": group,
                "source_commit": f"{index + 3:040x}",
                "source_tree": f"{index + 5:040x}",
                "upstream_commit": f"{index + 3:040x}",
            }
            for field in ("recipe", "source_lock", "profiles"):
                filename = f"{group}-{field.replace('_', '-')}.json"
                if field == "source_lock":
                    family = "gnu" if group == "group-a" else "llvm"
                    raw_lock = stage.canonical_json({"family": family})
                    (self.inputs / filename).write_bytes(raw_lock)
                    file_sha = digest(raw_lock)
                else:
                    file_sha = digest(filename.encode())
                group_value[field] = {"file": filename, "sha256": file_sha}
            groups.append(group_value)
            lanes.extend({"group_id": group, "host": host, "target_profile": profile}
                         for host in HOSTS)

        sdks = []
        for index, (sdk_id, group, profile) in enumerate(SDK_SPECS):
            identity_path = self.inputs / f"{sdk_id}-identity.json"
            raw_identity = stage.canonical_json(self.identities[sdk_id])
            identity_path.write_bytes(raw_identity)
            sdks.append({
                "id": sdk_id,
                "identity": {"file": identity_path.name, "sha256": digest(raw_identity)},
                "source_preset": f"source-{index}",
                "compiler_profiles": [{"group_id": group, "profile": profile}],
            })

        collection = {
            "schema": "aros-toolchain-release-inputs-v2",
            "producer_commit": PRODUCER,
            "tools_commit": TOOLS,
            "hosts": list(HOSTS),
            "groups": [{
                "id": group["group_id"], "recipe": group["recipe"],
                "source_lock": group["source_lock"], "profiles": group["profiles"],
            } for group in groups],
            "sdks": sdks,
        }
        collection_raw = stage.canonical_json(collection)
        self.collection.write_bytes(collection_raw)
        self.inputs_sha256 = digest(collection_raw)

        plan = {
            "schema": "aros-toolchain-producer-stage-v2",
            "operation": "release-plan",
            "release_format": "family-v2",
            "assurance": "input-binding-only",
            "inputs_sha256": self.inputs_sha256,
            "producer_commit": PRODUCER,
            "tools_commit": TOOLS,
            "hosts": list(HOSTS),
            "groups": groups,
            "lane_count": len(lanes),
            "lanes": lanes,
            "sdks": sdks,
            "sdk_count": len(sdks),
        }
        return stage.canonical_json(plan)

    @staticmethod
    def _tuple_key(row: dict) -> tuple[str, str, str, str]:
        return row["sdk_id"], row["group_id"], row["target_profile"], row["host"]

    def _make_owner_payload(self, sdk_id: str, group: str, profile: str,
                            host: str, host_index: int) -> dict:
        owner_id = selector._SDK_MATRIX._owner_id([sdk_id], group, host, profile)
        owner = self.owner_root / "owners" / owner_id
        readback = owner / "readback"
        payload = readback / "payload"
        readback.mkdir(parents=True)
        members = transport_fixture.product_members(sdk_id, "gnu" if group == "group-a" else "llvm")
        lane_path_in_bundle = f"sdk-{sdk_id}/sdk-lane.json"
        lane = json.loads(members[lane_path_in_bundle])
        lane.update({"group_id": group, "target_profile": profile, "host": host})
        members[lane_path_in_bundle] = stage.canonical_json(lane)
        retained = readback / "transport"
        selection = {"role": "sdk", "group": group, "host": host,
                     "profile": profile, "copy": "none"}
        bundle = transport_fixture.make_bundle(
            retained, sdk_ids=[sdk_id], family="gnu" if group == "group-a" else "llvm",
            members=members, selection=selection, signed_selection=selection,
        )
        (owner / "selection.json").write_bytes(
            transport_fixture.origin.canonical(bundle["selection"])
        )
        result = transport_fixture.transport.extract(
            retained, payload, sdk_ids=[sdk_id], group=group, profile=profile, host=host,
            compiler_family="gnu" if group == "group-a" else "llvm", owner_role="sdk",
        )
        result_raw = (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode()
        (readback / "transport-result.json").write_bytes(result_raw)
        (readback / "transport-readback.json").write_bytes(result_raw)
        (readback / "transport-reverification.json").write_bytes(result_raw)
        (readback / "origin-verification.log").write_bytes(
            b"Synthetic original-owner authentication; not real signature evidence.\n"
        )
        (readback / "readback.json").write_bytes(stage.canonical_json({
            "schema": "aros-sdk-owner-readback-v2",
            "assurance": "authenticated-transport-and-sdk-payload-readback-only",
            "sdk_owner_transport": result,
        }))

        product = payload / f"sdk-{sdk_id}"
        package = product / "package"
        lane_path = product / "sdk-lane.json"
        archive_names = [name for name in package.iterdir() if name.name.endswith(".tar.xz")]
        self.assert_package_archive_count(archive_names)
        archive_name = archive_names[0].name
        archive_path = package / archive_name
        manifest_path = package / f"{archive_name}.manifest.json"
        checksum_path = package / f"{archive_name}.sha256"
        self.archive_paths[(sdk_id, host)] = archive_path
        self.lane_paths[(sdk_id, host)] = lane_path
        self.manifest_paths[(sdk_id, host)] = manifest_path
        self.checksum_paths[(sdk_id, host)] = checksum_path
        return result["sdk_generations"][0]

    @staticmethod
    def assert_package_archive_count(archives: list[Path]) -> None:
        if len(archives) != 1:
            raise AssertionError(f"expected one SDK archive, got {len(archives)}")

    def _owner_transport_bindings(self) -> dict:
        bindings = {}
        for row in self.rows:
            package_dir = Path(row["package_dir"])
            owner_id = package_dir.parts[-5]
            result_path = self.owner_root / "owners" / owner_id / "readback" / "transport-result.json"
            bindings[owner_id] = {"path": str(result_path), "sha256": digest(result_path.read_bytes())}
        return bindings

    def _make_fragment(self) -> dict:
        return {
            "schema": "aros-sdk-generation-selection-fragment-v2",
            "assurance": "authenticated-owner-transport-selection-only",
            "aros_sha256": "7" * 64,
            "plan_sha256": self.plan_sha256,
            "inputs_sha256": self.inputs_sha256,
            "source_context_sha256": "8" * 64,
            "source_producer_commit": PRODUCER,
            "source_workflow": ".github/workflows/native-release.yml",
            "source_ref": "refs/heads/main",
            "producer_commit": PRODUCER,
            "tools_commit": TOOLS,
            "owner_count": len(self.rows),
            "sdk_generation_count": len(self.rows),
            "owner_transports": self.owner_transports,
            "sdk_generations": list(self.rows),
            "release_admission": False,
            "publication": False,
        }

    def write_fragment(self, raw: bytes | None = None) -> None:
        self.fragment_path.write_bytes(
            stage.canonical_json(self.fragment) if raw is None else raw
        )

    def rewrite_plan(self, plan: dict) -> None:
        self.plan = stage.canonical_json(plan)
        self.plan_path.write_bytes(self.plan)
        self.plan_sha256 = digest(self.plan)
        self.fragment["plan_sha256"] = self.plan_sha256
        self.write_fragment()

    def arguments(self) -> list[str]:
        return [
            sys.executable, "-B", str(SCRIPT),
            "--plan", str(self.plan_path), "--plan-sha256", self.plan_sha256,
            "--inputs-dir", str(self.inputs), "--inputs-sha256", self.inputs_sha256,
            "--producer-commit", PRODUCER, "--tools-commit", TOOLS,
            "--fragment", str(self.fragment_path),
            "--fragment-sha256", digest(self.fragment_path.read_bytes()),
            "--owner-root", str(self.owner_root),
        ]

    def run(self, extra: list[str] | None = None,
            overrides: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        arguments = self.arguments()
        for name, value in (overrides or {}).items():
            arguments[arguments.index(name) + 1] = value
        return subprocess.run([*arguments, *(extra or [])], capture_output=True,
                              text=True, check=False)


class SdkPackageInputsV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="sdk-package-inputs-v2.")
        self.fixture = Fixture(Path(self.temporary.name).resolve())

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def assert_rejected(self, *, fragment_raw: bytes | None = None,
                         extra: list[str] | None = None,
                         overrides: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        if fragment_raw is not None:
            self.fixture.write_fragment(fragment_raw)
        result = self.fixture.run(extra, overrides)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(result.stdout, "")
        self.assertIn("SDK package selection failed:", result.stderr)
        return result

    def test_projects_complete_plan_after_all_host_bytes_match(self) -> None:
        result = self.fixture.run()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(result.stdout.splitlines()), 1)
        output = json.loads(result.stdout)
        self.assertEqual(output["schema"], "aros-sdk-package-inputs-v2")
        self.assertEqual(output["assurance"], "package-byte-selection-only")
        self.assertEqual(output["sdk_package_count"], 2)
        self.assertEqual(set(output["sdk_packages"]), {"sdk-a", "sdk-b"})
        for sdk_id, value in output["sdk_packages"].items():
            archive_bytes = f"synthetic SDK archive bytes for {sdk_id}\n".encode()
            self.assertEqual(value, {
                "tree_sha256": TREE_DIGEST,
                "archive_sha256": digest(archive_bytes),
                "archive_size": len(archive_bytes),
            })
        self.assertEqual(len(output["package_locations"]), 2)
        self.assertEqual(
            [(item["sdk_id"], item["group_id"], item["target_profile"], item["host"])
             for item in output["package_locations"]],
            [("sdk-a", "group-a", "release", "linux-aarch64"),
             ("sdk-b", "group-b", "debug", "linux-aarch64")],
        )
        self.assertTrue(all(Path(item["archive_path"]).is_file()
                            and Path(item["manifest_path"]).is_file()
                            and Path(item["checksum_path"]).is_file()
                            for item in output["package_locations"]))

    def test_fixture_admits_the_actual_owner_reader_output_names(self) -> None:
        reader = SCRIPT.with_name("read-sdk-owner-v2.sh").read_text(encoding="utf-8")
        written_names = set(re.findall(r"\$root/([a-z][a-z.-]+)", reader))
        self.assertTrue(written_names)
        owner_id = selector._SDK_MATRIX._owner_id(["sdk-a"], "group-a", HOSTS[0], "release")
        readback = self.fixture.owner_root / "owners" / owner_id / "readback"
        self.assertTrue(written_names <= {path.name for path in readback.iterdir()})
        self.assertIn("origin-verification.log", written_names)
        self.assertIn("transport-readback.json", written_names)

    def test_rejects_missing_tuple(self) -> None:
        self.fixture.fragment["sdk_generations"].pop()
        self.fixture.fragment["sdk_generation_count"] -= 1
        self.fixture.fragment["owner_count"] -= 1
        self.assert_rejected(fragment_raw=stage.canonical_json(self.fixture.fragment))

    def test_rejects_substituted_identity_and_manifest(self) -> None:
        sdk_id, host = "sdk-a", HOSTS[0]
        identity_path = self.fixture.inputs / "sdk-a-identity.json"
        selected_identity = identity("sdk-a", stack="substituted")
        identity_path.write_bytes(stage.canonical_json(selected_identity))
        self.assert_rejected()

        fixture = Fixture(Path(tempfile.mkdtemp(prefix="sdk-package-manifest-substitution.")))
        self.addCleanup(lambda path=fixture.base: __import__("shutil").rmtree(path))
        manifest_path = fixture.manifest_paths[(sdk_id, host)]
        manifest = json.loads(manifest_path.read_bytes())
        manifest["identity"]["target"]["abi"]["stack"] = "substituted"
        manifest_raw = stage.canonical_json(manifest)
        manifest_path.write_bytes(manifest_raw)
        lane_path = fixture.lane_paths[(sdk_id, host)]
        lane = json.loads(lane_path.read_bytes())
        lane["files"][f"package/{manifest_path.name}"] = measurement(manifest_raw)
        lane_path.write_bytes(stage.canonical_json(lane))
        self.fixture = fixture
        self.assert_rejected()

    def test_rejects_archive_mutation_and_cross_host_disagreement(self) -> None:
        path = self.fixture.archive_paths[("sdk-a", HOSTS[0])]
        path.write_bytes(b"mutated archive bytes\n")
        self.assert_rejected()

        fixture = Fixture(Path(tempfile.mkdtemp(prefix="sdk-package-host-disagreement.")))
        self.addCleanup(lambda path=fixture.base: __import__("shutil").rmtree(path))
        sdk_id, host = "sdk-a", HOSTS[1]
        archive_path = fixture.archive_paths[(sdk_id, host)]
        archive_name = archive_path.name
        changed_archive = b"different but internally rebound host archive\n"
        archive_path.write_bytes(changed_archive)
        checksum_path = fixture.checksum_paths[(sdk_id, host)]
        checksum_path.write_bytes(f"{digest(changed_archive)}  {archive_name}\n".encode())
        lane_path = fixture.lane_paths[(sdk_id, host)]
        lane = json.loads(lane_path.read_bytes())
        lane["files"][f"package/{archive_name}"] = measurement(changed_archive)
        lane["files"][f"package/{archive_name}.sha256"] = measurement(checksum_path.read_bytes())
        lane_path.write_bytes(stage.canonical_json(lane))
        self.fixture = fixture
        self.assert_rejected()

    def test_rejects_coherent_all_host_package_rewrite_against_original_transport(self) -> None:
        fixture = Fixture(Path(tempfile.mkdtemp(prefix="sdk-package-coherent-rewrite.")))
        self.addCleanup(lambda path=fixture.base: shutil.rmtree(path))
        sdk_id = "sdk-a"
        for host_index, host in enumerate(HOSTS):
            archive_path = fixture.archive_paths[(sdk_id, host)]
            archive_name = archive_path.name
            archive_raw = f"coherently rewritten SDK archive {host_index}\n".encode()
            archive_path.write_bytes(archive_raw)

            manifest_path = fixture.manifest_paths[(sdk_id, host)]
            manifest = json.loads(manifest_path.read_bytes())
            manifest["tree_sha256"] = "9" * 64
            manifest_raw = stage.canonical_json(manifest)
            manifest_path.write_bytes(manifest_raw)

            checksum_path = fixture.checksum_paths[(sdk_id, host)]
            checksum_raw = f"{digest(archive_raw)}  {archive_name}\n".encode()
            checksum_path.write_bytes(checksum_raw)

            lane_path = fixture.lane_paths[(sdk_id, host)]
            lane = json.loads(lane_path.read_bytes())
            lane["files"][f"package/{archive_name}"] = measurement(archive_raw)
            lane["files"][f"package/{archive_name}.manifest.json"] = measurement(manifest_raw)
            lane["files"][f"package/{archive_name}.sha256"] = measurement(checksum_raw)
            lane_path.write_bytes(stage.canonical_json(lane))
        self.fixture = fixture
        self.assert_rejected()

    def test_rejects_duplicate_json_and_duplicate_rows(self) -> None:
        raw = self.fixture.fragment_path.read_bytes()
        duplicate = raw.replace(b'{"aros_sha256":', b'{"schema":"duplicate","aros_sha256":', 1)
        self.assert_rejected(fragment_raw=duplicate)

        fixture = Fixture(Path(tempfile.mkdtemp(prefix="sdk-package-duplicate-row.")))
        self.addCleanup(lambda path=fixture.base: __import__("shutil").rmtree(path))
        fixture.fragment["sdk_generations"].append(dict(fixture.fragment["sdk_generations"][0]))
        fixture.fragment["sdk_generation_count"] += 1
        self.fixture = fixture
        self.assert_rejected(fragment_raw=stage.canonical_json(fixture.fragment))

    def test_rejects_structural_plan_sdk_references_not_bound_by_collection(self) -> None:
        for mutation in ("identity", "compiler-profile"):
            with self.subTest(mutation=mutation):
                fixture = Fixture(Path(tempfile.mkdtemp(
                    prefix=f"sdk-package-unbound-{mutation}."
                )))
                self.addCleanup(
                    lambda path=fixture.base: __import__("shutil").rmtree(path)
                )
                plan = json.loads(fixture.plan)
                if mutation == "identity":
                    original = fixture.inputs / "sdk-a-identity.json"
                    replacement = fixture.inputs / "sdk-a-replacement-identity.json"
                    replacement_raw = original.read_bytes()
                    replacement.write_bytes(replacement_raw)
                    plan["sdks"][0]["identity"] = {
                        "file": replacement.name, "sha256": digest(replacement_raw),
                    }
                else:
                    plan["sdks"][0]["compiler_profiles"] = [
                        {"group_id": "group-b", "profile": "debug"}
                    ]
                selector._MATRIX._validate_plan(
                    plan,
                    expected_inputs_sha256=fixture.inputs_sha256,
                    expected_producer_commit=PRODUCER,
                    expected_tools_commit=TOOLS,
                )
                fixture.rewrite_plan(plan)
                self.fixture = fixture
                result = self.fixture.run()
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertEqual(result.stdout, "")
                self.assertIn("SDK package selection failed:", result.stderr)

    def test_rejects_path_escape_and_symlinked_package_file(self) -> None:
        row = self.fixture.fragment["sdk_generations"][0]
        row["package_dir"] = str(self.fixture.base / "outside" / "package")
        self.assert_rejected(fragment_raw=stage.canonical_json(self.fixture.fragment))

        fixture = Fixture(Path(tempfile.mkdtemp(prefix="sdk-package-symlink.")))
        self.addCleanup(lambda path=fixture.base: __import__("shutil").rmtree(path))
        archive_path = fixture.archive_paths[("sdk-a", HOSTS[0])]
        external = fixture.base / "external-archive.bin"
        external.write_bytes(archive_path.read_bytes())
        archive_path.unlink()
        archive_path.symlink_to(external)
        self.fixture = fixture
        self.assert_rejected()

        fixture = Fixture(Path(tempfile.mkdtemp(prefix="sdk-package-transport-result-link.")))
        self.addCleanup(lambda path=fixture.base: shutil.rmtree(path))
        owner_id = next(iter(fixture.owner_transports))
        result_path = fixture.owner_root / "owners" / owner_id / "readback" / "transport-result.json"
        external = fixture.base / "external-transport-result.json"
        external.write_bytes(result_path.read_bytes())
        result_path.unlink()
        result_path.symlink_to(external)
        self.fixture = fixture
        self.assert_rejected()

    def test_rejects_changed_plan_and_selected_digests(self) -> None:
        self.fixture.plan_path.write_bytes(self.fixture.plan + b" ")
        self.assert_rejected()

        fixture = Fixture(Path(tempfile.mkdtemp(prefix="sdk-package-stale-fragment.")))
        self.addCleanup(lambda path=fixture.base: __import__("shutil").rmtree(path))
        self.fixture = fixture
        self.assert_rejected(overrides={"--fragment-sha256": "0" * 64})

        fixture = Fixture(Path(tempfile.mkdtemp(prefix="sdk-package-stale-inputs.")))
        self.addCleanup(lambda path=fixture.base: __import__("shutil").rmtree(path))
        self.fixture = fixture
        with self.fixture.collection.open("ab") as stream:
            stream.write(b" ")
        self.assert_rejected()


if __name__ == "__main__":
    unittest.main()
