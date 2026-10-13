"""Synthetic process-boundary tests; no test performs real crypto or compiler proof."""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts/toolchain/record-complete-qualification-v2.py"
SPEC = importlib.util.spec_from_file_location("record_complete_qualification_v2", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
adapter = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = adapter
SPEC.loader.exec_module(adapter)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


FAKE_RUNTIME = r'''#!/usr/bin/env python3
import hashlib
import json
import os
from pathlib import Path
import sys

args = sys.argv[1:]
def option(name):
    return args[args.index(name) + 1]
def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def log_call():
    with open(os.environ["FAKE_NATIVE_LOG"], "a", encoding="utf-8") as handle:
        handle.write(json.dumps(args) + "\n")
def fail(message):
    print(message, file=sys.stderr)
    raise SystemExit(19)

log_call()
mode = os.environ.get("FAKE_MODE", "positive")
operation = args[2]
selection = json.loads(Path(option("--selection")).read_bytes())
release_dir = Path(option("--directory" if operation == "verify-qualification" else "--release-dir"))
index = json.loads((release_dir / "toolchain-index-v2.json").read_bytes())
subject_sha = option("--subject-manifest-sha256")
selection_sha = option("--selection-sha256")
inputs_sha = option("--inputs-sha256")
index_sha = option("--index-sha256")
checksums_sha = digest(release_dir / "SHA256SUMS")
provenance_sha = digest(release_dir / "toolchain-provenance.sigstore.json")
generation_rows = []
for row in selection["sdk_generations"]:
    generation_rows.append({
        "sdk_id": row["sdk_id"], "group_id": row["group_id"],
        "target_profile": row["target_profile"], "host": row["host"],
        "generation_record_sha256": row["record"]["sha256"],
        "compatibility_manifest_sha256": row["compatibility"]["manifest_sha256"],
        "compatibility_receipt_sha256": "e" * 64,
        "sdk_link_receipt_sha256": "f" * 64,
    })
lanes = []
evidence_lanes = []
for artifact in index["artifacts"]:
    asset = artifact["asset"]
    selected = selection["lanes"][asset]
    build_a = selected["builds"][0]["measurement"]["sha256"]
    build_b = selected["builds"][1]["measurement"]["sha256"]
    comparison = selected["comparison"]["sha256"]
    compatibility = selected["compatibility"]
    lanes.append({
        "asset": asset, "measurement_sha256": [build_a, build_b],
        "build_result_sha256": "1" * 64, "finished_receipt_sha256": "2" * 64,
        "comparison_sha256": comparison,
        "compatibility_inputs_sha256": compatibility["inputs"]["sha256"],
        "compatibility_manifest_sha256": compatibility["manifest_sha256"],
        "compatibility_receipt_sha256": "3" * 64, "standalone": {},
    })
    evidence_lanes.append({
        "group_id": artifact["group_id"], "asset": asset, "host": artifact["host"],
        "target_profile": artifact["target_profile"], "target_triple": artifact["target_triple"],
        "source_commit": artifact["source_commit"], "compiler": artifact["compiler"],
        "recipe_sha256": "4" * 64, "source_lock_sha256": "5" * 64,
        "profiles_sha256": "6" * 64, "archive_sha256": artifact["sha256"],
        "archive_size": artifact["size"], "tree_sha256": artifact["tree_sha256"],
        "build_a_report_sha256": build_a, "build_b_report_sha256": build_b,
        "comparison_report_sha256": comparison,
        "compatibility_report_sha256": compatibility["manifest_sha256"],
    })
sdk_rows = [{
    "sdk_id": sdk_id, "identity": {"sdk_id": sdk_id},
    "tree_sha256": row["tree_sha256"], "archive_sha256": row["archive_sha256"],
    "archive_size": row["archive_size"], "manifest_sha256": "7" * 64,
    "manifest_size": 42,
} for sdk_id, row in selection["sdk_packages"].items()]

result = {
    "schema": "aros-toolchain-producer-stage-v2",
    "operation": operation,
    "release_format": "family-v2",
    "assurance": "byte-consistency-only",
    "release_id": index["release_id"], "inputs_sha256": inputs_sha,
    "index_sha256": index_sha, "selection_sha256": selection_sha,
    "subject_manifest_sha256": subject_sha, "checksums_sha256": checksums_sha,
    "provenance_sha256": provenance_sha,
    "lane_count": len(lanes), "build_count": len(lanes) * 2, "lanes": lanes,
    "sdk_count": len(sdk_rows), "sdks": sdk_rows,
    "sdk_generation_count": len(generation_rows), "sdk_generations": generation_rows,
}
evidence_path = None
if operation == "record-qualification":
    output = Path(option("--output"))
    source_repository = option("--source-repository")
    source_workflow = option("--source-workflow")
    tag = option("--source-tag")
    tag_object = option("--source-tag-object")
    producer_commit = option("--source-tag-commit")
    evidence = {
        "schema": "aros-toolchain-qualification-evidence-v2",
        "created_at": int(option("--created-at")),
        "expires_at": int(option("--expires-at")),
        "source_run": {
            "repository": source_repository, "workflow": source_workflow,
            "run_id": int(option("--source-run-id")),
            "run_attempt": int(option("--source-run-attempt")),
            "producer_commit": producer_commit, "source_tag": tag,
            "tag_object": tag_object,
        },
        "release": {
            "release_id": index["release_id"], "base_url": index["base_url"],
            "inputs_sha256": inputs_sha, "release_index_sha256": index_sha,
            "pre_attestation_checksums_sha256": subject_sha,
            "checksums_sha256": checksums_sha, "provenance_sha256": provenance_sha,
            "producer_commit": index["producer_commit"],
            "tools_commit": index["tools_commit"],
        },
        "attestation": {
            "repository": option("--attestation-repository"),
            "workflow": option("--attestation-workflow"),
            "signer": option("--attestation-signer"),
            "subject_manifest_sha256": subject_sha,
        },
        "lanes": evidence_lanes,
        "sdk_generations": [{
            "sdk_id": row["sdk_id"], "group_id": row["group_id"],
            "target_profile": row["target_profile"], "host": row["host"],
            "generation_record_sha256": row["generation_record_sha256"],
            "compatibility_report_sha256": row["compatibility_manifest_sha256"],
            "compatibility_receipt_sha256": row["compatibility_receipt_sha256"],
            "sdk_link_receipt_sha256": row["sdk_link_receipt_sha256"],
        } for row in generation_rows],
        "coverage": "release-candidate",
    }
    if mode == "wrong-tuple":
        evidence["lanes"][0]["host"] = "wrong-host"
    if mode == "wrong-source-attempt":
        evidence["source_run"]["run_attempt"] += 1
    if mode == "wrong-recorded-source-tag":
        evidence["source_run"]["source_tag"] = "v9.9.9"
    raw = (json.dumps(evidence, sort_keys=True, separators=(",", ":")) + "\n").encode()
    with output.open("xb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    result["qualification_evidence"] = str(output)
    result["qualification_sha256"] = hashlib.sha256(raw).hexdigest()
    if mode == "wrong-emitted-sha":
        result["qualification_sha256"] = "0" * 64
    if mode == "wrong-reported-path":
        result["qualification_evidence"] = str(output.parent / "elsewhere.json")
    if mode == "wrong-count":
        result["lane_count"] += 1
    if mode == "wrong-sdk-digest":
        result["sdks"][0]["archive_sha256"] = "0" * 64
    if mode == "wrong-envelope":
        result["unexpected"] = True
    if mode == "mutate-after-record":
        selected_path = Path(option("--selection"))
        selected_path.write_bytes(selected_path.read_bytes() + b" ")
elif operation == "verify-qualification":
    evidence_path = Path(option("--qualification-evidence"))
    result["qualification_sha256"] = digest(evidence_path)
    result["policy_sha256"] = option("--policy-sha256")
    if mode == "wrong-verify-tuple":
        result["sdk_generations"][0]["sdk_link_receipt_sha256"] = "0" * 64
    if mode == "wrong-policy-sha":
        result["policy_sha256"] = "0" * 64
    if mode == "mutate-after-verify":
        target = release_dir / "toolchain-provenance.sigstore.json"
        target.write_bytes(target.read_bytes() + b" changed")
    elif mode.startswith("mutate-after-verify-"):
        target = Path(os.environ["FAKE_MUTATION_TARGET"])
        target.write_bytes(target.read_bytes() + b" changed")
else:
    fail("unexpected native operation")

print(json.dumps(result, sort_keys=True, separators=(",", ":")))
'''


FAKE_VERIFIER = r'''import json
import os
from pathlib import Path
import sys

args = sys.argv[1:]
with open(os.environ["FAKE_VERIFIER_LOG"], "w", encoding="utf-8") as handle:
    json.dump(args, handle)
def option(name):
    return args[args.index(name) + 1]
if os.environ.get("FAKE_MODE") == "verifier-fails":
    print("synthetic external verifier rejection", file=sys.stderr)
    raise SystemExit(23)
if option("--run-attempt") != os.environ.get("FAKE_EXPECTED_RUN_ATTEMPT", "2"):
    print("synthetic verifier rejected a different run attempt", file=sys.stderr)
    raise SystemExit(24)
if os.environ.get("FAKE_MODE") == "mutate-after-verifier":
    selected = Path(os.environ["FAKE_SELECTION"])
    selected.write_bytes(selected.read_bytes() + b" ")
with open(option("--output"), "xb") as handle:
    handle.write(b"[{\"synthetic\":true}]\n")
print("synthetic verification response")
'''


class Fixture:
    def __init__(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="fake-v2-qualification-")
        self.root = Path(self.temp.name).resolve()
        self.prefix_workspace = self.root / "workspace-root"
        self.prefix_workspace.mkdir()
        self.prefix_runner_temp = self.root / "runner-temp-root"
        self.prefix_runner_temp.mkdir()
        self.release = self.root / "release"
        self.release.mkdir()
        self.runtime = self.root / "bin" / "aros"
        self.runtime.parent.mkdir()
        self.runtime.write_text(FAKE_RUNTIME, encoding="utf-8")
        self.runtime.chmod(0o700)
        self.runtime_sha = digest(self.runtime.read_bytes())
        self.producer_commit = "a" * 40
        self.inputs_raw = b'{"synthetic":"inputs"}\n'
        self.inputs_sha = digest(self.inputs_raw)
        (self.release / "toolchain-release-inputs-v2.json").write_bytes(self.inputs_raw)
        self.group_asset = b"synthetic compiler archive"
        self.sdk_asset = b"synthetic SDK ABI archive"
        (self.release / "gnu-linux.tar.xz").write_bytes(self.group_asset)
        (self.release / "sdk+abi.tar.xz").write_bytes(self.sdk_asset)
        compiler_sha = digest(self.group_asset)
        sdk_sha = digest(self.sdk_asset)
        compiler_tree = "b" * 64
        sdk_tree = "c" * 64
        self.index = {
            "schema": 2,
            "release_id": "v1.2.3",
            "base_url": "https://github.com/example/aros-toolchains/releases/download/v1.2.3",
            "inputs_sha256": self.inputs_sha,
            "producer_commit": self.producer_commit,
            "tools_commit": "d" * 40,
            "artifacts": [{
                "group_id": "gnu-rv32", "asset": "gnu-linux.tar.xz",
                "sha256": compiler_sha, "size": len(self.group_asset),
                "host": "linux-x86_64", "target_profile": "rv32imac",
                "target_triple": "riscv32-unknown-elf", "source_commit": "e" * 40,
                "compiler": {"gcc": "15.1.0", "binutils": "2.43.1"},
                "tree_sha256": compiler_tree, "enabled": True,
                "strip_components": 1, "required_paths": ["bin/gcc"],
            }],
            "sdks": [{"identity": {"sdk_id": "sdk+abi"}}],
        }
        self.index_raw = canonical(self.index)
        self.index_sha = digest(self.index_raw)
        (self.release / "toolchain-index-v2.json").write_bytes(self.index_raw)
        self.selection_path = self.root / "selection.json"
        host_records = self.root / "source-owner"
        host_records.mkdir()
        package_a = host_records / "build-a-package"
        package_b = host_records / "build-b-package"
        package_a.mkdir()
        package_b.mkdir()
        self.selection = {
            "schema": "aros-toolchain-release-evidence-selection-v2",
            "lanes": {
                "gnu-linux.tar.xz": {
                    "build_environment": {}, "required_paths": ["bin/gcc"],
                    "builds": [
                        {"package_dir": str(package_a), "measurement": {
                            "path": str(host_records / "build-a.json"), "sha256": "1" * 64},
                         "executor": {"contract_sha256": "a" * 64,
                                      "binary_sha256": "b" * 64}},
                        {"package_dir": str(package_b), "measurement": {
                            "path": str(host_records / "build-b.json"), "sha256": "2" * 64},
                         "executor": {"contract_sha256": "c" * 64,
                                      "binary_sha256": "d" * 64}},
                    ],
                    "comparison": {"path": str(host_records / "comparison.json"), "sha256": "3" * 64},
                    "compatibility": {
                        "directory": str(host_records),
                        "inputs": {"path": str(host_records / "compat-inputs.json"), "sha256": "4" * 64},
                        "manifest_sha256": "5" * 64,
                        "native_sdk_required": True,
                    },
                },
            },
            "sdk_packages": {"sdk+abi": {
                "tree_sha256": sdk_tree, "archive_sha256": sdk_sha,
                "archive_size": len(self.sdk_asset),
            }},
            "sdk_generations": [{
                "sdk_id": "sdk+abi", "group_id": "gnu-rv32",
                "target_profile": "rv32imac", "host": "linux-x86_64",
                "package_dir": str(host_records),
                "record": {"path": str(host_records / "generation.json"), "sha256": "6" * 64},
                "compatibility": {
                    "directory": str(host_records),
                    "inputs": {"path": str(host_records / "generation-inputs.json"), "sha256": "7" * 64},
                    "manifest_sha256": "8" * 64,
                    "native_sdk_required": True,
                },
            }],
        }
        self.selection_path.write_bytes(canonical(self.selection))
        self.selection_sha = digest(self.selection_path.read_bytes())

        self.bundle_raw = b"synthetic attestation bundle"
        self.bundle = self.release / "toolchain-provenance.sigstore.json"
        self.bundle.write_bytes(self.bundle_raw)
        self.checksums = self.release / "SHA256SUMS"
        self.checksums.write_text("synthetic final checksum document\n", encoding="ascii")
        self.inventory = {
            "gnu-linux.tar.xz": {"sha256": compiler_sha, "size": len(self.group_asset)},
            "sdk+abi.tar.xz": {"sha256": sdk_sha, "size": len(self.sdk_asset)},
            "toolchain-index-v2.json": {"sha256": self.index_sha, "size": len(self.index_raw)},
            "toolchain-release-inputs-v2.json": {"sha256": self.inputs_sha, "size": len(self.inputs_raw)},
        }
        self.subject = self.root / "subject-manifest.json"
        self.subject.write_text("".join(
            f"{item['sha256']}  {name}\n" for name, item in sorted(self.inventory.items())
        ), encoding="ascii")
        self.subject_sha = digest(self.subject.read_bytes())
        self.summary = self.root / "candidate-summary.json"
        self.summary_doc = {
            "schema": "aros-toolchain-release-candidate-assembly-v2",
            "operation": "shared-native-pre-index-inventory",
            "assurance": "complete-native-pre-index-inventory-no-admission",
            "bindings": {
                "aros_sha256": self.runtime_sha, "inputs_sha256": self.inputs_sha,
                "producer_commit": self.producer_commit,
                "release_id": self.index["release_id"], "base_url": self.index["base_url"],
            },
            "release_root": str(self.release), "stage": "pre-attestation",
            "release_format": "family-v2",
            "outputs": {
                "index": {"path": str(self.release / "toolchain-index-v2.json"),
                          "sha256": self.index_sha, "size": len(self.index_raw)},
                "lane_inputs": {},
                "subject_manifest": {"path": str(self.subject), "sha256": self.subject_sha,
                                     "size": self.subject.stat().st_size},
                "native_index_result": {}, "sdk_sboms": {"sdk+abi": {}},
            },
            "release_inventory": self.inventory,
            "counts": {"lane_count": 1, "sdk_count": 1,
                       "subject_count": len(self.inventory),
                       "inventory_count": len(self.inventory) + 2},
            "scope": {"sdk_factory_execution_complete": False,
                      "release_admission": False, "publication": False},
        }
        self.summary.write_bytes(canonical(self.summary_doc))
        self.summary_sha = digest(self.summary.read_bytes())
        self.operation = self.root / "qualification-operation"
        self.native_log = self.root / "native-argv.jsonl"
        self.verifier_log = self.root / "verifier-argv.json"
        self.fake_verifier = self.root / "fake-verifier.py"
        self.fake_verifier.write_text(FAKE_VERIFIER, encoding="utf-8")

    def rewrite_release_identity(self, release_id: str, base_url: str) -> None:
        self.index["release_id"] = release_id
        self.index["base_url"] = base_url
        self.index_raw = canonical(self.index)
        (self.release / "toolchain-index-v2.json").write_bytes(self.index_raw)
        self.index_sha = digest(self.index_raw)
        self.inventory["toolchain-index-v2.json"] = {
            "sha256": self.index_sha, "size": len(self.index_raw),
        }
        self.subject.write_text("".join(
            f"{item['sha256']}  {name}\n" for name, item in sorted(self.inventory.items())
        ), encoding="ascii")
        self.subject_sha = digest(self.subject.read_bytes())
        self.summary_doc["bindings"]["release_id"] = release_id
        self.summary_doc["bindings"]["base_url"] = base_url
        self.summary_doc["outputs"]["index"].update({
            "sha256": self.index_sha, "size": len(self.index_raw),
        })
        self.summary_doc["outputs"]["subject_manifest"].update({
            "sha256": self.subject_sha, "size": self.subject.stat().st_size,
        })
        self.summary_doc["release_inventory"] = self.inventory
        self.summary.write_bytes(canonical(self.summary_doc))
        self.summary_sha = digest(self.summary.read_bytes())

    def environment(self, mode: str = "positive", *,
                    mutation_target: Path | None = None) -> dict[str, str]:
        result = {
            "FAKE_MODE": mode,
            "FAKE_NATIVE_LOG": str(self.native_log),
            "FAKE_VERIFIER_LOG": str(self.verifier_log),
            "FAKE_SELECTION": str(self.selection_path),
            "FAKE_SUMMARY": str(self.summary),
            "FAKE_SUBJECT": str(self.subject),
            "FAKE_BUNDLE": str(self.bundle),
            "FAKE_EXPECTED_RUN_ATTEMPT": "2",
        }
        if mutation_target is not None:
            result["FAKE_MUTATION_TARGET"] = str(mutation_target)
        return result

    def argv(self, **overrides: str) -> list[str]:
        options = {
            "--runtime": str(self.runtime), "--runtime-sha256": self.runtime_sha,
            "--release-dir": str(self.release), "--inputs-sha256": self.inputs_sha,
            "--index-sha256": self.index_sha, "--selection": str(self.selection_path),
            "--selection-sha256": self.selection_sha,
            "--subject-manifest": str(self.subject), "--subject-manifest-sha256": self.subject_sha,
            "--candidate-summary": str(self.summary), "--candidate-summary-sha256": self.summary_sha,
            "--repository": "example/aros-toolchains",
            "--workflow": ".github/workflows/toolchain-release.yml",
            "--run-id": "42", "--run-attempt": "2", "--source-tag": "v1.2.3",
            "--source-tag-object": "9" * 40, "--source-tag-commit": self.producer_commit,
            "--created-at": "100", "--expires-at": "300",
            "--operation-dir": str(self.operation),
        }
        options.update(overrides)
        result = []
        for name, value in options.items():
            result.extend((name, value))
        result.extend(("--forbidden-prefix", str(self.prefix_workspace),
                       "--forbidden-prefix", str(self.prefix_runner_temp)))
        return result

    def close(self) -> None:
        self.temp.cleanup()


class CompleteQualificationAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_verifier = adapter.VERIFIER_COMMAND

    def tearDown(self) -> None:
        adapter.VERIFIER_COMMAND = self.original_verifier

    def invoke(self, fixture: Fixture, *, mode: str = "positive",
               mutation_target: Path | None = None,
               argv: list[str] | None = None) -> tuple[int, str, str]:
        adapter.VERIFIER_COMMAND = (sys.executable, str(fixture.fake_verifier))
        stdout = __import__("io").StringIO()
        stderr = __import__("io").StringIO()
        with mock.patch.dict(os.environ, fixture.environment(mode,
                                                           mutation_target=mutation_target), clear=False), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = adapter.main(fixture.argv() if argv is None else argv)
        return result, stdout.getvalue(), stderr.getvalue()

    def assert_failure(self, fixture: Fixture, *, mode: str = "positive",
                       mutation_target: Path | None = None,
                       argv: list[str] | None = None) -> str:
        code, stdout, stderr = self.invoke(fixture, mode=mode,
                                          mutation_target=mutation_target, argv=argv)
        self.assertNotEqual(code, 0)
        self.assertEqual(stdout, "", "a failed helper call must emit no success summary")
        self.assertIn("failed", stderr)
        return stderr

    def native_calls(self, fixture: Fixture) -> list[list[str]]:
        if not fixture.native_log.exists():
            return []
        return [json.loads(line) for line in fixture.native_log.read_text().splitlines()]

    def test_positive_sequence_binds_attestation_record_and_complete_readback(self) -> None:
        fixture = Fixture()
        try:
            code, stdout, stderr = self.invoke(fixture)
            self.assertEqual(code, 0, stderr)
            self.assertEqual(stderr, "")
            summary = json.loads(stdout)
            self.assertEqual(summary["schema"], "aros-toolchain-full-qualification-record-adapter-v2")
            self.assertEqual(summary["assurance"], "external-provenance-and-native-byte-consistency-only")
            self.assertEqual(summary["counts"], {
                "lane_count": 1, "build_count": 2, "sdk_count": 1,
                "sdk_generation_count": 1,
            })
            self.assertFalse(summary["scope"]["tag_object_independently_authenticated"])
            self.assertFalse(summary["scope"]["original_owner_jobs_verified_by_this_adapter"])
            self.assertFalse(summary["scope"]["runtime_publication_verified_by_this_adapter"])
            evidence_path = Path(summary["qualification_evidence"]["path"])
            self.assertTrue(evidence_path.is_file())
            self.assertEqual(digest(evidence_path.read_bytes()), summary["qualification_evidence"]["sha256"])
            self.assertEqual(evidence_path.parent, fixture.operation)
            self.assertTrue(Path(summary["evidence_policy"]["path"]).is_file())
            policy = json.loads(Path(summary["evidence_policy"]["path"]).read_bytes())
            self.assertEqual(policy, {
                "source_repository": "https://github.com/example/aros-toolchains",
                "source_workflow": ".github/workflows/toolchain-release.yml",
                "signer_repository": "https://github.com/example/aros-toolchains",
                "signer_workflow": ".github/workflows/toolchain-release.yml",
                "signer": "github-actions", "now": 100,
            })
            native = self.native_calls(fixture)
            self.assertEqual([call[2] for call in native],
                             ["record-qualification", "verify-qualification"])
            record, verify = native
            for call in native:
                self.assertIn("--forbidden-prefix", call)
                self.assertEqual(call.count("--forbidden-prefix"), 2)
                self.assertIn("--selection", call)
                self.assertIn(str(fixture.selection_path), call)
                self.assertIn("--selection-sha256", call)
                self.assertIn(fixture.selection_sha, call)
                self.assertIn("--inputs-sha256", call)
                self.assertIn(fixture.inputs_sha, call)
                self.assertIn("--index-sha256", call)
                self.assertIn(fixture.index_sha, call)
            self.assertIn("--release-format", record)
            self.assertIn("family-v2", record)
            self.assertEqual(record[record.index("--source-run-attempt") + 1], "2")
            self.assertEqual(record[record.index("--source-tag") + 1], "v1.2.3")
            self.assertEqual(record[record.index("--source-tag-object") + 1], "9" * 40)
            self.assertEqual(record[record.index("--source-tag-commit") + 1], fixture.producer_commit)
            self.assertIn("--attestation-signer", record)
            self.assertEqual(record[record.index("--attestation-signer") + 1], "github-actions")
            self.assertIn(str(fixture.selection_path), verify)
            self.assertEqual(json.loads(fixture.selection_path.read_bytes())["sdk_packages"].keys(),
                             {"sdk+abi"})
            verification = json.loads(fixture.verifier_log.read_text())
            self.assertEqual(verification[verification.index("--source-ref") + 1], "refs/tags/v1.2.3")
            self.assertEqual(verification[verification.index("--source-digest") + 1], fixture.producer_commit)
            self.assertEqual(verification[verification.index("--run-id") + 1], "42")
            self.assertEqual(verification[verification.index("--run-attempt") + 1], "2")
            self.assertEqual(verification[verification.index("--repository") + 1], "example/aros-toolchains")
            self.assertEqual(verification[verification.index("--bundle") + 1], str(fixture.bundle))
            self.assertEqual(summary["source_observation"]["tag_object"], "9" * 40)
            self.assertEqual(summary["scope"]["provider_run_attempt_verified_by_external_attestation"], True)
        finally:
            fixture.close()

    def test_invalid_documents_hashes_sizes_and_symlinks_never_reach_verifier(self) -> None:
        cases = ("malformed-selection", "wrong-selection-hash", "oversized-subject",
                 "symlink-selection", "symlink-provenance", "oversized-provenance")
        for case in cases:
            with self.subTest(case=case):
                fixture = Fixture()
                try:
                    argv = fixture.argv()
                    if case == "malformed-selection":
                        fixture.selection_path.write_bytes(b"{")
                        self.replace_arg(argv, "--selection-sha256", digest(b"{"))
                    elif case == "wrong-selection-hash":
                        self.replace_arg(argv, "--selection-sha256", "0" * 64)
                    elif case == "oversized-subject":
                        fixture.subject.write_bytes(b"x" * (adapter.MAX_SUBJECT_MANIFEST + 1))
                    elif case == "symlink-selection":
                        original = fixture.root / "selection-target.json"
                        original.write_bytes(fixture.selection_path.read_bytes())
                        fixture.selection_path.unlink()
                        fixture.selection_path.symlink_to(original)
                    elif case == "symlink-provenance":
                        target = fixture.root / "bundle-target.json"
                        target.write_bytes(fixture.bundle.read_bytes())
                        fixture.bundle.unlink()
                        fixture.bundle.symlink_to(target)
                    elif case == "oversized-provenance":
                        fixture.bundle.write_bytes(b"x" * (adapter.MAX_METADATA + 1))
                    self.assert_failure(fixture, argv=argv)
                    self.assertFalse(fixture.verifier_log.exists())
                    self.assertEqual(self.native_calls(fixture), [])
                finally:
                    fixture.close()

    def test_failed_external_verifier_stops_before_native_recording(self) -> None:
        fixture = Fixture()
        try:
            error = self.assert_failure(fixture, mode="verifier-fails")
            self.assertIn("exit status 23", error)
            self.assertIn("provenance-verifier.stderr.log", error)
            self.assertTrue((fixture.operation / "provenance-verifier.stderr.log").is_file())
            self.assertEqual(self.native_calls(fixture), [])
        finally:
            fixture.close()

    def test_rehashed_candidate_identity_must_match_selected_release_tag_and_repository(self) -> None:
        cases = (
            ("toolchain-dev-abcdef", "https://github.com/example/aros-toolchains/releases/download/toolchain-dev-abcdef"),
            ("v1.2.3", "https://github.com/other/aros-toolchains/releases/download/v1.2.3"),
            ("v1.2.3", "https://github.com/example/aros-toolchains/releases/download/v2.0.0"),
            ("v1.2.3", "https://github.com/example/aros-toolchains/releases/download/other/v1.2.3"),
            ("v1.2.3", "https://github.com/example/aros-toolchains/releases/download/v1.2.3?download=1"),
            ("v1.2.3", "https://github.com/example/aros-toolchains/releases/download/v1.2.3/"),
        )
        for release_id, base_url in cases:
            with self.subTest(release_id=release_id, base_url=base_url):
                fixture = Fixture()
                try:
                    fixture.rewrite_release_identity(release_id, base_url)
                    self.assert_failure(fixture)
                    self.assertFalse(fixture.verifier_log.exists())
                    self.assertEqual(self.native_calls(fixture), [])
                finally:
                    fixture.close()

    def test_portable_sdk_plus_basename_is_accepted_and_path_basenames_are_rejected(self) -> None:
        self.assertTrue(adapter.SAFE_COMPONENT.fullmatch("sdk+abi.tar.xz"))
        for name in ("../sdk+abi.tar.xz", "/sdk+abi.tar.xz", "sdk\\abi.tar.xz",
                     "sdk.tar.xz/../../escape", ".", "", "unsafe name.tar.xz"):
            with self.subTest(name=name):
                self.assertIsNone(adapter.SAFE_COMPONENT.fullmatch(name))
                raw = f"{'a' * 64}  {name}\n".encode()
                with self.assertRaises(adapter.AdapterError):
                    adapter._subject_entries(raw, "synthetic path-basename probe")

    def test_run_attempt_selector_is_bound_to_external_verifier(self) -> None:
        fixture = Fixture()
        try:
            argv = fixture.argv()
            self.replace_arg(argv, "--run-attempt", "3")
            error = self.assert_failure(fixture, argv=argv)
            self.assertIn("exit status 24", error)
            verification = json.loads(fixture.verifier_log.read_text())
            self.assertEqual(verification[verification.index("--run-attempt") + 1], "3")
            self.assertEqual(self.native_calls(fixture), [])
        finally:
            fixture.close()

    def test_native_malformed_claims_and_result_selectors_do_not_emit_success(self) -> None:
        for mode, expected_calls in (("wrong-tuple", 1), ("wrong-source-attempt", 1),
                                     ("wrong-recorded-source-tag", 1), ("wrong-count", 1),
                                     ("wrong-emitted-sha", 1), ("wrong-reported-path", 1),
                                     ("wrong-sdk-digest", 1), ("wrong-envelope", 1),
                                     ("wrong-verify-tuple", 2), ("wrong-policy-sha", 2)):
            with self.subTest(mode=mode):
                fixture = Fixture()
                try:
                    self.assert_failure(fixture, mode=mode)
                    self.assertEqual(len(self.native_calls(fixture)), expected_calls)
                    self.assertFalse((fixture.operation / "qualification-evidence-v2.json").exists())
                finally:
                    fixture.close()

    def test_mutation_after_external_and_native_record_barriers_stops_the_next_call(self) -> None:
        for mode, expected_calls in (("mutate-after-verifier", 0), ("mutate-after-record", 1)):
            with self.subTest(mode=mode):
                fixture = Fixture()
                try:
                    self.assert_failure(fixture, mode=mode)
                    self.assertEqual(len(self.native_calls(fixture)), expected_calls)
                    self.assertFalse((fixture.operation / "qualification-evidence-v2.json").exists())
                finally:
                    fixture.close()

    def test_mutation_at_native_verify_barrier_prevents_success_summary(self) -> None:
        targets = {
            "mutate-after-verify-runtime": "runtime",
            "mutate-after-verify-summary": "summary",
            "mutate-after-verify-subject": "subject",
            "mutate-after-verify-provenance": "bundle",
            "mutate-after-verify-selection": "selection_path",
        }
        for mode, attribute in targets.items():
            with self.subTest(mode=mode):
                fixture = Fixture()
                try:
                    self.assert_failure(fixture, mode=mode,
                                        mutation_target=getattr(fixture, attribute))
                    self.assertEqual(len(self.native_calls(fixture)), 2)
                    self.assertFalse((fixture.operation / "qualification-evidence-v2.json").exists())
                finally:
                    fixture.close()

    def test_preexisting_operation_directory_sentinel_is_never_overwritten(self) -> None:
        fixture = Fixture()
        try:
            fixture.operation.mkdir()
            sentinel = fixture.operation / "keep.txt"
            sentinel.write_bytes(b"user data")
            argv = fixture.argv()
            self.assert_failure(fixture, argv=argv)
            self.assertEqual(sentinel.read_bytes(), b"user data")
            self.assertFalse(fixture.verifier_log.exists())
            self.assertEqual(self.native_calls(fixture), [])
        finally:
            fixture.close()

    def test_operation_directory_cannot_overlap_forbidden_prefix(self) -> None:
        fixture = Fixture()
        try:
            argv = fixture.argv()
            unsafe_operation = fixture.prefix_workspace / "qualification-operation"
            self.replace_arg(argv, "--operation-dir", str(unsafe_operation))
            self.assert_failure(fixture, argv=argv)
            self.assertFalse(fixture.verifier_log.exists())
            self.assertEqual(self.native_calls(fixture), [])
            self.assertFalse(unsafe_operation.exists())
        finally:
            fixture.close()

    def test_diagnostic_and_nonrelease_source_tags_are_rejected_before_verification(self) -> None:
        for tag in ("toolchain-dev-deadbeef", "diagnostic-v2", "v01.2.3"):
            with self.subTest(tag=tag):
                fixture = Fixture()
                try:
                    argv = fixture.argv()
                    self.replace_arg(argv, "--source-tag", tag)
                    self.assert_failure(fixture, argv=argv)
                    self.assertFalse(fixture.verifier_log.exists())
                    self.assertEqual(self.native_calls(fixture), [])
                finally:
                    fixture.close()

    def test_child_stdout_and_stderr_limits_are_enforced_by_real_processes(self) -> None:
        for fd, name in ((1, "stdout"), (2, "stderr")):
            with self.subTest(stream=name), tempfile.TemporaryDirectory(
                    prefix="qualification-child-output-") as temporary:
                root = Path(temporary).resolve()
                operation = root / "operation"
                operation.mkdir()
                amount = adapter.MAX_CHILD_OUTPUT + 1024
                code = (
                    "import os\n"
                    f"remaining = memoryview(b'x' * {amount})\n"
                    "while remaining:\n"
                    f"    written = os.write({fd}, remaining)\n"
                    "    remaining = remaining[written:]\n"
                )
                with self.assertRaises(adapter.AdapterError):
                    adapter._run_child(operation, name, [sys.executable, "-c", code], 5,
                                       {}, cwd=root)
                stdout_size = (operation / f"{name}.stdout.log").stat().st_size
                stderr_size = (operation / f"{name}.stderr.log").stat().st_size
                self.assertLessEqual(stdout_size, adapter.MAX_CHILD_OUTPUT)
                self.assertLessEqual(stderr_size, adapter.MAX_CHILD_OUTPUT)
                self.assertGreater(stdout_size if fd == 1 else stderr_size, 0)

    def test_child_output_within_contract_limit_is_retained(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qualification-child-output-positive-") as temporary:
            root = Path(temporary).resolve()
            operation = root / "operation"
            operation.mkdir()
            amount = 9 * 1024 * 1024
            code = (
                "import os\n"
                f"remaining = memoryview(b'x' * {amount})\n"
                "while remaining:\n"
                "    written = os.write(1, remaining)\n"
                "    remaining = remaining[written:]\n"
            )
            stdout, stderr = adapter._run_child(
                operation, "positive-output", [sys.executable, "-c", code], 5, {}, cwd=root
            )
            self.assertEqual(len(stdout), amount)
            self.assertEqual(stderr, b"")

    def test_child_timeout_kills_process_group_without_running_orphans(self) -> None:
        import time

        with tempfile.TemporaryDirectory(prefix="qualification-child-timeout-") as temporary:
            root = Path(temporary).resolve()
            operation = root / "operation"
            operation.mkdir()
            pid_file = root / "child-pids.txt"
            grandchild = "import time; time.sleep(30)"
            code = (
                "import os, subprocess, sys, time\n"
                "from pathlib import Path\n"
                f"child = subprocess.Popen([sys.executable, '-c', {grandchild!r}])\n"
                f"Path({str(pid_file)!r}).write_text(f'{{os.getpid()}} {{child.pid}}')\n"
                "time.sleep(30)\n"
            )
            with self.assertRaisesRegex(adapter.AdapterError, "timed out"):
                adapter._run_child(operation, "timeout", [sys.executable, "-c", code],
                                   0.3, {}, cwd=root)
            parent_pid, child_pid = (int(value) for value in pid_file.read_text().split())

            def process_state(pid: int) -> str:
                completed = __import__("subprocess").run(
                    ["ps", "-o", "stat=", "-p", str(pid)],
                    check=False, capture_output=True, text=True,
                )
                return completed.stdout.strip()

            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                states = [process_state(parent_pid), process_state(child_pid)]
                if all(not state or state.startswith("Z") for state in states):
                    break
                time.sleep(0.05)
            self.assertTrue(all(not state or state.startswith("Z") for state in states),
                            f"process-group timeout left live descendants: {states}")

    @staticmethod
    def replace_arg(argv: list[str], name: str, value: str) -> None:
        argv[argv.index(name) + 1] = value


if __name__ == "__main__":
    unittest.main()
