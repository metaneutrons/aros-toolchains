#!/usr/bin/env python3
"""Tests for the bounded V2 request adapter using a synthetic native child.

The child response uses the Rust result-envelope schema and selected join
fields. Its one-lane/one-SDK rows are fixtures, not the complete Rust release
inventory and not evidence of compiler, attestation, or signature proof. The
release-input and index files are opaque synthetic bytes: this adapter hashes
and holds them, while the fake child deliberately does not parse Rust schemas.
"""

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
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "prepare-recovery-request-v2.py"
REPOSITORY = "https://github.com/example/aros-toolchains"
WORKFLOW = ".github/workflows/publish.yml"
SOURCE_TAG = "v2.4.0"
RELEASE_ID = SOURCE_TAG
PRODUCER_COMMIT = "a" * 40
SOURCE_TAG_OBJECT = "b" * 40
HANDOFF_TAG_OBJECT = "d" * 40
HEX_A = "1" * 64
HEX_B = "2" * 64
HEX_C = "3" * 64
HEX_D = "4" * 64
HEX_E = "5" * 64
HEX_F = "6" * 64
HEX_G = "7" * 64
HEX_H = "8" * 64
HEX_I = "9" * 64


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


class RecoveryRequestV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="recovery-v2-adapter-")
        # macOS exposes /var as a symlink to /private/var; selected paths must
        # be canonical because the production helper rejects symlink parents.
        self.root = Path(self.tmp.name).resolve()
        self.evidence_dir = self.root / "evidence"
        self.evidence_dir.mkdir()
        self.release_dir = self.root / "release"
        self.release_dir.mkdir()
        self.inputs_path = self.release_dir / "toolchain-release-inputs-v2.json"
        self.index_path = self.release_dir / "toolchain-index-v2.json"
        self.inputs_bytes = b'{"synthetic_fixture_only":"release inputs"}\n'
        self.index_bytes = b'{"synthetic_fixture_only":"release index"}\n'
        self.inputs_path.write_bytes(self.inputs_bytes)
        self.index_path.write_bytes(self.index_bytes)
        self.bin_dir = self.root / "bin"
        self.bin_dir.mkdir()
        self.operation_parent = self.root / "operations"
        self.operation_parent.mkdir()
        self.operation_dir = self.operation_parent / "operation-1"
        self.forbidden_a = self.root / "build-a"
        self.forbidden_b = self.root / "build-b"
        self.forbidden_a.mkdir()
        self.forbidden_b.mkdir()
        self.capture_path = self.root / "captured-child-input.json"
        self.runtime_path = self.bin_dir / "aros"

        self.inputs_sha = sha256(self.inputs_bytes)
        self.index_sha = sha256(self.index_bytes)
        self.source_run = {
            "repository": REPOSITORY,
            "workflow": WORKFLOW,
            "run_id": 701,
            "run_attempt": 3,
            "producer_commit": PRODUCER_COMMIT,
            "source_tag": SOURCE_TAG,
            "tag_object": SOURCE_TAG_OBJECT,
        }
        self.source_tag = {
            "name": SOURCE_TAG,
            "tag_object": SOURCE_TAG_OBJECT,
            "peeled_commit": PRODUCER_COMMIT,
        }
        subject_raw = f"{HEX_C}  compiler.tar.zst\n".encode()
        self.subject_path = self.evidence_dir / "subjects.sha256"
        self.subject_path.write_bytes(subject_raw)
        self.subject_sha = sha256(subject_raw)
        self.attestation = {
            "repository": REPOSITORY,
            "workflow": WORKFLOW,
            "signer": "github-actions",
            "subject_manifest_sha256": self.subject_sha,
        }
        self.qualification = {
            "schema": "aros-toolchain-qualification-evidence-v2",
            "created_at": 1900000000,
            "expires_at": 1900003600,
            "source_run": self.source_run,
            "release": {
                "release_id": RELEASE_ID,
                "base_url": f"{REPOSITORY}/releases/download/{SOURCE_TAG}",
                "inputs_sha256": self.inputs_sha,
                "release_index_sha256": self.index_sha,
                "pre_attestation_checksums_sha256": self.subject_sha,
                "checksums_sha256": HEX_E,
                "provenance_sha256": HEX_F,
                "producer_commit": PRODUCER_COMMIT,
                "tools_commit": "c" * 40,
            },
            "attestation": self.attestation,
            # Synthetic lane/SDK claims exercise schema joins, not compiler proof.
            "lanes": [{
                "group_id": "main", "asset": "compiler-fixture.tar.zst",
                "host": "x86_64-linux", "target_profile": "m68k",
                "target_triple": "m68k-unknown-aros", "source_commit": PRODUCER_COMMIT,
                "compiler": {}, "recipe_sha256": HEX_C, "source_lock_sha256": HEX_D,
                "profiles_sha256": HEX_E, "archive_sha256": HEX_F, "archive_size": 27,
                "tree_sha256": HEX_G, "build_a_report_sha256": HEX_A,
                "build_b_report_sha256": HEX_B, "comparison_report_sha256": HEX_G,
                "compatibility_report_sha256": HEX_I,
            }],
            "sdk_generations": [{
                "sdk_id": "sdk-fixture", "group_id": "main",
                "target_profile": "m68k", "host": "x86_64-linux",
                "generation_record_sha256": HEX_A,
                "compatibility_report_sha256": HEX_B,
                "compatibility_receipt_sha256": HEX_C,
                "sdk_link_receipt_sha256": HEX_D,
            }],
            "coverage": "release-candidate",
        }
        self.selection = {
            "schema": "aros-toolchain-release-evidence-selection-v2",
            # A small selector fixture only; native Rust owns release inventory.
            "lanes": {"compiler-fixture.tar.zst": {
                "builds": [
                    {"measurement": {"sha256": HEX_A}},
                    {"measurement": {"sha256": HEX_B}},
                ],
                "comparison": {"sha256": HEX_G},
                "compatibility": {"inputs": {"sha256": HEX_H},
                                  "manifest_sha256": HEX_I},
            }},
            "sdk_packages": {"sdk-fixture": {
                "tree_sha256": HEX_G, "archive_sha256": HEX_H, "archive_size": 27,
            }},
            "sdk_generations": [{
                "sdk_id": "sdk-fixture", "group_id": "main",
                "target_profile": "m68k", "host": "x86_64-linux",
                "package_dir": str(self.release_dir / "sdk-generation"),
                "record": {"path": str(self.release_dir / "sdk-generation" / "record.json"),
                           "sha256": HEX_A},
                "compatibility": {
                    "directory": str(self.release_dir / "sdk-generation" / "compatibility"),
                    "inputs": {"path": str(self.release_dir / "sdk-generation" / "inputs.json"),
                               "sha256": HEX_D},
                    "manifest_sha256": HEX_B,
                    "native_sdk_required": True,
                },
            }],
        }
        self.policy = {
            "source_repository": REPOSITORY,
            "source_workflow": WORKFLOW,
            "signer_repository": REPOSITORY,
            "signer_workflow": WORKFLOW,
            "signer": "github-actions",
            "now": 1900000100,
        }

        self.paths = {
            "selection": self.evidence_dir / "selection.json",
            "subject_manifest": self.subject_path,
            "qualification_evidence": self.evidence_dir / "qualification.json",
            "policy": self.evidence_dir / "policy.json",
            "observed_run": self.evidence_dir / "observed-run.json",
            "observed_source_tag": self.evidence_dir / "observed-tag.json",
            "observed_attestation": self.evidence_dir / "observed-attestation.json",
            "handoff": self.evidence_dir / "handoff.json",
        }
        self._write_json(self.paths["selection"], self.selection)
        self._write_json(self.paths["qualification_evidence"], self.qualification)
        self._write_json(self.paths["policy"], self.policy)
        self._write_json(self.paths["observed_run"], self.source_run)
        self._write_json(self.paths["observed_source_tag"], self.source_tag)
        self._write_json(self.paths["observed_attestation"], self.attestation)
        self.handoff = {
            "release_id": "v2.4.1",
            "tag": {
                "name": "v2.4.1",
                "tag_object": HANDOFF_TAG_OBJECT,
                "peeled_commit": PRODUCER_COMMIT,
            },
            "state": "absent",
        }
        self._write_json(self.paths["handoff"], self.handoff)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write_json(self, path: Path, value: object) -> None:
        path.write_bytes(json_bytes(value))

    def _digest(self, key: str) -> str:
        return sha256(self.paths[key].read_bytes())

    def _lane_result(self) -> dict:
        return {
            "asset": "compiler-fixture.tar.zst",
            "measurement_sha256": [HEX_A, HEX_B],
            "build_result_sha256": [HEX_C, HEX_D],
            "finished_receipt_sha256": [HEX_E, HEX_F],
            "comparison_sha256": HEX_G,
            "compatibility_inputs_sha256": HEX_H,
            "compatibility_manifest_sha256": HEX_I,
            "compatibility_receipt_sha256": HEX_A,
            "standalone": [],
        }

    def _result(self, operation: str, *, decision: object | None = None) -> dict:
        expected_decision = ("replay-compatibility" if operation == "compatibility-replay" else {
            "repackage": {"release_id": self.handoff["release_id"],
                          "tag": self.handoff["tag"]},
        })
        return {
            "schema": "aros-toolchain-producer-stage-v2",
            "operation": "verify-recovery",
            "release_format": "family-v2",
            "assurance": "byte-consistency-only",
            "release_id": RELEASE_ID,
            "inputs_sha256": self.inputs_sha,
            "index_sha256": self.index_sha,
            "selection_sha256": self._digest("selection"),
            "subject_manifest_sha256": self.subject_sha,
            "checksums_sha256": HEX_E,
            "provenance_sha256": HEX_F,
            "lane_count": 1,
            "build_count": 2,
            "lanes": [self._lane_result()],
            "sdk_count": 1,
            "sdks": [{
                "sdk_id": "sdk-fixture",
                "identity": {"sdk_id": "sdk-fixture", "version": "1.2.3"},
                "tree_sha256": HEX_G,
                "archive_sha256": HEX_H,
                "archive_size": 27,
                "manifest_sha256": HEX_I,
                "manifest_size": 31,
            }],
            "sdk_generation_count": 1,
            "sdk_generations": [{
                "sdk_id": "sdk-fixture", "group_id": "main",
                "target_profile": "m68k", "host": "x86_64-linux",
                "generation_record_sha256": HEX_A,
                "compatibility_manifest_sha256": HEX_B,
                "compatibility_receipt_sha256": HEX_C,
                "sdk_link_receipt_sha256": HEX_D,
            }],
            "qualification_sha256": self._digest("qualification_evidence"),
            "policy_sha256": self._digest("policy"),
            # Fake executable fills this from the exact pending request bytes.
            "recovery_request_sha256": "__request_sha__",
            "decision": expected_decision if decision is None else decision,
        }

    def _make_runtime(self, operation: str = "packaging-recovery", *,
                      response: dict | None = None, return_code: int = 0,
                      mutate_path: Path | None = None) -> None:
        if response is None:
            response = self._result(operation)
        source = f'''#!/usr/bin/env python3
import hashlib, json, sys
from pathlib import Path

args = sys.argv[1:]
if args[:3] != ["toolchain", "producer", "verify-recovery"] or "--release-format" in args:
    raise SystemExit(41)
options = {{}}
forbidden = []
cursor = 3
while cursor < len(args):
    key = args[cursor]
    if key == "--forbidden-prefix":
        forbidden.append(args[cursor + 1])
        cursor += 2
    else:
        options[key] = args[cursor + 1]
        cursor += 2
request_path = Path(options["--recovery-request"])
request_bytes = request_path.read_bytes()
request_sha = hashlib.sha256(request_bytes).hexdigest()
Path({str(self.capture_path)!r}).write_text(json.dumps({{
    "argv": args,
    "forbidden_prefixes": forbidden,
    "request": json.loads(request_bytes),
    "request_sha256": request_sha,
}}))
if {str(mutate_path) if mutate_path is not None else None!r} is not None:
    Path({str(mutate_path) if mutate_path is not None else None!r}).write_bytes(b"late-mutation")
if {return_code} != 0:
    raise SystemExit({return_code})
result = json.loads({json.dumps(response)!r})
if result.get("recovery_request_sha256") == "__request_sha__":
    result["recovery_request_sha256"] = request_sha
print(json.dumps(result, sort_keys=True, separators=(",", ":")))
'''
        self.runtime_path.write_text(source)
        self.runtime_path.chmod(0o700)

    def _argv(self, operation: str = "packaging-recovery", *,
              failed_stage: str | None = "packaging", handoff: bool = True) -> list[str]:
        self.capture_path.unlink(missing_ok=True)
        if not self.runtime_path.exists():
            self._make_runtime(operation)
        argv = [
            "--runtime", str(self.runtime_path), "--runtime-sha256", sha256(self.runtime_path.read_bytes()),
            "--release-dir", str(self.release_dir), "--release-id", RELEASE_ID,
            "--base-url", f"{REPOSITORY}/releases/download/{SOURCE_TAG}",
            "--inputs-sha256", self.inputs_sha, "--index-sha256", self.index_sha,
            "--selection", str(self.paths["selection"]), "--selection-sha256", self._digest("selection"),
            "--subject-manifest", str(self.paths["subject_manifest"]), "--subject-manifest-sha256", self.subject_sha,
            "--qualification-evidence", str(self.paths["qualification_evidence"]),
            "--qualification-sha256", self._digest("qualification_evidence"),
            "--policy", str(self.paths["policy"]), "--policy-sha256", self._digest("policy"),
            "--observed-run", str(self.paths["observed_run"]), "--observed-run-sha256", self._digest("observed_run"),
            "--observed-source-tag", str(self.paths["observed_source_tag"]),
            "--observed-source-tag-sha256", self._digest("observed_source_tag"),
            "--observed-attestation", str(self.paths["observed_attestation"]),
            "--observed-attestation-sha256", self._digest("observed_attestation"),
            "--operation", operation,
        ]
        if failed_stage is not None:
            argv.extend(("--failed-stage", failed_stage))
        if handoff:
            argv.extend(("--handoff", str(self.paths["handoff"]),
                         "--handoff-sha256", self._digest("handoff")))
        argv.extend(("--operation-dir", str(self.operation_dir),
                     "--forbidden-prefix", str(self.forbidden_a),
                     "--forbidden-prefix", str(self.forbidden_b)))
        return argv

    def _invoke(self, operation: str = "packaging-recovery", *,
                failed_stage: str | None = "packaging", handoff: bool = True,
                extra: list[str] | None = None) -> subprocess.CompletedProcess:
        self._make_runtime(operation)
        command = [sys.executable, str(SCRIPT), *self._argv(
            operation, failed_stage=failed_stage, handoff=handoff), *(extra or [])]
        return subprocess.run(command, text=True, capture_output=True, timeout=30, check=False)

    def _assert_no_success(self, completed: subprocess.CompletedProcess, *,
                           child_ran: bool = False) -> None:
        self.assertNotEqual(completed.returncode, 0, completed.stdout)
        self.assertEqual(self.capture_path.exists(), child_ran,
                         "native child invocation did not match the expected preflight boundary")
        self.assertFalse((self.operation_dir / "recovery-request-v2.json").exists())
        self.assertNotIn("native_result", completed.stdout)

    def test_packaging_and_replay_emit_closed_request_and_exact_native_argv(self) -> None:
        for operation in ("packaging-recovery", "compatibility-replay"):
            with self.subTest(operation=operation):
                if self.operation_dir.exists():
                    for path in self.operation_dir.iterdir():
                        path.unlink()
                    self.operation_dir.rmdir()
                if self.capture_path.exists():
                    self.capture_path.unlink()
                failed_stage = ("packaging" if operation == "packaging-recovery"
                                else "compatibility-harness")
                completed = self._invoke(operation, failed_stage=failed_stage,
                                          handoff=(operation == "packaging-recovery"))
                self.assertEqual(completed.returncode, 0, completed.stderr)
                summary = json.loads(completed.stdout)
                capture = json.loads(self.capture_path.read_text())
                request = capture["request"]
                self.assertEqual(set(request), {
                    "schema", "qualification_sha256", "operation", "failed_stage",
                    "observed_run", "source_tag", "observed_attestation", "handoff",
                })
                self.assertEqual(request["schema"], "aros-toolchain-recovery-request-v2")
                self.assertEqual(request["qualification_sha256"], self._digest("qualification_evidence"))
                self.assertEqual(request["operation"], operation)
                self.assertEqual(request["failed_stage"],
                                 "packaging" if operation == "packaging-recovery" else "compatibility-harness")
                self.assertEqual(request["observed_run"], self.source_run)
                self.assertEqual(request["source_tag"], self.source_tag)
                self.assertEqual(request["observed_attestation"], self.attestation)
                self.assertEqual(request["handoff"], self.handoff if operation == "packaging-recovery" else None)
                self.assertEqual(capture["request_sha256"], sha256(
                    (self.operation_dir / ".recovery-request-v2.pending.json").read_bytes()))

                expected_native = [
                    "toolchain", "producer", "verify-recovery",
                    "--forbidden-prefix", str(self.forbidden_a),
                    "--forbidden-prefix", str(self.forbidden_b),
                    "--directory", str(self.release_dir),
                    "--release-id", RELEASE_ID,
                    "--base-url", f"{REPOSITORY}/releases/download/{SOURCE_TAG}",
                    "--inputs-sha256", self.inputs_sha,
                    "--index-sha256", self.index_sha,
                    "--selection", str(self.paths["selection"]),
                    "--selection-sha256", self._digest("selection"),
                    "--subject-manifest", str(self.paths["subject_manifest"]),
                    "--subject-manifest-sha256", self.subject_sha,
                    "--qualification-evidence", str(self.paths["qualification_evidence"]),
                    "--qualification-sha256", self._digest("qualification_evidence"),
                    "--policy", str(self.paths["policy"]), "--policy-sha256", self._digest("policy"),
                    "--recovery-request", str(self.operation_dir / ".recovery-request-v2.pending.json"),
                    "--recovery-request-sha256", capture["request_sha256"],
                    "--format", "json",
                ]
                self.assertEqual(capture["argv"], expected_native)
                self.assertFalse(any(arg == "--release-format" for arg in capture["argv"]))
                self.assertEqual(summary["native_result"]["operation"], "verify-recovery")
                self.assertEqual(summary["native_result"]["sdk_generations"], self._result(operation)["sdk_generations"])
                self.assertEqual(summary["native_result"]["sdks"], self._result(operation)["sdks"])
                self.assertEqual(summary["scope"], {
                    "provider_run_attempt_authenticated": False,
                    "tag_object_authenticated": False,
                    "signature_verified": False,
                    "original_owner_jobs_verified": False,
                    "publication_authorized": False,
                    "replay_or_repackage_executed": False,
                })
                final_path = Path(summary["recovery_request"]["path"])
                self.assertEqual(final_path.read_bytes(),
                                 (self.operation_dir / ".recovery-request-v2.pending.json").read_bytes())

    def test_observation_and_selector_mismatches_fail_before_child(self) -> None:
        cases = [
            ("observed_run", {**self.source_run, "run_attempt": 4}),
            ("observed_source_tag", {**self.source_tag, "name": "v2.4.1"}),
            ("observed_source_tag", {**self.source_tag, "peeled_commit": "e" * 40}),
            ("observed_attestation", {**self.attestation, "signer": "other-signer"}),
        ]
        for key, value in cases:
            with self.subTest(key=key, value=value):
                if self.capture_path.exists():
                    self.capture_path.unlink()
                self._write_json(self.paths[key], value)
                argv = self._argv()
                completed = subprocess.run([sys.executable, str(SCRIPT), *argv],
                                           text=True, capture_output=True, timeout=30)
                self._assert_no_success(completed)
                # Restore input between independent mismatch cases.
                original = {"observed_run": self.source_run,
                            "observed_source_tag": self.source_tag,
                            "observed_attestation": self.attestation}[key]
                self._write_json(self.paths[key], original)

        completed = self._invoke(extra=["--qualification-sha256", "0" * 64])
        self._assert_no_success(completed)

    def test_packaging_handoff_mismatches_and_non_absent_states_fail(self) -> None:
        invalid = [
            {**self.handoff, "release_id": "v2.4.2"},
            {**self.handoff, "tag": {**self.handoff["tag"], "name": "v2.4.2"}},
            {**self.handoff, "tag": {**self.handoff["tag"], "peeled_commit": "e" * 40}},
            {**self.handoff, "tag": {**self.handoff["tag"], "tag_object": SOURCE_TAG_OBJECT}},
            *[{**self.handoff, "state": state} for state in ("draft", "published", "unknown")],
        ]
        for handoff in invalid:
            with self.subTest(handoff=handoff):
                if self.capture_path.exists():
                    self.capture_path.unlink()
                self._write_json(self.paths["handoff"], handoff)
                completed = subprocess.run([sys.executable, str(SCRIPT), *self._argv()],
                                           text=True, capture_output=True, timeout=30)
                self._assert_no_success(completed)
        self._write_json(self.paths["handoff"], self.handoff)

    def test_only_the_two_eligible_operation_stage_pairs_are_accepted(self) -> None:
        for operation, stage in (("packaging-recovery", "comparison"),
                                 ("packaging-recovery", "attestation"),
                                 ("compatibility-replay", "packaging"),
                                 ("compatibility-replay", "unknown")):
            with self.subTest(operation=operation, stage=stage):
                completed = self._invoke(operation, failed_stage=stage,
                                         handoff=(operation == "packaging-recovery"))
                self._assert_no_success(completed)
        completed = self._invoke("compatibility-replay", failed_stage="compatibility-harness",
                                 handoff=True)
        self._assert_no_success(completed)
        completed = self._invoke("packaging-recovery", failed_stage="packaging", handoff=False)
        self._assert_no_success(completed)
        completed = self._invoke("packaging-recovery", failed_stage=None)
        self._assert_no_success(completed)

    def test_closed_json_rejects_missing_extra_duplicate_and_null_documents(self) -> None:
        original = self.paths["observed_run"].read_bytes()
        bad_documents = [
            b"null\n",
            json_bytes({key: value for key, value in self.source_run.items() if key != "run_attempt"}),
            json_bytes({**self.source_run, "extra": True}),
            (b'{"repository":"' + REPOSITORY.encode() + b'","repository":"'
             + REPOSITORY.encode() + b'","workflow":"' + WORKFLOW.encode()
             + b'","run_id":701,"run_attempt":3,"producer_commit":"'
             + PRODUCER_COMMIT.encode() + b'","source_tag":"' + SOURCE_TAG.encode()
             + b'","tag_object":"' + SOURCE_TAG_OBJECT.encode() + b'"}\n'),
        ]
        for raw in bad_documents:
            with self.subTest(raw=raw[:32]):
                self.paths["observed_run"].write_bytes(raw)
                completed = subprocess.run([sys.executable, str(SCRIPT), *self._argv()],
                                           text=True, capture_output=True, timeout=30)
                self._assert_no_success(completed)
        self.paths["observed_run"].write_bytes(original)

    def test_symlink_hardlink_oversize_and_hash_mismatch_fail_before_child(self) -> None:
        selected = self.paths["policy"]
        original = selected.read_bytes()
        real = self.evidence_dir / "policy-real.json"
        real.write_bytes(original)
        selected.unlink()
        selected.symlink_to(real)
        completed = subprocess.run([sys.executable, str(SCRIPT), *self._argv()],
                                   text=True, capture_output=True, timeout=30)
        self._assert_no_success(completed)
        selected.unlink()
        real.unlink()

        selected.write_bytes(original)
        hardlink = self.evidence_dir / "policy-hardlink.json"
        os.link(selected, hardlink)
        completed = subprocess.run([sys.executable, str(SCRIPT), *self._argv()],
                                   text=True, capture_output=True, timeout=30)
        self._assert_no_success(completed)
        hardlink.unlink()

        selected.write_bytes(b"{" + b" " * (16 * 1024 * 1024) + b"}")
        completed = subprocess.run([sys.executable, str(SCRIPT), *self._argv()],
                                   text=True, capture_output=True, timeout=30)
        self._assert_no_success(completed)

        selected.write_bytes(original)
        completed = self._invoke(extra=["--policy-sha256", "0" * 64])
        self._assert_no_success(completed)

    def test_missing_or_changed_release_input_and_index_fail_before_child(self) -> None:
        for path, original in ((self.inputs_path, self.inputs_bytes),
                               (self.index_path, self.index_bytes)):
            with self.subTest(path=path.name, failure="missing"):
                path.unlink()
                completed = subprocess.run(
                    [sys.executable, str(SCRIPT), *self._argv(failed_stage="packaging")],
                    text=True, capture_output=True, timeout=30)
                self._assert_no_success(completed)
                path.write_bytes(original)

            with self.subTest(path=path.name, failure="digest-mismatch"):
                path.write_bytes(b'{"changed_after_selection":true}\n')
                completed = subprocess.run(
                    [sys.executable, str(SCRIPT), *self._argv(failed_stage="packaging")],
                    text=True, capture_output=True, timeout=30)
                self._assert_no_success(completed)
                path.write_bytes(original)

    def test_native_failure_wrong_result_joins_or_decision_has_no_final_request(self) -> None:
        self._make_runtime(return_code=19)
        completed = subprocess.run([sys.executable, str(SCRIPT), *self._argv()],
                                   text=True, capture_output=True, timeout=30)
        self.assertNotEqual(completed.returncode, 0)
        self.assertTrue((self.operation_dir / "verify-recovery.stderr.log").exists())
        self.assertFalse((self.operation_dir / "recovery-request-v2.json").exists())

        for override in (
            {"decision": "replay-compatibility"},
            {"inputs_sha256": "0" * 64},
            {"selection_sha256": "0" * 64},
            {"qualification_sha256": "0" * 64},
            {"policy_sha256": "0" * 64},
            {"subject_manifest_sha256": "0" * 64},
            {"recovery_request_sha256": "0" * 64},
            {"checksums_sha256": "0" * 64},
            {"provenance_sha256": "0" * 64},
            {"sdk_count": 0},
            {"sdk_count": 2},
        ):
            with self.subTest(override=override):
                if self.operation_dir.exists():
                    for path in self.operation_dir.iterdir():
                        path.unlink()
                    self.operation_dir.rmdir()
                self.capture_path.unlink(missing_ok=True)
                response = self._result("packaging-recovery")
                response.update(override)
                self._make_runtime(response=response)
                completed = subprocess.run([sys.executable, str(SCRIPT), *self._argv()],
                                           text=True, capture_output=True, timeout=30)
                self._assert_no_success(completed, child_ran=True)
                self.assertTrue((self.operation_dir / "verify-recovery.stderr.log").exists())

        sdk_mutations = []
        wrong_identity = self._result("packaging-recovery")["sdks"][0]
        wrong_identity["identity"] = {"sdk_id": "other-sdk"}
        sdk_mutations.append({"sdks": [wrong_identity]})
        wrong_package = self._result("packaging-recovery")["sdks"][0]
        wrong_package["tree_sha256"] = "0" * 64
        sdk_mutations.append({"sdks": [wrong_package]})
        wrong_generation_tuple = self._result("packaging-recovery")["sdk_generations"][0]
        wrong_generation_tuple["group_id"] = "other-group"
        sdk_mutations.append({"sdk_generations": [wrong_generation_tuple]})
        wrong_generation_hash = self._result("packaging-recovery")["sdk_generations"][0]
        wrong_generation_hash["compatibility_receipt_sha256"] = "0" * 64
        sdk_mutations.append({"sdk_generations": [wrong_generation_hash]})
        for override in sdk_mutations:
            with self.subTest(sdk_override=override):
                if self.operation_dir.exists():
                    for path in self.operation_dir.iterdir():
                        path.unlink()
                    self.operation_dir.rmdir()
                self.capture_path.unlink(missing_ok=True)
                response = self._result("packaging-recovery")
                response.update(override)
                self._make_runtime(response=response)
                completed = subprocess.run([sys.executable, str(SCRIPT), *self._argv()],
                                           text=True, capture_output=True, timeout=30)
                self._assert_no_success(completed, child_ran=True)

        for omitted in ("sdks", "sdk_generations", "sdk_count", "sdk_generation_count"):
            with self.subTest(omitted=omitted):
                if self.operation_dir.exists():
                    for path in self.operation_dir.iterdir():
                        path.unlink()
                    self.operation_dir.rmdir()
                self.capture_path.unlink(missing_ok=True)
                response = self._result("packaging-recovery")
                response.pop(omitted)
                self._make_runtime(response=response)
                completed = subprocess.run([sys.executable, str(SCRIPT), *self._argv()],
                                           text=True, capture_output=True, timeout=30)
                self._assert_no_success(completed, child_ran=True)

    def test_late_mutation_retains_diagnostics_but_writes_no_final_request(self) -> None:
        self._make_runtime(mutate_path=self.paths["policy"])
        completed = subprocess.run([sys.executable, str(SCRIPT), *self._argv()],
                                   text=True, capture_output=True, timeout=30)
        self.assertNotEqual(completed.returncode, 0)
        self.assertTrue((self.operation_dir / "verify-recovery.stderr.log").exists())
        self.assertFalse((self.operation_dir / "recovery-request-v2.json").exists())

    def test_late_release_input_and_index_mutations_fail_without_final_request(self) -> None:
        for path, original in ((self.inputs_path, self.inputs_bytes),
                               (self.index_path, self.index_bytes)):
            with self.subTest(path=path.name):
                if self.operation_dir.exists():
                    for child in self.operation_dir.iterdir():
                        child.unlink()
                    self.operation_dir.rmdir()
                self.capture_path.unlink(missing_ok=True)
                path.write_bytes(original)
                self._make_runtime(mutate_path=path)
                completed = subprocess.run(
                    [sys.executable, str(SCRIPT), *self._argv(failed_stage="packaging")],
                    text=True, capture_output=True, timeout=30)
                self.assertNotEqual(completed.returncode, 0, completed.stdout)
                self.assertTrue(self.capture_path.exists())
                self.assertTrue((self.operation_dir / "verify-recovery.stderr.log").exists())
                self.assertFalse((self.operation_dir / "recovery-request-v2.json").exists())
                path.write_bytes(original)

    def _load_adapter(self):
        spec = importlib.util.spec_from_file_location("_recovery_request_v2_test_adapter", SCRIPT)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        adapter = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = adapter
        spec.loader.exec_module(adapter)
        return adapter

    def test_post_write_held_mutation_removes_only_the_new_final_request(self) -> None:
        self._make_runtime()
        adapter = self._load_adapter()
        args = adapter._parser().parse_args(self._argv(failed_stage="packaging"))
        original_check = adapter._HELPERS._check_held
        mutated = False

        def mutate_after_final(held):
            nonlocal mutated
            final = self.operation_dir / "recovery-request-v2.json"
            if final.exists() and not mutated:
                self.paths["policy"].write_bytes(b"post-write mutation")
                mutated = True
            return original_check(held)

        with mock.patch.object(adapter._HELPERS, "_check_held", side_effect=mutate_after_final):
            with self.assertRaises(adapter.AdapterError):
                adapter.run(args)
        self.assertTrue(mutated, "the counterprobe must mutate only after final creation")
        self.assertFalse((self.operation_dir / "recovery-request-v2.json").exists())
        self.assertTrue((self.operation_dir / "verify-recovery.stderr.log").exists())

    def test_restrictive_umask_preserves_success_and_late_failure_cleanup(self) -> None:
        adapter = self._load_adapter()
        self.operation_dir.mkdir(mode=0o700)
        identity = adapter._directory_identity(self.operation_dir)
        final = self.operation_dir / "recovery-request-v2.json"
        data = b"closed request fixture\n"
        digest = hashlib.sha256(data).hexdigest()
        previous_umask = os.umask(0o777)
        try:
            adapter._write_final_request(
                final, data, digest, held={}, operation_dir=self.operation_dir,
                expected_directory_identity=identity)
            self.assertEqual(final.read_bytes(), data)
            self.assertEqual(final.stat().st_mode & 0o777, 0o600)
            final.unlink()
            with mock.patch.object(adapter._HELPERS, "_check_held",
                                   side_effect=adapter.AdapterError("late failure")):
                with self.assertRaises(adapter.AdapterError):
                    adapter._write_final_request(
                        final, data, digest, held={}, operation_dir=self.operation_dir,
                        expected_directory_identity=identity)
            self.assertFalse(final.exists())
        finally:
            os.umask(previous_umask)

    def test_post_write_operation_root_change_removes_old_request_and_preserves_new_sentinel(self) -> None:
        self._make_runtime()
        adapter = self._load_adapter()
        args = adapter._parser().parse_args(self._argv(failed_stage="packaging"))
        moved = self.operation_parent / "moved-operation"
        sentinel = self.operation_dir / "preserve.me"
        original_identity = adapter._directory_identity
        changed = False

        def replace_after_final(path):
            nonlocal changed
            if path == self.operation_dir and (path / "recovery-request-v2.json").exists() and not changed:
                path.rename(moved)
                path.mkdir(mode=0o700)
                (path / "preserve.me").write_bytes(b"sentinel")
                changed = True
            return original_identity(path)

        with mock.patch.object(adapter, "_directory_identity", side_effect=replace_after_final):
            with self.assertRaises(adapter.AdapterError):
                adapter.run(args)
        self.assertTrue(changed, "the counterprobe must replace the root after final creation")
        self.assertFalse((moved / "recovery-request-v2.json").exists())
        self.assertEqual((self.operation_dir / "preserve.me").read_bytes(), b"sentinel")
        self.assertEqual((moved / "preserve.me").exists(), False)

    def test_operation_root_sentinel_and_selected_root_overlap_are_rejected(self) -> None:
        self.operation_dir.mkdir()
        sentinel = self.operation_dir / "keep.me"
        sentinel.write_bytes(b"preserve")
        completed = self._invoke()
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(sentinel.read_bytes(), b"preserve")
        self.assertFalse(self.capture_path.exists())

        sentinel.unlink()
        self.operation_dir.rmdir()
        args = self._argv()
        args[args.index("--operation-dir") + 1] = str(self.evidence_dir / "nested-operation")
        completed = subprocess.run([sys.executable, str(SCRIPT), *args], text=True,
                                   capture_output=True, timeout=30)
        self._assert_no_success(completed)

        args = self._argv()
        args[args.index("--operation-dir") + 1] = str(self.forbidden_a / "nested-operation")
        completed = subprocess.run([sys.executable, str(SCRIPT), *args], text=True,
                                   capture_output=True, timeout=30)
        self._assert_no_success(completed)


if __name__ == "__main__":
    unittest.main()
