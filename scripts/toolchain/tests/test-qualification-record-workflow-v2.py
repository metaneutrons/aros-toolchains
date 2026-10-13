#!/usr/bin/env python3
"""Exercise the V2 qualification and metadata-sealing workflow run blocks.

All producer, route and runtime commands are local synthetic stubs. The tests
run the extracted Bash/Python blocks but perform no network calls, builds, or
real signature verification.
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


ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = ROOT / ".github/workflows/toolchain-release.yml"
QUALIFICATION_STEP = "Record complete tag-bound V2 qualification"
SEAL_STEP = "Seal qualification transport metadata"
FINAL_EVIDENCE_STEP = "Verify genuine combined candidate provenance and final native evidence"
REPOSITORY = "example/aros-toolchains"
RELEASE_TAG = "v1.2.3"
TAG_OBJECT = "a" * 40
PRODUCER_COMMIT = "b" * 40
EXPECTED_DIGESTS = {
    "EXPECTED_RUNTIME_SHA": "1" * 64,
    "EXPECTED_INDEX_SHA": "2" * 64,
    "EXPECTED_SUBJECT_SHA": "3" * 64,
    "EXPECTED_SELECTION_SHA": "4" * 64,
    "EXPECTED_SUMMARY_SHA": "5" * 64,
    "EXPECTED_INPUTS_SHA": "6" * 64,
}


def _job_block(workflow: str, name: str) -> str:
    headers = list(re.finditer(r"(?m)^  ([A-Za-z0-9_-]+):[ \t]*$", workflow))
    matches = [match for match in headers if match.group(1) == name]
    if len(matches) != 1:
        raise AssertionError(f"expected exactly one {name} job")
    selected = matches[0]
    following = next((item for item in headers if item.start() > selected.start()), None)
    return workflow[selected.start() : following.start() if following else len(workflow)]


def _step_block(job: str, name: str) -> str:
    steps = list(re.finditer(r"(?m)^      - (?:name:|id:|uses:)", job))
    selected = [item for item in steps if job[item.start() :].startswith(f"      - name: {name}\n")]
    if len(selected) != 1:
        raise AssertionError(f"expected exactly one workflow step named {name!r}")
    start = selected[0].start()
    following = next((item for item in steps if item.start() > start), None)
    return job[start : following.start() if following else len(job)]


def _run_body(step: str) -> str:
    marker = "        run: |\n"
    if marker not in step:
        raise AssertionError("workflow step has no literal run block")
    raw = step.split(marker, 1)[1]
    body: list[str] = []
    for line in raw.splitlines():
        if not line:
            body.append("")
        elif line.startswith("          "):
            body.append(line[10:])
        else:
            break
    if not body:
        raise AssertionError("workflow run block is empty")
    return "\n".join(body).rstrip() + "\n"


FAKE_PYTHON = r'''#!/usr/bin/env python3
import hashlib
import json
import os
from pathlib import Path
import sys

args = sys.argv[1:]
if len(args) < 2 or args[0] != "-B":
    raise SystemExit("unexpected synthetic python invocation")
script = args[1]
if script.endswith("select-compiler-sdk-route-v2.py"):
    role = "route"
elif script.endswith("materialize-aros-tools-runtime.py"):
    role = "runtime"
elif script.endswith("record-complete-qualification-v2.py"):
    role = "record"
else:
    raise SystemExit("unexpected Python command in extracted workflow block")
with open(os.environ["FAKE_COMMAND_LOG"], "a", encoding="utf-8") as log:
    log.write(json.dumps({"role": role, "argv": args}, separators=(",", ":")) + "\n")

def option(name):
    return args[args.index(name) + 1]

mode = os.environ.get("FAKE_MODE", "positive")
if role == "route":
    route = Path(option("--github-output"))
    tag_object = os.environ.get("FAKE_ROUTE_TAG_OBJECT", os.environ["SELECTED_TAG_OBJECT"])
    route.write_text(
        f"tag_object={tag_object}\nrelease_id={os.environ['SELECTED_RELEASE_ID']}\nruntime_kind=released\n",
        encoding="utf-8",
    )
elif role == "runtime":
    if mode == "runtime-fails":
        print("synthetic runtime verification failure", file=sys.stderr)
        raise SystemExit(41)
elif role == "record":
    if mode == "record-fails":
        print("synthetic qualification recorder failure", file=sys.stderr)
        raise SystemExit(42)
    parent = Path(option("--operation-dir")).parent
    operation = Path(option("--operation-dir"))
    operation.mkdir()
    evidence_path = operation / "qualification-evidence-v2.json"
    evidence_raw = b"synthetic complete tag-bound V2 qualification evidence\n"
    with evidence_path.open("xb") as evidence:
        evidence.write(evidence_raw)
    source = {
        "tag": option("--source-tag"),
        "tag_object": option("--source-tag-object"),
        "peeled_commit": option("--source-tag-commit"),
        "run_id": int(option("--run-id")),
        "run_attempt": int(option("--run-attempt")),
    }
    if mode == "summary-wrong-run":
        source["run_id"] += 1
    if mode == "summary-wrong-tag":
        source["tag"] = "v9.8.7"
    if mode == "summary-wrong-object":
        source["tag_object"] = "f" * 40
    if mode == "summary-wrong-commit":
        source["peeled_commit"] = "f" * 40
    if mode == "summary-wrong-attempt":
        source["run_attempt"] += 1
    reported_path = str(evidence_path)
    reported_sha = hashlib.sha256(evidence_raw).hexdigest()
    if mode == "summary-wrong-path":
        reported_path = str(parent / "elsewhere.json")
    if mode == "summary-wrong-digest":
        reported_sha = "0" * 64
    summary = {
        "schema": "aros-toolchain-full-qualification-record-adapter-v2",
        "operation": "record-full-qualification",
        "qualification_evidence": {"path": reported_path, "sha256": reported_sha},
        "source_observation": source,
        "scope": {"publication": False},
    }
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
'''


class WorkflowProbe:
    def __init__(self, mode: str, *, event: str = "push", ref_type: str = "tag",
                 source_ref: str | None = None, attempt: str = "1") -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="qualification-workflow-v2-")
        self.root = Path(self.temp.name).resolve()
        self.home = self.root / "home"
        self.workspace = self.root / "workspace"
        self.runner_temp = self.root / "runner-temp"
        self.bin = self.root / "bin"
        for directory in (self.home, self.workspace, self.runner_temp, self.bin):
            directory.mkdir()
        (self.workspace / "toolchains").mkdir()
        (self.workspace / "toolchains/compiler-sdk-ci-selection-v2.json").write_text("{}\n")
        (self.workspace / "toolchains/aros-tools-runtime-v1.json").write_text("{}\n")
        runtime = self.runner_temp / "diagnostic-runtime/bin/aros"
        runtime.parent.mkdir(parents=True)
        runtime.write_bytes(b"synthetic runtime; never executed")
        (self.runner_temp / "release-candidate/release").mkdir(parents=True)
        self.output = self.root / "github-output"
        self.output.write_bytes(b"")
        self.log = self.root / "commands.jsonl"
        self.log.write_bytes(b"")
        python = self.bin / "python3"
        python.write_text(FAKE_PYTHON.replace(
            "#!/usr/bin/env python3", f"#!{sys.executable}", 1
        ), encoding="utf-8")
        python.chmod(0o755)
        self.environment = {
            **os.environ,
            "PATH": f"{self.bin}:{os.environ.get('PATH', '/usr/bin:/bin')}",
            "HOME": str(self.home),
            "GITHUB_WORKSPACE": str(self.workspace),
            "RUNNER_TEMP": str(self.runner_temp),
            "GITHUB_OUTPUT": str(self.output),
            "GITHUB_EVENT_NAME": event,
            "GITHUB_REF_TYPE": ref_type,
            "GITHUB_REF": source_ref or f"refs/tags/{RELEASE_TAG}",
            "GITHUB_REPOSITORY": REPOSITORY,
            "GITHUB_SHA": PRODUCER_COMMIT,
            "GITHUB_RUN_ID": "8421",
            "GITHUB_RUN_ATTEMPT": attempt,
            "TOOLS_RUNTIME_LOCK": "toolchains/aros-tools-runtime-v1.json",
            "SELECTED_TAG_OBJECT": TAG_OBJECT,
            "SELECTED_RELEASE_ID": RELEASE_TAG,
            "FAKE_COMMAND_LOG": str(self.log),
            "FAKE_MODE": mode,
            **EXPECTED_DIGESTS,
        }

    def close(self) -> None:
        self.temp.cleanup()

    def execute(self, script: str) -> dict:
        result = subprocess.run(
            ["bash", "--noprofile", "--norc", "-c", script],
            cwd=ROOT, env=self.environment, capture_output=True, text=True,
            check=False, timeout=20,
        )
        calls = [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]
        output_lines = self.output.read_text(encoding="utf-8").splitlines()
        outputs = dict(line.split("=", 1) for line in output_lines if "=" in line)
        parent = Path(outputs["parent"]) if "parent" in outputs else None
        summary = None
        summary_file = parent / "record-result.json" if parent else None
        if summary_file is not None and summary_file.is_file():
            try:
                summary = json.loads(summary_file.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                pass
        evidence_file = parent / "record/qualification-evidence-v2.json" if parent else None
        evidence_raw = evidence_file.read_bytes() if evidence_file is not None and evidence_file.is_file() else None
        route_file = self.runner_temp / "qualification-route.env"
        return {
            "status": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "calls": calls,
            "output_lines": output_lines,
            "outputs": outputs,
            "parent": str(parent) if parent else None,
            "summary": summary,
            "evidence_path": str(evidence_file) if evidence_file else None,
            "evidence_raw": evidence_raw,
            "route_lines": route_file.read_text(encoding="utf-8").splitlines() if route_file.is_file() else [],
            "workspace": str(self.workspace),
            "runner_temp": str(self.runner_temp),
        }


def _inside(path: str, parent: str) -> bool:
    candidate = Path(path)
    root = Path(parent)
    return candidate == root or root in candidate.parents


class QualificationWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")
        cls.job = _job_block(cls.workflow, "v2-readback")
        cls.record_step = _step_block(cls.job, QUALIFICATION_STEP)
        cls.record_body = _run_body(cls.record_step)
        cls.seal_step = _step_block(cls.job, SEAL_STEP)
        cls.seal_body = _run_body(cls.seal_step)

    def _probe(self, mode: str = "positive", **context: str) -> dict:
        fixture = WorkflowProbe(mode, **context)
        try:
            return fixture.execute(self.record_body)
        finally:
            fixture.close()

    def assert_no_evidence_success_outputs(self, result: dict) -> None:
        self.assertNotIn("evidence", result["outputs"])
        self.assertNotIn("evidence_sha256", result["outputs"])

    def test_workflow_gate_order_permissions_and_readback_checkout_are_closed(self) -> None:
        self.assertIn(
            "if: github.event_name == 'push' && needs.v2-prepare.outputs.runtime_kind == 'released'",
            self.record_step,
        )
        self.assertIn(
            '[[ "$GITHUB_EVENT_NAME" == push && "$GITHUB_REF_TYPE" == tag && "$GITHUB_RUN_ATTEMPT" == 1 ]]',
            self.record_body,
        )
        self.assertIn(
            '[[ "$GITHUB_REF" == "refs/tags/$SELECTED_RELEASE_ID"', self.record_body
        )

        final_evidence = _step_block(self.job, FINAL_EVIDENCE_STEP)
        self.assertLess(self.job.index(final_evidence), self.job.index(self.record_step))
        final_body = _run_body(final_evidence)
        self.assertEqual(final_body.count("bash scripts/toolchain/verify-provenance-attestation.sh"), 2)
        self.assertIn('"$runtime" toolchain producer verify-release-evidence', final_body)

        checkouts = list(re.finditer(
            r"(?ms)^      - uses: actions/checkout@[^\n]*\n(.*?)(?=^      - |\Z)", self.job
        ))
        self.assertTrue(checkouts, "readback job must check out the producer repository")
        self.assertIn(
            "fetch-depth: 0", checkouts[0].group(1),
            "the producer checkout needs full history for annotated tag checks",
        )

        permission_lines = re.findall(r"(?m)^      ([a-z-]+): ([a-z]+)$", self.job.split("    permissions:\n", 1)[1].split("    steps:", 1)[0])
        permissions = dict(permission_lines)
        self.assertEqual(permissions, {
            "contents": "read", "actions": "read", "id-token": "write", "attestations": "write",
        })
        self.assertNotRegex(
            self.record_body,
            r"(?im)^\s*(?:gh\s+release\b|git\s+(?:tag|push)\b|gh\s+api\b[^\n]*(?:-X|--method)\s+(?:POST|PUT|PATCH|DELETE))",
        )
        parent_output = self.record_body.index("printf 'parent=%s\\n'")
        route_verified = self.record_body.index("grep -Fx 'runtime_kind=released'")
        runtime_verified = self.record_body.index("materialize-aros-tools-runtime.py verify")
        self.assertLess(route_verified, parent_output)
        self.assertLess(parent_output, runtime_verified)
        self.assertLess(self.record_body.index("jq -e"), self.record_body.index("printf 'evidence=%s\\nevidence_sha256=%s\\n'"))

        attest = _step_block(self.job, "Attest the unchanged complete qualification record")
        seal = self.seal_step
        retain = _step_block(self.job, "Retain complete qualification and its signed provenance")
        failure_retain = _step_block(self.job, "Retain bounded qualification failure diagnostics")
        self.assertIn("steps.complete-qualification.outcome == 'success'", attest)
        self.assertIn("steps.qualification-signature.outcome == 'success'", seal)
        self.assertIn("${{ steps.complete-qualification.outputs.parent }}/", retain)
        self.assertIn("retention-days: 90", retain)
        self.assertIn("failure() && steps.complete-qualification.outputs.parent != ''", failure_retain)
        self.assertIn("retention-days: 7", failure_retain)
        self.assertIn("${{ runner.temp }}/qualification-route.env", failure_retain)

    def test_positive_run_emits_only_verified_helper_evidence_path_and_digest(self) -> None:
        result = self._probe()
        self.assertEqual(result["status"], 0, result["stderr"])
        self.assertEqual([call["role"] for call in result["calls"]], ["route", "runtime", "record"])
        self.assertEqual(result["route_lines"], [
            f"tag_object={TAG_OBJECT}", f"release_id={RELEASE_TAG}", "runtime_kind=released",
        ])

        workspace = Path(result["workspace"])
        runner_temp = Path(result["runner_temp"])
        runtime = runner_temp / "diagnostic-runtime/bin/aros"
        expected_route_argv = [
            "-B", "scripts/toolchain/select-compiler-sdk-route-v2.py",
            "--event", "push", "--ref-type", "tag", "--source-ref", f"refs/tags/{RELEASE_TAG}",
            "--repository", REPOSITORY, "--producer-commit", PRODUCER_COMMIT,
            "--run-attempt", "1", "--producer-dir", str(workspace),
            "--selection", str(workspace / "toolchains/compiler-sdk-ci-selection-v2.json"),
            "--runtime-lock", str(workspace / "toolchains/aros-tools-runtime-v1.json"),
            "--github-output", str(runner_temp / "qualification-route.env"),
        ]
        expected_runtime_argv = [
            "-B", "scripts/toolchain/materialize-aros-tools-runtime.py", "verify",
            "--lock", str(workspace / "toolchains/aros-tools-runtime-v1.json"),
            "--host", "linux-x86_64", "--directory", str(runner_temp / "diagnostic-runtime"),
        ]
        route, runtime_call, record = result["calls"]
        self.assertEqual(route["argv"], expected_route_argv)
        self.assertEqual(runtime_call["argv"], expected_runtime_argv)
        self.assertEqual(record["argv"][:2], ["-B", "scripts/toolchain/record-complete-qualification-v2.py"])
        record_args = record["argv"][2:]
        self.assertEqual(record_args, [
            "--runtime", str(runtime), "--runtime-sha256", EXPECTED_DIGESTS["EXPECTED_RUNTIME_SHA"],
            "--release-dir", str(runner_temp / "release-candidate/release"),
            "--inputs-sha256", EXPECTED_DIGESTS["EXPECTED_INPUTS_SHA"],
            "--index-sha256", EXPECTED_DIGESTS["EXPECTED_INDEX_SHA"],
            "--selection", str(runner_temp / "native-release-evidence-selection.json"),
            "--selection-sha256", EXPECTED_DIGESTS["EXPECTED_SELECTION_SHA"],
            "--subject-manifest", str(runner_temp / "release-candidate/subject-manifest.json"),
            "--subject-manifest-sha256", EXPECTED_DIGESTS["EXPECTED_SUBJECT_SHA"],
            "--candidate-summary", str(runner_temp / "release-candidate-summary.json"),
            "--candidate-summary-sha256", EXPECTED_DIGESTS["EXPECTED_SUMMARY_SHA"],
            "--repository", REPOSITORY, "--workflow", ".github/workflows/toolchain-release.yml",
            "--run-id", "8421", "--run-attempt", "1", "--source-tag", RELEASE_TAG,
            "--source-tag-object", TAG_OBJECT, "--source-tag-commit", PRODUCER_COMMIT,
            "--created-at", record_args[record_args.index("--created-at") + 1],
            "--expires-at", record_args[record_args.index("--expires-at") + 1],
            "--operation-dir", record_args[record_args.index("--operation-dir") + 1],
            "--forbidden-prefix", str(workspace), "--forbidden-prefix", str(runner_temp),
        ])
        created = int(record_args[record_args.index("--created-at") + 1])
        expires = int(record_args[record_args.index("--expires-at") + 1])
        self.assertEqual(expires - created, 7 * 24 * 60 * 60)
        operation = Path(record_args[record_args.index("--operation-dir") + 1])
        self.assertEqual(operation.parent, Path(result["parent"]))
        self.assertFalse(_inside(result["parent"], result["workspace"]))
        self.assertFalse(_inside(result["parent"], result["runner_temp"]))

        returned = result["summary"]["qualification_evidence"]
        self.assertEqual(returned["path"], result["evidence_path"])
        self.assertEqual(hashlib.sha256(result["evidence_raw"]).hexdigest(), returned["sha256"])
        self.assertEqual(result["outputs"]["evidence"], returned["path"])
        self.assertEqual(result["outputs"]["evidence_sha256"], returned["sha256"])
        self.assertEqual(result["summary"]["source_observation"], {
            "tag": RELEASE_TAG, "tag_object": TAG_OBJECT, "peeled_commit": PRODUCER_COMMIT,
            "run_id": 8421, "run_attempt": 1,
        })

    def test_wrong_invocation_contexts_stop_before_route_and_recorder(self) -> None:
        cases = (
            ("branch", {"event": "push", "ref_type": "branch", "source_ref": "refs/heads/main"}),
            ("rerun", {"event": "push", "ref_type": "tag", "attempt": "2"}),
            ("wrong-ref", {"event": "push", "ref_type": "tag", "source_ref": "refs/tags/v9.8.7"}),
        )
        for label, context in cases:
            with self.subTest(case=label):
                result = self._probe(**context)
                self.assertNotEqual(result["status"], 0)
                self.assertEqual(result["calls"], [])
                self.assert_no_evidence_success_outputs(result)

    def test_route_runtime_and_recorder_failures_never_emit_evidence_success(self) -> None:
        cases = (
            ("changed-route-object", "route-tag-mismatch", ["route"]),
            ("runtime-verify", "runtime-fails", ["route", "runtime"]),
            ("recorder", "record-fails", ["route", "runtime", "record"]),
        )
        for label, mode, expected_roles in cases:
            with self.subTest(case=label):
                if mode == "route-tag-mismatch":
                    fixture = WorkflowProbe("positive")
                    fixture.environment["FAKE_ROUTE_TAG_OBJECT"] = "f" * 40
                    try:
                        result = fixture.execute(self.record_body)
                    finally:
                        fixture.close()
                else:
                    result = self._probe(mode)
                self.assertNotEqual(result["status"], 0)
                self.assertEqual([call["role"] for call in result["calls"]], expected_roles)
                self.assert_no_evidence_success_outputs(result)
                if label in {"runtime-verify", "recorder"}:
                    self.assertIsNotNone(result["parent"], "parent output is failure-diagnostic metadata only")
                    self.assertFalse(_inside(result["parent"], result["workspace"]))
                    self.assertFalse(_inside(result["parent"], result["runner_temp"]))
                else:
                    self.assertIsNone(result["parent"])

    def test_wrong_recorder_summary_bindings_never_emit_evidence_success(self) -> None:
        for mode in ("summary-wrong-path", "summary-wrong-digest", "summary-wrong-run", "summary-wrong-tag",
                     "summary-wrong-object", "summary-wrong-commit", "summary-wrong-attempt"):
            with self.subTest(mode=mode):
                result = self._probe(mode)
                self.assertNotEqual(result["status"], 0)
                self.assertEqual([call["role"] for call in result["calls"]], ["route", "runtime", "record"])
                self.assertIsNotNone(result["parent"])
                self.assert_no_evidence_success_outputs(result)

    def _seal_probe(self, *, changed_evidence: bool = False, symlink_bundle: bool = False,
                    oversized_bundle: bool = False, existing_output: bool = False) -> dict:
        with tempfile.TemporaryDirectory(prefix="qualification-seal-v2-") as temporary_name:
            root = Path(temporary_name).resolve()
            parent = root / "parent"
            runner_temp = root / "runner-temp"
            parent.mkdir()
            runner_temp.mkdir()
            evidence = parent / "record/qualification-evidence-v2.json"
            evidence.parent.mkdir()
            evidence_raw = b"synthetic qualification record before attestation\n"
            evidence.write_bytes(evidence_raw + (b" changed\n" if changed_evidence else b""))
            bundle = runner_temp / "bundle.json"
            bundle_target = runner_temp / "bundle-target.json"
            if oversized_bundle:
                with bundle.open("wb") as handle:
                    handle.truncate(16 * 1024 * 1024 + 1)
            elif symlink_bundle:
                bundle_target.write_bytes(b"synthetic signed provenance bundle\n")
                bundle.symlink_to(bundle_target)
            else:
                bundle.write_bytes(b"synthetic signed provenance bundle\n")
            route = runner_temp / "qualification-route.env"
            route_raw = b"tag_object=" + TAG_OBJECT.encode() + b"\nrelease_id=v1.2.3\nruntime_kind=released\n"
            route.write_bytes(route_raw)
            bundle_output = parent / "qualification.sigstore.json"
            route_output = parent / "qualification-route.env"
            sentinel = b"preserve existing output\n"
            if existing_output:
                bundle_output.write_bytes(sentinel)
            environment = {
                **os.environ,
                "QUALIFICATION_PARENT": str(parent),
                "QUALIFICATION_PATH": str(evidence),
                "QUALIFICATION_SHA": hashlib.sha256(evidence_raw).hexdigest(),
                "QUALIFICATION_BUNDLE": str(bundle),
                "RUNNER_TEMP": str(runner_temp),
            }
            result = subprocess.run(
                ["bash", "--noprofile", "--norc", "-c", self.seal_body],
                cwd=ROOT, env=environment, capture_output=True, text=True,
                check=False, timeout=20,
            )
            return {
                "status": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "bundle_output": bundle_output.read_bytes() if bundle_output.exists() else None,
                "route_output": route_output.read_bytes() if route_output.exists() else None,
                "bundle_raw": bundle_target.read_bytes() if symlink_bundle else bundle.read_bytes() if bundle.exists() and not oversized_bundle else None,
                "route_raw": route_raw,
                "sentinel": sentinel,
            }

    def test_actual_metadata_sealing_block_copies_verified_inputs_exclusively(self) -> None:
        result = self._seal_probe()
        self.assertEqual(result["status"], 0, result["stderr"])
        self.assertEqual(result["bundle_output"], result["bundle_raw"])
        self.assertEqual(result["route_output"], result["route_raw"])

    def test_actual_metadata_sealing_block_rejects_changed_or_untrusted_inputs(self) -> None:
        cases = (
            ("changed-evidence", {"changed_evidence": True}),
            ("symlink-bundle", {"symlink_bundle": True}),
            ("oversized-bundle", {"oversized_bundle": True}),
        )
        for label, options in cases:
            with self.subTest(case=label):
                result = self._seal_probe(**options)
                self.assertNotEqual(result["status"], 0)
                self.assertIsNone(result["bundle_output"])
                self.assertIsNone(result["route_output"])

    def test_actual_metadata_sealing_block_refuses_to_overwrite_existing_output(self) -> None:
        result = self._seal_probe(existing_output=True)
        self.assertNotEqual(result["status"], 0)
        self.assertEqual(result["bundle_output"], result["sentinel"])
        self.assertIsNone(result["route_output"])


if __name__ == "__main__":
    unittest.main()
