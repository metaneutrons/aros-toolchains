#!/usr/bin/env python3
"""Run the final-candidate workflow shell against small synthetic fixtures.

The bundle, verified certificate/statement, and native CLI are test doubles.
They are explicitly synthetic and do not represent actual signing, a GitHub
attestation, or execution of the native Rust binary.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = ROOT / ".github/workflows/toolchain-release.yml"
STEP_NAME = "Verify genuine combined candidate provenance and final native evidence"
REPOSITORY = "synthetic/toolchain-fixture"
SOURCE_SHA = "a" * 40
SOURCE_REF = "refs/heads/final-candidate-fixture"
RUN_ID = "123456"
RUN_ATTEMPT = "2"
SIGNER_WORKFLOW = f"{REPOSITORY}/.github/workflows/toolchain-release.yml"
RELEASE_ID = f"toolchain-dev-{SOURCE_SHA[:12]}"
LANE_ASSET = "gnu-linux-x86_64-default"
SDK_ID = "synthetic-sdk"
GENERATION = {
    "sdk_id": SDK_ID,
    "group_id": "gnu",
    "target_profile": "default",
    "host": "linux-x86_64",
}
DIGESTS = {
    "compiler_measurement": "1" * 64,
    "compiler_build_result": "2" * 64,
    "compiler_finished_receipt": "3" * 64,
    "comparison": "4" * 64,
    "compatibility_inputs": "5" * 64,
    "compatibility_manifest": "6" * 64,
    "compatibility_receipt": "7" * 64,
    "sdk_tree": "8" * 64,
    "sdk_archive": "9" * 64,
    "sdk_manifest": "a" * 64,
    "generation_record": "b" * 64,
    "generation_compatibility_inputs": "c" * 64,
    "generation_compatibility_manifest": "d" * 64,
    "generation_compatibility_receipt": "e" * 64,
    "sdk_link_receipt": "f" * 64,
    "standalone_c": "a" * 64,
    "standalone_cxx": "b" * 64,
}


def final_candidate_shell():
    text = WORKFLOW.read_text(encoding="utf-8")
    heading = f"      - name: {STEP_NAME}\n"
    if text.count(heading) != 1:
        raise AssertionError(f"expected one workflow step named {STEP_NAME!r}")
    step = text.split(heading, 1)[1].split("      - name:", 1)[0]
    marker = "        run: |\n"
    if step.count(marker) != 1:
        raise AssertionError("workflow step must have one literal run block")
    release_id_binding = "          SELECTED_RELEASE_ID: ${{ needs.v2-prepare.outputs.release_id }}\n"
    if step.split(marker, 1)[0].count(release_id_binding) != 1:
        raise AssertionError("workflow step must bind SELECTED_RELEASE_ID to the selected route output")
    block = step.split(marker, 1)[1]
    lines = block.splitlines()
    if any(line and not line.startswith("          ") for line in lines):
        raise AssertionError("unexpected indentation in workflow run block")
    return "\n".join(line[10:] if line else "" for line in lines) + "\n"


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")


def write_jsonl(path, values):
    Path(path).write_text("".join(json.dumps(value, sort_keys=True) + "\n" for value in values), encoding="utf-8")


def supported_bash():
    candidates = []
    explicit = os.environ.get("BASH")
    if explicit:
        candidates.append(explicit)
    candidates.extend(("/opt/homebrew/bin/bash", shutil.which("bash")))
    visited = set()
    for candidate in candidates:
        if not candidate or candidate in visited:
            continue
        visited.add(candidate)
        try:
            version = subprocess.run([candidate, "--version"], capture_output=True, text=True, check=False)
        except OSError:
            continue
        match = re.search(r"GNU bash, version (\d+)", version.stdout)
        if version.returncode == 0 and match and int(match.group(1)) >= 4:
            return candidate
    raise unittest.SkipTest("the real provenance verifier requires GNU Bash 4 or newer")


GH_STUB = r'''#!/usr/bin/env python3
"""Synthetic gh attestation verifier. It validates fixture identity only."""
import json
import os
from pathlib import Path
import sys

args = sys.argv[1:]
if len(args) < 3 or args[:2] != ["attestation", "verify"]:
    raise SystemExit("unexpected synthetic gh invocation")
flags = {}
index = 2
while index < len(args):
    if args[index].startswith("--"):
        key = args[index]
        if key == "--deny-self-hosted-runners":
            flags[key] = True
            index += 1
        else:
            if index + 1 >= len(args):
                raise SystemExit("missing synthetic gh flag value")
            flags[key] = args[index + 1]
            index += 2
    else:
        index += 1
expected = {
    "--repo": os.environ["MOCK_REPOSITORY"],
    "--signer-workflow": os.environ["MOCK_SIGNER_WORKFLOW"],
    "--source-digest": os.environ["MOCK_SOURCE_SHA"],
    "--source-ref": os.environ["MOCK_SOURCE_REF"],
    "--format": "json",
    "--deny-self-hosted-runners": True,
}
if any(flags.get(key) != value for key, value in expected.items()):
    print("synthetic fixture rejects mismatched repository, signer, source, or verifier mode", file=sys.stderr)
    raise SystemExit(31)
bundle = Path(flags["--bundle"])
subject = Path(args[2])
if not bundle.is_file() or not subject.is_file():
    raise SystemExit("synthetic fixture input is missing")
with Path(os.environ["MOCK_GH_CALLS"]).open("a", encoding="utf-8") as calls:
    calls.write(json.dumps({"subject": str(subject), "flags": flags}, sort_keys=True) + "\n")
sys.stdout.write(Path(os.environ["MOCK_VERIFIED_JSON"]).read_text(encoding="utf-8"))
'''


AROS_STUB = r'''#!/usr/bin/env python3
"""Synthetic aros CLI with the exact family-v2 final-stage JSON envelopes."""
import hashlib
import json
import os
from pathlib import Path
import sys

args = sys.argv[1:]
mode = os.environ.get("FAKE_AROS_MODE", "success")
log = Path(os.environ["FAKE_AROS_CALLS"])
with log.open("a", encoding="utf-8") as calls:
    calls.write(json.dumps(args) + "\n")

def option(name):
    return args[args.index(name) + 1]

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def fail(message):
    print(message, file=sys.stderr)
    raise SystemExit(41)

def emit_over_limit():
    payload = b"x" * (1024 * 1024)
    try:
        for _ in range(9):
            sys.stdout.buffer.write(payload)
        sys.stdout.buffer.flush()
    except OSError:
        print("synthetic child exceeded its stdout file-size limit", file=sys.stderr)
        raise SystemExit(42)

def late_mutation(path, label):
    selected = Path(path)
    selected.write_bytes(selected.read_bytes() + f"\nSYNTHETIC LATE MUTATION: {label}\n".encode())

if args[:2] != ["toolchain", "producer"]:
    fail("unexpected synthetic native CLI command")
operation = args[2] if len(args) > 2 else ""
release = Path(option("--directory"))
summary = json.loads(Path(os.environ["FAKE_SUMMARY"]).read_text(encoding="utf-8"))
selection_path = Path(os.environ["FAKE_SELECTION"])
selection = json.loads(selection_path.read_text(encoding="utf-8"))
evidence_digests = json.loads(os.environ["FAKE_EVIDENCE_DIGESTS"])
subject = Path(option("--subject-manifest"))
subject_sha = option("--subject-manifest-sha256")
if digest(subject) != subject_sha:
    fail("synthetic CLI received a mismatched subject digest")
if option("--format") != "json" or option("--release-id") != os.environ["FAKE_RELEASE_ID"]:
    fail("synthetic CLI received an unexpected result format or release ID")

if operation == "index":
    if mode == "index-error":
        fail("synthetic native index failure")
    if (option("--release-format"), option("--stage")) != ("family-v2", "final"):
        fail("synthetic CLI received an unexpected final-index selection")
    if Path(option("--lane-inputs")).read_bytes() != b"{}\n":
        fail("synthetic CLI received unexpected lane inputs")
    if mode == "index-output":
        emit_over_limit()
    bundle = release / "toolchain-provenance.sigstore.json"
    names = ["toolchain-index-v2.json", "toolchain-provenance.sigstore.json",
             "toolchain-release-inputs-v2.json"]
    checksum_bytes = "".join(f"{digest(release / name)}  {name}\n" for name in names).encode()
    checksums = release / "SHA256SUMS"
    checksums.write_bytes(checksum_bytes)
    counts = summary["counts"]
    document = {
        "schema": "aros-toolchain-producer-stage-v2",
        "operation": "index",
        "release_format": "family-v2",
        "stage": "final",
        "release_id": option("--release-id"),
        "index": str(release / "toolchain-index-v2.json"),
        "index_sha256": digest(release / "toolchain-index-v2.json"),
        "subject_manifest": str(subject),
        "subject_manifest_sha256": subject_sha,
        "subject_manifest_size": subject.stat().st_size,
        "subject_count": counts["subject_count"],
        "inventory_count": counts["inventory_count"],
        "lane_count": counts["lane_count"],
        "sdk_count": counts["sdk_count"],
        "checksums": str(checksums),
        "checksums_sha256": digest(checksums),
        "provenance_sha256": digest(bundle),
        "provenance_size": bundle.stat().st_size,
    }
    if mode == "index-sha":
        document["index_sha256"] = "f" * 64
    elif mode == "index-count":
        document["lane_count"] += 1
    elif mode == "index-provenance-size":
        document["provenance_size"] += 1
    elif mode == "late-selection-index":
        late_mutation(selection_path, "selection")
    elif mode == "late-runtime-index":
        late_mutation(os.environ["FAKE_RUNTIME"], "runtime")
    print(json.dumps(document, sort_keys=True))
elif operation == "verify-release-evidence":
    if mode == "evidence-error":
        fail("synthetic native evidence readback failure")
    if option("--inputs-sha256") != os.environ["FAKE_INPUTS_SHA"]:
        fail("synthetic CLI received an unexpected inputs digest")
    if option("--index-sha256") != digest(release / "toolchain-index-v2.json"):
        fail("synthetic CLI received an unexpected index digest")
    if option("--selection-sha256") != digest(selection_path):
        fail("synthetic CLI received an unexpected selection digest")
    lane_ids = sorted(selection["lanes"])
    sdk_ids = sorted(selection["sdk_packages"])
    selected_generations = sorted(selection["sdk_generations"], key=lambda item: (item["sdk_id"], item["group_id"], item["target_profile"], item["host"]))
    generations = [{
        "sdk_id": generation["sdk_id"],
        "group_id": generation["group_id"],
        "target_profile": generation["target_profile"],
        "host": generation["host"],
        "generation_record_sha256": generation["record"]["sha256"],
        "compatibility_manifest_sha256": generation["compatibility"]["manifest_sha256"],
        "compatibility_receipt_sha256": evidence_digests["generation_compatibility_receipt"],
        "sdk_link_receipt_sha256": evidence_digests["sdk_link_receipt"],
    } for generation in selected_generations]
    checksums = release / "SHA256SUMS"
    bundle = release / "toolchain-provenance.sigstore.json"
    lanes = []
    for asset in lane_ids:
        selected_lane = selection["lanes"][asset]
        lanes.append({
            "asset": asset,
            "measurement_sha256": evidence_digests["compiler_measurement"],
            "build_result_sha256": evidence_digests["compiler_build_result"],
            "finished_receipt_sha256": evidence_digests["compiler_finished_receipt"],
            "comparison_sha256": selected_lane["comparison"]["sha256"],
            "compatibility_inputs_sha256": selected_lane["compatibility"]["inputs"]["sha256"],
            "compatibility_manifest_sha256": selected_lane["compatibility"]["manifest_sha256"],
            "compatibility_receipt_sha256": evidence_digests["compatibility_receipt"],
            "standalone": {"synthetic-target": {
                "c": {"sha256": evidence_digests["standalone_c"], "size": 256, "class": "elf32"},
                "cxx": {"sha256": evidence_digests["standalone_cxx"], "size": 512, "class": "elf32"},
            }},
        })
    sdks = []
    for sdk_id in sdk_ids:
        selected_sdk = selection["sdk_packages"][sdk_id]
        sdks.append({
            "sdk_id": sdk_id,
            "identity": {
                "sdk_id": sdk_id,
                "version": "1.0.0",
                "target": {"target_triple": "i686-unknown-linux-gnu", "abi": {}},
                "source": {
                    "commit": "a" * 40,
                    "git_tree": "b" * 40,
                    "content_sha256": "c" * 64,
                    "contract_sha256": "d" * 64,
                },
                "source_date_epoch": 1,
            },
            "tree_sha256": selected_sdk["tree_sha256"],
            "archive_sha256": selected_sdk["archive_sha256"],
            "archive_size": selected_sdk["archive_size"],
            "manifest_sha256": evidence_digests["sdk_manifest"],
            "manifest_size": 1024,
        })
    document = {
        "schema": "aros-toolchain-producer-stage-v2",
        "operation": "verify-release-evidence",
        "release_format": "family-v2",
        "assurance": "byte-consistency-only",
        "release_id": option("--release-id"),
        "inputs_sha256": option("--inputs-sha256"),
        "index_sha256": option("--index-sha256"),
        "selection_sha256": option("--selection-sha256"),
        "subject_manifest_sha256": subject_sha,
        "checksums_sha256": digest(checksums),
        "provenance_sha256": digest(bundle),
        "lane_count": len(lane_ids),
        "build_count": len(lane_ids) * 2,
        "lanes": lanes,
        "sdk_generation_count": len(generations),
        "sdk_generations": generations,
        "sdk_count": len(sdk_ids),
        "sdks": sdks,
    }
    if mode == "evidence-index-sha":
        document["index_sha256"] = "f" * 64
    elif mode == "evidence-selection-sha":
        document["selection_sha256"] = "e" * 64
    elif mode == "evidence-count":
        document["build_count"] += 1
    elif mode == "evidence-sdk-count":
        document["sdk_generation_count"] += 1
    elif mode == "evidence-sdk-tuples":
        document["sdk_generations"][0]["host"] = "linux-aarch64"
    elif mode == "evidence-generation-record-sha":
        document["sdk_generations"][0]["generation_record_sha256"] = "f" * 64
    elif mode == "evidence-comparison-sha":
        document["lanes"][0]["comparison_sha256"] = "f" * 64
    elif mode == "evidence-output":
        emit_over_limit()
    elif mode == "late-summary-evidence":
        late_mutation(os.environ["FAKE_SUMMARY"], "summary")
    elif mode == "late-subject-evidence":
        late_mutation(subject, "subject manifest")
    elif mode == "late-bundle-evidence":
        late_mutation(bundle, "staged bundle")
    print(json.dumps(document, sort_keys=True))
else:
    fail("unexpected synthetic native CLI operation")
'''


class FinalCandidateWorkflow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.shell = final_candidate_shell()
        cls.bash = supported_bash()
        gtimeout = shutil.which("gtimeout") or shutil.which("timeout")
        if not gtimeout:
            raise unittest.SkipTest("GNU timeout or gtimeout is required by the extracted workflow")
        cls.gtimeout = gtimeout

    def fixture(self):
        temporary = tempfile.TemporaryDirectory(prefix="final-candidate-workflow-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        candidate = root / "release-candidate"
        release = candidate / "release"
        runtime = root / "diagnostic-runtime" / "bin"
        tools = root / "fixture-bin"
        for directory in (release, runtime, tools):
            directory.mkdir(parents=True, exist_ok=True)

        (release / "toolchain-index-v2.json").write_text('{"schema":"synthetic-index-v2"}\n', encoding="utf-8")
        (release / "toolchain-release-inputs-v2.json").write_text('{"schema":"synthetic-inputs-v2"}\n', encoding="utf-8")
        (candidate / "lane-inputs.json").write_bytes(b"{}\n")
        subject_lines = []
        for name in ("toolchain-index-v2.json", "toolchain-release-inputs-v2.json"):
            subject_lines.append(f"{sha256(release / name)}  {name}\n")
        subject_path = candidate / "subject-manifest.json"
        subject_path.write_text("".join(subject_lines), encoding="utf-8")

        summary = {
            "counts": {"subject_count": 2, "inventory_count": 3, "lane_count": 1, "sdk_count": 1},
            "outputs": {"subject_manifest": {"size": subject_path.stat().st_size}},
        }
        summary_path = root / "release-candidate-summary.json"
        write_json(summary_path, summary)
        def selected_file(name, digest):
            return {"path": str(root / name), "sha256": digest}

        compiler_compatibility = {
            "directory": str(root / "synthetic-compiler-compatibility"),
            "inputs": selected_file("synthetic-compiler-compatibility-inputs.json", DIGESTS["compatibility_inputs"]),
            "manifest_sha256": DIGESTS["compatibility_manifest"],
            "native_sdk_required": True,
        }
        lane = {
            "build_environment": {},
            "required_paths": [],
            "builds": [
                {
                    "package_dir": str(root / f"synthetic-compiler-build-{number}"),
                    "measurement": selected_file(f"synthetic-compiler-measurement-{number}.json", DIGESTS["compiler_measurement"]),
                    "executor": {"contract_sha256": DIGESTS["compiler_build_result"],
                                 "binary_sha256": DIGESTS["compiler_finished_receipt"]},
                }
                for number in (1, 2)
            ],
            "comparison": selected_file("synthetic-compiler-comparison.json", DIGESTS["comparison"]),
            "compatibility": compiler_compatibility,
        }
        generation_compatibility = {
            "directory": str(root / "synthetic-sdk-generation-compatibility"),
            "inputs": selected_file("synthetic-sdk-generation-compatibility-inputs.json",
                                     DIGESTS["generation_compatibility_inputs"]),
            "manifest_sha256": DIGESTS["generation_compatibility_manifest"],
            "native_sdk_required": True,
        }
        selected_generation = {
            **GENERATION,
            "package_dir": str(root / "synthetic-sdk-generation-package"),
            "record": selected_file("synthetic-sdk-generation-record.json", DIGESTS["generation_record"]),
            "compatibility": generation_compatibility,
        }
        selection = {
            "schema": "aros-toolchain-release-evidence-selection-v2",
            "lanes": {LANE_ASSET: lane},
            "sdk_packages": {SDK_ID: {
                "tree_sha256": DIGESTS["sdk_tree"],
                "archive_sha256": DIGESTS["sdk_archive"],
                "archive_size": 4096,
            }},
            "sdk_generations": [selected_generation],
        }
        selection_path = root / "native-release-evidence-selection.json"
        write_json(selection_path, selection)
        runtime_path = runtime / "aros"
        runtime_path.write_text(AROS_STUB, encoding="utf-8")
        runtime_path.chmod(0o700)

        bundle = root / "synthetic-provenance.bundle"
        bundle.write_text(json.dumps({"fixture_label": "SYNTHETIC ONLY; NOT ACTUAL SIGNING"}) + "\n", encoding="utf-8")
        signed_subjects = []
        for line in subject_path.read_text(encoding="utf-8").splitlines():
            digest, name = line.split("  ", 1)
            signed_subjects.append({"name": name, "digest": {"sha256": digest}})
        verified = [{
            "fixture_label": "SYNTHETIC VERIFIED CERTIFICATE AND STATEMENT; NOT ACTUAL SIGNING",
            "verificationResult": {
                "statement": {"subject": signed_subjects},
                "signature": {"certificate": {"runInvocationURI":
                    f"https://github.com/{REPOSITORY}/actions/runs/{RUN_ID}/attempts/{RUN_ATTEMPT}"}},
            },
        }]
        verified_path = root / "synthetic-gh-verified.json"
        write_json(verified_path, verified)

        (tools / "gh").write_text(GH_STUB, encoding="utf-8")
        (tools / "gh").chmod(0o700)
        (tools / "timeout").write_text(f"#!/bin/sh\nexec {self.gtimeout} \"$@\"\n", encoding="utf-8")
        (tools / "timeout").chmod(0o700)

        gh_calls = root / "synthetic-gh-calls.jsonl"
        native_calls = root / "synthetic-aros-calls.jsonl"
        env = {
            **os.environ,
            "PATH": str(tools) + os.pathsep + os.environ.get("PATH", ""),
            "RUNNER_TEMP": str(root),
            "GITHUB_WORKSPACE": str(ROOT),
            "GITHUB_REPOSITORY": REPOSITORY,
            "GITHUB_SHA": SOURCE_SHA,
            "GITHUB_REF": SOURCE_REF,
            "GITHUB_RUN_ID": RUN_ID,
            "GITHUB_RUN_ATTEMPT": RUN_ATTEMPT,
            "GH_TOKEN": "synthetic-fixture-token",
            "PROVENANCE_BUNDLE": str(bundle),
            "EXPECTED_INDEX_SHA": sha256(release / "toolchain-index-v2.json"),
            "EXPECTED_SUBJECT_SHA": sha256(subject_path),
            "EXPECTED_SELECTION_SHA": sha256(selection_path),
            "EXPECTED_SUMMARY_SHA": sha256(summary_path),
            "EXPECTED_INPUTS_SHA": sha256(release / "toolchain-release-inputs-v2.json"),
            "EXPECTED_RUNTIME_SHA": sha256(runtime_path),
            "MOCK_REPOSITORY": REPOSITORY,
            "MOCK_SIGNER_WORKFLOW": SIGNER_WORKFLOW,
            "MOCK_SOURCE_SHA": SOURCE_SHA,
            "MOCK_SOURCE_REF": SOURCE_REF,
            "MOCK_VERIFIED_JSON": str(verified_path),
            "MOCK_GH_CALLS": str(gh_calls),
            "FAKE_AROS_CALLS": str(native_calls),
            "FAKE_AROS_MODE": "success",
            "FAKE_SUMMARY": str(summary_path),
            "FAKE_SELECTION": str(selection_path),
            "FAKE_RUNTIME": str(runtime_path),
            "FAKE_SUBJECT": str(subject_path),
            "FAKE_EVIDENCE_DIGESTS": json.dumps(DIGESTS, sort_keys=True),
            "FAKE_RELEASE_ID": RELEASE_ID,
            "SELECTED_RELEASE_ID": RELEASE_ID,
            "FAKE_INPUTS_SHA": sha256(release / "toolchain-release-inputs-v2.json"),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        return {
            "root": root,
            "candidate": candidate,
            "release": release,
            "runtime": runtime_path,
            "subject": subject_path,
            "summary": summary_path,
            "selection": selection_path,
            "bundle": bundle,
            "verified": verified_path,
            "gh_calls": gh_calls,
            "native_calls": native_calls,
            "env": env,
        }

    def run_shell(self, fixture, *, shell=None, env=None):
        return subprocess.run(
            [self.bash, "-c", self.shell if shell is None else shell],
            cwd=ROOT,
            env={**fixture["env"], **(env or {})},
            capture_output=True,
            text=True,
            check=False,
        )

    @staticmethod
    def lines(path):
        if not Path(path).exists():
            return []
        return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines()]

    def assert_no_native_cli(self, fixture):
        self.assertEqual(self.lines(fixture["native_calls"]), [])
        self.assertFalse((fixture["root"] / "final-combined-index.json").exists())
        self.assertFalse((fixture["root"] / "final-combined-evidence.json").exists())

    def test_selected_route_release_id_must_match_the_native_candidate(self):
        fixture = self.fixture()
        completed = self.run_shell(fixture, env={"SELECTED_RELEASE_ID": "v99.0.0"})
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual([call[2] for call in self.lines(fixture["native_calls"])], ["index"])
        self.assertFalse((fixture["root"] / "final-combined-evidence.json").exists())

    def test_actual_shell_verifies_synthetic_provenance_then_both_native_stages(self):
        fixture = self.fixture()
        completed = self.run_shell(fixture)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(len(self.lines(fixture["gh_calls"])), 2)
        native_calls = self.lines(fixture["native_calls"])
        self.assertEqual([call[2] for call in native_calls], ["index", "verify-release-evidence"])

        release = fixture["release"]
        index = json.loads((fixture["root"] / "final-combined-index.json").read_text(encoding="utf-8"))
        self.assertEqual(set(index), {
            "schema", "operation", "release_format", "stage", "release_id", "index",
            "index_sha256", "subject_manifest", "subject_manifest_sha256", "subject_manifest_size",
            "subject_count", "inventory_count", "lane_count", "sdk_count", "checksums",
            "checksums_sha256", "provenance_sha256", "provenance_size",
        })
        self.assertEqual(index["schema"], "aros-toolchain-producer-stage-v2")
        self.assertEqual(index["operation"], "index")
        self.assertEqual(index["release_format"], "family-v2")
        self.assertEqual(index["stage"], "final")
        self.assertEqual(index["release_id"], RELEASE_ID)
        self.assertEqual(index["index_sha256"], fixture["env"]["EXPECTED_INDEX_SHA"])
        self.assertEqual(index["subject_manifest_sha256"], fixture["env"]["EXPECTED_SUBJECT_SHA"])
        self.assertEqual(index["subject_count"], 2)
        self.assertEqual(index["inventory_count"], 3)
        self.assertEqual(index["lane_count"], 1)
        self.assertEqual(index["sdk_count"], 1)
        self.assertEqual(index["checksums_sha256"], sha256(release / "SHA256SUMS"))
        self.assertEqual(index["provenance_sha256"], sha256(release / "toolchain-provenance.sigstore.json"))
        self.assertEqual(index["provenance_size"], (release / "toolchain-provenance.sigstore.json").stat().st_size)

        evidence = json.loads((fixture["root"] / "final-combined-evidence.json").read_text(encoding="utf-8"))
        self.assertEqual(set(evidence), {
            "schema", "operation", "release_format", "assurance", "release_id", "inputs_sha256",
            "index_sha256", "selection_sha256", "subject_manifest_sha256", "checksums_sha256",
            "provenance_sha256", "lane_count", "build_count", "lanes", "sdk_generation_count",
            "sdk_generations", "sdk_count", "sdks",
        })
        self.assertEqual(evidence["operation"], "verify-release-evidence")
        self.assertEqual(evidence["assurance"], "byte-consistency-only")
        self.assertEqual(evidence["inputs_sha256"], fixture["env"]["EXPECTED_INPUTS_SHA"])
        self.assertEqual(evidence["index_sha256"], fixture["env"]["EXPECTED_INDEX_SHA"])
        self.assertEqual(evidence["selection_sha256"], fixture["env"]["EXPECTED_SELECTION_SHA"])
        self.assertEqual(evidence["lane_count"], 1)
        self.assertEqual(evidence["build_count"], 2)
        self.assertEqual([lane["asset"] for lane in evidence["lanes"]], [LANE_ASSET])
        self.assertEqual(evidence["sdk_count"], 1)
        self.assertEqual(set(evidence["lanes"][0]), {
            "asset", "measurement_sha256", "build_result_sha256", "finished_receipt_sha256",
            "comparison_sha256", "compatibility_inputs_sha256", "compatibility_manifest_sha256",
            "compatibility_receipt_sha256", "standalone",
        })
        self.assertEqual(evidence["lanes"][0]["comparison_sha256"], DIGESTS["comparison"])
        self.assertEqual(evidence["lanes"][0]["compatibility_inputs_sha256"], DIGESTS["compatibility_inputs"])
        self.assertEqual(evidence["lanes"][0]["compatibility_manifest_sha256"], DIGESTS["compatibility_manifest"])
        self.assertEqual(set(evidence["sdks"][0]), {
            "sdk_id", "identity", "tree_sha256", "archive_sha256", "archive_size",
            "manifest_sha256", "manifest_size",
        })
        self.assertEqual(evidence["sdks"][0]["tree_sha256"], DIGESTS["sdk_tree"])
        self.assertEqual(evidence["sdks"][0]["archive_sha256"], DIGESTS["sdk_archive"])
        self.assertEqual(evidence["sdks"][0]["archive_size"], 4096)
        self.assertEqual(evidence["sdk_generation_count"], 1)
        self.assertEqual(set(evidence["sdk_generations"][0]), {
            "sdk_id", "group_id", "target_profile", "host", "generation_record_sha256",
            "compatibility_manifest_sha256", "compatibility_receipt_sha256", "sdk_link_receipt_sha256",
        })
        self.assertEqual(
            [evidence["sdk_generations"][0][key] for key in ("sdk_id", "group_id", "target_profile", "host")],
            [GENERATION[key] for key in ("sdk_id", "group_id", "target_profile", "host")],
        )
        self.assertEqual(evidence["sdk_generations"][0]["generation_record_sha256"], DIGESTS["generation_record"])
        self.assertEqual(evidence["sdk_generations"][0]["compatibility_manifest_sha256"],
                         DIGESTS["generation_compatibility_manifest"])
        self.assertEqual((fixture["release"] / "toolchain-provenance.sigstore.json").read_bytes(),
                         fixture["bundle"].read_bytes())

    def test_wrong_held_hash_stops_before_verifier_and_native_cli(self):
        fixture = self.fixture()
        completed = self.run_shell(fixture, env={"EXPECTED_INDEX_SHA": "f" * 64})
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(self.lines(fixture["gh_calls"]), [])
        self.assert_no_native_cli(fixture)

    def test_signer_ref_and_run_attempt_must_match_the_synthetic_certificate(self):
        signer_path = "/.github/workflows/toolchain-release.yml"
        self.assertEqual(self.shell.count(signer_path), 2)
        wrong_signer_shell = self.shell.replace(signer_path, "/.github/workflows/other.yml")
        cases = (
            ("signer", wrong_signer_shell, {}),
            ("ref", None, {"GITHUB_REF": "refs/heads/other"}),
            ("run-attempt", None, {"GITHUB_RUN_ATTEMPT": "3"}),
        )
        for name, shell, env in cases:
            with self.subTest(identity=name):
                fixture = self.fixture()
                completed = self.run_shell(fixture, shell=shell, env=env)
                self.assertNotEqual(completed.returncode, 0)
                self.assert_no_native_cli(fixture)
                self.assertFalse((fixture["root"] / "verified-combined-provenance.json").exists())

    def test_source_repository_mismatch_is_rejected_by_the_verifier_fixture(self):
        fixture = self.fixture()
        completed = self.run_shell(fixture, env={"GITHUB_REPOSITORY": "attacker/other"})
        self.assertNotEqual(completed.returncode, 0)
        self.assert_no_native_cli(fixture)

    def test_attested_subject_set_must_equal_the_manifest(self):
        fixture = self.fixture()
        verified = json.loads(fixture["verified"].read_text(encoding="utf-8"))
        verified[0]["verificationResult"]["statement"]["subject"].append(
            {"name": "unlisted.bin", "digest": {"sha256": "b" * 64}}
        )
        write_json(fixture["verified"], verified)
        completed = self.run_shell(fixture)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("signed provenance subjects do not exactly match", completed.stderr)
        self.assert_no_native_cli(fixture)

    def test_stale_summary_runtime_and_selection_digests_stop_before_verification(self):
        for selected in ("summary", "runtime", "selection"):
            with self.subTest(file=selected):
                fixture = self.fixture()
                path = fixture[selected]
                path.write_bytes(path.read_bytes() + b"stale\n")
                completed = self.run_shell(fixture)
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(self.lines(fixture["gh_calls"]), [])
                self.assert_no_native_cli(fixture)

    def test_symlink_bundle_is_rejected_before_provenance_verification(self):
        fixture = self.fixture()
        alias = fixture["root"] / "bundle-alias"
        alias.symlink_to(fixture["bundle"])
        completed = self.run_shell(fixture, env={"PROVENANCE_BUNDLE": str(alias)})
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(self.lines(fixture["gh_calls"]), [])
        self.assert_no_native_cli(fixture)

    def test_oversize_bundle_is_rejected_before_any_gh_invocation(self):
        fixture = self.fixture()
        fixture["bundle"].write_bytes(b"SYNTHETIC NOT ACTUAL SIGNING\n" + b"x" * (16 * 1024 * 1024))
        completed = self.run_shell(fixture)
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(self.lines(fixture["gh_calls"]), [])
        self.assertFalse((fixture["root"] / "verified-combined-provenance.json").exists())
        self.assertFalse((fixture["release"] / "toolchain-provenance.sigstore.json").exists())
        self.assert_no_native_cli(fixture)

    def test_existing_verifier_output_is_preserved(self):
        fixture = self.fixture()
        output = fixture["root"] / "verified-combined-provenance.json"
        output.write_bytes(b"preserve existing verifier output\n")
        completed = self.run_shell(fixture)
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(output.read_bytes(), b"preserve existing verifier output\n")
        self.assertEqual(self.lines(fixture["gh_calls"]), [])
        self.assert_no_native_cli(fixture)

    def test_existing_staged_bundle_target_is_preserved(self):
        fixture = self.fixture()
        target = fixture["release"] / "toolchain-provenance.sigstore.json"
        target.write_bytes(b"preserve existing staged bundle\n")
        completed = self.run_shell(fixture)
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(target.read_bytes(), b"preserve existing staged bundle\n")
        self.assertEqual(len(self.lines(fixture["gh_calls"])), 1)
        self.assert_no_native_cli(fixture)

    def test_existing_final_index_output_is_preserved(self):
        fixture = self.fixture()
        target = fixture["root"] / "final-combined-index.json"
        target.write_bytes(b"preserve existing final index\n")
        completed = self.run_shell(fixture)
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(target.read_bytes(), b"preserve existing final index\n")
        self.assertEqual(len(self.lines(fixture["gh_calls"])), 2)
        self.assertEqual(self.lines(fixture["native_calls"]), [])

    def test_native_cli_errors_stop_the_shell(self):
        for mode in ("index-error", "evidence-error"):
            with self.subTest(native_stage=mode):
                fixture = self.fixture()
                completed = self.run_shell(fixture, env={"FAKE_AROS_MODE": mode})
                self.assertNotEqual(completed.returncode, 0)
                calls = self.lines(fixture["native_calls"])
                if mode == "index-error":
                    self.assertEqual([call[2] for call in calls], ["index"])
                    self.assertFalse((fixture["root"] / "final-combined-evidence.json").exists())
                else:
                    self.assertEqual([call[2] for call in calls], ["index", "verify-release-evidence"])

    def test_native_child_stdout_is_limited_to_eight_mebibytes(self):
        for mode, output_name, expected_calls in (
            ("index-output", "final-combined-index.json", ["index"]),
            ("evidence-output", "final-combined-evidence.json", ["index", "verify-release-evidence"]),
        ):
            with self.subTest(native_stage=mode):
                fixture = self.fixture()
                completed = self.run_shell(fixture, env={"FAKE_AROS_MODE": mode})
                output = fixture["root"] / output_name
                self.assertNotEqual(completed.returncode, 0, completed.stderr)
                self.assertTrue(output.is_file())
                self.assertGreater(output.stat().st_size, 0)
                self.assertLessEqual(output.stat().st_size, 8 * 1024 * 1024)
                self.assertEqual([call[2] for call in self.lines(fixture["native_calls"])], expected_calls)
                with self.assertRaises(json.JSONDecodeError):
                    json.loads(output.read_text(encoding="utf-8"))

    def test_late_child_mutations_trip_the_workflow_rechecks(self):
        cases = (
            ("late-selection-index", "selection", ["index"]),
            ("late-runtime-index", "runtime", ["index"]),
            ("late-summary-evidence", "summary", ["index", "verify-release-evidence"]),
            ("late-subject-evidence", "subject", ["index", "verify-release-evidence"]),
            ("late-bundle-evidence", "bundle", ["index", "verify-release-evidence"]),
        )
        for mode, selected, expected_calls in cases:
            with self.subTest(late_mutation=selected):
                fixture = self.fixture()
                selected_path = {
                    "selection": fixture["selection"],
                    "runtime": fixture["runtime"],
                    "summary": fixture["summary"],
                    "subject": fixture["subject"],
                    "bundle": fixture["release"] / "toolchain-provenance.sigstore.json",
                }[selected]
                initial = selected_path.read_bytes() if selected != "bundle" else fixture["bundle"].read_bytes()
                completed = self.run_shell(fixture, env={"FAKE_AROS_MODE": mode})
                self.assertNotEqual(completed.returncode, 0, completed.stderr)
                self.assertNotEqual(selected_path.stat().st_size, 0)
                self.assertNotEqual(selected_path.read_bytes(), initial)
                self.assertEqual([call[2] for call in self.lines(fixture["native_calls"])], expected_calls)

    def test_index_envelope_hash_and_counts_are_checked(self):
        for mode in ("index-sha", "index-count", "index-provenance-size"):
            with self.subTest(index_envelope=mode):
                fixture = self.fixture()
                completed = self.run_shell(fixture, env={"FAKE_AROS_MODE": mode})
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual([call[2] for call in self.lines(fixture["native_calls"])],
                                 ["index", "verify-release-evidence"])

    def test_evidence_envelope_hashes_counts_and_sdk_tuples_are_checked(self):
        for mode in ("evidence-index-sha", "evidence-selection-sha", "evidence-count",
                     "evidence-sdk-count", "evidence-sdk-tuples",
                     "evidence-generation-record-sha", "evidence-comparison-sha"):
            with self.subTest(evidence_envelope=mode):
                fixture = self.fixture()
                completed = self.run_shell(fixture, env={"FAKE_AROS_MODE": mode})
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual([call[2] for call in self.lines(fixture["native_calls"])],
                                 ["index", "verify-release-evidence"])

    def test_repeated_run_preserves_all_first_run_outputs(self):
        fixture = self.fixture()
        first = self.run_shell(fixture)
        self.assertEqual(first.returncode, 0, first.stderr)
        tracked = [
            fixture["root"] / "verified-combined-provenance.json",
            fixture["root"] / "verified-staged-combined-provenance.json",
            fixture["root"] / "final-combined-index.json",
            fixture["root"] / "final-combined-evidence.json",
            fixture["release"] / "toolchain-provenance.sigstore.json",
            fixture["release"] / "SHA256SUMS",
        ]
        before = {path: path.read_bytes() for path in tracked}
        gh_count = len(self.lines(fixture["gh_calls"]))
        native_count = len(self.lines(fixture["native_calls"]))
        second = self.run_shell(fixture)
        self.assertNotEqual(second.returncode, 0)
        self.assertEqual({path: path.read_bytes() for path in tracked}, before)
        self.assertEqual(len(self.lines(fixture["gh_calls"])), gh_count)
        self.assertEqual(len(self.lines(fixture["native_calls"])), native_count)


if __name__ == "__main__":
    unittest.main()
