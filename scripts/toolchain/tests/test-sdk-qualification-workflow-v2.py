"""Offline contracts for the manually dispatched SDK workflow (M4-A1)."""

import importlib.util
from pathlib import Path
from textwrap import dedent
import unittest

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("compiler_workflow_contracts", HERE / "test-compiler-qualification-workflow-v2.py")
contracts = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(contracts)
WORKFLOW = contracts.ROOT / ".github/workflows/toolchain-sdk-v2.yml"


class SdkQualificationWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = WORKFLOW.read_text()
        cls.manifest = contracts.job_text(cls.text, "manifest")
        cls.inputs = contracts.job_text(cls.text, "inputs")
        cls.admit = contracts.job_text(cls.text, "admit")
        cls.sdk = contracts.job_text(cls.text, "v2-sdk")
        cls.readback = contracts.job_text(cls.text, "v2-readback")

    def test_dispatch_runs_only_the_sdk_qualification_graph(self):
        jobs = contracts.top_level_jobs(self.text)
        self.assertEqual(jobs, ["manifest", "inputs", "admit", "v2-sdk", "v2-readback"])
        trigger = self.text.split("\non:\n")[1].split("\npermissions:")[0]
        self.assertIn("  workflow_dispatch:\n    inputs:\n      compiler_run_id:", trigger)
        self.assertRegex(trigger, r"(?s)compiler_run_id:.*?required: true.*?type: string")
        self.assertNotRegex(trigger, r"(?m)^  (?!workflow_dispatch:)[\w-]+:")
        self.assertNotIn("contents: write", self.text)
        self.assertNotIn("uses: ./.github/actions/build-native-lane-v2", self.text)
        contracts.check_pinned(self.text)

    def test_source_is_verified_before_inputs_and_sdk_fanout(self):
        self.assertIn("id-token: write", self.manifest)
        self.assertIn("scripts/toolchain/read-compiler-run-manifest-v2.py", self.manifest)
        self.assertIn('--compiler-run-id "$COMPILER_RUN_ID" --compiler-run-attempt "$COMPILER_RUN_ATTEMPT"', self.manifest)
        self.assertIn("--job-name 'Verify compiler manifest' --require-fresh", self.manifest)
        self.assertIn("    needs: manifest\n", self.inputs)
        self.assertIn("uses: ./.github/workflows/toolchain-v2-inputs.yml", self.inputs)
        self.assertIn("mode: qualify-v2-full", self.inputs)
        self.assertIn("needs: [manifest, inputs]", self.admit)
        self.assertIn("needs.manifest.outputs.summary_sha256", self.admit)
        self.assertIn("scripts/toolchain/admit-sdk-compiler-manifest-v2.py", self.admit)
        self.assertIn("needs: [inputs, admit]", self.sdk)
        self.assertIn("fromJSON(needs.inputs.outputs.sdk_lane_matrix)", self.sdk)

    def test_reuse_predictions_precede_full_build_and_final_observation_is_signed(self):
        self.assertIn("read-sdk-reuse-baseline.py", self.admit)
        self.assertIn("sdk-reuse-observation.py predict", self.admit)
        self.assertIn('needs: [inputs, admit]', self.sdk)
        self.assertNotIn('reuse-candidate', self.sdk)
        self.assertIn("if: matrix.host == 'linux-x86_64'", self.sdk)
        self.assertIn("sdk-reuse-observation.py capture", self.sdk)
        self.assertIn("pattern: sdk-surface-*-", self.readback)
        index = self.readback.index("--stage final")
        record = self.readback.index("sdk-reuse-observation.py observe")
        sign = self.readback.index("id: reuse-signature")
        self.assertLess(index, record)
        self.assertLess(record, sign)
        self.assertIn('subject-path: ${{ runner.temp }}/sdk-reuse-observation/sdk-reuse-observation.json',
                      self.readback[sign:])
        self.assertIn('name: sdk-reuse-${{ github.run_id }}-${{ github.run_attempt }}', self.readback[sign:])

    def test_sdk_lane_reads_the_admitted_compiler_attempt(self):
        self.assertIn("needs.admit.outputs.summary_sha256", self.sdk)
        self.assertIn("jq -ceS '.context'", self.sdk)
        self.assertIn("'.context.run_id'", self.sdk)
        self.assertIn("'.context.run_attempt'", self.sdk)
        for pattern in ("native-v2-", "native-v2-proof-"):
            self.assertIn(f'{pattern}$lane_sha-$compiler_run-$compiler_attempt"', self.sdk)
        self.assertIn('--compiler-manifest "$manifest" --compiler-manifest-sha256 "$SUMMARY_SHA256"', self.sdk)
        self.assertIn("--source-workflow .github/workflows/toolchain-compilers-v2.yml", self.sdk)
        self.assertNotIn("--same-attempt", self.sdk)
        self.assertIn("uses: ./.github/actions/retain-sdk-owner-payload-v2", self.sdk)
        self.assertIn("workflow: .github/workflows/toolchain-sdk-v2.yml", self.sdk)
        self.assertIn("fromJSON(needs.inputs.outputs.cache_archives)[matrix.host]", self.sdk)

    def test_final_candidate_depends_on_every_sdk_lane_and_is_attested(self):
        self.assertIn("v2-sdk", next(line for line in self.readback.splitlines() if "needs:" in line))
        self.assertIn("needs.admit.outputs.summary_sha256", self.readback)
        self.assertIn("uses: actions/attest-build-provenance@", self.readback)
        self.assertIn("subject-checksums:", self.readback)

    def test_final_readback_joins_both_contexts_before_signing(self):
        compiler, sdk = self.readback.split("bash scripts/toolchain/collect-sdk-owners-v2.sh", 1)
        compiler = compiler.split("bash scripts/toolchain/collect-compiler-owners-v2.sh", 1)[1]
        sdk = sdk.split("      - id: candidate", 1)[0]
        self.assertIn('--source-context "$COMPILER_CONTEXT"', compiler)
        self.assertNotIn("--same-attempt", compiler)
        self.assertIn('--source-context "$SDK_CONTEXT"', sdk)
        self.assertIn("--same-attempt", sdk)
        self.assertEqual(self.readback.count('--compiler-source-context "$COMPILER_CONTEXT"'), 2)
        self.assertLess(self.readback.index("verify-compiler-manifest-receipts-v2.py"),
                        self.readback.index("uses: actions/attest-build-provenance@"))

    def test_sdk_final_stage_checks_its_own_attestation_and_native_evidence(self):
        spec = importlib.util.spec_from_file_location("candidate_fixture", HERE / "test-final-candidate-workflow-v2.py")
        fixture_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixture_module)
        case = fixture_module.FinalCandidateWorkflow()
        case.setUpClass()
        self.addCleanup(case.doCleanups)
        fixture = case.fixture()
        step = self.readback.split("      - name: " + fixture_module.STEP_NAME + "\n", 1)[1]
        step = step.split("      - name:", 1)[0]
        env, shell = step.split("        run: |\n", 1)
        self.assertIn("SELECTED_RELEASE_ID: ${{ needs.inputs.outputs.release_id }}", env)
        signer = fixture_module.REPOSITORY + "/.github/workflows/toolchain-sdk-v2.yml"
        result = case.run_shell(fixture, shell=dedent(shell), env={"MOCK_SIGNER_WORKFLOW": signer})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([call[2] for call in case.lines(fixture["native_calls"])],
                         ["index", "verify-release-evidence"])


if __name__ == "__main__":
    unittest.main()
