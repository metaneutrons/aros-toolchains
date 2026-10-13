#!/usr/bin/env python3
"""Probe SDK owner-action wiring with synthetic staging, never provider proof."""

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
ACTION = ROOT / ".github/actions/retain-sdk-owner-payload-v2/action.yml"


def stages(text: str) -> list[str]:
    return re.split(r"(?m)^    - ", text)[1:]


def validate(text: str) -> None:
    parts = stages(text)
    if len(parts) != 6:
        raise ValueError("owner transport must retain six ordered stages")
    needles = (
        ("id: stage", "stage-sdk-owner-payload-v2.py", "ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "SDK_IDS",
         "SDK_OWNER_ROLE: ${{ inputs.owner-role }}", 'case "$SDK_OWNER_ROLE" in diagnostic|sdk) ;; *) exit 1;; esac'),
        ("id: payload", "path: ${{ inputs.root }}/payload/", "if-no-files-found: error", "include-hidden-files: true"),
        ('artifact-origin.py" record', "steps.payload.outputs.artifact-id", "steps.payload.outputs.artifact-digest",
         "SDK_OWNER_ROLE: ${{ inputs.owner-role }}", '--role "$SDK_OWNER_ROLE"',
         '--copy none', '--payload-dir "$SDK_ROOT/payload"', '--output "$SDK_ROOT/proof/origin.json"'),
        ("id: signature", "actions/attest-build-provenance@", "subject-path: ${{ inputs.root }}/proof/origin.json"),
        ("steps.signature.outputs.bundle-path", '"$SDK_ROOT/proof/origin.sigstore.json"'),
        ("id: proof", "path: ${{ inputs.root }}/proof/", "if-no-files-found: error", "include-hidden-files: true"),
    )
    for part, required in zip(parts, needles, strict=True):
        if not all(needle in part for needle in required):
            raise ValueError("SDK owner stage lost a required transport boundary")
        if "run: |" in part and "${{ inputs." in part.split("run: |", 1)[1]:
            raise ValueError("caller selector interpolated directly into shell")
    owner_role = re.search(r"(?ms)^  owner-role:\n(?P<block>.*?)(?=^  [a-z][a-z-]*:\n|^outputs:)", text)
    if owner_role is None or not all(needle in owner_role.group("block") for needle in (
            "required: false", "default: diagnostic")):
        raise ValueError("owner role must remain optional and default to diagnostic")
    if "continue-on-error" in text or re.search(r"(?m)^\s+(?:-\s+)?if:", text):
        raise ValueError("required owner gates must not be skipped or suppressed")
    used = re.findall(r"(?m)^\s+uses: (\S+)", text)
    if len(used) != 3 or any(re.fullmatch(r"[^@]+@[0-9a-f]{40}", value) is None for value in used):
        raise ValueError("all transport and attestation actions require exact pins")
    for kind in ("payload", "proof"):
        for value in ("artifact-id", "artifact-digest"):
            field = "id" if value == "artifact-id" else "sha256"
            output = f"  {kind}-{field}:\n"
            outputs = text.split("\nruns:\n", 1)[0]
            block = re.split(r"\n  [^ ]", outputs.split(output, 1)[1], maxsplit=1)[0] if output in outputs else ""
            if f"value: ${{{{ steps.{kind}.outputs.{value} }}}}" not in block:
                raise ValueError("original upload identity was not retained")


def stage_script() -> str:
    text = stages(ACTION.read_text())[0].split("      run: |\n", 1)[1]
    return "\n".join(line[8:] for line in text.splitlines()) + "\n"


class OwnerContractTests(unittest.TestCase):
    def test_exact_success_only_owning_job_protocol(self):
        validate(ACTION.read_text())

    def test_rejects_missing_selectors_shadow_payload_and_suppressed_gates(self):
        valid = ACTION.read_text()
        for needle, replacement in (
            ('--role "$SDK_OWNER_ROLE"', "--role diagnostic"),
            ("steps.payload.outputs.artifact-id", "steps.other.outputs.artifact-id"),
            ("steps.payload.outputs.artifact-digest", "steps.other.outputs.artifact-digest"),
            ("path: ${{ inputs.root }}/payload/", "path: ${{ inputs.root }}/other/"),
            ("subject-path: ${{ inputs.root }}/proof/origin.json", "subject-path: other.json"),
            ("if-no-files-found: error", "if-no-files-found: warn"),
            ("    - id: payload", "    - if: always()\n      id: payload"),
        ):
            with self.subTest(needle=needle), self.assertRaises(ValueError):
                validate(valid.replace(needle, replacement, 1))

    def test_rejects_invalid_owner_role_choice_and_disconnected_default(self):
        valid = ACTION.read_text()
        invalid_choice = valid.replace("diagnostic|sdk) ;; *) exit 1;; esac",
                                       "diagnostic|other) ;; *) exit 1;; esac", 1)
        with self.assertRaises(ValueError):
            validate(invalid_choice)

        invalid_default = valid.replace("    default: diagnostic", "    default: sdk", 1)
        with self.assertRaises(ValueError):
            validate(invalid_default)

        record_step = "    - name: Bind the upload to this still-running original SDK owning job"
        prefix, separator, tail = valid.partition(record_step)
        self.assertTrue(separator)
        disconnected = (prefix + separator + tail.replace(
            "SDK_OWNER_ROLE: ${{ inputs.owner-role }}", "SDK_OWNER_ROLE: diagnostic", 1))
        with self.assertRaises(ValueError):
            validate(disconnected)

    def execute_stage(self, overrides=None):
        with tempfile.TemporaryDirectory(prefix="sdk-owner-action-") as temporary:
            root = Path(temporary).resolve()
            commands = root / "commands"
            commands.mkdir()
            mock = commands / "python3"
            mock.write_text(f"#!{sys.executable}\n" + '''
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
assert args[0] == '-B' and args[1].endswith('/stage-sdk-owner-payload-v2.py')
options = args[2:]
selected = {}
while options:
    key = options.pop(0)
    if '=' in key:
        key, value = key.split('=', 1)
    else:
        value = options.pop(0)
    selected[key] = value
with Path(os.environ['MOCK_CALLS']).open('a') as stream:
    stream.write(json.dumps(selected) + '\\n')
out = Path(selected['--output-dir'])
out.mkdir(mode=0o700)
(out / 'synthetic.json').write_text('{}')
''')
            mock.chmod(0o700)
            environment = {
                **os.environ, "PATH": str(commands) + os.pathsep + os.environ["PATH"],
                "SDK_IDS": '["arm-raspi","pc-x86_64"]', "SDK_GROUP": "llvm",
                "SDK_PRESET": "fixture", "SDK_HOST": "linux-x86_64",
                "SDK_OPERATION_ROOT": str(root / "lane"), "SDK_ROOT": str(root / "owner"),
                "SDK_WORKFLOW": ".github/workflows/toolchain-release.yml",
                "SDK_JOB_NAME": "Synthetic SDK owner", "GITHUB_RUN_ID": "123",
                "SDK_OWNER_ROLE": "diagnostic",
                "GITHUB_RUN_ATTEMPT": "2", "GITHUB_ACTION_PATH": str(ACTION.parent),
                "GITHUB_OUTPUT": str(root / "outputs"), "MOCK_CALLS": str(root / "calls"),
                "ACTIONS_ID_TOKEN_REQUEST_URL": "https://example.invalid/fixture",
                "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "synthetic-test-only",
            }
            environment.update(overrides or {})
            completed = subprocess.run(["bash", "-c", stage_script()], env=environment,
                                       capture_output=True, text=True, check=False)
            calls = (root / "calls").read_text().splitlines() if (root / "calls").exists() else []
            output = (root / "outputs").read_text() if (root / "outputs").exists() else ""
            return completed, [json.loads(line) for line in calls], output, (root / "owner").exists()

    def test_stages_every_selected_product_in_separate_closed_roots(self):
        result, calls, output, created = self.execute_stage()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(created)
        self.assertEqual([call["--sdk-id"] for call in calls], ["arm-raspi", "pc-x86_64"])
        for call in calls:
            self.assertTrue(call["--operation-dir"].endswith("/sdk-" + call["--sdk-id"]))
            self.assertTrue(call["--output-dir"].endswith("/payload/sdk-" + call["--sdk-id"]))
            self.assertEqual(call["--group"], "llvm")
            self.assertEqual(call["--profile"], "fixture")
        self.assertRegex(output, r"payload-name=sdk-v2-[0-9a-f]{64}-123-2\n")
        self.assertRegex(output, r"proof-name=sdk-v2-proof-[0-9a-f]{64}-123-2\n")

    def test_accepts_native_sdk_tokens_without_alphanumeric_endpoint_rules(self):
        result, calls, _output, _created = self.execute_stage({"SDK_IDS": '["+sdk","sdk+"]'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([call["--sdk-id"] for call in calls], ["+sdk", "sdk+"])

    def test_sdk_owner_role_stages_successfully_and_uses_a_distinct_artifact_name(self):
        diagnostic, diagnostic_calls, diagnostic_output, _ = self.execute_stage()
        sdk, sdk_calls, sdk_output, _ = self.execute_stage({"SDK_OWNER_ROLE": "sdk"})
        self.assertEqual(diagnostic.returncode, 0, diagnostic.stderr)
        self.assertEqual(sdk.returncode, 0, sdk.stderr)
        self.assertEqual([call["--sdk-id"] for call in diagnostic_calls],
                         ["arm-raspi", "pc-x86_64"])
        self.assertEqual([call["--sdk-id"] for call in sdk_calls],
                         ["arm-raspi", "pc-x86_64"])

        selected_ids = '["arm-raspi","pc-x86_64"]'

        def lane_sha(parts):
            return hashlib.sha256(("\0".join(parts) + "\0").encode()).hexdigest()

        diagnostic_sha = lane_sha([selected_ids, "llvm", "linux-x86_64", "fixture"])
        sdk_sha = lane_sha(["sdk", selected_ids, "llvm", "linux-x86_64", "fixture"])
        self.assertEqual(diagnostic_output,
                         f"payload-name=sdk-v2-{diagnostic_sha}-123-2\n"
                         f"proof-name=sdk-v2-proof-{diagnostic_sha}-123-2\n")
        self.assertEqual(sdk_output,
                         f"payload-name=sdk-v2-{sdk_sha}-123-2\n"
                         f"proof-name=sdk-v2-proof-{sdk_sha}-123-2\n")
        self.assertNotEqual(diagnostic_sha, sdk_sha)

    def test_invalid_independent_selectors_fail_before_stage_or_output(self):
        for override in (
            {"SDK_IDS": "[]"}, {"SDK_IDS": '["x","x"]'}, {"SDK_IDS": '["z","a"]'},
            {"SDK_OWNER_ROLE": "other"},
            {"SDK_IDS": '["."]'}, {"SDK_IDS": '[".."]'},
            {"SDK_IDS": '["../x"]'}, {"SDK_IDS": '["A"]'}, {"SDK_IDS": "{}"},
            {"SDK_IDS": '[null]'}, {"SDK_IDS": '["x/y"]'}, {"SDK_IDS": '["a\nb"]'},
            {"SDK_GROUP": "../x"}, {"SDK_PRESET": ".."}, {"SDK_HOST": "macos-x86_64"},
            {"SDK_WORKFLOW": "../other.yml"}, {"SDK_JOB_NAME": "bad\njob"},
            {"ACTIONS_ID_TOKEN_REQUEST_TOKEN": ""}, {"GITHUB_RUN_ATTEMPT": "0"},
            {"SDK_ROOT": "/private/tmp/sdk-owner-glob-*"},
            {"SDK_ROOT": "/private/tmp/sdk-owner-glob-[ab]"},
            {"SDK_ROOT": "/private/tmp/sdk-owner-glob-@(a)"},
            {"SDK_ROOT": "/private/tmp/sdk-owner-glob-?"},
        ):
            with self.subTest(override=override):
                result, calls, output, created = self.execute_stage(override)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(calls, [])
                self.assertEqual(output, "")
                self.assertFalse(created)


if __name__ == "__main__":
    unittest.main()
