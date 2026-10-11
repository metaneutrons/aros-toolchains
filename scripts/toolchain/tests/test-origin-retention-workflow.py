#!/usr/bin/env python3
"""Execute the actual diagnostic selector script with mocked provider pages.

This tests workflow plumbing, not live OIDC, signatures or native admission.
"""

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = ROOT / ".github/workflows/ci.yml"
COMMIT = "a" * 40


def selector_script():
    text = WORKFLOW.read_text()
    heading = "      - name: Select the completed owner and original uploads independently\n"
    assert text.count(heading) == 1
    step = text.split(heading, 1)[1].split("      - name:", 1)[0]
    script = step.split("        run: |\n", 1)[1]
    return "\n".join(line[10:] if line else "" for line in script.splitlines()) + "\n"


def observations():
    job = {"id": 42, "name": "Artifact origin probe", "head_sha": COMMIT,
           "run_id": 123, "run_attempt": 2, "status": "completed", "conclusion": "success",
           "check_run_url": "https://api.github.com/repos/example/project/check-runs/99"}
    result = {"jobs": [{"total_count": 1, "jobs": [job]}]}
    for key, identity, prefix in (("payload", 101, "artifact-origin-payload"),
                                  ("proof", 102, "artifact-origin-proof")):
        result[key] = {"id": identity, "name": f"{prefix}-123-2", "digest": "sha256:" + "b" * 64,
                       "expired": False, "size_in_bytes": 100,
                       "workflow_run": {"id": 123, "head_sha": COMMIT,
                                        "repository_id": 789, "head_repository_id": 789}}
    return result


class WorkflowSelection(unittest.TestCase):
    def execute(self, fixture):
        with tempfile.TemporaryDirectory(prefix="origin-workflow-") as temporary:
            root = Path(temporary).resolve()
            provider = root / "provider.json"
            provider.write_text(json.dumps(fixture))
            gh = root / "gh"
            gh.write_text(f"#!{sys.executable}\n" + """
import json, os, sys
from pathlib import Path
fixture = json.loads(Path(os.environ['MOCK_PROVIDER']).read_text())
endpoint = sys.argv[-1]
if endpoint.endswith('/jobs?per_page=100'):
    selected = fixture['jobs']
elif endpoint.endswith('/artifacts/101'):
    selected = fixture['payload']
elif endpoint.endswith('/artifacts/102'):
    selected = fixture['proof']
else:
    raise SystemExit('unexpected mocked provider request')
print(json.dumps(selected))
""")
            gh.chmod(0o700)
            environment = {**os.environ, "PATH": str(root) + os.pathsep + os.environ["PATH"],
                           "MOCK_PROVIDER": str(provider), "RUNNER_TEMP": str(root),
                           "GITHUB_REPOSITORY": "example/project", "GITHUB_REPOSITORY_ID": "789",
                           "GITHUB_SHA": COMMIT, "GITHUB_REF": "refs/heads/fixture",
                           "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2",
                           "PAYLOAD_ID": "101", "PROOF_ID": "102", "PYTHONDONTWRITEBYTECODE": "1"}
            completed = subprocess.run(["bash", "-c", selector_script()], cwd=ROOT,
                                       env=environment, capture_output=True, text=True, check=False)
            selected = root / "same-attempt-origin/selection.json"
            return completed, json.loads(selected.read_bytes()) if selected.exists() else None

    def test_selected_completed_original_owner_and_both_uploads(self):
        completed, selected = self.execute(observations())
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(selected["job"], {"id": 42, "name": "Artifact origin probe"})
        self.assertEqual(selected["artifact"]["id"], 101)
        self.assertEqual(selected["proof"]["id"], 102)
        self.assertEqual(selected["context"]["run_attempt"], 2)

    def test_duplicate_owner_is_rejected_without_selection(self):
        fixture = observations()
        duplicate = copy.deepcopy(fixture["jobs"][0]["jobs"][0])
        duplicate["id"] = 43
        fixture["jobs"][0] = {"total_count": 2, "jobs": [fixture["jobs"][0]["jobs"][0], duplicate]}
        completed, selected = self.execute(fixture)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("diagnostic owner is not unique", completed.stderr)
        self.assertIsNone(selected)

    def test_unsuccessful_owner_is_rejected_without_selection(self):
        fixture = observations()
        fixture["jobs"][0]["jobs"][0]["conclusion"] = "failure"
        completed, selected = self.execute(fixture)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("owning job did not succeed", completed.stderr)
        self.assertIsNone(selected)

    def test_wrong_provider_digest_or_source_is_rejected_without_selection(self):
        for corrupt in ("digest", "source"):
            with self.subTest(corrupt=corrupt):
                fixture = observations()
                if corrupt == "digest":
                    fixture["proof"]["digest"] = "sha256:invalid"
                else:
                    fixture["proof"]["workflow_run"]["head_sha"] = "c" * 40
                completed, selected = self.execute(fixture)
                self.assertNotEqual(completed.returncode, 0)
                self.assertIsNone(selected)


if __name__ == "__main__":
    unittest.main()
