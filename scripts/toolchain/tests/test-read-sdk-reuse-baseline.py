"""Bind the observation signature and provider artifact to the previous successful attempt."""

import hashlib
import importlib.util
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "read-sdk-reuse-baseline.py"
spec = importlib.util.spec_from_file_location("baseline", SCRIPT)
baseline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(baseline)
origin = baseline.origin
SOURCE = {
    "repository": "a/b",
    "repository_id": 1,
    "run_id": 5,
    "run_attempt": 2,
    "producer_commit": "a" * 40,
    "source_ref": "refs/heads/main",
    "workflow": origin.SPLIT_SDK_WORKFLOW,
}


class BaselineTests(unittest.TestCase):
    def test_select_previous_success_before_current_workflow_number(self):
        def run(n):
            return {"run_number": n, "id": n + 1, "run_attempt": 2, "head_sha": "a" * 40}

        caller = dict(SOURCE, run_id=9)
        with (
            patch.object(
                origin, "gh_json", return_value={"workflow_runs": [run(12), run(8), run(4)]}
            ) as query,
            patch.object(origin, "observe_run_event", return_value="workflow_dispatch") as observed,
        ):
            self.assertEqual(baseline.select_baseline(caller, 8), SOURCE)
            api_call = query.call_args.args[0]
            for entry in ("branch=main", "status=success", "event=workflow_dispatch"):
                self.assertIn(entry, api_call)
            observed.assert_called_once_with(SOURCE, require_success=True)

    def signed_record(self, root, *, wrong_attempt=False, corrupt=False):
        raw = origin.canonical({"schema": baseline.SCHEMA, "context": SOURCE, "targets": {}})
        archive = root / "source.zip"
        with zipfile.ZipFile(archive, "w") as z:
            z.writestr(baseline.SUBJECT, raw)
            z.writestr(baseline.BUNDLE, b"{}")
        data = archive.read_bytes()
        artifact = {
            "id": 42,
            "name": "sdk-reuse-5-2",
            "expired": False,
            "size_in_bytes": len(data),
            "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
            "workflow_run": {
                "id": 5,
                "head_sha": SOURCE["producer_commit"],
                "repository_id": 1,
                "head_repository_id": 1,
            },
        }

        def download(ctx, selected, dest):
            self.assertEqual(ctx, SOURCE)
            self.assertEqual(selected["id"], 42)
            dest.write_bytes(data + (b"x" if corrupt else b""))

        certificate = {
            "runInvocationURI": "https://github.com/a/b/actions/runs/5/attempts/"
            + ("1" if wrong_attempt else "2")
        }
        subjects = [{"name": baseline.SUBJECT, "digest": {"sha256": hashlib.sha256(raw).hexdigest()}}]
        with (
            patch.object(origin, "download_payload", side_effect=download),
            patch.object(
                origin,
                "gh_json",
                return_value=[
                    {
                        "verificationResult": {
                            "signature": {"certificate": certificate},
                            "statement": {"subject": subjects},
                        }
                    }
                ],
            ) as verify,
        ):
            result = baseline.authenticate(SOURCE, artifact, root)
            for field in (
                "--signer-workflow",
                "--source-ref",
                "--source-digest",
                "--deny-self-hosted-runners",
            ):
                self.assertIn(field, verify.call_args.args[0])
            return result

    def test_accepts_signed_record_from_the_selected_attempt(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(self.signed_record(Path(tmp).resolve())["context"], SOURCE)

    def test_rejects_other_attempt_and_zip_substitution(self):
        for flags, reason in (
            ({"wrong_attempt": True}, "run attempt"),
            ({"corrupt": True}, "provider digest"),
        ):
            with (
                self.subTest(flags=flags),
                tempfile.TemporaryDirectory() as tmp,
                self.assertRaisesRegex(origin.OriginError, reason),
            ):
                self.signed_record(Path(tmp).resolve(), **flags)


if __name__ == "__main__":
    unittest.main()
