#!/usr/bin/env python3
"""Offline tests for the inactive protected-start authentication component."""

from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


SOURCE_ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = SOURCE_ROOT / "scripts/toolchain/compiler-sdk-release-start-v2.py"
SPEC = importlib.util.spec_from_file_location("compiler_sdk_release_start_v2", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
start = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(start)

ADMISSION = start.ADMISSION
ORIGIN = start.ORIGIN
REPOSITORY = "metaneutrons/aros-toolchains"
MAIN = "refs/heads/main"
WORKFLOW = ".github/workflows/compiler-sdk-release-start.yml"
COMMIT = "a" * 40
TAG_OBJECT = "b" * 40
RUN_ID = 123456
REPOSITORY_ID = 7890
RUN_ATTEMPT = 1
JOB_ID = 90901
CHECK_RUN_ID = 555001
JOB_NAME = start.JOB
VERSION = "1.2.3"
TAG_NAME = f"v{VERSION}"
TAG_EPOCH = 1_800_000_000
DRAFT_ID = 667002
LOCK_PATH = "toolchains/aros-tools-runtime-v1.json"
RECORD_BYTES = b"synthetic canonical protected-start record fixture\n"
BUNDLE_BYTES = b"synthetic Sigstore bundle fixture; verifier is mocked\n"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def context(**overrides: object) -> dict:
    value = {
        "repository": REPOSITORY,
        "repository_id": REPOSITORY_ID,
        "producer_commit": COMMIT,
        "source_ref": MAIN,
        "workflow": WORKFLOW,
        "run_id": RUN_ID,
        "run_attempt": RUN_ATTEMPT,
    }
    value.update(overrides)
    return value


def input_bytes() -> dict[str, bytes]:
    return {
        path: (b"synthetic committed runtime-lock bytes\n" if path == LOCK_PATH
               else f"synthetic committed input: {path}\n".encode())
        for path in ADMISSION.INPUT_PATHS
    }


def admission_receipt(blobs: dict[str, bytes], **overrides: object) -> dict:
    digests = {path: sha256(raw) for path, raw in blobs.items()}
    receipt = {
        "schema": "aros-toolchains-release-admission-v2",
        "assurance": "metadata-only",
        "repository": REPOSITORY,
        "commit": COMMIT,
        "version": VERSION,
        "tag": TAG_NAME,
        "pull_request": 1100,
        "runs": {"producer_contracts": {"id": 900, "attempt": 1}},
        "governance": {
            "ruleset_id": 55,
            "policy_sha256": "c" * 64,
            "checked_at": TAG_EPOCH,
        },
        "inputs": digests,
        "release_absence": {
            "candidate_tag_ref": "absent",
            "visible_release": "absent",
            "private_draft_absence": "unproven",
            "required_start_recheck": {
                "method": "GET",
                "endpoint": f"repos/{REPOSITORY}/releases/tags/{TAG_NAME}",
                "permission": "contents:write",
                "absence_status": 404,
            },
        },
    }
    receipt.update(overrides)
    return receipt


def record_fixture() -> tuple[dict, dict, dict[str, bytes]]:
    blobs = input_bytes()
    source = context()
    receipt = admission_receipt(blobs)
    record = {
        "schema": start.SCHEMA,
        "assurance": start.ASSURANCE,
        "context": copy.deepcopy(source),
        "event": "workflow_run",
        "job": {"id": JOB_ID, "check_run_id": CHECK_RUN_ID, "name": JOB_NAME},
        "admission": receipt,
        "tag": {
            "name": TAG_NAME,
            "object": TAG_OBJECT,
            "commit": COMMIT,
            "epoch": TAG_EPOCH,
        },
        "draft": {"id": DRAFT_ID, "tag_name": TAG_NAME, "target_commitish": COMMIT},
        "runtime": {
            "lock_sha256": receipt["inputs"][LOCK_PATH],
            "receipt_sha256": "d" * 64,
            "interface_sha256": "e" * 64,
            "executable_sha256": "f" * 64,
        },
    }
    return record, source, blobs


def provider_run(ctx: dict, *, status: str = "completed", conclusion: str | None = "success") -> dict:
    return {
        "id": ctx["run_id"],
        "run_attempt": ctx["run_attempt"],
        "head_sha": ctx["producer_commit"],
        "head_branch": "main",
        "path": f'{ctx["workflow"]}@{ctx["source_ref"]}',
        "head_repository": {"id": ctx["repository_id"], "full_name": ctx["repository"]},
        "event": "workflow_run",
        "status": status,
        "conclusion": conclusion,
    }


def provider_job(ctx: dict, *, job_id: int = JOB_ID, check_id: int = CHECK_RUN_ID,
                 name: str = JOB_NAME, status: str = "completed",
                 conclusion: str | None = "success", attempt: int = RUN_ATTEMPT) -> dict:
    return {
        "id": job_id,
        "check_run_url": f"https://api.github.com/repos/{ctx['repository']}/check-runs/{check_id}",
        "name": name,
        "head_sha": ctx["producer_commit"],
        "run_id": ctx["run_id"],
        "run_attempt": attempt,
        "status": status,
        "conclusion": conclusion,
    }


def tagger_date() -> str:
    return datetime.fromtimestamp(TAG_EPOCH, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def provider_responses(record: dict) -> dict[str, dict]:
    tag = record["tag"]
    draft = record["draft"]
    ctx = record["context"]
    return {
        f"repos/{REPOSITORY}": {
            "full_name": REPOSITORY, "archived": False, "disabled": False,
            "default_branch": "main",
        },
        f"repos/{REPOSITORY}/git/ref/tags/{tag['name']}": {
            "ref": f"refs/tags/{tag['name']}",
            "object": {
                "type": "tag", "sha": tag["object"],
                "url": f"https://api.github.com/repos/{REPOSITORY}/git/tags/{tag['object']}",
            },
        },
        f"repos/{REPOSITORY}/git/tags/{tag['object']}": {
            "sha": tag["object"],
            "tag": tag["name"],
            "object": {"type": "commit", "sha": tag["commit"]},
            "tagger": {"date": tagger_date()},
        },
        f"repos/{REPOSITORY}/releases/{draft['id']}": {
            "id": draft["id"], "tag_name": tag["name"],
            "target_commitish": tag["commit"], "draft": True,
            "prerelease": False, "immutable": False, "assets": [],
        },
        f"repos/{REPOSITORY}/releases/tags/{tag['name']}": {"id": draft["id"]},
        f"repos/{REPOSITORY}/actions/runs/{ctx['run_id']}/attempts/{ctx['run_attempt']}":
            provider_run(ctx),
        f"repos/{REPOSITORY}/actions/runs/{ctx['run_id']}": {
            "id": ctx["run_id"], "run_attempt": ctx["run_attempt"],
            "head_sha": ctx["producer_commit"], "status": "completed",
            "conclusion": "success",
        },
    }


def attestation(raw: bytes, *, invocation: str | None = None,
                subject_name: str = "start.json", subject_digest: str | None = None) -> list[dict]:
    if invocation is None:
        invocation = (f"https://github.com/{REPOSITORY}/actions/runs/{RUN_ID}"
                      f"/attempts/{RUN_ATTEMPT}")
    if subject_digest is None:
        subject_digest = sha256(raw)
    return [{"verificationResult": {
        "signature": {"certificate": {"runInvocationURI": invocation}},
        "statement": {"subject": [{
            "name": subject_name, "digest": {"sha256": subject_digest},
        }]},
    }}]


class StartFixture:
    """Synthetic, fixed-repository data; only mocked verifier/provider calls authenticate it."""

    def __init__(self, root: Path):
        root = root.resolve()
        self.record, self.source, self.blobs = record_fixture()
        self.record_path = root / "start.json"
        self.bundle_path = root / "start.sigstore.json"
        self.record_bytes = ADMISSION.canonical_json(self.record).encode("utf-8") + b"\n"
        self.bundle_bytes = BUNDLE_BYTES
        self.record_path.write_bytes(self.record_bytes)
        self.bundle_path.write_bytes(self.bundle_bytes)
        self.provider = provider_responses(self.record)
        self.source_job = provider_job(self.source)
        self.signature = attestation(self.record_bytes)
        self.case: str | None = None
        self.calls: dict[str, list] = {"api": [], "gh": [], "git": [], "reads": []}

    def run_api(self, path: str, **kwargs):
        if kwargs:
            raise AssertionError(f"provider observation attempted a non-default API operation: {kwargs!r}")
        self.calls["api"].append((path, kwargs))
        response = copy.deepcopy(self.provider.get(path))
        if response is None:
            raise AssertionError(f"unexpected mocked GET endpoint: {path}")
        if path.endswith(f"/attempts/{RUN_ATTEMPT}") and self.case == "failed_attempt":
            response["conclusion"] = "failure"
        if path == f"repos/{REPOSITORY}/actions/runs/{RUN_ID}" and self.case == "rerun":
            response["run_attempt"] = 2
        if path.endswith(f"/releases/{DRAFT_ID}") and self.case == "draft_mismatch":
            response["target_commitish"] = "9" * 40
        if path.endswith(f"/git/ref/tags/{TAG_NAME}") and self.case == "ref_mismatch":
            response["object"]["sha"] = "9" * 40
        return response

    def run_origin_gh(self, arguments: list[str], purpose: str = "GitHub observation"):
        self.calls["gh"].append((list(arguments), purpose))
        if arguments[:2] == ["api", "--paginate"]:
            return [{"total_count": 1, "jobs": [copy.deepcopy(self.source_job)]}]
        if arguments[:1] == ["api"] and "/actions/runs/" in arguments[1]:
            ctx = self.source
            return provider_run(ctx)
        raise AssertionError(f"unexpected mocked gh provider command: {arguments!r}")

    def run_bounded_gh(self, arguments: list[str], purpose: str = "start provider observation"):
        selected = list(arguments)
        self.calls["gh"].append((selected, purpose))
        if selected[:2] != ["attestation", "verify"]:
            raise AssertionError(f"unexpected gh command: {selected!r}")
        if purpose != "start signature authentication":
            raise AssertionError(f"unexpected gh command purpose: {purpose}")
        expected_arguments = [
            "attestation", "verify", str(self.record_path), "--bundle", str(self.bundle_path),
            "--repo", REPOSITORY, "--signer-workflow", f"{REPOSITORY}/{WORKFLOW}",
            "--signer-digest", COMMIT, "--source-digest", COMMIT, "--source-ref", MAIN,
            "--deny-self-hosted-runners", "--format", "json",
        ]
        if selected != expected_arguments:
            raise AssertionError("attestation verifier argument vector differs from the exact selection")
        return copy.deepcopy(self.signature)

    def run_git(self, *arguments: str) -> bytes:
        self.calls["git"].append(arguments)
        if len(arguments) != 2 or arguments[0] != "show":
            raise AssertionError(f"unexpected mocked git command: {arguments!r}")
        selected = arguments[1]
        prefix = f"{COMMIT}:"
        if not selected.startswith(prefix) or selected[len(prefix):] not in self.blobs:
            raise AssertionError(f"unexpected frozen input selection: {selected!r}")
        path = selected[len(prefix):]
        data = self.blobs[path]
        if self.case == "frozen_input_corruption" and path == LOCK_PATH:
            return data + b"changed"
        return data

    def verify(self, *, case: str | None = None, signature: list[dict] | None = None,
               mutate_after_candidate: str | None = None) -> dict:
        self.case = case
        if signature is not None:
            self.signature = signature
        real_read = ADMISSION.read_regular_file

        def track_read(path: Path, label: str, maximum: int) -> bytes:
            self.calls["reads"].append((Path(path), label, maximum))
            return real_read(path, label, maximum)

        real_observe_candidate = start.observe_candidate

        def observe_candidate_with_optional_mutation(record: dict) -> None:
            real_observe_candidate(record)
            if mutate_after_candidate == "record":
                self.record_path.write_bytes(self.record_path.read_bytes() + b" ")
            elif mutate_after_candidate == "bundle":
                self.bundle_path.write_bytes(self.bundle_path.read_bytes() + b" ")
            elif mutate_after_candidate == "job":
                self.source_job["check_run_url"] = (
                    f"https://api.github.com/repos/{REPOSITORY}/check-runs/{CHECK_RUN_ID + 1}"
                )
            elif mutate_after_candidate == "draft":
                self.provider[f"repos/{REPOSITORY}/releases/{DRAFT_ID}"]["draft"] = False
            elif mutate_after_candidate == "tag":
                self.provider[f"repos/{REPOSITORY}/git/ref/tags/{TAG_NAME}"]["object"]["sha"] = "9" * 40

        with mock.patch.object(ADMISSION, "api", side_effect=self.run_api), \
                mock.patch.object(ADMISSION, "git", side_effect=self.run_git), \
                mock.patch.object(ADMISSION, "read_regular_file", side_effect=track_read), \
                mock.patch.object(ORIGIN, "gh_json", side_effect=self.run_origin_gh), \
                mock.patch.object(start, "bounded_gh", side_effect=self.run_bounded_gh), \
                mock.patch.object(start, "observe_candidate",
                                  side_effect=observe_candidate_with_optional_mutation):
            return start.verify_start(self.record_path, self.bundle_path, self.source)


class ValidateStartTests(unittest.TestCase):
    def setUp(self) -> None:
        self.record, self.source, self.blobs = record_fixture()

    def rejected(self, record: dict, source: dict | None = None) -> None:
        with self.assertRaises((start.StartError, ADMISSION.AdmissionError, ORIGIN.OriginError)):
            start.validate_start(record, self.source if source is None else source)

    def test_positive_joined_fixture_uses_fixed_repository_and_selectors(self) -> None:
        self.assertEqual(start.validate_start(self.record, self.source), self.record)
        self.assertEqual(self.source["repository"], REPOSITORY)
        self.assertEqual(self.source["source_ref"], MAIN)
        self.assertEqual(self.source["workflow"], WORKFLOW)

    def test_structure_validation_does_not_authenticate_or_observe_provider_state(self) -> None:
        # A structurally joined record is accepted without a signature, provider,
        # or blob observation. Full authenticity belongs to verify_start.
        with mock.patch.object(ADMISSION, "api", side_effect=AssertionError("unexpected API call")), \
                mock.patch.object(ADMISSION, "git", side_effect=AssertionError("unexpected Git call")):
            accepted = start.validate_start(self.record, self.source)
        self.assertEqual(accepted, self.record)

    def test_boolean_ids_are_rejected(self) -> None:
        for path in (
            ("context", "repository_id"), ("context", "run_id"), ("context", "run_attempt"),
            ("job", "id"), ("job", "check_run_id"), ("tag", "epoch"),
            ("draft", "id"), ("admission", "pull_request"),
            ("admission", "runs", "producer_contracts", "id"),
        ):
            with self.subTest(path=path):
                candidate = copy.deepcopy(self.record)
                target = candidate
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = True
                self.rejected(candidate)

    def test_closed_field_sets_reject_extra_and_missing_fields(self) -> None:
        candidates = []
        extra_record = copy.deepcopy(self.record)
        extra_record["unexpected"] = None
        candidates.append(extra_record)
        missing_record = copy.deepcopy(self.record)
        del missing_record["runtime"]
        candidates.append(missing_record)
        extra_job = copy.deepcopy(self.record)
        extra_job["job"]["attempt"] = 1
        candidates.append(extra_job)
        missing_runtime = copy.deepcopy(self.record)
        del missing_runtime["runtime"]["interface_sha256"]
        candidates.append(missing_runtime)
        for candidate in candidates:
            with self.subTest(candidate=candidate):
                self.rejected(candidate)

    def test_main_workflow_event_and_original_attempt_are_closed(self) -> None:
        for field, value in (("source_ref", "refs/heads/release"),
                             ("workflow", ".github/workflows/other.yml"),
                             ("run_attempt", 2)):
            with self.subTest(field=field):
                selected = copy.deepcopy(self.source)
                selected[field] = value
                self.rejected(copy.deepcopy(self.record), selected)
        for event in ("push", "workflow_dispatch", "pull_request"):
            with self.subTest(event=event):
                candidate = copy.deepcopy(self.record)
                candidate["event"] = event
                self.rejected(candidate)

    def test_signed_context_must_equal_independent_source_context(self) -> None:
        for field, value in (("producer_commit", "9" * 40), ("run_id", RUN_ID + 1),
                             ("repository_id", REPOSITORY_ID + 1)):
            with self.subTest(field=field):
                candidate = copy.deepcopy(self.record)
                candidate["context"][field] = value
                self.rejected(candidate)

    def test_admission_version_commit_tag_and_runtime_lock_joins_are_enforced(self) -> None:
        candidates = []
        bad_version = copy.deepcopy(self.record)
        bad_version["admission"]["version"] = "2.0.0"
        candidates.append(bad_version)
        bad_tag = copy.deepcopy(self.record)
        bad_tag["tag"]["name"] = "v2.0.0"
        candidates.append(bad_tag)
        bad_commit = copy.deepcopy(self.record)
        bad_commit["tag"]["commit"] = "9" * 40
        candidates.append(bad_commit)
        bad_receipt_commit = copy.deepcopy(self.record)
        bad_receipt_commit["admission"]["commit"] = "9" * 40
        candidates.append(bad_receipt_commit)
        bad_lock_digest = copy.deepcopy(self.record)
        bad_lock_digest["runtime"]["lock_sha256"] = "0" * 64
        candidates.append(bad_lock_digest)
        for candidate in candidates:
            with self.subTest(candidate=candidate):
                self.rejected(candidate)

    def test_runtime_measurement_digests_are_canonical_but_other_bytes_need_authentication(self) -> None:
        accepted = copy.deepcopy(self.record)
        accepted["runtime"]["receipt_sha256"] = "1" * 64
        accepted["runtime"]["interface_sha256"] = "2" * 64
        accepted["runtime"]["executable_sha256"] = "3" * 64
        self.assertEqual(start.validate_start(accepted, self.source), accepted)
        accepted["runtime"]["executable_sha256"] = "not-a-digest"
        self.rejected(accepted)


class ObserveCandidateTests(unittest.TestCase):
    def test_candidate_metadata_uses_mocked_gets_and_accepts_the_exact_annotated_draft(self) -> None:
        record, _, _ = record_fixture()
        responses = provider_responses(record)
        calls: list[str] = []

        def api(path: str, **kwargs):
            calls.append(path)
            self.assertEqual(kwargs, {})
            if path not in responses:
                raise AssertionError(f"unexpected provider request: {path}")
            return copy.deepcopy(responses[path])

        with mock.patch.object(ADMISSION, "api", side_effect=api):
            start.observe_candidate(record)
        self.assertEqual(len(calls), 5)
        self.assertTrue(all("/releases/" not in path or path.startswith(f"repos/{REPOSITORY}/")
                            for path in calls))

    def test_candidate_metadata_rejects_ref_or_draft_rebinding(self) -> None:
        record, _, _ = record_fixture()
        for case, path, mutate in (
            ("tag ref", f"repos/{REPOSITORY}/git/ref/tags/{TAG_NAME}",
             lambda value: value["object"].update(sha="9" * 40)),
            ("draft", f"repos/{REPOSITORY}/releases/{DRAFT_ID}",
             lambda value: value.update(target_commitish="9" * 40)),
        ):
            with self.subTest(case=case):
                responses = provider_responses(record)
                mutate(responses[path])

                def api(requested: str, **kwargs):
                    if requested not in responses:
                        raise AssertionError(f"unexpected provider request: {requested}")
                    return copy.deepcopy(responses[requested])

                with mock.patch.object(ADMISSION, "api", side_effect=api), \
                        self.assertRaises(start.StartError):
                    start.observe_candidate(record)


class VerifyStartTests(unittest.TestCase):
    def run_fixture(self, *, case: str | None = None, signature: list[dict] | None = None,
                    mutate_after_candidate: str | None = None):
        temporary = tempfile.TemporaryDirectory(prefix="compiler-sdk-release-start-v2.")
        self.addCleanup(temporary.cleanup)
        fixture = StartFixture(Path(temporary.name))
        fixture.verify(case=case, signature=signature,
                       mutate_after_candidate=mutate_after_candidate)
        return fixture

    def assert_rejected(self, fixture: StartFixture, *, case: str | None = None,
                        signature: list[dict] | None = None,
                        mutate_after_candidate: str | None = None,
                        exception=(start.StartError, ADMISSION.AdmissionError, ORIGIN.OriginError)):
        with self.assertRaises(exception):
            fixture.verify(case=case, signature=signature,
                           mutate_after_candidate=mutate_after_candidate)

    def test_positive_full_verification_uses_real_files_and_mocked_read_only_evidence(self) -> None:
        fixture = self.run_fixture()
        self.assertEqual(fixture.record_path.read_bytes(), fixture.record_bytes)
        self.assertEqual(fixture.bundle_path.read_bytes(), fixture.bundle_bytes)
        self.assertEqual(fixture.calls["git"], [("show", f"{COMMIT}:{path}")
                                                 for path in sorted(ADMISSION.INPUT_PATHS)])
        self.assertEqual([path for path, _, _ in fixture.calls["reads"]], [
            fixture.record_path, fixture.bundle_path, fixture.record_path, fixture.bundle_path,
        ])
        self.assertEqual(sum(purpose == "start signature authentication"
                             for _, purpose in fixture.calls["gh"]), 1)
        self.assertEqual(len(fixture.calls["api"]), 14)
        self.assertTrue(all("/actions/runs/" not in path or path.startswith(f"repos/{REPOSITORY}/")
                            for path, _ in fixture.calls["api"]))
        self.assertTrue(all(command[:1] in (["api"], ["attestation"])
                            for command, _ in fixture.calls["gh"]))

    def test_failed_source_attempt_and_latest_run_rerun_are_rejected(self) -> None:
        for case in ("failed_attempt", "rerun"):
            with self.subTest(case=case):
                temp = tempfile.TemporaryDirectory(prefix="compiler-sdk-release-start-v2.")
                self.addCleanup(temp.cleanup)
                fixture = StartFixture(Path(temp.name))
                self.assert_rejected(fixture, case=case)

    def test_failed_or_wrong_attempt_job_is_rejected(self) -> None:
        for job_case, job in (
            ("failed", provider_job(context(), status="completed", conclusion="failure")),
            ("wrong attempt", provider_job(context(), attempt=2)),
            ("wrong identity", provider_job(context(), job_id=JOB_ID + 1)),
        ):
            with self.subTest(job_case=job_case):
                temp = tempfile.TemporaryDirectory(prefix="compiler-sdk-release-start-v2.")
                self.addCleanup(temp.cleanup)
                fixture = StartFixture(Path(temp.name))
                fixture.source_job = job
                self.assert_rejected(fixture)

    def test_signature_must_bind_the_original_invocation_and_exact_subject(self) -> None:
        changes = (
            ("invocation", "start signature belongs to another original run attempt"),
            ("subject_name", "start signature subject differs"),
            ("subject_digest", "start signature subject differs"),
        )
        for change, message in changes:
            with self.subTest(change=change):
                temp = tempfile.TemporaryDirectory(prefix="compiler-sdk-release-start-v2.")
                self.addCleanup(temp.cleanup)
                fixture = StartFixture(Path(temp.name))
                candidate = copy.deepcopy(fixture.signature)
                result = candidate[0]["verificationResult"]
                if change == "invocation":
                    result["signature"]["certificate"]["runInvocationURI"] = (
                        f"https://github.com/{REPOSITORY}/actions/runs/{RUN_ID}/attempts/2"
                    )
                elif change == "subject_name":
                    result["statement"]["subject"][0]["name"] = "other.json"
                else:
                    result["statement"]["subject"][0]["digest"]["sha256"] = "0" * 64
                with self.assertRaisesRegex(start.StartError, message):
                    fixture.verify(signature=candidate)

    def test_late_provider_job_rebinding_is_rejected(self) -> None:
        temp = tempfile.TemporaryDirectory(prefix="compiler-sdk-release-start-v2.")
        self.addCleanup(temp.cleanup)
        fixture = StartFixture(Path(temp.name))
        with self.assertRaisesRegex(start.StartError, "provider start job changed during authentication"):
            fixture.verify(mutate_after_candidate="job")

    def test_late_candidate_changes_are_rejected(self) -> None:
        for change, message in (("draft", "exact private empty stable candidate"),
                                ("tag", "exact annotated start tag")):
            with self.subTest(change=change):
                temp = tempfile.TemporaryDirectory(prefix="compiler-sdk-release-start-v2.")
                self.addCleanup(temp.cleanup)
                fixture = StartFixture(Path(temp.name))
                with self.assertRaisesRegex(start.StartError, message):
                    fixture.verify(mutate_after_candidate=change)

    def test_committed_input_byte_corruption_is_rejected_after_signature_verification(self) -> None:
        temp = tempfile.TemporaryDirectory(prefix="compiler-sdk-release-start-v2.")
        self.addCleanup(temp.cleanup)
        fixture = StartFixture(Path(temp.name))
        self.assert_rejected(fixture, case="frozen_input_corruption")
        self.assertEqual(len(fixture.calls["git"]),
                         sorted(ADMISSION.INPUT_PATHS).index(LOCK_PATH) + 1)

    def test_tag_and_draft_provider_mismatches_are_rejected(self) -> None:
        for case in ("ref_mismatch", "draft_mismatch"):
            with self.subTest(case=case):
                temp = tempfile.TemporaryDirectory(prefix="compiler-sdk-release-start-v2.")
                self.addCleanup(temp.cleanup)
                fixture = StartFixture(Path(temp.name))
                self.assert_rejected(fixture, case=case)

    def test_record_or_bundle_changed_after_verification_is_rejected(self) -> None:
        for selected in ("record", "bundle"):
            with self.subTest(selected=selected):
                temp = tempfile.TemporaryDirectory(prefix="compiler-sdk-release-start-v2.")
                self.addCleanup(temp.cleanup)
                fixture = StartFixture(Path(temp.name))
                self.assert_rejected(fixture, mutate_after_candidate=selected)


if __name__ == "__main__":
    unittest.main(verbosity=2)
