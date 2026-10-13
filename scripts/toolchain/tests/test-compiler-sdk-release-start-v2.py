#!/usr/bin/env python3
"""Offline tests for the inactive protected-start authentication component."""

from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
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
        "labels": ["ubuntu-24.04"],
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
        self.runtime_lock_path = root / "runtime-lock.json"
        self.runtime_directory = root / "runtime"
        self.runtime_interface_path = root / "runtime-interface.json"
        self.runtime_host = "linux-x86_64"
        self.runtime_binding_calls: list = []
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
        private_record, private_bundle = Path(selected[2]), Path(selected[4])
        if (private_record == self.record_path or private_bundle == self.bundle_path
                or private_record.name != self.record_path.name
                or private_record.read_bytes() != self.record_bytes
                or private_bundle.read_bytes() != self.bundle_bytes
                or private_record.stat().st_mode & 0o777 != 0o600
                or private_bundle.stat().st_mode & 0o777 != 0o600):
            raise AssertionError("verifier did not receive private copies of selected bytes")
        expected_arguments = [
            "attestation", "verify", str(private_record), "--bundle", str(private_bundle),
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
               mutate_after_candidate: str | None = None, **byte_selection) -> dict:
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
            elif mutate_after_candidate == "runner":
                self.source_job["labels"] = ["self-hosted"]
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
                                  side_effect=observe_candidate_with_optional_mutation), \
                mock.patch.object(start, "verify_runtime_evidence") as runtime_binding:
            result = start.verify_start(
                self.record_path, self.bundle_path, self.source,
                runtime_lock=self.runtime_lock_path,
                runtime_directory=self.runtime_directory,
                runtime_interface=self.runtime_interface_path,
                runtime_host=self.runtime_host,
                **byte_selection,
            )
            self.runtime_binding_calls = runtime_binding.call_args_list
            return result


class RuntimeEvidenceFixture:
    """Small local runtime closure using the real release lock contract."""

    def __init__(self, root: Path):
        self.root = root.resolve()
        self.host = "linux-x86_64"
        self.lock_path = self.root / "runtime-lock.json"
        self.directory = self.root / "runtime"
        self.interface_path = self.root / "runtime-interface.json"
        self.directory.mkdir()
        (self.directory / "bin").mkdir()

        real_lock_path = SOURCE_ROOT / LOCK_PATH
        self.lock = json.loads(real_lock_path.read_text(encoding="utf-8"))
        self.file_bytes = {
            path: f"synthetic bounded runtime file: {path}\n".encode("ascii")
            for path in start.RUNTIME.EXPECTED_FILES
        }
        manifest_files = []
        for relative, (mode, _) in sorted(start.RUNTIME.EXPECTED_FILES.items()):
            payload = self.file_bytes[relative]
            path = self.directory / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            path.chmod(int(mode, 8))
            manifest_files.append({
                "path": relative,
                "mode": mode,
                "sha256": sha256(payload),
                "size": len(payload),
            })
        entry = self.lock["hosts"][self.host]
        self.manifest = {
            "schema": 1,
            "package": "aros-tools",
            "version": self.lock["version"],
            "target": entry["target"],
            "source_commit": self.lock["source_commit"],
            "source_date_epoch": self.lock["source_date_epoch"],
            "archive": entry["archive"]["name"],
            "archive_sha256": entry["archive"]["sha256"],
            "archive_size": entry["archive"]["size"],
            "files": manifest_files,
        }
        self.manifest_bytes = start.RUNTIME.canonical_json(self.manifest) + b"\n"
        entry["manifest"]["size"] = len(self.manifest_bytes)
        entry["manifest"]["sha256"] = sha256(self.manifest_bytes)
        self.lock_path.write_text(json.dumps(self.lock, sort_keys=True, indent=2) + "\n",
                                  encoding="utf-8")
        (self.directory / ".aros-tools-runtime-manifest.json").write_bytes(self.manifest_bytes)
        self.write_receipt()
        self.write_interface()

        self.record, _, _ = record_fixture()
        self.record = copy.deepcopy(self.record)
        lock_digest = sha256(self.lock_path.read_bytes())
        self.record["admission"]["inputs"][LOCK_PATH] = lock_digest
        self.record["runtime"] = {
            "lock_sha256": lock_digest,
            "receipt_sha256": sha256(self.receipt_path.read_bytes()),
            "interface_sha256": sha256(self.interface_path.read_bytes()),
            "executable_sha256": sha256((self.directory / "bin/aros").read_bytes()),
        }

    @property
    def receipt_path(self) -> Path:
        return self.directory / ".aros-tools-runtime-receipt-v1.json"

    @property
    def executable_path(self) -> Path:
        return self.directory / "bin/aros"

    def write_receipt(self) -> None:
        receipt = start.RUNTIME.receipt(
            self.lock_path, self.lock, self.host, self.manifest, sha256(self.manifest_bytes)
        )
        self.receipt_path.write_bytes(start.RUNTIME.canonical_json(receipt) + b"\n")

    def interface_receipt(self) -> dict:
        metadata = self.executable_path.stat()
        checks = [{
            "kind": "version",
            "checked_selectors": {
                "argv": ["--version"],
                "expected_version": self.lock["version"],
            },
            "result": "passed",
        }]
        checks.extend({
            "kind": "command-interface",
            "checked_selectors": {
                "command": list(command),
                "required_options": list(options),
            },
            "result": "passed",
        } for command, options in start.INTERFACE.INTERFACES)
        return {
            "schema": "aros-tools-runtime-interface-preflight-v1",
            "assurance": "interface-only-exact-selected-binary",
            "runtime": {
                # This remains the original producer-side path; the verifier
                # checks it as bounded metadata and opens its own selected path.
                "path": str(self.executable_path),
                "sha256": sha256(self.executable_path.read_bytes()),
                "version": self.lock["version"],
                "execution_binding": "sha256-identical-private-temporary-copy",
                "file_identity": {
                    "device": metadata.st_dev,
                    "inode": metadata.st_ino,
                    "mode": metadata.st_mode,
                    "size": metadata.st_size,
                    "mtime_ns": metadata.st_mtime_ns,
                    "ctime_ns": metadata.st_ctime_ns,
                },
            },
            "checks": checks,
            "limitations": [
                "does not authenticate published runtime provenance or authenticity",
                "does not establish V2 behavior, ABI compatibility, or qualification",
                "does not establish source commit, signatures, or release authority",
                "the caller must separately materialize and authenticate the runtime",
            ],
        }

    def write_interface(self, value: dict | None = None) -> None:
        receipt = self.interface_receipt() if value is None else value
        contents = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
        self.interface_path.write_bytes(contents)

    def refresh_digest(self, key: str, path: Path) -> None:
        selected = sha256(path.read_bytes())
        self.record["runtime"][key] = selected
        if key == "lock_sha256":
            self.record["admission"]["inputs"][LOCK_PATH] = selected

    def verify(self, *, host: str | None = None, record: dict | None = None) -> None:
        start.verify_runtime_evidence(
            self.record if record is None else record,
            lock_path=self.lock_path,
            directory=self.directory,
            interface_path=self.interface_path,
            host=self.host if host is None else host,
        )


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
    def test_source_runner_identity_is_required_in_both_provider_snapshots(self) -> None:
        for labels in (None, [], ["self-hosted"], ["ubuntu-24.04-arm"]):
            with self.subTest(labels=labels), tempfile.TemporaryDirectory() as directory:
                fixture = StartFixture(Path(directory))
                fixture.source_job["labels"] = labels
                with self.assertRaisesRegex(start.StartError, "runner label"):
                    fixture.verify()
        with tempfile.TemporaryDirectory() as directory:
            fixture = StartFixture(Path(directory))
            with self.assertRaisesRegex(start.StartError, "runner label"):
                fixture.verify(mutate_after_candidate="runner")

    def test_external_verifier_does_not_reopen_temporarily_substituted_caller_inputs(self) -> None:
        with tempfile.TemporaryDirectory(prefix="compiler-sdk-start-private-bytes.") as directory:
            fixture = StartFixture(Path(directory))
            original_verifier = fixture.run_bounded_gh
            observed_private_paths = []

            def substitute_caller_paths(arguments, purpose):
                fixture.record_path.write_bytes(fixture.record_bytes + b" ")
                fixture.bundle_path.write_bytes(b"different valid bundle fixture")
                try:
                    observed_private_paths.extend((Path(arguments[2]), Path(arguments[4])))
                    return original_verifier(arguments, purpose)
                finally:
                    fixture.record_path.write_bytes(fixture.record_bytes)
                    fixture.bundle_path.write_bytes(fixture.bundle_bytes)

            with mock.patch.object(fixture, "run_bounded_gh", side_effect=substitute_caller_paths):
                self.assertEqual(fixture.verify(), fixture.record)
            self.assertTrue(observed_private_paths)
            self.assertTrue(all(not path.exists() for path in observed_private_paths))

    def test_exact_record_and_bundle_pins_join_authentication_to_claim_bytes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="compiler-sdk-start-byte-pins.") as directory:
            fixture = StartFixture(Path(directory))
            pins = {"expected_record_sha256": sha256(fixture.record_bytes),
                    "expected_bundle_sha256": sha256(fixture.bundle_bytes)}
            self.assertEqual(fixture.verify(**pins), fixture.record)
            for field, value in (("expected_record_sha256", "0" * 64),
                                 ("expected_bundle_sha256", "0" * 64),
                                 ("expected_record_sha256", True),
                                 ("expected_bundle_sha256", "invalid"),
                                 ("expected_bundle_sha256", None)):
                with self.subTest(field=field, value=value), self.assertRaises(start.StartError):
                    fixture.verify(**dict(pins, **{field: value}))
            # Semantically identical JSON must not select different claim bytes.
            fixture.record_path.write_bytes(fixture.record_bytes + b" ")
            with self.assertRaisesRegex(start.StartError, "independently selected bytes"):
                fixture.verify(**pins)

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
        expected_runtime_call = mock.call(
            fixture.record,
            lock_path=fixture.runtime_lock_path,
            directory=fixture.runtime_directory,
            interface_path=fixture.runtime_interface_path,
            host=fixture.runtime_host,
        )
        self.assertEqual(fixture.runtime_binding_calls,
                         [expected_runtime_call, expected_runtime_call])
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


class VerifyRuntimeEvidenceTests(unittest.TestCase):
    def fixture(self) -> RuntimeEvidenceFixture:
        temporary = tempfile.TemporaryDirectory(prefix="compiler-sdk-runtime-evidence.")
        self.addCleanup(temporary.cleanup)
        return RuntimeEvidenceFixture(Path(temporary.name))

    def assert_runtime_rejected(self, fixture: RuntimeEvidenceFixture, *,
                                host: str | None = None,
                                record: dict | None = None,
                                exception=(start.StartError, start.RUNTIME.RuntimeError,
                                           start.INTERFACE.PreflightError, ADMISSION.AdmissionError,
                                           OSError)) -> None:
        with self.assertRaises(exception):
            fixture.verify(host=host, record=record)

    def test_positive_binding_runs_real_extracted_verifier_without_external_actions(self) -> None:
        fixture = self.fixture()
        with mock.patch.object(start.RUNTIME, "verify_extracted_frozen",
                               wraps=start.RUNTIME.verify_extracted_frozen) as extracted, \
                mock.patch.object(start.RUNTIME, "run",
                                  side_effect=AssertionError("runtime subprocess helper used")), \
                mock.patch.object(start.RUNTIME, "verify_signature",
                                  side_effect=AssertionError("runtime signature verifier used")), \
                mock.patch.object(start.RUNTIME, "verify_attestation",
                                  side_effect=AssertionError("runtime attestation verifier used")), \
                mock.patch.object(start.RUNTIME.subprocess, "run",
                                  side_effect=AssertionError("subprocess.run used")), \
                mock.patch.object(start.RUNTIME.subprocess, "Popen",
                                  side_effect=AssertionError("subprocess.Popen used")), \
                mock.patch.object(ADMISSION, "api",
                                  side_effect=AssertionError("network observation used")), \
                mock.patch.object(start, "bounded_gh",
                                  side_effect=AssertionError("signature authentication used")), \
                mock.patch.object(ORIGIN, "gh_json",
                                  side_effect=AssertionError("provider authentication used")):
            fixture.verify()
        extracted.assert_called_once_with(fixture.lock, fixture.record["runtime"]["lock_sha256"],
                                          fixture.host, fixture.directory)

    def test_signed_runtime_digests_bind_each_retained_file(self) -> None:
        for selected in ("lock", "receipt", "executable", "interface"):
            with self.subTest(selected=selected):
                fixture = self.fixture()
                if selected == "lock":
                    fixture.lock_path.write_bytes(fixture.lock_path.read_bytes() + b" ")
                elif selected == "receipt":
                    fixture.receipt_path.write_bytes(fixture.receipt_path.read_bytes() + b" ")
                elif selected == "executable":
                    fixture.executable_path.write_bytes(fixture.executable_path.read_bytes() + b"changed\n")
                else:
                    fixture.interface_path.write_bytes(fixture.interface_path.read_bytes() + b" ")
                self.assert_runtime_rejected(fixture)

    def test_frozen_runtime_repository_and_selected_host_are_required(self) -> None:
        fixture = self.fixture()
        fixture.lock["repository"] = "example/aros-tools"
        workflow = "example/aros-tools/.github/workflows/release.yml"
        fixture.lock["signer_workflow"] = workflow
        fixture.lock["certificate_identity"] = (
            f"https://github.com/{workflow}@refs/tags/{fixture.lock['tag']}"
        )
        fixture.lock_path.write_text(json.dumps(fixture.lock, sort_keys=True, indent=2) + "\n",
                                     encoding="utf-8")
        fixture.write_receipt()
        fixture.refresh_digest("lock_sha256", fixture.lock_path)
        fixture.refresh_digest("receipt_sha256", fixture.receipt_path)
        with self.assertRaisesRegex(start.StartError, "repository or independently selected host"):
            fixture.verify()

        wrong_host = self.fixture()
        self.assert_runtime_rejected(wrong_host, host="linux-aarch64")

    def test_interface_schema_assurance_runtime_version_and_checks_are_closed(self) -> None:
        mutations = (
            ("schema", lambda value: value.update(schema="unexpected-interface-v1")),
            ("assurance", lambda value: value.update(assurance="runtime-authenticated")),
            ("extra field", lambda value: value.update(unexpected=True)),
            ("runtime digest", lambda value: value["runtime"].update(sha256="0" * 64)),
            ("runtime version", lambda value: value["runtime"].update(version="99.0.0")),
            ("version selector", lambda value: value["checks"][0]["checked_selectors"].update(
                expected_version="99.0.0")),
            ("command selector", lambda value: value["checks"][1]["checked_selectors"].update(
                command=["toolchain", "producer", "unexpected"])),
        )
        for label, mutate in mutations:
            with self.subTest(label=label):
                fixture = self.fixture()
                receipt = json.loads(fixture.interface_path.read_text(encoding="utf-8"))
                mutate(receipt)
                fixture.write_interface(receipt)
                # The synthetic signed digest has been updated; rejection must
                # come from its schema or binding, not from a stale digest.
                fixture.refresh_digest("interface_sha256", fixture.interface_path)
                self.assert_runtime_rejected(fixture)

    def test_interface_identity_and_complete_selector_set_are_required(self) -> None:
        changes = (
            ("bool size", lambda value: value["runtime"]["file_identity"].update(size=True)),
            ("wrong mode", lambda value: value["runtime"]["file_identity"].update(mode=0o100644)),
            ("relative path", lambda value: value["runtime"].update(path="bin/aros")),
            ("noncanonical path", lambda value: value["runtime"].update(path="/tmp//runtime/aros")),
            ("limitations removed", lambda value: value.update(limitations=[])),
            ("missing check", lambda value: value["checks"].pop()),
            ("failed check", lambda value: value["checks"][1].update(result="failed")),
            ("missing option", lambda value: value["checks"][1]["checked_selectors"]["required_options"].pop()),
        )
        for label, mutate in changes:
            with self.subTest(label=label):
                fixture = self.fixture()
                interface = fixture.interface_receipt()
                mutate(interface)
                fixture.write_interface(interface)
                fixture.refresh_digest("interface_sha256", fixture.interface_path)
                with self.assertRaises(start.StartError):
                    fixture.verify()

    def test_late_evidence_replacement_is_rejected_by_readback(self) -> None:
        for name in ("lock_path", "receipt_path", "interface_path"):
            with self.subTest(name=name):
                fixture = self.fixture()
                real_held = start.INTERFACE.HeldExecutable

                def replace_after_open(*args, **kwargs):
                    held = real_held(*args, **kwargs)
                    path = getattr(fixture, name)
                    path.write_bytes(path.read_bytes() + b" ")
                    return held

                with mock.patch.object(start.INTERFACE, "HeldExecutable", side_effect=replace_after_open), \
                        self.assertRaisesRegex(start.StartError, "evidence changed during verification"):
                    fixture.verify()

    def test_original_interface_path_is_not_executed_on_the_reader(self) -> None:
        fixture = self.fixture()
        interface = fixture.interface_receipt()
        interface["runtime"]["path"] = "/unused-original-start-root/bin/aros"
        fixture.write_interface(interface)
        fixture.refresh_digest("interface_sha256", fixture.interface_path)
        with mock.patch.object(start.INTERFACE, "HeldExecutable",
                               wraps=start.INTERFACE.HeldExecutable) as held:
            fixture.verify()
        held.assert_called_once_with(fixture.executable_path.absolute(),
                                     fixture.record["runtime"]["executable_sha256"])

    def test_frozen_closure_never_reopens_the_lock_or_changes_modes(self) -> None:
        fixture = self.fixture()
        original_modes = {path: path.stat().st_mode for path in fixture.directory.rglob("*")}
        with mock.patch.object(start.RUNTIME, "read_json",
                               side_effect=AssertionError("lock pathname reopened")), \
                mock.patch.object(start.RUNTIME, "sha256_file",
                                  side_effect=AssertionError("pathname hashing used")), \
                mock.patch.object(start.RUNTIME.os, "fchmod",
                                  side_effect=AssertionError("verification changed a mode")):
            start.RUNTIME.verify_extracted_frozen(fixture.lock, fixture.record["runtime"]["lock_sha256"],
                                                  fixture.host, fixture.directory)
        self.assertEqual(original_modes,
                         {path: path.stat().st_mode for path in fixture.directory.rglob("*")})

    def test_late_other_payload_mutation_is_rejected_by_held_closure_recheck(self) -> None:
        fixture = self.fixture()
        real_hash = start.RUNTIME._hash_fd
        modified = False

        def mutate_after_first_hash(fd, label, **kwargs):
            nonlocal modified
            result = real_hash(fd, label, **kwargs)
            if label == "README.md" and not modified:
                modified = True
                path = fixture.directory / label
                data = path.read_bytes()
                path.write_bytes(bytes([data[0] ^ 1]) + data[1:])
            return result

        with mock.patch.object(start.RUNTIME, "_hash_fd", side_effect=mutate_after_first_hash), \
                self.assertRaisesRegex(start.RUNTIME.RuntimeError, "differs from signed manifest"):
            fixture.verify()
        self.assertTrue(modified)

    def test_change_after_an_early_final_hash_is_rejected_by_final_state_check(self) -> None:
        fixture = self.fixture()
        real_hash = start.RUNTIME._hash_fd
        reads = 0

        def mutate_after_second_hash(fd, label, **kwargs):
            nonlocal reads
            result = real_hash(fd, label, **kwargs)
            if label == "LICENSE":
                reads += 1
                if reads == 2:
                    path = fixture.directory / label
                    data = path.read_bytes()
                    path.write_bytes(bytes([data[0] ^ 1]) + data[1:])
            return result

        with mock.patch.object(start.RUNTIME, "_hash_fd", side_effect=mutate_after_second_hash), \
                self.assertRaisesRegex(start.RUNTIME.RuntimeError, "changed during frozen closure verification"):
            fixture.verify()
        self.assertEqual(reads, 2)

    def test_added_entry_during_final_hashes_is_rejected_by_directory_readback(self) -> None:
        fixture = self.fixture()
        real_hash = start.RUNTIME._hash_fd
        reads = 0

        def add_after_second_hash(fd, label, **kwargs):
            nonlocal reads
            result = real_hash(fd, label, **kwargs)
            if label == "LICENSE":
                reads += 1
                if reads == 2:
                    (fixture.directory / "unlisted-during-inspection").write_bytes(b"unexpected\n")
            return result

        with mock.patch.object(start.RUNTIME, "_hash_fd", side_effect=add_after_second_hash), \
                self.assertRaisesRegex(start.RUNTIME.RuntimeError, "file set differs"):
            fixture.verify()
        self.assertEqual(reads, 2)

    def test_runtime_closure_rejects_symlink_roots_and_unlisted_files(self) -> None:
        linked = self.fixture()
        real_directory = linked.root / "runtime-real"
        linked.directory.rename(real_directory)
        linked.directory = linked.root / "runtime-link"
        linked.directory.symlink_to(real_directory, target_is_directory=True)
        self.assert_runtime_rejected(linked)

        extra = self.fixture()
        (extra.directory / "unlisted-runtime-file").write_bytes(b"outside the manifest\n")
        self.assert_runtime_rejected(extra)


if __name__ == "__main__":
    unittest.main(verbosity=2)
