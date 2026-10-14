#!/usr/bin/env python3
"""Offline tests for the inactive dispatch-claim payload codec."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock


SOURCE_ROOT = Path(__file__).resolve().parents[3]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


start_tests = load_module(
    "compiler_sdk_release_start_test_fixture_v2",
    SOURCE_ROOT / "scripts/toolchain/tests/test-compiler-sdk-release-start-v2.py",
)
claim = load_module(
    "compiler_sdk_dispatch_claim_v2",
    SOURCE_ROOT / "scripts/toolchain/compiler-sdk-dispatch-claim-v2.py",
)


class DispatchClaimCodecTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.record, cls.source_context, _ = start_tests.record_fixture()
        cls.record_bytes = (claim.START.ADMISSION.canonical_json(cls.record).encode("ascii") + b"\n")
        cls.bundle_bytes = b"synthetic Sigstore bundle fixture; verifier is not invoked\n"
        cls.dispatcher_context = {
            "repository": cls.source_context["repository"],
            "repository_id": cls.source_context["repository_id"],
            # The dispatcher workflow executes on main; its code revision need
            # not equal the producer commit selected by the signed start.
            "producer_commit": "9" * 40,
            "source_ref": "refs/heads/main",
            "workflow": claim.WORKFLOW,
            "run_id": cls.source_context["run_id"] + 1,
            "run_attempt": 1,
        }
        cls.dispatcher_job = {
            "id": 90902,
            "check_run_id": 555002,
            "name": claim.JOB,
        }
        cls.raw = claim.claim_bytes(
            cls.record_bytes,
            cls.bundle_bytes,
            source_context=cls.source_context,
            dispatcher_context=cls.dispatcher_context,
            dispatcher_job=cls.dispatcher_job,
            dispatcher_event="workflow_run", trigger_context=cls.source_context,
        )
        cls.value = claim.START.ADMISSION.parse_json(cls.raw, "test dispatch claim")

    def encode(self, value: dict) -> bytes:
        return (claim.START.ADMISSION.canonical_json(value) + "\n").encode("ascii")

    def assert_codec_rejected(self, message: str, callback) -> None:
        errors = (claim.START.StartError, claim.START.ORIGIN.OriginError,
                  claim.START.ADMISSION.AdmissionError)
        with self.assertRaises(errors) as raised:
            callback()
        self.assertRegex(str(raised.exception), message)

    def call_claim_bytes(self, *, record_bytes: bytes | None = None,
                         bundle_bytes: bytes | None = None,
                         source_context: dict | None = None,
                         dispatcher_context: dict | None = None,
                         dispatcher_job: dict | None = None,
                         dispatcher_event: str = "workflow_run", trigger_context: dict | None = None) -> bytes:
        return claim.claim_bytes(
            self.record_bytes if record_bytes is None else record_bytes,
            self.bundle_bytes if bundle_bytes is None else bundle_bytes,
            source_context=self.source_context if source_context is None else source_context,
            dispatcher_context=(self.dispatcher_context if dispatcher_context is None
                                else dispatcher_context),
            dispatcher_job=self.dispatcher_job if dispatcher_job is None else dispatcher_job,
            dispatcher_event=dispatcher_event,
            trigger_context=self.source_context if trigger_context is None else trigger_context,
        )

    def call_validate_claim(self, raw: bytes, *, record_bytes: bytes | None = None,
                            bundle_bytes: bytes | None = None,
                            source_context: dict | None = None,
                            dispatcher_context: dict | None = None,
                            dispatcher_job: dict | None = None,
                            dispatcher_event: str = "workflow_run", trigger_context: dict | None = None) -> dict:
        return claim.validate_claim(
            raw,
            self.record_bytes if record_bytes is None else record_bytes,
            self.bundle_bytes if bundle_bytes is None else bundle_bytes,
            source_context=self.source_context if source_context is None else source_context,
            dispatcher_context=(self.dispatcher_context if dispatcher_context is None
                                else dispatcher_context),
            dispatcher_job=self.dispatcher_job if dispatcher_job is None else dispatcher_job,
            dispatcher_event=dispatcher_event,
            trigger_context=self.source_context if trigger_context is None else trigger_context,
        )

    def test_canonical_payload_round_trips_selected_start_and_dispatcher(self) -> None:
        self.assertEqual(self.raw, self.call_claim_bytes())
        self.assertEqual(self.raw, self.encode(self.value))
        self.assertEqual(self.call_validate_claim(self.raw), self.value)
        self.assertEqual(self.value["assurance"], claim.ASSURANCE)
        self.assertEqual(self.value["start"]["record_sha256"],
                         hashlib.sha256(self.record_bytes).hexdigest())
        self.assertEqual(self.value["start"]["bundle_sha256"],
                         hashlib.sha256(self.bundle_bytes).hexdigest())
        self.assertEqual(self.value["dispatcher"]["context"], self.dispatcher_context)
        self.assertEqual(self.value["dispatcher"]["job"], self.dispatcher_job)
        self.assertEqual(self.value["dispatcher"]["trigger_context"], self.source_context)
        self.assertEqual(self.value["name"], "compiler-sdk-dispatch-claim-v2.json")
        self.assertEqual(self.value["native"], {
            "workflow": ".github/workflows/toolchain-release.yml", "event": "workflow_dispatch",
            "source_ref": f'refs/tags/{self.record["tag"]["name"]}',
            "producer_commit": self.record["tag"]["commit"],
        })
        self.assertNotEqual(self.value["native"]["producer_commit"],
                            self.dispatcher_context["producer_commit"])

    def test_codec_does_not_call_provider_subprocess_or_file_write_helpers(self) -> None:
        with mock.patch.object(claim.START.ADMISSION, "api",
                               side_effect=AssertionError("provider API helper called")) as api, \
                mock.patch.object(claim.START.ORIGIN, "gh_json",
                                  side_effect=AssertionError("gh helper called")) as gh, \
                mock.patch.object(claim.START, "bounded_gh",
                                  side_effect=AssertionError("signature subprocess helper called")) as bounded_gh, \
                mock.patch.object(claim.START.RUNTIME, "run",
                                  side_effect=AssertionError("runtime subprocess helper called")) as runtime_run, \
                mock.patch.object(claim.START.RUNTIME.subprocess, "run",
                                  side_effect=AssertionError("subprocess.run called")) as subprocess_run, \
                mock.patch.object(claim.START.RUNTIME.subprocess, "Popen",
                                  side_effect=AssertionError("subprocess.Popen called")) as subprocess_popen, \
                mock.patch.object(Path, "write_bytes",
                                  side_effect=AssertionError("Path.write_bytes called")) as write_bytes, \
                mock.patch.object(Path, "write_text",
                                  side_effect=AssertionError("Path.write_text called")) as write_text:
            encoded = self.call_claim_bytes()
            self.assertEqual(self.call_validate_claim(encoded), self.value)

        for helper in (api, gh, bounded_gh, runtime_run, subprocess_run,
                       subprocess_popen, write_bytes, write_text):
            helper.assert_not_called()

    def test_valid_start_metadata_or_bundle_byte_changes_invalidate_prior_claim(self) -> None:
        changed_record = copy.deepcopy(self.record)
        changed_record["runtime"]["receipt_sha256"] = "9" * 64
        changed_record_bytes = self.encode(changed_record)
        # This is a structurally valid start with changed signed metadata.
        claim.START.validate_start(
            claim.START.ADMISSION.parse_json(changed_record_bytes, "changed test start"),
            self.source_context,
        )
        self.assert_codec_rejected(
            "claim payload differs from the exact selected start and dispatcher",
            lambda: self.call_validate_claim(self.raw, record_bytes=changed_record_bytes),
        )

        changed_bundle = self.bundle_bytes + b"changed\n"
        self.assert_codec_rejected(
            "claim payload differs from the exact selected start and dispatcher",
            lambda: self.call_validate_claim(self.raw, bundle_bytes=changed_bundle),
        )

    def test_changed_independent_source_context_is_rejected_at_start_join(self) -> None:
        changed_source = copy.deepcopy(self.source_context)
        changed_source["run_id"] += 1
        self.assert_codec_rejected(
            "start record context differs from independent source selection",
            lambda: self.call_validate_claim(self.raw, source_context=changed_source),
        )

    def test_changed_dispatcher_context_and_job_invalidate_prior_claim(self) -> None:
        changed_context = copy.deepcopy(self.dispatcher_context)
        changed_context["run_id"] += 1
        self.assert_codec_rejected(
            "claim payload differs from the exact selected start and dispatcher",
            lambda: self.call_validate_claim(self.raw, dispatcher_context=changed_context),
        )

        changed_job = copy.deepcopy(self.dispatcher_job)
        changed_job["id"] += 1
        changed_job["check_run_id"] += 1
        self.assert_codec_rejected(
            "claim payload differs from the exact selected start and dispatcher",
            lambda: self.call_validate_claim(self.raw, dispatcher_job=changed_job),
        )

    def test_candidate_tag_draft_input_and_runtime_projections_are_closed(self) -> None:
        mutations = {
            "tag": lambda candidate: candidate["tag"].update(name="v1.2.4"),
            "draft": lambda candidate: candidate["draft"].update(id=667003),
            "inputs": lambda candidate: candidate["inputs"].update(
                {"version.txt": "1" * 64}),
            "runtime": lambda candidate: candidate["runtime"].update(
                receipt_sha256="2" * 64),
        }
        for label, mutate in mutations.items():
            with self.subTest(projection=label):
                changed = copy.deepcopy(self.value)
                mutate(changed["candidate"])
                self.assert_codec_rejected(
                    "claim payload differs from the exact selected start and dispatcher",
                    lambda changed=changed: self.call_validate_claim(self.encode(changed)),
                )

    def test_native_event_ref_and_producer_are_not_substituted_by_dispatcher_code(self) -> None:
        for key, value in (("event", "push"), ("source_ref", "refs/heads/main"),
                           ("producer_commit", self.dispatcher_context["producer_commit"]),
                           ("workflow", ".github/workflows/ci.yml")):
            with self.subTest(field=key):
                changed = copy.deepcopy(self.value)
                changed["native"][key] = value
                self.assert_codec_rejected(
                    "claim payload differs from the exact selected start and dispatcher",
                    lambda: self.call_validate_claim(self.encode(changed)),
                )

    def test_encoder_rejects_an_oversize_claim_before_it_can_be_retained(self) -> None:
        with mock.patch.object(claim.START.ADMISSION, "canonical_json",
                               return_value="x" * (claim.START.MAX_RECORD + 1)):
            self.assert_codec_rejected("encoded claim exceeds its metadata limit", self.call_claim_bytes)

    def test_actual_event_and_complete_trigger_edge_are_required(self) -> None:
        for event in ("push", "workflow_dispatch", "pull_request"):
            with self.subTest(event=event):
                self.assert_codec_rejected(
                    "claim dispatcher event or triggering start context differs",
                    lambda: self.call_claim_bytes(dispatcher_event=event),
                )
        for key, value in (("run_id", self.source_context["run_id"] + 10), ("run_attempt", 2),
                           ("producer_commit", "c" * 40), ("source_ref", "refs/heads/other")):
            with self.subTest(trigger=key):
                trigger = copy.deepcopy(self.source_context)
                trigger[key] = value
                self.assert_codec_rejected(
                    "claim dispatcher event or triggering start context differs",
                    lambda: self.call_claim_bytes(trigger_context=trigger),
                )

    def test_unknown_fields_and_noncanonical_whitespace_are_rejected(self) -> None:
        extra_top_level = copy.deepcopy(self.value)
        extra_top_level["unrecognized"] = "extra"
        extra_candidate = copy.deepcopy(self.value)
        extra_candidate["candidate"]["unrecognized"] = "extra"
        for label, changed in (("top-level", extra_top_level), ("candidate", extra_candidate)):
            with self.subTest(location=label):
                self.assert_codec_rejected(
                    "claim payload differs from the exact selected start and dispatcher",
                    lambda changed=changed: self.call_validate_claim(self.encode(changed)),
                )

        self.assert_codec_rejected(
            "claim payload differs from the exact selected start and dispatcher",
            lambda: self.call_validate_claim(self.raw + b"  \n"),
        )

    def test_dispatcher_must_be_the_distinct_original_protected_main_run(self) -> None:
        invalid_contexts = {
            "wrong workflow": {"workflow": claim.START.WORKFLOW},
            "wrong ref": {"source_ref": "refs/heads/feature"},
            "wrong repository": {"repository": "fork/aros-toolchains",
                                 "repository_id": self.source_context["repository_id"] + 1},
            "reused source run": {"run_id": self.source_context["run_id"]},
            "non-original attempt": {"run_attempt": 2},
        }
        for label, overrides in invalid_contexts.items():
            with self.subTest(context=label):
                changed = copy.deepcopy(self.dispatcher_context)
                changed.update(overrides)
                self.assert_codec_rejected(
                    "claim dispatcher is not a distinct original protected-main workflow",
                    lambda changed=changed: self.call_claim_bytes(dispatcher_context=changed),
                )

    def test_boolean_provider_and_job_ids_are_rejected_as_integers(self) -> None:
        for key in ("repository_id", "run_id", "run_attempt"):
            with self.subTest(context_id=key):
                changed = copy.deepcopy(self.dispatcher_context)
                changed[key] = True
                self.assert_codec_rejected(
                    "selected provider identity is not an integer",
                    lambda changed=changed: self.call_claim_bytes(dispatcher_context=changed),
                )

        for key in ("id", "check_run_id"):
            with self.subTest(dispatcher_job_id=key):
                changed = copy.deepcopy(self.dispatcher_job)
                changed[key] = True
                self.assert_codec_rejected(
                    "claim dispatcher .* is not a positive u64 integer",
                    lambda changed=changed: self.call_claim_bytes(dispatcher_job=changed),
                )

        changed_record = copy.deepcopy(self.record)
        changed_record["job"]["id"] = True
        changed_record_bytes = self.encode(changed_record)
        self.assert_codec_rejected(
            "start job id is not a positive u64 integer",
            lambda: self.call_claim_bytes(record_bytes=changed_record_bytes),
        )

    def test_dispatcher_job_cannot_reuse_start_owner_or_check_run(self) -> None:
        for key in ("id", "check_run_id"):
            with self.subTest(reused=key):
                changed = copy.deepcopy(self.dispatcher_job)
                changed[key] = self.record["job"][key]
                self.assert_codec_rejected(
                    "claim dispatcher job differs or reuses the start owner",
                    lambda changed=changed: self.call_claim_bytes(dispatcher_job=changed),
                )

    def test_record_bundle_and_claim_byte_bounds_are_enforced(self) -> None:
        self.assert_codec_rejected(
            "claim requires bounded original start bytes",
            lambda: self.call_claim_bytes(record_bytes=b"x" * (claim.START.MAX_RECORD + 1)),
        )
        self.assert_codec_rejected(
            "claim requires bounded original signature bytes",
            lambda: self.call_claim_bytes(bundle_bytes=b"x" * (claim.START.MAX_BUNDLE + 1)),
        )
        self.assert_codec_rejected(
            "claim payload is not bounded bytes",
            lambda: self.call_validate_claim(b"x" * (claim.START.MAX_RECORD + 1)),
        )
        self.assert_codec_rejected(
            "claim requires bounded original start bytes",
            lambda: self.call_claim_bytes(record_bytes=b""),
        )
        self.assert_codec_rejected(
            "claim requires bounded original signature bytes",
            lambda: self.call_claim_bytes(bundle_bytes=b""),
        )
        self.assert_codec_rejected(
            "claim payload is not bounded bytes",
            lambda: self.call_validate_claim(b""),
        )


class DispatcherClaimSignatureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.record, cls.source_context, _ = start_tests.record_fixture()
        cls.record_bytes = (claim.START.ADMISSION.canonical_json(cls.record).encode("ascii") + b"\n")
        cls.start_bundle_bytes = b"synthetic original start signature bundle\n"
        cls.dispatcher_context = {
            "repository": cls.source_context["repository"],
            "repository_id": cls.source_context["repository_id"],
            "producer_commit": "9" * 40,
            "source_ref": claim.START.ADMISSION.MAIN_REF,
            "workflow": claim.WORKFLOW,
            "run_id": cls.source_context["run_id"] + 1,
            "run_attempt": 1,
        }
        cls.dispatcher_job = {"id": 90902, "check_run_id": 555002, "name": claim.JOB}
        cls.raw_claim = claim.claim_bytes(
            cls.record_bytes, cls.start_bundle_bytes,
            source_context=cls.source_context,
            dispatcher_context=cls.dispatcher_context,
            dispatcher_job=cls.dispatcher_job,
            dispatcher_event="workflow_run", trigger_context=cls.source_context,
        )
        cls.signature_bytes = b"synthetic dispatcher Sigstore bundle\n"

    def setUp(self) -> None:
        # The safe input reader rejects any symlinked ancestor. Place fixtures
        # under this checkout rather than macOS /var/folders, which may resolve
        # through a system symlink.
        temporary = tempfile.TemporaryDirectory(prefix=".dispatch-claim-signature-test.",
                                                dir=SOURCE_ROOT)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.claim_path = self.root / claim.CLAIM_NAME
        self.signature_path = self.root / "claim.sigstore.json"
        self.claim_path.write_bytes(self.raw_claim)
        self.signature_path.write_bytes(self.signature_bytes)

        self.reset_provider_observations()
        self.signature_result = [{
            "verificationResult": {
                "signature": {"certificate": {"runInvocationURI": self.invocation_uri()}},
                "statement": {"subject": [{
                    "name": claim.CLAIM_NAME,
                    "digest": {"sha256": hashlib.sha256(self.raw_claim).hexdigest()},
                }]},
            },
        }]
        self.mutate_inputs_during_verify = False

    def reset_provider_observations(self) -> None:
        self.dispatcher_attempt = start_tests.provider_run(self.dispatcher_context)
        self.dispatcher_latest = start_tests.provider_run(self.dispatcher_context)
        self.dispatcher_event_run = start_tests.provider_run(self.dispatcher_context)
        self.dispatcher_provider_job = start_tests.provider_job(
            self.dispatcher_context,
            job_id=self.dispatcher_job["id"],
            check_id=self.dispatcher_job["check_run_id"],
            name=claim.JOB,
        )
        self.api_calls: list[tuple[str, dict]] = []
        self.origin_calls: list[tuple[list[str], str]] = []
        self.signature_calls: list[tuple[list[str], str]] = []

    def invocation_uri(self) -> str:
        return (f'https://github.com/{self.dispatcher_context["repository"]}/actions/runs/'
                f'{self.dispatcher_context["run_id"]}/attempts/1')

    def valid_environment(self) -> dict[str, str]:
        return {"GH_HOST": "github.com", "GH_TOKEN": "synthetic-job-token"}

    def api_observer(self, path: str, **kwargs):
        self.api_calls.append((path, kwargs))
        if kwargs:
            raise AssertionError(f"dispatcher verifier used unsupported API options: {kwargs!r}")
        repository = self.dispatcher_context["repository"]
        run_id = self.dispatcher_context["run_id"]
        if path == f"repos/{repository}/actions/runs/{run_id}/attempts/1":
            return copy.deepcopy(self.dispatcher_attempt)
        if path == f"repos/{repository}/actions/runs/{run_id}":
            return copy.deepcopy(self.dispatcher_latest)
        raise AssertionError(f"unexpected dispatcher metadata endpoint: {path!r}")

    def origin_observer(self, arguments: list[str], purpose: str = "GitHub observation"):
        selected = list(arguments)
        self.origin_calls.append((selected, purpose))
        repository = self.dispatcher_context["repository"]
        run_id = self.dispatcher_context["run_id"]
        attempt_path = f"repos/{repository}/actions/runs/{run_id}/attempts/1"
        if selected == ["api", attempt_path]:
            return copy.deepcopy(self.dispatcher_event_run)
        jobs_path = f"{attempt_path}/jobs?per_page=100"
        if selected == ["api", "--paginate", "--slurp", jobs_path]:
            return [{"total_count": 1, "jobs": [copy.deepcopy(self.dispatcher_provider_job)]}]
        raise AssertionError(f"unexpected dispatcher provider selector: {selected!r}")

    def signature_verifier(self, arguments: list[str], purpose: str = "start provider observation"):
        selected = list(arguments)
        self.signature_calls.append((selected, purpose))
        subject = Path(selected[2])
        bundle = Path(selected[4])
        self.assertEqual(purpose, "dispatcher claim signature authentication")
        self.assertEqual(subject.name, claim.CLAIM_NAME)
        self.assertEqual(subject.read_bytes(), self.raw_claim)
        self.assertEqual(bundle.read_bytes(), self.signature_bytes)
        self.assertEqual(stat.S_IMODE(subject.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(subject.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(bundle.stat().st_mode), 0o600)
        repository = self.dispatcher_context["repository"]
        commit = self.dispatcher_context["producer_commit"]
        self.assertEqual(selected, [
            "attestation", "verify", str(subject), "--bundle", str(bundle),
            "--hostname", "github.com", "--repo", repository,
            "--signer-workflow", f"{repository}/{claim.WORKFLOW}",
            "--signer-digest", commit, "--source-digest", commit,
            "--source-ref", claim.START.ADMISSION.MAIN_REF,
            "--deny-self-hosted-runners", "--format", "json",
        ])
        if self.mutate_inputs_during_verify:
            self.claim_path.write_bytes(b"substituted claim after private copy\n")
            self.signature_path.write_bytes(b"substituted bundle after private copy\n")
            # gh verifies the selected private copies, not the caller paths.
            self.assertEqual(subject.read_bytes(), self.raw_claim)
            self.assertEqual(bundle.read_bytes(), self.signature_bytes)
        return copy.deepcopy(self.signature_result)

    def invoke(self, *, environment: dict[str, str] | None = None,
               expected_claim_sha256: str | None = None,
               expected_signature_sha256: str | None = None) -> dict:
        environment = self.valid_environment() if environment is None else environment
        with mock.patch.object(claim.START.ADMISSION, "api", side_effect=self.api_observer), \
                mock.patch.object(claim.START.ORIGIN, "gh_json", side_effect=self.origin_observer), \
                mock.patch.object(claim.START, "bounded_gh", side_effect=self.signature_verifier), \
                mock.patch.dict(os.environ, environment, clear=True):
            return claim.verify_dispatcher_claim_signature(
                self.claim_path, self.signature_path,
                record_bytes=self.record_bytes, start_bundle_bytes=self.start_bundle_bytes,
                source_context=self.source_context,
                dispatcher_context=self.dispatcher_context,
                dispatcher_job=self.dispatcher_job,
                expected_claim_sha256=(expected_claim_sha256 or hashlib.sha256(self.raw_claim).hexdigest()),
                expected_signature_sha256=(expected_signature_sha256
                                           or hashlib.sha256(self.signature_bytes).hexdigest()),
            )

    def assert_rejected(self, pattern: str, **kwargs) -> None:
        errors = (claim.START.StartError, claim.START.ADMISSION.AdmissionError,
                  claim.START.ORIGIN.OriginError)
        with self.assertRaises(errors) as raised:
            self.invoke(**kwargs)
        self.assertRegex(str(raised.exception), pattern)

    def test_original_dispatcher_claim_is_closed_and_signed_by_the_exact_run(self) -> None:
        selected = self.invoke()
        self.assertEqual(selected, claim.START.ADMISSION.parse_json(self.raw_claim, "verified claim"))
        self.assertEqual(len(self.api_calls), 4)
        self.assertEqual(len(self.origin_calls), 4)
        self.assertEqual(len(self.signature_calls), 1)
        self.assertTrue(all(not options for _, options in self.api_calls))
        repository = self.dispatcher_context["repository"]
        run_id = self.dispatcher_context["run_id"]
        attempt_path = f"repos/{repository}/actions/runs/{run_id}/attempts/1"
        self.assertEqual([arguments for arguments, _ in self.origin_calls], [
            ["api", attempt_path],
            ["api", "--paginate", "--slurp", f"{attempt_path}/jobs?per_page=100"],
        ] * 2)
        self.assertTrue(all(arguments[0] == "attestation" and arguments[1] == "verify"
                            for arguments, _ in self.signature_calls))

    def test_fixed_host_and_job_token_are_required_before_any_observation(self) -> None:
        for label, environment in (
            ("wrong host", {"GH_HOST": "api.github.com", "GH_TOKEN": "synthetic-job-token"}),
            ("missing host", {"GH_TOKEN": "synthetic-job-token"}),
            ("missing token", {"GH_HOST": "github.com"}),
            ("empty token", {"GH_HOST": "github.com", "GH_TOKEN": ""}),
        ):
            with self.subTest(case=label):
                with self.assertRaisesRegex(claim.START.StartError, "fixed-host job token"):
                    self.invoke(environment=environment)
                self.assertEqual(self.api_calls, [])
                self.assertEqual(self.origin_calls, [])
                self.assertEqual(self.signature_calls, [])

    def test_claim_and_signature_byte_pins_must_match_before_provider_reads(self) -> None:
        for label, kwargs in (
            ("claim", {"expected_claim_sha256": "0" * 64}),
            ("signature", {"expected_signature_sha256": "0" * 64}),
        ):
            with self.subTest(pin=label):
                with self.assertRaisesRegex(claim.START.StartError,
                                            "claim or signature differs from selected bytes"):
                    self.invoke(**kwargs)
                self.assertEqual(self.api_calls, [])
                self.assertEqual(self.origin_calls, [])
                self.assertEqual(self.signature_calls, [])

    def test_subject_name_must_be_fixed_and_inputs_must_be_unlinked_regular_files(self) -> None:
        wrong_name = self.root / "other-claim.json"
        wrong_name.write_bytes(self.raw_claim)
        self.claim_path = wrong_name
        with self.assertRaisesRegex(claim.START.StartError, "subject or separate signature path differs"):
            self.invoke()
        self.assertEqual(self.api_calls, [])
        self.assertEqual(self.origin_calls, [])

        self.claim_path = self.root / claim.CLAIM_NAME
        self.claim_path.unlink()
        linked_target = self.root / "linked-claim-target.json"
        linked_target.write_bytes(self.raw_claim)
        self.claim_path.symlink_to(linked_target)
        with self.assertRaises((claim.START.ADMISSION.AdmissionError, OSError)):
            self.invoke()
        self.claim_path.unlink()

        self.claim_path.write_bytes(self.raw_claim)
        self.signature_path.unlink()
        signature_target = self.root / "linked-signature-target.json"
        signature_target.write_bytes(self.signature_bytes)
        os.link(signature_target, self.signature_path)
        with self.assertRaisesRegex(claim.START.ADMISSION.AdmissionError,
                                    "singly-linked regular file"):
            self.invoke()
        self.assertEqual(self.api_calls, [])
        self.assertEqual(self.origin_calls, [])
        self.assertEqual(self.signature_calls, [])

    def test_signature_result_must_be_unique_well_formed_and_bind_invocation_subject(self) -> None:
        valid = copy.deepcopy(self.signature_result[0])
        changes = (
            ("empty", [], "exactly one verified signature"),
            ("multiple", [copy.deepcopy(valid), copy.deepcopy(valid)],
             "exactly one verified signature"),
            ("malformed", {"verificationResult": {}}, "exactly one verified signature"),
        )
        for label, result, message in changes:
            with self.subTest(result=label):
                self.signature_result = copy.deepcopy(result)
                self.assert_rejected(message)

        bad_invocation = copy.deepcopy(valid)
        bad_invocation["verificationResult"]["signature"]["certificate"]["runInvocationURI"] = (
            self.invocation_uri().rsplit("/", 1)[0] + "/attempts/2"
        )
        bad_subject_name = copy.deepcopy(valid)
        bad_subject_name["verificationResult"]["statement"]["subject"][0]["name"] = "other.json"
        bad_subject_digest = copy.deepcopy(valid)
        bad_subject_digest["verificationResult"]["statement"]["subject"][0]["digest"]["sha256"] = "0" * 64
        for label, result, message in (
            ("invocation", [bad_invocation], "belongs to another original attempt"),
            ("subject name", [bad_subject_name], "signature subject differs"),
            ("subject digest", [bad_subject_digest], "signature subject differs"),
        ):
            with self.subTest(binding=label):
                self.signature_result = copy.deepcopy(result)
                self.assert_rejected(message)

    def test_provider_attempt_run_workflow_repository_and_owning_job_are_rechecked(self) -> None:
        cases = (
            ("failed attempt", "original start attempt is incomplete or unsuccessful",
             "dispatcher_attempt", "conclusion", "failure"),
            ("rerun", "start run was rerun", "dispatcher_latest", "run_attempt", 2),
            ("wrong workflow", "provider run workflow path differs", "dispatcher_event_run", "path",
             ".github/workflows/other.yml@refs/heads/main"),
        )
        for label, message, target, key, value in cases:
            with self.subTest(provider=label):
                setattr(self, target, {**getattr(self, target), key: value})
                self.assert_rejected(message)
                self.reset_provider_observations()

        wrong_repo = copy.deepcopy(self.dispatcher_event_run)
        wrong_repo["head_repository"] = {"id": self.dispatcher_context["repository_id"] + 1,
                                          "full_name": "other/aros-toolchains"}
        self.dispatcher_event_run = wrong_repo
        self.assert_rejected("provider run repository differs")
        self.reset_provider_observations()

        wrong_job = copy.deepcopy(self.dispatcher_provider_job)
        wrong_job["id"] += 1
        self.dispatcher_provider_job = wrong_job
        self.assert_rejected("source job ID/name does not select one provider job")
        self.reset_provider_observations()

        wrong_check = copy.deepcopy(self.dispatcher_provider_job)
        wrong_check["check_run_url"] = (
            f'https://api.github.com/repos/{self.dispatcher_context["repository"]}/check-runs/555003'
        )
        self.dispatcher_provider_job = wrong_check
        self.assert_rejected("dispatcher claim owning job differs")

    def test_verifier_uses_private_frozen_subject_when_original_inputs_change(self) -> None:
        self.mutate_inputs_during_verify = True
        self.assert_rejected("claim or signature changed during verification")
        self.assertEqual(self.signature_calls[0][0][1], "verify")
        self.assertNotEqual(self.claim_path.read_bytes(), self.raw_claim)
        self.assertNotEqual(self.signature_path.read_bytes(), self.signature_bytes)
        self.assertEqual(len(self.signature_calls), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
