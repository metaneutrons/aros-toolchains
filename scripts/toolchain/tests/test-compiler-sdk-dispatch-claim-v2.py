#!/usr/bin/env python3
"""Offline tests for the inactive dispatch-claim payload codec."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
from pathlib import Path
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
