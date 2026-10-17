#!/usr/bin/env python3
"""Offline tests for the bounded compiler/SDK dispatch binding codec."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
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


claim_fixture = load_module(
    "compiler_sdk_dispatch_binding_claim_fixture_v2",
    SOURCE_ROOT / "scripts/toolchain/tests/test-compiler-sdk-dispatch-claim-v2.py",
)
binding = load_module(
    "compiler_sdk_dispatch_binding_v2",
    SOURCE_ROOT / "scripts/toolchain/compiler-sdk-dispatch-binding-v2.py",
)


REPOSITORY = "metaneutrons/aros-toolchains"
MAX_SAFE_INTEGER = 9007199254740991
CONFIRMED_RUN_ID = 991001


class DispatchBindingCodecTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        # Reuse only the canonical fixture data. Do not inherit or execute the
        # prior suite's test methods.
        fixture_type = claim_fixture.DispatchClaimCodecTests
        fixture_type.setUpClass()
        cls.claim_raw = bytes(fixture_type.raw)
        cls.record_bytes = bytes(fixture_type.record_bytes)
        cls.start_bundle_bytes = bytes(fixture_type.bundle_bytes)
        cls.source_context = copy.deepcopy(fixture_type.source_context)
        cls.dispatcher_context = copy.deepcopy(fixture_type.dispatcher_context)
        cls.dispatcher_job = copy.deepcopy(fixture_type.dispatcher_job)
        cls.claim_value = copy.deepcopy(fixture_type.value)
        cls.claim_asset = {
            "id": 887766,
            "name": binding.CLAIM.CLAIM_NAME,
            "size": len(cls.claim_raw),
            "sha256": hashlib.sha256(cls.claim_raw).hexdigest(),
        }
        cls.claim_signature_bytes = b"synthetic claim signature fixture; not verified by this codec\n"
        cls.expected_claim_bundle_sha256 = hashlib.sha256(
            cls.claim_signature_bytes
        ).hexdigest()
        cls.response_value = cls.response_value_for(CONFIRMED_RUN_ID)
        cls.response_body = cls.encode_json(cls.response_value)
        cls.native_context = cls.native_context_for(CONFIRMED_RUN_ID)

    @staticmethod
    def encode_json(value: object) -> bytes:
        return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
                + "\n").encode("ascii")

    @classmethod
    def response_value_for(cls, run_id: object) -> dict:
        return {
            "workflow_run_id": run_id,
            "run_url": f"https://api.github.com/repos/{REPOSITORY}/actions/runs/{run_id}",
            "html_url": f"https://github.com/{REPOSITORY}/actions/runs/{run_id}",
        }

    @classmethod
    def native_context_for(cls, run_id: int) -> dict:
        native = cls.claim_value["native"]
        return {
            "repository": cls.source_context["repository"],
            "repository_id": cls.source_context["repository_id"],
            "producer_commit": native["producer_commit"],
            "source_ref": native["source_ref"],
            "workflow": native["workflow"],
            "run_id": run_id,
            "run_attempt": 1,
        }

    @classmethod
    def domain_errors(cls) -> tuple[type[BaseException], ...]:
        start = binding.START
        return (start.StartError, start.ORIGIN.OriginError, start.ADMISSION.AdmissionError)

    def assert_rejected(self, callback) -> None:
        with self.assertRaises(self.domain_errors()):
            callback()

    def call_confirmed_run(self, *, status: int = 200, raw: bytes | None = None) -> dict:
        return binding.confirmed_run(
            status,
            self.response_body if raw is None else raw,
        )

    def call_binding_bytes(
        self,
        *,
        claim_raw: bytes | None = None,
        record_bytes: bytes | None = None,
        start_bundle_bytes: bytes | None = None,
        source_context: dict | None = None,
        dispatcher_context: dict | None = None,
        dispatcher_job: dict | None = None,
        claim_asset: dict | None = None,
        expected_claim_bundle_sha256: str | None = None,
        response_status: int = 200,
        response_body: bytes | None = None,
    ) -> bytes:
        return binding.binding_bytes(
            self.claim_raw if claim_raw is None else claim_raw,
            self.record_bytes if record_bytes is None else record_bytes,
            self.start_bundle_bytes if start_bundle_bytes is None else start_bundle_bytes,
            source_context=(self.source_context if source_context is None else source_context),
            dispatcher_context=(self.dispatcher_context if dispatcher_context is None
                                else dispatcher_context),
            dispatcher_job=(self.dispatcher_job if dispatcher_job is None else dispatcher_job),
            claim_asset=(self.claim_asset if claim_asset is None else claim_asset),
            expected_claim_bundle_sha256=(
                self.expected_claim_bundle_sha256
                if expected_claim_bundle_sha256 is None else expected_claim_bundle_sha256
            ),
            response_status=response_status,
            response_body=self.response_body if response_body is None else response_body,
        )

    def call_validate_binding(
        self,
        raw: bytes,
        *,
        claim_raw: bytes | None = None,
        record_bytes: bytes | None = None,
        start_bundle_bytes: bytes | None = None,
        source_context: dict | None = None,
        dispatcher_context: dict | None = None,
        dispatcher_job: dict | None = None,
        claim_asset: dict | None = None,
        expected_claim_bundle_sha256: str | None = None,
        actual_native_context: dict | None = None,
        actual_native_event: str = "workflow_dispatch",
    ) -> dict:
        return binding.validate_binding(
            raw,
            self.claim_raw if claim_raw is None else claim_raw,
            self.record_bytes if record_bytes is None else record_bytes,
            self.start_bundle_bytes if start_bundle_bytes is None else start_bundle_bytes,
            source_context=(self.source_context if source_context is None else source_context),
            dispatcher_context=(self.dispatcher_context if dispatcher_context is None
                                else dispatcher_context),
            dispatcher_job=(self.dispatcher_job if dispatcher_job is None else dispatcher_job),
            claim_asset=(self.claim_asset if claim_asset is None else claim_asset),
            expected_claim_bundle_sha256=(
                self.expected_claim_bundle_sha256
                if expected_claim_bundle_sha256 is None else expected_claim_bundle_sha256
            ),
            actual_native_context=(
                self.native_context if actual_native_context is None else actual_native_context
            ),
            actual_native_event=actual_native_event,
        )

    def canonical_binding(self, raw: bytes) -> tuple[dict, bytes]:
        value = binding.START.ADMISSION.parse_json(raw, "test dispatch binding")
        encoded = (binding.START.ADMISSION.canonical_json(value) + "\n").encode("ascii")
        return value, encoded

    def test_confirmed_run_returns_only_canonical_run_identity_and_urls(self) -> None:
        result = self.call_confirmed_run()
        self.assertEqual(result, {
            "workflow_run_id": CONFIRMED_RUN_ID,
            "run_url": (
                f"https://api.github.com/repos/{REPOSITORY}/actions/runs/{CONFIRMED_RUN_ID}"
            ),
            "html_url": (
                f"https://github.com/{REPOSITORY}/actions/runs/{CONFIRMED_RUN_ID}"
            ),
        })
        self.assertEqual(set(result), {"workflow_run_id", "run_url", "html_url"})

    def test_confirmed_run_accepts_the_inclusive_safe_integer_boundary(self) -> None:
        value = self.response_value_for(MAX_SAFE_INTEGER)
        result = self.call_confirmed_run(raw=self.encode_json(value))
        self.assertEqual(result["workflow_run_id"], MAX_SAFE_INTEGER)
        self.assertEqual(
            result["run_url"],
            f"https://api.github.com/repos/{REPOSITORY}/actions/runs/{MAX_SAFE_INTEGER}",
        )

    def test_confirmed_run_requires_http_200(self) -> None:
        for status in (True, False, "200", 200.0, 0, 201, 202, 204, 301, 302, 307, 400, 401, 404, 500):
            with self.subTest(status=status):
                self.assert_rejected(
                    lambda status=status: self.call_confirmed_run(status=status)
                )

    def test_confirmed_run_requires_bounded_nonempty_bytes(self) -> None:
        for raw in (b"", "not bytes", bytearray(self.response_body)):
            with self.subTest(raw_type=type(raw).__name__, raw_length=len(raw)):
                self.assert_rejected(
                    lambda raw=raw: binding.confirmed_run(200, raw)
                )

        oversized = b"x" * (binding.MAX_RESPONSE + 1)
        self.assert_rejected(lambda: binding.confirmed_run(200, oversized))
        self.assertEqual(binding.MAX_RESPONSE, 4096)

    def test_valid_response_at_exact_byte_boundary_but_not_one_byte_over(self) -> None:
        raw = self.response_body + b" " * (binding.MAX_RESPONSE - len(self.response_body))
        self.assertEqual(len(raw), binding.MAX_RESPONSE)
        self.assertEqual(binding.confirmed_run(200, raw), self.response_value)
        with self.assertRaisesRegex(binding.START.StartError, "not bounded bytes"):
            binding.confirmed_run(200, raw + b" ")

    def test_constructor_rejects_reusing_start_or_dispatcher_run_before_signing_subject(self) -> None:
        for run_id in (self.source_context["run_id"], self.dispatcher_context["run_id"]):
            with self.subTest(run_id=run_id):
                response = self.encode_json(self.response_value_for(run_id))
                self.assertEqual(binding.confirmed_run(200, response)["workflow_run_id"], run_id)
                with self.assertRaisesRegex(binding.START.StartError, "original context differs"):
                    self.call_binding_bytes(response_body=response)

    def test_confirmed_run_rejects_duplicate_missing_extra_and_non_object_json(self) -> None:
        run_url = f"https://api.github.com/repos/{REPOSITORY}/actions/runs/{CONFIRMED_RUN_ID}"
        html_url = f"https://github.com/{REPOSITORY}/actions/runs/{CONFIRMED_RUN_ID}"
        duplicate = (
            f'{{"workflow_run_id":{CONFIRMED_RUN_ID},'
            f'"workflow_run_id":{CONFIRMED_RUN_ID},'
            f'"run_url":"{run_url}","html_url":"{html_url}"}}\n'
        ).encode("ascii")
        bodies = (
            duplicate,
            self.encode_json({"workflow_run_id": CONFIRMED_RUN_ID, "run_url": run_url}),
            self.encode_json({"workflow_run_id": CONFIRMED_RUN_ID, "run_url": run_url,
                              "html_url": html_url, "extra": "not allowed"}),
            self.encode_json({
                "id": CONFIRMED_RUN_ID,
                "url": run_url,
                "html_url": html_url,
            }),
            self.encode_json([CONFIRMED_RUN_ID, run_url, html_url]),
            self.encode_json(None),
            b"{",
        )
        for raw in bodies:
            with self.subTest(body=raw[:80]):
                self.assert_rejected(lambda raw=raw: binding.confirmed_run(200, raw))

    def test_confirmed_run_requires_an_exact_positive_safe_integer_id(self) -> None:
        invalid_ids = (
            True,
            False,
            0,
            -1,
            1.0,
            float(CONFIRMED_RUN_ID),
            str(CONFIRMED_RUN_ID),
            MAX_SAFE_INTEGER + 1,
        )
        for run_id in invalid_ids:
            with self.subTest(run_id=run_id, run_id_type=type(run_id).__name__):
                raw = self.encode_json(self.response_value_for(run_id))
                self.assert_rejected(lambda raw=raw: binding.confirmed_run(200, raw))

    def test_confirmed_run_rejects_wrong_noncanonical_or_mismatched_urls(self) -> None:
        good = self.response_value_for(CONFIRMED_RUN_ID)
        bad_values = []
        for key, invalid_url in (
            ("run_url", f"http://api.github.com/repos/{REPOSITORY}/actions/runs/{CONFIRMED_RUN_ID}"),
            ("run_url", f"https://api.github.com/repos/other/repo/actions/runs/{CONFIRMED_RUN_ID}"),
            ("run_url", f"https://api.github.com/repos/{REPOSITORY}/actions/runs/0991001"),
            ("run_url", f"https://api.github.com/repos/{REPOSITORY}/actions/runs/{CONFIRMED_RUN_ID + 1}"),
            ("run_url", f"https://api.github.com/repos/{REPOSITORY}/actions/runs/{CONFIRMED_RUN_ID}?x=1"),
            ("run_url", f"https://api.github.com/repos/{REPOSITORY}/actions/runs/{CONFIRMED_RUN_ID}/"),
            ("html_url", f"http://github.com/{REPOSITORY}/actions/runs/{CONFIRMED_RUN_ID}"),
            ("html_url", f"https://github.com/other/repo/actions/runs/{CONFIRMED_RUN_ID}"),
            ("html_url", f"https://github.com/{REPOSITORY}/actions/runs/{CONFIRMED_RUN_ID}#run"),
            ("html_url", f"https://github.com/{REPOSITORY}/actions/runs/{CONFIRMED_RUN_ID}?tab=jobs"),
        ):
            changed = copy.deepcopy(good)
            changed[key] = invalid_url
            bad_values.append((key, invalid_url, changed))

        changed_id = copy.deepcopy(good)
        changed_id["workflow_run_id"] = CONFIRMED_RUN_ID + 1
        bad_values.append(("id/url disagreement", None, changed_id))

        for label, invalid_url, value in bad_values:
            with self.subTest(field=label, url=invalid_url):
                self.assert_rejected(
                    lambda value=value: binding.confirmed_run(200, self.encode_json(value))
                )

    def test_binding_payload_is_canonical_and_validates_against_independent_native_context(self) -> None:
        self.assertEqual(binding.BINDING_NAME, "compiler-sdk-dispatch-binding-v2.json")
        self.assertEqual(
            binding.ASSURANCE,
            "dispatch-run-binding-payload-only-not-native-authority",
        )
        self.assertNotIn(self.native_context["run_id"], (
            self.source_context["run_id"], self.dispatcher_context["run_id"],
        ))

        raw = self.call_binding_bytes()
        value, canonical = self.canonical_binding(raw)
        self.assertEqual(raw, canonical)
        self.assertTrue(raw.endswith(b"\n"))
        self.assertEqual(binding.START.ADMISSION.canonical_json(value), raw[:-1].decode("ascii"))
        self.assertEqual(value["name"], binding.BINDING_NAME)
        self.assertEqual(value["assurance"], binding.ASSURANCE)
        self.assertEqual(set(value), {
            "schema", "assurance", "name", "start", "dispatcher", "candidate",
            "claim", "claim_bundle_sha256", "native",
        })
        self.assertEqual(value["schema"], "aros-toolchains-dispatch-binding-v2")
        self.assertEqual(value["start"], {
            "context": self.source_context,
            "job": claim_fixture.DispatchClaimCodecTests.record["job"],
            "record_sha256": hashlib.sha256(self.record_bytes).hexdigest(),
            "bundle_sha256": hashlib.sha256(self.start_bundle_bytes).hexdigest(),
        })
        self.assertEqual(value["dispatcher"], {
            "context": self.dispatcher_context,
            "event": "workflow_run",
            "trigger_context": self.source_context,
            "job": self.dispatcher_job,
        })
        self.assertEqual(value["candidate"], {
            "tag": claim_fixture.DispatchClaimCodecTests.record["tag"],
            "draft": claim_fixture.DispatchClaimCodecTests.record["draft"],
        })
        self.assertEqual(value["claim"], self.claim_asset)
        self.assertEqual(value["claim_bundle_sha256"], self.expected_claim_bundle_sha256)
        self.assertEqual(value["native"], {
            "context": self.native_context,
            "event": "workflow_dispatch",
            "response": self.response_value,
        })
        self.assertEqual(
            self.call_validate_binding(raw),
            value,
        )

    def test_codec_positive_path_calls_no_provider_subprocess_or_file_write_helpers(self) -> None:
        with mock.patch.object(binding.START.ADMISSION, "api",
                               side_effect=AssertionError("provider API helper called")) as api, \
                mock.patch.object(binding.START.ORIGIN, "gh_json",
                                  side_effect=AssertionError("provider JSON helper called")) as gh_json, \
                mock.patch.object(binding.START, "bounded_gh",
                                  side_effect=AssertionError("signature subprocess helper called")) as bounded_gh, \
                mock.patch.object(binding.START.RUNTIME, "run",
                                  side_effect=AssertionError("runtime subprocess helper called")) as runtime_run, \
                mock.patch.object(binding.START.RUNTIME.subprocess, "run",
                                  side_effect=AssertionError("subprocess.run called")) as subprocess_run, \
                mock.patch.object(binding.START.RUNTIME.subprocess, "Popen",
                                  side_effect=AssertionError("subprocess.Popen called")) as subprocess_popen, \
                mock.patch.object(Path, "write_bytes",
                                  side_effect=AssertionError("Path.write_bytes called")) as write_bytes, \
                mock.patch.object(Path, "write_text",
                                  side_effect=AssertionError("Path.write_text called")) as write_text:
            confirmed = self.call_confirmed_run()
            encoded = self.call_binding_bytes()
            validated = self.call_validate_binding(encoded)

        self.assertEqual(confirmed["workflow_run_id"], CONFIRMED_RUN_ID)
        self.assertEqual(validated, self.canonical_binding(encoded)[0])
        for helper in (api, gh_json, bounded_gh, runtime_run, subprocess_run,
                       subprocess_popen, write_bytes, write_text):
            helper.assert_not_called()

    def test_binding_bytes_rejects_claim_asset_metadata_drift_or_open_shape(self) -> None:
        mutations = {
            "boolean id": lambda asset: asset.update(id=True),
            "nonpositive id": lambda asset: asset.update(id=0),
            "wrong name": lambda asset: asset.update(name="different.json"),
            "wrong size": lambda asset: asset.update(size=asset["size"] + 1),
            "wrong digest": lambda asset: asset.update(sha256="0" * 64),
            "extra field": lambda asset: asset.update(unrecognized="extra"),
            "missing digest": lambda asset: asset.pop("sha256"),
        }
        for label, mutate in mutations.items():
            with self.subTest(asset=label):
                asset = copy.deepcopy(self.claim_asset)
                mutate(asset)
                self.assert_rejected(
                    lambda asset=asset: self.call_binding_bytes(claim_asset=asset)
                )

    def test_binding_bytes_rejects_malformed_claim_signature_pins_and_changed_selected_bytes(self) -> None:
        for pin in ("", "A" * 64, "0" * 63):
            with self.subTest(pin=pin):
                self.assert_rejected(
                    lambda pin=pin: self.call_binding_bytes(
                        expected_claim_bundle_sha256=pin
                    )
                )

        alternate_signature_digest = hashlib.sha256(
            b"another synthetic claim signature fixture; not verified by this codec\n"
        ).hexdigest()
        zero_digest_binding = self.call_binding_bytes(
            expected_claim_bundle_sha256="0" * 64
        )
        zero_digest_value, _ = self.canonical_binding(zero_digest_binding)
        self.assertEqual(zero_digest_value["claim_bundle_sha256"], "0" * 64)

        original_binding = self.call_binding_bytes()
        alternate_binding = self.call_binding_bytes(
            expected_claim_bundle_sha256=alternate_signature_digest
        )
        original_value, _ = self.canonical_binding(original_binding)
        alternate_value, _ = self.canonical_binding(alternate_binding)
        self.assertNotEqual(original_binding, alternate_binding)
        self.assertEqual(
            original_value["claim_bundle_sha256"], self.expected_claim_bundle_sha256
        )
        self.assertEqual(
            alternate_value["claim_bundle_sha256"], alternate_signature_digest
        )
        self.assert_rejected(
            lambda: self.call_validate_binding(
                original_binding,
                expected_claim_bundle_sha256=alternate_signature_digest,
            )
        )

        changed_bundle = self.start_bundle_bytes + b"changed\n"
        self.assert_rejected(
            lambda: self.call_binding_bytes(start_bundle_bytes=changed_bundle)
        )

        changed_record = copy.deepcopy(claim_fixture.DispatchClaimCodecTests.record)
        changed_record["runtime"]["receipt_sha256"] = "9" * 64
        changed_record_bytes = (
            binding.CLAIM.START.ADMISSION.canonical_json(changed_record) + "\n"
        ).encode("ascii")
        self.assert_rejected(
            lambda: self.call_binding_bytes(record_bytes=changed_record_bytes)
        )

        self.assert_rejected(
            lambda: self.call_binding_bytes(claim_raw=self.claim_raw + b" \n")
        )

    def test_binding_bytes_revalidates_independent_source_dispatcher_and_job_selections(self) -> None:
        changed_source = copy.deepcopy(self.source_context)
        changed_source["run_id"] += 10
        changed_dispatcher = copy.deepcopy(self.dispatcher_context)
        changed_dispatcher["run_id"] += 10
        changed_job = copy.deepcopy(self.dispatcher_job)
        changed_job["id"] += 1

        for label, kwargs in (
            ("source", {"source_context": changed_source}),
            ("dispatcher", {"dispatcher_context": changed_dispatcher}),
            ("job", {"dispatcher_job": changed_job}),
        ):
            with self.subTest(selection=label):
                self.assert_rejected(
                    lambda kwargs=kwargs: self.call_binding_bytes(**kwargs)
                )

    def test_binding_bytes_rejects_unconfirmed_run_responses(self) -> None:
        for status in (204, 302, 500):
            with self.subTest(status=status):
                self.assert_rejected(
                    lambda status=status: self.call_binding_bytes(response_status=status)
                )

        self.assert_rejected(lambda: self.call_binding_bytes(response_body=b""))
        self.assert_rejected(
            lambda: self.call_binding_bytes(
                response_body=b"x" * (binding.MAX_RESPONSE + 1)
            )
        )

    def test_validate_binding_rejects_a_copied_selector_run_or_other_native_context(self) -> None:
        raw = self.call_binding_bytes()
        invalid_contexts = {
            "copied source selector": {
                **self.native_context, "run_id": self.source_context["run_id"],
            },
            "copied dispatcher selector": {
                **self.native_context, "run_id": self.dispatcher_context["run_id"],
            },
            "different run": {
                **self.native_context, "run_id": CONFIRMED_RUN_ID + 1,
            },
            "attempt rerun": {
                **self.native_context, "run_attempt": 2,
            },
            "wrong repository": {
                **self.native_context, "repository": "other/repo",
            },
            "wrong repository id": {
                **self.native_context, "repository_id": self.native_context["repository_id"] + 1,
            },
            "wrong workflow": {
                **self.native_context, "workflow": ".github/workflows/other.yml",
            },
            "wrong producer commit": {
                **self.native_context, "producer_commit": "c" * 40,
            },
            "wrong tag ref": {
                **self.native_context, "source_ref": "refs/heads/main",
            },
            "missing context field": {
                key: value for key, value in self.native_context.items()
                if key != "run_attempt"
            },
            "extra context field": {
                **self.native_context, "unrecognized": "extra",
            },
        }
        for label, context in invalid_contexts.items():
            with self.subTest(context=label):
                self.assert_rejected(
                    lambda context=context: self.call_validate_binding(
                        raw, actual_native_context=context
                    )
                )

    def test_validate_binding_requires_the_actual_workflow_dispatch_event(self) -> None:
        raw = self.call_binding_bytes()
        for event in ("push", "workflow_run", "pull_request", ""):
            with self.subTest(event=event):
                self.assert_rejected(
                    lambda event=event: self.call_validate_binding(
                        raw, actual_native_event=event
                    )
                )

    def test_validate_binding_rejects_mutated_or_noncanonical_payloads(self) -> None:
        raw = self.call_binding_bytes()
        value, _ = self.canonical_binding(raw)
        extra = copy.deepcopy(value)
        extra["unrecognized"] = "extra"
        duplicate_key = next(iter(value))
        encoded_key = json.dumps(duplicate_key, ensure_ascii=True).encode("ascii")
        duplicate = raw[:-2] + b"," + encoded_key + b":null}\n"
        cases = {
            "extra field": self.encode_json(extra),
            "duplicate field": duplicate,
            "noncanonical whitespace": raw[:-1] + b" \n",
            "truncated": raw[:-2],
            "oversized": b"x" * (binding.START.MAX_RECORD + 1),
        }
        for label, candidate in cases.items():
            with self.subTest(payload=label):
                self.assert_rejected(
                    lambda candidate=candidate: self.call_validate_binding(candidate)
                )

    def test_validate_binding_rejects_changed_external_claim_asset_and_start_pins(self) -> None:
        raw = self.call_binding_bytes()
        changed_asset = copy.deepcopy(self.claim_asset)
        changed_asset["id"] += 1

        changed_record = copy.deepcopy(claim_fixture.DispatchClaimCodecTests.record)
        changed_record["runtime"]["receipt_sha256"] = "8" * 64
        changed_record_bytes = (
            binding.CLAIM.START.ADMISSION.canonical_json(changed_record) + "\n"
        ).encode("ascii")

        cases = {
            "claim bytes": {"claim_raw": self.claim_raw + b" "},
            "start record": {"record_bytes": changed_record_bytes},
            "start bundle": {"start_bundle_bytes": self.start_bundle_bytes + b"changed"},
            "claim asset": {"claim_asset": changed_asset},
            "bundle pin": {
                "expected_claim_bundle_sha256": hashlib.sha256(
                    b"another synthetic claim signature fixture; not verified by this codec\n"
                ).hexdigest()
            },
        }
        for label, kwargs in cases.items():
            with self.subTest(selection=label):
                self.assert_rejected(
                    lambda kwargs=kwargs: self.call_validate_binding(raw, **kwargs)
                )


if __name__ == "__main__":
    unittest.main()
