#!/usr/bin/env python3
"""Offline tests for the inactive dispatcher-signature binding reader.

Fixtures are deterministic structural data, not cryptographic signatures or a
provider qualification. The real reader, codec, dispatcher owner-selection and
provider/job helpers execute; only GitHub metadata and attestation transport
are replaced.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
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


# This existing fixture supplies canonical start data only. Its test cases and
# mocked verifier/provider methods are deliberately not inherited or invoked.
DATA = load_module(
    "compiler_sdk_dispatch_binding_signature_start_fixture_v2",
    SOURCE_ROOT / "scripts/toolchain/tests/test-compiler-sdk-release-start-v2.py",
)
READER = load_module(
    "verify_compiler_sdk_dispatch_binding_v2",
    SOURCE_ROOT / "scripts/toolchain/verify-compiler-sdk-dispatch-binding-v2.py",
)
AUTH = READER.AUTH
START = READER.START
ORIGIN = START.ORIGIN
CLAIM = READER.CLAIM
CODEC = READER.CODEC

REPOSITORY = DATA.REPOSITORY
DISPATCHER_RUN_ID = DATA.RUN_ID + 100
DISPATCHER_JOB_ID = DATA.JOB_ID + 100
DISPATCHER_CHECK_ID = DATA.CHECK_RUN_ID + 100
NATIVE_RUN_ID = 991001
OVER_SAFE_INTEGER = 9007199254740992
FIXED_ENV = {
    "GH_HOST": "github.com",
    "GH_TOKEN": "job-token-fixture",
    "GITHUB_TOKEN": "fallback-token-fixture",
    "GH_AUTH_TOKEN": "fallback-auth-fixture",
    "GH_ENTERPRISE_TOKEN": "enterprise-token-fixture",
    "GITHUB_ENTERPRISE_TOKEN": "enterprise-fallback-fixture",
    "GOVERNANCE_TOKEN": "governance-token-fixture",
}
ERRORS = (START.StartError, START.ADMISSION.AdmissionError, ORIGIN.OriginError)
DEFAULT = object()


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
            + "\n").encode("ascii")


class BindingSignatureFixture:
    """Real canonical payloads plus narrow fake GitHub/attestation transports."""

    def __init__(self, root: Path, *, native_run_id: int = NATIVE_RUN_ID,
                 record_changes: dict | None = None,
                 dispatcher_job_changes: dict | None = None,
                 claim_asset_id: int = 887766):
        self.root = root.resolve()
        self.start = DATA.StartFixture(self.root)
        self.record = copy.deepcopy(self.start.record)
        if record_changes:
            for parent, changes in record_changes.items():
                self.record[parent].update(copy.deepcopy(changes))
        self.record_bytes = canonical_json(self.record)
        self.record_bundle_bytes = self.start.bundle_bytes
        self.source_context = copy.deepcopy(self.start.source)
        self.dispatcher_context = {
            "repository": self.source_context["repository"],
            "repository_id": self.source_context["repository_id"],
            "producer_commit": "9" * 40,
            "source_ref": "refs/heads/main",
            "workflow": CLAIM.WORKFLOW,
            "run_id": DISPATCHER_RUN_ID,
            "run_attempt": 1,
        }
        self.dispatcher_job = {
            "id": DISPATCHER_JOB_ID,
            "check_run_id": DISPATCHER_CHECK_ID,
            "name": CLAIM.JOB,
        }
        if dispatcher_job_changes:
            self.dispatcher_job.update(copy.deepcopy(dispatcher_job_changes))
        self.claim_raw = CLAIM.claim_bytes(
            self.record_bytes,
            self.record_bundle_bytes,
            source_context=self.source_context,
            dispatcher_context=self.dispatcher_context,
            dispatcher_job=self.dispatcher_job,
            dispatcher_event="workflow_run",
            trigger_context=self.source_context,
        )
        self.claim_asset = {
            "id": claim_asset_id,
            "name": CLAIM.CLAIM_NAME,
            "size": len(self.claim_raw),
            "sha256": sha256(self.claim_raw),
        }
        self.claim_signature_bytes = b"synthetic original-claim signature bundle; not verified\n"
        self.expected_claim_bundle_sha256 = sha256(self.claim_signature_bytes)
        self.native_run_id = native_run_id
        self.native_context = {
            "repository": self.source_context["repository"],
            "repository_id": self.source_context["repository_id"],
            "producer_commit": self.record["tag"]["commit"],
            "source_ref": f'refs/tags/{self.record["tag"]["name"]}',
            "workflow": CLAIM.NATIVE_WORKFLOW,
            "run_id": native_run_id,
            "run_attempt": 1,
        }
        response = {
            "workflow_run_id": native_run_id,
            "run_url": (f"https://api.github.com/repos/{REPOSITORY}/actions/runs/"
                        f"{native_run_id}"),
            "html_url": f"https://github.com/{REPOSITORY}/actions/runs/{native_run_id}",
        }
        self.binding_raw = CODEC.binding_bytes(
            self.claim_raw,
            self.record_bytes,
            self.record_bundle_bytes,
            source_context=self.source_context,
            dispatcher_context=self.dispatcher_context,
            dispatcher_job=self.dispatcher_job,
            claim_asset=self.claim_asset,
            expected_claim_bundle_sha256=self.expected_claim_bundle_sha256,
            response_status=200,
            response_body=canonical_json(response),
        )
        self.binding_path = self.root / CODEC.BINDING_NAME
        self.signature_path = self.root / "signature.json"
        self.binding_path.write_bytes(self.binding_raw)
        self.signature_bytes = b"synthetic selected binding signature bundle; verifier mocked\n"
        self.signature_path.write_bytes(self.signature_bytes)
        self.verified = self.attestation_result()
        self.calls: dict[str, list] = {"api": [], "origin": [], "attestation": []}
        self.provider_fault: str | None = None
        self.transport_hook = None
        self.transport_reads: list[dict] = []
        # Provider observations are independent of mutable caller selectors.
        # A selector-drift probe must not accidentally mutate both surfaces.
        self.provider_dispatcher_context = copy.deepcopy(self.dispatcher_context)
        self.provider_dispatcher_job = copy.deepcopy(self.dispatcher_job)

    def attestation_result(self, *, invocation: object = DEFAULT,
                           subject_name: object = DEFAULT,
                           subject_digest: object = DEFAULT) -> list:
        selected_invocation = (f"https://github.com/{REPOSITORY}/actions/runs/"
                               f"{DISPATCHER_RUN_ID}/attempts/1"
                               if invocation is DEFAULT else invocation)
        selected_name = CODEC.BINDING_NAME if subject_name is DEFAULT else subject_name
        selected_digest = sha256(self.binding_raw) if subject_digest is DEFAULT else subject_digest
        return [{"verificationResult": {
            "signature": {"certificate": {"runInvocationURI": selected_invocation}},
            "statement": {"subject": [{
                "name": selected_name, "digest": {"sha256": selected_digest},
            }]},
        }}]

    @property
    def dispatcher_attempt_path(self) -> str:
        return (f"repos/{REPOSITORY}/actions/runs/{DISPATCHER_RUN_ID}"
                "/attempts/1")

    @property
    def dispatcher_latest_path(self) -> str:
        return f"repos/{REPOSITORY}/actions/runs/{DISPATCHER_RUN_ID}"

    @property
    def dispatcher_jobs_path(self) -> str:
        return (f"repos/{REPOSITORY}/actions/runs/{DISPATCHER_RUN_ID}"
                "/attempts/1/jobs?per_page=100")

    def provider_api(self, path: str, **kwargs):
        self.calls["api"].append((path, copy.deepcopy(kwargs)))
        if kwargs:
            raise AssertionError(f"unexpected provider API options: {kwargs!r}")
        if path == self.dispatcher_attempt_path:
            value = {"status": "completed", "conclusion": "success"}
            if self.provider_fault == "failed_attempt":
                value["conclusion"] = "failure"
            return value
        if path == self.dispatcher_latest_path:
            value = {
                "id": DISPATCHER_RUN_ID,
                "run_attempt": 1,
                "head_sha": self.provider_dispatcher_context["producer_commit"],
                "status": "completed",
                "conclusion": "success",
            }
            if self.provider_fault == "rerun":
                value["run_attempt"] = 2
            return value
        raise AssertionError(f"unexpected provider GET: {path!r}")

    def provider_origin(self, arguments: list[str], purpose: str = "GitHub observation"):
        selected = list(arguments)
        self.calls["origin"].append((selected, purpose))
        if selected == ["api", self.dispatcher_attempt_path]:
            value = DATA.provider_run(self.provider_dispatcher_context)
            if self.provider_fault == "wrong_event":
                value["event"] = "push"
            return value
        if selected == ["api", "--paginate", "--slurp", self.dispatcher_jobs_path]:
            job = DATA.provider_job(
                self.provider_dispatcher_context,
                job_id=self.provider_dispatcher_job["id"],
                check_id=self.provider_dispatcher_job["check_run_id"],
                name=self.provider_dispatcher_job["name"],
            )
            if self.provider_fault == "wrong_job":
                job["id"] += 1
            if self.provider_fault == "wrong_job_name":
                job["name"] = "Different dispatcher job"
            return [{"total_count": 1, "jobs": [job]}]
        raise AssertionError(f"unexpected provider observation: {selected!r}")

    def fake_attestation(self, command: list[str], purpose: str = ""):
        selected = list(command)
        self.calls["attestation"].append((selected, purpose))
        if (len(selected) != 20 or selected[:2] != ["attestation", "verify"]
                or "--bundle" not in selected):
            raise AssertionError(f"unexpected attestation command: {selected!r}")
        subject = Path(selected[2])
        bundle = Path(selected[selected.index("--bundle") + 1])
        root = subject.parent
        subject_info = subject.stat(follow_symlinks=False)
        bundle_info = bundle.stat(follow_symlinks=False)
        read = {
            "subject_path": subject,
            "bundle_path": bundle,
            "subject_bytes": subject.read_bytes(),
            "bundle_bytes": bundle.read_bytes(),
            "root_mode": stat.S_IMODE(root.stat(follow_symlinks=False).st_mode),
            "subject_mode": stat.S_IMODE(subject_info.st_mode),
            "bundle_mode": stat.S_IMODE(bundle_info.st_mode),
            "subject_nlink": subject_info.st_nlink,
            "bundle_nlink": bundle_info.st_nlink,
            "subject_uid": subject_info.st_uid,
            "bundle_uid": bundle_info.st_uid,
        }
        self.transport_reads.append(read)
        if self.transport_hook is not None:
            self.transport_hook(self, selected, read)
        return copy.deepcopy(self.verified)

    def verify(self, *, binding_path: Path | None = None,
               signature_path: Path | None = None,
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
               expected_binding_sha256: object = DEFAULT,
               expected_signature_sha256: object = DEFAULT,
               env: dict[str, str] | None = None,
               verified: object = DEFAULT):
        if verified is not DEFAULT:
            self.verified = copy.deepcopy(verified)
        selected_binding_path = self.binding_path if binding_path is None else binding_path
        selected_signature_path = self.signature_path if signature_path is None else signature_path
        selected_raw = self.claim_raw if claim_raw is None else claim_raw
        selected_record = self.record_bytes if record_bytes is None else record_bytes
        selected_start_bundle = (self.record_bundle_bytes if start_bundle_bytes is None
                                 else start_bundle_bytes)
        selected_source = self.source_context if source_context is None else source_context
        selected_dispatcher = (self.dispatcher_context if dispatcher_context is None
                               else dispatcher_context)
        selected_job = self.dispatcher_job if dispatcher_job is None else dispatcher_job
        selected_asset = self.claim_asset if claim_asset is None else claim_asset
        selected_claim_bundle_pin = (self.expected_claim_bundle_sha256
                                     if expected_claim_bundle_sha256 is None
                                     else expected_claim_bundle_sha256)
        selected_native = (self.native_context if actual_native_context is None
                           else actual_native_context)
        binding_pin = (sha256(selected_binding_path.read_bytes())
                       if expected_binding_sha256 is DEFAULT else expected_binding_sha256)
        signature_pin = (sha256(selected_signature_path.read_bytes())
                         if expected_signature_sha256 is DEFAULT else expected_signature_sha256)
        environment = FIXED_ENV if env is None else env

        with mock.patch.dict(os.environ, environment, clear=True), \
                mock.patch.object(START.ADMISSION, "api", side_effect=self.provider_api), \
                mock.patch.object(ORIGIN, "gh_json", side_effect=self.provider_origin), \
                mock.patch.object(START, "bounded_gh", side_effect=self.fake_attestation):
            return READER.verify_binding_signature(
                selected_binding_path,
                selected_signature_path,
                claim_raw=selected_raw,
                record_bytes=selected_record,
                start_bundle_bytes=selected_start_bundle,
                source_context=selected_source,
                dispatcher_context=selected_dispatcher,
                dispatcher_job=selected_job,
                claim_asset=selected_asset,
                expected_claim_bundle_sha256=selected_claim_bundle_pin,
                actual_native_context=selected_native,
                actual_native_event=actual_native_event,
                expected_binding_sha256=binding_pin,
                expected_signature_sha256=signature_pin,
            )


class VerifyDispatchBindingSignatureTests(unittest.TestCase):
    def fixture(self, directory: str, **kwargs) -> BindingSignatureFixture:
        return BindingSignatureFixture(Path(directory), **kwargs)

    def assert_rejected(self, fixture: BindingSignatureFixture, **kwargs) -> None:
        with self.assertRaises(ERRORS):
            fixture.verify(**kwargs)

    def test_private_module_graph_reuses_the_original_dispatcher_codec_objects(self) -> None:
        self.assertIs(READER.START, AUTH.START)
        self.assertIs(READER.CLAIM, AUTH.CLAIM)
        self.assertIs(CODEC.START, AUTH.START)
        self.assertIs(CODEC.CLAIM, AUTH.CLAIM)
        self.assertIs(AUTH.ORIGIN, AUTH.START.ORIGIN)
        self.assertIs(CODEC.START.ORIGIN, AUTH.ORIGIN)
        self.assertIs(AUTH.ORIGIN.gh_json, CODEC.START.ORIGIN.gh_json)

    def test_positive_authenticates_fixed_binding_subject_and_returns_full_limited_output(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aros-binding-signature-positive.") as directory:
            fixture = self.fixture(directory)
            result = fixture.verify(
                expected_binding_sha256=sha256(fixture.binding_raw),
                expected_signature_sha256=sha256(fixture.signature_bytes),
            )

        expected_binding = START.ADMISSION.parse_json(fixture.binding_raw, "test binding")
        self.assertEqual(result, {
            "schema": "aros-toolchains-authenticated-dispatch-binding-v2",
            "assurance": "dispatcher-signature-only-not-native-consumption-or-qualification",
            "binding": expected_binding,
            "limitations": [
                "actual native execution identity must be authenticated independently",
                "start, claim and candidate authenticity must be established independently",
                "does not establish durable consumption, authorize fan-out or qualify a release",
            ],
        })
        self.assertEqual(fixture.binding_path.name, "compiler-sdk-dispatch-binding-v2.json")
        self.assertNotEqual(fixture.binding_path.name, CLAIM.CLAIM_NAME)
        self.assertEqual(len(fixture.calls["attestation"]), 1)
        command, purpose = fixture.calls["attestation"][0]
        private_subject = fixture.transport_reads[0]["subject_path"]
        private_bundle = fixture.transport_reads[0]["bundle_path"]
        self.assertEqual(purpose, "dispatch binding signature authentication")
        self.assertEqual(command, [
            "attestation", "verify", str(private_subject), "--bundle", str(private_bundle),
            "--hostname", "github.com", "--repo", REPOSITORY,
            "--signer-workflow", f"{REPOSITORY}/{CLAIM.WORKFLOW}",
            "--signer-digest", fixture.dispatcher_context["producer_commit"],
            "--source-digest", fixture.dispatcher_context["producer_commit"],
            "--source-ref", "refs/heads/main", "--deny-self-hosted-runners",
            "--format", "json",
        ])
        self.assertEqual(private_subject.name, CODEC.BINDING_NAME)
        self.assertNotEqual(private_subject, fixture.binding_path)
        self.assertEqual(private_bundle.name, "signature.json")
        self.assertNotEqual(private_bundle, fixture.signature_path)
        self.assertEqual(fixture.transport_reads[0]["subject_bytes"], fixture.binding_raw)
        self.assertEqual(fixture.transport_reads[0]["bundle_bytes"], fixture.signature_bytes)
        self.assertEqual(fixture.transport_reads[0]["root_mode"], 0o700)
        for key in ("subject_mode", "bundle_mode"):
            self.assertEqual(fixture.transport_reads[0][key], 0o600)
        for key in ("subject_nlink", "bundle_nlink"):
            self.assertEqual(fixture.transport_reads[0][key], 1)
        for key in ("subject_uid", "bundle_uid"):
            self.assertEqual(fixture.transport_reads[0][key], os.getuid())
        self.assertEqual(len(fixture.calls["api"]), 4)
        self.assertEqual([path for path, _ in fixture.calls["api"]], [
            fixture.dispatcher_attempt_path, fixture.dispatcher_latest_path,
            fixture.dispatcher_attempt_path, fixture.dispatcher_latest_path,
        ])
        self.assertEqual(len(fixture.calls["origin"]), 4)
        self.assertEqual([arguments for arguments, _ in fixture.calls["origin"]], [
            ["api", fixture.dispatcher_attempt_path],
            ["api", "--paginate", "--slurp", fixture.dispatcher_jobs_path],
            ["api", fixture.dispatcher_attempt_path],
            ["api", "--paginate", "--slurp", fixture.dispatcher_jobs_path],
        ])
        self.assertEqual(
            fixture.binding_raw,
            CODEC._encode(expected_binding),
        )

    def test_wrong_or_copied_binding_and_independent_native_run_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aros-binding-native-join.") as directory:
            fixture = self.fixture(directory)
            other_raw = CODEC.binding_bytes(
                fixture.claim_raw, fixture.record_bytes, fixture.record_bundle_bytes,
                source_context=fixture.source_context,
                dispatcher_context=fixture.dispatcher_context,
                dispatcher_job=fixture.dispatcher_job,
                claim_asset=fixture.claim_asset,
                expected_claim_bundle_sha256=fixture.expected_claim_bundle_sha256,
                response_status=200,
                response_body=canonical_json({
                    "workflow_run_id": NATIVE_RUN_ID + 1,
                    "run_url": (f"https://api.github.com/repos/{REPOSITORY}/actions/runs/"
                                f"{NATIVE_RUN_ID + 1}"),
                    "html_url": (f"https://github.com/{REPOSITORY}/actions/runs/"
                                 f"{NATIVE_RUN_ID + 1}"),
                }),
            )
            copied_path = fixture.root / CODEC.BINDING_NAME
            copied_path.write_bytes(other_raw)
            wrong_native = copy.deepcopy(fixture.native_context)
            wrong_native["run_id"] += 1
            fixture.binding_path.write_bytes(fixture.binding_raw)
            self.assert_rejected(fixture, actual_native_context=wrong_native)
            self.assert_rejected(fixture, actual_native_event="workflow_run")

            copied_path.write_bytes(other_raw)
            # Even a matching signature over the other run cannot substitute
            # for the independently selected actual native execution context.
            fixture.verified = fixture.attestation_result(subject_digest=sha256(other_raw))
            self.assert_rejected(fixture)

            malformed = fixture.root / CODEC.BINDING_NAME
            malformed.write_bytes(fixture.binding_raw + b" ")
            fixture.verified = fixture.attestation_result(
                subject_digest=sha256(fixture.binding_raw + b" "))
            self.assert_rejected(fixture)
            self.assertEqual(fixture.calls["api"], [])
            self.assertEqual(fixture.calls["origin"], [])
            self.assertEqual(fixture.calls["attestation"], [])

    def test_signature_result_count_shape_invocation_subject_and_digest_are_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aros-binding-signature-output.") as directory:
            fixture = self.fixture(directory)
            wrong_attempt = fixture.attestation_result(
                invocation=(f"https://github.com/{REPOSITORY}/actions/runs/"
                            f"{DISPATCHER_RUN_ID}/attempts/2"))
            cases = [
                ("zero signatures", []),
                ("multiple signatures", [fixture.attestation_result()[0],
                                         fixture.attestation_result()[0]]),
                ("malformed outer result", {}),
                ("malformed signature entry", [None]),
                ("malformed result body", [{"verificationResult": None}]),
                ("malformed certificate", [{"verificationResult": {
                    "signature": {"certificate": {"runInvocationURI": "not-a-run"}},
                    "statement": {"subject": [{"name": CODEC.BINDING_NAME,
                                                 "digest": {"sha256": sha256(b"wrong")}}]},
                }}]),
                ("wrong attempt", wrong_attempt),
                ("wrong subject name", fixture.attestation_result(subject_name=CLAIM.CLAIM_NAME)),
                ("wrong subject digest", fixture.attestation_result(subject_digest=sha256(b"other"))),
                ("malformed subject digest", fixture.attestation_result(subject_digest=None)),
            ]
            for label, value in cases:
                with self.subTest(case=label):
                    self.assert_rejected(fixture, verified=value)

    def test_binding_and_signature_sha256_pins_are_required_and_exact(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aros-binding-pins.") as directory:
            fixture = self.fixture(directory)
            for field, pin in (
                ("binding", "0" * 64),
                ("binding", "A" * 64),
                ("binding", "g" * 64),
                ("binding", "f" * 63),
                ("signature", "0" * 64),
                ("signature", "A" * 64),
                ("signature", "g" * 64),
                ("signature", "f" * 63),
            ):
                with self.subTest(field=field, pin=pin):
                    kwargs = ({"expected_binding_sha256": pin} if field == "binding"
                              else {"expected_signature_sha256": pin})
                    self.assert_rejected(fixture, **kwargs)

    def test_fixed_host_nonblank_job_token_and_noncolliding_paths_are_required(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aros-binding-input-contract.") as directory:
            fixture = self.fixture(directory)
            for environment in (
                {"GH_HOST": "github.com", "GH_TOKEN": ""},
                {"GH_HOST": "github.com", "GH_TOKEN": "  \t"},
                {"GH_HOST": "github.enterprise", "GH_TOKEN": "job-token"},
            ):
                with self.subTest(environment=environment):
                    self.assert_rejected(fixture, env=environment)
            self.assert_rejected(fixture, signature_path=fixture.binding_path)

            claim_named_path = fixture.root / CLAIM.CLAIM_NAME
            claim_named_path.write_bytes(fixture.binding_raw)
            self.assert_rejected(fixture, binding_path=claim_named_path)

    def test_selected_inputs_must_be_bounded_singly_linked_regular_files(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aros-binding-file-boundaries.") as directory:
            fixture = self.fixture(directory)
            linked = fixture.root / "binding-hardlink.json"
            os.link(fixture.binding_path, linked)
            self.assert_rejected(fixture)
            linked.unlink()

            fixture.binding_path.write_bytes(fixture.binding_raw)
            fixture.signature_path.write_bytes(fixture.signature_bytes)
            binding_too_large = fixture.root / CODEC.BINDING_NAME
            binding_too_large.write_bytes(b"b" * (START.MAX_RECORD + 1))
            self.assert_rejected(fixture)

        with tempfile.TemporaryDirectory(prefix="aros-binding-signature-bound.") as directory:
            fixture = self.fixture(directory)
            fixture.signature_path.write_bytes(b"s" * (START.MAX_BUNDLE + 1))
            self.assert_rejected(fixture)

        with tempfile.TemporaryDirectory(prefix="aros-binding-symlink.") as directory:
            fixture = self.fixture(directory)
            target = fixture.root / "actual-binding.json"
            target.write_bytes(fixture.binding_raw)
            fixture.binding_path.unlink()
            fixture.binding_path.symlink_to(target)
            self.assert_rejected(fixture)

    def test_failed_or_rerun_dispatcher_and_wrong_original_job_are_rejected(self) -> None:
        for fault in ("failed_attempt", "rerun", "wrong_job", "wrong_job_name", "wrong_event"):
            with self.subTest(fault=fault), \
                    tempfile.TemporaryDirectory(prefix="aros-binding-dispatcher-owner.") as directory:
                fixture = self.fixture(directory)
                fixture.provider_fault = fault
                self.assert_rejected(fixture)
                self.assertEqual(fixture.calls["attestation"], [])

    def test_original_dispatcher_observation_is_repeated_after_attestation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aros-binding-owner-repeat.") as directory:
            fixture = self.fixture(directory)
            fixture.verify()
        self.assertEqual(fixture.calls["api"], [
            (fixture.dispatcher_attempt_path, {}),
            (fixture.dispatcher_latest_path, {}),
            (fixture.dispatcher_attempt_path, {}),
            (fixture.dispatcher_latest_path, {}),
        ])
        self.assertEqual([arguments for arguments, _ in fixture.calls["origin"]], [
            ["api", fixture.dispatcher_attempt_path],
            ["api", "--paginate", "--slurp", fixture.dispatcher_jobs_path],
            ["api", fixture.dispatcher_attempt_path],
            ["api", "--paginate", "--slurp", fixture.dispatcher_jobs_path],
        ])

    def test_late_binding_or_signature_bytes_change_is_rejected(self) -> None:
        for target in ("binding", "signature"):
            with self.subTest(target=target), \
                    tempfile.TemporaryDirectory(prefix="aros-binding-late-bytes.") as directory:
                fixture = self.fixture(directory)

                def mutate_after_private_read(selected_fixture, command, read):
                    path = (selected_fixture.binding_path if target == "binding"
                            else selected_fixture.signature_path)
                    path.write_bytes(path.read_bytes() + b"late mutation\n")

                fixture.transport_hook = mutate_after_private_read
                self.assert_rejected(fixture)
                self.assertEqual(len(fixture.calls["attestation"]), 1)

    def test_dispatcher_owner_drift_after_signature_is_rejected(self) -> None:
        for fault in ("failed_attempt", "rerun", "wrong_job", "wrong_job_name", "wrong_event"):
            with self.subTest(fault=fault), \
                    tempfile.TemporaryDirectory(prefix="aros-binding-late-owner.") as directory:
                fixture = self.fixture(directory)

                def change_owner_after_signature(selected_fixture, command, read):
                    selected_fixture.provider_fault = fault

                fixture.transport_hook = change_owner_after_signature
                self.assert_rejected(fixture)
                self.assertEqual(len(fixture.calls["attestation"]), 1)
                self.assertGreater(len(fixture.calls["api"]), 2)

    def test_independent_context_and_claim_asset_selectors_are_rechecked(self) -> None:
        mutations = (
            ("source context", "source_context", "run_id"),
            ("dispatcher context", "dispatcher_context", "run_id"),
            ("dispatcher job", "dispatcher_job", "id"),
            ("native context", "native_context", "run_id"),
            ("claim asset", "claim_asset", "id"),
        )
        for label, selector, field in mutations:
            with self.subTest(selector=label), \
                    tempfile.TemporaryDirectory(prefix="aros-binding-selector-drift.") as directory:
                fixture = self.fixture(directory)

                def drift_after_attestation(selected_fixture, command, read):
                    selected = getattr(selected_fixture, selector)
                    selected[field] += 1

                fixture.transport_hook = drift_after_attestation
                self.assert_rejected(fixture)
                # Both provider-owner rounds completed against independent,
                # unchanged observations; only the final selected join fails.
                self.assertEqual(len(fixture.calls["api"]), 4)
                self.assertEqual(len(fixture.calls["origin"]), 4)
                self.assertEqual(len(fixture.calls["attestation"]), 1)

    def test_independent_claim_asset_and_claim_bundle_selectors_must_join(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aros-binding-claim-selector.") as directory:
            fixture = self.fixture(directory)
            wrong_asset = copy.deepcopy(fixture.claim_asset)
            wrong_asset["id"] += 1
            self.assert_rejected(fixture, claim_asset=wrong_asset)
            self.assert_rejected(
                fixture,
                expected_claim_bundle_sha256="0" * 64,
            )

    def test_every_selected_provider_id_stays_within_exact_json_integer_range(self) -> None:
        cases = (
            ("start job ID", {"job": {"id": OVER_SAFE_INTEGER}}, {}, 887766),
            ("start check ID", {"job": {"check_run_id": OVER_SAFE_INTEGER}}, {}, 887766),
            ("candidate draft ID", {"draft": {"id": OVER_SAFE_INTEGER}}, {}, 887766),
            ("dispatcher job ID", {}, {"id": OVER_SAFE_INTEGER}, 887766),
            ("dispatcher check ID", {}, {"check_run_id": OVER_SAFE_INTEGER}, 887766),
            ("claim asset ID", {}, {}, OVER_SAFE_INTEGER),
        )
        for label, record_changes, dispatcher_changes, asset_id in cases:
            with self.subTest(identity=label), \
                    tempfile.TemporaryDirectory(prefix="aros-binding-safe-id.") as directory:
                fixture = self.fixture(
                    directory,
                    record_changes=record_changes,
                    dispatcher_job_changes=dispatcher_changes,
                    claim_asset_id=asset_id,
                )
                with self.assertRaisesRegex(ORIGIN.OriginError, "exact integer limit"):
                    fixture.verify()
                self.assertEqual(fixture.calls["api"], [])
                self.assertEqual(fixture.calls["origin"], [])
                self.assertEqual(fixture.calls["attestation"], [])

    def test_largest_exact_json_integer_remains_accepted_for_selected_ids(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aros-binding-safe-id-boundary.") as directory:
            fixture = self.fixture(
                directory,
                record_changes={
                    "job": {"id": 9007199254740991, "check_run_id": 9007199254740990},
                    "draft": {"id": 9007199254740989},
                },
                dispatcher_job_changes={
                    "id": 9007199254740988,
                    "check_run_id": 9007199254740987,
                },
                claim_asset_id=9007199254740986,
            )
            result = fixture.verify()
        self.assertEqual(result["binding"]["start"]["job"]["id"], 9007199254740991)
        self.assertEqual(result["binding"]["dispatcher"]["job"]["check_run_id"],
                         9007199254740987)
        self.assertEqual(result["binding"]["claim"]["id"], 9007199254740986)


if __name__ == "__main__":
    unittest.main()
