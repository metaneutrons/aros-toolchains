#!/usr/bin/env python3
"""Offline tests for the inactive post-claim protected-start reader."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
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


# This file is a data/helper fixture only. Do not subclass its unittest cases
# or call StartFixture.verify(), which patches the pre-claim module instance.
DATA = load_module(
    "compiler_sdk_release_start_test_data_v2",
    SOURCE_ROOT / "scripts/toolchain/tests/test-compiler-sdk-release-start-v2.py",
)
CLAIMED = load_module(
    "verify_claimed_compiler_sdk_start_v2",
    SOURCE_ROOT / "scripts/toolchain/verify-claimed-compiler-sdk-start-v2.py",
)
AUTH = CLAIMED.AUTH
UPLOAD = CLAIMED.UPLOAD
CLAIM = CLAIMED.CLAIM
START = CLAIMED.START
ADMISSION = START.ADMISSION
ORIGIN = START.ORIGIN

REPOSITORY = DATA.REPOSITORY
ASSET_ID = 771234
DISPATCHER_RUN_ID = DATA.RUN_ID + 100
DISPATCHER_JOB_ID = DATA.JOB_ID + 100
DISPATCHER_CHECK_ID = DATA.CHECK_RUN_ID + 100
FIXED_ENV = {
    "GH_HOST": "github.com",
    "GH_TOKEN": "job-token-fixture",
    "GITHUB_TOKEN": "fallback-token-fixture",
    "GH_AUTH_TOKEN": "fallback-auth-fixture",
    "GH_ENTERPRISE_TOKEN": "enterprise-token-fixture",
    "GITHUB_ENTERPRISE_TOKEN": "enterprise-fallback-fixture",
    "GOVERNANCE_TOKEN": "governance-token-fixture",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "oidc-token-fixture",
    "ACTIONS_ID_TOKEN_REQUEST_URL": "https://oidc.invalid/token",
}
ERRORS = (START.StartError, ADMISSION.AdmissionError, ORIGIN.OriginError)
TRANSPORT_ERRORS = (*ERRORS, OSError, subprocess.TimeoutExpired)
DEFAULT_SELECTION = object()


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def included(status: int, body: bytes, headers: bytes = b"") -> bytes:
    return (f"HTTP/1.1 {status} fixture\r\n".encode("ascii") + headers
            + b"Content-Type: application/octet-stream\r\n\r\n" + body)


class ClaimedStartFixture:
    """A real canonical start/claim and bounded fake provider/transport."""

    def __init__(self, root: Path):
        self.start = DATA.StartFixture(root)
        self.dispatcher_context = DATA.context(
            workflow=CLAIM.WORKFLOW,
            run_id=DISPATCHER_RUN_ID,
        )
        self.dispatcher_job = {
            "id": DISPATCHER_JOB_ID,
            "check_run_id": DISPATCHER_CHECK_ID,
            "name": CLAIM.JOB,
        }
        self.claim_path = root / CLAIM.CLAIM_NAME
        self.claim_bytes = CLAIM.claim_bytes(
            self.start.record_bytes,
            self.start.bundle_bytes,
            source_context=self.start.source,
            dispatcher_context=self.dispatcher_context,
            dispatcher_job=self.dispatcher_job,
            dispatcher_event="workflow_run",
            trigger_context=self.start.source,
        )
        self.claim_path.write_bytes(self.claim_bytes)
        self.claim_asset_id = ASSET_ID
        self.asset_response = self.make_asset()
        self.start.provider[f"repos/{REPOSITORY}"]["private"] = True
        self.start.provider[f"repos/{REPOSITORY}"]["visibility"] = "private"
        self.release_path = f"repos/{REPOSITORY}/releases/{DATA.DRAFT_ID}"
        self.start.provider[self.release_path]["assets"] = [copy.deepcopy(self.asset_response)]
        self.transport_calls: list[tuple[list[str], dict]] = []
        self.transport_status = 200
        self.transport_body = self.claim_bytes
        self.transport_raw: bytes | None = None
        self.transport_headers = b""
        self.transport_returncode = 0
        self.transport_error: BaseException | None = None
        self.transport_hook = None
        self.runtime_calls = []
        self.upload_calls = []
        self.http_helper_calls = []
        self.metadata_counts: dict[str, int] = {}

    def make_asset(self, **changes: object) -> dict:
        identifier = self.claim_asset_id
        value = {
            "id": identifier,
            "name": CLAIM.CLAIM_NAME,
            "state": "uploaded",
            "content_type": "application/json",
            "size": len(self.claim_bytes),
            "digest": f"sha256:{sha256(self.claim_bytes)}",
            "url": f"https://api.github.com/repos/{REPOSITORY}/releases/assets/{identifier}",
        }
        value.update(changes)
        return value

    def verify(self, *, api_hook=None, env: dict[str, str] | None = None,
               claim_asset_id: object = DEFAULT_SELECTION,
               claim_path: Path | None = None,
               pins: dict[str, object] | None = None):
        """Call the new public API with every provider boundary controlled."""
        environment = FIXED_ENV if env is None else env
        real_api = self.start.run_api
        selected_id = (self.claim_asset_id if claim_asset_id is DEFAULT_SELECTION
                       else claim_asset_id)
        selected_claim_path = self.claim_path if claim_path is None else claim_path
        selected_pins = {} if pins is None else pins

        def provider_api(path: str, **kwargs):
            self.metadata_counts[path] = self.metadata_counts.get(path, 0) + 1
            value = real_api(path, **kwargs)
            if api_hook is not None:
                value = api_hook(path, self.metadata_counts[path], value)
            return value

        def bounded(command: list[str], **kwargs):
            selected_command = list(command)
            selected_kwargs = copy.deepcopy(kwargs)
            self.transport_calls.append((selected_command, selected_kwargs))
            if self.transport_error is not None:
                raise self.transport_error
            response = (self.transport_raw if self.transport_raw is not None else
                        included(self.transport_status, self.transport_body,
                                 self.transport_headers))
            if self.transport_hook is not None:
                self.transport_hook(len(self.transport_calls), selected_command, selected_kwargs)
            return subprocess.CompletedProcess(
                selected_command,
                self.transport_returncode,
                response,
                b"fixture transport error",
            )

        def forbidden_upload(*args, **kwargs):
            self.upload_calls.append((args, kwargs))
            raise AssertionError("claimed-start reader attempted a claim upload")

        def forbidden_http(*args, **kwargs):
            self.http_helper_calls.append((args, kwargs))
            raise AssertionError("claimed-start reader used the upload HTTP helper")

        with mock.patch.dict(os.environ, environment, clear=True), \
                mock.patch.object(ADMISSION, "api", side_effect=provider_api), \
                mock.patch.object(ADMISSION, "git", side_effect=self.start.run_git), \
                mock.patch.object(ADMISSION, "_bounded_subprocess", side_effect=bounded), \
                mock.patch.object(ORIGIN, "gh_json", side_effect=self.start.run_origin_gh), \
                mock.patch.object(START, "bounded_gh", side_effect=self.start.run_bounded_gh), \
                mock.patch.object(START, "verify_runtime_evidence") as runtime_evidence, \
                mock.patch.object(UPLOAD, "upload_claim_once", side_effect=forbidden_upload), \
                mock.patch.object(UPLOAD, "gh_response", side_effect=forbidden_http):
            result = CLAIMED.verify_claimed_start(
                self.start.record_path,
                self.start.bundle_path,
                self.start.source,
                dispatcher_context=self.dispatcher_context,
                dispatcher_job=self.dispatcher_job,
                claim_path=selected_claim_path,
                claim_asset_id=selected_id,
                expected_claim_sha256=selected_pins.get(
                    "expected_claim_sha256", sha256(self.claim_bytes)),
                expected_record_sha256=selected_pins.get(
                    "expected_record_sha256", sha256(self.start.record_bytes)),
                expected_bundle_sha256=selected_pins.get(
                    "expected_bundle_sha256", sha256(self.start.bundle_bytes)),
                runtime_lock=self.start.runtime_lock_path,
                runtime_directory=self.start.runtime_directory,
                runtime_interface=self.start.runtime_interface_path,
                runtime_host=self.start.runtime_host,
            )
            self.runtime_calls = runtime_evidence.call_args_list
        return result

    def old_verify(self) -> dict:
        """Exercise the unchanged pre-claim API using this new module's core."""
        with mock.patch.dict(os.environ, FIXED_ENV, clear=True), \
                mock.patch.object(ADMISSION, "api", side_effect=self.start.run_api), \
                mock.patch.object(ADMISSION, "git", side_effect=self.start.run_git), \
                mock.patch.object(ORIGIN, "gh_json", side_effect=self.start.run_origin_gh), \
                mock.patch.object(START, "bounded_gh", side_effect=self.start.run_bounded_gh), \
                mock.patch.object(START, "verify_runtime_evidence") as runtime_evidence:
            result = START.verify_start(
                self.start.record_path,
                self.start.bundle_path,
                self.start.source,
                runtime_lock=self.start.runtime_lock_path,
                runtime_directory=self.start.runtime_directory,
                runtime_interface=self.start.runtime_interface_path,
                runtime_host=self.start.runtime_host,
            )
            self.runtime_calls = runtime_evidence.call_args_list
            return result


class VerifyClaimedStartTests(unittest.TestCase):
    def fixture(self, directory: str) -> ClaimedStartFixture:
        # macOS exposes its temporary directory through /var -> /private/var.
        # Canonicalize the test root; production deliberately rejects linked
        # path components rather than following them while reading inputs.
        return ClaimedStartFixture(Path(directory).resolve())

    def assert_rejected(self, fixture: ClaimedStartFixture, *, exception=ERRORS,
                        api_hook=None, env: dict[str, str] | None = None,
                        claim_asset_id: object = DEFAULT_SELECTION,
                        claim_path: Path | None = None,
                        pins: dict[str, object] | None = None) -> None:
        with self.assertRaises(exception):
            fixture.verify(api_hook=api_hook, env=env,
                           claim_asset_id=claim_asset_id, claim_path=claim_path,
                           pins=pins)

    def test_positive_post_claim_verification_uses_exact_asset_and_returns_only_start(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aros-claimed-start-positive.") as directory:
            fixture = self.fixture(directory)
            result = fixture.verify()

        self.assertEqual(result, fixture.start.record)
        expected_runtime_call = mock.call(
            fixture.start.record,
            lock_path=fixture.start.runtime_lock_path,
            directory=fixture.start.runtime_directory,
            interface_path=fixture.start.runtime_interface_path,
            host=fixture.start.runtime_host,
        )
        self.assertEqual(fixture.runtime_calls,
                         [expected_runtime_call, expected_runtime_call])
        self.assertEqual(len(fixture.transport_calls), 2)
        command, options = fixture.transport_calls[0]
        self.assertEqual(command, [
            "gh", "api", f"repos/{REPOSITORY}/releases/assets/{ASSET_ID}",
            "--method", "GET", "--include", "--hostname", "github.com",
            "-H", "Accept: application/octet-stream",
            "-H", "X-GitHub-Api-Version: 2022-11-28",
        ])
        self.assertEqual(fixture.transport_calls[1][0], command)
        self.assertIsNone(options["cwd"])
        self.assertEqual(options["timeout"], ADMISSION.API_TIMEOUT_SECONDS)
        self.assertEqual(options["stdout_limit"], START.MAX_RECORD + UPLOAD.MAX_HEADERS)
        self.assertEqual(options["stderr_limit"], ADMISSION.MAX_API_STDERR_BYTES)
        self.assertEqual(options["label"], "selected claim numeric readback")
        environment = options["env"]
        self.assertEqual(environment.get("GH_HOST"), "github.com")
        self.assertEqual(environment.get("GH_TOKEN"), "job-token-fixture")
        for name in (
            "GITHUB_TOKEN", "GH_AUTH_TOKEN", "GH_ENTERPRISE_TOKEN",
            "GITHUB_ENTERPRISE_TOKEN", "GOVERNANCE_TOKEN",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL",
        ):
            self.assertNotIn(name, environment)
        self.assertEqual(fixture.metadata_counts[fixture.release_path], 4)
        self.assertEqual(fixture.metadata_counts[f"repos/{REPOSITORY}"], 4)
        self.assertEqual(fixture.metadata_counts[
            f"repos/{REPOSITORY}/releases/tags/{DATA.TAG_NAME}"], 4)
        self.assertEqual(fixture.metadata_counts[
            f"repos/{REPOSITORY}/git/ref/tags/{DATA.TAG_NAME}"], 4)
        self.assertEqual(fixture.metadata_counts[
            f"repos/{REPOSITORY}/git/tags/{DATA.TAG_OBJECT}"], 4)
        self.assertEqual(fixture.upload_calls, [])
        self.assertEqual(fixture.http_helper_calls, [])
        self.assertEqual(sum(purpose == "start signature authentication"
                             for _, purpose in fixture.start.calls["gh"]), 1)
        self.assertTrue(all(command[:1] in (["api"], ["attestation"])
                            for command, _ in fixture.start.calls["gh"]))

    def test_preclaim_api_still_accepts_only_the_empty_draft(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aros-claimed-start-empty.") as directory:
            fixture = self.fixture(directory)
            fixture.start.provider[fixture.release_path]["assets"] = []
            self.assertEqual(fixture.old_verify(), fixture.start.record)
            self.assertEqual(len(fixture.runtime_calls), 2)
            fixture.start.provider[fixture.release_path]["assets"] = [
                copy.deepcopy(fixture.asset_response)
            ]
            fixture.start.calls = {"api": [], "gh": [], "git": [], "reads": []}
            with self.assertRaisesRegex(START.StartError, "empty stable candidate"):
                fixture.old_verify()

    def test_post_claim_asset_closure_rejects_empty_extra_and_malformed_assets(self) -> None:
        mutations = (
            ("empty", lambda asset: []),
            ("extra", lambda asset: [copy.deepcopy(asset), {"id": ASSET_ID + 1}]),
            ("wrong id", lambda asset: [dict(
                asset, id=ASSET_ID + 1,
                url=f"https://api.github.com/repos/{REPOSITORY}/releases/assets/{ASSET_ID + 1}")]),
            ("wrong name", lambda asset: [dict(asset, name="another.json")]),
            ("wrong size", lambda asset: [dict(asset, size=asset["size"] + 1)]),
            ("wrong digest", lambda asset: [dict(asset, digest="sha256:" + "0" * 64)]),
            ("wrong state", lambda asset: [dict(asset, state="new")]),
            ("wrong content type", lambda asset: [dict(asset, content_type="application/zip")]),
            ("wrong API URL", lambda asset: [dict(asset, url="https://api.github.com/repos/other/releases/assets/771234")]),
        )
        for label, make_assets in mutations:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                fixture = self.fixture(directory)
                fixture.start.provider[fixture.release_path]["assets"] = make_assets(
                    fixture.asset_response)
                self.assert_rejected(fixture)

    def test_post_claim_requires_private_stable_unimmutable_candidate_and_exact_tag_lookup(self) -> None:
        cases = (
            ("draft is public", fixture_release_path(), {"draft": False}),
            ("prerelease", fixture_release_path(), {"prerelease": True}),
            ("immutable release", fixture_release_path(), {"immutable": True}),
            ("archived repository", f"repos/{REPOSITORY}", {"archived": True}),
            ("disabled repository", f"repos/{REPOSITORY}", {"disabled": True}),
            ("tag lookup rebound", f"repos/{REPOSITORY}/releases/tags/{DATA.TAG_NAME}", {"id": DATA.DRAFT_ID + 1}),
            ("annotated tag rebound", f"repos/{REPOSITORY}/git/ref/tags/{DATA.TAG_NAME}", {
                "object": {"type": "tag", "sha": "9" * 40,
                           "url": f"https://api.github.com/repos/{REPOSITORY}/git/tags/" + "9" * 40}}),
        )
        for label, path, fields in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                fixture = self.fixture(directory)
                if path.endswith(f"/releases/{DATA.DRAFT_ID}"):
                    fixture.start.provider[path].update(fields)
                else:
                    original = fixture.start.provider[path]
                    fixture.start.provider[path] = dict(original, **fields)
                self.assert_rejected(fixture)

    def test_fixed_identity_claim_and_exact_numeric_id_are_required(self) -> None:
        invalid_ids = (None, 0, True, False, "771234", 771234.0, 2**64)
        for identifier in invalid_ids:
            with self.subTest(identifier=identifier), tempfile.TemporaryDirectory() as directory:
                fixture = self.fixture(directory)
                # All provider and subprocess boundaries remain mocked even
                # if a regression lets an invalid selector progress farther.
                self.assert_rejected(fixture, claim_asset_id=identifier)
                self.assertEqual(fixture.start.calls["api"], [])
                self.assertEqual(fixture.transport_calls, [])

        with tempfile.TemporaryDirectory() as directory:
            fixture = self.fixture(directory)
            renamed = fixture.claim_path.with_name("renamed-claim.json")
            fixture.claim_path.rename(renamed)
            self.assert_rejected(fixture, claim_path=renamed)

    def test_claim_and_original_byte_pins_are_closed_and_lowercase(self) -> None:
        bad_fields = (
            ("claim digest", "expected_claim_sha256", "0" * 64),
            ("record digest", "expected_record_sha256", "0" * 64),
            ("bundle digest", "expected_bundle_sha256", "0" * 64),
            ("uppercase claim digest", "expected_claim_sha256", sha256(b"x").upper()),
            ("uppercase record digest", "expected_record_sha256", sha256(b"x").upper()),
            ("uppercase bundle digest", "expected_bundle_sha256", sha256(b"x").upper()),
            ("short record digest", "expected_record_sha256", "a" * 63),
            ("nonhex bundle digest", "expected_bundle_sha256", "g" * 64),
            ("boolean claim digest", "expected_claim_sha256", True),
            ("missing bundle digest", "expected_bundle_sha256", None),
        )
        for label, field, value in bad_fields:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                fixture = self.fixture(directory)
                self.assert_rejected(fixture, pins={field: value})
                self.assertEqual(fixture.start.calls["api"], [])
                self.assertEqual(fixture.transport_calls, [])

    def test_claim_context_job_record_bundle_and_canonical_bytes_must_join(self) -> None:
        cases = ("dispatcher run", "dispatcher workflow", "dispatcher job", "source context",
                 "claim body", "record bytes", "bundle bytes")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                fixture = self.fixture(directory)
                if case == "dispatcher run":
                    fixture.dispatcher_context["run_id"] += 1
                elif case == "dispatcher workflow":
                    fixture.dispatcher_context["workflow"] = ".github/workflows/other.yml"
                elif case == "dispatcher job":
                    fixture.dispatcher_job["id"] += 1
                elif case == "source context":
                    fixture.start.source["producer_commit"] = "9" * 40
                elif case == "claim body":
                    fixture.claim_bytes += b" "
                    fixture.claim_path.write_bytes(fixture.claim_bytes)
                elif case == "record bytes":
                    fixture.start.record_path.write_bytes(fixture.start.record_bytes + b" ")
                elif case == "bundle bytes":
                    fixture.start.bundle_path.write_bytes(fixture.start.bundle_bytes + b" ")
                self.assert_rejected(fixture)

    def test_claim_must_be_bounded_before_any_provider_observation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.fixture(directory)
            fixture.claim_path.write_bytes(b"x" * (START.MAX_RECORD + 1))
            self.assert_rejected(fixture)
            self.assertEqual(fixture.start.calls["api"], [])
            self.assertEqual(fixture.transport_calls, [])

    def test_numeric_download_rejects_http_errors_nonzero_exit_and_wrong_bytes_without_retry(self) -> None:
        for case in ("404", "403", "500", "nonzero", "wrong body", "malformed status"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                fixture = self.fixture(directory)
                if case == "404":
                    fixture.transport_status = 404
                elif case == "403":
                    fixture.transport_status = 403
                elif case == "500":
                    fixture.transport_status = 500
                elif case == "nonzero":
                    fixture.transport_returncode = 1
                elif case == "wrong body":
                    fixture.transport_body = fixture.claim_bytes + b"extra"
                elif case == "malformed status":
                    # The status line is malformed but the transport remains
                    # a successful, bounded process response.
                    fixture.transport_raw = b"not an HTTP response\r\n\r\n" + fixture.claim_bytes
                self.assert_rejected(fixture, exception=TRANSPORT_ERRORS)
                self.assertEqual(len(fixture.transport_calls), 1)

        with tempfile.TemporaryDirectory() as directory:
            fixture = self.fixture(directory)
            fixture.transport_error = subprocess.TimeoutExpired(["gh", "api"], 30)
            self.assert_rejected(fixture, exception=TRANSPORT_ERRORS)
            self.assertEqual(len(fixture.transport_calls), 1)

    def test_transport_rejects_oversized_headers_and_output_without_retry(self) -> None:
        for case in ("headers", "body"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                fixture = self.fixture(directory)
                if case == "headers":
                    fixture.transport_headers = b"X-Filler: x\r\n" * (UPLOAD.MAX_HEADERS // 10)
                else:
                    fixture.transport_body = b"x" * (START.MAX_RECORD + 1)
                self.assert_rejected(fixture)
                self.assertEqual(len(fixture.transport_calls), 1)

    def test_fixed_host_and_job_token_guards_run_before_provider_or_download(self) -> None:
        invalid_environments = (
            {**FIXED_ENV, "GH_HOST": "github.example"},
            {key: value for key, value in FIXED_ENV.items() if key != "GH_HOST"},
            {key: value for key, value in FIXED_ENV.items() if key != "GH_TOKEN"},
            {**FIXED_ENV, "GH_TOKEN": ""},
            {**FIXED_ENV, "GH_TOKEN": "   "},
        )
        for environment in invalid_environments:
            with self.subTest(environment=environment), tempfile.TemporaryDirectory() as directory:
                fixture = self.fixture(directory)
                self.assert_rejected(fixture, env=environment)
                self.assertEqual(fixture.start.calls["api"], [])
                self.assertEqual(fixture.transport_calls, [])

    def test_release_and_tag_changes_between_candidate_phases_are_rejected(self) -> None:
        mutations = (
            ("asset added", lambda value: value["assets"].append({"id": ASSET_ID + 1})),
            ("asset changed", lambda value: value["assets"][0].update(state="new")),
            ("draft changed", lambda value: value.update(draft=False)),
        )
        for label, mutate in mutations:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                fixture = self.fixture(directory)

                def hook(path: str, count: int, value):
                    if path == fixture.release_path and count == 3:
                        mutate(value)
                    return value

                self.assert_rejected(fixture, api_hook=hook)
                self.assertEqual(fixture.metadata_counts[fixture.release_path], 3)

    def test_tag_lookup_rebinding_during_second_numeric_get_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.fixture(directory)
            lookup_path = f"repos/{REPOSITORY}/releases/tags/{DATA.TAG_NAME}"

            def rebind_lookup(downloading: int, command: list[str], options: dict) -> None:
                if downloading == 2:
                    fixture.start.provider[lookup_path]["id"] = DATA.DRAFT_ID + 1

            fixture.transport_hook = rebind_lookup
            self.assert_rejected(fixture)

            self.assertEqual(len(fixture.transport_calls), 2)
            self.assertEqual(fixture.start.provider[fixture.release_path]["id"], DATA.DRAFT_ID)
            self.assertEqual(fixture.start.provider[fixture.release_path]["assets"],
                             [fixture.asset_response])
            self.assertEqual(fixture.start.provider[lookup_path]["id"], DATA.DRAFT_ID + 1)
            self.assertEqual(fixture.metadata_counts[lookup_path], 4)

    def test_local_input_changes_during_authentication_are_rejected(self) -> None:
        for changed in ("claim", "record", "bundle"):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as directory:
                fixture = self.fixture(directory)
                real_bounded = fixture.start.run_bounded_gh

                def mutate_after_signature(command, purpose="start provider observation"):
                    result = real_bounded(command, purpose)
                    path = {"claim": fixture.claim_path,
                            "record": fixture.start.record_path,
                            "bundle": fixture.start.bundle_path}[changed]
                    path.write_bytes(path.read_bytes() + b" ")
                    return result

                with mock.patch.object(fixture.start, "run_bounded_gh",
                                       side_effect=mutate_after_signature):
                    self.assert_rejected(fixture)


def fixture_release_path() -> str:
    return f"repos/{REPOSITORY}/releases/{DATA.DRAFT_ID}"


if __name__ == "__main__":
    unittest.main(verbosity=2)
