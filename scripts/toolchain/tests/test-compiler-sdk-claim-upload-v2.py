#!/usr/bin/env python3
"""Offline tests for the inactive, post-authentication claim upload primitive.

The codec fixture supplies structurally canonical bytes and a selected context.
Authentication is a caller prerequisite and is not tested here. Provider calls
are mocked; this suite has no network, workflow, CLI, or dispatch authority.
"""

from __future__ import annotations

import copy
from contextlib import contextmanager, redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
from types import SimpleNamespace
import unittest
from unittest import mock


SOURCE_ROOT = Path(__file__).resolve().parents[3]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


codec_tests = load_module(
    "compiler_sdk_dispatch_claim_upload_fixture_v2",
    SOURCE_ROOT / "scripts/toolchain/tests/test-compiler-sdk-dispatch-claim-v2.py",
)
upload = load_module(
    "compiler_sdk_claim_upload_v2",
    SOURCE_ROOT / "scripts/toolchain/compiler-sdk-claim-upload-v2.py",
)


class ClaimUploadPrimitiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        # Reuse the prior codec test's canonical raw bytes and provider selection.
        codec_tests.DispatchClaimCodecTests.setUpClass()
        cls.fixture = codec_tests.DispatchClaimCodecTests
        cls.selected = {
            "source_context": copy.deepcopy(cls.fixture.source_context),
            "dispatcher_context": copy.deepcopy(cls.fixture.dispatcher_context),
            "dispatcher_job": copy.deepcopy(cls.fixture.dispatcher_job),
            "dispatcher_event": "workflow_run",
            "trigger_context": copy.deepcopy(cls.fixture.source_context),
        }
        cls.candidate_observation = {
            key: copy.deepcopy(cls.fixture.value["candidate"][key])
            for key in ("tag", "draft")
        }
        cls.repository = upload.START.ADMISSION.REPOSITORY
        cls.draft_id = cls.fixture.value["candidate"]["draft"]["id"]
        cls.asset_id = 887766

    def upload_once(self):
        return upload.upload_claim_once(
            self.fixture.raw,
            self.fixture.record_bytes,
            self.fixture.bundle_bytes,
            **copy.deepcopy(self.selected),
        )

    def asset(self, **overrides) -> dict:
        raw = self.fixture.raw
        value = {
            "id": self.asset_id,
            "name": upload.CLAIM.CLAIM_NAME,
            "state": "uploaded",
            "content_type": "application/json",
            "size": len(raw),
            "digest": f"sha256:{hashlib.sha256(raw).hexdigest()}",
            "url": (f"https://api.github.com/repos/{self.repository}/releases/assets/"
                    f"{self.asset_id}"),
        }
        value.update(overrides)
        return value

    def release(self, asset: dict, **overrides) -> dict:
        candidate = self.fixture.value["candidate"]
        value = {
            "id": self.draft_id,
            "tag_name": candidate["tag"]["name"],
            "target_commitish": candidate["tag"]["commit"],
            "draft": True,
            "prerelease": False,
            "immutable": False,
            "assets": [copy.deepcopy(asset)],
        }
        value.update(overrides)
        return value

    def assert_post_input(self, arguments: list[str], purpose: str) -> tuple[Path, Path]:
        expected_url = (
            f"https://uploads.github.com/repos/{self.repository}/releases/"
            f"{self.draft_id}/assets?name={upload.CLAIM.CLAIM_NAME}"
        )
        self.assertEqual(purpose, "claim upload")
        self.assertEqual(arguments[0], expected_url)
        self.assertEqual(
            arguments[1:6],
            ["--method", "POST", "-H", "Content-Type: application/json", "--input"],
        )
        self.assertEqual(len(arguments), 7)
        payload_path = Path(arguments[6])
        self.assertEqual(payload_path.name, upload.CLAIM.CLAIM_NAME)
        self.assertEqual(payload_path.read_bytes(), self.fixture.raw)
        private_directory = payload_path.parent
        self.assertFalse(stat.S_IMODE(private_directory.stat().st_mode) & 0o077)
        return payload_path, private_directory

    def assert_numeric_readback_request(self, arguments: list[str], purpose: str,
                                        asset_id: int | bool | str | None = None) -> None:
        selected_id = self.asset_id if asset_id is None else asset_id
        self.assertEqual(purpose, "claim numeric readback")
        self.assertEqual(
            arguments,
            [f"repos/{self.repository}/releases/assets/{selected_id}", "--method", "GET",
             "-H", "Accept: application/octet-stream"],
        )

    @contextmanager
    def mocked_upload_protocol(self, *, post_status: int = 201,
                               post_body: bytes | None = None,
                               readback_status: int = 200,
                               readback_body: bytes | None = None,
                               release: dict | None = None,
                               post_exception: BaseException | None = None,
                               preflight_exception: BaseException | None = None,
                               tag_exception: BaseException | None = None):
        asset = self.asset()
        if post_body is None:
            post_body = json.dumps(asset, separators=(",", ":")).encode("utf-8")
        if readback_body is None:
            readback_body = self.fixture.raw
        selected_release = self.release(asset) if release is None else copy.deepcopy(release)
        gh_calls: list[tuple[list[str], str]] = []
        api_calls: list[tuple[str, dict]] = []
        observed: list[dict] = []
        events: list[str] = []
        temp_paths: list[tuple[Path, Path]] = []

        def observe(candidate: dict) -> None:
            events.append("observe candidate")
            observed.append(copy.deepcopy(candidate))
            if preflight_exception is not None:
                raise preflight_exception

        def provider(arguments: list[str], purpose: str) -> tuple[int, bytes]:
            gh_calls.append((list(arguments), purpose))
            if len(gh_calls) == 1:
                events.append("upload")
                payload_path, private_directory = self.assert_post_input(arguments, purpose)
                temp_paths.append((payload_path, private_directory))
                if post_exception is not None:
                    raise post_exception
                return post_status, post_body
            if len(gh_calls) == 2:
                events.append("numeric readback")
                self.assert_numeric_readback_request(arguments, purpose)
                return readback_status, readback_body
            raise AssertionError(f"unexpected extra provider request: {arguments!r}")

        def api(path: str, **kwargs):
            events.append("draft readback")
            api_calls.append((path, kwargs))
            expected_path = f"repos/{self.repository}/releases/{self.draft_id}"
            if path != expected_path or kwargs:
                raise AssertionError(f"unexpected release readback: {path!r}, {kwargs!r}")
            return copy.deepcopy(selected_release)

        def tag_readback(tag: dict) -> None:
            self.assertEqual(tag, self.candidate_observation["tag"])
            events.append("tag readback")
            if tag_exception is not None:
                raise tag_exception

        with mock.patch.object(upload.START, "observe_candidate", side_effect=observe) as observe_mock, \
                mock.patch.object(upload, "gh_response", side_effect=provider) as gh_mock, \
                mock.patch.object(upload.START.ADMISSION, "api", side_effect=api) as api_mock, \
                mock.patch.object(upload.START.ADMISSION, "require_active_repository") as active_mock, \
                mock.patch.object(upload.START, "observe_tag", side_effect=tag_readback) as tag_mock:
            yield SimpleNamespace(
                gh_calls=gh_calls, api_calls=api_calls, observed=observed, events=events,
                temp_paths=temp_paths, observe_mock=observe_mock, gh_mock=gh_mock,
                api_mock=api_mock,
                active_mock=active_mock, tag_mock=tag_mock,
            )

    def assert_no_retry_or_followup(self, state, *, provider_calls: int) -> None:
        self.assertEqual(len(state.gh_calls), provider_calls)
        self.assertEqual(len(state.api_calls), 0)
        if provider_calls:
            self.assertEqual(sum(1 for args, _ in state.gh_calls if "POST" in args), 1)
        self.assertEqual(state.events[:1], ["observe candidate"])

    def test_confirmed_upload_uses_one_private_fixed_name_input_and_exact_readbacks(self) -> None:
        with self.mocked_upload_protocol() as state:
            result = self.upload_once()

        self.assertEqual(result, {
            "id": self.asset_id,
            "name": upload.CLAIM.CLAIM_NAME,
            "size": len(self.fixture.raw),
            "sha256": hashlib.sha256(self.fixture.raw).hexdigest(),
        })
        state.observe_mock.assert_called_once_with(self.candidate_observation)
        self.assertEqual(state.observed, [self.candidate_observation])
        self.assertEqual(state.gh_calls, [
            ([
                f"https://uploads.github.com/repos/{self.repository}/releases/{self.draft_id}"
                f"/assets?name={upload.CLAIM.CLAIM_NAME}",
                "--method", "POST", "-H", "Content-Type: application/json", "--input",
                str(state.temp_paths[0][0]),
            ], "claim upload"),
            ([
                f"repos/{self.repository}/releases/assets/{self.asset_id}", "--method", "GET",
                "-H", "Accept: application/octet-stream",
            ], "claim numeric readback"),
        ])
        self.assertEqual(state.api_calls, [
            (f"repos/{self.repository}/releases/{self.draft_id}", {}),
        ])
        self.assertEqual(state.events, [
            "observe candidate", "upload", "numeric readback", "draft readback", "tag readback",
        ])
        state.active_mock.assert_called_once_with()
        state.tag_mock.assert_called_once_with(self.candidate_observation["tag"])
        payload_path, private_directory = state.temp_paths[0]
        self.assertFalse(payload_path.exists())
        self.assertFalse(private_directory.exists())
        self.assertEqual(len(state.gh_calls), 2)
        self.assertEqual(sum(1 for args, _ in state.gh_calls if "POST" in args), 1)

    def test_candidate_preflight_failure_stops_before_any_upload(self) -> None:
        failure = upload.START.ADMISSION.AdmissionError("synthetic candidate preflight failure")
        with self.mocked_upload_protocol(preflight_exception=failure) as state:
            with self.assertRaisesRegex(type(failure), "synthetic candidate preflight failure"):
                self.upload_once()

        self.assertEqual(state.observed, [self.candidate_observation])
        self.assertEqual(state.gh_calls, [])
        self.assertEqual(state.api_calls, [])
        self.assertEqual(state.events, ["observe candidate"])

    def test_tag_change_after_upload_stops_without_retry_or_dispatch(self) -> None:
        failure = upload.START.StartError("synthetic tag retargeted after upload")
        with self.mocked_upload_protocol(tag_exception=failure) as state:
            with self.assertRaisesRegex(upload.START.StartError, "tag retargeted after upload"):
                self.upload_once()
        self.assertEqual(len(state.gh_calls), 2)
        self.assertEqual(sum("POST" in args for args, _ in state.gh_calls), 1)
        state.tag_mock.assert_called_once_with(self.candidate_observation["tag"])

    def test_non_201_upload_statuses_are_unknown_and_never_retried(self) -> None:
        for status in (404, 422, 502):
            with self.subTest(status=status):
                with self.mocked_upload_protocol(post_status=status) as state:
                    with self.assertRaisesRegex(
                            upload.START.StartError,
                            "claim upload is not confirmed HTTP 201; no retry or dispatch"):
                        self.upload_once()
                self.assert_no_retry_or_followup(state, provider_calls=1)
                payload_path, private_directory = state.temp_paths[0]
                self.assertFalse(payload_path.exists())
                self.assertFalse(private_directory.exists())

    def test_upload_transport_exception_is_not_retried_or_reported_as_success(self) -> None:
        failure = TimeoutError("synthetic upload timeout")
        with self.mocked_upload_protocol(post_exception=failure) as state:
            with self.assertRaisesRegex(TimeoutError, "synthetic upload timeout"):
                self.upload_once()

        self.assert_no_retry_or_followup(state, provider_calls=1)
        payload_path, private_directory = state.temp_paths[0]
        self.assertFalse(payload_path.exists())
        self.assertFalse(private_directory.exists())

    def test_http_201_with_invalid_provider_json_stops_without_readback(self) -> None:
        with self.mocked_upload_protocol(post_body=b"not provider JSON") as state:
            with self.assertRaisesRegex(
                    upload.START.ADMISSION.AdmissionError, "claim upload asset is invalid JSON"):
                self.upload_once()

        self.assert_no_retry_or_followup(state, provider_calls=1)

    def test_asset_identity_and_metadata_mismatches_stop_after_one_post(self) -> None:
        cases = {
            "boolean ID": (self.asset(id=True), "claim asset ID is not a positive u64 integer"),
            "zero ID": (self.asset(id=0), "claim asset ID is not a positive u64 integer"),
            "ID disagrees with URL": (
                self.asset(id=self.asset_id + 1), "claim asset identity, bytes or upload state differs"),
            "name": (self.asset(name="other.json"), "claim asset identity, bytes or upload state differs"),
            "URL": (self.asset(url="https://api.github.com/repos/other/releases/assets/1"),
                    "claim asset identity, bytes or upload state differs"),
            "state": (self.asset(state="new"), "claim asset identity, bytes or upload state differs"),
            "size": (self.asset(size=len(self.fixture.raw) + 1),
                     "claim asset identity, bytes or upload state differs"),
            "boolean size": (self.asset(size=True),
                             "claim asset identity, bytes or upload state differs"),
            "digest": (self.asset(digest="sha256:" + "0" * 64),
                       "claim asset identity, bytes or upload state differs"),
            "content type": (self.asset(content_type="application/octet-stream"),
                             "claim asset identity, bytes or upload state differs"),
        }
        for label, (bad_asset, message) in cases.items():
            with self.subTest(metadata=label):
                body = json.dumps(bad_asset, separators=(",", ":")).encode("utf-8")
                with self.mocked_upload_protocol(post_body=body) as state:
                    with self.assertRaisesRegex(upload.START.StartError, message):
                        self.upload_once()
                self.assert_no_retry_or_followup(state, provider_calls=1)

    def test_numeric_readback_requires_http_200_and_exact_raw_bytes(self) -> None:
        cases = ((206, self.fixture.raw, "non-200 status"),
                 (404, self.fixture.raw, "missing numeric asset"),
                 (200, self.fixture.raw + b"changed", "changed numeric asset bytes"))
        for status, body, label in cases:
            with self.subTest(readback=label):
                with self.mocked_upload_protocol(readback_status=status,
                                                 readback_body=body) as state:
                    with self.assertRaisesRegex(
                            upload.START.StartError,
                            "claim numeric readback differs; no retry or dispatch"):
                        self.upload_once()
                self.assertEqual(len(state.gh_calls), 2)
                self.assertEqual(len(state.api_calls), 0)
                self.assertEqual(state.events, ["observe candidate", "upload", "numeric readback"])

    def test_public_changed_or_extra_asset_draft_fails_final_closure_check(self) -> None:
        asset = self.asset()
        cases = {
            "public release": self.release(asset, draft=False),
            "changed draft ID": self.release(asset, id=self.draft_id + 1),
            "changed tag": self.release(asset, tag_name="v9.9.9"),
            "changed commit": self.release(asset, target_commitish="9" * 40),
            "prerelease": self.release(asset, prerelease=True),
            "immutable": self.release(asset, immutable=True),
            "extra asset": self.release(asset, assets=[asset, self.asset(id=887767)]),
        }
        for label, remote_release in cases.items():
            with self.subTest(draft=label):
                with self.mocked_upload_protocol(release=remote_release) as state:
                    with self.assertRaisesRegex(
                            upload.START.StartError,
                            "claim candidate changed or has an unexpected asset closure; no dispatch"):
                        self.upload_once()
                self.assertEqual(len(state.gh_calls), 2)
                self.assertEqual(len(state.api_calls), 1)
                self.assertEqual(state.events, [
                    "observe candidate", "upload", "numeric readback", "draft readback",
                ])


class IncludedResponseTests(unittest.TestCase):
    def test_included_response_extracts_status_and_body(self) -> None:
        raw = (b"HTTP/2 201 Created\r\ncontent-type: application/json\r\n"
               b"x-request-id: synthetic\r\n\r\n{\"id\":7}")
        self.assertEqual(upload.included_response(raw), (201, b'{"id":7}'))

    def test_included_response_rejects_bad_status_missing_headers_and_bounds(self) -> None:
        cases = (
            (b"not an HTTP response\r\n\r\nbody", "claim HTTP status is missing or malformed"),
            (b"HTTP/1.1 201 Created\r\nheader: value", "claim HTTP header block is missing or too large"),
            (b"HTTP/1.1 201 Created\r\n" + b"x" * (upload.MAX_HEADERS + 1)
             + b"\r\n\r\nbody", "claim HTTP header block is missing or too large"),
            (b"x" * (upload.START.ADMISSION.MAX_API_BYTES + 1),
             "claim HTTP response exceeds the metadata limit"),
        )
        for raw, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(upload.START.StartError, message):
                    upload.included_response(raw)


class ClaimTransportTests(unittest.TestCase):
    job_token = "synthetic-job-token"
    governance_token = "synthetic-governance-token"
    provider_body = b"synthetic-provider-body-must-not-be-reported"

    def environment(self, *, include_job_token: bool = True) -> dict[str, str]:
        values = {
            "PATH": "/synthetic/bin",
            "GOVERNANCE_TOKEN": self.governance_token,
            "GITHUB_TOKEN": "synthetic-github-token",
            "GH_AUTH_TOKEN": "synthetic-gh-auth-token",
            "GH_ENTERPRISE_TOKEN": "synthetic-gh-enterprise-token",
            "GITHUB_ENTERPRISE_TOKEN": "synthetic-github-enterprise-token",
            "GH_HOST": "attacker.invalid",
        }
        if include_job_token:
            values["GH_TOKEN"] = self.job_token
        return values

    def test_transport_uses_only_the_job_token_and_explicit_github_headers(self) -> None:
        stdout = (b"HTTP/2 200 OK\r\ncontent-type: application/json\r\n\r\n"
                  b"synthetic response body")
        result = subprocess.CompletedProcess(["gh"], 0, stdout=stdout, stderr=b"")
        path = "repos/metaneutrons/aros-toolchains/releases/667002"
        with mock.patch.dict(os.environ, self.environment(), clear=True), \
                mock.patch.object(upload.START.ADMISSION, "_bounded_subprocess",
                                  return_value=result) as bounded:
            status, body = upload.gh_response([path], "claim transport test")

        self.assertEqual((status, body), (200, b"synthetic response body"))
        bounded.assert_called_once()
        command = bounded.call_args.args[0]
        kwargs = bounded.call_args.kwargs
        self.assertEqual(command, [
            "gh", "api", path, "--include", "--hostname", "github.com",
            "-H", "X-GitHub-Api-Version: 2022-11-28",
        ])
        self.assertIsNone(kwargs["cwd"])
        self.assertEqual(kwargs["timeout"], upload.START.ADMISSION.API_TIMEOUT_SECONDS)
        self.assertEqual(kwargs["stdout_limit"], upload.START.ADMISSION.MAX_API_BYTES)
        self.assertEqual(kwargs["stderr_limit"], upload.START.ADMISSION.MAX_API_STDERR_BYTES)
        self.assertEqual(kwargs["label"], "claim transport test")
        self.assertEqual(kwargs["env"], {
            "PATH": "/synthetic/bin", "GH_TOKEN": self.job_token, "GH_HOST": "github.com",
        })
        token_names = {
            "GH_TOKEN", "GOVERNANCE_TOKEN", "GITHUB_TOKEN", "GH_AUTH_TOKEN",
            "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN",
        }
        self.assertEqual({key for key in kwargs["env"] if key in token_names}, {"GH_TOKEN"})

    def test_missing_job_token_fails_before_subprocess(self) -> None:
        with mock.patch.dict(os.environ, self.environment(include_job_token=False), clear=True), \
                mock.patch.object(upload.START.ADMISSION, "_bounded_subprocess") as bounded:
            with self.assertRaisesRegex(
                    upload.START.StartError, "claim transport requires the job token") as raised:
                upload.gh_response(["repos/metaneutrons/aros-toolchains"], "missing token test")

        bounded.assert_not_called()
        self.assertNotIn(self.governance_token, str(raised.exception))
        self.assertNotIn("synthetic-github-token", str(raised.exception))

    def test_nonzero_transport_result_does_not_report_credentials_or_provider_body(self) -> None:
        stdout = (b"HTTP/1.1 403 Forbidden\r\n\r\n" + self.provider_body + b"\n"
                  + self.job_token.encode("ascii"))
        stderr = self.governance_token.encode("ascii") + b" synthetic provider error"
        result = subprocess.CompletedProcess(["gh"], 1, stdout=stdout, stderr=stderr)
        console = io.StringIO()
        with mock.patch.dict(os.environ, self.environment(), clear=True), \
                mock.patch.object(upload.START.ADMISSION, "_bounded_subprocess",
                                  return_value=result) as bounded, \
                redirect_stdout(console), redirect_stderr(console):
            with self.assertRaisesRegex(
                    upload.START.StartError,
                    "claim transport test failed or is unknown; no mutation retry") as raised:
                upload.gh_response(["repos/metaneutrons/aros-toolchains"], "claim transport test")

        bounded.assert_called_once()
        reported = str(raised.exception) + console.getvalue()
        for secret in (self.job_token, self.governance_token, self.provider_body.decode("ascii"),
                       "synthetic provider error"):
            self.assertNotIn(secret, reported)

    def test_transport_timeout_does_not_report_credentials_or_provider_body(self) -> None:
        command = ["gh", "api", "synthetic-endpoint"]
        timeout = subprocess.TimeoutExpired(
            command, upload.START.ADMISSION.API_TIMEOUT_SECONDS,
            output=self.provider_body + b" " + self.job_token.encode("ascii"),
            stderr=self.governance_token.encode("ascii"),
        )
        console = io.StringIO()
        with mock.patch.dict(os.environ, self.environment(), clear=True), \
                mock.patch.object(upload.START.ADMISSION, "_bounded_subprocess",
                                  side_effect=timeout) as bounded, \
                redirect_stdout(console), redirect_stderr(console):
            with self.assertRaisesRegex(upload.START.StartError, "claim timeout test failed or is unknown") as raised:
                upload.gh_response(["repos/metaneutrons/aros-toolchains"], "claim timeout test")

        bounded.assert_called_once()
        reported = str(raised.exception) + console.getvalue()
        for secret in (self.job_token, self.governance_token, self.provider_body.decode("ascii")):
            self.assertNotIn(secret, reported)

    def test_metadata_observations_use_the_same_pinned_host_and_job_token(self) -> None:
        path = "repos/metaneutrons/aros-toolchains"
        result = subprocess.CompletedProcess(["gh"], 0,
                                              b'HTTP/2.0 200 OK\nContent-Type: application/json\n\n{"archived":false}', b"")
        with mock.patch.dict(os.environ, self.environment(), clear=True), \
                mock.patch.object(upload.START.ADMISSION, "_bounded_subprocess", return_value=result) as bounded:
            self.assertIs(upload.START.ADMISSION.api, upload.fixed_metadata)
            self.assertEqual(upload.START.ADMISSION.api(path), {"archived": False})
        command = bounded.call_args.args[0]
        self.assertIn("--hostname", command)
        self.assertEqual(command[command.index("--hostname") + 1], "github.com")
        self.assertEqual(bounded.call_args.kwargs["env"]["GH_HOST"], "github.com")
        self.assertNotIn("GH_ENTERPRISE_TOKEN", bounded.call_args.kwargs["env"])
        with mock.patch.object(upload, "gh_response") as transport:
            with self.assertRaisesRegex(upload.START.StartError, "outside its fixed repository"):
                upload.fixed_metadata("repos/other/aros-toolchains")
        transport.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
