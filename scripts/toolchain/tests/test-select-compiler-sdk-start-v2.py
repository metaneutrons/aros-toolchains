#!/usr/bin/env python3
"""Offline tests for inactive cross-run protected-start transport selection.

Provider, OIDC, and download transports use controlled fixtures. The selected
ZIP is real and is read by the bounded production archive reader; these tests
do not qualify live provider behavior, start signatures, or native execution.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest import mock
import zipfile


SOURCE_ROOT = Path(__file__).resolve().parents[3]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


auth_tests = load_module(
    "compiler_sdk_dispatcher_auth_test_fixtures_for_selector_v2",
    SOURCE_ROOT / "scripts/toolchain/tests/test-compiler-sdk-dispatcher-auth-v2.py",
)
selector = load_module(
    "compiler_sdk_start_transport_selector_v2",
    SOURCE_ROOT / "scripts/toolchain/select-compiler-sdk-start-v2.py",
)

START = selector.START
ORIGIN = selector.ORIGIN
UPLOAD = selector.UPLOAD
ADMISSION = selector.ADMISSION
ARCHIVE = selector.ARCHIVE
REPOSITORY = auth_tests.REPOSITORY
DOWNLOAD_ID = 77001
OTHER_ARTIFACT_ID = 76000
AUTH_ERRORS = (
    START.StartError,
    ORIGIN.OriginError,
    ADMISSION.AdmissionError,
    ARCHIVE.StartError,
)


def archive_fixture(record: bytes, bundle: bytes) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as handle:
        handle.writestr(ARCHIVE.RECORD_BASENAME, record)
        handle.writestr(ARCHIVE.BUNDLE_BASENAME, bundle)
    return output.getvalue()


class TransportHarness(auth_tests.AuthenticationHarness):
    """Reuse the dispatcher-auth fixture with an artifact and ZIP transport."""

    def __init__(self, root: Path):
        super().__init__(root)
        self.environment.update({
            "GH_HOST": "github.com",
            "GH_TOKEN": "job-token-fixture",
            "GITHUB_TOKEN": "fallback-token-fixture",
            "GH_AUTH_TOKEN": "fallback-auth-fixture",
            "GH_ENTERPRISE_TOKEN": "enterprise-token-fixture",
            "GITHUB_ENTERPRISE_TOKEN": "enterprise-fallback-fixture",
            "GOVERNANCE_TOKEN": "governance-token-fixture",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "oidc-token-fixture",
            "ACTIONS_ID_TOKEN_REQUEST_URL": "https://oidc.invalid/token",
        })
        self.record_bytes = b'{"transport_fixture":"record bytes; signature is not verified"}\n'
        self.bundle_bytes = b'{"transport_fixture":"bundle bytes"}\n'
        self.archive_bytes = archive_fixture(self.record_bytes, self.bundle_bytes)
        self.artifact_name = (
            f"{selector.ARTIFACT_PREFIX}{self.source['run_id']}-1"
        )
        self.artifact = self.make_artifact()
        self.artifacts = [
            {"id": OTHER_ARTIFACT_ID + index, "name": f"other-{index}"}
            for index in range(100)
        ] + [copy.deepcopy(self.artifact)]
        self.total_count_override = None
        self.selector_hook = None
        self.download_calls: list[tuple[list[str], dict]] = []
        self.download_result: tuple[int, bytes] = (0, self.archive_bytes)
        self.download_error: BaseException | None = None
        self.forbidden_upload = None
        self.forbidden_http = None

    @property
    def artifacts_path(self) -> str:
        return (f'repos/{REPOSITORY}/actions/runs/{self.source["run_id"]}'
                "/artifacts?per_page=100&page=")

    @property
    def direct_artifact_path(self) -> str:
        return f"repos/{REPOSITORY}/actions/artifacts/{DOWNLOAD_ID}"

    def make_artifact(self, **changes: object) -> dict:
        value = {
            "id": DOWNLOAD_ID,
            "name": self.artifact_name if hasattr(self, "artifact_name") else "unused",
            "size_in_bytes": len(self.archive_bytes) if hasattr(self, "archive_bytes") else 1,
            "digest": ("sha256:" + hashlib.sha256(self.archive_bytes).hexdigest()
                       if hasattr(self, "archive_bytes") else "sha256:" + "0" * 64),
            "expired": False,
            "workflow_run": {
                "id": self.source["run_id"],
                "head_sha": self.source["producer_commit"],
                "repository_id": self.source["repository_id"],
                "head_repository_id": self.source["repository_id"],
            },
            # This deliberately points away from GitHub. The selector must
            # ignore it and build its download path from the numeric ID.
            "archive_download_url": "https://attacker.invalid/not-the-selector",
        }
        value.update(changes)
        return value

    def set_artifact(self, **changes: object) -> None:
        self.artifact.update(changes)
        for index, item in enumerate(self.artifacts):
            if item.get("name") == self.artifact_name:
                self.artifacts[index] = copy.deepcopy(self.artifact)
                break

    def provider_metadata(self, path: str):
        if path.startswith(self.artifacts_path):
            self.metadata_calls.append(path)
            self.metadata_counts[path] = self.metadata_counts.get(path, 0) + 1
            page = int(path.rsplit("=", 1)[1])
            total = (len(self.artifacts) if self.total_count_override is None
                     else self.total_count_override)
            start = (page - 1) * selector.ARTIFACT_PAGE_SIZE
            value = {
                "total_count": total,
                "artifacts": copy.deepcopy(
                    self.artifacts[start:start + selector.ARTIFACT_PAGE_SIZE]
                ),
            }
        elif path == self.direct_artifact_path:
            self.metadata_calls.append(path)
            self.metadata_counts[path] = self.metadata_counts.get(path, 0) + 1
            value = copy.deepcopy(self.artifact)
        else:
            return super().provider_metadata(path)

        if self.selector_hook is not None:
            value = self.selector_hook(path, self.metadata_counts[path], value)
        return value

    def bounded_subprocess(self, command: list[str], **kwargs):
        self.download_calls.append((copy.deepcopy(command), copy.deepcopy(kwargs)))
        if self.download_error is not None:
            raise self.download_error
        code, output = self.download_result
        return subprocess.CompletedProcess(command, code, output, b"")

    def select(self) -> dict:
        def forbidden(*args, **kwargs):
            raise AssertionError("selector attempted a claim upload or HTTP mutation")

        with mock.patch.dict(os.environ, self.environment, clear=True), \
                mock.patch.object(ADMISSION, "api", side_effect=self.provider_api), \
                mock.patch.object(ADMISSION, "_bounded_subprocess",
                                  side_effect=self.bounded_subprocess), \
                mock.patch.object(UPLOAD, "fixed_metadata", side_effect=self.provider_metadata), \
                mock.patch.object(ORIGIN, "owning_check_id", side_effect=self.oidc_check_id), \
                mock.patch.object(UPLOAD, "gh_response", side_effect=forbidden) as http, \
                mock.patch.object(UPLOAD, "upload_claim_once", side_effect=forbidden) as upload:
            self.forbidden_http = http
            self.forbidden_upload = upload
            return selector.select_start_transport()

    def assert_no_mutation_or_retry(self, testcase: unittest.TestCase) -> None:
        testcase.assertIsNotNone(self.forbidden_http)
        testcase.assertIsNotNone(self.forbidden_upload)
        testcase.assertEqual(self.forbidden_http.call_count, 0)
        testcase.assertEqual(self.forbidden_upload.call_count, 0)
        testcase.assertLessEqual(len(self.download_calls), 1)


class StartTransportSelectionTests(unittest.TestCase):
    def harness(self, directory: str) -> TransportHarness:
        return TransportHarness(Path(directory))

    def assert_rejected(self, fixture: TransportHarness) -> None:
        with self.assertRaises(AUTH_ERRORS):
            fixture.select()
        fixture.assert_no_mutation_or_retry(self)

    def test_selects_exact_real_zip_after_complete_list_direct_readback_and_rechecks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.harness(directory)
            result = fixture.select()

        self.assertEqual(set(result), {
            "assurance", "source_context", "dispatcher_identity", "artifact_selector",
            "record_bytes", "bundle_bytes",
        })
        self.assertEqual(result["assurance"], selector.ASSURANCE)
        self.assertEqual(result["source_context"], fixture.source)
        self.assertEqual(result["dispatcher_identity"]["context"], fixture.context)
        self.assertEqual(result["artifact_selector"], {
            "id": DOWNLOAD_ID,
            "name": fixture.artifact_name,
            "sha256": hashlib.sha256(fixture.archive_bytes).hexdigest(),
            "size_in_bytes": len(fixture.archive_bytes),
        })
        self.assertEqual(result["record_bytes"], fixture.record_bytes)
        self.assertEqual(result["bundle_bytes"], fixture.bundle_bytes)
        self.assertEqual(len(fixture.download_calls), 1)
        command, options = fixture.download_calls[0]
        self.assertEqual(command, [
            "gh", "api", "--hostname", "github.com", "--method", "GET",
            f"repos/{REPOSITORY}/actions/artifacts/{DOWNLOAD_ID}/zip",
        ])
        self.assertEqual(options["timeout"], ADMISSION.API_TIMEOUT_SECONDS)
        self.assertEqual(options["stdout_limit"], len(fixture.archive_bytes))
        self.assertEqual(options["stderr_limit"], ADMISSION.MAX_API_STDERR_BYTES)
        self.assertEqual(options["env"]["GH_HOST"], "github.com")
        self.assertEqual(options["env"]["GH_TOKEN"], "job-token-fixture")
        for key in (
            "GITHUB_TOKEN", "GH_AUTH_TOKEN", "GH_ENTERPRISE_TOKEN",
            "GITHUB_ENTERPRISE_TOKEN", "GOVERNANCE_TOKEN",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL",
        ):
            self.assertNotIn(key, options["env"])
        self.assertNotIn("attacker.invalid", " ".join(command))
        self.assertEqual(fixture.metadata_counts[fixture.artifacts_path + "1"], 2)
        self.assertEqual(fixture.metadata_counts[fixture.artifacts_path + "2"], 2)
        self.assertEqual(fixture.metadata_counts[fixture.direct_artifact_path], 2)
        self.assertEqual(len(fixture.oidc_calls), 2)
        fixture.assert_no_mutation_or_retry(self)

    def test_rejects_event_own_context_and_provider_source_mismatches_before_download(self) -> None:
        cases = ("event", "own-context", "source-provider")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                fixture = self.harness(directory)
                if case == "event":
                    event = auth_tests.event_fixture(fixture.source)
                    event["workflow_run"]["head_sha"] = "A" * 40
                    fixture.set_event(event)
                elif case == "own-context":
                    fixture.set_environment(GITHUB_RUN_ID=str(fixture.source["run_id"]))
                else:
                    source_latest = (
                        f"repos/{REPOSITORY}/actions/runs/{fixture.source['run_id']}"
                    )

                    def wrong_source(path: str, count: int, value: dict) -> dict:
                        if path == source_latest:
                            value["head_sha"] = "0" * 40
                        return value

                    fixture.api_hook = wrong_source
                self.assert_rejected(fixture)
                self.assertEqual(fixture.download_calls, [])
                if case == "event":
                    self.assertEqual(fixture.api_calls, [])

    def test_requires_fixed_github_host_and_job_token_before_provider_access(self) -> None:
        for changes in ({"GH_HOST": "github.example"}, {"GH_TOKEN": ""}, {"GH_TOKEN": "missing"}):
            with self.subTest(changes=changes), tempfile.TemporaryDirectory() as directory:
                fixture = self.harness(directory)
                if changes.get("GH_TOKEN") == "missing":
                    fixture.environment.pop("GH_TOKEN")
                else:
                    fixture.set_environment(**changes)
                self.assert_rejected(fixture)
                self.assertEqual(fixture.api_calls, [])
                self.assertEqual(fixture.metadata_calls, [])

    def test_event_paths_reject_links_and_noncanonical_components_before_provider_access(self) -> None:
        for kind in ("file-link", "parent-link", "noncanonical", "hard-link"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                fixture = self.harness(directory)
                if kind == "file-link":
                    selected = fixture.root / "event-link.json"
                    selected.symlink_to(fixture.event_path)
                elif kind == "parent-link":
                    parent_link = fixture.root / "event-parent"
                    parent_link.symlink_to(fixture.root, target_is_directory=True)
                    selected = parent_link / fixture.event_path.name
                elif kind == "noncanonical":
                    unused = fixture.root / "unused"
                    unused.mkdir()
                    selected = unused / ".." / fixture.event_path.name
                else:
                    os.link(fixture.event_path, fixture.root / "event-hardlink.json")
                    selected = fixture.event_path
                fixture.set_environment(GITHUB_EVENT_PATH=str(selected))
                self.assert_rejected(fixture)
                self.assertEqual(fixture.api_calls, [])
                self.assertEqual(fixture.metadata_calls, [])
                self.assertEqual(fixture.oidc_calls, [])
                self.assertEqual(fixture.download_calls, [])

    def test_archive_is_read_from_owned_private_canonical_ephemeral_staging(self) -> None:
        read_archive = ARCHIVE.read_start_archive
        observed = []

        def inspect_archive(path: Path, digest: str, size: int) -> dict:
            file_metadata = path.lstat()
            parent_metadata = path.parent.lstat()
            self.assertEqual(path.resolve(strict=True), path)
            self.assertTrue(stat.S_ISREG(file_metadata.st_mode))
            self.assertEqual(file_metadata.st_uid, os.geteuid())
            self.assertEqual(file_metadata.st_nlink, 1)
            self.assertEqual(stat.S_IMODE(file_metadata.st_mode), 0o600)
            self.assertTrue(stat.S_ISDIR(parent_metadata.st_mode))
            self.assertEqual(parent_metadata.st_uid, os.geteuid())
            self.assertEqual(stat.S_IMODE(parent_metadata.st_mode), 0o700)
            observed.append(path)
            return read_archive(path, digest, size)

        with tempfile.TemporaryDirectory() as directory:
            fixture = self.harness(directory)
            with mock.patch.object(ARCHIVE, "read_start_archive", side_effect=inspect_archive):
                result = fixture.select()
            self.assertEqual(result["record_bytes"], fixture.record_bytes)
            self.assertEqual(len(observed), 1)
            self.assertFalse(observed[0].exists())
            self.assertFalse(observed[0].parent.exists())
            fixture.assert_no_mutation_or_retry(self)

    def test_zero_or_multiple_exact_artifacts_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.harness(directory)
            fixture.artifacts[-1]["name"] = "some-other-artifact"
            self.assert_rejected(fixture)
            self.assertEqual(fixture.download_calls, [])

        with tempfile.TemporaryDirectory() as directory:
            fixture = self.harness(directory)
            duplicate = copy.deepcopy(fixture.artifact)
            duplicate["id"] = DOWNLOAD_ID + 1
            fixture.artifacts.append(duplicate)
            self.assert_rejected(fixture)
            self.assertEqual(fixture.download_calls, [])

    def test_rejects_expired_wrong_run_digest_size_and_untyped_metadata(self) -> None:
        mutations = (
            ("expired", {"expired": True}),
            ("wrong-run", {"workflow_run": {"id": 123, "head_sha": "a" * 40,
                                               "repository_id": 7890,
                                               "head_repository_id": 7890}}),
            ("wrong-sha", {"workflow_run": {"id": 123456, "head_sha": "0" * 40,
                                              "repository_id": 7890,
                                              "head_repository_id": 7890}}),
            ("wrong-repository", {"workflow_run": {"id": 123456, "head_sha": "a" * 40,
                                                     "repository_id": 999,
                                                     "head_repository_id": 7890}}),
            ("bad-digest", {"digest": "SHA256:" + "a" * 64}),
            ("oversized", {"size_in_bytes": ARCHIVE.MAX_ARCHIVE + 1}),
            ("zero-size", {"size_in_bytes": 0}),
            ("string-id", {"id": str(DOWNLOAD_ID)}),
            ("boolean-id", {"id": True}),
            ("boolean-size", {"size_in_bytes": True}),
        )
        for label, changes in mutations:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                fixture = self.harness(directory)
                fixture.set_artifact(**changes)
                self.assert_rejected(fixture)
                self.assertEqual(fixture.download_calls, [])

        for field in ("id", "repository_id", "head_repository_id"):
            for invalid in (str(123456), True):
                with self.subTest(field=field, invalid=invalid), tempfile.TemporaryDirectory() as directory:
                    fixture = self.harness(directory)
                    workflow_run = copy.deepcopy(fixture.artifact["workflow_run"])
                    workflow_run[field] = invalid
                    fixture.set_artifact(workflow_run=workflow_run)
                    self.assert_rejected(fixture)
                    self.assertEqual(fixture.download_calls, [])

    def test_rejects_inconsistent_duplicate_short_and_overflowing_pages(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.harness(directory)

            def inconsistent(path: str, count: int, value: dict) -> dict:
                if path.endswith("page=2"):
                    value["total_count"] += 1
                return value

            fixture.selector_hook = inconsistent
            self.assert_rejected(fixture)
            self.assertEqual(fixture.download_calls, [])

        with tempfile.TemporaryDirectory() as directory:
            fixture = self.harness(directory)
            fixture.artifacts[-1]["id"] = fixture.artifacts[0]["id"]
            self.assert_rejected(fixture)
            self.assertEqual(fixture.download_calls, [])

        with tempfile.TemporaryDirectory() as directory:
            fixture = self.harness(directory)

            def short_first_page(path: str, count: int, value: dict) -> dict:
                if path.endswith("page=1"):
                    value["artifacts"] = value["artifacts"][:-1]
                return value

            fixture.selector_hook = short_first_page
            self.assert_rejected(fixture)
            self.assertEqual(fixture.download_calls, [])

        with tempfile.TemporaryDirectory() as directory:
            fixture = self.harness(directory)
            fixture.total_count_override = selector.MAX_ARTIFACT_PAGES * selector.ARTIFACT_PAGE_SIZE + 1
            self.assert_rejected(fixture)
            self.assertEqual(fixture.download_calls, [])

    def test_rejects_malformed_page_shape_and_nontyped_counts(self) -> None:
        cases = (
            ("not-object", lambda value: [value]),
            ("not-array", lambda value: {**value, "artifacts": "100"}),
            ("string-total", lambda value: {**value, "total_count": "101"}),
            ("boolean-total", lambda value: {**value, "total_count": True}),
            ("negative-total", lambda value: {**value, "total_count": -1}),
        )
        for label, mutate in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                fixture = self.harness(directory)

                def malformed(path: str, count: int, value: dict):
                    if path.endswith("page=1"):
                        return mutate(value)
                    return value

                fixture.selector_hook = malformed
                self.assert_rejected(fixture)
                self.assertEqual(fixture.download_calls, [])

    def test_initial_direct_metadata_must_normalize_to_the_complete_listing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.harness(directory)

            def mismatch(path: str, count: int, value: dict) -> dict:
                if path == fixture.direct_artifact_path and count == 1:
                    value["size_in_bytes"] += 1
                return value

            fixture.selector_hook = mismatch
            self.assert_rejected(fixture)
            self.assertEqual(fixture.download_calls, [])

    def test_rejects_direct_metadata_drift_after_download(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.harness(directory)

            def drift(path: str, count: int, value: dict) -> dict:
                if path == fixture.direct_artifact_path and count == 2:
                    value["digest"] = "sha256:" + "0" * 64
                return value

            fixture.selector_hook = drift
            self.assert_rejected(fixture)
            self.assertEqual(len(fixture.download_calls), 1)

    def test_rejects_complete_relist_drift_after_download(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.harness(directory)

            def drift(path: str, count: int, value: dict) -> dict:
                if path.endswith("page=2") and count == 2:
                    value["artifacts"][-1]["digest"] = "sha256:" + "0" * 64
                return value

            fixture.selector_hook = drift
            self.assert_rejected(fixture)
            self.assertEqual(len(fixture.download_calls), 1)

    def test_rejects_late_source_provider_and_actual_event_byte_drift(self) -> None:
        source_latest = f"repos/{REPOSITORY}/actions/runs/{auth_tests.SOURCE_RUN_ID}"
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.harness(directory)

            def drift_source(path: str, count: int, value: dict) -> dict:
                if path == source_latest and count == 3:
                    value["head_sha"] = "0" * 40
                return value

            fixture.api_hook = drift_source
            self.assert_rejected(fixture)
            self.assertEqual(len(fixture.download_calls), 1)

        with tempfile.TemporaryDirectory() as directory:
            fixture = self.harness(directory)

            def drift_event(path: str, count: int, value: dict) -> dict:
                if path.endswith("page=2") and count == 2:
                    changed = auth_tests.event_fixture(fixture.source)
                    changed["extra_same_identity_field"] = "late event bytes"
                    fixture.set_event(changed)
                return value

            fixture.selector_hook = drift_event
            self.assert_rejected(fixture)
            self.assertEqual(len(fixture.download_calls), 1)

    def test_download_failure_unknown_oversize_and_digest_mismatch_are_not_retried(self) -> None:
        cases = (
            ("failed", lambda fixture: setattr(fixture, "download_result", (1, b""))),
            ("unknown", lambda fixture: setattr(
                fixture, "download_error", subprocess.TimeoutExpired(["gh", "api"], 30)
            )),
            ("oversized", lambda fixture: setattr(
                fixture, "download_result", (0, fixture.archive_bytes + b"x")
            )),
            ("digest", lambda fixture: setattr(
                fixture, "download_result", (0, b"x" + fixture.archive_bytes[1:])
            )),
        )
        for label, configure in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                fixture = self.harness(directory)
                configure(fixture)
                self.assert_rejected(fixture)
                self.assertEqual(len(fixture.download_calls), 1)

    def test_all_metadata_selectors_are_gets_and_source_record_is_not_used_for_selection(self) -> None:
        source_bytes = b'{"not-a-selector":"record content stays opaque"}\n'
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.harness(directory)
            fixture.record_bytes = source_bytes
            fixture.archive_bytes = archive_fixture(fixture.record_bytes, fixture.bundle_bytes)
            fixture.download_result = (0, fixture.archive_bytes)
            fixture.set_artifact(
                size_in_bytes=len(fixture.archive_bytes),
                digest="sha256:" + hashlib.sha256(fixture.archive_bytes).hexdigest(),
            )
            result = fixture.select()

        self.assertEqual(result["record_bytes"], source_bytes)
        self.assertEqual(result["artifact_selector"]["name"], fixture.artifact_name)
        self.assertEqual(len(fixture.download_calls), 1)
        self.assertTrue(all("/actions/runs/" in path or "/actions/artifacts/" in path
                            for path in fixture.metadata_calls))
        fixture.assert_no_mutation_or_retry(self)


if __name__ == "__main__":
    unittest.main()
