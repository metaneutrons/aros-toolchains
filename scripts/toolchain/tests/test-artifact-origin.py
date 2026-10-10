#!/usr/bin/env python3
"""Closed-boundary unit tests for artifact-origin.py; no provider access."""

from __future__ import annotations

import argparse
import copy
from contextlib import redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import warnings
import zipfile


HELPER = Path(__file__).resolve().parents[1] / "artifact-origin.py"
SPEC = importlib.util.spec_from_file_location("artifact_origin", HELPER)
assert SPEC is not None and SPEC.loader is not None
origin = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(origin)


COMMIT = "a" * 40
REPOSITORY = "example/project"
WORKFLOW = ".github/workflows/toolchain.yml"
RUN_ID = 123456
RUN_ATTEMPT = 2
REPOSITORY_ID = 7890
CHECK_RUN_ID = 555001
ARTIFACT_ID = 667002
ARTIFACT_NAME = "toolchain-build"
ARTIFACT_DIGEST = "b" * 64


def context() -> dict:
    return {
        "repository": REPOSITORY,
        "repository_id": REPOSITORY_ID,
        "producer_commit": COMMIT,
        "source_ref": "refs/heads/main",
        "workflow": WORKFLOW,
        "run_id": RUN_ID,
        "run_attempt": RUN_ATTEMPT,
    }


def claims(now: int) -> dict:
    ctx = context()
    return {
        "iss": "https://token.actions.githubusercontent.com",
        "aud": origin.AUDIENCE,
        "repository": ctx["repository"],
        "repository_id": str(ctx["repository_id"]),
        "sha": ctx["producer_commit"],
        "ref": ctx["source_ref"],
        "workflow_ref": f'{ctx["repository"]}/{ctx["workflow"]}@{ctx["source_ref"]}',
        "workflow_sha": ctx["producer_commit"],
        "runner_environment": "github-hosted",
        "run_id": str(ctx["run_id"]),
        "run_attempt": str(ctx["run_attempt"]),
        "check_run_id": str(CHECK_RUN_ID),
        "iat": now,
        "nbf": now,
        "exp": now + 900,
    }


def job(check_run_id: int = CHECK_RUN_ID) -> dict:
    return {
        "id": 90901,
        "check_run_url": f"https://api.github.com/repos/{REPOSITORY}/check-runs/{check_run_id}",
        "name": "Build toolchain",
        "head_sha": COMMIT,
        "run_id": RUN_ID,
        "run_attempt": RUN_ATTEMPT,
        "status": "completed",
        "conclusion": "success",
    }


def artifact() -> dict:
    return {
        "id": ARTIFACT_ID,
        "name": ARTIFACT_NAME,
        "digest": f"sha256:{ARTIFACT_DIGEST}",
        "expired": False,
        "size_in_bytes": 321,
        "workflow_run": {
            "id": RUN_ID,
            "head_sha": COMMIT,
            "repository_id": REPOSITORY_ID,
            "head_repository_id": REPOSITORY_ID,
        },
    }


def measurement(data: bytes) -> dict:
    return {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}


def zip_file(directory: Path, members: list[tuple[str, bytes, int | None]]) -> Path:
    directory = directory.resolve()
    path = directory / "payload.zip"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data, mode in members:
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", message=r"Duplicate name:.*", category=UserWarning)
                if mode is None:
                    archive.writestr(name, data)
                else:
                    info = zipfile.ZipInfo(name)
                    info.create_system = 3
                    info.external_attr = mode << 16
                    archive.writestr(info, data)
    return path


def archive_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def lane_args(**overrides) -> argparse.Namespace:
    values = {
        "workflow": WORKFLOW,
        "job_name": "Build toolchain",
        "artifact_id": ARTIFACT_ID,
        "artifact_name": ARTIFACT_NAME,
        "role": "build",
        "group": "rv32",
        "host": "linux",
        "profile": "release",
        "copy": "a",
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def origin_record(files: dict, digest: str, size: int) -> dict:
    args = lane_args()
    return {
        "schema": origin.SCHEMA,
        "context": context(),
        "selection": {key: getattr(args, key) for key in ("role", "group", "host", "profile", "copy")},
        "job": {"id": 90901, "check_run_id": CHECK_RUN_ID, "name": args.job_name},
        "artifact": {
            "id": ARTIFACT_ID,
            "name": ARTIFACT_NAME,
            "sha256": digest,
            "size_in_bytes": size,
        },
        "files": files,
    }


def verify_fixture(root: Path, *, signed_digest: str | None = None,
                   signed_size: int | None = None, signed_size_delta: int = 0) -> dict:
    """Build local synthetic bytes; these are not authenticated provider fixtures."""
    root = root.resolve()
    archive_path = zip_file(root, [("bin/tool", b"mock executable", None)])
    download_bytes = archive_path.read_bytes()
    actual_digest = hashlib.sha256(download_bytes).hexdigest()
    actual_size = len(download_bytes)
    digest = actual_digest if signed_digest is None else signed_digest
    size = actual_size + signed_size_delta if signed_size is None else signed_size
    files = {"bin/tool": measurement(b"mock executable")}
    record_bytes = origin.canonical(origin_record(files, digest, size))
    origin_path = root / "origin.json"
    origin_path.write_bytes(record_bytes)
    bundle_path = root / "bundle.json"
    bundle_path.write_bytes(b"synthetic bundle bytes; mock only")
    args = lane_args(origin=origin_path, bundle=bundle_path)

    # This synthetic attestation result is an explicit mock. It exercises the
    # call flow only; no certificate, signature, or provider authentication occurs.
    invocation = (f"https://github.com/{REPOSITORY}/actions/runs/{RUN_ID}"
                  f"/attempts/{RUN_ATTEMPT}")
    verified = [{"verificationResult": {
        "signature": {"certificate": {"runInvocationURI": invocation}},
        "statement": {"subject": [{
            "name": origin_path.name,
            "digest": {"sha256": hashlib.sha256(record_bytes).hexdigest()},
        }]},
    }}]
    observed_artifact = artifact()
    observed_artifact["digest"] = f"sha256:{digest}"
    observed_artifact["size_in_bytes"] = size
    return {
        "args": args,
        "context": context(),
        "origin_record": origin_record(files, digest, size),
        "origin_bytes": record_bytes,
        "bundle_bytes": bundle_path.read_bytes(),
        "download_bytes": download_bytes,
        "actual_digest": actual_digest,
        "actual_size": actual_size,
        "files": files,
        "verified": verified,
        "jobs": [{"total_count": 1, "jobs": [job()]}],
        "artifact": observed_artifact,
    }


class CanonicalMetadataTests(unittest.TestCase):
    def test_positive_accepts_only_canonical_exact_integers(self) -> None:
        self.assertEqual(origin.positive(1), 1)
        self.assertEqual(origin.positive("9007199254740991"), 9007199254740991)
        for value in (True, False, 0, -1, 1.0, "0", "01", "+1", " 1", "1 ", "1e2",
                      "9007199254740992", "1" * 17, None):
            with self.subTest(value=value):
                with self.assertRaises(origin.OriginError):
                    origin.positive(value)

    def test_json_parser_rejects_duplicate_keys_and_nonfinite_numbers(self) -> None:
        self.assertEqual(origin.parse_json(b'{"a":1,"nested":{"b":true}}'),
                         {"a": 1, "nested": {"b": True}})
        for raw in (b'{"a":1,"a":2}', b'{"nested":{"x":1,"x":2}}',
                    b'{"n":NaN}', b'{"n":Infinity}', b'{"n":-Infinity}'):
            with self.subTest(raw=raw):
                with self.assertRaises(origin.OriginError):
                    origin.parse_json(raw)


class OidcClaimTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = 1_800_000_000
        self.valid = claims(self.now)
        self.ctx = context()

    def test_exact_hosted_workflow_source_times_and_current_check_id(self) -> None:
        self.assertEqual(origin.require_oidc_claims(self.valid, self.ctx, self.now), CHECK_RUN_ID)

    def test_rejects_mismatched_audience_repository_source_workflow_or_runner(self) -> None:
        mismatches = {
            "iss": "https://issuer.example.invalid",
            "aud": "another-audience",
            "repository": "other/project",
            "sha": "c" * 40,
            "ref": "refs/heads/other",
            "workflow_ref": "other/project/.github/workflows/toolchain.yml@refs/heads/main",
            "workflow_sha": "d" * 40,
            "runner_environment": "self-hosted",
        }
        for key, value in mismatches.items():
            with self.subTest(key=key):
                observed = dict(self.valid)
                observed[key] = value
                with self.assertRaises(origin.OriginError):
                    origin.require_oidc_claims(observed, self.ctx, self.now)

    def test_rejects_mismatched_run_attempt_and_repository_ids(self) -> None:
        for key, value in (("repository_id", "7891"), ("run_id", str(RUN_ID + 1)),
                           ("run_attempt", str(RUN_ATTEMPT + 1))):
            with self.subTest(key=key):
                observed = dict(self.valid)
                observed[key] = value
                with self.assertRaises(origin.OriginError):
                    origin.require_oidc_claims(observed, self.ctx, self.now)

    def test_rejects_missing_or_invalid_check_id_reusable_job_and_expired_token(self) -> None:
        missing_check = dict(self.valid)
        del missing_check["check_run_id"]
        reusable = dict(self.valid, job_workflow_ref=f"{REPOSITORY}/{WORKFLOW}@{COMMIT}")
        expired = dict(self.valid, exp=self.now)
        invalid_check = dict(self.valid, check_run_id="0")
        for name, observed in (("missing check", missing_check), ("reusable workflow", reusable),
                               ("expired", expired), ("invalid check", invalid_check)):
            with self.subTest(case=name):
                with self.assertRaises(origin.OriginError):
                    origin.require_oidc_claims(observed, self.ctx, self.now)

    def test_job_workflow_diagnostics_are_closed_and_still_fail_before_recording(self) -> None:
        cases = (
            ({"job_workflow_ref": None}, "ref=null, sha=absent"),
            ({"job_workflow_ref": "", "job_workflow_sha": ""}, "ref=empty, sha=empty"),
            ({"job_workflow_ref": self.valid["workflow_ref"], "job_workflow_sha": COMMIT},
             "ref=matches-caller, sha=matches-caller"),
            ({"job_workflow_ref": "DO-NOT-LOG-this-provider-value", "job_workflow_sha": COMMIT},
             "ref=differs, sha=matches-caller"),
            ({"job_workflow_ref": 17, "job_workflow_sha": False}, "ref=non-string, sha=non-string"),
        )
        for fields, shape in cases:
            with self.subTest(shape=shape):
                with self.assertRaises(origin.OriginError) as caught:
                    origin.require_oidc_claims(dict(self.valid, **fields), self.ctx, self.now)
                self.assertEqual(str(caught.exception),
                                 f"unapproved job workflow identity ({shape}); no token or claim values logged")

    def test_rejects_times_outside_the_short_token_window(self) -> None:
        cases = {
            "issued too far in the future": dict(self.valid, iat=self.now + 31),
            "not yet valid": dict(self.valid, nbf=self.now + 31),
            "lifetime over one hour": dict(self.valid, exp=self.now + 3601),
            "string timestamp": dict(self.valid, iat=str(self.now)),
            "boolean timestamp": dict(self.valid, exp=True),
        }
        for label, observed in cases.items():
            with self.subTest(case=label):
                with self.assertRaises(origin.OriginError):
                    origin.require_oidc_claims(observed, self.ctx, self.now)


class JobSelectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.ctx = context()
        self.selected = job()

    def test_selects_one_exact_check_from_complete_attempt_pages(self) -> None:
        decoy = job(CHECK_RUN_ID + 1)
        decoy["id"] = self.selected["id"] + 1
        pages = [
            {"total_count": 2, "jobs": [decoy]},
            {"total_count": 2, "jobs": [self.selected]},
        ]
        self.assertEqual(origin.select_job(pages, self.ctx, CHECK_RUN_ID, "Build toolchain", "completed"), {
            "id": self.selected["id"], "check_run_id": CHECK_RUN_ID, "name": "Build toolchain",
        })

    def test_accepts_the_currently_executing_owner_for_recording(self) -> None:
        active = {**self.selected, "status": "in_progress", "conclusion": None}
        pages = [{"total_count": 1, "jobs": [active]}]
        self.assertEqual(origin.select_job(pages, self.ctx, CHECK_RUN_ID,
                                           "Build toolchain", "in_progress"), {
            "id": active["id"], "check_run_id": CHECK_RUN_ID, "name": "Build toolchain",
        })

    def test_rejects_duplicate_or_incomplete_pages_and_nonunique_check(self) -> None:
        duplicate = copy.deepcopy(self.selected)
        incomplete_pages = [{"total_count": 2, "jobs": [self.selected]}]
        duplicate_pages = [{"total_count": 2, "jobs": [self.selected, duplicate]}]
        inconsistent_totals = [
            {"total_count": 2, "jobs": [self.selected]},
            {"total_count": 3, "jobs": [job(CHECK_RUN_ID + 1)]},
        ]
        wrong_check = [({**self.selected, "check_run_url": "https://api.github.com/repos/example/project/check-runs/1"})]
        cases = (
            ([{"total_count": 0, "jobs": []}], "empty result"),
            (incomplete_pages, "incomplete pages"),
            (duplicate_pages, "duplicate job identity"),
            (inconsistent_totals, "inconsistent totals"),
            ([{"total_count": 1, "jobs": wrong_check}], "wrong check URL"),
        )
        for pages, label in cases:
            with self.subTest(case=label):
                with self.assertRaises(origin.OriginError):
                    origin.select_job(pages, self.ctx, CHECK_RUN_ID, "Build toolchain", "completed")

    def test_rejects_wrong_source_name_status_or_attempt(self) -> None:
        variants = {
            "source": {**self.selected, "head_sha": "e" * 40},
            "name": {**self.selected, "name": "Different job"},
            "status": {**self.selected, "status": "in_progress", "conclusion": None},
            "attempt": {**self.selected, "run_attempt": RUN_ATTEMPT - 1},
        }
        for label, observed in variants.items():
            with self.subTest(case=label):
                pages = [{"total_count": 1, "jobs": [observed]}]
                with self.assertRaises(origin.OriginError):
                    origin.select_job(pages, self.ctx, CHECK_RUN_ID, "Build toolchain", "completed")


class ArtifactSelectionTests(unittest.TestCase):
    def test_exact_artifact_identity_and_expiry(self) -> None:
        self.assertEqual(origin.select_artifact(artifact(), context(), ARTIFACT_ID,
                                                ARTIFACT_NAME, ARTIFACT_DIGEST), {
            "id": ARTIFACT_ID,
            "name": ARTIFACT_NAME,
            "sha256": ARTIFACT_DIGEST,
            "size_in_bytes": 321,
        })

    def test_rejects_wrong_id_name_digest_expiry_repository_run_or_source(self) -> None:
        variants = {}
        changed = artifact()
        changed["id"] += 1
        variants["artifact id"] = changed
        changed = artifact()
        changed["name"] = "other-artifact"
        variants["artifact name"] = changed
        changed = artifact()
        changed["digest"] = "sha256:" + "c" * 64
        variants["digest"] = changed
        changed = artifact()
        changed["expired"] = True
        variants["expired"] = changed
        for key, value in (("id", RUN_ID + 1), ("head_sha", "f" * 40),
                           ("repository_id", REPOSITORY_ID + 1),
                           ("head_repository_id", REPOSITORY_ID + 1)):
            changed = artifact()
            changed["workflow_run"][key] = value
            variants[f"workflow {key}"] = changed
        for label, observed in variants.items():
            with self.subTest(case=label):
                with self.assertRaises(origin.OriginError):
                    origin.select_artifact(observed, context(), ARTIFACT_ID,
                                           ARTIFACT_NAME, ARTIFACT_DIGEST)


class PayloadInventoryTests(unittest.TestCase):
    def test_empty_payload_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(origin.OriginError):
                origin.measure_files(Path(temporary).resolve())

    def test_safe_ordinary_files_are_measured_exactly(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "include").mkdir()
            (root / "include" / "header.h").write_bytes(b"#define VALUE 7\n")
            (root / "tool.bin").write_bytes(b"binary\x00payload")
            self.assertEqual(origin.measure_files(root), {
                "include/header.h": measurement(b"#define VALUE 7\n"),
                "tool.bin": measurement(b"binary\x00payload"),
            })

    def test_symlink_and_hardlink_payload_files_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "target").write_bytes(b"payload")
            os.symlink(root / "target", root / "linked")
            with self.assertRaises((origin.OriginError, OSError)):
                origin.measure_files(root)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "one.bin").write_bytes(b"payload")
            os.link(root / "one.bin", root / "two.bin")
            with self.assertRaises(origin.OriginError):
                origin.measure_files(root)

    def test_casefold_path_collision_is_rejected(self) -> None:
        # The system temporary volume may be case-insensitive on macOS. Put
        # this fixture beside the test so both spellings can coexist.
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as temporary:
            root = Path(temporary).resolve()
            (root / "Tool.bin").write_bytes(b"one")
            (root / "tool.bin").write_bytes(b"two")
            with self.assertRaises(origin.OriginError):
                origin.measure_files(root)


class ZipVerificationTests(unittest.TestCase):
    def test_exact_zip_file_bytes_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = zip_file(root, [("bin/tool", b"executable bytes", None),
                                   ("share/info.txt", b"metadata\n", None)])
            files = {
                "bin/tool": measurement(b"executable bytes"),
                "share/info.txt": measurement(b"metadata\n"),
            }
            origin.verify_zip(path, files, archive_digest(path), path.stat().st_size)

    def test_zip_size_and_signed_casefold_aliases_are_checked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = zip_file(root, [("tool.txt", b"exact", None)])
            files = {"tool.txt": measurement(b"exact")}
            with self.assertRaises(origin.OriginError):
                origin.verify_zip(path, files, archive_digest(path), path.stat().st_size + 1)
            aliased = {"Tool.txt": measurement(b"exact"), "tool.txt": measurement(b"exact")}
            with self.assertRaises(origin.OriginError):
                origin.verify_zip(path, aliased, archive_digest(path))

    def test_implicit_directory_case_aliases_and_file_directory_conflicts_fail(self) -> None:
        cases = (
            ([ ("A/one", b"one", None), ("a/two", b"two", None) ],
             {"A/one": measurement(b"one"), "a/two": measurement(b"two")}, "directory case alias"),
            ([ ("node", b"file", None), ("node/child", b"child", None) ],
             {"node": measurement(b"file"), "node/child": measurement(b"child")}, "file before directory"),
            ([ ("node/child", b"child", None), ("node", b"file", None) ],
             {"node/child": measurement(b"child"), "node": measurement(b"file")}, "directory before file"),
        )
        for members, files, label in cases:
            with self.subTest(case=label), tempfile.TemporaryDirectory() as temporary:
                path = zip_file(Path(temporary), members)
                with self.assertRaises(origin.OriginError):
                    origin.verify_zip(path, files, archive_digest(path))

    def test_duplicate_unselected_and_traversal_members_fail(self) -> None:
        cases = (
            ([ ("a.txt", b"one", None), ("a.txt", b"two", None) ],
             {"a.txt": measurement(b"one"), "b.txt": measurement(b"two")}, "duplicate"),
            ([ ("a.txt", b"one", None), ("extra.txt", b"two", None) ],
             {"a.txt": measurement(b"one"), "b.txt": measurement(b"two")}, "unselected"),
            ([ ("../escape", b"one", None) ], {"../escape": measurement(b"one")}, "traversal"),
        )
        for members, files, label in cases:
            with self.subTest(case=label), tempfile.TemporaryDirectory() as temporary:
                path = zip_file(Path(temporary), members)
                with self.assertRaises(origin.OriginError):
                    origin.verify_zip(path, files, archive_digest(path))

    def test_symlink_members_tampered_file_bytes_and_archive_digest_fail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            link_mode = stat.S_IFLNK | 0o777
            path = zip_file(root, [("link", b"target", link_mode)])
            with self.assertRaises(origin.OriginError):
                origin.verify_zip(path, {"link": measurement(b"target")}, archive_digest(path))

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = zip_file(root, [("file.txt", b"changed", None)])
            with self.assertRaises(origin.OriginError):
                origin.verify_zip(path, {"file.txt": measurement(b"original")}, archive_digest(path))

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = zip_file(root, [("file.txt", b"exact", None)])
            wrong_digest = "0" * 64
            self.assertNotEqual(archive_digest(path), wrong_digest)
            with self.assertRaises(origin.OriginError):
                origin.verify_zip(path, {"file.txt": measurement(b"exact")}, wrong_digest)


class RecordVerifyCallFlowTests(unittest.TestCase):
    """Call-flow tests use explicit mocks; no provider or signature is authenticated."""

    def _mocked_verify(self, fixture: dict, *, attestation: list | None = None,
                       jobs: list | None = None, observed_artifact: dict | None = None,
                       download_bytes: bytes | None = None) -> tuple[list, list]:
        """Run verify with mock provider, attestation, and download boundaries."""
        selected_attestation = fixture["verified"] if attestation is None else attestation
        selected_jobs = fixture["jobs"] if jobs is None else jobs
        selected_artifact = fixture["artifact"] if observed_artifact is None else observed_artifact
        selected_download = fixture["download_bytes"] if download_bytes is None else download_bytes
        gh_calls = []
        download_calls = []
        fixture["_gh_calls"] = gh_calls
        fixture["_download_calls"] = download_calls

        def mocked_gh_json(arguments, purpose="GitHub observation"):
            args = list(arguments)
            gh_calls.append((args, purpose))
            if purpose == "origin signature authentication":
                return selected_attestation
            if args[:3] == ["api", "--paginate", "--slurp"]:
                return selected_jobs
            if args == ["api", f"repos/{REPOSITORY}/actions/artifacts/{ARTIFACT_ID}"]:
                return selected_artifact
            raise AssertionError(f"unexpected mocked GitHub call: {args!r}, {purpose!r}")

        def mocked_run(command, *, stdout=None, stderr=None, timeout=None, check=None):
            download_calls.append(list(command))
            if stdout is None:
                raise AssertionError("mocked ZIP download did not receive an output handle")
            stdout.write(selected_download)
            return SimpleNamespace(returncode=0)

        with mock.patch.object(origin, "gh_json", side_effect=mocked_gh_json), \
                mock.patch.object(origin.subprocess, "run", side_effect=mocked_run):
            with redirect_stdout(io.StringIO()):
                origin.verify(fixture["args"], fixture["context"])
        return gh_calls, download_calls

    def test_mocked_record_writes_exact_fresh_origin_and_never_overwrites_or_overlaps(self) -> None:
        # OIDC ownership and provider observations are mocks, not authenticated claims.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            payload = root / "payload"
            payload.mkdir()
            (payload / "tool.bin").write_bytes(b"record payload")
            output = root / "origin.json"
            ctx = context()
            args = lane_args(artifact_sha256=ARTIFACT_DIGEST,
                             payload_dir=payload, output=output)
            active_job = {**job(), "status": "in_progress", "conclusion": None}
            pages = [{"total_count": 1, "jobs": [active_job]}]
            provider_artifact = artifact()
            gh_calls = []

            def mocked_gh_json(arguments, purpose="GitHub observation"):
                call = (list(arguments), purpose)
                gh_calls.append(call)
                if arguments[:3] == ["api", "--paginate", "--slurp"]:
                    return pages
                if arguments == ["api", f"repos/{REPOSITORY}/actions/artifacts/{ARTIFACT_ID}"]:
                    return provider_artifact
                raise AssertionError(f"unexpected mocked GitHub call: {call!r}")

            with mock.patch.object(origin, "owning_check_id", return_value=CHECK_RUN_ID) as mocked_oidc, \
                    mock.patch.object(origin, "gh_json", side_effect=mocked_gh_json):
                with redirect_stdout(io.StringIO()):
                    origin.record(args, ctx)
                stored = output.read_bytes()
                expected_files = origin.measure_files(payload)
                expected = {
                    "schema": origin.SCHEMA,
                    "context": ctx,
                    "selection": {"role": "build", "group": "rv32", "host": "linux",
                                  "profile": "release", "copy": "a"},
                    "job": {"id": 90901, "check_run_id": CHECK_RUN_ID, "name": "Build toolchain"},
                    "artifact": {"id": ARTIFACT_ID, "name": ARTIFACT_NAME,
                                 "sha256": ARTIFACT_DIGEST, "size_in_bytes": 321},
                    "files": expected_files,
                }
                self.assertEqual(stored, origin.canonical(expected))
                self.assertEqual(origin.parse_json(stored), expected)
                mocked_oidc.assert_called_once_with(ctx)
                self.assertEqual(gh_calls, [
                    (["api", "--paginate", "--slurp",
                      f"repos/{REPOSITORY}/actions/runs/{RUN_ID}/attempts/{RUN_ATTEMPT}/jobs?per_page=100"],
                     "GitHub observation"),
                    (["api", f"repos/{REPOSITORY}/actions/artifacts/{ARTIFACT_ID}"],
                     "GitHub observation"),
                ])

                # An existing record cannot be replaced, and placing it under
                # the payload root is rejected before any mocked observations.
                with self.assertRaises(origin.OriginError):
                    origin.record(args, ctx)
                args.output = payload / "origin.json"
                with self.assertRaises(origin.OriginError):
                    origin.record(args, ctx)
                self.assertEqual(output.read_bytes(), stored)
                self.assertEqual(mocked_oidc.call_count, 1)
                self.assertEqual(len(gh_calls), 2)

    def test_mocked_verify_uses_exact_signer_source_and_remeasures_all_inputs(self) -> None:
        # All bytes and the successful attestation response are synthetic mocks.
        with tempfile.TemporaryDirectory() as temporary:
            fixture = verify_fixture(Path(temporary))
            with mock.patch.object(origin, "normalized_file", wraps=origin.normalized_file) as measured, \
                    mock.patch.object(origin, "verify_zip", wraps=origin.verify_zip) as verify_zip_mock:
                gh_calls, download_calls = self._mocked_verify(fixture)

            expected_attestation_args = [
                "attestation", "verify", str(fixture["args"].origin),
                "--bundle", str(fixture["args"].bundle),
                "--repo", REPOSITORY,
                "--signer-workflow", f"{REPOSITORY}/{WORKFLOW}",
                "--signer-digest", COMMIT,
                "--source-digest", COMMIT,
                "--source-ref", "refs/heads/main",
                "--deny-self-hosted-runners", "--format", "json",
            ]
            self.assertEqual(gh_calls, [
                (expected_attestation_args, "origin signature authentication"),
                (["api", "--paginate", "--slurp",
                  f"repos/{REPOSITORY}/actions/runs/{RUN_ID}/attempts/{RUN_ATTEMPT}/jobs?per_page=100"],
                 "GitHub observation"),
                (["api", f"repos/{REPOSITORY}/actions/artifacts/{ARTIFACT_ID}"],
                 "GitHub observation"),
            ])
            self.assertEqual(download_calls, [[
                "gh", "api", f"repos/{REPOSITORY}/actions/artifacts/{ARTIFACT_ID}/zip",
            ]])
            zip_path = verify_zip_mock.call_args.args[0]
            normalized_paths = [Path(call.args[0]) for call in measured.call_args_list]
            self.assertEqual(normalized_paths.count(fixture["args"].origin), 2)
            self.assertEqual(normalized_paths.count(fixture["args"].bundle), 2)
            self.assertEqual(normalized_paths.count(zip_path), 2)

    def test_mocked_verify_rejects_changed_run_and_missing_or_extra_subjects(self) -> None:
        # Each mocked attestation is deliberately altered; no signature checks are real.
        for label in ("run invocation", "missing subject", "extra subject"):
            with self.subTest(case=label), tempfile.TemporaryDirectory() as temporary:
                fixture = verify_fixture(Path(temporary))
                changed = copy.deepcopy(fixture["verified"])
                verification = changed[0]["verificationResult"]
                if label == "run invocation":
                    verification["signature"]["certificate"]["runInvocationURI"] += "/wrong"
                elif label == "missing subject":
                    verification["statement"]["subject"] = []
                else:
                    verification["statement"]["subject"].append(
                        {"name": "extra.json", "digest": {"sha256": "0" * 64}})
                with self.assertRaises(origin.OriginError):
                    self._mocked_verify(fixture, attestation=changed)

    def test_mocked_verify_rejects_changed_job_and_artifact_selection(self) -> None:
        for label in ("job", "artifact"):
            with self.subTest(case=label), tempfile.TemporaryDirectory() as temporary:
                fixture = verify_fixture(Path(temporary))
                jobs = fixture["jobs"]
                provider = fixture["artifact"]
                if label == "job":
                    replacement = job()
                    replacement["id"] += 1
                    jobs = [{"total_count": 1, "jobs": [replacement]}]
                else:
                    provider = copy.deepcopy(provider)
                    provider["size_in_bytes"] += 1
                with self.assertRaises(origin.OriginError):
                    self._mocked_verify(fixture, jobs=jobs, observed_artifact=provider)
                self.assertEqual(fixture["_download_calls"], [])

    def test_mocked_verify_rejects_a_linked_signature_bundle(self) -> None:
        # The fixture bytes are synthetic; the check is local path handling only.
        with tempfile.TemporaryDirectory() as temporary:
            fixture = verify_fixture(Path(temporary))
            target = Path(temporary).resolve() / "bundle-target.json"
            target.write_bytes(b"mock bundle target")
            linked_bundle = Path(temporary).resolve() / "linked-bundle.json"
            linked_bundle.symlink_to(target)
            fixture["args"].bundle = linked_bundle
            with mock.patch.object(origin, "gh_json") as mocked_gh, \
                    mock.patch.object(origin.subprocess, "run") as mocked_download:
                with self.assertRaises((origin.OriginError, OSError)):
                    origin.verify(fixture["args"], fixture["context"])
                mocked_gh.assert_not_called()
                mocked_download.assert_not_called()

    def test_mocked_verify_rejects_wrong_downloaded_zip_size_or_digest(self) -> None:
        # Both provider metadata and the signed record are mock inputs; downloaded bytes stay fixed.
        cases = (
            ("size", {"signed_size_delta": 1}),
            ("digest", {"signed_digest": "0" * 64}),
        )
        for label, options in cases:
            with self.subTest(case=label), tempfile.TemporaryDirectory() as temporary:
                fixture = verify_fixture(Path(temporary), **options)
                with self.assertRaises(origin.OriginError):
                    self._mocked_verify(fixture)
                self.assertEqual(len(fixture["_download_calls"]), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
