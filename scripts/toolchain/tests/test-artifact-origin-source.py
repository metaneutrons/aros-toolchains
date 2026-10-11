#!/usr/bin/env python3
"""Mocked cross-run artifact recovery tests; no provider or signature is authenticated."""

from __future__ import annotations

import argparse
import copy
import hashlib
from contextlib import redirect_stdout
import importlib.util
import io
import os
from pathlib import Path
import resource
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import warnings
import zipfile


HELPER = Path(__file__).resolve().parents[1] / "artifact-origin.py"
SPEC = importlib.util.spec_from_file_location("artifact_origin_source", HELPER)
assert SPEC is not None and SPEC.loader is not None
origin = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(origin)


REPOSITORY = "example/project"
REPOSITORY_ID = 7890
SOURCE = {
    "repository": REPOSITORY,
    "repository_id": REPOSITORY_ID,
    "producer_commit": "a" * 40,
    "source_ref": "refs/heads/main",
    "workflow": ".github/workflows/toolchain.yml",
    "run_id": 123456,
    "run_attempt": 2,
}
CALLER = {
    "repository": REPOSITORY,
    "repository_id": REPOSITORY_ID,
    "producer_commit": "c" * 40,
    "source_ref": "refs/heads/recover",
    "workflow": ".github/workflows/reader.yml",
    "run_id": 234567,
    "run_attempt": 3,
}
SOURCE_CHECK_ID = 555001
CALLER_CHECK_ID = 555101
SOURCE_JOB_ID = 90901
CALLER_JOB_ID = 90911
SOURCE_JOB_NAME = "Build toolchain"
CALLER_JOB_NAME = "Read source"
PAYLOAD_ID = 667002
PROOF_ID = 667003
PAYLOAD_NAME = "toolchain-build"
PROOF_NAME = "toolchain-origin-proof"
LANE = {"role": "build", "group": "rv32", "host": "linux",
        "profile": "release", "copy": "a"}
PAYLOAD_BYTES = b"synthetic executable payload\x00"
BUNDLE_BYTES = b"synthetic signature bundle; mock only\n"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def measurement(data: bytes) -> dict:
    return {"sha256": sha256(data), "size": len(data)}


def write_zip(path: Path, members: dict[str, bytes]) -> bytes:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return path.read_bytes()


def proof_zip_bytes(entries: list[tuple[str, bytes, int | None]]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data, mode in entries:
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", message=r"Duplicate name:.*", category=UserWarning)
                if mode is None:
                    archive.writestr(name, data)
                else:
                    member = zipfile.ZipInfo(name)
                    member.create_system = 3
                    member.external_attr = mode << 16
                    archive.writestr(member, data)
    return buffer.getvalue()


def caller_job() -> dict:
    return {
        "id": CALLER_JOB_ID,
        "check_run_url": f"https://api.github.com/repos/{REPOSITORY}/check-runs/{CALLER_CHECK_ID}",
        "name": CALLER_JOB_NAME,
        "head_sha": CALLER["producer_commit"],
        "run_id": CALLER["run_id"],
        "run_attempt": CALLER["run_attempt"],
        "status": "in_progress",
        "conclusion": None,
    }


def source_job() -> dict:
    return {
        "id": SOURCE_JOB_ID,
        "check_run_url": f"https://api.github.com/repos/{REPOSITORY}/check-runs/{SOURCE_CHECK_ID}",
        "name": SOURCE_JOB_NAME,
        "head_sha": SOURCE["producer_commit"],
        "run_id": SOURCE["run_id"],
        "run_attempt": SOURCE["run_attempt"],
        "status": "completed",
        "conclusion": "success",
    }


def provider_artifact(ctx: dict, identity: dict) -> dict:
    return {
        "id": identity["id"],
        "name": identity["name"],
        "digest": f"sha256:{identity['sha256']}",
        "expired": False,
        "size_in_bytes": identity["size_in_bytes"],
        "workflow_run": {
            "id": ctx["run_id"],
            "head_sha": ctx["producer_commit"],
            "repository_id": ctx["repository_id"],
            "head_repository_id": ctx["repository_id"],
        },
    }


def fixture(root: Path) -> dict:
    root = root.resolve()
    payload_zip = root / "payload.zip"
    payload_zip_bytes = write_zip(payload_zip, {"bin/tool": PAYLOAD_BYTES})
    payload = {
        "id": PAYLOAD_ID,
        "name": PAYLOAD_NAME,
        "sha256": sha256(payload_zip_bytes),
        "size_in_bytes": len(payload_zip_bytes),
    }

    origin_record = {
        "schema": origin.SCHEMA,
        "context": copy.deepcopy(SOURCE),
        "selection": dict(LANE),
        "job": {"id": SOURCE_JOB_ID, "check_run_id": SOURCE_CHECK_ID,
                "name": SOURCE_JOB_NAME},
        "artifact": dict(payload),
        "files": {"bin/tool": measurement(PAYLOAD_BYTES)},
    }
    origin_bytes = origin.canonical(origin_record)
    origin_path = root / "origin.json"
    origin_path.write_bytes(origin_bytes)
    bundle_path = root / "origin.sigstore.json"
    bundle_path.write_bytes(BUNDLE_BYTES)

    proof_zip = root / "proof.zip"
    proof_zip_bytes = write_zip(proof_zip, {
        "origin.json": origin_bytes,
        "origin.sigstore.json": BUNDLE_BYTES,
    })
    proof = {
        "id": PROOF_ID,
        "name": PROOF_NAME,
        "sha256": sha256(proof_zip_bytes),
        "size_in_bytes": len(proof_zip_bytes),
    }
    selection = {
        "schema": origin.SELECTION_SCHEMA,
        "context": copy.deepcopy(SOURCE),
        "selection": dict(LANE),
        "job": {"id": SOURCE_JOB_ID, "name": SOURCE_JOB_NAME},
        "artifact": dict(payload),
        "proof": dict(proof),
    }
    selection_path = root / "source-selection.json"
    selection_path.write_bytes(origin.canonical(selection))
    invocation = (f"https://github.com/{REPOSITORY}/actions/runs/{SOURCE['run_id']}"
                  f"/attempts/{SOURCE['run_attempt']}")
    verified = [{"verificationResult": {
        "signature": {"certificate": {"runInvocationURI": invocation}},
        "statement": {"subject": [{"name": origin_path.name,
                                    "digest": {"sha256": sha256(origin_bytes)}}]},
    }}]
    return {
        "root": root,
        "source": copy.deepcopy(SOURCE),
        "caller": copy.deepcopy(CALLER),
        "origin_record": origin_record,
        "origin_bytes": origin_bytes,
        "origin_path": origin_path,
        "bundle_path": bundle_path,
        "bundle_bytes": BUNDLE_BYTES,
        "proof_zip_bytes": proof_zip_bytes,
        "payload_zip_bytes": payload_zip_bytes,
        "selection": selection,
        "selection_path": selection_path,
        "payload": payload,
        "proof": proof,
        "source_pages": [{"total_count": 1, "jobs": [source_job()]}],
        "caller_pages": [{"total_count": 1, "jobs": [caller_job()]}],
        "proof_provider": provider_artifact(SOURCE, proof),
        "payload_provider": provider_artifact(SOURCE, payload),
        "verified": verified,
        "args": argparse.Namespace(
            workflow=CALLER["workflow"], job_name=CALLER_JOB_NAME,
            source_selection=selection_path, origin=origin_path, bundle=bundle_path,
        ),
    }


def environment_for(ctx: dict) -> dict[str, str]:
    return {
        "GITHUB_REPOSITORY": ctx["repository"],
        "GITHUB_REPOSITORY_ID": str(ctx["repository_id"]),
        "GITHUB_SHA": ctx["producer_commit"],
        "GITHUB_REF": ctx["source_ref"],
        "GITHUB_RUN_ID": str(ctx["run_id"]),
        "GITHUB_RUN_ATTEMPT": str(ctx["run_attempt"]),
        "GITHUB_WORKFLOW_REF": f"{ctx['repository']}/{ctx['workflow']}@{ctx['source_ref']}",
        "GITHUB_WORKFLOW_SHA": ctx["producer_commit"],
    }


def flag_value(arguments: list[str], flag: str) -> str:
    return arguments[arguments.index(flag) + 1]


class CrossRunVerifySourceTests(unittest.TestCase):
    """Provider, signature and runner OIDC observations are explicit mocks."""

    def rebind_proof(self, data: dict, archive: bytes) -> None:
        proof = dict(data["proof"])
        proof["sha256"] = sha256(archive)
        proof["size_in_bytes"] = len(archive)
        data["proof_zip_bytes"] = archive
        data["proof"] = proof
        data["selection"]["proof"] = dict(proof)
        data["selection_path"].write_bytes(origin.canonical(data["selection"]))
        data["proof_provider"] = provider_artifact(data["source"], proof)

    def run_source_verification(self, data: dict, *, source_pages: list | None = None,
                                caller_pages: list | None = None,
                                oidc_check_id: int = CALLER_CHECK_ID,
                                download_overrides: dict[str, bytes] | None = None,
                                mutate_selection_after_verify: bool = False) -> tuple[list, list]:
        gh_calls: list[tuple[list[str], str]] = []
        download_calls: list[list[str]] = []
        downloads = {"proof": data["proof_zip_bytes"],
                     "payload": data["payload_zip_bytes"]}
        downloads.update(download_overrides or {})
        provider_index = 0
        selected_source_pages = data["source_pages"] if source_pages is None else source_pages
        selected_caller_pages = data["caller_pages"] if caller_pages is None else caller_pages

        def mocked_gh_json(arguments, purpose="GitHub observation"):
            nonlocal provider_index
            command = list(arguments)
            gh_calls.append((command, purpose))
            if purpose == "origin signature authentication":
                selected = data["selection"]["context"]
                expected_signature_binding = {
                    "--repo": data["source"]["repository"],
                    "--signer-workflow": f"{data['source']['repository']}/{data['source']['workflow']}",
                    "--signer-digest": data["source"]["producer_commit"],
                    "--source-digest": data["source"]["producer_commit"],
                    "--source-ref": data["source"]["source_ref"],
                }
                observed = {key: flag_value(command, key) for key in expected_signature_binding}
                # This is a synthetic verifier response boundary. It rejects
                # selectors that differ from the only mock signature fixture.
                if selected != data["source"] or observed != expected_signature_binding:
                    raise origin.OriginError("mock signature verifier rejected source binding")
                return data["verified"]
            if command[:3] == ["api", "--paginate", "--slurp"]:
                endpoint = command[3]
                caller_endpoint = (
                    f"repos/{CALLER['repository']}/actions/runs/{CALLER['run_id']}"
                    f"/attempts/{CALLER['run_attempt']}/jobs?per_page=100"
                )
                if endpoint == caller_endpoint:
                    return selected_caller_pages
                return selected_source_pages
            if len(command) == 2 and command[0] == "api" \
                    and "/actions/artifacts/" in command[1]:
                result = data["proof_provider"] if provider_index == 0 else data["payload_provider"]
                provider_index += 1
                return result
            raise AssertionError(f"unexpected mocked GitHub call: {command!r}, {purpose!r}")

        def mocked_run(command, *, stdout=None, stderr=None, timeout=None, check=None,
                       preexec_fn=None):
            selected_command = list(command)
            download_calls.append(selected_command)
            if stdout is None:
                raise AssertionError("mock ZIP download has no output handle")
            if selected_command[-1].endswith(f"/{PROOF_ID}/zip"):
                limit = data["selection"]["proof"]["size_in_bytes"] + 1
                if preexec_fn is None:
                    raise AssertionError("proof download omitted its child file-size cap")
                # Execute the callback with setrlimit replaced so the test
                # inspects the intended cap without changing the parent.
                with mock.patch.object(origin.resource, "setrlimit") as setrlimit:
                    preexec_fn()
                    setrlimit.assert_called_once_with(origin.resource.RLIMIT_FSIZE,
                                                       (limit, limit))
                stdout.write(downloads["proof"])
            elif selected_command[-1].endswith(f"/{PAYLOAD_ID}/zip"):
                if preexec_fn is None:
                    raise AssertionError("payload download omitted its child file-size cap")
                with mock.patch.object(origin.resource, "setrlimit") as setrlimit:
                    preexec_fn()
                    limit = data["selection"]["artifact"]["size_in_bytes"] + 1
                    setrlimit.assert_called_once_with(origin.resource.RLIMIT_FSIZE, (limit, limit))
                stdout.write(downloads["payload"])
            else:
                if preexec_fn is None:
                    raise AssertionError("payload download omitted its child file-size cap")
                # Dynamic selected identities still receive the relevant
                # baseline synthetic bytes and must fail the independent check.
                stdout.write(downloads["payload"])
            return SimpleNamespace(returncode=0)

        oidc_calls: list[dict] = []
        oidc_env: list[dict[str, str | None]] = []
        verified_args: list[argparse.Namespace] = []
        materialized_dirs: list[tuple[Path, tuple[str, ...]]] = []
        materialized_bytes: list[tuple[bytes, bytes]] = []

        def mocked_oidc(ctx: dict) -> int:
            oidc_calls.append(copy.deepcopy(ctx))
            oidc_env.append({key: os.environ.get(key) for key in (
                "GITHUB_REPOSITORY", "GITHUB_REPOSITORY_ID", "GITHUB_SHA", "GITHUB_REF",
                "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_WORKFLOW_REF",
                "GITHUB_WORKFLOW_SHA",
            )})
            return oidc_check_id

        real_verify = origin.verify

        def maybe_change_selection(*args, **kwargs):
            source_args = args[0]
            verified_args.append(source_args)
            materialized_dirs.append((source_args.origin.parent,
                                      tuple(sorted(path.name for path in source_args.origin.parent.iterdir()))))
            materialized_bytes.append((source_args.origin.read_bytes(), source_args.bundle.read_bytes()))
            result = real_verify(*args, **kwargs)
            if mutate_selection_after_verify:
                changed = copy.deepcopy(data["selection"])
                changed["selection"]["group"] = "changed"
                data["args"].source_selection.write_bytes(origin.canonical(changed))
            return result

        try:
            with mock.patch.dict(os.environ, environment_for(CALLER), clear=False), \
                    mock.patch.object(origin, "owning_check_id", side_effect=mocked_oidc), \
                    mock.patch.object(origin, "gh_json", side_effect=mocked_gh_json), \
                    mock.patch.object(origin.subprocess, "run", side_effect=mocked_run), \
                    mock.patch.object(origin, "verify", side_effect=maybe_change_selection):
                with redirect_stdout(io.StringIO()):
                    origin.verify_source(data["args"], CALLER)
        finally:
            data["gh_calls"] = gh_calls
            data["download_calls"] = download_calls
            data["oidc_calls"] = oidc_calls
            data["oidc_env"] = oidc_env
            data["verified_args"] = verified_args
            data["materialized_dirs"] = materialized_dirs
            data["materialized_bytes"] = materialized_bytes
        return gh_calls, download_calls

    def run_rejected(self, data: dict, **options) -> None:
        with self.assertRaises(origin.OriginError):
            self.run_source_verification(data, **options)

    def test_positive_uses_source_for_signature_provider_and_downloads_caller_for_oidc_and_jobs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data = fixture(Path(temporary))
            gh_calls, downloads = self.run_source_verification(data)

            self.assertEqual(data["origin_path"].read_bytes(), data["origin_bytes"])
            self.assertEqual(data["args"].source_selection.read_bytes(),
                             origin.canonical(data["selection"]))
            self.assertEqual(data["oidc_calls"], [CALLER])
            self.assertEqual(data["oidc_env"], [environment_for(CALLER)])

            job_endpoints = [call[0][3] for call in gh_calls
                             if call[0][:3] == ["api", "--paginate", "--slurp"]]
            self.assertEqual(job_endpoints, [
                f"repos/{REPOSITORY}/actions/runs/{CALLER['run_id']}"
                f"/attempts/{CALLER['run_attempt']}/jobs?per_page=100",
                f"repos/{REPOSITORY}/actions/runs/{SOURCE['run_id']}"
                f"/attempts/{SOURCE['run_attempt']}/jobs?per_page=100",
                f"repos/{REPOSITORY}/actions/runs/{SOURCE['run_id']}"
                f"/attempts/{SOURCE['run_attempt']}/jobs?per_page=100",
            ])
            signature = [call for call in gh_calls
                         if call[1] == "origin signature authentication"]
            self.assertEqual(len(signature), 1)
            signed_args = signature[0][0]
            self.assertEqual(flag_value(signed_args, "--repo"), SOURCE["repository"])
            self.assertEqual(flag_value(signed_args, "--signer-workflow"),
                             f"{REPOSITORY}/{SOURCE['workflow']}")
            self.assertEqual(flag_value(signed_args, "--signer-digest"), SOURCE["producer_commit"])
            self.assertEqual(flag_value(signed_args, "--source-ref"), SOURCE["source_ref"])
            artifact_endpoints = [call[0][1] for call in gh_calls
                                  if call[0][:1] == ["api"] and len(call[0]) == 2
                                  and "/actions/artifacts/" in call[0][1]]
            self.assertEqual(artifact_endpoints, [
                f"repos/{REPOSITORY}/actions/artifacts/{PROOF_ID}",
                f"repos/{REPOSITORY}/actions/artifacts/{PAYLOAD_ID}",
            ])
            self.assertEqual(downloads, [
                ["gh", "api", f"repos/{REPOSITORY}/actions/artifacts/{PROOF_ID}/zip"],
                ["gh", "api", f"repos/{REPOSITORY}/actions/artifacts/{PAYLOAD_ID}/zip"],
            ])

    def test_automatic_proof_download_materializes_only_fixed_files_and_cleans_private_temp(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data = fixture(Path(temporary))
            data["args"].origin = None
            data["args"].bundle = None
            self.run_source_verification(data)

            self.assertEqual(len(data["verified_args"]), 1)
            verified_args = data["verified_args"][0]
            self.assertEqual(verified_args.origin.name, "origin.json")
            self.assertEqual(verified_args.bundle.name, "origin.sigstore.json")
            self.assertEqual(verified_args.origin.parent, verified_args.bundle.parent)
            self.assertNotEqual(verified_args.origin, data["origin_path"])
            self.assertNotEqual(verified_args.bundle, data["bundle_path"])
            self.assertEqual(data["materialized_dirs"], [(
                verified_args.origin.parent,
                ("origin.json", "origin.sigstore.json", "proof.zip"),
            )])
            self.assertFalse(verified_args.origin.parent.exists())
            self.assertEqual(data["materialized_bytes"], [(
                data["origin_bytes"], data["bundle_bytes"],
            )])

    def test_rejects_incomplete_optional_local_pair_before_provider_access(self) -> None:
        for origin_path, bundle_path in ((None, "bundle"), ("origin", None)):
            with self.subTest(origin=origin_path, bundle=bundle_path), \
                    tempfile.TemporaryDirectory() as temporary:
                data = fixture(Path(temporary))
                data["args"].origin = (None if origin_path is None else data["origin_path"])
                data["args"].bundle = (None if bundle_path is None else data["bundle_path"])
                self.run_rejected(data)
                self.assertEqual(data["gh_calls"], [])
                self.assertEqual(data["download_calls"], [])
                self.assertEqual(data["oidc_calls"], [])
                self.assertEqual(data["verified_args"], [])

    def test_child_file_size_limit_stops_a_regular_file_write(self) -> None:
        limit = 4096
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "bounded-output"

            def set_child_limit() -> None:
                resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))

            with output.open("xb") as handle:
                result = subprocess.run(
                    [sys.executable, "-c",
                     "import os; os.write(1, b'x' * 4096); os.write(1, b'y')"],
                    stdout=handle, stderr=subprocess.DEVNULL, timeout=10,
                    check=False, preexec_fn=set_child_limit,
                )
            self.assertNotEqual(result.returncode, 0)
            self.assertLessEqual(output.stat().st_size, limit)

    def test_rejects_digest_rebound_unsafe_proof_zips_before_signature_or_payload_fetch(self) -> None:
        cases = ("extra", "traversal", "duplicate", "symlink", "oversized")
        for case in cases:
            with self.subTest(zip_entry=case), tempfile.TemporaryDirectory() as temporary:
                data = fixture(Path(temporary))
                entries: list[tuple[str, bytes, int | None]] = [
                    ("origin.json", data["origin_bytes"], None),
                    ("origin.sigstore.json", data["bundle_bytes"], None),
                ]
                metadata_limit = max(
                    data["selection_path"].stat().st_size,
                    data["origin_path"].stat().st_size,
                    data["bundle_path"].stat().st_size,
                ) + 64
                if case == "extra":
                    entries.append(("extra.json", b"unexpected", None))
                elif case == "traversal":
                    entries[1] = ("../origin.sigstore.json", data["bundle_bytes"], None)
                elif case == "duplicate":
                    entries.append(("origin.json", b"duplicate member", None))
                elif case == "symlink":
                    entries[0] = ("origin.json", data["origin_bytes"], stat.S_IFLNK | 0o777)
                else:
                    oversized = data["origin_bytes"] + b"x" * (
                        metadata_limit + 1 - len(data["origin_bytes"]))
                    entries[0] = ("origin.json", oversized, None)

                archive = proof_zip_bytes(entries)
                self.rebind_proof(data, archive)
                self.assertEqual(data["selection"]["proof"]["sha256"], sha256(archive))
                self.assertEqual(data["selection"]["proof"]["size_in_bytes"], len(archive))
                self.assertEqual(data["proof_provider"]["digest"], f"sha256:{sha256(archive)}")

                with mock.patch.object(origin, "proof_members", wraps=origin.proof_members) as boundary:
                    if case == "oversized":
                        with mock.patch.object(origin, "MAX_METADATA", metadata_limit):
                            self.run_rejected(data)
                    else:
                        self.run_rejected(data)
                    boundary.assert_called_once()
                self.assertEqual(data["download_calls"], [
                    ["gh", "api", f"repos/{REPOSITORY}/actions/artifacts/{PROOF_ID}/zip"]
                ])
                self.assertEqual(data["verified_args"], [])
                self.assertFalse(any(purpose == "origin signature authentication"
                                     for _, purpose in data["gh_calls"]))
                self.assertEqual([command[1] for command, purpose in data["gh_calls"]
                                  if purpose == "GitHub observation" and command[0] == "api"
                                  and len(command) == 2 and "/actions/artifacts/" in command[1]], [
                    f"repos/{REPOSITORY}/actions/artifacts/{PROOF_ID}"
                ])

    def test_rejects_digest_rebound_raw_nul_zip_names_in_proof_and_payload_verification(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data = fixture(Path(temporary))
            archive = proof_zip_bytes([
                ("origin.json_suffix", data["origin_bytes"], None),
                ("origin.sigstore.json", data["bundle_bytes"], None),
            ])
            original_name = b"origin.json_suffix"
            nul_name = b"origin.json\x00suffix"
            self.assertEqual(len(original_name), len(nul_name))
            self.assertEqual(archive.count(original_name), 2)
            archive = archive.replace(original_name, nul_name)
            self.assertEqual(archive.count(nul_name), 2)

            # CPython's public filename is truncated at NUL. The ZIP's
            # original name remains distinct, which the closed readers check.
            with zipfile.ZipFile(io.BytesIO(archive)) as handle:
                member = handle.infolist()[0]
                self.assertEqual(member.filename, "origin.json")
                self.assertEqual(member.orig_filename, "origin.json\x00suffix")

            self.rebind_proof(data, archive)
            data["args"].origin = None
            data["args"].bundle = None
            self.assertEqual(data["selection"]["proof"]["sha256"], sha256(archive))
            with mock.patch.object(origin, "proof_members", wraps=origin.proof_members) as boundary:
                self.run_rejected(data)
                boundary.assert_called_once()
            self.assertEqual(data["download_calls"], [
                ["gh", "api", f"repos/{REPOSITORY}/actions/artifacts/{PROOF_ID}/zip"]
            ])
            self.assertEqual(data["verified_args"], [])
            self.assertFalse(any(purpose == "origin signature authentication"
                                 for _, purpose in data["gh_calls"]))
            self.assertEqual([command[1] for command, purpose in data["gh_calls"]
                              if purpose == "GitHub observation" and command[0] == "api"
                              and len(command) == 2 and "/actions/artifacts/" in command[1]], [
                f"repos/{REPOSITORY}/actions/artifacts/{PROOF_ID}"
            ])

            path = Path(temporary) / "nul-name.zip"
            path.write_bytes(archive)
            with self.assertRaises(origin.OriginError):
                origin.verify_zip(path, {
                    "origin.json": measurement(data["origin_bytes"]),
                    "origin.sigstore.json": measurement(data["bundle_bytes"]),
                }, sha256(archive), len(archive))

    def test_source_selection_is_closed_and_rejects_duplicate_json_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data = fixture(Path(temporary))
            with self.assertRaises(origin.OriginError):
                origin.source_selection({**data["selection"], "unexpected": True}, CALLER)

            duplicate = (b'{"schema":"' + origin.SELECTION_SCHEMA.encode()
                         + b'","schema":"' + origin.SELECTION_SCHEMA.encode() + b'"}')
            data["args"].source_selection.write_bytes(duplicate)
            self.run_rejected(data)

    def test_source_selection_rejects_unknown_nested_keys_and_unknown_json_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data = fixture(Path(temporary))
            unknown = copy.deepcopy(data["selection"])
            unknown["proof"]["provider_url"] = "https://example.invalid"
            data["args"].source_selection.write_bytes(origin.canonical(unknown))
            self.run_rejected(data)

            unknown = copy.deepcopy(data["selection"])
            unknown["unexpected"] = True
            data["args"].source_selection.write_bytes(origin.canonical(unknown))
            self.run_rejected(data)

    def test_rejects_source_context_run_attempt_commit_ref_workflow_and_repository_changes(self) -> None:
        mutations = {
            "run": lambda ctx: ctx.__setitem__("run_id", ctx["run_id"] + 1),
            "attempt": lambda ctx: ctx.__setitem__("run_attempt", ctx["run_attempt"] + 1),
            "commit": lambda ctx: ctx.__setitem__("producer_commit", "d" * 40),
            "ref": lambda ctx: ctx.__setitem__("source_ref", "refs/heads/other"),
            "workflow": lambda ctx: ctx.__setitem__("workflow", ".github/workflows/other.yml"),
            "repository": lambda ctx: ctx.__setitem__("repository", "other/project"),
            "repository ID": lambda ctx: ctx.__setitem__("repository_id", REPOSITORY_ID + 1),
        }
        for label, mutate in mutations.items():
            with self.subTest(context=label), tempfile.TemporaryDirectory() as temporary:
                data = fixture(Path(temporary))
                mutate(data["selection"]["context"])
                data["args"].source_selection.write_bytes(origin.canonical(data["selection"]))
                self.run_rejected(data)

    def test_rejects_source_attempt_equal_to_caller_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data = fixture(Path(temporary))
            data["selection"]["context"]["run_id"] = CALLER["run_id"]
            data["selection"]["context"]["run_attempt"] = CALLER["run_attempt"]
            data["args"].source_selection.write_bytes(origin.canonical(data["selection"]))
            self.run_rejected(data)

    def test_selects_source_job_by_id_and_rejects_a_signed_owner_with_another_id(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data = fixture(Path(temporary))
            duplicate = copy.deepcopy(source_job())
            duplicate["id"] += 1
            duplicate["check_run_url"] = f"https://api.github.com/repos/{REPOSITORY}/check-runs/555002"
            data["source_pages"] = [{"total_count": 2, "jobs": [source_job(), duplicate]}]
            self.run_source_verification(data)
            self.assertEqual(data["oidc_calls"], [CALLER])

        with tempfile.TemporaryDirectory() as temporary:
            data = fixture(Path(temporary))
            duplicate = copy.deepcopy(source_job())
            duplicate["id"] += 1
            duplicate["check_run_url"] = f"https://api.github.com/repos/{REPOSITORY}/check-runs/555002"
            data["source_pages"] = [{"total_count": 2, "jobs": [source_job(), duplicate]}]
            data["selection"]["job"]["id"] = duplicate["id"]
            data["args"].source_selection.write_bytes(origin.canonical(data["selection"]))
            self.run_rejected(data)

    def test_rejects_duplicate_source_job_ids_and_check_bindings(self) -> None:
        duplicate_id = copy.deepcopy(source_job())
        duplicate_id["name"] = "Other name"
        duplicate_check = copy.deepcopy(source_job())
        duplicate_check["id"] += 1
        for label, duplicate in (("ID", duplicate_id), ("check binding", duplicate_check)):
            with self.subTest(identity=label), tempfile.TemporaryDirectory() as temporary:
                data = fixture(Path(temporary))
                data["source_pages"] = [{"total_count": 2,
                                         "jobs": [source_job(), duplicate]}]
                self.run_rejected(data)

        for key, value in (("head_sha", "e" * 40), ("run_id", SOURCE["run_id"] + 1),
                           ("run_attempt", SOURCE["run_attempt"] + 1)):
            with self.subTest(identity=key), tempfile.TemporaryDirectory() as temporary:
                data = fixture(Path(temporary))
                changed = source_job()
                changed[key] = value
                data["source_pages"] = [{"total_count": 1, "jobs": [changed]}]
                self.run_rejected(data)

    def test_rejects_each_independent_payload_and_proof_identity_field(self) -> None:
        for artifact_key in ("artifact", "proof"):
            for field in ("id", "name", "sha256", "size_in_bytes"):
                with self.subTest(artifact=artifact_key, field=field), \
                        tempfile.TemporaryDirectory() as temporary:
                    data = fixture(Path(temporary))
                    selected = data["selection"][artifact_key]
                    if field == "id":
                        selected[field] += 77
                    elif field == "name":
                        selected[field] += "-changed"
                    elif field == "sha256":
                        selected[field] = "f" * 64
                    else:
                        selected[field] += 1
                    data["args"].source_selection.write_bytes(origin.canonical(data["selection"]))
                    self.run_rejected(data)

    def test_rejects_changed_proof_zip_and_changed_local_proof_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data = fixture(Path(temporary))
            self.run_rejected(data, download_overrides={"proof": data["proof_zip_bytes"] + b"changed"})

        for filename, key in (("origin.json", "origin_path"),
                              ("origin.sigstore.json", "bundle_path")):
            with self.subTest(file=filename), tempfile.TemporaryDirectory() as temporary:
                data = fixture(Path(temporary))
                path = data[key]
                path.write_bytes(path.read_bytes() + b"changed")
                self.run_rejected(data)

    def test_rejects_caller_workflow_identity_oidc_and_job_mismatch(self) -> None:
        for variable, value in (("GITHUB_WORKFLOW_REF", "other/project/workflow.yml@refs/heads/x"),
                                ("GITHUB_WORKFLOW_SHA", "f" * 40)):
            with self.subTest(caller_environment=variable), tempfile.TemporaryDirectory() as temporary:
                data = fixture(Path(temporary))
                changed_env = environment_for(CALLER)
                changed_env[variable] = value
                with mock.patch.dict(os.environ, changed_env, clear=False), \
                        mock.patch.object(origin, "owning_check_id") as oidc:
                    with self.assertRaises(origin.OriginError):
                        with redirect_stdout(io.StringIO()):
                            origin.verify_source(data["args"], CALLER)
                    oidc.assert_not_called()

        with tempfile.TemporaryDirectory() as temporary:
            data = fixture(Path(temporary))
            self.run_rejected(data, oidc_check_id=SOURCE_CHECK_ID)
            self.assertEqual(data["oidc_calls"], [CALLER])

        with tempfile.TemporaryDirectory() as temporary:
            data = fixture(Path(temporary))
            wrong_caller = caller_job()
            wrong_caller["name"] = "Different caller job"
            data["caller_pages"] = [{"total_count": 1, "jobs": [wrong_caller]}]
            self.run_rejected(data)

    def test_rejects_linked_or_changed_selection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data = fixture(Path(temporary))
            link = data["root"] / "linked-selection.json"
            link.symlink_to(data["selection_path"])
            data["args"].source_selection = link
            with self.assertRaises((origin.OriginError, OSError)):
                self.run_source_verification(data)
            self.assertEqual(data["oidc_calls"], [])

        with tempfile.TemporaryDirectory() as temporary:
            data = fixture(Path(temporary))
            self.run_rejected(data, mutate_selection_after_verify=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
