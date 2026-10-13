"""Synthetic process-boundary tests for isolated V2 audits; no real proof is run."""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts/toolchain/audit-isolated-release-v2.py"
SPEC = importlib.util.spec_from_file_location("audit_isolated_release_v2", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
adapter = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = adapter
SPEC.loader.exec_module(adapter)

FIXTURE_SCRIPT = ROOT / "scripts/toolchain/tests/test-record-complete-qualification-v2.py"
FIXTURE_SPEC = importlib.util.spec_from_file_location("record_qualification_fixture", FIXTURE_SCRIPT)
assert FIXTURE_SPEC is not None and FIXTURE_SPEC.loader is not None
fixture_module = importlib.util.module_from_spec(FIXTURE_SPEC)
sys.modules[FIXTURE_SPEC.name] = fixture_module
FIXTURE_SPEC.loader.exec_module(fixture_module)
recorder = fixture_module.adapter


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


class AuditFixture(fixture_module.Fixture):
    def __init__(self) -> None:
        super().__init__()
        self.qualification_dir = self.root / "original-qualification"
        self.qualification_dir.mkdir()
        self.qualification = self.qualification_dir / "qualification-evidence-v2.json"
        recorder_args = recorder._parser().parse_args(super().argv())
        state = recorder._preflight(recorder_args)
        command = recorder._record_argv(recorder_args, state, self.qualification)
        process = subprocess.run(
            command, env={**os.environ, **self.environment()},
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        if process.returncode != 0:
            raise AssertionError(process.stderr.decode("utf-8", errors="replace"))
        self.qualification_sha = digest(self.qualification.read_bytes())
        self.native_log.unlink(missing_ok=True)
        self.operation_root = tempfile.TemporaryDirectory(prefix="fake-v2-audit-output-")
        self.operation = Path(self.operation_root.name).resolve() / "operation"

    def argv(self, **overrides: str) -> list[str]:
        result = super().argv(**overrides)
        result.extend(("--qualification-evidence", str(self.qualification),
                       "--qualification-sha256", self.qualification_sha,
                       "--now", "150"))
        return result

    def refresh_runtime_binding(self) -> None:
        self.runtime_sha = digest(self.runtime.read_bytes())
        self.summary_doc["bindings"]["aros_sha256"] = self.runtime_sha
        self.summary.write_bytes(recorder.json.dumps(
            self.summary_doc, sort_keys=True, separators=(",", ":")
        ).encode() + b"\n")
        self.summary_sha = digest(self.summary.read_bytes())

    def close(self) -> None:
        self.operation_root.cleanup()
        super().close()


class IsolatedReleaseAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_verifier = adapter.VERIFIER_COMMAND

    def tearDown(self) -> None:
        adapter.VERIFIER_COMMAND = self.original_verifier

    def invoke(self, fixture: AuditFixture, *, mode: str = "positive",
               mutation_target: Path | None = None,
               argv: list[str] | None = None) -> tuple[int, str, str]:
        adapter.VERIFIER_COMMAND = (sys.executable, str(fixture.fake_verifier))
        stdout = __import__("io").StringIO()
        stderr = __import__("io").StringIO()
        with mock.patch.dict(os.environ, fixture.environment(
                mode, mutation_target=mutation_target), clear=False), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = adapter.main(fixture.argv() if argv is None else argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def assert_failure(self, fixture: AuditFixture, *, mode: str = "positive",
                       mutation_target: Path | None = None,
                       argv: list[str] | None = None) -> str:
        code, stdout, stderr = self.invoke(
            fixture, mode=mode, mutation_target=mutation_target, argv=argv
        )
        self.assertNotEqual(code, 0)
        self.assertEqual(stdout, "", "a failed audit must emit no success summary")
        self.assertFalse((fixture.operation / "audit-summary.json").exists())
        self.assertIn("failed", stderr)
        return stderr

    @staticmethod
    def replace_arg(argv: list[str], name: str, value: str) -> None:
        argv[argv.index(name) + 1] = value

    def native_calls(self, fixture: AuditFixture) -> list[list[str]]:
        if not fixture.native_log.exists():
            return []
        return [json.loads(line) for line in fixture.native_log.read_text().splitlines()]

    def test_positive_audit_verifies_dynamic_compiler_and_plus_sdk_inventory(self) -> None:
        fixture = AuditFixture()
        try:
            original = fixture.qualification.read_bytes()
            code, stdout, stderr = self.invoke(fixture)
            self.assertEqual(code, 0, stderr)
            self.assertEqual(stderr, "")
            summary = json.loads(stdout)
            self.assertEqual(summary["schema"], "aros-toolchain-isolated-release-audit-v2")
            self.assertEqual(summary["counts"], {
                "lane_count": 1, "build_count": 2, "sdk_count": 1,
                "sdk_generation_count": 1,
            })
            self.assertEqual(summary["native_readback"]["operation"], "verify-qualification")
            self.assertEqual(summary["native_readback"]["sdks"][0]["sdk_id"], "sdk+abi")
            self.assertEqual(summary["original_qualification"]["sha256"], fixture.qualification_sha)
            self.assertEqual(fixture.qualification.read_bytes(), original)
            self.assertFalse((fixture.operation / "qualification-evidence-v2.json").exists())
            self.assertFalse((fixture.operation / ".qualification-evidence-pending.json").exists())
            self.assertFalse((fixture.operation / "audit-summary.json").exists())
            self.assertEqual(json.loads((fixture.operation / "evidence-policy.json").read_bytes())[
                "now"], 150)
            native = self.native_calls(fixture)
            self.assertEqual([call[2] for call in native], ["verify-qualification"])
            verify = native[0]
            self.assertEqual(verify[verify.index("--qualification-evidence") + 1],
                             str(fixture.qualification))
            self.assertEqual(verify[verify.index("--qualification-sha256") + 1],
                             fixture.qualification_sha)
            self.assertFalse(summary["scope"]["tag_object_independently_authenticated"])
            self.assertFalse(summary["scope"]["qualification_recorded_by_this_adapter"])
            external = json.loads(fixture.verifier_log.read_text())
            self.assertEqual(external[external.index("--source-ref") + 1], "refs/tags/v1.2.3")
            self.assertEqual(external[external.index("--run-attempt") + 1], "2")
        finally:
            fixture.close()

    def test_extra_or_missing_release_file_fails_before_external_child(self) -> None:
        for missing in (False, True):
            with self.subTest(missing=missing):
                fixture = AuditFixture()
                try:
                    if missing:
                        (fixture.release / "sdk+abi.tar.xz").unlink()
                    else:
                        (fixture.release / "unselected-extra.bin").write_bytes(b"extra")
                    error = self.assert_failure(fixture)
                    self.assertIn("missing or extra", error)
                    self.assertFalse(fixture.verifier_log.exists())
                    self.assertEqual(self.native_calls(fixture), [])
                finally:
                    fixture.close()

    def test_independent_selectors_and_candidate_identity_fail_before_children(self) -> None:
        cases = (
            ("--runtime-sha256", "0" * 64),
            ("--inputs-sha256", "0" * 64),
            ("--index-sha256", "0" * 64),
            ("--selection-sha256", "0" * 64),
            ("--subject-manifest-sha256", "0" * 64),
            ("--candidate-summary-sha256", "0" * 64),
            ("--qualification-sha256", "0" * 64),
            ("--source-tag", "v1.2.4"),
            ("--now", "300"),
        )
        for option, value in cases:
            with self.subTest(option=option):
                fixture = AuditFixture()
                try:
                    argv = fixture.argv()
                    self.replace_arg(argv, option, value)
                    self.assert_failure(fixture, argv=argv)
                    self.assertFalse(fixture.verifier_log.exists())
                    self.assertEqual(self.native_calls(fixture), [])
                finally:
                    fixture.close()

    def test_release_tag_and_download_url_must_match_selected_repository(self) -> None:
        cases = (
            ("toolchain-dev-abcd", "https://github.com/example/aros-toolchains/releases/download/toolchain-dev-abcd"),
            ("v1.2.3", "https://github.com/other/aros-toolchains/releases/download/v1.2.3"),
            ("v1.2.3", "https://github.com/example/aros-toolchains/releases/download/v2.0.0"),
        )
        for release_id, url in cases:
            with self.subTest(release_id=release_id, url=url):
                fixture = AuditFixture()
                try:
                    fixture.rewrite_release_identity(release_id, url)
                    self.assert_failure(fixture)
                    self.assertFalse(fixture.verifier_log.exists())
                    self.assertEqual(self.native_calls(fixture), [])
                finally:
                    fixture.close()

    def test_native_result_must_bind_operation_counts_and_sdk_digests(self) -> None:
        for mode in ("wrong-operation", "wrong-count", "wrong-sdk-digest"):
            with self.subTest(mode=mode):
                fixture = AuditFixture()
                try:
                    runtime = fixture.runtime.read_text()
                    marker = '    fail("unexpected native operation")\n\nprint(json.dumps(result, sort_keys=True, separators=(",", ":")))'
                    injection = '''    fail("unexpected native operation")

if operation == "verify-qualification":
    if mode == "native-fails":
        fail("synthetic native verifier rejection")
    if mode == "wrong-operation":
        result["operation"] = "record-qualification"
    if mode == "wrong-count":
        result["lane_count"] += 1
    if mode == "wrong-sdk-digest":
        result["sdks"][0]["archive_sha256"] = "0" * 64

print(json.dumps(result, sort_keys=True, separators=(",", ":")))'''
                    self.assertIn(marker, runtime)
                    fixture.runtime.write_text(runtime.replace(marker, injection))
                    fixture.refresh_runtime_binding()
                    self.assert_failure(fixture, mode=mode)
                    self.assertTrue(fixture.verifier_log.exists())
                finally:
                    fixture.close()

    def test_external_and_native_failures_never_report_success(self) -> None:
        for mode in ("verifier-fails", "native-fails", "operation-root-replaced"):
            with self.subTest(mode=mode):
                fixture = AuditFixture()
                try:
                    if mode == "native-fails":
                        runtime = fixture.runtime.read_text()
                        marker = '    fail("unexpected native operation")\n\nprint(json.dumps(result, sort_keys=True, separators=(",", ":")))'
                        injection = '''    fail("unexpected native operation")

if operation == "verify-qualification" and mode == "native-fails":
    fail("synthetic native verifier rejection")

print(json.dumps(result, sort_keys=True, separators=(",", ":")))'''
                        fixture.runtime.write_text(runtime.replace(marker, injection))
                        fixture.refresh_runtime_binding()
                    elif mode == "operation-root-replaced":
                        runtime = fixture.runtime.read_text()
                        marker = '    fail("unexpected native operation")\n\nprint(json.dumps(result, sort_keys=True, separators=(",", ":")))'
                        injection = '''    fail("unexpected native operation")

if operation == "verify-qualification" and mode == "operation-root-replaced":
    output_root = Path(option("--policy")).parent
    output_root.rename(output_root.with_name(output_root.name + "-replaced"))
    output_root.mkdir()

print(json.dumps(result, sort_keys=True, separators=(",", ":")))'''
                        fixture.runtime.write_text(runtime.replace(marker, injection))
                        fixture.refresh_runtime_binding()
                    self.assert_failure(fixture, mode=mode)
                    self.assertEqual(len(self.native_calls(fixture)),
                                     0 if mode == "verifier-fails" else 1)
                finally:
                    fixture.close()

    def test_late_changes_to_release_file_set_qualification_summary_or_archive_prevent_success(self) -> None:
        for target_name in ("qualification", "summary", "archive", "release-directory"):
            with self.subTest(target=target_name):
                fixture = AuditFixture()
                try:
                    runtime = fixture.runtime.read_text()
                    marker = '    fail("unexpected native operation")\n\nprint(json.dumps(result, sort_keys=True, separators=(",", ":")))'
                    injection = '''    fail("unexpected native operation")

if operation == "verify-qualification" and mode.startswith("mutate-after-verify-"):
    target = Path(os.environ["FAKE_MUTATION_TARGET"])
    if target.is_dir():
        (target / "late-extra.bin").write_bytes(b"late file")
    else:
        target.write_bytes(target.read_bytes() + b" changed")

print(json.dumps(result, sort_keys=True, separators=(",", ":")))'''
                    old_mutator = '''elif mode.startswith("mutate-after-verify-"):
        target = Path(os.environ["FAKE_MUTATION_TARGET"])
        target.write_bytes(target.read_bytes() + b" changed")'''
                    new_mutator = '''elif mode.startswith("mutate-after-verify-") and not Path(
        os.environ["FAKE_MUTATION_TARGET"]
    ).is_dir():
        target = Path(os.environ["FAKE_MUTATION_TARGET"])
        target.write_bytes(target.read_bytes() + b" changed")'''
                    self.assertIn(old_mutator, runtime)
                    runtime = runtime.replace(old_mutator, new_mutator)
                    fixture.runtime.write_text(runtime.replace(marker, injection))
                    fixture.refresh_runtime_binding()
                    target = {
                        "qualification": fixture.qualification,
                        "summary": fixture.summary,
                        "archive": fixture.release / "sdk+abi.tar.xz",
                        "release-directory": fixture.release,
                    }[target_name]
                    before = set(target.iterdir()) if target.is_dir() else target.read_bytes()
                    self.assert_failure(
                        fixture, mode="mutate-after-verify-late", mutation_target=target
                    )
                    after = set(target.iterdir()) if target.is_dir() else target.read_bytes()
                    self.assertNotEqual(after, before)
                finally:
                    fixture.close()

    def test_qualification_link_size_and_operation_sentinel_boundaries(self) -> None:
        cases = (
            "symlink", "hardlink", "oversized", "release-symlink", "release-hardlink",
            "release-oversized", "overlap", "forbidden-overlap", "sentinel",
        )
        for case in cases:
            with self.subTest(case=case):
                fixture = AuditFixture()
                try:
                    argv = fixture.argv()
                    sentinel = None
                    if case == "symlink":
                        link = fixture.qualification_dir / "linked.json"
                        link.symlink_to(fixture.qualification)
                        self.replace_arg(argv, "--qualification-evidence", str(link))
                    elif case == "hardlink":
                        alias = fixture.qualification_dir / "hardlink.json"
                        os.link(fixture.qualification, alias)
                    elif case == "oversized":
                        fixture.qualification.write_bytes(b"x" * (adapter.MAX_METADATA + 1))
                        fixture.qualification_sha = digest(fixture.qualification.read_bytes())
                        self.replace_arg(argv, "--qualification-sha256", fixture.qualification_sha)
                    elif case == "release-symlink":
                        asset = fixture.release / "sdk+abi.tar.xz"
                        target = fixture.root / "sdk-target.bin"
                        target.write_bytes(asset.read_bytes())
                        asset.unlink()
                        asset.symlink_to(target)
                    elif case == "release-hardlink":
                        os.link(fixture.release / "sdk+abi.tar.xz", fixture.root / "sdk-hardlink.bin")
                    elif case == "release-oversized":
                        fixture.bundle.write_bytes(b"x" * (adapter.MAX_METADATA + 1))
                    elif case == "overlap":
                        overlap = fixture.qualification_dir / "operation"
                        self.replace_arg(argv, "--operation-dir", str(overlap))
                    elif case == "forbidden-overlap":
                        overlap = fixture.prefix_workspace / "operation"
                        self.replace_arg(argv, "--operation-dir", str(overlap))
                    else:
                        fixture.operation.mkdir()
                        sentinel = fixture.operation / "sentinel.txt"
                        sentinel.write_text("keep")
                    self.assert_failure(fixture, argv=argv)
                    self.assertFalse(fixture.verifier_log.exists())
                    self.assertEqual(self.native_calls(fixture), [])
                    if sentinel is not None:
                        self.assertEqual(sentinel.read_text(), "keep")
                finally:
                    fixture.close()


if __name__ == "__main__":
    unittest.main()
