#!/usr/bin/env python3
"""Exercise bounded SDK config.log retention and its Bash failure boundary."""

from __future__ import annotations

from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
HELPER = REPOSITORY_ROOT / "scripts/toolchain/retain-sdk-config-logs.py"
QUALIFIER = REPOSITORY_ROOT / "scripts/toolchain/qualify-compiler-sdk-lane-v2.sh"
FIRST_OUTPUT = "upstream-build-config.log"
SECOND_OUTPUT = "upstream-build-config-subdir-config.log"
MAX_LOG_BYTES = 4 * 1024 * 1024


def _sdk_wrapper() -> str:
    source = QUALIFIER.read_text(encoding="utf-8")
    match = re.search(
        r"(?ms)^build_sdk_with_diagnostics\(\) \{\n.*?^\}",
        source,
    )
    if match is None:
        raise AssertionError("qualifier must define its SDK failure diagnostic wrapper")
    return match.group(0)


class RetainSdkConfigLogsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.wrapper = _sdk_wrapper()

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="retain-sdk-config-logs-")
        self.base = Path(self.temporary.name).resolve()
        self.operation = self.base / "operation"
        self.operation.mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _run_helper(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-B", str(HELPER), "--operation-dir", str(self.operation)],
            check=False,
            capture_output=True,
            text=True,
        )

    def _log(self, name: str, content: bytes) -> Path:
        path = self.operation / "upstream-build" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def _write_fake_sdk(self, status: int) -> Path:
        path = self.base / "fake-aros"
        path.write_text(
            "#!/bin/sh\nprintf '%s\\n' '{\"fixture\":\"sdk\"}'\n"
            f"exit {status}\n",
            encoding="utf-8",
        )
        path.chmod(0o700)
        return path

    def _run_wrapper(self, status: int) -> subprocess.CompletedProcess[str]:
        fake_aros = self._write_fake_sdk(status)
        assignments = {
            "aros": str(fake_aros),
            "producer": str(REPOSITORY_ROOT),
            "operation": str(self.operation),
            "identity": "fixture-identity.json",
            "identity_sha": "0" * 64,
            "source": str(self.base / "source"),
            "recipe": str(self.base / "recipe.json"),
            "lock": str(self.base / "lock.json"),
            "profiles": str(self.base / "profiles.json"),
            "source_preset": "release",
            "preset": "release",
            "root": str(self.base / "root"),
            "release_id": "fixture-release",
            "host": "linux-x86_64",
            "cache": str(self.base / "cache"),
            "ports": str(self.base / "ports.json"),
            "jobs": "1",
            "deadline": "60",
            "parent": str(self.base),
            "tools": str(self.base / "tools"),
            "inputs": str(self.base / "inputs"),
            "upstream": str(self.base / "upstream-source"),
        }
        shell_assignments = "\n".join(
            f"{name}={shlex.quote(value)}" for name, value in assignments.items()
        )
        script = (
            "set -euo pipefail\n"
            f"{shell_assignments}\n"
            "host_tools=(--host-tool fixture=/bin/true)\n"
            f"{self.wrapper}\n"
            "build_sdk_with_diagnostics\n"
            "printf 'wrapper-returned-success\\n'\n"
        )
        return subprocess.run(
            ["/bin/bash", "--noprofile", "--norc", "-c", script],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_captures_only_both_exact_logs_without_modifying_sources(self) -> None:
        first = self._log("config.log", b"root config log\n")
        second = self._log("config/config.log", b"nested config log\n")
        unrelated = self._log("other/config.log", b"must not be captured\n")
        original = {path: path.read_bytes() for path in (first, second, unrelated)}

        result = self._run_helper()

        self.assertEqual(result.returncode, 0, result.stderr)
        reports = self.operation / "reports"
        self.assertEqual(
            {path.name for path in reports.iterdir()},
            {FIRST_OUTPUT, SECOND_OUTPUT},
        )
        self.assertEqual((reports / FIRST_OUTPUT).read_bytes(), original[first])
        self.assertEqual((reports / SECOND_OUTPUT).read_bytes(), original[second])
        self.assertEqual({path: path.read_bytes() for path in original}, original)

    def test_missing_logs_are_allowed_without_creating_reports(self) -> None:
        result = self._run_helper()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.operation / "reports").exists())

    def test_symlink_source_file_is_rejected(self) -> None:
        target = self.base / "outside-config.log"
        target.write_bytes(b"outside\n")
        source = self._log("config.log", b"placeholder\n")
        source.unlink()
        source.symlink_to(target)

        result = self._run_helper()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("retain-sdk-config-logs", result.stderr)
        self.assertFalse((self.operation / "reports").exists())
        self.assertEqual(target.read_bytes(), b"outside\n")

    def test_symlink_source_parent_is_rejected(self) -> None:
        outside = self.base / "outside-build"
        outside.mkdir()
        (outside / "config.log").write_bytes(b"outside\n")
        (self.operation / "upstream-build").symlink_to(outside, target_is_directory=True)

        result = self._run_helper()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("retain-sdk-config-logs", result.stderr)
        self.assertFalse((self.operation / "reports").exists())

    def test_symlink_nested_source_parent_is_rejected(self) -> None:
        upstream = self.operation / "upstream-build"
        upstream.mkdir()
        outside = self.base / "outside-config"
        outside.mkdir()
        (outside / "config.log").write_bytes(b"outside\n")
        (upstream / "config").symlink_to(outside, target_is_directory=True)

        result = self._run_helper()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("retain-sdk-config-logs", result.stderr)
        self.assertFalse((self.operation / "reports").exists())

    def test_nonregular_source_is_rejected(self) -> None:
        source = self.operation / "upstream-build/config.log"
        source.parent.mkdir(parents=True)
        source.mkdir()

        result = self._run_helper()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("regular file", result.stderr)
        self.assertFalse((self.operation / "reports").exists())

    def test_oversized_source_is_rejected_before_output_creation(self) -> None:
        self._log("config.log", b"x" * (MAX_LOG_BYTES + 1))

        result = self._run_helper()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("4 MiB", result.stderr)
        self.assertFalse((self.operation / "reports").exists())

    def test_output_collision_rejects_capture_without_overwriting(self) -> None:
        self._log("config.log", b"new input\n")
        reports = self.operation / "reports"
        reports.mkdir()
        collision = reports / FIRST_OUTPUT
        collision.write_bytes(b"preexisting evidence\n")

        result = self._run_helper()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("already exists", result.stderr)
        self.assertEqual(collision.read_bytes(), b"preexisting evidence\n")

    def test_symlink_output_collision_is_rejected_without_following_it(self) -> None:
        self._log("config.log", b"new input\n")
        reports = self.operation / "reports"
        reports.mkdir()
        target = self.base / "outside-output.log"
        target.write_bytes(b"outside evidence\n")
        collision = reports / FIRST_OUTPUT
        collision.symlink_to(target)

        result = self._run_helper()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("already exists", result.stderr)
        self.assertTrue(collision.is_symlink())
        self.assertEqual(target.read_bytes(), b"outside evidence\n")

    def test_later_output_collision_rolls_back_earlier_new_capture(self) -> None:
        self._log("config.log", b"first input\n")
        self._log("config/config.log", b"second input\n")
        reports = self.operation / "reports"
        reports.mkdir()
        collision = reports / SECOND_OUTPUT
        collision.write_bytes(b"preexisting evidence\n")

        result = self._run_helper()

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual({path.name for path in reports.iterdir()}, {SECOND_OUTPUT})
        self.assertEqual(collision.read_bytes(), b"preexisting evidence\n")

    def test_symlink_reports_directory_is_rejected(self) -> None:
        outside = self.base / "outside-reports"
        outside.mkdir()
        (self.operation / "reports").symlink_to(outside, target_is_directory=True)
        self._log("config.log", b"config\n")

        result = self._run_helper()

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list(outside.iterdir()), [])

    def test_read_only_input_is_retained_without_changing_it(self) -> None:
        source = self._log("config.log", b"read-only config\n")
        source.chmod(0o444)
        before = (source.read_bytes(), source.stat().st_mode)

        result = self._run_helper()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((source.read_bytes(), source.stat().st_mode), before)
        self.assertEqual(
            ((self.operation / "reports" / FIRST_OUTPUT).read_bytes()),
            before[0],
        )

    def test_actual_bash_wrapper_retains_log_and_preserves_sdk_failure_status(self) -> None:
        self._log("config.log", b"compiler cannot create executables\n")

        result = self._run_wrapper(37)

        self.assertEqual(result.returncode, 37, result.stderr)
        self.assertEqual(
            (self.operation / "reports" / FIRST_OUTPUT).read_bytes(),
            b"compiler cannot create executables\n",
        )
        self.assertNotIn("unable to retain", result.stderr)

    def test_actual_bash_wrapper_preserves_sdk_status_when_retention_fails(self) -> None:
        self._log("config.log", b"diagnostic\n")
        reports = self.operation / "reports"
        reports.mkdir()
        (reports / FIRST_OUTPUT).write_bytes(b"existing\n")

        result = self._run_wrapper(37)

        self.assertEqual(result.returncode, 37, result.stderr)
        self.assertIn("output already exists", result.stderr)
        self.assertIn("unable to retain", result.stderr)

    def test_actual_bash_wrapper_does_not_claim_failure_on_sdk_success(self) -> None:
        self._log("config.log", b"not copied on success\n")

        result = self._run_wrapper(0)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "wrapper-returned-success\n")
        self.assertEqual(result.stderr, "")
        self.assertFalse((self.operation / "reports").exists())
        self.assertIn('{"fixture":"sdk"}', (self.operation / "result.json").read_text())


if __name__ == "__main__":
    unittest.main()
