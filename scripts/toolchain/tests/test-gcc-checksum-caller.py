#!/usr/bin/env python3
"""Exercise the GCC checksum observer call in the qualification shell adapter."""

from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
QUALIFIER = REPOSITORY_ROOT / "scripts/toolchain/qualify-compiler-sdk-lane-v2.sh"
OBSERVER = "scripts/toolchain/observe-gcc-checksum-inputs.py"

def _native_evidence_names() -> tuple[str, ...]:
    source = REPOSITORY_ROOT / "scripts/toolchain/native-lane-transport.py"
    declarations = [
        node.value
        for node in ast.parse(source.read_text(encoding="utf-8")).body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "EVIDENCE_NAMES" for target in node.targets)
    ]
    if len(declarations) != 1:
        raise AssertionError("native transport must declare exactly one evidence allowlist")
    names = ast.literal_eval(declarations[0])
    if not isinstance(names, set) or not names or any(not isinstance(name, str) for name in names):
        raise AssertionError("native transport evidence allowlist must be a nonempty string set")
    return tuple(sorted(names))


NATIVE_EVIDENCE = _native_evidence_names()


def _snapshot(root: Path) -> dict[str, tuple[object, ...]]:
    snapshot: dict[str, tuple[object, ...]] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        status = path.lstat()
        common = (status.st_mode, status.st_size, status.st_mtime_ns, status.st_ctime_ns)
        if path.is_symlink():
            snapshot[relative] = ("symlink", os.readlink(path), *common)
        elif path.is_dir():
            snapshot[relative] = ("directory", *common)
        elif path.is_file():
            snapshot[relative] = (
                "file",
                hashlib.sha256(path.read_bytes()).hexdigest(),
                *common,
            )
        else:
            snapshot[relative] = ("other", *common)
    return snapshot


def _extract_observer_function() -> str:
    source = QUALIFIER.read_text(encoding="utf-8")
    matches = re.findall(r"(?ms)^observe_gcc_inputs\(\) \{\n.*?^\}", source)
    if len(matches) != 1:
        raise AssertionError(
            "qualification adapter must contain exactly one bounded observe_gcc_inputs function"
        )
    return matches[0]


class GccChecksumCallerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.observer_function = _extract_observer_function()

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="gcc-checksum-caller-test-")
        self.base = Path(self.temporary.name)
        self.fixture = self.base / "fixture with spaces"
        self.operation_root = self.fixture / "operation"
        self.compiler_root = self.operation_root / "compiler-a"
        self.native_root = self.compiler_root / "work/native-lifecycle"
        self.build_root = self.native_root / "build"
        self.gcc_dir = self.build_root / "bin/host/gcc/gcc"
        self.producer = self.fixture / "producer"
        self.observer_script = self.producer / OBSERVER
        self.fake_bin = self.fixture / "fake-bin"
        self.call_log = self.fixture / "observer-call.json"
        self.output = self.operation_root / "gcc-checksum-inputs-compiler-a.json"
        self._write_payload_sentinels()
        self.fake_bin.mkdir(parents=True)
        self.observer_script.parent.mkdir(parents=True)
        self.observer_script.write_text(
            "# This placeholder is consumed by the fake python3 executable.\n",
            encoding="utf-8",
        )
        self._write_fake_python()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_payload_sentinels(self) -> None:
        package = self.compiler_root / "payload/package"
        evidence = self.compiler_root / "payload/evidence"
        package.mkdir(parents=True)
        evidence.mkdir(parents=True)
        for index, name in enumerate(NATIVE_EVIDENCE):
            target = self.compiler_root / "payload" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(f"native evidence sentinel {index}\n".encode())
        archive = "compiler.tar.xz"
        for name in (
            archive,
            f"{archive}.manifest.json",
            f"{archive}.sha256",
            f"{archive}.spdx.json",
        ):
            (package / name).write_bytes(f"native package sentinel {name}\n".encode())

    def _write_fake_python(self) -> None:
        fake_python = self.fake_bin / "python3"
        fake_python.write_text(
            f"#!{sys.executable}\n"
            "import json, os, pathlib, sys\n"
            "arguments = sys.argv[1:]\n"
            "log = pathlib.Path(os.environ['FAKE_OBSERVER_LOG'])\n"
            "log.write_text(json.dumps({'argv': arguments}) + '\\n', encoding='utf-8')\n"
            "expected = os.environ['FAKE_EXPECTED_OBSERVER']\n"
            "if len(arguments) < 2 or arguments[0] != '-B' or arguments[1] != expected:\n"
            "    sys.exit(90)\n"
            "failure = int(os.environ.get('FAKE_OBSERVER_EXIT', '0'))\n"
            "if failure:\n"
            "    sys.exit(failure)\n"
            "try:\n"
            "    output_index = arguments.index('--output') + 1\n"
            "    output = pathlib.Path(arguments[output_index])\n"
            "except (ValueError, IndexError):\n"
            "    sys.exit(91)\n"
            "output.write_text(json.dumps({'schema': 'fake-gcc-observation-v1', 'argv': arguments}) + '\\n', encoding='utf-8')\n",
            encoding="utf-8",
        )
        fake_python.chmod(0o755)

    def _make_makefile(self, *, directory: Path | None = None) -> Path:
        target = (directory or self.gcc_dir) / "Makefile"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("# Generated GCC Makefile sentinel\n", encoding="utf-8")
        return target

    def _harness(self) -> str:
        return "\n".join(
            (
                "set -euo pipefail",
                "set -C",
                "fail() { printf 'caller test: %s\\n' \"$*\" >&2; exit 1; }",
                "producer=$1",
                "compiler_root=$2",
                self.observer_function,
                'observe_gcc_inputs "$compiler_root"',
            )
        )

    def _run_caller(
        self,
        *,
        compiler_root: Path | None = None,
        observer_exit: int = 0,
    ) -> subprocess.CompletedProcess[bytes]:
        environment = os.environ.copy()
        environment.update(
            {
                "PATH": f"{self.fake_bin}{os.pathsep}{environment.get('PATH', '')}",
                "FAKE_OBSERVER_LOG": str(self.call_log),
                "FAKE_EXPECTED_OBSERVER": str(self.observer_script),
                "FAKE_OBSERVER_EXIT": str(observer_exit),
            }
        )
        return subprocess.run(
            [
                "bash",
                "--noprofile",
                "--norc",
                "-c",
                self._harness(),
                "gcc-checksum-caller-test",
                str(self.producer),
                str(compiler_root or self.compiler_root),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            check=False,
            timeout=10,
        )

    def _payload_snapshot(self) -> dict[str, tuple[object, ...]]:
        return _snapshot(self.compiler_root / "payload")

    def _assert_payload_is_closed(self) -> None:
        expected = {
            "evidence",
            "package",
            *NATIVE_EVIDENCE,
            "package/compiler.tar.xz",
            "package/compiler.tar.xz.manifest.json",
            "package/compiler.tar.xz.sha256",
            "package/compiler.tar.xz.spdx.json",
        }
        self.assertEqual(set(self._payload_snapshot()), expected)

    def _assert_no_output_or_payload_change(
        self, before: dict[str, tuple[object, ...]], result: subprocess.CompletedProcess[bytes]
    ) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout.decode(errors="replace"))
        self.assertFalse(self.output.exists())
        self.assertEqual(before, _snapshot(self.compiler_root))
        self._assert_payload_is_closed()

    def test_one_generated_makefile_writes_diagnostic_json_beside_compiler_root(self) -> None:
        makefile = self._make_makefile()
        compiler_before = _snapshot(self.compiler_root)
        payload_before = self._payload_snapshot()

        result = self._run_caller()

        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertEqual(result.stderr, b"")
        self.assertTrue(self.output.is_file())
        self.assertEqual(compiler_before, _snapshot(self.compiler_root))
        self.assertEqual(payload_before, self._payload_snapshot())
        self._assert_payload_is_closed()
        self.assertEqual(self.output.parent, self.compiler_root.parent)
        observation = json.loads(self.output.read_text(encoding="utf-8"))
        self.assertEqual(observation["schema"], "fake-gcc-observation-v1")
        self.assertEqual(
            observation["argv"],
            [
                "-B",
                str(self.observer_script),
                "--gcc-build-dir",
                str(makefile.parent),
                "--allowed-root",
                str(self.native_root),
                "--output",
                str(self.output),
            ],
        )
        self.assertEqual(json.loads(self.call_log.read_text(encoding="utf-8"))["argv"], observation["argv"])

    def test_zero_matching_makefiles_fail_without_observer_or_payload_change(self) -> None:
        self.build_root.mkdir(parents=True)
        before = _snapshot(self.compiler_root)

        result = self._run_caller()

        self._assert_no_output_or_payload_change(before, result)
        self.assertIn(b"exactly one generated GCC Makefile", result.stderr)
        self.assertFalse(self.call_log.exists())

    def test_two_matching_makefiles_fail_without_observer_or_payload_change(self) -> None:
        self._make_makefile()
        self._make_makefile(directory=self.build_root / "second/host/gcc/gcc")
        before = _snapshot(self.compiler_root)

        result = self._run_caller()

        self._assert_no_output_or_payload_change(before, result)
        self.assertIn(b"exactly one generated GCC Makefile", result.stderr)
        self.assertFalse(self.call_log.exists())

    def test_observer_failure_leaves_no_output_and_preserves_payload(self) -> None:
        self._make_makefile()
        before = _snapshot(self.compiler_root)

        result = self._run_caller(observer_exit=23)

        self._assert_no_output_or_payload_change(before, result)
        self.assertTrue(self.call_log.is_file())

    def test_newline_in_matching_path_fails_safely(self) -> None:
        self._make_makefile(directory=self.build_root / "host\nname/gcc/gcc")
        before = _snapshot(self.compiler_root)

        result = self._run_caller()

        self._assert_no_output_or_payload_change(before, result)
        self.assertIn(b"exactly one generated GCC Makefile", result.stderr)
        self.assertFalse(self.call_log.exists())


if __name__ == "__main__":
    unittest.main()
