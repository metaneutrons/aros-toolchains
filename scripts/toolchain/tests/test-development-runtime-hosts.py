#!/usr/bin/env python3
"""Process probes for the non-publishing development runtime host guard."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
ACTION = ROOT / ".github" / "actions" / "materialize-development-aros-tools" / "action.yml"
COMMIT = "0123456789abcdef0123456789abcdef01234567"
RUST_VERSION = "1.84.0"
OUTPUT_SENTINEL = b"existing output must remain unchanged\n"


def action_run_body() -> str:
    lines = ACTION.read_text(encoding="utf-8").splitlines()
    try:
        start = lines.index("      run: |") + 1
    except ValueError as error:
        raise AssertionError("development runtime action has no literal Bash run body") from error

    body: list[str] = []
    for line in lines[start:]:
        if line.startswith("        "):
            body.append(line[8:])
        elif not line.strip():
            body.append("")
        else:
            break
    if not body:
        raise AssertionError("development runtime action Bash body is empty")
    return "\n".join(body).rstrip() + "\n"


def write_executable(path: Path, contents: str) -> None:
    path.write_text(contents, encoding="utf-8")
    path.chmod(0o755)


class DevelopmentRuntimeHostTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.body = action_run_body()

    def probe(self, event: str, runner_os: str, runner_arch: str) -> tuple[int, list[str], bytes, bool]:
        with tempfile.TemporaryDirectory(prefix="development-runtime-host-") as temporary_name:
            temporary = Path(temporary_name)
            fake_bin = temporary / "fake-bin"
            fake_bin.mkdir()
            tools_source = temporary / "aros-tools"
            tools_source.mkdir()
            (tools_source / "rust-toolchain.toml").write_text(
                f'[toolchain]\nchannel = "{RUST_VERSION}"\n', encoding="utf-8"
            )
            runtime_root = temporary / "runtime"
            runner_temp = temporary / "runner-temp"
            runner_temp.mkdir()
            output = temporary / "github-output"
            output.write_bytes(OUTPUT_SENTINEL)
            probe_log = temporary / "commands.log"
            probe_log.write_text("", encoding="utf-8")

            write_executable(
                fake_bin / "git",
                "#!/bin/sh\n"
                "printf 'git %s\\n' \"$*\" >> \"$PROBE_LOG\"\n"
                "case \"$3:$4\" in\n"
                "  rev-parse:HEAD) printf '%s\\n' \"$PROBE_COMMIT\" ;;\n"
                "  status:--porcelain) exit 0 ;;\n"
                "  *) exit 94 ;;\n"
                "esac\n",
            )
            write_executable(
                fake_bin / "cargo",
                "#!/bin/sh\n"
                "printf 'cargo %s\\n' \"$*\" >> \"$PROBE_LOG\"\n"
                "case \"$1\" in\n"
                f"  --version) printf 'cargo {RUST_VERSION} fake\\n' ;;\n"
                "  build) exit 73 ;;\n"
                "  *) exit 94 ;;\n"
                "esac\n",
            )
            write_executable(
                fake_bin / "rustc",
                "#!/bin/sh\n"
                "printf 'rustc %s\\n' \"$*\" >> \"$PROBE_LOG\"\n"
                f"printf 'rustc {RUST_VERSION} fake\\n'\n",
            )

            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": f"{fake_bin}:{environment.get('PATH', '/usr/bin:/bin')}",
                    "GITHUB_EVENT_NAME": event,
                    "GITHUB_OUTPUT": str(output),
                    "RUNNER_OS": runner_os,
                    "RUNNER_ARCH": runner_arch,
                    "RUNNER_TEMP": str(runner_temp),
                    "TOOLS_SOURCE": str(tools_source),
                    "TOOLS_COMMIT": COMMIT,
                    "RUNTIME_ROOT": str(runtime_root),
                    "PROBE_COMMIT": COMMIT,
                    "PROBE_LOG": str(probe_log),
                }
            )
            result = subprocess.run(
                ["bash", "--noprofile", "--norc", "-c", self.body],
                cwd=temporary,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
                timeout=15,
            )
            calls = probe_log.read_text(encoding="utf-8").splitlines()
            return result.returncode, calls, output.read_bytes(), runtime_root.exists()

    def test_accepts_exact_native_runner_pairs_through_build_boundary(self) -> None:
        for runner_os, runner_arch in (("Linux", "X64"), ("Linux", "ARM64"), ("macOS", "ARM64")):
            with self.subTest(runner_os=runner_os, runner_arch=runner_arch):
                status, calls, output, runtime_exists = self.probe(
                    "workflow_dispatch", runner_os, runner_arch
                )
                self.assertEqual(status, 73, "fake cargo must stop exactly at the build boundary")
                # The temporary path is intentionally variable; verify call shape and ordering.
                self.assertTrue(calls[0].endswith(" rev-parse HEAD"), calls)
                source = calls[0][len("git -C ") : -len(" rev-parse HEAD")]
                self.assertEqual(
                    calls,
                    [
                        f"git -C {source} rev-parse HEAD",
                        f"git -C {source} status --porcelain",
                        "cargo --version",
                        "rustc --version",
                        f"cargo build --manifest-path {source}/Cargo.toml --locked --release --workspace --bins",
                    ],
                )
                self.assertEqual(output, OUTPUT_SENTINEL)
                self.assertFalse(runtime_exists)

    def test_rejects_unsupported_runner_pairs_before_commands_or_output(self) -> None:
        rejected_pairs = (
            ("macOS", "X64"),
            ("Windows", "X64"),
            ("Windows", "ARM64"),
            ("Linux", "x86_64"),
            ("unknown", "unknown"),
            ("", ""),
        )
        for runner_os, runner_arch in rejected_pairs:
            with self.subTest(runner_os=runner_os, runner_arch=runner_arch):
                status, calls, output, runtime_exists = self.probe(
                    "workflow_dispatch", runner_os, runner_arch
                )
                self.assertNotEqual(status, 0)
                self.assertEqual(calls, [])
                self.assertEqual(output, OUTPUT_SENTINEL)
                self.assertFalse(runtime_exists)

    def test_rejects_non_manual_events_before_commands_or_output(self) -> None:
        status, calls, output, runtime_exists = self.probe("schedule", "Linux", "X64")
        self.assertNotEqual(status, 0)
        self.assertEqual(calls, [])
        self.assertEqual(output, OUTPUT_SENTINEL)
        self.assertFalse(runtime_exists)


if __name__ == "__main__":
    unittest.main()
