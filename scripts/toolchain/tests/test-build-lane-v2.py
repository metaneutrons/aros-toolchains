#!/usr/bin/env python3
"""Offline contracts for the native v2 build and guarded-package handoff.

The fake ``aros`` executable exercises only the adapter's process boundary.
Its archive and manifest are placeholders; these tests do not establish
compiler, archive-closure, signature, or release-admission evidence.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import textwrap
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "build-lane-v2.sh"
BUILD_BYTES = b'{"fixture":"cold native build"}\n'
ENVIRONMENT = {"fixture": "native producer environment"}
MEASUREMENT_BYTES = b'{"assurance":"fixture-only"}\n'


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def available_bashes() -> list[Path]:
    """Return distinct system and current Bash binaries, if available."""

    candidates = [Path("/bin/bash")]
    current = shutil.which("bash")
    if current:
        candidates.append(Path(current))
    found: list[Path] = []
    seen: set[tuple[int, int]] = set()
    for candidate in candidates:
        if not candidate.is_file():
            continue
        try:
            stat = candidate.stat()
        except OSError:
            continue
        identity = (stat.st_dev, stat.st_ino)
        if identity in seen:
            continue
        result = subprocess.run(
            [str(candidate), "--version"], capture_output=True, text=True, check=False
        )
        if result.returncode == 0 and "GNU bash" in result.stdout.splitlines()[0]:
            seen.add(identity)
            found.append(candidate)
    return found


FAKE_AROS = r'''#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys


def option(name):
    values = [args[index + 1] for index, value in enumerate(args[:-1]) if value == name]
    if not values:
        raise SystemExit(f"fixture CLI missing {name}")
    return values[0]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


raw_args = sys.argv[1:]
# Exercise actual option/value parsing before the fixture implements results.
# This does not substitute for the native Rust parser or real compilation.
parser = argparse.ArgumentParser(add_help=False)
parser.add_argument("--preset")
parser.parse_known_args(raw_args)
args = []
for token in raw_args:
    args.extend(token.split("=", 1) if token.startswith("--") and "=" in token else [token])
mode = os.environ.get("FAKE_AROS_MODE", "success")
entry = {"args": args, "raw_args": raw_args}
if args[:2] == ["toolchain", "build"]:
    work = Path(option("--work-dir"))
    output = Path(option("--output-dir"))
    entry["work_dir_existed"] = work.exists()
    entry["output_dir_existed"] = output.exists()
elif args[:3] == ["toolchain", "producer", "package"]:
    entry["build_result_sha256"] = option("--build-result-sha256")

with open(os.environ["FAKE_AROS_LOG"], "a", encoding="utf-8") as log:
    log.write(json.dumps(entry, separators=(",", ":")) + "\n")

if args[:2] == ["toolchain", "build"]:
    if mode == "build-failure":
        raise SystemExit(31)
    output = Path(option("--output-dir"))
    (output / "toolchain").mkdir(parents=True)
    (output / "toolchain" / "fixture.txt").write_text("fixture\n", encoding="utf-8")
    sys.stdout.buffer.write(b'{"fixture":"cold native build"}\n')
elif args[:3] == ["toolchain", "producer", "environment"]:
    environment = {"fixture": "native producer environment"}
    Path(option("--output")).write_text(json.dumps(environment) + "\n", encoding="utf-8")
    sys.stdout.write('{"fixture":"environment response"}\n')
elif args[:3] == ["toolchain", "producer", "package"]:
    if mode == "package-failure":
        raise SystemExit(32)
    package = Path(option("--output-dir"))
    package.mkdir(parents=True)
    archive = package / "fixture-package.tar.xz"
    archive.write_bytes(b"offline placeholder archive\n")
    archive_digest = digest(archive)
    manifest = {
        "schema": 2,
        "host": option("--host"),
        "target_profile": option("--preset"),
        "tree_sha256": "a" * 64,
    }
    archive.with_name(archive.name + ".manifest.json").write_text(
        json.dumps(manifest, separators=(",", ":")) + "\n", encoding="utf-8"
    )
    archive.with_name(archive.name + ".sha256").write_text(
        archive_digest + "  " + archive.name + "\n", encoding="utf-8"
    )
    archive.with_name(archive.name + ".spdx.json").write_text(
        '{"fixture":"offline placeholder SBOM"}\n', encoding="utf-8"
    )
    build_sha = option("--build-result-sha256")
    if mode == "build-result-join-mismatch":
        build_sha = "f" * 64
    measurement_sha = hashlib.sha256(b'{"assurance":"fixture-only"}\n').hexdigest()
    if mode == "measurement-hash-mismatch":
        measurement_sha = "0" * 64
    response = {
        "schema": "aros-toolchain-producer-stage-v1",
        "operation": "package",
        "package_dir": str(package),
        "archive": str(archive),
        "manifest": str(archive) + ".manifest.json",
        "checksum": str(archive) + ".sha256",
        "sbom": str(archive) + ".spdx.json",
        "sha256": archive_digest,
        "size": archive.stat().st_size,
        "finished_candidate": {
            "build_result_sha256": build_sha,
            "package_tree_sha256": "b" * 64
            if mode == "tree-join-mismatch"
            else "a" * 64,
            "portable_measurement": '{"assurance":"fixture-only"}\n',
            "portable_measurement_sha256": measurement_sha,
        },
    }
    if mode == "package-schema-mismatch":
        response["schema"] = "unexpected-schema"
    sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
elif args[:3] == ["toolchain", "producer", "verify-package"]:
    if mode == "verify-failure":
        raise SystemExit(33)
    package = Path(option("--input-dir"))
    archive = package / "fixture-package.tar.xz"
    manifest = {
        "schema": 2,
        "host": "linux-aarch64" if mode == "host-mismatch" else option("--host"),
        "target_profile": "wrong-profile"
        if mode == "profile-mismatch"
        else option("--preset"),
        "tree_sha256": "a" * 64,
    }
    response = {
        "schema": "unexpected-schema"
        if mode == "verify-schema-mismatch"
        else "aros-toolchain-producer-stage-v1",
        "operation": "verify-package",
        "manifest": manifest,
        "sha256": "f" * 64 if mode == "readback-sha-mismatch" else digest(archive),
        "size": archive.stat().st_size,
    }
    sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
    if mode == "runtime-change":
        with open(os.environ["FAKE_AROS_RUNTIME"], "ab") as runtime:
            runtime.write(b"# changed during handoff\n")
else:
    raise SystemExit("fixture CLI received an unexpected invocation")
'''


class BuildLaneV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not shutil.which("jq") or not shutil.which("shasum"):
            raise RuntimeError("build-lane-v2.sh contract tests require jq and shasum")
        cls.bashes = available_bashes()
        if not cls.bashes:
            raise RuntimeError("build-lane-v2.sh contract tests require Bash")

    def setUp(self) -> None:
        self._create_fixture()

    def _create_fixture(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="build-lane-v2.")
        # The shell adapter requires operation roots to use a canonical parent
        # path. macOS commonly exposes its temporary directory through /var.
        self.base = Path(self.temporary.name).resolve()
        self.runtime = self.base / "aros-fixture"
        self.runtime.write_text(FAKE_AROS, encoding="utf-8")
        self.runtime.chmod(0o755)
        self.recipe = self._file("recipe.json", b'{"recipe":"fixture"}\n')
        self.source_lock = self._file("source-lock.json", b'{"lock":"fixture"}\n')
        self.profiles = self._file("profiles.json", b'{"profiles":[]}\n')
        self.source_dir = self._directory("source")
        self.producer_dir = self._directory("producer")
        self.tools_dir = self._directory("tools")
        self.cache_dir = self._directory("cache")
        self.forbidden_dir = self._directory("forbidden")
        self.operations = self._directory("operations")
        self.root = self.operations / "lane"
        self.log = self.base / "aros-calls.jsonl"

    def fresh_fixture(self) -> None:
        self.temporary.cleanup()
        self._create_fixture()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _file(self, name: str, raw: bytes) -> Path:
        path = self.base / name
        path.write_bytes(raw)
        return path

    def _directory(self, name: str) -> Path:
        path = self.base / name
        path.mkdir()
        return path

    def arguments(self, *, root: Path | None = None) -> list[str]:
        operation_root = root or self.root
        return [
            "--aros",
            str(self.runtime),
            "--aros-sha256",
            sha256(self.runtime.read_bytes()),
            "--recipe",
            str(self.recipe),
            "--source-lock",
            str(self.source_lock),
            "--profiles",
            str(self.profiles),
            "--source-dir",
            str(self.source_dir),
            "--producer-dir",
            str(self.producer_dir),
            "--tools-dir",
            str(self.tools_dir),
            "--cache-dir",
            str(self.cache_dir),
            "--preset",
            "rv32-fixture",
            "--host",
            "linux-x86_64",
            "--release-id",
            "release-fixture",
            "--jobs",
            "2",
            "--timeout-seconds",
            "900",
            "--root",
            str(operation_root),
            "--forbidden-prefix",
            str(self.forbidden_dir),
        ]

    def run_lane(
        self,
        *,
        mode: str = "success",
        arguments: list[str] | None = None,
        interpreter: Path | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        shell = interpreter or self.bashes[-1]
        environment = os.environ.copy()
        environment.update(
            {
                "FAKE_AROS_MODE": mode,
                "FAKE_AROS_LOG": str(self.log),
                "FAKE_AROS_RUNTIME": str(self.runtime),
            }
        )
        return subprocess.run(
            [str(shell), str(SCRIPT), *(arguments if arguments is not None else self.arguments())],
            cwd=SCRIPT.parents[2],
            env=environment,
            capture_output=True,
            check=False,
        )

    def calls(self) -> list[dict[str, object]]:
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]

    @staticmethod
    def arg_values(call: dict[str, object], option: str) -> list[str]:
        args = call["args"]
        assert isinstance(args, list)
        return [args[index + 1] for index, value in enumerate(args[:-1]) if value == option]

    def assert_no_handoff(self) -> None:
        self.assertFalse((self.root / "handoff.json").exists())

    def assert_rejected_before_cli(self, arguments: list[str], *, root: Path | None = None) -> None:
        result = self.run_lane(arguments=arguments)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.calls(), [])
        self.assertFalse((root or self.root).joinpath("payload").exists())

    def test_successful_cold_handoff_binds_raw_build_bytes_and_exact_measurement(self) -> None:
        result = self.run_lane()
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        calls = self.calls()
        self.assertEqual(
            [call["args"][:3] for call in calls],
            [
                ["toolchain", "build", "--preset"],
                ["toolchain", "producer", "environment"],
                ["toolchain", "producer", "package"],
                ["toolchain", "producer", "verify-package"],
            ],
        )

        build = calls[0]
        self.assertFalse(build["work_dir_existed"])
        self.assertFalse(build["output_dir_existed"])
        build_args = build["args"]
        assert isinstance(build_args, list)
        for option, value in (
            ("--compiler-cache", "off"),
            ("--preset", "rv32-fixture"),
            ("--jobs", "2"),
            ("--timeout-seconds", "900"),
            ("--release-id", "release-fixture"),
            ("--format", "json"),
        ):
            self.assertIn(option, build_args)
            self.assertEqual(build_args[build_args.index(option) + 1], value)
        for forbidden_option in ("--resume", "--offline", "--clean"):
            self.assertNotIn(forbidden_option, build_args)
        self.assertEqual(
            build_args,
            [
                "toolchain",
                "build",
                "--preset",
                "rv32-fixture",
                "--recipe",
                str(self.recipe),
                "--source-dir",
                str(self.source_dir),
                "--producer-dir",
                str(self.producer_dir),
                "--tools-dir",
                str(self.tools_dir),
                "--work-dir",
                str(self.root / "work"),
                "--output-dir",
                str(self.root / "candidate"),
                "--cache-dir",
                str(self.cache_dir),
                "--compiler-cache",
                "off",
                "--jobs",
                "2",
                "--timeout-seconds",
                "900",
                "--release-id",
                "release-fixture",
                "--format",
                "json",
            ],
        )
        self.assertEqual(
            calls[1]["args"],
            [
                "toolchain",
                "producer",
                "environment",
                "--host",
                "linux-x86_64",
                "--output",
                str(self.root / "payload" / "evidence" / "environment.json"),
                "--format",
                "json",
            ],
        )

        payload = self.root / "payload"
        package = payload / "package"
        evidence = payload / "evidence"
        package_files = {path.name for path in package.iterdir()}
        self.assertEqual(
            package_files,
            {
                "fixture-package.tar.xz",
                "fixture-package.tar.xz.manifest.json",
                "fixture-package.tar.xz.sha256",
                "fixture-package.tar.xz.spdx.json",
            },
        )
        self.assertEqual(
            {path.name for path in evidence.iterdir()},
            {
                "build-result.json",
                "environment-result.json",
                "environment.json",
                "package-result.json",
                "package-verify.json",
                "measurement.json",
            },
        )
        self.assertEqual({path.name for path in payload.iterdir()}, {"package", "evidence"})
        self.assertEqual(
            json.loads((evidence / "environment.json").read_bytes()),
            {"fixture": "native producer environment"},
        )

        package_call = calls[2]["args"]
        assert isinstance(package_call, list)
        context = [
            "--recipe",
            str(self.recipe),
            "--source-lock",
            str(self.source_lock),
            "--profiles",
            str(self.profiles),
            "--preset",
            "rv32-fixture",
            "--host",
            "linux-x86_64",
            "--release-id",
            "release-fixture",
            "--build-environment",
            str(evidence / "environment.json"),
            "--package-format",
            "family-v2",
            "--forbidden-prefix",
            str(self.root),
            "--forbidden-prefix",
            str(self.source_dir),
            "--forbidden-prefix",
            str(self.producer_dir),
            "--forbidden-prefix",
            str(self.tools_dir),
            "--forbidden-prefix",
            str(self.forbidden_dir),
        ]
        self.assertEqual(
            package_call,
            [
                "toolchain",
                "producer",
                "package",
                *context,
                "--build-result",
                str(evidence / "build-result.json"),
                "--build-result-sha256",
                sha256(BUILD_BYTES),
                "--build-work-dir",
                str(self.root / "work"),
                "--input-dir",
                str(self.root / "candidate" / "toolchain"),
                "--output-dir",
                str(package),
                "--format",
                "json",
            ],
        )
        self.assertEqual(self.arg_values(calls[2], "--package-format"), ["family-v2"])
        self.assertEqual(
            self.arg_values(calls[2], "--forbidden-prefix"),
            [
                str(self.root),
                str(self.source_dir),
                str(self.producer_dir),
                str(self.tools_dir),
                str(self.forbidden_dir),
            ],
        )
        for option, value in (
            ("--recipe", str(self.recipe)),
            ("--source-lock", str(self.source_lock)),
            ("--profiles", str(self.profiles)),
            ("--preset", "rv32-fixture"),
            ("--host", "linux-x86_64"),
            ("--release-id", "release-fixture"),
            ("--build-environment", str(evidence / "environment.json")),
            ("--build-result", str(evidence / "build-result.json")),
            ("--build-work-dir", str(self.root / "work")),
            ("--input-dir", str(self.root / "candidate" / "toolchain")),
            ("--output-dir", str(package)),
            ("--format", "json"),
        ):
            self.assertEqual(self.arg_values(calls[2], option), [value], option)
        raw_build = (evidence / "build-result.json").read_bytes()
        expected_build_sha = sha256(raw_build)
        self.assertEqual(raw_build, BUILD_BYTES)
        self.assertEqual(self.arg_values(calls[2], "--build-result-sha256"), [expected_build_sha])

        verify_call = calls[3]
        self.assertEqual(
            verify_call["args"],
            [
                "toolchain",
                "producer",
                "verify-package",
                *context,
                "--input-dir",
                str(package),
                "--format",
                "json",
            ],
        )
        for option, value in (
            ("--package-format", "family-v2"),
            ("--build-environment", str(evidence / "environment.json")),
            ("--input-dir", str(package)),
            ("--format", "json"),
        ):
            self.assertEqual(self.arg_values(verify_call, option), [value], option)
        self.assertEqual(
            self.arg_values(verify_call, "--forbidden-prefix"),
            self.arg_values(calls[2], "--forbidden-prefix"),
        )

        measurement = evidence / "measurement.json"
        self.assertEqual(measurement.read_bytes(), MEASUREMENT_BYTES)
        self.assertEqual(measurement.read_bytes().count(b"\n"), 1)
        handoff_path = self.root / "handoff.json"
        self.assertTrue(handoff_path.is_file())
        self.assertFalse(payload in handoff_path.parents)
        handoff = json.loads(handoff_path.read_bytes())
        self.assertEqual(handoff["schema"], "aros-toolchain-build-handoff-v2")
        self.assertEqual(handoff["assurance"], "local-byte-readback-only")
        self.assertEqual(handoff["payload_dir"], str(payload))
        self.assertEqual(handoff["package_dir"], str(package))
        self.assertEqual(handoff["measurement"], str(measurement))
        self.assertEqual(handoff["runtime_sha256"], sha256(self.runtime.read_bytes()))
        self.assertEqual(handoff["build_result_sha256"], expected_build_sha)
        self.assertEqual(handoff["measurement_sha256"], sha256(MEASUREMENT_BYTES))

    def test_happy_path_runs_under_system_and_current_bash(self) -> None:
        for shell in self.bashes:
            with self.subTest(shell=str(shell)):
                result = self.run_lane(interpreter=shell)
                self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
                self.assertTrue((self.root / "handoff.json").is_file())
                self.fresh_fixture()

    def test_native_case_preserving_profile_identifiers_pass_without_aliasing(self) -> None:
        for profile in ("RV32-Mixed", ".profile", "_profile", "-profile", "P" * 128):
            with self.subTest(profile=profile):
                args = self.arguments()
                args[args.index("--preset") + 1] = profile
                result = self.run_lane(arguments=args)
                self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
                self.assertEqual(self.arg_values(self.calls()[0], "--preset"), [profile])
                for call in self.calls():
                    if call["args"][:3] != ["toolchain", "producer", "environment"]:
                        self.assertIn("--preset=" + profile, call["raw_args"])
                self.assertEqual(json.loads((self.root / "handoff.json").read_bytes())["target_profile"], profile)
                self.fresh_fixture()

    def test_rejects_unknown_duplicate_and_missing_selectors_before_cli(self) -> None:
        base = self.arguments()
        self.assert_rejected_before_cli(base + ["--unknown", "value"])

        duplicate = base + ["--host", "linux-aarch64"]
        self.assert_rejected_before_cli(duplicate)

        missing = base[:]
        index = missing.index("--release-id")
        del missing[index : index + 2]
        self.assert_rejected_before_cli(missing)

    def test_rejects_wrong_runtime_digest_before_creating_operation_root(self) -> None:
        arguments = self.arguments()
        index = arguments.index("--aros-sha256") + 1
        arguments[index] = "f" * 64
        result = self.run_lane(arguments=arguments)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"selected executable differs", result.stderr)
        self.assertEqual(self.calls(), [])
        self.assertFalse(self.root.exists())

    def test_rejects_existing_and_dangling_symlink_operation_roots(self) -> None:
        self.root.mkdir()
        self.assert_rejected_before_cli(self.arguments(), root=self.root)

        self.root.rmdir()
        target = self.base / "absent-target"
        self.root.symlink_to(target)
        self.assert_rejected_before_cli(self.arguments(), root=self.root)

    def test_rejects_operation_root_overlapping_selected_input_root(self) -> None:
        overlapping_root = self.source_dir / "operation"
        arguments = self.arguments(root=overlapping_root)
        result = self.run_lane(arguments=arguments)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"operation root overlaps", result.stderr)
        self.assertEqual(self.calls(), [])
        self.assertFalse(overlapping_root.exists())

    def test_build_failure_stops_environment_and_all_handoff_steps(self) -> None:
        result = self.run_lane(mode="build-failure")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(self.calls()), 1)
        self.assertEqual(self.calls()[0]["args"][:2], ["toolchain", "build"])
        self.assert_no_handoff()

    def test_package_failure_stops_verification_and_handoff(self) -> None:
        result = self.run_lane(mode="package-failure")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(
            [call["args"][:3] for call in self.calls()],
            [
                ["toolchain", "build", "--preset"],
                ["toolchain", "producer", "environment"],
                ["toolchain", "producer", "package"],
            ],
        )
        self.assert_no_handoff()

    def test_verify_failure_stops_join_measurement_and_handoff(self) -> None:
        result = self.run_lane(mode="verify-failure")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(self.calls()), 4)
        self.assertEqual(self.calls()[-1]["args"][:3], ["toolchain", "producer", "verify-package"])
        self.assertFalse((self.root / "payload" / "evidence" / "measurement.json").exists())
        self.assert_no_handoff()

    def test_rejects_join_measurement_and_runtime_tampering_without_handoff(self) -> None:
        for mode in (
            "readback-sha-mismatch",
            "build-result-join-mismatch",
            "tree-join-mismatch",
            "measurement-hash-mismatch",
        ):
            with self.subTest(mode=mode):
                result = self.run_lane(mode=mode)
                self.assertNotEqual(result.returncode, 0, mode)
                self.assertEqual(len(self.calls()), 4, mode)
                self.assert_no_handoff()
                self.fresh_fixture()

    def test_rejects_host_profile_and_schema_mismatches_in_native_readback(self) -> None:
        for mode in (
            "host-mismatch",
            "profile-mismatch",
            "package-schema-mismatch",
            "verify-schema-mismatch",
        ):
            with self.subTest(mode=mode):
                result = self.run_lane(mode=mode)
                self.assertNotEqual(result.returncode, 0, mode)
                self.assertIn(b"guarded package/readback join failed", result.stderr, mode)
                self.assertEqual(len(self.calls()), 4, mode)
                self.assert_no_handoff()
                self.fresh_fixture()

    def test_runtime_changed_after_independent_verification_blocks_handoff(self) -> None:
        original_runtime_sha = sha256(self.runtime.read_bytes())
        result = self.run_lane(mode="runtime-change")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"runtime changed during handoff", result.stderr)
        self.assertEqual(len(self.calls()), 4)
        self.assertNotEqual(sha256(self.runtime.read_bytes()), original_runtime_sha)
        self.assert_no_handoff()


ACTION = SCRIPT.parents[2] / ".github" / "actions" / "build-native-lane-v2" / "action.yml"


def validate_owner_sequence(text: str) -> None:
    """Guard this specific action boundary, not a general YAML validator."""

    stages = re.split(r"(?m)^    - ", text)[1:]
    if len(stages) != 6:
        raise ValueError("owning-job action must retain six ordered stages")
    required = (
        ("id: build", "build-lane-v2.sh", "stage-native-owner-payload-v2.py", "ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
         '--source-dir "$ARGS_ROOT/payload" --output-dir "$ARGS_ROOT/transport-payload"'),
        ("id: payload", "actions/upload-artifact@", "path: ${{ steps.build.outputs.payload-dir }}/", "include-hidden-files: true"),
        ("artifact-origin.py\" record", "steps.payload.outputs.artifact-id", "steps.payload.outputs.artifact-digest",
         '--role build', 'ORIGIN_PAYLOAD: ${{ steps.build.outputs.payload-dir }}', '--payload-dir "$ORIGIN_PAYLOAD"', '--output "$ORIGIN_ROOT/proof/origin.json"'),
        ("id: signature", "actions/attest-build-provenance@", "subject-path: ${{ inputs.root }}/proof/origin.json"),
        ("steps.signature.outputs.bundle-path", '"$ORIGIN_ROOT/proof/origin.sigstore.json"'),
        ("id: proof", "actions/upload-artifact@", "path: ${{ inputs.root }}/proof/", "include-hidden-files: true"),
    )
    for stage, needles in zip(stages, required, strict=True):
        if not all(needle in stage for needle in needles):
            raise ValueError("owning-job stage lost its exact transport boundary")
    if stages[0].index("build-lane-v2.sh") >= stages[0].index("stage-native-owner-payload-v2.py"):
        raise ValueError("native transport must be staged after guarded package readback")
    if "printf 'payload-dir=%s/transport-payload\\n'" not in stages[0]:
        raise ValueError("native transport directory must be bound to the staged result")
    if "continue-on-error" in text or re.search(r"(?m)^\s+if:", text):
        raise ValueError("owning-job stages must not suppress or skip a required gate")
    # Inputs enter executable shell through env, never through direct expression
    # interpolation in a run body. The workflow/source/job context stays explicit.
    for stage in stages:
        if "run: |" in stage and "${{ inputs." in stage.split("run: |", 1)[1]:
            raise ValueError("caller input was interpolated directly into shell")
    for name in ("artifact-id", "artifact-digest"):
        if f"steps.payload.outputs.{name}" not in text or f"steps.proof.outputs.{name}" not in text:
            raise ValueError("caller lost the independent upload selectors")
    uses = re.findall(r"(?m)^\s+uses: (\S+)", text)
    if len(uses) != 3 or any(re.fullmatch(r"[^@]+@[0-9a-f]{40}", item) is None for item in uses):
        raise ValueError("transport/signature actions must have exact commit pins")


class OwnerActionContractTests(unittest.TestCase):
    def test_owner_sequence_preserves_original_payload_and_separate_proof(self) -> None:
        validate_owner_sequence(ACTION.read_text(encoding="utf-8"))

    def test_owner_sequence_rejects_suppressed_gate_shadow_payload_and_missing_selector(self) -> None:
        valid = ACTION.read_text(encoding="utf-8")
        mutants = (
            valid.replace("id: signature", "id: signature\n      continue-on-error: true", 1),
            valid.replace("path: ${{ inputs.root }}/proof/", "path: ${{ inputs.root }}/payload/", 1),
            valid.replace("steps.payload.outputs.artifact-digest", "steps.payload.outputs.other-digest"),
            valid.replace("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "OTHER_REQUEST_TOKEN"),
            valid.replace("artifact-origin.py\" record", "artifact-origin.py\" verify", 1),
            valid.replace('--role build', '--role diagnostic', 1),
            valid.replace('stage-native-owner-payload-v2.py', 'echo-no-staging.py', 1),
            valid.replace('path: ${{ steps.build.outputs.payload-dir }}/', 'path: ${{ inputs.root }}/payload/', 1),
            valid.replace('--payload-dir "$ORIGIN_PAYLOAD"', '--payload-dir "$ORIGIN_ROOT/payload"', 1),
            valid.replace('"$ARGS_AROS"', '"${{ inputs.aros }}"', 1),
        )
        for mutant in mutants:
            with self.subTest(mutant=hashlib.sha256(mutant.encode()).hexdigest()[:12]):
                with self.assertRaises(ValueError):
                    validate_owner_sequence(mutant)

    def names(self, group: str, host: str, profile: str, copy: str, *, run_id: str = "123456", attempt: str = "2", workflow: str = ".github/workflows/toolchain-release.yml", reject: bool = False) -> tuple[str, str]:
        # Execute the actual action preflight before the expensive native call;
        # no fake reproduction of its tuple encoding or name formula.
        text = ACTION.read_text(encoding="utf-8")
        prefix = text.split("      run: |\n", 1)[1].split('        bash "$GITHUB_ACTION_PATH/', 1)[0]
        fragment = textwrap.dedent(prefix) + 'printf "%s\\n%s\\n" "$payload_name" "$proof_name"\n'
        environment = os.environ.copy()
        environment.update({
            "ARGS_GROUP": group, "ARGS_HOST": host, "ARGS_PRESET": profile,
            "ARGS_COPY": copy, "ARGS_WORKFLOW": workflow,
            "ARGS_JOB_NAME": "Explicit build lane", "GITHUB_RUN_ID": run_id,
            "GITHUB_RUN_ATTEMPT": attempt, "ACTIONS_ID_TOKEN_REQUEST_URL": "fixture",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "fixture",
        })
        result = subprocess.run(["bash", "-c", fragment], env=environment, capture_output=True, text=True, check=False)
        if reject:
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")
            return "", ""
        self.assertEqual(result.returncode, 0, result.stderr)
        names = result.stdout.splitlines()
        self.assertEqual(len(names), 2)
        return names[0], names[1]

    def test_action_workflow_validation_matches_origin_recorder_before_build(self) -> None:
        for workflow in (".github/workflows/release.yaml", ".github/workflows/release.extra.yml",
                         ".github/workflows/../release.yml", ".github/workflows/release.yml\n"):
            with self.subTest(workflow=workflow):
                self.names("group", "linux-x86_64", "profile", "a", workflow=workflow, reject=True)
        self.names("group", "linux-x86_64", "profile", "a", workflow=".github/workflows/Release_v2-test.yml")

    def test_actual_action_names_preserve_structured_lane_identity_and_transport_limit(self) -> None:
        first = self.names("foo", "linux-aarch64", "abc-linux-x86_64-def", "a")
        second = self.names("foo-linux-aarch64-abc", "linux-x86_64", "def", "a")
        self.assertNotEqual(first, second)
        long_names = self.names("g" * 64, "macos-aarch64", "P" * 128, "b", run_id="9" * 20, attempt="9" * 20)
        for name in long_names:
            self.assertLessEqual(len(name), 128)
            self.assertRegex(name, r"\Anative-v2-(?:proof-)?[0-9a-f]{64}-[0-9]+-[0-9]+\Z")
        self.assertNotEqual(self.names("group", "linux-x86_64", "profile", "a"),
                            self.names("group", "linux-x86_64", "Profile", "a"))
        for changed in (("group", "linux-x86_64", "Profile", "b"),
                        ("other", "linux-x86_64", "Profile", "a"),
                        ("group", "linux-aarch64", "Profile", "a")):
            self.assertNotEqual(self.names("group", "linux-x86_64", "Profile", "a"), self.names(*changed))


if __name__ == "__main__":
    unittest.main()
