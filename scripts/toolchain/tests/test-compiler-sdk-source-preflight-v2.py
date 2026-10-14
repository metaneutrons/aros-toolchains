#!/usr/bin/env python3
"""Local orchestration tests for the non-publishing source preflight."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
PREFLIGHT = ROOT / "scripts/toolchain/check-compiler-sdk-source-preflight-v2.py"
SOURCE_SEED = b"canonical locked zlib test seed\n"


class SourcePreflightFixture:
    def __init__(
        self,
        root: Path,
        *,
        fail_release_test: bool = False,
        mutate_aros: bool = False,
        oversize_release_output: bool = False,
    ):
        self.root = root
        self.source = root / "source"
        self.source.mkdir()
        self.output = root / "private-output"
        self.host_home = root / "host-home"
        (self.host_home / ".config/gh").mkdir(parents=True)
        (self.host_home / ".config/gh/hosts.yml").write_text(
            "github.com:\n  oauth_token: fixture-secret-stored-gh-token\n", encoding="utf-8"
        )
        (self.host_home / ".netrc").write_text(
            "machine github.com login fixture password fixture-secret-netrc\n", encoding="utf-8"
        )
        (self.host_home / ".credentials").write_text("fixture-secret-credential-store\n", encoding="utf-8")
        self.seed = root / "chromium-zlib-da752eb2.tar.gz"
        self.seed.write_bytes(SOURCE_SEED)
        self.seed_sha256 = hashlib.sha256(SOURCE_SEED).hexdigest()
        self.aros = root / "runtime" / "bin" / "aros"
        self.aros.parent.mkdir(parents=True)
        self.aros_log = root / "aros-calls.log"

        self._write_source_fixture(
            fail_release_test=fail_release_test,
            mutate_aros=mutate_aros,
            oversize_release_output=oversize_release_output,
        )
        self._write_aros_fixture()
        self._commit_source()

    def _write(self, relative: str, contents: str, *, executable: bool = False) -> Path:
        path = self.source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")
        if executable:
            path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        return path

    def _write_source_fixture(
        self,
        *,
        fail_release_test: bool,
        mutate_aros: bool,
        oversize_release_output: bool,
    ) -> None:
        plan = {
            "schema": "aros-cache-source-fetch-plan-v1",
            "entries": [
                {
                    "role": "product:chromium-zlib@da752eb2a3660cf1bf8dac620f6380b89dd953a7",
                    "filename": "zlib.tar.gz",
                    "candidates": [{"url": "https://example.invalid/locked-zlib.tar.gz"}],
                    "representation": "archive",
                    "normalization": "canonical-tar-gzip-v1",
                    "integrity": {"kind": "locked", "sha256": self.seed_sha256, "size": len(SOURCE_SEED)},
                }
            ],
        }
        staging = {
            "schema": "aros-nx-product-source-staging-v1",
            "entries": [
                {
                    "role": "product:chromium-zlib@da752eb2a3660cf1bf8dac620f6380b89dd953a7",
                    "destination": "portssources/zlib.tar.gz",
                    "source_guard": {"path": "scripts/ci/source-guard.txt", "line": "locked-source-fixture"},
                }
            ],
        }
        (self.source / "scripts/ci").mkdir(parents=True)
        (self.source / "scripts/ci/product-sources.plan.json").write_text(
            json.dumps(plan, indent=2) + "\n", encoding="utf-8"
        )
        (self.source / "scripts/ci/product-sources.staging.json").write_text(
            json.dumps(staging, indent=2) + "\n", encoding="utf-8"
        )
        (self.source / "scripts/ci/source-guard.txt").write_text("locked-source-fixture\n", encoding="utf-8")

        mutation = ""
        if mutate_aros:
            mutation = (
                "    def test_selected_cli_is_still_the_pinned_file(self):\n"
                f"        Path({str(self.aros)!r}).write_bytes(b'changed executable')\n"
            )
        test_body = (
            "import os\n"
            "from pathlib import Path\n"
            "import unittest\n\n"
            "class SourceContractFixture(unittest.TestCase):\n"
            "    def test_provider_credentials_are_absent(self):\n"
            "        for name in (\n"
            "            'GH_TOKEN', 'GITHUB_TOKEN', 'ACTIONS_ID_TOKEN_REQUEST_TOKEN',\n"
            "            'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AZURE_CLIENT_SECRET',\n"
            "            'GOOGLE_APPLICATION_CREDENTIALS', 'GIT_CONFIG_COUNT',\n"
            "            'GIT_CONFIG_KEY_0', 'GIT_CONFIG_VALUE_0', 'PYTHONPATH',\n"
            "            'API_KEY', 'PRIVATE_KEY', 'SIGNING_KEY', 'BASH_ENV', 'ENV',\n"
            "            'AUTHORIZATION', 'LD_PRELOAD', 'DYLD_INSERT_LIBRARIES', 'PYTHONNOUSERSITE',\n"
            "            'NETRC', 'NETRC_FILE', 'CURL_NETRC', 'CURL_NETRC_FILE',\n"
            "            'CREDENTIALSTORE', 'CREDENTIAL_STORE',\n"
            "        ):\n"
            "            self.assertNotIn(name, os.environ)\n"
            f"        private_home = Path({str((self.output / 'child-home').resolve())!r})\n"
            "        self.assertEqual(os.environ.get('HOME'), str(private_home))\n"
            "        expected_dirs = {\n"
            "            'XDG_CONFIG_HOME': 'xdg-config', 'XDG_CACHE_HOME': 'xdg-cache',\n"
            "            'XDG_DATA_HOME': 'xdg-data', 'GH_CONFIG_DIR': 'gh-config',\n"
            "            'CURL_HOME': 'curl-home',\n"
            "        }\n"
            "        for variable, dirname in expected_dirs.items():\n"
            "            directory = private_home / dirname\n"
            "            self.assertEqual(os.environ.get(variable), str(directory))\n"
            "            self.assertTrue(directory.is_dir())\n"
            "            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)\n"
            "        self.assertFalse((private_home / '.netrc').exists())\n"
            "        self.assertFalse((private_home / 'gh-config/hosts.yml').exists())\n"
            "        self.assertNotIn('GITHUB_SHA', os.environ)\n"
            "        self.assertNotIn('GITHUB_EVENT_NAME', os.environ)\n"
            "        self.assertNotIn('GITHUB_OUTPUT', os.environ)\n"
            + mutation
        )
        self._write("scripts/ci/test_preflight_contracts.py", test_body)

        hygiene = r'''import json
import os
import subprocess
import sys

def provider_credentials_present():
    prefixes = ("GH_", "ACTIONS_", "OIDC_", "AWS_", "AZURE_", "GOOGLE_", "GCP_", "CLOUDSDK_")
    exact = {
        "GITHUB_TOKEN", "GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0",
        "PYTHONPATH", "GOOGLE_APPLICATION_CREDENTIALS", "BASH_ENV", "ENV",
        "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "PYTHONNOUSERSITE",
    }
    return any(
        (name.startswith(prefixes) and name != "GH_CONFIG_DIR")
        or name in exact
        or any(fragment in name.upper() for fragment in ("AUTH", "API_KEY", "PRIVATE_KEY", "SIGNING_KEY"))
        for name in os.environ
    )

if provider_credentials_present():
    raise SystemExit(31)
if sys.argv[1] == "plan":
    if os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch":
        raise SystemExit(32)
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    if os.environ.get("GITHUB_SHA") != head:
        raise SystemExit(33)
    if set(name for name in os.environ if name.startswith("GITHUB_")) != {
        "GITHUB_EVENT_NAME", "GITHUB_SHA", "GITHUB_OUTPUT"
    }:
        raise SystemExit(34)
    matrix = {"include": [{"host": "linux-x86_64", "preset": "fixture"}]}
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        output.write("scope=full\n")
        output.write("matrix=" + json.dumps(matrix, separators=(",", ":")) + "\n")
elif sys.argv[1] != "paths":
    raise SystemExit(35)
'''
        self._write("scripts/ci/ci_hygiene.py", hygiene)

        locked_sources = r'''import hashlib
import json
import os
from pathlib import Path
import shutil
import sys

if any(
    (
        name.startswith(("GH_", "GITHUB", "ACTIONS_", "OIDC_", "AWS_", "AZURE_", "GOOGLE_", "GCP_", "CLOUDSDK_"))
        and name != "GH_CONFIG_DIR"
    )
    or name in {
        "GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0", "PYTHONPATH",
        "BASH_ENV", "ENV", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "PYTHONNOUSERSITE",
    }
    or any(fragment in name.upper() for fragment in ("AUTH", "API_KEY", "PRIVATE_KEY", "SIGNING_KEY"))
    for name in os.environ
):
    raise SystemExit(41)
args = sys.argv[1:]
if args == ["validate"]:
    plan = json.loads(Path("scripts/ci/product-sources.plan.json").read_text())
    staging = json.loads(Path("scripts/ci/product-sources.staging.json").read_text())
    if len(plan["entries"]) != len(staging["entries"]):
        raise SystemExit(42)
elif args and args[0] == "export":
    cache = Path(args[args.index("--cache") + 1])
    output = Path(args[args.index("--output") + 1])
    entry = json.loads(Path("scripts/ci/product-sources.plan.json").read_text())["entries"][0]
    source = cache / entry["filename"]
    if hashlib.sha256(source.read_bytes()).hexdigest() != entry["integrity"]["sha256"]:
        raise SystemExit(43)
    output.mkdir()
    shutil.copyfile(source, output / entry["filename"])
else:
    raise SystemExit(44)
'''
        self._write("scripts/ci/locked_product_sources.py", locked_sources)

        for name in ("test-header-closure.sh", "test-release-layout.sh", "test-zstd-closure.sh"):
            body = "#!/bin/sh\nset -eu\n"
            body += 'test "${GH_TOKEN+x}" != x\n'
            body += 'test "${GITHUB_TOKEN+x}" != x\n'
            body += 'test "${ACTIONS_ID_TOKEN_REQUEST_TOKEN+x}" != x\n'
            body += 'test "${AWS_ACCESS_KEY_ID+x}" != x\n'
            body += 'test "${AZURE_CLIENT_SECRET+x}" != x\n'
            body += 'test "${GIT_CONFIG_COUNT+x}" != x\n'
            body += 'test "${PYTHONPATH+x}" != x\n'
            body += 'test "${API_KEY+x}" != x\n'
            body += 'test "${PRIVATE_KEY+x}" != x\n'
            body += 'test "${SIGNING_KEY+x}" != x\n'
            body += 'test "${AUTHORIZATION+x}" != x\n'
            body += 'test "${BASH_ENV+x}" != x\n'
            body += 'test "${ENV+x}" != x\n'
            body += 'test "${LD_PRELOAD+x}" != x\n'
            body += 'test "${DYLD_INSERT_LIBRARIES+x}" != x\n'
            body += 'test "${PYTHONNOUSERSITE+x}" != x\n'
            body += 'test "${NETRC+x}" != x\n'
            body += 'test "${NETRC_FILE+x}" != x\n'
            body += 'test "${CREDENTIALSTORE+x}" != x\n'
            body += 'test "${CREDENTIAL_STORE+x}" != x\n'
            body += f'test "$HOME" = {shlex.quote(str((self.output / "child-home").resolve()))}\n'
            if name == "test-release-layout.sh" and oversize_release_output:
                command = shlex.join(
                    [sys.executable, "-c", "import sys; sys.stderr.write('x' * 1048577)"]
                )
                body += f"{command}\n"
            if name == "test-release-layout.sh" and fail_release_test:
                body += "printf '%s\\n' 'fixture release-layout diagnostic' >&2\nexit 23\n"
            else:
                body += "exit 0\n"
            self._write(f"tools/crosstools/gnu/tests/{name}", body)

        for relative in (
            "compiler/sdk/test_export.py",
            "compiler/sdk/export.py",
            "arch/riscv-esp32p4/native-sdk/test_export.py",
            "arch/riscv-esp32p4/native-sdk/export.py",
        ):
            self._write(relative, "pass\n")

    def _write_aros_fixture(self) -> None:
        body = f'''#!/bin/sh
set -eu
test "${{GH_TOKEN+x}}" != x
test "${{GITHUB_TOKEN+x}}" != x
test "${{ACTIONS_ID_TOKEN_REQUEST_TOKEN+x}}" != x
test "${{AWS_ACCESS_KEY_ID+x}}" != x
test "${{AZURE_CLIENT_SECRET+x}}" != x
test "${{GIT_CONFIG_COUNT+x}}" != x
test "${{PYTHONPATH+x}}" != x
test "${{API_KEY+x}}" != x
test "${{PRIVATE_KEY+x}}" != x
test "${{SIGNING_KEY+x}}" != x
test "${{AUTHORIZATION+x}}" != x
test "${{BASH_ENV+x}}" != x
test "${{ENV+x}}" != x
test "${{LD_PRELOAD+x}}" != x
test "${{DYLD_INSERT_LIBRARIES+x}}" != x
test "${{PYTHONNOUSERSITE+x}}" != x
test "${{NETRC+x}}" != x
test "${{NETRC_FILE+x}}" != x
test "${{CREDENTIALSTORE+x}}" != x
test "${{CREDENTIAL_STORE+x}}" != x
test "$HOME" = {shlex.quote(str((self.output / "child-home").resolve()))}
test "${{GITHUB_SHA+x}}" != x
test "${{GITHUB_EVENT_NAME+x}}" != x
test "${{GITHUB_OUTPUT+x}}" != x
printf '%s\\n' "$*" >> {shlex.quote(str(self.aros_log))}
if [ "$1" != cache ] || [ "$2" != sources ]; then exit 51; fi
operation=$3
shift 3
plan=
cache=
offline=no
while [ "$#" -gt 0 ]; do
  case "$1" in
    --source-fetch-plan) plan=$2; shift 2 ;;
    --dir) cache=$2; shift 2 ;;
    --offline) offline=yes; shift ;;
    *) exit 52 ;;
  esac
done
if [ "$plan" = "" ] || [ "$cache" = "" ]; then exit 53; fi
if [ "$operation" = fetch ] && [ "$offline" != yes ]; then exit 54; fi
cmp "$cache/zlib.tar.gz" {shlex.quote(str(self.seed))}
if [ "$operation" != fetch ] && [ "$operation" != verify ]; then exit 55; fi
'''
        self.aros.write_text(body, encoding="utf-8")
        self.aros.chmod(0o755)

    def _commit_source(self) -> None:
        subprocess.run(["git", "init", "-q"], cwd=self.source, check=True)
        subprocess.run(["git", "config", "user.email", "fixture@example.invalid"], cwd=self.source, check=True)
        subprocess.run(["git", "config", "user.name", "Source preflight fixture"], cwd=self.source, check=True)
        subprocess.run(["git", "add", "-A"], cwd=self.source, check=True)
        subprocess.run(["git", "commit", "-qm", "source fixture"], cwd=self.source, check=True)
        self.expected_commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=self.source, text=True
        ).strip()

    def invoke(
        self,
        *,
        expected_commit: str | None = None,
        product_source_seed: Path | None = None,
        aros_path: Path | None = None,
    ):
        command = [
            sys.executable,
            "-B",
            str(PREFLIGHT),
            "--source-dir",
            str(self.source),
            "--expected-commit",
            expected_commit or self.expected_commit,
            "--output-dir",
            str(self.output),
            "--aros",
            str(aros_path or self.aros),
            "--aros-sha256",
            hashlib.sha256(self.aros.read_bytes()).hexdigest(),
            "--product-source-seed",
            str(product_source_seed or self.seed),
        ]
        environment = os.environ.copy()
        environment.update(
            {
                "GH_TOKEN": "fixture-secret-gh-token",
                "GITHUB_TOKEN": "fixture-secret-github-token",
                "ACTIONS_ID_TOKEN_REQUEST_URL": "https://oidc.invalid/request",
                "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "fixture-secret-oidc-token",
                "AWS_ACCESS_KEY_ID": "fixture-aws-access-key",
                "AWS_SECRET_ACCESS_KEY": "fixture-secret-aws-key",
                "AZURE_CLIENT_SECRET": "fixture-secret-azure-key",
                "GOOGLE_APPLICATION_CREDENTIALS": str(self.root / "provider-creds.json"),
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "credential.helper",
                "GIT_CONFIG_VALUE_0": "fixture-malicious-helper",
                "PYTHONPATH": str(self.root / "python-injection"),
                "API_KEY": "fixture-secret-api-key",
                "PRIVATE_KEY": "fixture-secret-private-key",
                "SIGNING_KEY": "fixture-secret-signing-key",
                "AUTHORIZATION": "fixture-secret-authorization",
                "BASH_ENV": str(self.root / "bash-env"),
                "ENV": str(self.root / "shell-env"),
                "LD_PRELOAD": "",
                "DYLD_INSERT_LIBRARIES": "",
                "PYTHONNOUSERSITE": "0",
                "GITHUB_EVENT_NAME": "workflow_run",
                "GITHUB_SHA": "f" * 40,
                "GITHUB_OUTPUT": str(self.root / "caller-output"),
                "HOME": str(self.host_home),
                "XDG_CONFIG_HOME": str(self.host_home / ".config"),
                "XDG_CACHE_HOME": str(self.host_home / ".cache"),
                "XDG_DATA_HOME": str(self.host_home / ".local/share"),
                "GH_CONFIG_DIR": str(self.host_home / ".config/gh"),
                "CURL_HOME": str(self.host_home),
                "NETRC": str(self.host_home / ".netrc"),
                "NETRC_FILE": str(self.host_home / ".netrc"),
                "CURL_NETRC": "1",
                "CURL_NETRC_FILE": str(self.host_home / ".netrc"),
                "CREDENTIALSTORE": str(self.host_home / ".credentials"),
                "CREDENTIAL_STORE": str(self.host_home / ".credentials"),
            }
        )
        return subprocess.run(command, capture_output=True, text=True, env=environment, check=False, timeout=10)

    def report(self) -> dict:
        return json.loads((self.output / "source-preflight-v2.json").read_text(encoding="utf-8"))


class SourcePreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="aros-source-preflight-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def make_fixture(self, **kwargs) -> SourcePreflightFixture:
        return SourcePreflightFixture(self.root, **kwargs)

    def assert_failed_without_success(self, fixture: SourcePreflightFixture, result: subprocess.CompletedProcess[str]) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn('"status": "passed"', result.stdout)
        self.assertNotIn('"status":"passed"', result.stdout)
        if fixture.output.exists() and (fixture.output / "source-preflight-v2.json").exists():
            self.assertEqual(fixture.report()["status"], "failed")

    def test_positive_orchestration_uses_source_sha_sanitizes_children_and_uses_offline_seed(self) -> None:
        fixture = self.make_fixture()
        result = fixture.invoke()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = fixture.report()
        self.assertEqual(report["schema"], "aros-compiler-sdk-source-preflight-v2")
        self.assertEqual(report["assurance"], "source-contract-preflight-only-not-ci-qualification-or-release-admission")
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["source_commit"], fixture.expected_commit)
        self.assertEqual(report["hygiene_scope"], "full")
        self.assertEqual(report["product_source"]["fetch_mode"], "offline-cache-hit")
        self.assertEqual(report["product_source"]["cache_seed"]["sha256"], fixture.seed_sha256)
        self.assertEqual(report["product_source"]["cache_seed"]["size"], len(SOURCE_SEED))
        self.assertEqual(report["product_source"]["export_sha256"], fixture.seed_sha256)
        self.assertEqual(report["product_source"]["export_size"], len(SOURCE_SEED))
        self.assertEqual(
            [step["name"] for step in report["steps"]],
            [
                "ci-contract-tests",
                "gnu-header-closure",
                "gnu-release-layout",
                "gnu-zstd-closure",
                "hygiene-plan",
                "hygiene-paths",
                "product-source-lock-validation",
                "llvm-sdk-exporter-tests",
                "llvm-sdk-export-check",
                "native-sdk-exporter-tests",
                "native-sdk-export-check",
                "product-source-fetch-offline",
                "product-source-verify",
                "product-source-export",
                "source-checkout-final",
                "aros-executable-final",
            ],
        )
        self.assertEqual((fixture.output / "product-source-cache/zlib.tar.gz").read_bytes(), SOURCE_SEED)
        self.assertEqual((fixture.output / "product-source-export/zlib.tar.gz").read_bytes(), SOURCE_SEED)
        self.assertFalse((fixture.output / "ci-hygiene-plan.out").exists())
        self.assertEqual(stat.S_IMODE(fixture.output.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((fixture.output / "source-preflight-v2.json").stat().st_mode), 0o600)
        private_home = fixture.output / "child-home"
        self.assertEqual(stat.S_IMODE(private_home.stat().st_mode), 0o700)
        for name in ("xdg-config", "xdg-cache", "xdg-data", "gh-config", "curl-home"):
            self.assertEqual(stat.S_IMODE((private_home / name).stat().st_mode), 0o700)
        self.assertFalse((private_home / ".netrc").exists())
        self.assertFalse((private_home / "gh-config/hosts.yml").exists())
        self.assertIn("private child configuration directories do not sandbox", " ".join(report["limitations"]))
        self.assertFalse(report["child_environment"]["os_sandbox"])
        self.assertTrue((fixture.host_home / ".config/gh/hosts.yml").is_file())
        self.assertTrue((fixture.host_home / ".netrc").is_file())
        self.assertTrue((fixture.host_home / ".credentials").is_file())
        self.assertFalse((fixture.root / "caller-output").exists())
        for step in report["steps"]:
            if "stdout_log" not in step:
                continue
            for stream in ("stdout_log", "stderr_log"):
                log_path = fixture.output / step[stream]
                self.assertTrue(log_path.is_file())
                self.assertLessEqual(log_path.stat().st_size, 1024 * 1024)
                self.assertEqual(stat.S_IMODE(log_path.stat().st_mode), 0o600)
        self.assertIn(
            "test_provider_credentials_are_absent",
            (fixture.output / report["steps"][0]["stderr_log"]).read_text(encoding="utf-8"),
        )
        for log_path in fixture.output.glob("*.log"):
            log_bytes = log_path.read_bytes()
            for secret in (
                b"fixture-secret-gh-token",
                b"fixture-secret-github-token",
                b"fixture-secret-oidc-token",
                b"fixture-secret-aws-key",
                b"fixture-secret-api-key",
                b"fixture-secret-private-key",
                b"fixture-secret-signing-key",
                b"fixture-secret-authorization",
            ):
                self.assertNotIn(secret, log_bytes)
        calls = fixture.aros_log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(calls), 2)
        self.assertIn("fetch", calls[0])
        self.assertIn("--offline", calls[0])
        self.assertIn("verify", calls[1])
        self.assertNotIn("fixture-secret-gh-token", result.stdout)
        self.assertNotIn("fixture-secret-oidc-token", result.stdout)
        self.assertNotIn("fixture-secret-aws-key", result.stdout)
        self.assertIn("does not replace AROS-NX protected CI", " ".join(report["limitations"]))

    def test_wrong_commit_fails_before_private_output_is_created(self) -> None:
        fixture = self.make_fixture()
        result = fixture.invoke(expected_commit="0" * 40)

        self.assert_failed_without_success(fixture, result)
        self.assertFalse(fixture.output.exists())
        self.assertFalse(fixture.aros_log.exists())

    def test_dirty_tracked_source_fails_before_any_check(self) -> None:
        fixture = self.make_fixture()
        (fixture.source / "scripts/ci/source-guard.txt").write_text("tampered\n", encoding="utf-8")
        result = fixture.invoke()

        self.assert_failed_without_success(fixture, result)
        self.assertFalse(fixture.output.exists())
        self.assertFalse(fixture.aros_log.exists())

    def test_first_failing_source_check_stops_without_suppression_or_success_report(self) -> None:
        fixture = self.make_fixture(fail_release_test=True)
        result = fixture.invoke()

        self.assert_failed_without_success(fixture, result)
        report = fixture.report()
        self.assertEqual(report["failed_step"], "gnu-release-layout")
        self.assertEqual(report["steps"][2]["name"], "gnu-release-layout")
        self.assertEqual(report["steps"][2]["status"], "failed")
        self.assertEqual(report["steps"][2]["failure"], "nonzero-exit")
        self.assertIn(
            "fixture release-layout diagnostic",
            (fixture.output / report["steps"][2]["stderr_log"]).read_text(encoding="utf-8"),
        )
        self.assertNotIn("product-source-lock-validation", [step["name"] for step in report["steps"]])
        self.assertFalse(fixture.aros_log.exists())

    def test_oversized_child_output_is_bounded_and_diagnostic_prefix_is_retained(self) -> None:
        fixture = self.make_fixture(oversize_release_output=True)
        result = fixture.invoke()

        self.assert_failed_without_success(fixture, result)
        report = fixture.report()
        step = report["steps"][2]
        self.assertEqual(report["failed_step"], "gnu-release-layout")
        self.assertEqual(step["failure"], "output-limit")
        stderr_log = fixture.output / step["stderr_log"]
        self.assertEqual(stderr_log.stat().st_size, 1024 * 1024)
        self.assertFalse(fixture.aros_log.exists())

    def test_product_source_seed_must_match_the_selected_locked_sha_and_size(self) -> None:
        fixture = self.make_fixture()
        fixture.seed.write_bytes(b"different bytes")
        result = fixture.invoke()

        self.assert_failed_without_success(fixture, result)
        report = fixture.report()
        self.assertEqual(report["failed_step"], "product-source-seed")
        self.assertFalse(fixture.aros_log.exists())

    def test_fifo_seed_and_runtime_inputs_are_rejected_without_blocking(self) -> None:
        fixture = self.make_fixture()
        seed_fifo = fixture.root / "source-seed.fifo"
        os.mkfifo(seed_fifo)
        result = fixture.invoke(product_source_seed=seed_fifo)
        self.assert_failed_without_success(fixture, result)
        self.assertFalse(fixture.output.exists())
        self.assertFalse(fixture.aros_log.exists())

        second_root = self.root / "runtime-fifo-case"
        second_root.mkdir()
        second = SourcePreflightFixture(second_root)
        runtime_fifo = second_root / "runtime-fifo"
        os.mkfifo(runtime_fifo)
        result = second.invoke(aros_path=runtime_fifo)
        self.assert_failed_without_success(second, result)
        self.assertFalse(second.output.exists())
        self.assertFalse(second.aros_log.exists())

    def test_source_metadata_fifo_probe_is_nonblocking(self) -> None:
        source_fifo = self.root / "source-metadata.fifo"
        os.mkfifo(source_fifo)
        probe = (
            "import importlib.util, pathlib, sys\n"
            f"spec = importlib.util.spec_from_file_location('preflight', {str(PREFLIGHT)!r})\n"
            "module = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(module)\n"
            "try:\n"
            "    module._open_regular(pathlib.Path(sys.argv[1]), 'source metadata')\n"
            "except module.PreflightError:\n"
            "    raise SystemExit(0)\n"
            "raise SystemExit(1)\n"
        )
        result = subprocess.run(
            [sys.executable, "-B", "-c", probe, str(source_fifo)],
            capture_output=True,
            text=True,
            timeout=3,
            env={"PYTHONDONTWRITEBYTECODE": "1"},
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_changed_aros_binary_fails_and_never_invokes_it(self) -> None:
        fixture = self.make_fixture(mutate_aros=True)
        result = fixture.invoke()

        self.assert_failed_without_success(fixture, result)
        report = fixture.report()
        self.assertEqual(report["status"], "failed")
        self.assertTrue(report["failed_step"].startswith("aros-integrity-after-ci-contract-tests"))
        self.assertFalse(fixture.aros_log.exists())

    def test_occupied_and_symlink_output_paths_are_rejected_without_mutation(self) -> None:
        fixture = self.make_fixture()
        fixture.output.mkdir()
        marker = fixture.output / "do-not-touch"
        marker.write_text("preserve\n", encoding="utf-8")
        result = fixture.invoke()
        self.assert_failed_without_success(fixture, result)
        self.assertEqual(marker.read_text(encoding="utf-8"), "preserve\n")
        self.assertFalse(fixture.aros_log.exists())

        second_root = self.root / "symlink-case"
        second_root.mkdir()
        second = SourcePreflightFixture(second_root)
        target = second_root / "target"
        target.mkdir()
        marker = target / "keep"
        marker.write_text("keep\n", encoding="utf-8")
        second.output.symlink_to(target, target_is_directory=True)
        result = second.invoke()
        self.assert_failed_without_success(second, result)
        self.assertEqual(marker.read_text(encoding="utf-8"), "keep\n")
        self.assertFalse(second.aros_log.exists())


if __name__ == "__main__":
    unittest.main()
