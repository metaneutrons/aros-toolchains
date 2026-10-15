#!/usr/bin/env python3
"""Exercise the Markdown link-checking wrapper without network access."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


CHECKER = Path(__file__).resolve().parents[1] / "check-markdown-links.sh"
LYCHEE_URL = (
    "https://github.com/lycheeverse/lychee/releases/download/"
    "lychee-v0.24.2/lychee-x86_64-unknown-linux-gnu.tar.gz"
)


class MarkdownLinksTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.runner_temp = self.root / "runner-temp"
        self.runner_temp.mkdir()
        self.fake_bin = self.root / "fake-bin"
        self.fake_bin.mkdir()
        self.markers = self.root / "markers"
        self.markers.mkdir()
        self.call_order = self.root / "calls.txt"
        self.curl_arguments = self.root / "curl-arguments.nul"
        self.lychee_arguments = self.root / "lychee-arguments.nul"
        self.fake_lychee = self.root / "fake-lychee"
        self._initialize_repository()
        self._install_fake_tools()

    def _git(self, *args: str) -> bytes:
        result = subprocess.run(
            ["git", *args],
            cwd=self.repo,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return result.stdout

    def _write_repo_file(self, relative_path: str, content: str) -> None:
        path = self.repo / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def _write_executable(self, name: str, content: str) -> None:
        path = self.fake_bin / name
        path.write_text(content, encoding="utf-8")
        path.chmod(0o755)

    def _initialize_repository(self) -> None:
        self._git("init", "--quiet")
        self._git("config", "user.name", "Markdown checker test")
        self._git("config", "user.email", "markdown-checker@example.invalid")
        self._write_repo_file("README.md", "# README\n")
        self._write_repo_file("docs/guide with spaces.md", "[local](../README.md#readme)\n")
        self._write_repo_file("docs/line\nbreak.md", "[external](https://example.invalid/)\n")
        self._git("add", "--all")
        self._git("commit", "--quiet", "-m", "add Markdown fixtures")
        self._write_repo_file("untracked.md", "must not be checked\n")

    def _install_fake_tools(self) -> None:
        self.fake_lychee.write_text(
            "#!/usr/bin/env python3\n"
            "import os, sys\n"
            "from pathlib import Path\n"
            "with Path(os.environ['CALL_ORDER']).open('a', encoding='ascii') as order:\n"
            "    order.write('lychee\\n')\n"
            "Path(os.environ['LYCHEE_ARGUMENTS']).write_bytes(\n"
            "    b'\\0'.join(os.fsencode(item) for item in sys.argv[1:])\n"
            ")\n",
            encoding="utf-8",
        )
        self.fake_lychee.chmod(0o755)

        self._write_executable(
            "uname",
            "#!/bin/sh\n"
            "case \"$1\" in\n"
            "  -s) printf 'Linux\\n' ;;\n"
            "  -m) printf 'x86_64\\n' ;;\n"
            "  *) exit 2 ;;\n"
            "esac\n",
        )
        self._write_executable(
            "curl",
            "#!/usr/bin/env python3\n"
            "import os, sys\n"
            "from pathlib import Path\n"
            "args = sys.argv[1:]\n"
            "with Path(os.environ['CALL_ORDER']).open('a', encoding='ascii') as order:\n"
            "    order.write('curl\\n')\n"
            "Path(os.environ['CURL_ARGUMENTS']).write_bytes(\n"
            "    b'\\0'.join(os.fsencode(item) for item in args)\n"
            ")\n"
            "Path(args[args.index('--output') + 1]).write_bytes(b'fixture archive')\n",
        )
        self._write_executable(
            "shasum",
            "#!/usr/bin/env python3\n"
            "import os, sys\n"
            "from pathlib import Path\n"
            "with Path(os.environ['CALL_ORDER']).open('a', encoding='ascii') as order:\n"
            "    order.write('shasum\\n')\n"
            "print(os.environ['FAKE_SHA256'] + '  ' + sys.argv[-1])\n",
        )
        self._write_executable(
            "tar",
            "#!/usr/bin/env python3\n"
            "import os, shutil, sys\n"
            "from pathlib import Path\n"
            "args = sys.argv[1:]\n"
            "with Path(os.environ['CALL_ORDER']).open('a', encoding='ascii') as order:\n"
            "    order.write('tar\\n')\n"
            "destination = Path(args[args.index('-C') + 1])\n"
            "destination.mkdir(parents=True, exist_ok=True)\n"
            "shutil.copyfile(os.environ['FAKE_LYCHEE'], destination / 'lychee')\n"
            "(destination / 'lychee').chmod(0o755)\n",
        )

    def _expected_sha256(self) -> str:
        source = CHECKER.read_text(encoding="utf-8")
        match = re.search(r'LYCHEE_SHA256="([0-9a-f]{64})"', source)
        self.assertIsNotNone(match, "the wrapper must keep a fixed archive digest")
        assert match is not None
        return match.group(1)

    def _invoke(
        self,
        *,
        repository: Path | None = None,
        reported_sha256: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment.update(
            {
                "PATH": f"{self.fake_bin}{os.pathsep}{environment['PATH']}",
                "RUNNER_TEMP": str(self.runner_temp),
                "CALL_ORDER": str(self.call_order),
                "CURL_ARGUMENTS": str(self.curl_arguments),
                "LYCHEE_ARGUMENTS": str(self.lychee_arguments),
                "FAKE_LYCHEE": str(self.fake_lychee),
                "FAKE_SHA256": reported_sha256 or self._expected_sha256(),
                "GITHUB_TOKEN": "test-token-never-log",
            }
        )
        return subprocess.run(
            ["bash", str(CHECKER), str(repository or self.repo)],
            cwd=repository or self.repo,
            env=environment,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
        )

    def test_uses_fixed_download_and_checks_all_tracked_markdown_paths(self) -> None:
        result = self._invoke()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            self.call_order.read_text(encoding="ascii").splitlines(),
            ["curl", "shasum", "tar", "lychee"],
        )

        curl_arguments = self.curl_arguments.read_bytes().split(b"\0")
        self.assertIn(os.fsencode(LYCHEE_URL), curl_arguments)
        self.assertIn(b"--retry", curl_arguments)
        self.assertIn(b"--max-time", curl_arguments)
        self.assertIn(b"--connect-timeout", curl_arguments)

        lychee_arguments = [
            os.fsdecode(value)
            for value in self.lychee_arguments.read_bytes().split(b"\0")
        ]
        fixed_arguments = [
            "--no-progress",
            "--timeout",
            "20",
            "--max-retries",
            "1",
            "--max-concurrency",
            "8",
            "--include-fragments=anchor-only",
            "--root-dir",
            str(self.repo.resolve()),
        ]
        tracked_paths = subprocess.run(
            ["git", "ls-files", "-z", "--", ":(glob)**/*.md"],
            cwd=self.repo,
            check=True,
            stdout=subprocess.PIPE,
        ).stdout.split(b"\0")[:-1]
        expected_files = [str(self.repo.resolve() / os.fsdecode(path)) for path in tracked_paths]
        self.assertEqual(lychee_arguments, fixed_arguments + expected_files)
        self.assertNotIn(str(self.repo / "untracked.md"), lychee_arguments)
        self.assertNotIn("--verbose", lychee_arguments)
        self.assertNotIn("--cache", lychee_arguments)
        self.assertNotIn("test-token-never-log", result.stdout + result.stderr)

    def test_checksum_failure_stops_before_extraction_or_execution(self) -> None:
        result = self._invoke(reported_sha256="0" * 64)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checksum mismatch", result.stderr)
        self.assertEqual(
            self.call_order.read_text(encoding="ascii").splitlines(),
            ["curl", "shasum"],
        )
        self.assertFalse(self.lychee_arguments.exists())

    def test_tracked_markdown_symlink_is_rejected_before_download(self) -> None:
        (self.repo / "linked.md").symlink_to("README.md")
        self._git("add", "linked.md")
        self._git("commit", "--quiet", "-m", "add Markdown symlink")

        result = self._invoke()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("symlink", result.stderr)
        self.assertFalse(self.call_order.exists())

    def test_repository_without_tracked_markdown_is_rejected_before_download(self) -> None:
        empty_repo = self.root / "empty-repo"
        empty_repo.mkdir()
        subprocess.run(["git", "init", "--quiet"], cwd=empty_repo, check=True)
        subprocess.run(
            ["git", "config", "user.name", "Markdown checker test"],
            cwd=empty_repo,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.email", "markdown-checker@example.invalid"],
            cwd=empty_repo,
            check=True,
        )
        (empty_repo / "notes.txt").write_text("plain text\n", encoding="utf-8")
        subprocess.run(["git", "add", "notes.txt"], cwd=empty_repo, check=True)
        subprocess.run(
            ["git", "commit", "--quiet", "-m", "plain text only"],
            cwd=empty_repo,
            check=True,
        )

        result = self._invoke(repository=empty_repo)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no tracked Markdown files", result.stderr)
        self.assertFalse(self.call_order.exists())


if __name__ == "__main__":
    unittest.main()
