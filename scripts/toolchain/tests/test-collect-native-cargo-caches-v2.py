"""CLI counterprobes for the closed native Cargo-cache identity catalog."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts/toolchain/collect-native-cargo-caches-v2.py"
PRODUCER = "a" * 40
TOOLS = "b" * 40
RUN_ID = "123456789"
RUN_ATTEMPT = "2"
RUNNERS = {
    "linux-aarch64": "ubuntu-24.04-arm",
    "linux-x86_64": "ubuntu-24.04",
    "macos-aarch64": "macos-15",
}
SCHEMA = "aros-native-cargo-cache-v1"
ERROR = "native Cargo cache identity catalog rejected; no valid mapping was authorized\n"


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


class CollectNativeCargoCachesCLITests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name).resolve()
        self.identity_dir = self.base / "identity"
        self.identity_dir.mkdir()
        self.github_output = self.base / "github-output"
        self.github_output.write_bytes(b"prior=value\n")
        self._write_identity("linux-x86_64")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _record(self, host: str, **overrides: object) -> dict[str, object]:
        record: dict[str, object] = {
            "schema": SCHEMA,
            "host": host,
            "producer_commit": PRODUCER,
            "tools_commit": TOOLS,
            "run_id": RUN_ID,
            "run_attempt": RUN_ATTEMPT,
            "archive_sha256": ("c" if host == "linux-x86_64" else "d") * 64,
        }
        record.update(overrides)
        return record

    def _host_directory(self, host: str) -> Path:
        return self.identity_dir / f"diagnostic-v2-cargo-identity-{host}"

    def _write_identity(self, folder_host: str, raw: bytes | None = None,
                        **overrides: object) -> Path:
        directory = self._host_directory(folder_host)
        directory.mkdir(exist_ok=True)
        path = directory / f"{folder_host}.json"
        if raw is None:
            record = self._record(folder_host)
            record.update(overrides)
            raw = canonical(record)
        path.write_bytes(raw)
        return path

    def _matrix(self, hosts: list[str]) -> dict[str, object]:
        return {"include": [{"host": host, "runner": RUNNERS[host]} for host in hosts]}

    def _run(self, *, matrix: str | dict[str, object] | None = None,
             output: Path | None = None, producer: str = PRODUCER, tools: str = TOOLS,
             run_id: str = RUN_ID, attempt: str = RUN_ATTEMPT) -> subprocess.CompletedProcess[str]:
        matrix_arg = matrix if isinstance(matrix, str) else json.dumps(
            self._matrix(["linux-x86_64"]) if matrix is None else matrix,
            separators=(",", ":"),
        )
        return subprocess.run(
            [
                sys.executable, "-B", str(SCRIPT),
                "--identity-dir", str(self.identity_dir),
                "--host-matrix", matrix_arg,
                "--producer-commit", producer,
                "--tools-commit", tools,
                "--run-id", run_id,
                "--run-attempt", attempt,
                "--github-output", str(output or self.github_output),
            ],
            capture_output=True, text=True, check=False,
        )

    def _assert_rejected_without_output_change(
        self, *, matrix: str | dict[str, object] | None = None,
        output: Path | None = None, producer: str = PRODUCER, tools: str = TOOLS,
        run_id: str = RUN_ID, attempt: str = RUN_ATTEMPT,
    ) -> subprocess.CompletedProcess[str]:
        selected_output = output or self.github_output
        before = selected_output.read_bytes()
        result = self._run(
            matrix=matrix, output=selected_output, producer=producer, tools=tools,
            run_id=run_id, attempt=attempt,
        )
        self.assertEqual(result.returncode, 2, result)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, ERROR)
        self.assertEqual(selected_output.read_bytes(), before)
        return result

    def test_valid_single_host_catalog_appends_compact_mapping(self) -> None:
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")
        lines = self.github_output.read_text(encoding="ascii").splitlines()
        self.assertEqual(lines[0], "prior=value")
        self.assertEqual(lines[1], f'cache_archives={{"linux-x86_64":"{"c" * 64}"}}')

    def test_valid_three_host_catalog_matches_exact_selected_host_set(self) -> None:
        self._write_identity("linux-aarch64")
        self._write_identity("macos-aarch64")
        result = self._run(matrix=self._matrix(list(RUNNERS)))
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = self.github_output.read_text(encoding="ascii").splitlines()
        self.assertEqual(lines[0], "prior=value")
        self.assertEqual(json.loads(lines[1].removeprefix("cache_archives=")), {
            "linux-aarch64": "d" * 64,
            "linux-x86_64": "c" * 64,
            "macos-aarch64": "d" * 64,
        })

    def test_missing_selected_host_artifact_is_rejected(self) -> None:
        self._assert_rejected_without_output_change(
            matrix=self._matrix(["linux-x86_64", "linux-aarch64"]),
        )

    def test_extra_host_artifact_directory_is_rejected(self) -> None:
        self._write_identity("linux-aarch64")
        self._assert_rejected_without_output_change()

    def test_extra_file_in_selected_host_artifact_is_rejected(self) -> None:
        (self._host_directory("linux-x86_64") / "extra.json").write_bytes(b"{}\n")
        self._assert_rejected_without_output_change()

    def test_extra_root_file_is_rejected(self) -> None:
        (self.identity_dir / "unexpected").write_bytes(b"not an artifact")
        self._assert_rejected_without_output_change()

    def test_duplicate_selected_host_is_rejected(self) -> None:
        matrix = {"include": [
            {"host": "linux-x86_64", "runner": RUNNERS["linux-x86_64"]},
            {"host": "linux-x86_64", "runner": RUNNERS["linux-x86_64"]},
        ]}
        self._assert_rejected_without_output_change(matrix=matrix)

    def test_unknown_host_and_wrong_runner_are_rejected(self) -> None:
        self._assert_rejected_without_output_change(
            matrix={"include": [{"host": "linux-riscv64", "runner": "ubuntu-24.04"}]},
        )
        self._assert_rejected_without_output_change(
            matrix={"include": [{"host": "linux-x86_64", "runner": "ubuntu-latest"}]},
        )

    def test_empty_matrix_and_duplicate_matrix_keys_are_rejected(self) -> None:
        self._assert_rejected_without_output_change(matrix={"include": []})
        self._assert_rejected_without_output_change(matrix='{"include":[],"include":[]}')

    def test_matrix_shape_and_size_are_closed(self) -> None:
        self._assert_rejected_without_output_change(
            matrix={"include": [{"host": "linux-x86_64", "runner": RUNNERS["linux-x86_64"],
                                 "extra": True}]},
        )
        self._assert_rejected_without_output_change(matrix=" " * (64 * 1024 + 1))

    def test_identity_schema_shape_host_and_commits_are_bound(self) -> None:
        bad_records = (
            {"schema": "aros-native-cargo-cache-v2"},
            {"host": "linux-aarch64"},
            {"producer_commit": "e" * 40},
            {"tools_commit": "f" * 40},
            {"extra": "not allowed"},
        )
        for override in bad_records:
            with self.subTest(override=override):
                self._write_identity("linux-x86_64", **override)
                self._assert_rejected_without_output_change()
                self._write_identity("linux-x86_64")

    def test_identity_run_id_and_attempt_are_bound(self) -> None:
        for override in ({"run_id": "123456788"}, {"run_attempt": "3"},
                         {"run_id": 123456789}, {"run_attempt": True}):
            with self.subTest(override=override):
                self._write_identity("linux-x86_64", **override)
                self._assert_rejected_without_output_change()
                self._write_identity("linux-x86_64")

    def test_cli_commit_run_and_attempt_arguments_are_validated(self) -> None:
        for kwargs in (
            {"producer": "A" * 40}, {"tools": "g" * 40},
            {"run_id": "0"}, {"run_id": "01"}, {"attempt": "-1"},
        ):
            with self.subTest(kwargs=kwargs):
                self._assert_rejected_without_output_change(**kwargs)

    def test_malformed_and_duplicate_key_identity_json_are_rejected(self) -> None:
        for raw in (b"{not json}\n", b'{"host":"linux-x86_64","host":"linux-x86_64"}\n'):
            with self.subTest(raw=raw):
                self._write_identity("linux-x86_64", raw=raw)
                self._assert_rejected_without_output_change()
                self._write_identity("linux-x86_64")

    def test_oversized_identity_is_rejected(self) -> None:
        self._write_identity("linux-x86_64", raw=b" " * (16 * 1024 + 1))
        self._assert_rejected_without_output_change()

    def test_symlink_and_hardlinked_identity_files_are_rejected(self) -> None:
        identity = self._host_directory("linux-x86_64") / "linux-x86_64.json"
        target = self.base / "identity-target.json"
        target.write_bytes(identity.read_bytes())
        identity.unlink()
        identity.symlink_to(target)
        self._assert_rejected_without_output_change()
        identity.unlink()
        self._write_identity("linux-x86_64")
        linked_copy = self.base / "hardlinked-identity.json"
        os.link(identity, linked_copy)
        self._assert_rejected_without_output_change()

    def test_invalid_zero_and_malformed_archive_digests_are_rejected(self) -> None:
        for value in ("0" * 64, "not-a-digest", "C" * 64, True):
            with self.subTest(value=value):
                self._write_identity("linux-x86_64", archive_sha256=value)
                self._assert_rejected_without_output_change()
                self._write_identity("linux-x86_64")

    def test_output_symlink_and_hardlink_are_rejected_without_target_change(self) -> None:
        target = self.base / "output-target"
        target.write_bytes(b"untouched\n")
        self.github_output.unlink()
        self.github_output.symlink_to(target)
        result = subprocess.run(
            [sys.executable, "-B", str(SCRIPT),
             "--identity-dir", str(self.identity_dir),
             "--host-matrix", json.dumps(self._matrix(["linux-x86_64"]), separators=(",", ":")),
             "--producer-commit", PRODUCER, "--tools-commit", TOOLS,
             "--run-id", RUN_ID, "--run-attempt", RUN_ATTEMPT,
             "--github-output", str(self.github_output)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stderr, ERROR)
        self.assertEqual(target.read_bytes(), b"untouched\n")

        self.github_output.unlink()
        self.github_output.write_bytes(b"prior=value\n")
        hardlink = self.base / "output-hardlink"
        os.link(self.github_output, hardlink)
        self._assert_rejected_without_output_change()
        self.assertEqual(hardlink.read_bytes(), b"prior=value\n")

    def test_output_without_line_boundary_is_rejected_unchanged(self) -> None:
        self.github_output.write_bytes(b"prior=value")
        self._assert_rejected_without_output_change()


if __name__ == "__main__":
    unittest.main()
