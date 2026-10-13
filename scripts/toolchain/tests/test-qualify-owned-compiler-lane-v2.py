#!/usr/bin/env python3
"""Offline process-boundary tests for compiler owner qualification.

The shell wrapper is real. The CLI, native owner reader, native builder, and
GNU checksum observer are controlled fixtures. These tests prove adapter
dispatch and stop conditions only; they do not establish artifact-origin
authentication, compiler behavior, SDK correctness, or release authority.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "qualify-compiler-sdk-lane-v2.sh"
GROUP = "rv32"
PRESET = "release"
HOST = "linux-x86_64"
WORKFLOW = ".github/workflows/qualify.yml"
SOURCE_WORKFLOW = ".github/workflows/native-owner.yml"
SOURCE_REF = "refs/heads/main"
JOB_NAME = "Qualify compiler and SDK"


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


FAKE_AROS = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys


def option(name):
    for index, value in enumerate(sys.argv[1:-1]):
        if value == name:
            return sys.argv[index + 2]
    raise SystemExit("fixture CLI missing " + name)


def record(stage, args):
    entry = {"stage": stage, "args": args}
    with open(os.environ["FAKE_CALL_LOG"], "a", encoding="utf-8") as stream:
        stream.write(json.dumps(entry, separators=(",", ":")) + "\n")


args = sys.argv[1:]
if args[:3] == ["toolchain", "producer", "release-plan"]:
    record("release-plan", args)
    sys.stdout.write(Path(os.environ["FAKE_PLAN_FILE"]).read_text(encoding="utf-8"))
elif args[:3] == ["toolchain", "producer", "compare"]:
    record("compare", args)
    sys.stdout.write('{"fixture":"comparison reached"}\n')
    raise SystemExit(int(os.environ.get("FAKE_COMPARE_EXIT", "77")))
else:
    record("unexpected-aros", args)
    raise SystemExit("fixture CLI received an unexpected invocation")
'''


FAKE_NATIVE_READER = r'''#!/usr/bin/env bash
set -euo pipefail
python3 - "$@" <<'PY'
import json
import os
from pathlib import Path
import sys


def option(name):
    for index, value in enumerate(sys.argv[1:-1]):
        if value == name:
            return sys.argv[index + 2]
    raise SystemExit("fixture reader missing " + name)


args = sys.argv[1:]
copy = option("--copy")
entry = {"stage": "read-" + copy, "args": args}
with open(os.environ["FAKE_CALL_LOG"], "a", encoding="utf-8") as stream:
    stream.write(json.dumps(entry, separators=(",", ":")) + "\n")
if os.environ.get("FAKE_OWNER_FAIL_COPY") == copy:
    raise SystemExit(41)
root = Path(option("--root"))
(root / "payload/package").mkdir(parents=True)
(root / "payload/evidence").mkdir(parents=True)
(root / "payload/package/fixture-package.tar.xz").write_bytes(b"authenticated placeholder\n")
(root / "payload/evidence/environment.json").write_text('{"fixture":"owner environment"}\n', encoding="utf-8")
PY
'''


FAKE_NATIVE_BUILDER = r'''#!/usr/bin/env bash
set -euo pipefail
root=''
while (( $# )); do
    if [[ "$1" == --root ]]; then root=$2; shift 2; else shift 2; fi
done
[[ -n "$root" ]]
python3 - "$root" <<'PY'
import json
import os
from pathlib import Path
import sys

root = Path(sys.argv[1])
for relative in ("payload/package", "payload/evidence", "work/native-lifecycle/build/gcc/gcc"):
    (root / relative).mkdir(parents=True, exist_ok=True)
(root / "payload/package/fixture-package.tar.xz").write_bytes(b"built placeholder\n")
(root / "payload/evidence/environment.json").write_text('{"fixture":"build environment"}\n', encoding="utf-8")
(root / "work/native-lifecycle/build/gcc/gcc/Makefile").write_text("# fixture\n", encoding="utf-8")
entry = {"stage": "build", "root": str(root)}
with open(os.environ["FAKE_CALL_LOG"], "a", encoding="utf-8") as stream:
    stream.write(json.dumps(entry, separators=(",", ":")) + "\n")
PY
'''


FAKE_GCC_OBSERVER = r'''import json
import os
from pathlib import Path
import sys

args = sys.argv[1:]
output = Path(args[args.index("--output") + 1])
entry = {"stage": "observe-gcc", "args": args}
with open(os.environ["FAKE_CALL_LOG"], "a", encoding="utf-8") as stream:
    stream.write(json.dumps(entry, separators=(",", ":")) + "\n")
output.write_text('{"fixture":"GNU inputs observed"}\n', encoding="utf-8")
'''


FAKE_GIT = "#!/bin/sh\nprintf '0123456789ab\\n'\n"


class QualifyOwnedCompilerLaneTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not shutil.which("jq") or not shutil.which("shasum"):
            raise RuntimeError("qualification contract tests require jq and shasum")
        if not Path("/bin/bash").is_file():
            raise RuntimeError("qualification contract tests require Bash")

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="qualify-owned-compiler-v2.")
        self.base = Path(self.temporary.name).resolve()
        self.call_log = self.base / "calls.jsonl"
        self.fake_bin = self.base / "bin"
        self.fake_bin.mkdir()
        self._write_executable(self.fake_bin / "git", FAKE_GIT)

        wrapper_dir = self.base / "scripts/toolchain"
        wrapper_dir.mkdir(parents=True)
        self.script = wrapper_dir / SCRIPT.name
        shutil.copy2(SCRIPT, self.script)

        self.runtime = self.base / "aros-fixture"
        self._write_executable(self.runtime, FAKE_AROS)
        self.inputs = self._directory("inputs")
        self.source = self._directory("source")
        self.producer = self._directory("producer")
        self.tools = self._directory("tools")
        self.cache = self._directory("cache")
        self.upstream = self._directory("upstream")
        self.operations = self._directory("operations")
        self.root = self.operations / "qualification"

        self._file(self.inputs / "toolchain-release-inputs-v2.json", b'{"fixture":"inputs"}\n')
        self.recipe = self._file(self.inputs / "recipe.json", b'{"fixture":"recipe"}\n')
        self.lock = self._file(self.inputs / "source-lock.json", b'{"family":"gnu"}\n')
        self.profiles = self._file(self.inputs / "profiles.json", b'{"fixture":"profiles"}\n')
        self.selection = self._file(
            self.base / "selection.json",
            b'{"groups":[{"id":"rv32","ports_lock":"toolchains/compatibility-ports-v3.json"}]}\n',
        )
        self.owner_a = self._file(self.base / "owner-a-selection.json", b'{"owner":"a"}\n')
        self.owner_b = self._file(self.base / "owner-b-selection.json", b'{"owner":"b"}\n')

        plan = {
            "groups": [
                {
                    "group_id": GROUP,
                    "recipe": {"file": "recipe.json"},
                    "source_lock": {"file": "source-lock.json"},
                    "profiles": {"file": "profiles.json"},
                }
            ],
            "lanes": [{"group_id": GROUP, "target_profile": PRESET, "host": HOST}],
            "sdks": [],
        }
        self.plan_file = self._file(
            self.base / "release-plan.json",
            (json.dumps(plan, separators=(",", ":")) + "\n").encode(),
        )
        ports = self.producer / "toolchains/compatibility-ports-v3.json"
        ports.parent.mkdir(parents=True)
        self._file(ports, b'{"fixture":"ports"}\n')

        toolchain_dir = self.producer / "scripts/toolchain"
        toolchain_dir.mkdir(parents=True)
        self.reader = self._write_executable(toolchain_dir / "read-native-owner-v2.sh", FAKE_NATIVE_READER)
        self.builder = self._write_executable(toolchain_dir / "build-lane-v2.sh", FAKE_NATIVE_BUILDER)
        self.observer = self._file(toolchain_dir / "observe-gcc-checksum-inputs.py", FAKE_GCC_OBSERVER.encode())

        self.env = os.environ.copy()
        self.env["PATH"] = str(self.fake_bin) + os.pathsep + self.env.get("PATH", "")
        self.env["FAKE_CALL_LOG"] = str(self.call_log)
        self.env["FAKE_PLAN_FILE"] = str(self.plan_file)
        self.env["FAKE_COMPARE_EXIT"] = "77"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _directory(self, relative: str) -> Path:
        path = self.base / relative
        path.mkdir(parents=True)
        return path

    def _file(self, path: Path, raw: bytes) -> Path:
        path.write_bytes(raw)
        return path

    def _write_executable(self, path: Path, content: str) -> Path:
        path.write_text(content, encoding="utf-8")
        path.chmod(0o755)
        return path

    def _base_args(self) -> list[str]:
        return [
            "--aros", str(self.runtime),
            "--runtime-sha256", sha256(FAKE_AROS.encode()),
            "--inputs-dir", str(self.inputs),
            "--selection", str(self.selection),
            "--source-dir", str(self.source),
            "--producer-dir", str(self.producer),
            "--tools-dir", str(self.tools),
            "--cache-dir", str(self.cache),
            "--upstream-source-dir", str(self.upstream),
            "--group", GROUP,
            "--preset", PRESET,
            "--host", HOST,
            "--root", str(self.root),
            "--jobs", "2",
            "--timeout-seconds", "30",
        ]

    def _owner_args(self) -> list[str]:
        return [
            "--owner-a-selection", str(self.owner_a),
            "--owner-b-selection", str(self.owner_b),
            "--source-workflow", SOURCE_WORKFLOW,
            "--source-ref", SOURCE_REF,
            "--workflow", WORKFLOW,
            "--job-name", JOB_NAME,
        ]

    def _run(self, extra: list[str], *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["/bin/bash", str(self.script), *self._base_args(), *extra],
            capture_output=True,
            text=True,
            check=False,
            env=env or self.env,
        )

    def _events(self) -> list[dict[str, object]]:
        if not self.call_log.exists():
            return []
        return [json.loads(line) for line in self.call_log.read_text(encoding="utf-8").splitlines()]

    def test_authenticated_owner_reads_precede_comparison_and_skip_builds(self) -> None:
        result = self._run(self._owner_args() + ["--same-attempt"])
        self.assertEqual(result.returncode, 77, result.stderr)
        events = self._events()
        stages = [event["stage"] for event in events]
        self.assertEqual(stages, ["release-plan", "read-a", "read-b", "compare"])
        self.assertNotIn("build", stages)
        self.assertNotIn("observe-gcc", stages)
        reads = [event for event in events if str(event["stage"]).startswith("read-")]
        self.assertIn(str(self.owner_a), reads[0]["args"])
        self.assertIn(str(self.owner_b), reads[1]["args"])
        self.assertIn("--same-attempt", reads[0]["args"])
        self.assertIn("--same-attempt", reads[1]["args"])
        for read, owner_selection, copy in zip(reads, (self.owner_a, self.owner_b), ("a", "b")):
            args = read["args"]
            values = {args[index]: args[index + 1] for index in range(len(args) - 1) if args[index].startswith("--")}
            self.assertEqual(values["--recipe"], str(self.recipe))
            self.assertEqual(values["--recipe-file-sha256"], sha256(self.recipe.read_bytes()))
            self.assertEqual(values["--source-lock"], str(self.lock))
            self.assertEqual(values["--source-lock-sha256"], sha256(self.lock.read_bytes()))
            self.assertEqual(values["--profiles"], str(self.profiles))
            self.assertEqual(values["--profiles-sha256"], sha256(self.profiles.read_bytes()))
            self.assertEqual(values["--source-selection"], str(owner_selection))
            self.assertEqual(values["--source-selection-sha256"], sha256(owner_selection.read_bytes()))
            self.assertEqual(values["--workflow"], WORKFLOW)
            self.assertEqual(values["--job-name"], JOB_NAME)
            self.assertEqual(values["--source-workflow"], SOURCE_WORKFLOW)
            self.assertEqual(values["--source-ref"], SOURCE_REF)
            self.assertEqual(values["--group"], GROUP)
            self.assertEqual(values["--preset"], PRESET)
            self.assertEqual(values["--host"], HOST)
            self.assertEqual(values["--copy"], copy)
            self.assertEqual(values["--release-id"], "toolchain-dev-0123456789ab")
            self.assertEqual(values["--root"], str(self.root / f"compiler-{copy}"))
            self.assertEqual(values["--forbidden-prefix"], str(self.operations))
        compare = events[-1]["args"]
        self.assertEqual(compare[compare.index("--left") + 1], str(self.root / "compiler-a/payload/package"))
        self.assertEqual(compare[compare.index("--right") + 1], str(self.root / "compiler-b/payload/package"))

    def _assert_owner_authentication_failure(self, failed_copy: str, expected_reads: list[str]) -> None:
        env = self.env.copy()
        env["FAKE_OWNER_FAIL_COPY"] = failed_copy
        result = self._run(self._owner_args(), env=env)
        self.assertEqual(result.returncode, 41, result.stderr)
        stages = [event["stage"] for event in self._events()]
        self.assertEqual(stages, ["release-plan", *expected_reads])
        self.assertNotIn("compare", stages)
        self.assertNotIn("build", stages)
        self.assertNotIn("observe-gcc", stages)
        self.assertFalse(any(stage == "sdk-build" for stage in stages))

    def test_owner_a_authentication_failure_never_compares_or_rebuilds(self) -> None:
        self._assert_owner_authentication_failure("a", ["read-a"])

    def test_owner_b_authentication_failure_never_compares_or_rebuilds(self) -> None:
        self._assert_owner_authentication_failure("b", ["read-a", "read-b"])

    def test_partial_owner_context_is_rejected_before_root_or_runtime_calls(self) -> None:
        result = self._run(["--owner-a-selection", str(self.owner_a)])
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("compiler owner selectors must be supplied together", result.stderr)
        self.assertFalse(self.root.exists())
        self.assertEqual(self._events(), [])

    def test_noncanonical_or_linked_owner_selection_is_rejected_before_runtime_call(self) -> None:
        linked = self.base / "owner-a-selection-link.json"
        linked.symlink_to(self.owner_a)
        args = self._owner_args()
        args[args.index("--owner-a-selection") + 1] = str(linked)
        result = self._run(args)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("owner selections must be absolute regular nonlinked files", result.stderr)
        self.assertFalse(self.root.exists())
        self.assertEqual(self._events(), [])

    def test_unselected_owner_mode_keeps_two_cold_builds_and_gnu_observers(self) -> None:
        result = self._run([])
        self.assertEqual(result.returncode, 77, result.stderr)
        stages = [event["stage"] for event in self._events()]
        self.assertEqual(stages, ["release-plan", "build", "observe-gcc", "build", "observe-gcc", "compare"])
        self.assertNotIn("read-a", stages)
        self.assertNotIn("read-b", stages)


if __name__ == "__main__":
    unittest.main()
