#!/usr/bin/env python3
"""Offline process-boundary tests for authenticated native lane admission.

The wrapper, Bash, jq, shasum, and cmp are real. The colocated origin and
transport helpers plus the ``aros`` executable are fixtures. In particular,
these tests do not verify signatures, provider identity, Rust behavior,
archives, or release qualification.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "admit-lane-v2.sh"
MEASUREMENT = b'{"fixture":"synthetic measurement; not native evidence"}\n'
ENVIRONMENT = b'{"fixture":"selected owning-host environment"}\n'
BUILD_RESULT = b'{"fixture":"build result"}\n'
PACKAGE_ARCHIVE = b"offline package bytes; not a real archive\n"
PRODUCER_COMMIT = "a" * 40
HOST = "linux-aarch64"
PRESET = "release"
GROUP = "rv32"
COPY = "a"
WORKFLOW = ".github/workflows/read-lane.yml"
SOURCE_WORKFLOW = ".github/workflows/build-lane.yml"
SOURCE_REF = "refs/heads/main"


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def available_bashes() -> list[Path]:
    """Return distinct /bin/bash and current (often Homebrew) Bash binaries."""

    found: list[Path] = []
    seen: set[tuple[int, int]] = set()
    for candidate in (Path("/bin/bash"), Path(shutil.which("bash") or "/nonexistent")):
        if not candidate.is_file():
            continue
        try:
            stat = candidate.stat()
            identity = (stat.st_dev, stat.st_ino)
            result = subprocess.run(
                [str(candidate), "--version"], capture_output=True, text=True, check=False
            )
        except OSError:
            continue
        if (identity not in seen and result.returncode == 0 and result.stdout
                and "bash" in result.stdout.splitlines()[0].lower()):
            seen.add(identity)
            found.append(candidate.resolve())
    return found


FAKE_ORIGIN = r'''#!/usr/bin/env python3
import hashlib
import json
import os
from pathlib import Path
import sys


def record(stage, args):
    with open(os.environ["FAKE_STAGE_LOG"], "a", encoding="utf-8") as stream:
        stream.write(json.dumps({"stage": stage, "args": args}, separators=(",", ":")) + "\n")


def option(name):
    for index, value in enumerate(sys.argv[1:]):
        if value == name and index + 2 < len(sys.argv):
            return sys.argv[index + 2]
    raise SystemExit("fixture origin missing " + name)


def no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


args = sys.argv[1:]
record("origin", args)
if not args or args[0] != "verify-source":
    raise SystemExit("fixture origin received a non-verification operation")
if os.environ.get("FAKE_ORIGIN_MODE") == "fail":
    print("fixture authentication failure", file=sys.stderr)
    raise SystemExit(41)

selection_path = Path(option("--source-selection"))
try:
    selection = json.loads(selection_path.read_text(encoding="utf-8"), object_pairs_hook=no_duplicate_keys)
except (OSError, ValueError, json.JSONDecodeError):
    print("fixture rejects malformed or duplicate selection JSON", file=sys.stderr)
    raise SystemExit(42)

retained = Path(option("--verified-output-dir"))
retained.mkdir()
measurement_path = Path(os.environ["FAKE_MEASUREMENT_FILE"])
measurement = measurement_path.read_bytes()
origin_record = {
    "files": {
        "evidence/measurement.json": {
            "sha256": hashlib.sha256(measurement).hexdigest(),
            "size": len(measurement),
        }
    }
}
(retained / "payload.zip").write_bytes(b"fixture payload container; not an archive\n")
(retained / "origin.json").write_text(json.dumps(origin_record, separators=(",", ":")) + "\n", encoding="utf-8")
(retained / "origin.sigstore.json").write_bytes(b"fixture signature bundle; not a signature\n")
(retained / "selection.json").write_bytes(selection_path.read_bytes())

if os.environ.get("FAKE_ORIGIN_MODE") == "change-runtime":
    with open(os.environ["FAKE_RUNTIME_FILE"], "ab") as stream:
        stream.write(b"# changed after fixture authentication\n")
print("fixture authenticated-source placeholder")
'''


FAKE_TRANSPORT = r'''#!/usr/bin/env python3
import hashlib
import json
import os
from pathlib import Path
import sys


def record(stage, args):
    with open(os.environ["FAKE_STAGE_LOG"], "a", encoding="utf-8") as stream:
        stream.write(json.dumps({"stage": stage, "args": args}, separators=(",", ":")) + "\n")


def option(name):
    for index, value in enumerate(sys.argv[1:]):
        if value == name and index + 2 < len(sys.argv):
            return sys.argv[index + 2]
    raise SystemExit("fixture transport missing " + name)


def write_result(directory):
    files = {}
    for path in sorted(directory.rglob("*")):
        if path.is_file():
            raw = path.read_bytes()
            name = path.relative_to(directory).as_posix()
            files[name] = {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}
    result = {
        "schema": "aros-toolchain-native-lane-transport-v2",
        "assurance": "transport-byte-readback-only",
        "files": files,
    }
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")


args = sys.argv[1:]
retained = Path(option("--retained-dir"))
if "--output-dir" in args:
    record("transport-extract", args)
    if os.environ.get("FAKE_TRANSPORT_MODE") == "extraction-failure":
        raise SystemExit(51)
    output = Path(option("--output-dir"))
    package = output / "package"
    evidence = output / "evidence"
    package.mkdir(parents=True)
    evidence.mkdir()
    archive = package / "fixture-toolchain.tar.xz"
    archive.write_bytes(b"offline package bytes; not a real archive\n")
    tree = "a" * 64
    (package / (archive.name + ".manifest.json")).write_text(json.dumps({
        "schema": 2, "host": os.environ["FAKE_HOST"],
        "target_profile": os.environ["FAKE_PRESET"], "tree_sha256": tree,
    }, separators=(",", ":")) + "\n", encoding="utf-8")
    (package / (archive.name + ".sha256")).write_text(hashlib.sha256(archive.read_bytes()).hexdigest() + "  " + archive.name + "\n", encoding="utf-8")
    (package / (archive.name + ".spdx.json")).write_bytes(b'{"fixture":"placeholder SBOM"}\n')
    (evidence / "build-result.json").write_bytes(b'{"fixture":"build result"}\n')
    environment = Path(os.environ["FAKE_ENVIRONMENT_FILE"]).read_bytes()
    if os.environ.get("FAKE_TRANSPORT_MODE") == "environment-mismatch":
        environment = b'{"fixture":"different environment"}\n'
    (evidence / "environment.json").write_bytes(environment)
    (evidence / "environment-result.json").write_bytes(b'{"fixture":"environment result"}\n')
    (evidence / "measurement.json").write_bytes(Path(os.environ["FAKE_MEASUREMENT_FILE"]).read_bytes())
    (evidence / "package-result.json").write_bytes(b'{"fixture":"package result"}\n')
    (evidence / "package-verify.json").write_bytes(b'{"fixture":"package verification"}\n')
    write_result(output)
elif "--verify-output-dir" in args:
    record("transport-readback", args)
    output = Path(option("--verify-output-dir"))
    # This operation is modeled as a read-only measurement of the output tree.
    write_result(output)
else:
    raise SystemExit("fixture transport received an unexpected operation")
'''


FAKE_AROS = r'''#!/usr/bin/env python3
import hashlib
import json
import os
from pathlib import Path
import sys


def record(args):
    with open(os.environ["FAKE_STAGE_LOG"], "a", encoding="utf-8") as stream:
        stream.write(json.dumps({"stage": "native", "args": args}, separators=(",", ":")) + "\n")


def option(name):
    for index, value in enumerate(sys.argv[1:]):
        if value == name and index + 2 < len(sys.argv):
            return sys.argv[index + 2]
        if value.startswith(name + "="):
            return value.split("=", 1)[1]
    raise SystemExit("fixture native CLI missing " + name)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


args = sys.argv[1:]
record(args)
if args[:3] != ["toolchain", "producer", "verify-package"]:
    raise SystemExit("fixture native CLI received an unexpected operation")
mode = os.environ.get("FAKE_AROS_MODE", "success")
if mode == "fail":
    raise SystemExit(61)

tree = "a" * 64
package = Path(option("--input-dir"))
archive = package / "fixture-toolchain.tar.xz"
build_result = package.parent / "evidence" / "build-result.json"
manifest = {
    "schema": 2,
    "host": "linux-x86_64" if mode == "host-mismatch" else option("--host"),
    "target_profile": "wrong-profile" if mode == "profile-mismatch" else option("--preset"),
    "tree_sha256": tree,
}
candidate = {
    "schema": "aros-toolchain-portable-package-readback-v2",
    "assurance": "portable-byte-readback-only",
    "measurement_sha256": "0" * 64 if mode == "measurement-mismatch" else option("--package-measurement-sha256"),
    "build_result_sha256": "0" * 64 if mode == "build-result-mismatch" else digest(build_result),
    "package_tree_sha256": "b" * 64 if mode == "tree-mismatch" else tree,
}
if mode == "ignore-portable-readback":
    candidate = None
elif mode == "readback-schema-mismatch":
    candidate["schema"] = "aros-toolchain-portable-package-readback-v1"
elif mode == "readback-assurance-mismatch":
    candidate["assurance"] = "metadata-only"

response = {
    "schema": "wrong-schema" if mode == "schema-mismatch" else "aros-toolchain-producer-stage-v1",
    "operation": "verify-package",
    "manifest": manifest,
    "finished_candidate": candidate,
    "sha256": "0" * 64 if mode == "archive-hash-mismatch" else digest(archive),
    "size": archive.stat().st_size + 1 if mode == "archive-size-mismatch" else archive.stat().st_size,
}
if mode == "invalid-then-valid":
    sys.stdout.write('{"schema":"unvalidated-first-response"}\n')
if mode != "empty-output":
    value = [response] if mode == "array-output" else response
    sys.stdout.write(json.dumps(value, separators=(",", ":")) + "\n")
if mode == "valid-then-valid":
    sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
elif mode == "valid-then-invalid":
    sys.stdout.write('{"schema":"invalid-final-response"}\n')
sys.stdout.flush()
if mode == "change-runtime":
    with open(os.environ["FAKE_RUNTIME_FILE"], "ab") as stream:
        stream.write(b"# changed during native verification\n")
elif mode == "change-recipe":
    with open(os.environ["FAKE_RECIPE_FILE"], "ab") as stream:
        stream.write(b"\n")
elif mode == "change-payload":
    archive = Path(option("--input-dir")) / "fixture-toolchain.tar.xz"
    archive.write_bytes(archive.read_bytes() + b"changed during native verification\n")
'''


class AdmitLaneV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        missing = [name for name in ("jq", "shasum", "cmp", "python3") if not shutil.which(name)]
        if missing:
            raise RuntimeError("admit-lane-v2 tests require: " + ", ".join(missing))
        cls.bashes = available_bashes()
        if not cls.bashes:
            raise RuntimeError("admit-lane-v2 tests require Bash")

    def setUp(self) -> None:
        self._create_fixture()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _fresh_fixture(self) -> None:
        self.temporary.cleanup()
        self._create_fixture()

    def _create_fixture(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="admit-lane-v2.")
        # Resolve macOS /var aliases so every path passed to the shell is canonical.
        self.base = Path(self.temporary.name).resolve()
        self.script_dir = self.base / "scripts" / "toolchain"
        self.script_dir.mkdir(parents=True)
        shutil.copy2(SCRIPT, self.script_dir / "admit-lane-v2.sh")
        self._script("artifact-origin.py", FAKE_ORIGIN)
        self._script("native-lane-transport.py", FAKE_TRANSPORT)
        self.runtime = self._script("aros-fixture", FAKE_AROS)
        self.inputs = self.base / "inputs"
        self.inputs.mkdir()
        self.recipe = self._file("recipe.json", canonical_json({
            "schema": "aros-toolchain-recipe-v2", "producer_commit": PRODUCER_COMMIT,
        }))
        self.source_lock = self._file("source-lock.json", b'{"fixture":"source lock"}\n')
        self.profiles = self._file("profiles.json", b'{"fixture":"profiles"}\n')
        self.environment = self._file("environment.json", ENVIRONMENT)
        self.measurement = self._file("measurement.json", MEASUREMENT)
        self.selection = self._file("selection.json", canonical_json(self._selection()))
        self.operations = self.base / "operations"
        self.operations.mkdir()
        self.root = self.operations / "admission"
        self.stage_log = self.base / "stage-log.jsonl"
        self.forbidden = [str(self.base / "forbidden-cache"), str(self.base / "forbidden-tools")]

    def _script(self, name: str, source: str) -> Path:
        path = self.script_dir / name
        path.write_text(textwrap.dedent(source), encoding="utf-8")
        path.chmod(0o755)
        return path

    def _file(self, name: str, raw: bytes) -> Path:
        path = self.inputs / name
        path.write_bytes(raw)
        return path

    @staticmethod
    def _selection() -> dict:
        return {
            "schema": "aros-toolchain-artifact-selection-v1",
            "context": {
                "workflow": SOURCE_WORKFLOW,
                "source_ref": SOURCE_REF,
                "producer_commit": PRODUCER_COMMIT,
            },
            "selection": {
                "role": "build", "group": GROUP, "host": HOST,
                "profile": PRESET, "copy": COPY,
            },
        }

    def _args(self) -> list[str]:
        return [
            "--aros", str(self.runtime), "--aros-sha256", sha256(self.runtime.read_bytes()),
            "--recipe", str(self.recipe), "--recipe-file-sha256", sha256(self.recipe.read_bytes()),
            "--source-lock", str(self.source_lock), "--source-lock-sha256", sha256(self.source_lock.read_bytes()),
            "--profiles", str(self.profiles), "--profiles-sha256", sha256(self.profiles.read_bytes()),
            "--build-environment", str(self.environment), "--build-environment-sha256", sha256(self.environment.read_bytes()),
            "--source-selection", str(self.selection), "--source-selection-sha256", sha256(self.selection.read_bytes()),
            "--workflow", WORKFLOW, "--job-name", "Read native lane artifact",
            "--source-workflow", SOURCE_WORKFLOW, "--source-ref", SOURCE_REF,
            "--group", GROUP, "--preset", PRESET, "--host", HOST, "--copy", COPY,
            "--release-id", "r2026.10",
            "--executor-contract-sha256", "1" * 64,
            "--executor-binary-sha256", "2" * 64,
            "--forbidden-prefix", self.forbidden[0],
            "--forbidden-prefix", self.forbidden[1],
            "--root", str(self.root),
        ]

    def _env(self, *, origin: str = "success", transport: str = "success",
             aros: str = "success") -> dict[str, str]:
        return os.environ | {
            "FAKE_STAGE_LOG": str(self.stage_log),
            "FAKE_ORIGIN_MODE": origin,
            "FAKE_TRANSPORT_MODE": transport,
            "FAKE_AROS_MODE": aros,
            "FAKE_RUNTIME_FILE": str(self.runtime),
            "FAKE_RECIPE_FILE": str(self.recipe),
            "FAKE_MEASUREMENT_FILE": str(self.measurement),
            "FAKE_ENVIRONMENT_FILE": str(self.environment),
            "FAKE_HOST": HOST,
            "FAKE_PRESET": PRESET,
        }

    def _run(self, bash: Path, args: list[str] | None = None, **modes: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(bash), str(self.script_dir / "admit-lane-v2.sh"), *(args if args is not None else self._args())],
            capture_output=True, text=True, check=False, timeout=20,
            env=self._env(**modes),
        )

    def _events(self) -> list[dict]:
        if not self.stage_log.exists():
            return []
        return [json.loads(line) for line in self.stage_log.read_text(encoding="utf-8").splitlines()]

    def _assert_rejected(self, result: subprocess.CompletedProcess[str]) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.root / "admission.json").exists())

    def _native_expected_args(self) -> list[str]:
        payload = self.root / "payload"
        return [
            "toolchain", "producer", "verify-package",
            "--recipe", str(self.recipe),
            "--source-lock", str(self.source_lock),
            "--profiles", str(self.profiles),
            "--preset=release", "--host", HOST, "--release-id", "r2026.10",
            "--build-environment", str(self.environment), "--package-format", "family-v2",
            "--input-dir", str(payload / "package"),
            "--package-measurement", str(payload / "evidence" / "measurement.json"),
            "--package-measurement-sha256", sha256(MEASUREMENT),
            "--executor-contract-sha256", "1" * 64,
            "--executor-binary-sha256", "2" * 64,
            "--forbidden-prefix", self.forbidden[0],
            "--forbidden-prefix", self.forbidden[1],
            "--format", "json",
        ]

    def test_success_has_authenticated_order_exact_selectors_and_readback(self) -> None:
        for bash in self.bashes:
            with self.subTest(bash=str(bash)):
                if bash != self.bashes[0]:
                    self._fresh_fixture()
                args = self._args() + ["--same-attempt"]
                result = self._run(bash, args)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertTrue((self.root / "admission.json").is_file())
                events = self._events()
                self.assertEqual([event["stage"] for event in events], [
                    "origin", "transport-extract", "native", "transport-readback",
                ])
                self.assertEqual(events[0]["args"], [
                    "verify-source", "--workflow", WORKFLOW,
                    "--job-name", "Read native lane artifact",
                    "--source-selection", str(self.selection),
                    "--verified-output-dir", str(self.root / "transport"),
                    "--same-attempt",
                ])
                self.assertEqual(events[1]["args"], [
                    "--retained-dir", str(self.root / "transport"),
                    "--output-dir", str(self.root / "payload"),
                ])
                self.assertEqual(events[2]["args"], self._native_expected_args())
                self.assertEqual(events[3]["args"], [
                    "--retained-dir", str(self.root / "transport"),
                    "--verify-output-dir", str(self.root / "payload"),
                ])
                admission = json.loads((self.root / "admission.json").read_text(encoding="utf-8"))
                self.assertEqual(admission["schema"], "aros-toolchain-native-lane-admission-v2")
                self.assertEqual(admission["assurance"], "authenticated-transport-and-native-byte-readback-only")
                self.assertEqual(admission["group"], GROUP)
                self.assertEqual(admission["host"], HOST)
                self.assertEqual(admission["target_profile"], PRESET)
                self.assertEqual(admission["copy"], COPY)
                self.assertEqual(admission["reader_runtime_sha256"], sha256(self.runtime.read_bytes()))
                self.assertEqual(admission["recipe_file_sha256"], sha256(self.recipe.read_bytes()))
                self.assertEqual(admission["source_selection_sha256"], sha256(self.selection.read_bytes()))
                self.assertEqual(admission["executor_contract_sha256"], "1" * 64)
                self.assertEqual(admission["executor_binary_sha256"], "2" * 64)
                self.assertNotEqual(admission["reader_runtime_sha256"], admission["executor_binary_sha256"])
                self.assertEqual(admission["native"]["finished_candidate"]["build_result_sha256"], sha256(BUILD_RESULT))
                self.assertEqual(admission["native"]["sha256"], sha256(PACKAGE_ARCHIVE))
                self.assertEqual(admission["native"]["size"], len(PACKAGE_ARCHIVE))
                self.assertEqual(admission["transport"]["assurance"], "transport-byte-readback-only")
                self.assertEqual(admission["native"]["finished_candidate"]["assurance"], "portable-byte-readback-only")
                self.assertFalse(any(token in " ".join(event["args"]).lower()
                                     for event in events for token in ("upload", "resign", "publish")))

    def test_same_attempt_is_optional(self) -> None:
        for bash in self.bashes:
            with self.subTest(bash=str(bash)):
                if bash != self.bashes[0]:
                    self._fresh_fixture()
                result = self._run(bash)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertNotIn("--same-attempt", self._events()[0]["args"])

    def test_independent_selection_joins_fail_before_authentication(self) -> None:
        probes = {
            "host": lambda doc: doc["selection"].__setitem__("host", "linux-x86_64"),
            "group": lambda doc: doc["selection"].__setitem__("group", "rv64"),
            "copy": lambda doc: doc["selection"].__setitem__("copy", "b"),
            "producer": lambda doc: doc["context"].__setitem__("producer_commit", "b" * 40),
            "workflow": lambda doc: doc["context"].__setitem__("workflow", ".github/workflows/other.yml"),
            "ref": lambda doc: doc["context"].__setitem__("source_ref", "refs/heads/other"),
        }
        for bash in self.bashes:
            for name, mutate in probes.items():
                with self.subTest(bash=str(bash), selector=name):
                    self._fresh_fixture()
                    document = self._selection()
                    mutate(document)
                    self.selection.write_bytes(canonical_json(document))
                    args = self._args()
                    result = self._run(bash, args)
                    self._assert_rejected(result)
                    self.assertEqual(self._events(), [], result.stderr)

    def test_malformed_missing_and_duplicate_selectors_are_rejected(self) -> None:
        for bash in self.bashes:
            probes = ("malformed-json", "missing-lane-copy", "duplicate-lane-host",
                      "duplicate-cli-host", "missing-cli-copy", "missing-forbidden-prefix")
            for probe in probes:
                with self.subTest(bash=str(bash), probe=probe):
                    self._fresh_fixture()
                    args = self._args()
                    if probe == "malformed-json":
                        self.selection.write_bytes(b'{"schema":\n')
                        args = self._args()
                    elif probe == "missing-lane-copy":
                        document = self._selection()
                        del document["selection"]["copy"]
                        self.selection.write_bytes(canonical_json(document))
                        args = self._args()
                    elif probe == "duplicate-lane-host":
                        # jq reads the last occurrence; the strict origin fixture
                        # must still reject this closed-JSON violation.
                        raw = (
                            '{"schema":"aros-toolchain-artifact-selection-v1",'
                            '"context":{"workflow":"' + SOURCE_WORKFLOW + '","source_ref":"' + SOURCE_REF
                            + '","producer_commit":"' + PRODUCER_COMMIT + '"},'
                            '"selection":{"role":"build","group":"rv32","host":"linux-x86_64",'
                            '"host":"' + HOST + '","profile":"release","copy":"a"}}\n'
                        ).encode()
                        self.selection.write_bytes(raw)
                        args = self._args()
                    elif probe == "duplicate-cli-host":
                        args += ["--host", HOST]
                    elif probe == "missing-cli-copy":
                        position = args.index("--copy")
                        del args[position:position + 2]
                    elif probe == "missing-forbidden-prefix":
                        position = args.index("--forbidden-prefix")
                        del args[position:position + 4]
                    result = self._run(bash, args)
                    self._assert_rejected(result)
                    events = self._events()
                    if probe == "duplicate-lane-host":
                        self.assertEqual([item["stage"] for item in events], ["origin"])
                    else:
                        self.assertEqual(events, [], result.stderr)

    def test_initial_hash_mismatch_and_authentication_failure_stop_pipeline(self) -> None:
        for bash in self.bashes:
            with self.subTest(bash=str(bash), case="hash-mismatch"):
                self._fresh_fixture()
                args = self._args()
                args[args.index("--aros-sha256") + 1] = "0" * 64
                result = self._run(bash, args)
                self._assert_rejected(result)
                self.assertEqual(self._events(), [])
            with self.subTest(bash=str(bash), case="authentication-failure"):
                self._fresh_fixture()
                result = self._run(bash, origin="fail")
                self._assert_rejected(result)
                self.assertEqual([event["stage"] for event in self._events()], ["origin"])

    def test_authentication_time_input_change_stops_before_extraction(self) -> None:
        for bash in self.bashes:
            with self.subTest(bash=str(bash)):
                self._fresh_fixture()
                result = self._run(bash, origin="change-runtime")
                self._assert_rejected(result)
                self.assertEqual([event["stage"] for event in self._events()], ["origin"])

    def test_extraction_failure_environment_mismatch_and_native_failure_stop_admission(self) -> None:
        cases = (
            ("extraction", {"transport": "extraction-failure"}, ["origin", "transport-extract"]),
            ("environment", {"transport": "environment-mismatch"}, ["origin", "transport-extract"]),
            ("native", {"aros": "fail"}, ["origin", "transport-extract", "native"]),
        )
        for bash in self.bashes:
            for name, modes, expected in cases:
                with self.subTest(bash=str(bash), case=name):
                    self._fresh_fixture()
                    result = self._run(bash, **modes)
                    self._assert_rejected(result)
                    self.assertEqual([event["stage"] for event in self._events()], expected)

    def test_native_response_must_prove_portable_measurement_tree_and_selectors(self) -> None:
        modes = (
            "ignore-portable-readback", "schema-mismatch", "readback-schema-mismatch",
            "readback-assurance-mismatch", "measurement-mismatch", "build-result-mismatch",
            "archive-hash-mismatch", "archive-size-mismatch", "tree-mismatch",
            "host-mismatch", "profile-mismatch",
        )
        for bash in self.bashes:
            for mode in modes:
                with self.subTest(bash=str(bash), native_response=mode):
                    self._fresh_fixture()
                    result = self._run(bash, aros=mode)
                    self._assert_rejected(result)
                    self.assertEqual([event["stage"] for event in self._events()], [
                        "origin", "transport-extract", "native",
                    ])
                    self.assertEqual(result.stderr, "V2 lane admission: native portable verification result differs\n")

    def test_native_response_is_exactly_one_validated_object(self) -> None:
        for bash in self.bashes:
            for mode in ("invalid-then-valid", "valid-then-valid", "valid-then-invalid",
                         "empty-output", "array-output"):
                with self.subTest(bash=str(bash), native_response=mode):
                    self._fresh_fixture()
                    result = self._run(bash, aros=mode)
                    self._assert_rejected(result)
                    self.assertEqual([event["stage"] for event in self._events()], [
                        "origin", "transport-extract", "native",
                    ])
                    self.assertIn("native portable verification result differs", result.stderr)

    def test_final_transport_and_selected_input_mutations_prevent_admission(self) -> None:
        cases = (
            ("transport-output", {"aros": "change-payload"},
             ["origin", "transport-extract", "native", "transport-readback"]),
            ("runtime", {"aros": "change-runtime"},
             ["origin", "transport-extract", "native", "transport-readback"]),
            ("recipe", {"aros": "change-recipe"},
             ["origin", "transport-extract", "native", "transport-readback"]),
        )
        for bash in self.bashes:
            for name, modes, expected in cases:
                with self.subTest(bash=str(bash), mutation=name):
                    self._fresh_fixture()
                    result = self._run(bash, **modes)
                    self._assert_rejected(result)
                    self.assertEqual([event["stage"] for event in self._events()], expected)

    def test_existing_operation_root_and_retained_auth_are_never_reused(self) -> None:
        for bash in self.bashes:
            with self.subTest(bash=str(bash)):
                self._fresh_fixture()
                self.root.mkdir()
                retained = self.root / "transport"
                retained.mkdir()
                sentinel = retained / "sentinel"
                sentinel.write_bytes(b"pre-existing retained data\n")
                result = self._run(bash)
                self._assert_rejected(result)
                self.assertEqual(sentinel.read_bytes(), b"pre-existing retained data\n")
                self.assertEqual(self._events(), [])


if __name__ == "__main__":
    unittest.main()
