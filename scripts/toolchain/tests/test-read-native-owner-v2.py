#!/usr/bin/env python3
"""Process-boundary tests for the authenticated original native owner reader.

The wrapper and Bash, jq, shasum, cmp, and Python are real. The provider,
transport helper, and native CLI are synthetic subprocess fixtures. These
tests do not establish real provider identity, signatures, Rust behavior,
compiler execution, archives, release admission, or publication.
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


SCRIPT = Path(__file__).resolve().parents[1] / "read-native-owner-v2.sh"
PRODUCER_COMMIT = "a" * 40
SOURCE_COMMIT = "b" * 40
TOOLS_COMMIT = "c" * 40
WORKFLOW = ".github/workflows/read-native-owner.yml"
SOURCE_WORKFLOW = ".github/workflows/build-native.yml"
SOURCE_REF = "refs/heads/main"
GROUP = "rv32"
PRESET = "rv32-esp32p4"
HOST = "linux-aarch64"
COPY = "a"
RELEASE_ID = "r2026.10"
CONTRACT_ID = "aros-toolchain-producer-v1"
CONTRACT_SHA = "1" * 64
EXECUTOR_SHA = "2" * 64
MEASUREMENT = b'{"executor_binary_sha256":"' + b"f" * 64 + b'","fixture":"not an expectation source"}\n'
ENVIRONMENT = b'{"fixture":"signed original owning-host environment"}\n'
ARCHIVE = b"synthetic package bytes; not a real archive\n"


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def recipe_document(source_lock_sha: str, profiles_sha: str) -> dict:
    record = {
        "schema": "aros-toolchain-recipe-v2",
        "source_commit": SOURCE_COMMIT,
        "source_tree": SOURCE_COMMIT,
        "producer_commit": PRODUCER_COMMIT,
        "producer_tree": PRODUCER_COMMIT,
        "tools_commit": TOOLS_COMMIT,
        "tools_tree": TOOLS_COMMIT,
        "source_date_epoch": 100,
        "source_lock_sha256": source_lock_sha,
        "profiles_sha256": profiles_sha,
        "patches": [],
    }
    record["recipe_sha256"] = sha256(canonical_json(record))
    return record


def selection_document(*, host: str = HOST, preset: str = PRESET,
                       copy: str = COPY, producer: str = PRODUCER_COMMIT,
                       workflow: str = SOURCE_WORKFLOW, ref: str = SOURCE_REF) -> dict:
    return {
        "schema": "aros-toolchain-artifact-selection-v1",
        "context": {
            "repository": "example/aros",
            "repository_id": 123,
            "producer_commit": producer,
            "source_ref": ref,
            "workflow": workflow,
            "run_id": 456,
            "run_attempt": 1,
        },
        "selection": {"role": "build", "group": GROUP, "host": host,
                      "profile": preset, "copy": copy},
        "job": {"id": 12, "name": "original compiler owner"},
        "artifact": {"id": 34, "name": "native-build", "sha256": "3" * 64,
                     "size_in_bytes": 100},
        "proof": {"id": 35, "name": "native-proof", "sha256": "4" * 64,
                   "size_in_bytes": 50},
    }


def build_result(recipe: dict, *, host: str = HOST, preset: str = PRESET,
                 mutation: str = "") -> dict:
    identity = {
        "recipe_sha256": recipe["recipe_sha256"],
        "source_commit": recipe["source_commit"],
        "producer_commit": recipe["producer_commit"],
        "tools_commit": recipe["tools_commit"],
        "host": host,
        "target_profile": preset,
        "executor": {
            "contract_id": CONTRACT_ID,
            "contract_sha256": CONTRACT_SHA,
            "tools_commit": recipe["tools_commit"],
            "binary_sha256": EXECUTOR_SHA,
            "origin_evidence_sha256": None,
        },
    }
    if mutation == "source-mismatch":
        identity["source_commit"] = "d" * 40
    elif mutation == "producer-mismatch":
        identity["producer_commit"] = "d" * 40
    elif mutation == "tools-mismatch":
        identity["tools_commit"] = "d" * 40
    elif mutation == "recipe-mismatch":
        identity["recipe_sha256"] = "d" * 64
    elif mutation == "host-mismatch":
        identity["host"] = "linux-x86_64"
    elif mutation == "profile-mismatch":
        identity["target_profile"] = "other-profile"
    elif mutation == "executor-tools-mismatch":
        identity["executor"]["tools_commit"] = "d" * 40
    elif mutation == "executor-origin-claimed":
        identity["executor"]["origin_evidence_sha256"] = "e" * 64
    result = {
        "schema": "aros-toolchain-result-v1",
        "operation": "build",
        "identity": identity,
        "output_root": "/original/owner/output",
        "outputs": [],
        "evidence": [
            {"check": name, "status": "passed", "report_sha256": f"{index + 5:x}" * 64}
            for index, name in enumerate(("preflight", "environment", "configure", "compiler",
                                          "collector", "publish", "finished-candidate"))
        ] + [{"check": "origin", "status": "not-run", "report_sha256": None}],
        "qualification": "local-only",
        "commit_state": "committed",
    }
    if mutation == "unknown-field":
        result["unexpected"] = "not in the closed native schema"
    elif mutation == "wrong-schema":
        result["schema"] = "aros-toolchain-build-result-v2"
    elif mutation == "wrong-operation":
        result["operation"] = "package"
    elif mutation == "lifecycle-mismatch":
        result["evidence"][3]["status"] = "not-run"
    return result


FAKE_ORIGIN = r'''#!/usr/bin/env python3
import hashlib
import json
import os
from pathlib import Path
import sys

if __name__ != "__main__":
    import importlib.util
    helper_path = Path(__file__).with_name("artifact-origin-real.py")
    spec = importlib.util.spec_from_file_location("artifact_origin_real", helper_path)
    if spec is None or spec.loader is None:
        raise ImportError("real artifact-origin validation helpers are unavailable")
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    for name in ("MAX_METADATA", "OriginError", "json", "normalized_file", "parse_json",
                 "require", "source_selection"):
        globals()[name] = getattr(helper, name)


def record(stage, args):
    with open(os.environ["FAKE_STAGE_LOG"], "a", encoding="utf-8") as stream:
        stream.write(json.dumps({"stage": stage, "args": args}, separators=(",", ":")) + "\n")


def option(name):
    for index, value in enumerate(sys.argv[1:]):
        if value == name and index + 2 < len(sys.argv):
            return sys.argv[index + 2]
    raise SystemExit("fixture origin missing " + name)


if __name__ == "__main__":
    args = sys.argv[1:]
    record("origin", args)
    if not args or args[0] != "verify-source":
        raise SystemExit("fixture origin received an unexpected operation")
    if os.environ.get("FAKE_ORIGIN_MODE") == "fail":
        print("synthetic authentication failure", file=sys.stderr)
        raise SystemExit(41)
    selection = Path(option("--source-selection"))
    retained = Path(option("--verified-output-dir"))
    retained.mkdir(mode=0o700)
    measurement = Path(os.environ["FAKE_MEASUREMENT_FILE"]).read_bytes()
    origin_record = {"files": {"evidence/measurement.json": {
        "sha256": hashlib.sha256(measurement).hexdigest(), "size": len(measurement)}}}
    (retained / "payload.zip").write_bytes(b"synthetic payload; not an archive\n")
    (retained / "origin.json").write_text(json.dumps(origin_record, separators=(",", ":")) + "\n", encoding="utf-8")
    (retained / "origin.sigstore.json").write_bytes(b"synthetic signature; not a signature\n")
    (retained / "selection.json").write_bytes(selection.read_bytes())
    if os.environ.get("FAKE_ORIGIN_MODE") == "change-runtime":
        with open(os.environ["FAKE_RUNTIME_FILE"], "ab") as stream:
            stream.write(b"changed during synthetic authentication\n")
    print("synthetic authenticated-source placeholder")
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


def result(directory):
    files = {}
    for path in sorted(directory.rglob("*")):
        if path.is_file():
            raw = path.read_bytes()
            name = path.relative_to(directory).as_posix()
            files[name] = {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}
    return {"schema": "aros-toolchain-native-lane-transport-v2",
            "assurance": "transport-byte-readback-only", "files": files}


args = sys.argv[1:]
retained = Path(option("--retained-dir"))
output_arg = "--output-dir" if "--output-dir" in args else "--verify-output-dir"
output = Path(option(output_arg))
if output_arg == "--output-dir":
    record("transport-extract", args)
    if os.environ.get("FAKE_TRANSPORT_MODE") == "extraction-failure":
        raise SystemExit(51)
    output.mkdir(mode=0o700)
    package = output / "package"
    evidence = output / "evidence"
    package.mkdir(mode=0o700)
    evidence.mkdir(mode=0o700)
    archive = package / "fixture-toolchain.tar.xz"
    archive.write_bytes(b"synthetic package bytes; not a real archive\n")
    tree = "a" * 64
    (package / (archive.name + ".manifest.json")).write_text(json.dumps({
        "schema": 2, "host": os.environ["FAKE_HOST"],
        "target_profile": os.environ["FAKE_PRESET"], "tree_sha256": tree,
    }, separators=(",", ":")) + "\n", encoding="utf-8")
    (package / (archive.name + ".sha256")).write_text(
        hashlib.sha256(archive.read_bytes()).hexdigest() + "  " + archive.name + "\n", encoding="utf-8")
    (package / (archive.name + ".spdx.json")).write_bytes(b'{"synthetic":true}\n')
    mutation = os.environ.get("FAKE_RESULT_MODE", "")
    native_result = json.loads(os.environ["FAKE_BUILD_RESULT_JSON"])
    (evidence / "build-result.json").write_text(
        json.dumps(native_result, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    (evidence / "environment.json").write_bytes(Path(os.environ["FAKE_ENVIRONMENT_FILE"]).read_bytes())
    (evidence / "environment-result.json").write_bytes(b'{"synthetic":"environment result"}\n')
    (evidence / "measurement.json").write_bytes(Path(os.environ["FAKE_MEASUREMENT_FILE"]).read_bytes())
    (evidence / "package-result.json").write_bytes(b'{"synthetic":"package result"}\n')
    (evidence / "package-verify.json").write_bytes(b'{"synthetic":"package verification"}\n')
    if os.environ.get("FAKE_TRANSPORT_MODE") == "two-archives":
        (package / "second.tar.xz").write_bytes(b"second archive\n")
    encoded = json.dumps(result(output), sort_keys=True, separators=(",", ":")) + "\n"
    Path(os.environ["FAKE_TRANSPORT_RESULT"]).write_text(encoded, encoding="utf-8")
    sys.stdout.write(encoded)
elif output_arg == "--verify-output-dir":
    record("transport-readback", args)
    if os.environ.get("FAKE_TRANSPORT_MODE") == "readback-failure":
        raise SystemExit(52)
    if os.environ.get("FAKE_TRANSPORT_MODE") == "changed-output-on-readback":
        archive = output / "package" / "fixture-toolchain.tar.xz"
        archive.write_bytes(archive.read_bytes() + b"changed after native verification\n")
    encoded = json.dumps(result(output), sort_keys=True, separators=(",", ":")) + "\n"
    sys.stdout.write(encoded)
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
profile_doc = json.loads(Path(option("--profiles")).read_text(encoding="utf-8"))
profile_names = [item.get("name") for item in profile_doc.get("profiles", [])]
if option("--preset").removeprefix("=") not in profile_names:
    raise SystemExit("fixture native CLI rejected an unselected profile")
if option("--package-format") != "family-v2":
    raise SystemExit("fixture native CLI rejected the package format")
mode = os.environ.get("FAKE_AROS_MODE", "success")
if mode == "fail":
    raise SystemExit(61)
if mode == "change-runtime":
    with open(os.environ["FAKE_RUNTIME_FILE"], "ab") as stream:
        stream.write(b"changed during native verification\n")
package = Path(option("--input-dir"))
archive = package / "fixture-toolchain.tar.xz"
build_result = package.parent / "evidence" / "build-result.json"
signed_result = json.loads(build_result.read_text(encoding="utf-8"))
if set(signed_result) != {"schema", "operation", "identity", "output_root", "outputs",
                          "evidence", "qualification", "commit_state"}:
    raise SystemExit("fixture native verifier rejected the closed build-result schema")
expected_evidence = ["preflight", "environment", "configure", "compiler", "collector",
                     "publish", "finished-candidate", "origin"]
if [item.get("check") for item in signed_result["evidence"]] != expected_evidence:
    raise SystemExit("fixture native verifier rejected incomplete lifecycle evidence")
if any(item.get("status") != ("not-run" if item["check"] == "origin" else "passed")
       for item in signed_result["evidence"]):
    raise SystemExit("fixture native verifier rejected incomplete lifecycle evidence")
tree = "a" * 64
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
response = {
    "schema": "wrong-schema" if mode == "schema-mismatch" else "aros-toolchain-producer-stage-v1",
    "operation": "verify-package",
    "manifest": manifest,
    "finished_candidate": candidate,
    "sha256": "0" * 64 if mode == "archive-hash-mismatch" else digest(archive),
    "size": archive.stat().st_size + 1 if mode == "archive-size-mismatch" else archive.stat().st_size,
}
if mode == "ignore-portable-readback":
    response["finished_candidate"] = None
if mode == "empty-output":
    sys.exit(0)
if mode == "multiple-output":
    sys.stdout.write('{"schema":"unvalidated-first-object"}\n')
sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
sys.stdout.flush()
'''


class ReadNativeOwnerProcessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        missing = [name for name in ("jq", "shasum", "cmp", "python3") if not shutil.which(name)]
        if missing:
            raise RuntimeError("read-native-owner-v2 tests require: " + ", ".join(missing))
        cls.bashes = [Path("/bin/bash")]
        current_bash = Path(shutil.which("bash") or "/nonexistent")
        try:
            if current_bash.is_file() and os.path.samefile(current_bash, cls.bashes[0]) is False:
                cls.bashes.append(current_bash.resolve())
        except OSError:
            pass

    def setUp(self) -> None:
        self._create_fixture()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _create_fixture(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="read-native-owner-v2-")
        self.base = Path(self.temporary.name).resolve()
        self.script_dir = self.base / "scripts" / "toolchain"
        self.script_dir.mkdir(parents=True)
        self.script = self.script_dir / SCRIPT.name
        shutil.copy2(SCRIPT, self.script)
        real_origin = SCRIPT.with_name("artifact-origin.py")
        self._script("artifact-origin-real.py", real_origin.read_text(encoding="utf-8"))
        self._script("artifact-origin.py", FAKE_ORIGIN)
        self._script("native-lane-transport.py", FAKE_TRANSPORT)
        self.runtime = self._script("aros-fixture", FAKE_AROS)
        self.inputs = self.base / "inputs"
        self.inputs.mkdir()
        self.source_lock = self._file("source-lock.json", b'{"fixture":"source lock"}\n')
        profile_source = Path(__file__).resolve().parents[3] / "toolchains" / "profiles-gnu-rv32-v2.json"
        self.profiles = self._file("profiles.json", profile_source.read_bytes())
        self.recipe = self._file("recipe.json", canonical_json(recipe_document(
            sha256(self.source_lock.read_bytes()), sha256(self.profiles.read_bytes()))))
        self.environment = self._file("environment.json", ENVIRONMENT)
        self.measurement = self._file("measurement.json", MEASUREMENT)
        self.selection = self._file("selection.json", canonical_json(selection_document()))
        self.recipe_doc = json.loads(self.recipe.read_text(encoding="utf-8"))
        self.stage_log = self.base / "stage-log.jsonl"
        self.transport_result = self.base / "transport-result-state.json"
        self.operations = self.base / "operations"
        self.operations.mkdir()
        self.root = self.operations / "observation"
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

    def _write_selection(self, *, host: str = HOST, preset: str = PRESET,
                         copy: str = COPY, producer: str = PRODUCER_COMMIT,
                         workflow: str = SOURCE_WORKFLOW, ref: str = SOURCE_REF) -> None:
        self.selection.write_bytes(canonical_json(selection_document(
            host=host, preset=preset, copy=copy, producer=producer, workflow=workflow, ref=ref)))

    def _select_profiles(self, family: str) -> str:
        name = "profiles-gnu-rv32-v2.json" if family == "gnu" else "profiles-v1.json"
        source = Path(__file__).resolve().parents[3] / "toolchains" / name
        self.profiles.write_bytes(source.read_bytes())
        self.recipe_doc = recipe_document(
            sha256(self.source_lock.read_bytes()), sha256(self.profiles.read_bytes()))
        self.recipe.write_bytes(canonical_json(self.recipe_doc))
        return "rv32-esp32p4" if family == "gnu" else "pc-x86_64"

    def _args(self) -> list[str]:
        return [
            "--aros", str(self.runtime), "--aros-sha256", sha256(self.runtime.read_bytes()),
            "--recipe", str(self.recipe), "--recipe-file-sha256", sha256(self.recipe.read_bytes()),
            "--source-lock", str(self.source_lock), "--source-lock-sha256", sha256(self.source_lock.read_bytes()),
            "--profiles", str(self.profiles), "--profiles-sha256", sha256(self.profiles.read_bytes()),
            "--source-selection", str(self.selection), "--source-selection-sha256", sha256(self.selection.read_bytes()),
            "--workflow", WORKFLOW, "--job-name", "SDK from owned compilers (rv32, linux-aarch64, release)",
            "--source-workflow", SOURCE_WORKFLOW, "--source-ref", SOURCE_REF,
            "--group", GROUP, "--preset", PRESET, "--host", HOST, "--copy", COPY,
            "--release-id", RELEASE_ID,
            "--forbidden-prefix", self.forbidden[0], "--forbidden-prefix", self.forbidden[1],
            "--root", str(self.root),
        ]

    def _env(self, *, origin: str = "success", transport: str = "success",
             result: str = "success", aros: str = "success", host: str = HOST,
             preset: str = PRESET) -> dict[str, str]:
        result_doc = build_result(self.recipe_doc, host=host, preset=preset)
        if result != "success":
            result_doc = build_result(self.recipe_doc, host=host, preset=preset, mutation=result)
        return os.environ | {
            "FAKE_STAGE_LOG": str(self.stage_log),
            "FAKE_ORIGIN_MODE": origin,
            "FAKE_TRANSPORT_MODE": transport,
            "FAKE_RESULT_MODE": "" if result == "success" else result,
            "FAKE_BUILD_RESULT_JSON": json.dumps(result_doc, sort_keys=True, separators=(",", ":")),
            "FAKE_ENVIRONMENT_FILE": str(self.environment),
            "FAKE_MEASUREMENT_FILE": str(self.measurement),
            "FAKE_TRANSPORT_RESULT": str(self.transport_result),
            "FAKE_RECIPE_FILE": str(self.recipe),
            "FAKE_RUNTIME_FILE": str(self.runtime),
            "FAKE_HOST": host,
            "FAKE_PRESET": preset,
            "FAKE_AROS_MODE": aros,
        }

    def _run(self, bash: Path, args: list[str] | None = None, **modes: str) -> subprocess.CompletedProcess[str]:
        selected_args = args if args is not None else self._args()
        host = selected_args[selected_args.index("--host") + 1]
        preset = selected_args[selected_args.index("--preset") + 1]
        return subprocess.run(
            [str(bash), str(self.script), *selected_args],
            capture_output=True, text=True, check=False, timeout=20,
            env=self._env(host=host, preset=preset, **modes),
        )

    def _events(self) -> list[dict]:
        if not self.stage_log.exists():
            return []
        return [json.loads(line) for line in self.stage_log.read_text(encoding="utf-8").splitlines()]

    def _assert_rejected(self, result: subprocess.CompletedProcess[str]) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.root / "observation.json").exists())

    def _native_args(self) -> list[str]:
        payload = self.root / "payload"
        return [
            "toolchain", "producer", "verify-package",
            "--recipe", str(self.recipe), "--source-lock", str(self.source_lock),
            "--profiles", str(self.profiles), "--preset=" + PRESET,
            "--host", HOST, "--release-id", RELEASE_ID,
            "--build-environment", str(payload / "evidence" / "environment.json"),
            "--package-format", "family-v2", "--input-dir", str(payload / "package"),
            "--package-measurement", str(payload / "evidence" / "measurement.json"),
            "--package-measurement-sha256", sha256(MEASUREMENT),
            "--executor-contract-sha256", CONTRACT_SHA,
            "--executor-binary-sha256", EXECUTOR_SHA,
            "--forbidden-prefix", self.forbidden[0],
            "--forbidden-prefix", self.forbidden[1], "--format", "json",
        ]

    def test_success_authenticates_then_extracts_then_derives_native_selectors_and_reads_back(self) -> None:
        for index, bash in enumerate(self.bashes):
            with self.subTest(bash=str(bash)):
                if index:
                    self.tearDown()
                    self.setUp()
                args = self._args() + ["--same-attempt"]
                result = self._run(bash, args)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                events = self._events()
                self.assertEqual([event["stage"] for event in events], [
                    "origin", "transport-extract", "native", "transport-readback",
                ])
                self.assertEqual(events[0]["args"], [
                    "verify-source", "--workflow", WORKFLOW,
                    "--job-name", "SDK from owned compilers (rv32, linux-aarch64, release)",
                    "--source-selection", str(self.selection),
                    "--verified-output-dir", str(self.root / "transport"), "--same-attempt",
                ])
                self.assertEqual(events[2]["args"], self._native_args())
                self.assertEqual(events[3]["args"], [
                    "--retained-dir", str(self.root / "transport"),
                    "--verify-output-dir", str(self.root / "payload"),
                ])
                self.assertTrue((self.root / "observation.json").is_file())
                wrapper = json.loads((self.root / "observation.json").read_text(encoding="utf-8"))
                self.assertEqual(wrapper["schema"], "aros-toolchain-original-owner-observation-v2")
                self.assertEqual(wrapper["assurance"], "authenticated-original-job-and-native-byte-readback-only")
                self.assertEqual(wrapper["scope"], {
                    "original_owner_job_observation": True,
                    "native_package_byte_readback": True,
                    "independently_executed_collector": False,
                    "release_admission": False,
                    "publication": False,
                })
                self.assertEqual(wrapper["executor_contract_id"], CONTRACT_ID)
                self.assertEqual(wrapper["executor_contract_sha256"], CONTRACT_SHA)
                self.assertEqual(wrapper["executor_binary_sha256"], EXECUTOR_SHA)
                self.assertEqual(wrapper["original_identity"], {
                    "recipe_self_sha256": json.loads(self.recipe.read_text())["recipe_sha256"],
                    "source_commit": SOURCE_COMMIT,
                    "producer_commit": PRODUCER_COMMIT,
                    "tools_commit": TOOLS_COMMIT,
                    "host": HOST,
                    "target_profile": PRESET,
                })
                self.assertEqual(wrapper["measurement_sha256"], sha256(MEASUREMENT))
                self.assertEqual(wrapper["environment_sha256"], sha256(ENVIRONMENT))
                self.assertEqual(wrapper["native"]["finished_candidate"]["build_result_sha256"],
                                 sha256((self.root / "payload/evidence/build-result.json").read_bytes()))
                self.assertNotEqual(wrapper["executor_binary_sha256"], "f" * 64)
                self.assertTrue((self.root.stat().st_mode & 0o777) == 0o700)
                # Reusing the operation root cannot replay the prior authenticated result.
                before = list(events)
                observation = (self.root / "observation.json").read_bytes()
                replay = self._run(bash, args)
                self.assertNotEqual(replay.returncode, 0, replay.stdout + replay.stderr)
                self.assertEqual((self.root / "observation.json").read_bytes(), observation)
                self.assertEqual(self._events(), before)

    def test_successful_gnu_and_llvm_profile_selectors_are_preserved(self) -> None:
        cases = (("gnu", "linux-aarch64", GROUP), ("llvm", "macos-aarch64", GROUP))
        for index, (family, host, group) in enumerate(cases):
            with self.subTest(family=family, host=host):
                if index:
                    self.tearDown()
                    self.setUp()
                    self.root = self.operations / f"observation-{index}"
                preset = self._select_profiles(family)
                self._write_selection(host=host, preset=preset)
                args = self._args()
                args[args.index("--preset") + 1] = preset
                args[args.index("--host") + 1] = host
                args[args.index("--group") + 1] = group
                result = self._run(self.bashes[0], args)
                self.assertEqual(result.returncode, 0, result.stderr)
                native_args = self._events()[2]["args"]
                self.assertIn("--preset=" + preset, native_args)
                self.assertEqual(native_args[native_args.index("--host") + 1], host)
                wrapper = json.loads((self.root / "observation.json").read_text(encoding="utf-8"))
                self.assertEqual(wrapper["target_profile"], preset)
                self.assertEqual(wrapper["host"], host)
                self.assertEqual(wrapper["group"], group)

    def test_bad_independent_source_lane_rejects_before_operation_root_or_provider(self) -> None:
        probes = (
            ("wrong-producer", {"producer": "f" * 40}),
            ("wrong-workflow", {"workflow": ".github/workflows/other.yml"}),
            ("wrong-ref", {"ref": "refs/heads/other"}),
            ("wrong-host", {"host": "linux-x86_64"}),
            ("wrong-profile", {"preset": "other-profile"}),
            ("wrong-copy", {"copy": "b"}),
        )
        for bash in self.bashes:
            for name, values in probes:
                with self.subTest(bash=str(bash), selector=name):
                    self.tearDown()
                    self.setUp()
                    self._write_selection(**values)
                    result = self._run(bash)
                    self._assert_rejected(result)
                    self.assertFalse(self.root.exists())
                    self.assertEqual(self._events(), [])
            for name in ("duplicate-selection", "duplicate-recipe-producer"):
                with self.subTest(bash=str(bash), selector=name):
                    self.tearDown()
                    self.setUp()
                    if name == "duplicate-selection":
                        original = b'"host":"linux-aarch64"'
                        self.selection.write_bytes(self.selection.read_bytes().replace(
                            original, b'"host":"linux-x86_64","host":"linux-aarch64"', 1))
                    else:
                        original = b'"producer_commit":"' + PRODUCER_COMMIT.encode() + b'"'
                        self.recipe.write_bytes(self.recipe.read_bytes().replace(
                            original, b'"producer_commit":"' + b"d" * 40 + b'","producer_commit":"'
                            + PRODUCER_COMMIT.encode() + b'"', 1))
                    result = self._run(bash)
                    self._assert_rejected(result)
                    self.assertFalse(self.root.exists())
                    self.assertEqual(self._events(), [])

    def test_bad_inputs_duplicate_cli_and_nonfresh_roots_reject_before_provider(self) -> None:
        probes: list[list[str]] = []
        bad_hash = self._args()
        bad_hash[bad_hash.index("--aros-sha256") + 1] = "0" * 64
        probes.append(bad_hash)
        probes.append(self._args() + ["--host", HOST])
        probes.append(self._args() + ["--unknown", "x"])
        missing_copy = self._args()
        position = missing_copy.index("--copy")
        del missing_copy[position:position + 2]
        probes.append(missing_copy)
        no_forbidden = self._args()
        position = no_forbidden.index("--forbidden-prefix")
        del no_forbidden[position:position + 4]
        probes.append(no_forbidden)
        for bash in self.bashes:
            for args in probes:
                with self.subTest(bash=str(bash), args=args[-4:]):
                    self.tearDown()
                    self.setUp()
                    result = self._run(bash, args)
                    self._assert_rejected(result)
                    self.assertFalse(self.root.exists())
                    self.assertEqual(self._events(), [])
            self.tearDown()
            self.setUp()
            self.root.mkdir()
            sentinel = self.root / "sentinel"
            sentinel.write_bytes(b"preserve existing operation state\n")
            result = self._run(bash)
            self._assert_rejected(result)
            self.assertEqual(sentinel.read_bytes(), b"preserve existing operation state\n")
            self.assertEqual(self._events(), [])

    def test_authentication_failure_precedes_extraction_and_native_result_derivation(self) -> None:
        for bash in self.bashes:
            with self.subTest(bash=str(bash)):
                result = self._run(bash, origin="fail", result="wrong-schema")
                self._assert_rejected(result)
                self.assertEqual([event["stage"] for event in self._events()], ["origin"])
                self.assertFalse((self.root / "payload").exists())

    def test_signed_build_result_schema_and_each_expected_identity_field_are_checked(self) -> None:
        modes = ("wrong-schema", "wrong-operation", "unknown-field", "source-mismatch",
                 "producer-mismatch", "tools-mismatch", "recipe-mismatch", "host-mismatch",
                 "profile-mismatch", "executor-tools-mismatch", "executor-origin-claimed",
                 "lifecycle-mismatch")
        for bash in self.bashes:
            for mode in modes:
                with self.subTest(bash=str(bash), result=mode):
                    self.tearDown()
                    self.setUp()
                    result = self._run(bash, result=mode)
                    self._assert_rejected(result)
                    expected_stages = ["origin", "transport-extract"]
                    if mode in ("unknown-field", "lifecycle-mismatch"):
                        expected_stages.append("native")
                    self.assertEqual([event["stage"] for event in self._events()], expected_stages)

    def test_measurement_and_manifest_cannot_choose_executor_expectations(self) -> None:
        result = self._run(self.bashes[0])
        self.assertEqual(result.returncode, 0, result.stderr)
        native_args = self._events()[2]["args"]
        self.assertEqual(native_args[native_args.index("--executor-contract-sha256") + 1], CONTRACT_SHA)
        self.assertEqual(native_args[native_args.index("--executor-binary-sha256") + 1], EXECUTOR_SHA)
        self.assertEqual(native_args[native_args.index("--package-measurement-sha256") + 1], sha256(MEASUREMENT))
        wrapper = json.loads((self.root / "observation.json").read_text(encoding="utf-8"))
        self.assertEqual(wrapper["executor_binary_sha256"], EXECUTOR_SHA)

    def test_native_result_closed_joins_archive_uniqueness_and_transport_readback(self) -> None:
        cases = (
            ("native-response", {"aros": "schema-mismatch"}, ["origin", "transport-extract", "native"]),
            ("candidate", {"aros": "ignore-portable-readback"}, ["origin", "transport-extract", "native"]),
            ("measurement-hash", {"aros": "measurement-mismatch"}, ["origin", "transport-extract", "native"]),
            ("build-result-hash", {"aros": "build-result-mismatch"}, ["origin", "transport-extract", "native"]),
            ("archive-hash", {"aros": "archive-hash-mismatch"}, ["origin", "transport-extract", "native"]),
            ("archive-size", {"aros": "archive-size-mismatch"}, ["origin", "transport-extract", "native"]),
            ("host", {"aros": "host-mismatch"}, ["origin", "transport-extract", "native"]),
            ("profile", {"aros": "profile-mismatch"}, ["origin", "transport-extract", "native"]),
            ("tree", {"aros": "tree-mismatch"}, ["origin", "transport-extract", "native"]),
            ("unique-archive", {"transport": "two-archives"}, ["origin", "transport-extract"]),
            ("changed-output", {"transport": "changed-output-on-readback"},
             ["origin", "transport-extract", "native", "transport-readback"]),
        )
        for bash in self.bashes:
            for index, (name, modes, expected) in enumerate(cases):
                with self.subTest(bash=str(bash), case=name):
                    self.tearDown()
                    self.setUp()
                    result = self._run(bash, **modes)
                    self._assert_rejected(result)
                    self.assertEqual([event["stage"] for event in self._events()], expected)

    def test_authentication_time_input_change_stops_before_extraction(self) -> None:
        for bash in self.bashes:
            with self.subTest(bash=str(bash)):
                self.tearDown()
                self.setUp()
                result = self._run(bash, origin="change-runtime")
                self._assert_rejected(result)
                self.assertEqual([event["stage"] for event in self._events()], ["origin"])


if __name__ == "__main__":
    unittest.main()
