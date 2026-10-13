"""Contract tests for the bounded native compiler owner selector."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts/toolchain/compiler-owner-matrix-v2.py"
ACTION = ROOT / ".github/actions/build-native-lane-v2/action.yml"
RELEASE_MATRIX_TEST = ROOT / "scripts/toolchain/tests/test-release-matrix-v2.py"
PRODUCER_COMMIT = "a" * 40
TOOLS_COMMIT = "b" * 40
INPUTS_SHA256 = "d" * 64
SOURCE_REF = "refs/heads/main"
TAG_REF = "refs/tags/v2.4.0"
SOURCE_WORKFLOW = ".github/workflows/toolchain-release.yml"


FAKE_GH = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import re
import sys

args = sys.argv[1:]
endpoint = os.environ["FAKE_GH_ENDPOINT"]
attempt_endpoint = re.compile(
    r"repos/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+/actions/runs/"
    r"[1-9][0-9]*/attempts/[1-9][0-9]*"
)
if (len(args) != 2 or args[0] != "api" or args[1] != endpoint or
        attempt_endpoint.fullmatch(endpoint) is None):
    raise SystemExit(90)
responses = json.loads(Path(os.environ["FAKE_GH_RESPONSES"]).read_text(encoding="utf-8"))
count_path = Path(os.environ["FAKE_GH_CALL_COUNT"])
count = int(count_path.read_text(encoding="ascii"))
if count >= len(responses):
    raise SystemExit(91)
count_path.write_text(str(count + 1), encoding="ascii")
response = responses[count]
if type(response) is not dict or set(response) != {"returncode", "stdout"}:
    raise SystemExit(92)
sys.stdout.write(response["stdout"])
raise SystemExit(response["returncode"])
'''


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _compact(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _load_release_fixture():
    spec = importlib.util.spec_from_file_location("compiler_release_matrix_test_fixture", RELEASE_MATRIX_TEST)
    if spec is None or spec.loader is None:
        raise RuntimeError("release matrix fixture is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


release_fixture = _load_release_fixture()


def _load_owner_selector():
    spec = importlib.util.spec_from_file_location("compiler_owner_matrix_v2_test_module", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("compiler owner selector is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class CompilerOwnerMatrixV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="compiler-owner-matrix-v2.")
        self.root = Path(self.temporary.name).resolve()
        self.fake_bin = self.root / "fake-bin"
        self.fake_bin.mkdir()
        fake_gh = self.fake_bin / "gh"
        fake_gh.write_text(FAKE_GH, encoding="utf-8")
        fake_gh.chmod(0o755)
        self.gh_responses = self.root / "gh-responses.json"
        self.gh_call_count = self.root / "gh-call-count.txt"
        self.inputs = self.root / "inputs"
        self.inputs.mkdir()
        self.plan_path = self.root / "plan.json"
        self.context_path = self.root / "source-context.json"
        self.plan = release_fixture.owner_plan()
        self.reference_bytes: dict[tuple[str, str], bytes] = {}
        for group in self.plan["groups"]:
            group_id = group["group_id"]
            for reference_name in ("recipe", "source_lock", "profiles"):
                reference = group[reference_name]
                raw = f"raw fixture bytes for {group_id}/{reference_name}\n".encode("utf-8")
                (self.inputs / reference["file"]).write_bytes(raw)
                reference["sha256"] = _sha(raw)
                self.reference_bytes[(group_id, reference_name)] = raw
        self.context = {
            "repository": "example/toolchains",
            "repository_id": 1234,
            "producer_commit": PRODUCER_COMMIT,
            "source_ref": SOURCE_REF,
            "workflow": SOURCE_WORKFLOW,
            "run_id": 123456,
            "run_attempt": 2,
        }
        self.context_raw = json.dumps(
            self.context, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8") + b"\n"
        self.context_path.write_bytes(self.context_raw)
        self.env = os.environ.copy()
        self.env.update({
            "PATH": str(self.fake_bin) + os.pathsep + self.env.get("PATH", ""),
            "FAKE_GH_ENDPOINT": self._gh_endpoint(),
            "FAKE_GH_RESPONSES": str(self.gh_responses),
            "FAKE_GH_CALL_COUNT": str(self.gh_call_count),
        })

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def set_source_ref(self, source_ref: str) -> None:
        self.context["source_ref"] = source_ref
        self.context_raw = json.dumps(
            self.context, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8") + b"\n"
        self.context_path.write_bytes(self.context_raw)
        self.env["FAKE_GH_ENDPOINT"] = self._gh_endpoint()

    def _gh_endpoint(self) -> str:
        return (f'repos/{self.context["repository"]}/actions/runs/'
                f'{self.context["run_id"]}/attempts/{self.context["run_attempt"]}')

    def _provider_reply(self, event: str = "workflow_dispatch", **changes: object) -> dict:
        ref = self.context["source_ref"]
        _, _, suffix = ref.partition("/")
        _, _, branch = suffix.partition("/")
        run = {
            "id": self.context["run_id"],
            "run_attempt": self.context["run_attempt"],
            "head_sha": self.context["producer_commit"],
            "head_branch": branch,
            "path": self.context["workflow"],
            "head_repository": {
                "id": self.context["repository_id"],
                "full_name": self.context["repository"],
            },
            "event": event,
        }
        run.update(changes)
        return {
            "returncode": 0,
            "stdout": json.dumps(run, sort_keys=True, separators=(",", ":")),
        }

    def _set_provider_replies(self, replies: list[dict]) -> None:
        self.provider_replies = replies

    def write_plan(self, plan: dict | None = None) -> bytes:
        raw = _compact(plan if plan is not None else self.plan)
        self.plan_path.write_bytes(raw)
        return raw

    def arguments(self, raw: bytes | None = None) -> list[str]:
        raw = raw if raw is not None else self.write_plan()
        return [
            sys.executable,
            "-B",
            str(SCRIPT),
            "--plan", str(self.plan_path),
            "--plan-sha256", _sha(raw),
            "--inputs-dir", str(self.inputs),
            "--inputs-sha256", INPUTS_SHA256,
            "--producer-commit", PRODUCER_COMMIT,
            "--tools-commit", TOOLS_COMMIT,
            "--source-context", str(self.context_path),
            "--source-context-sha256", _sha(self.context_raw),
            "--source-workflow", SOURCE_WORKFLOW,
            "--source-ref", self.context["source_ref"],
        ]

    def run_cli(self, raw: bytes | None = None, *, timeout: float = 10,
                arguments: list[str] | None = None) -> subprocess.CompletedProcess[str]:
        command = arguments if arguments is not None else self.arguments(raw)
        replies = getattr(self, "provider_replies", None)
        if replies is None:
            reply = self._provider_reply()
            replies = [reply, reply]
        self.gh_responses.write_text(
            json.dumps(replies, sort_keys=True, separators=(",", ":")), encoding="utf-8"
        )
        self.gh_call_count.write_text("0", encoding="ascii")
        self.env["FAKE_GH_ENDPOINT"] = self._gh_endpoint()
        return subprocess.run(command, capture_output=True, text=True, check=False, timeout=timeout,
                              env=self.env)

    def assert_rejected(self, result: subprocess.CompletedProcess[str]) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(result.stdout, "")
        self.assertIn("compiler owner matrix selection failed:", result.stderr)

    def test_complete_native_plan_projects_all_24_original_owners(self) -> None:
        raw = self.write_plan()
        result = self.run_cli(raw)
        self.assertEqual(result.returncode, 0, result.stderr)
        wrapper = json.loads(result.stdout)
        self.assertEqual(
            set(wrapper),
            {
                "schema", "assurance", "plan_sha256", "inputs_sha256",
                "source_context_sha256", "producer_commit", "tools_commit",
                "owners", "expected_compiler_lanes",
            },
        )
        self.assertEqual(wrapper["schema"], "aros-compiler-owner-matrix-v2")
        self.assertEqual(wrapper["assurance"], "owner-selection-only")
        self.assertEqual(wrapper["plan_sha256"], _sha(raw))
        self.assertEqual(wrapper["inputs_sha256"], INPUTS_SHA256)
        self.assertEqual(wrapper["source_context_sha256"], _sha(self.context_raw))
        self.assertEqual(wrapper["producer_commit"], PRODUCER_COMMIT)
        self.assertEqual(wrapper["tools_commit"], TOOLS_COMMIT)
        self.assertEqual(len(wrapper["owners"]), 24)
        self.assertEqual(len(wrapper["expected_compiler_lanes"]), 12)
        self.assertEqual(
            {owner["host"] for owner in wrapper["owners"]},
            {"linux-aarch64", "linux-x86_64", "macos-aarch64"},
        )
        self.assertEqual(
            [(owner["group_id"], owner["host"], owner["profile"], owner["copy"])
             for owner in wrapper["owners"]],
            sorted((owner["group_id"], owner["host"], owner["profile"], owner["copy"])
                   for owner in wrapper["owners"]),
        )
        self.assertEqual(
            [(lane["group_id"], lane["host"], lane["target_profile"])
             for lane in wrapper["expected_compiler_lanes"]],
            sorted((lane["group_id"], lane["host"], lane["target_profile"])
                   for lane in wrapper["expected_compiler_lanes"]),
        )

        groups = {group["group_id"]: group for group in self.plan["groups"]}
        action = ACTION.read_text(encoding="utf-8")
        self.assertIn(
            "printf '%s\\0' \"$ARGS_GROUP\" \"$ARGS_HOST\" \"$ARGS_PRESET\" \"$ARGS_COPY\"",
            action,
        )
        for owner in wrapper["owners"]:
            self.assertEqual(
                set(owner),
                {"owner_id", "group_id", "host", "profile", "copy", "job_name",
                 "payload_name", "proof_name", "recipe", "source_lock", "profiles"},
            )
            group = groups[owner["group_id"]]
            for name in ("recipe", "source_lock", "profiles"):
                self.assertEqual(owner[name], group[name])

            shell_hash = subprocess.run(
                ["bash", "-c",
                 'printf "%s\\0" "$1" "$2" "$3" "$4" | shasum -a 256 | awk \'{print $1}\'',
                 "native-action-owner-formula", owner["group_id"], owner["host"],
                 owner["profile"], owner["copy"]],
                capture_output=True, text=True, check=True,
            ).stdout.strip()
            self.assertEqual(owner["owner_id"], shell_hash)
            self.assertEqual(
                owner["job_name"],
                f"Native compiler ({owner['group_id']}, {owner['host']}, {owner['profile']}, {owner['copy']})",
            )
            self.assertEqual(
                owner["payload_name"],
                f"native-v2-{owner['owner_id']}-{self.context['run_id']}-{self.context['run_attempt']}",
            )
            self.assertEqual(
                owner["proof_name"],
                f"native-v2-proof-{owner['owner_id']}-{self.context['run_id']}-{self.context['run_attempt']}",
            )

        expected_canonical = json.dumps(wrapper, sort_keys=True, separators=(",", ":"),
                                        ensure_ascii=True) + "\n"
        self.assertEqual(result.stdout, expected_canonical)

    def test_actual_provider_event_selects_only_valid_projection_routes(self) -> None:
        for source_ref, event in (
            (SOURCE_REF, "workflow_dispatch"),
            (TAG_REF, "push"),
            (TAG_REF, "workflow_dispatch"),
        ):
            with self.subTest(source_ref=source_ref, event=event):
                self.set_source_ref(source_ref)
                raw = self.write_plan()
                reply = self._provider_reply(event)
                self._set_provider_replies([reply, reply])
                result = self.run_cli(raw)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.gh_call_count.read_text(encoding="ascii"), "2")
                wrapper = json.loads(result.stdout)
                self.assertEqual(len(wrapper["owners"]), 24)

    def test_unrecognized_source_ref_is_rejected_without_stdout(self) -> None:
        self.set_source_ref("refs/pull/17/merge")
        self.assert_rejected(self.run_cli())
        self.assertEqual(self.gh_call_count.read_text(encoding="ascii"), "0")
        module = _load_owner_selector()
        for ref, event in (("refs/pull/17/merge", "workflow_dispatch"),
                           (SOURCE_REF, None), (SOURCE_REF, "workflow_run"),
                           (SOURCE_REF, "unexpected")):
            with self.subTest(ref=ref, event=event):
                with self.assertRaises(module.artifact_origin.OriginError):
                    module._projection_route(ref, event)

    def test_duplicate_plan_json_field_is_rejected_without_stdout(self) -> None:
        raw = self.write_plan()
        duplicate = raw.replace(b'"operation":"release-plan"',
                                b'"operation":"release-plan","operation":"release-plan"', 1)
        self.plan_path.write_bytes(duplicate)
        self.assert_rejected(self.run_cli(duplicate))

    def test_missing_host_lane_is_rejected_without_stdout(self) -> None:
        plan = release_fixture.owner_plan()
        plan["lanes"] = [
            lane for lane in plan["lanes"]
            if not (lane["group_id"] == "family-alpha"
                    and lane["target_profile"] == "alpha-one"
                    and lane["host"] == "macos-aarch64")
        ]
        plan["lane_count"] = len(plan["lanes"])
        for group in plan["groups"]:
            for reference_name in ("recipe", "source_lock", "profiles"):
                group[reference_name]["sha256"] = _sha(
                    self.reference_bytes[(group["group_id"], reference_name)]
                )
        self.assert_rejected(self.run_cli(self.write_plan(plan)))

    def test_reference_file_with_wrong_bytes_is_rejected_without_stdout(self) -> None:
        self.write_plan()
        group = self.plan["groups"][0]
        path = self.inputs / group["recipe"]["file"]
        path.write_bytes(b"modified after the plan digest\n")
        self.assert_rejected(self.run_cli())

    def test_source_context_mismatch_and_digest_mismatch_are_rejected(self) -> None:
        raw = self.write_plan()
        arguments = self.arguments(raw)
        arguments[arguments.index("--source-ref") + 1] = "refs/heads/other"
        self.assert_rejected(self.run_cli(arguments=arguments))
        self.assertEqual(self.gh_call_count.read_text(encoding="ascii"), "0")

        arguments = self.arguments(raw)
        arguments[arguments.index("--source-context-sha256") + 1] = "e" * 64
        self.assert_rejected(self.run_cli(arguments=arguments))
        self.assertEqual(self.gh_call_count.read_text(encoding="ascii"), "0")

    def test_provider_event_ref_identity_and_api_failures_emit_no_json(self) -> None:
        missing_event = self._provider_reply()
        missing_run = json.loads(missing_event["stdout"])
        del missing_run["event"]
        missing_event["stdout"] = json.dumps(
            missing_run, sort_keys=True, separators=(",", ":")
        )
        cases: list[tuple[str, str, list[dict]]] = [
            (SOURCE_REF, "push", [self._provider_reply("push")]),
            (TAG_REF, "workflow_run", [self._provider_reply("workflow_run")]),
            (SOURCE_REF, "missing-event", [missing_event]),
            (SOURCE_REF, "unknown-event", [self._provider_reply("deployment")]),
            (SOURCE_REF, "run-id-mismatch", [self._provider_reply(id=123457)]),
            (SOURCE_REF, "attempt-mismatch", [self._provider_reply(run_attempt=3)]),
            (SOURCE_REF, "ref-mismatch", [self._provider_reply(head_branch="other")]),
            (SOURCE_REF, "malformed-json", [{"returncode": 0, "stdout": "{bad-json"}]),
            (SOURCE_REF, "malformed-run", [{"returncode": 0, "stdout": "[]"}]),
            (SOURCE_REF, "provider-failure", [{"returncode": 1, "stdout": ""}]),
        ]
        for source_ref, label, replies in cases:
            with self.subTest(source_ref=source_ref, failure=label):
                self.set_source_ref(source_ref)
                self._set_provider_replies(replies)
                self.assert_rejected(self.run_cli())

    def test_changed_provider_event_or_identity_before_stdout_is_rejected(self) -> None:
        self.set_source_ref(TAG_REF)
        self._set_provider_replies([
            self._provider_reply("workflow_dispatch"),
            self._provider_reply("push"),
        ])
        self.assert_rejected(self.run_cli())
        self.assertEqual(self.gh_call_count.read_text(encoding="ascii"), "2")

        self._set_provider_replies([
            self._provider_reply("workflow_dispatch"),
            self._provider_reply("workflow_dispatch", run_attempt=3),
        ])
        self.assert_rejected(self.run_cli())
        self.assertEqual(self.gh_call_count.read_text(encoding="ascii"), "2")

    def test_reference_symlink_is_rejected_without_stdout(self) -> None:
        raw = self.write_plan()
        group = self.plan["groups"][0]
        selected = self.inputs / group["recipe"]["file"]
        target = self.inputs / "reference-target.json"
        target.write_bytes(selected.read_bytes())
        selected.unlink()
        selected.symlink_to(target.name)
        self.assert_rejected(self.run_cli(raw))

    def test_hard_linked_reference_is_rejected_without_stdout(self) -> None:
        raw = self.write_plan()
        group = self.plan["groups"][0]
        selected = self.inputs / group["recipe"]["file"]
        os.link(selected, self.inputs / "second-reference-link.json")
        self.assert_rejected(self.run_cli(raw))

    def test_corrupt_plan_reference_digest_is_rejected_without_stdout(self) -> None:
        plan = release_fixture.owner_plan()
        for group in plan["groups"]:
            for reference_name in ("recipe", "source_lock", "profiles"):
                group[reference_name]["sha256"] = _sha(
                    self.reference_bytes[(group["group_id"], reference_name)]
                )
        plan["groups"][0]["profiles"]["sha256"] = "invalid"
        self.assert_rejected(self.run_cli(self.write_plan(plan)))

    def test_repeated_argument_is_rejected_before_opening_plan(self) -> None:
        fifo = self.root / "input-must-not-be-opened.fifo"
        os.mkfifo(fifo)
        raw = self.write_plan()
        arguments = self.arguments(raw)
        arguments[arguments.index("--plan") + 1] = str(fifo)
        arguments.extend(("--plan", str(fifo)))
        result = self.run_cli(arguments=arguments, timeout=3)
        self.assert_rejected(result)
        self.assertIn("repeated command-line option", result.stderr)


if __name__ == "__main__":
    unittest.main()
