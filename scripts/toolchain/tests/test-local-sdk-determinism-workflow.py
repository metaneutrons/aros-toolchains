#!/usr/bin/env python3
"""Audit that local self-hosted runners can only run owner-dispatched code.

The local runners (label aros-local) belong to the repository owner. They must
never execute code from outside the repository, so:

* no workflow may combine a self-hosted runner with a trigger that can start
  from a pull request or from another repository's content;
* the local loop workflow has a single workflow_dispatch trigger, is guarded to
  the owner on main, holds no secrets or write permissions, and starts from an
  empty work directory.

The checks use only the Python standard library and read the workflow text.
"""

from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[3]
WORKFLOWS = ROOT / ".github/workflows"
LOCAL = WORKFLOWS / "local-sdk-determinism.yml"
UNSAFE_TRIGGERS = ("pull_request", "pull_request_target", "push", "workflow_run",
                   "issue_comment", "issues", "fork", "release", "schedule")
SELF_HOSTED = re.compile(r"self-hosted|aros-local")


def triggers(text: str) -> list[str]:
    """Return the top-level keys of the `on:` mapping."""
    match = re.search(r"^on:\s*\n((?:[ \t]+.*\n|\n)+)", text, re.MULTILINE)
    if match is None:
        inline = re.search(r"^on:\s*(.+)$", text, re.MULTILINE)
        assert inline is not None, "workflow has no on: block"
        return re.findall(r"[a-z_]+", inline.group(1))
    return re.findall(r"^  ([a-z_]+):", match.group(1), re.MULTILINE)


class LocalRunnerPolicy(unittest.TestCase):
    def test_no_workflow_mixes_self_hosted_with_untrusted_triggers(self) -> None:
        for path in sorted(WORKFLOWS.glob("*.yml")):
            text = path.read_text(encoding="utf-8")
            if SELF_HOSTED.search(text) is None:
                continue
            with self.subTest(workflow=path.name):
                found = triggers(text)
                self.assertEqual(found, ["workflow_dispatch"], "self-hosted runners admit only workflow_dispatch")

    def test_unsafe_trigger_names_are_known(self) -> None:
        # Guard the guard: the allow-list above is a single trigger, so every
        # unsafe name is rejected by construction; keep the list for review.
        self.assertIn("pull_request_target", UNSAFE_TRIGGERS)

    def test_only_the_local_loop_uses_the_local_label(self) -> None:
        users = [path.name for path in sorted(WORKFLOWS.glob("*.yml"))
                 if re.search(r"aros-local", path.read_text(encoding="utf-8"))]
        self.assertEqual(users, [LOCAL.name])

    def test_local_loop_is_owner_dispatch_on_main_only(self) -> None:
        text = LOCAL.read_text(encoding="utf-8")
        self.assertEqual(triggers(text), ["workflow_dispatch"])
        for guard in ("github.repository == 'metaneutrons/aros-toolchains'",
                      "github.event_name == 'workflow_dispatch'",
                      "github.ref == 'refs/heads/main'",
                      "github.triggering_actor == github.repository_owner"):
            self.assertIn(guard, text)

    def test_local_loop_holds_no_secret_and_no_write_permission(self) -> None:
        text = LOCAL.read_text(encoding="utf-8")
        self.assertNotRegex(text, r"secrets\.")
        for permission in re.findall(r"^\s+([a-z-]+): (read|write|none)$", text, re.MULTILINE):
            self.assertEqual(permission[1], "read", f"{permission[0]} must stay read-only")
        self.assertNotIn("id-token", text)
        self.assertNotIn("attestations", text)
        self.assertGreaterEqual(text.count("persist-credentials: false"), 2)

    def test_local_loop_starts_and_ends_with_a_clean_work_directory(self) -> None:
        text = LOCAL.read_text(encoding="utf-8")
        first_step = text.index("Start from an empty workspace and temp directory")
        first_checkout = text.index("actions/checkout@")
        self.assertLess(first_step, first_checkout)
        self.assertIn('find "$GITHUB_WORKSPACE" -mindepth 1 -maxdepth 1 -exec rm -rf {} +', text)
        self.assertIn('find "$RUNNER_TEMP" -mindepth 1 -maxdepth 1 -exec rm -rf {} +', text)
        final = text.rindex("Leave no build tree behind")
        self.assertIn("if: always()", text[final - 40:final + 80])

    def test_local_loop_binds_the_source_run_to_this_commit(self) -> None:
        text = LOCAL.read_text(encoding="utf-8")
        for needle in ('.head_sha == $sha', '.head_repository.full_name == $repo',
                       '.path == ".github/workflows/toolchain-release.yml"'):
            self.assertIn(needle, text)

    def test_local_loop_cannot_publish(self) -> None:
        text = LOCAL.read_text(encoding="utf-8")
        self.assertNotRegex(text, r"gh release|gh attestation|upload-release|retain-sdk-owner-payload")


if __name__ == "__main__":
    unittest.main()
