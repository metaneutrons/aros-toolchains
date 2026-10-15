#!/usr/bin/env python3
"""Choose whether a pull request can use the Markdown-only CI path.

This planner is deliberately conservative. Any input or Git result it cannot
classify safely selects the full CI path.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import NamedTuple


_FULL_SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
_RAW_HEADER_RE = re.compile(
    rb":([0-7]{6}) ([0-7]{6}) ([0-9a-f]{40}) ([0-9a-f]{40}) ([A-Z][0-9]*)\Z"
)
_GIT_TIMEOUT_SECONDS = 10
_MAX_DIFF_BYTES = 1_048_576


class Change(NamedTuple):
    old_mode: bytes
    new_mode: bytes
    status: bytes
    path: bytes


def _result(scope: str, reason: str) -> dict[str, str]:
    """Return the closed, JSON-safe planner result shape."""
    return {"scope": scope, "reason": reason}


def _parse_raw_diff(data: bytes) -> tuple[list[Change] | None, str | None]:
    """Parse Git's NUL-delimited raw diff format without path quoting."""
    if not data:
        return [], None
    if not data.endswith(b"\0"):
        return None, "malformed_diff"

    fields = data[:-1].split(b"\0")
    if len(fields) % 2:
        return None, "malformed_diff"

    changes: list[Change] = []
    for index in range(0, len(fields), 2):
        header, path = fields[index], fields[index + 1]
        match = _RAW_HEADER_RE.fullmatch(header)
        if match is None or not path:
            return None, "malformed_diff"

        old_mode, new_mode, _old_oid, _new_oid, status = match.groups()
        # A rename/copy record has a different path arity. --no-renames should
        # prevent it, but fail closed if Git or a wrapper returns one anyway.
        if status[:1] in (b"R", b"C"):
            return None, "rename_or_copy"
        changes.append(Change(old_mode, new_mode, status, path))

    return changes, None


def _safe_path(path: bytes) -> bool:
    """Reject ambiguous, non-portable, or malformed Git paths."""
    if not path or any(not 0x20 <= value < 0x7F for value in path):
        return False
    if path.startswith(b"/") or b"\\" in path:
        return False
    return all(component not in (b"", b".", b"..") for component in path.split(b"/"))


def plan_changes(
    *,
    event: str,
    base: str | None,
    head: str | None,
    repository_dir: str | Path,
) -> dict[str, str]:
    """Return a conservative ``scope`` and a reason from a closed set."""
    if event != "pull_request":
        return _result("full", "event_not_pull_request")
    if not base:
        return _result("full", "missing_base")
    if not _FULL_SHA_RE.fullmatch(base):
        return _result("full", "invalid_base")
    if not head:
        return _result("full", "missing_head")
    if not _FULL_SHA_RE.fullmatch(head):
        return _result("full", "invalid_head")
    if base == head:
        return _result("full", "identical_refs")

    # SHA validation above prevents user-controlled options or revisions from
    # reaching Git. Every remaining argument here is fixed by this program.
    command = [
        "git",
        "diff",
        "--raw",
        "--no-abbrev",
        "-z",
        "--no-renames",
        "--no-ext-diff",
        "--no-textconv",
        base,
        head,
        "--",
    ]
    git_env = {
        key: value
        for key, value in os.environ.items()
        if key
        not in {
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        }
    }
    try:
        completed = subprocess.run(
            command,
            cwd=repository_dir,
            env=git_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=_GIT_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return _result("full", "git_error")
    if completed.returncode != 0 or len(completed.stdout) > _MAX_DIFF_BYTES:
        return _result("full", "git_error")

    changes, parse_error = _parse_raw_diff(completed.stdout)
    if parse_error:
        return _result("full", parse_error)
    assert changes is not None
    if not changes:
        return _result("full", "empty_diff")
    if any(not _safe_path(change.path) for change in changes):
        return _result("full", "unsafe_path")

    for change in changes:
        if not change.path.endswith(b".md"):
            return _result("full", "other_path")
        expected_modes = {
            b"M": (b"100644", b"100644"),
            b"A": (b"000000", b"100644"),
            b"D": (b"100644", b"000000"),
        }
        if change.status not in expected_modes:
            return _result("full", "unsupported_status")
        if (change.old_mode, change.new_mode) != expected_modes[change.status]:
            return _result("full", "mode_change")

    # With renames disabled, a Markdown-to-Markdown rename appears as one
    # deletion and one addition. Both paths have already been validated.
    return _result("markdown", "markdown_only")


def _write_github_output(path: str | Path, result: dict[str, str]) -> None:
    """Append only fixed-key values generated by this planner."""
    with open(path, "a", encoding="ascii", newline="\n") as output:
        output.write(f"scope={result['scope']}\n")
        output.write(f"reason={result['reason']}\n")


def _normalize_ref_options(argv: list[str]) -> list[str]:
    """Let malformed dash-prefixed refs reach validation as values."""
    normalized: list[str] = []
    index = 0
    while index < len(argv):
        argument = argv[index]
        if argument in ("--base", "--head"):
            if index + 1 < len(argv) and argv[index + 1].startswith("-"):
                normalized.append(f"{argument}={argv[index + 1]}")
                index += 2
                continue
        normalized.append(argument)
        index += 1
    return normalized


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--event", required=True, help="GitHub event name")
    parser.add_argument("--base", help="full 40-character base commit SHA")
    parser.add_argument("--head", help="full 40-character head commit SHA")
    parser.add_argument("--repository-dir", required=True, help="repository checkout path")
    parser.add_argument("--github-output", help="append GitHub Actions outputs to this file")
    args = parser.parse_args(_normalize_ref_options(sys.argv[1:] if argv is None else argv))

    result = plan_changes(
        event=args.event,
        base=args.base,
        head=args.head,
        repository_dir=args.repository_dir,
    )
    if args.github_output:
        try:
            _write_github_output(args.github_output, result)
        except OSError as error:
            print(f"could not write GitHub output: {error}", file=sys.stderr)
            return 2
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
