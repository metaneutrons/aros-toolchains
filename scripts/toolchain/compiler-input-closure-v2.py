#!/usr/bin/env python3
"""Compute the compiler input closure digest of one exact producer commit.

The SDK qualification run may consume a compiler qualification run from an
earlier producer commit only if both commits have the same compiler input
closure. The closure is deny-by-default: every tracked path of the commit is a
compiler input unless the classification file of that same commit lists it as
SDK-stage only. A new or unclassified path therefore changes the digest.

The digest covers the sorted (path, mode, type, object ID) entries of the
closure, read from the commit's tree, never from a working tree. It is a
content identity, not a provenance claim: compiler owner provenance is still
verified against the compiler run's own commit and workflow.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import PurePosixPath
import re
import subprocess
import sys

CLASSIFICATION_PATH = "toolchains/compiler-input-classification-v2.json"
CLASSIFICATION_SCHEMA = "aros-compiler-input-classification-v2"
CLOSURE_SCHEMA = "aros-compiler-input-closure-v2"
# Paths that can never be SDK-stage only. The classification file decides the
# closure itself, and the compiler workflow produces the compiler owners.
PROTECTED_PATHS = (
    CLASSIFICATION_PATH,
    ".github/workflows/toolchain-compilers-v2.yml",
)
OBJECT_ID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
ENTRY_TYPES = {"blob", "commit"}
MAX_ENTRIES = 200_000
MAX_CLASSIFICATION = 1 << 20


class ClosureError(ValueError):
    """The commit or its classification cannot define a compiler input closure."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ClosureError(message)


def git(repository: str, *arguments: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", repository, *arguments], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    require(result.returncode == 0, f"git {arguments[0]} failed for the selected commit")
    return result.stdout


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def valid_path(path: object) -> bool:
    if not isinstance(path, str) or not 0 < len(path) <= 1024:
        return False
    if path.startswith("/") or path.endswith("/") or "\\" in path or "\0" in path:
        return False
    parts = path.split("/")
    return all(part not in ("", ".", "..") for part in parts) and str(PurePosixPath(path)) == path


def resolve_commit(repository: str, commit: str) -> str:
    require(isinstance(commit, str) and OBJECT_ID.fullmatch(commit) is not None,
            "commit must be a full lowercase object ID")
    resolved = git(repository, "rev-parse", "--verify", "--end-of-options", f"{commit}^{{commit}}")
    require(resolved.decode("ascii", "replace").strip() == commit,
            "commit does not name exactly one commit object")
    return commit


def tree_entries(repository: str, commit: str) -> dict[str, tuple[str, str, str]]:
    raw = git(repository, "ls-tree", "-r", "-z", "--full-tree", commit)
    entries: dict[str, tuple[str, str, str]] = {}
    for record in raw.split(b"\0"):
        if not record:
            continue
        meta, separator, path_bytes = record.partition(b"\t")
        require(separator == b"\t", "tree listing is malformed")
        try:
            path = path_bytes.decode("utf-8")
            mode, kind, object_id = meta.decode("ascii").split(" ")
        except (UnicodeDecodeError, ValueError):
            raise ClosureError("tree entry is not a portable UTF-8 path") from None
        require(valid_path(path), "tree entry path is not canonical")
        require(kind in ENTRY_TYPES and OBJECT_ID.fullmatch(object_id) is not None
                and re.fullmatch(r"[0-7]{6}", mode) is not None, "tree entry is malformed")
        require(path not in entries, "tree lists a path twice")
        entries[path] = (mode, kind, object_id)
        require(len(entries) <= MAX_ENTRIES, "tree exceeds its entry bound")
    require(bool(entries), "commit tree is empty")
    return entries


def load_classification(repository: str, commit: str,
                        entries: dict[str, tuple[str, str, str]]) -> list[dict[str, str]]:
    require(CLASSIFICATION_PATH in entries and entries[CLASSIFICATION_PATH][1] == "blob",
            "commit has no compiler input classification file")
    raw = git(repository, "cat-file", "blob", entries[CLASSIFICATION_PATH][2])
    require(len(raw) <= MAX_CLASSIFICATION, "classification file exceeds its size bound")

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            require(key not in result, "classification repeats a JSON key")
            result[key] = value
        return result

    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ClosureError("classification file is not UTF-8 JSON") from None
    require(isinstance(document, dict) and set(document) == {"schema", "sdk_only"},
            "classification has unexpected or missing keys")
    require(document["schema"] == CLASSIFICATION_SCHEMA, "classification schema differs")
    sdk_only = document["sdk_only"]
    require(isinstance(sdk_only, list), "classification sdk_only must be a list")
    seen: set[str] = set()
    result = []
    for item in sdk_only:
        require(isinstance(item, dict) and set(item) == {"path", "kind", "reason"},
                "classification entry has unexpected or missing keys")
        path, kind, reason = item["path"], item["kind"], item["reason"]
        require(valid_path(path), "classification path is not canonical")
        require(kind in ("file", "directory"), "classification kind must be file or directory")
        require(isinstance(reason, str) and reason.strip() == reason and 0 < len(reason) <= 500,
                "classification entry needs a reason")
        require(path not in seen, "classification lists a path twice")
        seen.add(path)
        for protected in PROTECTED_PATHS:
            require(protected != path and not (kind == "directory" and protected.startswith(path + "/")),
                    "classification cannot exclude a protected compiler input")
        if kind == "file":
            require(path in entries and entries[path][1] == "blob",
                    "classified file does not exist as a file in the commit")
        else:
            require(path not in entries and any(name.startswith(path + "/") for name in entries),
                    "classified directory does not exist as a directory in the commit")
        result.append({"path": path, "kind": kind})
    require([item["path"] for item in result] == sorted(item["path"] for item in result),
            "classification entries must be sorted by path")
    for index, item in enumerate(result):
        for other in result[index + 1:]:
            require(not (item["kind"] == "directory" and other["path"].startswith(item["path"] + "/")),
                    "classification entries overlap")
    return result


def excluded(path: str, sdk_only: list[dict[str, str]]) -> bool:
    for item in sdk_only:
        if item["kind"] == "file" and path == item["path"]:
            return True
        if item["kind"] == "directory" and path.startswith(item["path"] + "/"):
            return True
    return False


def closure(repository: str, commit: str) -> dict[str, object]:
    commit = resolve_commit(repository, commit)
    entries = tree_entries(repository, commit)
    sdk_only = load_classification(repository, commit, entries)
    included = sorted(path for path in entries if not excluded(path, sdk_only))
    require(all(path in included for path in PROTECTED_PATHS if path in entries),
            "protected compiler input is missing from the closure")
    identity = {
        "schema": CLOSURE_SCHEMA,
        "entries": [[path, *entries[path]] for path in included],
    }
    return {
        "schema": CLOSURE_SCHEMA,
        "commit": commit,
        "closure_sha256": hashlib.sha256(canonical(identity)).hexdigest(),
        "included_count": len(included),
        "excluded_count": len(entries) - len(included),
        "classification_object": entries[CLASSIFICATION_PATH][2],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--repository-dir", required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args(argv)
    try:
        result = closure(args.repository_dir, args.commit)
    except ClosureError as error:
        sys.stderr.write(f"compiler input closure failed: {error}\n")
        return 2
    sys.stdout.write(canonical(result).decode("utf-8") + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
