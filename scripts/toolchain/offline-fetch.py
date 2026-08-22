#!/usr/bin/env python3
"""Guard AROS fetch.sh so a release build can consume only verified archives."""

import hashlib
import json
import os
from pathlib import Path
import sys


def die(message: str) -> None:
    raise SystemExit(f"offline fetch guard: {message}")


def value(option: str, arguments: list[str], default: str = "") -> str:
    try:
        return arguments[arguments.index(option) + 1]
    except (ValueError, IndexError):
        return default


arguments = sys.argv[1:]
archive = value("-a", arguments)
suffixes = value("-s", arguments).split()
location = Path(value("-l", arguments, ".")).resolve()
index_path = os.environ.get("AROS_VERIFIED_SOURCE_INDEX")
upstream = os.environ.get("AROS_UPSTREAM_FETCH")
if not archive or not index_path or not upstream:
    die("archive, AROS_VERIFIED_SOURCE_INDEX, and AROS_UPSTREAM_FETCH are required")
index = json.loads(Path(index_path).read_text(encoding="utf-8"))
locked = {item["filename"]: item for item in index.get("sources", [])}
candidates = [archive + "." + suffix for suffix in suffixes] if suffixes else [archive]
match = next((name for name in candidates if name in locked and (location / name).is_file()), None)
if match is None:
    die(f"{archive} is not present in the verified offline source set")
digest = hashlib.sha256((location / match).read_bytes()).hexdigest()
if digest != locked[match]["sha256"]:
    die(f"verified archive changed after prefetch: {match}")
os.execv("/bin/bash", ["bash", upstream, *arguments])
