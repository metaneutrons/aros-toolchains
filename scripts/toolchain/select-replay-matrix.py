#!/usr/bin/env python3
"""Select only declared compatibility replay lanes, without arbitrary matrix input."""

import itertools
import json
from pathlib import Path
import sys


HOSTS = (
    ("linux-x86_64", "ubuntu-24.04"),
    ("linux-aarch64", "ubuntu-24.04-arm"),
    ("macos-aarch64", "macos-15"),
)
PROFILES = ("pc-x86_64", "arm-raspi", "rpi-aarch64")


def select(host: str, profile: str) -> dict[str, list[dict[str, str]]]:
    """Return a nonempty subset of the closed active release matrix."""
    if host not in {"all", *(item[0] for item in HOSTS)}:
        raise ValueError(f"unsupported replay host: {host}")
    if profile not in {"all", *PROFILES}:
        raise ValueError(f"unsupported replay profile: {profile}")
    include = [
        {"host": selected_host, "runner": runner, "profile": selected_profile}
        for (selected_host, runner), selected_profile in itertools.product(HOSTS, PROFILES)
        if (host == "all" or host == selected_host)
        and (profile == "all" or profile == selected_profile)
    ]
    if not include:
        raise ValueError("replay selection is empty")
    return {"include": include}


def main() -> int:
    if len(sys.argv) != 4:
        raise SystemExit("usage: select-replay-matrix.py HOST PROFILE GITHUB_OUTPUT")
    try:
        matrix = select(sys.argv[1], sys.argv[2])
    except ValueError as error:
        raise SystemExit(str(error)) from error
    with Path(sys.argv[3]).open("a", encoding="utf-8") as output:
        output.write("matrix=" + json.dumps(matrix, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
