#!/usr/bin/env python3
"""Validate a canonical SemVer toolchain release tag and classify its channel."""

from pathlib import Path
import re
import sys


TAG_PATTERN = re.compile(
    r"v(?P<major>0|[1-9][0-9]*)"
    r"\.(?P<minor>0|[1-9][0-9]*)"
    r"\.(?P<patch>0|[1-9][0-9]*)"
    r"(?:-rc\.(?P<candidate>[1-9][0-9]*))?"
)


def classify_tag(tag: str) -> bool:
    """Return whether *tag* denotes a prerelease; reject noncanonical tags."""
    match = TAG_PATTERN.fullmatch(tag)
    if match is None:
        raise ValueError(
            "expected vMAJOR.MINOR.PATCH or vMAJOR.MINOR.PATCH-rc.N "
            "with canonical ASCII numerals"
        )

    return match.group("candidate") is not None


def main() -> int:
    if len(sys.argv) != 3:
        print(
            "usage: validate-release-tag.py TAG OUTPUT_FILE",
            file=sys.stderr,
        )
        return 2

    tag, output_path = sys.argv[1:]
    try:
        prerelease = classify_tag(tag)
    except ValueError as error:
        print(f"invalid toolchain release tag {tag!r}: {error}", file=sys.stderr)
        return 1

    with Path(output_path).open("a", encoding="utf-8") as output:
        output.write(f"prerelease={str(prerelease).lower()}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
