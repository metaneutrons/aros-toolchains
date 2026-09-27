#!/usr/bin/env python3
"""Verify the pinned LLVM 11 patch and its AROS triple hunks offline."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import os
import hashlib
import re
from pathlib import Path


if "AROS_TEST_SOURCE_ROOT" not in os.environ:
    raise SystemExit("AROS_TEST_SOURCE_ROOT must name the AROS source checkout")
SOURCE_ROOT = Path(os.environ["AROS_TEST_SOURCE_ROOT"]).resolve()
PATCH = SOURCE_ROOT / "tools" / "crosstools" / "llvm" / "llvm-11.0.0.src-aros.diff"
EXPECTED_PATCH_SHA256 = "cc7876734c45eea469056ea4cb7fdf61a62316f677d94f25aab8b9cd9d6b595e"
FIXTURE_PATHS = frozenset(
    {
        "include/llvm/ADT/Triple.h",
        "include/llvm/Support/Signals.h",
        "lib/Support/Triple.cpp",
    }
)


def selected_hunks(patch: str) -> str:
    blocks = re.split(r"(?=^diff -ruN )", patch, flags=re.MULTILINE)
    selected = []
    for block in blocks:
        match = re.search(r"^--- llvm-11\.0\.0\.src/([^\t\n]+)", block, re.MULTILINE)
        if match and match.group(1) in FIXTURE_PATHS:
            selected.append(block)
    if len(selected) != len(FIXTURE_PATHS):
        raise SystemExit("LLVM patch lacks one of the closed AROS triple fixture paths")
    return "".join(selected)


def padded_lines(count: int) -> list[str]:
    return ["// fixture padding\n"] * count


def write_fixture(root: Path) -> None:
    tree = root / "llvm-11.0.0.src"
    fixtures: dict[str, list[str]] = {}

    triple_header = padded_lines(500)
    triple_header[15:21] = [
        "#undef NetBSD\n",
        "#undef mips\n",
        "#undef sparc\n",
        "\n",
        "namespace llvm {\n",
        "\n",
    ]
    triple_header[160:166] = [
        "    UnknownOS,\n",
        "\n",
        "    Ananas,\n",
        "    CloudABI,\n",
        "    Darwin,\n",
        "    DragonFly,\n",
    ]
    triple_header[447:453] = [
        "    return getOS() == Triple::Darwin || getOS() == Triple::MacOSX;\n",
        "  }\n",
        "\n",
        "  /// Is this an iOS triple.\n",
        "  /// Note: This identifies tvOS as a variant of iOS. If that ever\n",
        "  /// changes, i.e., if the two operating systems diverge or their version\n",
    ]
    fixtures["include/llvm/ADT/Triple.h"] = triple_header

    signals = padded_lines(24)
    signals[14:20] = [
        "#define LLVM_SUPPORT_SIGNALS_H\n",
        "\n",
        "#include <string>\n",
        "\n",
        "namespace llvm {\n",
        "class StringRef;\n",
    ]
    fixtures["include/llvm/Support/Signals.h"] = signals

    triple_cpp = padded_lines(520)
    triple_cpp[187:193] = [
        '  case AMDPAL: return "amdpal";\n',
        '  case Ananas: return "ananas";\n',
        '  case CNK: return "cnk";\n',
        '  case CUDA: return "cuda";\n',
        '  case CloudABI: return "cloudabi";\n',
        '  case Contiki: return "contiki";\n',
    ]
    triple_cpp[488:494] = [
        "static Triple::OSType parseOS(StringRef OSName) {\n",
        "  return StringSwitch<Triple::OSType>(OSName)\n",
        '    .StartsWith("ananas", Triple::Ananas)\n',
        '    .StartsWith("cloudabi", Triple::CloudABI)\n',
        '    .StartsWith("darwin", Triple::Darwin)\n',
        '    .StartsWith("dragonfly", Triple::DragonFly)\n',
    ]
    fixtures["lib/Support/Triple.cpp"] = triple_cpp

    for relative, lines in fixtures.items():
        destination = tree / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text("".join(lines), encoding="utf-8")


def main() -> None:
    if shutil.which("patch") is None:
        raise SystemExit("LLVM patch contract test requires patch")
    patch = PATCH.read_bytes()
    if hashlib.sha256(patch).hexdigest() != EXPECTED_PATCH_SHA256:
        raise SystemExit("LLVM patch bytes differ from the locally verified exact-source patch")

    with tempfile.TemporaryDirectory(prefix="aros-llvm-patch-test.") as temporary:
        root = Path(temporary)
        write_fixture(root)
        result = subprocess.run(
            ["patch", "-p1", "--dry-run", "--batch", "--silent"],
            cwd=root / "llvm-11.0.0.src",
            input=selected_hunks(patch.decode("utf-8")),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    if result.returncode != 0:
        raise SystemExit(
            "locked LLVM patch does not apply to its exact fixture:\n"
            + (result.stdout + result.stderr).strip()
        )

    print("LLVM 11 AROS patch identity and triple-hunk applicability passed")


if __name__ == "__main__":
    main()
