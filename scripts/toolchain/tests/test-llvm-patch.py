#!/usr/bin/env python3
"""Verify that the locked LLVM 11 AROS patch is accepted by `patch -p1`."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path


SOURCE_ROOT = Path(__file__).resolve().parents[3]
PATCH = SOURCE_ROOT / "tools" / "crosstools" / "llvm" / "llvm-11.0.0.src-aros.diff"


def padded_lines(count: int) -> list[str]:
    return ["// fixture padding\n"] * count


def write_fixture(root: Path) -> None:
    tree = root / "llvm-11.0.0.src"
    fixtures: dict[str, list[str]] = {}

    triple_header = padded_lines(500)
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

    x86_header = padded_lines(24)
    x86_header[12:17] = [
        "#ifndef LLVM_LIB_TARGET_X86_MCTARGETDESC_X86MCTARGETDESC_H\n",
        "#define LLVM_LIB_TARGET_X86_MCTARGETDESC_X86MCTARGETDESC_H\n",
        "\n",
        "#include <memory>\n",
        "#include <string>\n",
    ]
    fixtures["lib/Target/X86/MCTargetDesc/X86MCTargetDesc.h"] = x86_header

    for relative, lines in fixtures.items():
        destination = tree / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text("".join(lines), encoding="utf-8")


def main() -> None:
    if shutil.which("patch") is None:
        raise SystemExit("LLVM patch contract test requires patch")

    with tempfile.TemporaryDirectory(prefix="aros-llvm-patch-test.") as temporary:
        root = Path(temporary)
        write_fixture(root)
        result = subprocess.run(
            ["patch", "-p1", "--dry-run", "--batch", "--silent"],
            cwd=root / "llvm-11.0.0.src",
            input=PATCH.read_text(encoding="utf-8"),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    if result.returncode != 0:
        raise SystemExit(
            "locked LLVM patch does not apply to its exact fixture:\n"
            + (result.stdout + result.stderr).strip()
        )

    print("LLVM 11 AROS patch applicability contract passed")


if __name__ == "__main__":
    main()
