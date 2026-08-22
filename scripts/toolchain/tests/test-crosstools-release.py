#!/usr/bin/env python3
"""Contract-test the opt-in, minimal crosstools release MetaMake closure.

The producer must build the compiler's C/C++ runtime without silently pulling
the general Ports or target-SDK closure.  This test runs GenMF, then follows
the generated ``#MM`` declarations exactly as MetaMake does for the relevant
targets.  It deliberately checks both the release graph and the unchanged
normal graph.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path


SOURCE_ROOT = Path(__file__).resolve().parents[3]
GENMF = SOURCE_ROOT / "tools" / "genmf" / "genmf.py"
VARIABLE = re.compile(r"\$\(([^()]+)\)")


def generate(source: Path, destination: Path) -> None:
    subprocess.run(
        [sys.executable, "-B", str(GENMF), str(SOURCE_ROOT / "config" / "make.tmpl"), str(source), str(destination)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def expand(text: str, variables: dict[str, str]) -> str:
    return VARIABLE.sub(lambda match: variables.get(match.group(1), match.group(0)), text)


def parse_meta_rules(path: Path, variables: dict[str, str]) -> dict[str, list[str]]:
    """Return the dependency declarations after GenMF/variable expansion.

    This is intentionally small: MetaMake's relevant contract is that every
    ``#MM`` declaration adds its dependencies to the named target.  Physical
    Make recipes are not needed to establish the producer closure.
    """

    lines = path.read_text(encoding="iso-8859-1").splitlines()
    rules: dict[str, list[str]] = {}
    line_number = 0
    while line_number < len(lines):
        line = lines[line_number]
        if not line.startswith("#MM"):
            line_number += 1
            continue

        prefix_length = 4 if line.startswith("#MM-") else 3
        declaration = line[prefix_length:].strip()
        while declaration.endswith("\\"):
            declaration = declaration[:-1].rstrip()
            line_number += 1
            if line_number >= len(lines) or not lines[line_number].startswith("#MM"):
                raise AssertionError(f"unterminated MetaMake declaration in {path}")
            continuation = lines[line_number]
            continuation_prefix = 4 if continuation.startswith("#MM-") else 3
            declaration += " " + continuation[continuation_prefix:].strip()

        if ":" in declaration:
            targets, dependencies = declaration.split(":", 1)
            dependency_names = expand(dependencies, variables).split()
            for target in expand(targets, variables).split():
                target_dependencies = rules.setdefault(target, [])
                for dependency in dependency_names:
                    if dependency not in target_dependencies:
                        target_dependencies.append(dependency)
        line_number += 1
    return rules


def merge_rules(*rule_sets: dict[str, list[str]]) -> dict[str, list[str]]:
    merged: dict[str, list[str]] = {}
    for rule_set in rule_sets:
        for target, dependencies in rule_set.items():
            target_dependencies = merged.setdefault(target, [])
            for dependency in dependencies:
                if dependency not in target_dependencies:
                    target_dependencies.append(dependency)
    return merged


def trace(rules: dict[str, list[str]], target: str) -> set[str]:
    reached: set[str] = set()
    todo = [target]
    while todo:
        current = todo.pop()
        if current in reached:
            continue
        reached.add(current)
        todo.extend(rules.get(current, []))
    return reached


def require_contains(values: set[str] | list[str], expected: str, label: str) -> None:
    if expected not in values:
        raise AssertionError(f"{label} is missing {expected}: {sorted(values)}")


def main() -> None:
    variables = {
        "AROS_TOOLCHAIN": "llvm",
        "AROS_TARGET_CPU": "x86_64",
        "TARGET_LIBATOMIC": "yes",
        "CROSSTOOLS_PORTS_INCLUDES": "",
        "ARCH": "pc",
        "CPU": "x86_64",
        "FAMILY": "standalone",
        "AROS_TARGET_VARIANT": "",
    }

    with tempfile.TemporaryDirectory(prefix="aros-crosstools-release-test.") as temporary:
        temporary_path = Path(temporary)
        generated_llvm = temporary_path / "llvm.mmakefile"
        generated_atomic = temporary_path / "atomic.mmakefile"
        generate(SOURCE_ROOT / "tools" / "crosstools" / "llvm" / "mmakefile.src", generated_llvm)
        generate(SOURCE_ROOT / "compiler" / "atomic" / "mmakefile.src", generated_atomic)

        rules = merge_rules(
            parse_meta_rules(SOURCE_ROOT / "tools" / "crosstools" / "mmakefile.src", variables),
            parse_meta_rules(generated_llvm, variables),
            parse_meta_rules(generated_atomic, variables),
            parse_meta_rules(SOURCE_ROOT / "compiler" / "include" / "mmakefile.src", variables),
        )

    # The producer aggregate never uses the regular generic CPU aggregate.
    release_aggregate = set(rules["toolchain-linklibs-release"])
    for required in {
        "linklibs-atomic",
        "toolchain-linklibs-llvm-release-x86_64",
        "toolchain-linklibs-llvm-release",
    }:
        require_contains(release_aggregate, required, "release aggregate")
    if "toolchain-linklibs-x86_64" in release_aggregate:
        raise AssertionError("release aggregate accidentally uses the generic CPU linklib closure")

    # `%build_linklib` hits includes-generate-deps directly; release mode must
    # retain generated architecture headers while suppressing Ports only there.
    include_dependencies = set(rules["includes-generate-deps"])
    assert include_dependencies == {
        "includes-copy",
        "includes-pc-x86_64",
        "includes-standalone-x86_64",
    }, include_dependencies
    if "ports-includes" in trace(rules, "linklibs-atomic"):
        raise AssertionError("release linklib trace reaches ports-includes")

    # The generated release CMake targets use only setup/includes, whereas the
    # upstream target remains broad.  This catches accidental macro-default
    # regressions in config/make-cmake.tmpl.
    release_compiler_rt = set(rules["crosstools-compiler-rt-release"])
    if "core-linklibs" in release_compiler_rt:
        raise AssertionError("release compiler-rt target reaches core-linklibs")
    require_contains(release_compiler_rt, "includes", "release compiler-rt target")
    require_contains(release_compiler_rt, "tools-crosstools-runtime-linklibs", "release compiler-rt target")
    normal_compiler_rt = set(rules["crosstools-compiler-rt"])
    require_contains(normal_compiler_rt, "core-linklibs", "normal compiler-rt target")

    # The CMake configure node itself must wait for the installed C++ runtime;
    # otherwise parallel make can configure/link libunwind too early.
    unwind_cmake = set(rules["crosstools-libunwind-release-cmake"])
    for required in {
        "crosstools-libunwind-setup",
        "tools-crosstools-llvm-toolchain",
        "tools-crosstools-llvm-libcxx-release",
        "tools-crosstools-llvm-libcxxabi-release",
    }:
        require_contains(unwind_cmake, required, "release libunwind CMake target")

    # libc++abi's normal CMake compiler probe would otherwise attempt a target
    # executable link before the deliberately minimal release SDK is complete.
    # Keep it static just like libc++, libunwind, and compiler-rt.
    llvm_source = (SOURCE_ROOT / "tools" / "crosstools" / "llvm" / "mmakefile.src").read_text(
        encoding="utf-8"
    )
    libcxxabi_options_start = llvm_source.index("LLVM_LIBCXXABI_CMAKEOPTIONS :=")
    libcxxabi_options_end = llvm_source.index("LLVM_LIBCXX_CMAKEOPTIONS :=", libcxxabi_options_start)
    libcxxabi_options = llvm_source[libcxxabi_options_start:libcxxabi_options_end]
    assert "-DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY" in libcxxabi_options

    # Keep the locked LLVM patch consumable by the host's patch utility. The
    # X86 include hunk needs ordinary leading context on macOS; a malformed
    # four-plus new-file header makes that hunk fail after source extraction.
    llvm_patch = (SOURCE_ROOT / "tools" / "crosstools" / "llvm" / "llvm-11.0.0.src-aros.diff").read_text(
        encoding="utf-8"
    )
    assert "\n++++ " not in llvm_patch
    assert re.search(
        r"^\+\+\+ llvm-11\.0\.0\.src\.aros/lib/Target/X86/MCTargetDesc/X86MCTargetDesc\.h\t.*\n"
        r"@@ -13,5 \+13,6 @@\n"
        r" #ifndef LLVM_LIB_TARGET_X86_MCTARGETDESC_X86MCTARGETDESC_H\n"
        r" #define LLVM_LIB_TARGET_X86_MCTARGETDESC_X86MCTARGETDESC_H\n"
        r"-\n"
        r"\+\n"
        r"\+#include <cstdint>\n",
        llvm_patch,
        re.MULTILINE,
    )

    # Compiler-rt supplies ARM/AArch64 builtins, so the producer must not
    # reach linklibs-arm/SoftFloat. x86_64 keeps its historical 32-bit runtime.
    assert rules["toolchain-linklibs-llvm-release-arm"] == []
    assert rules["toolchain-linklibs-llvm-release-armeb"] == []
    assert rules["toolchain-linklibs-llvm-release-aarch64"] == []
    assert rules["toolchain-linklibs-llvm-release-x86_64"] == [
        "crosstools-compiler-rt32-release"
    ]
    for target in (
        "toolchain-linklibs-llvm-release-arm",
        "toolchain-linklibs-llvm-release-armeb",
        "toolchain-linklibs-llvm-release-aarch64",
    ):
        forbidden = {"linklibs-arm", "linklibs-armeb", "linklibs-softfloat"}
        assert not (trace(rules, target) & forbidden), (target, trace(rules, target) & forbidden)

    # Wire the configure-time switch and producer entry point together. The
    # regular target remains available for fully compatible upstream builds.
    configure_source = (SOURCE_ROOT / "configure.in").read_text(encoding="utf-8")
    assert "--enable-toolchain-release" in configure_source
    target_config = (SOURCE_ROOT / "config" / "target.cfg.in").read_text(encoding="iso-8859-1")
    assert "AROS_TOOLCHAIN_RELEASE" in target_config
    assert "CROSSTOOLS_PORTS_INCLUDES" in target_config
    makefile_source = (SOURCE_ROOT / "Makefile.in").read_text(encoding="iso-8859-1")
    assert "crosstools-release : crosstools-toolchain features" in makefile_source
    assert "toolchain-linklibs-release" in makefile_source
    release_script = (SOURCE_ROOT / "scripts" / "toolchain" / "build-release.sh").read_text(encoding="utf-8")
    assert "--enable-toolchain-release" in release_script
    assert "crosstools-release" in release_script

    print("crosstools-release MetaMake graph contract passed")


if __name__ == "__main__":
    main()
