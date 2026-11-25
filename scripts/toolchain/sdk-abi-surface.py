#!/usr/bin/env python3
"""Target-compiled AROS SDK ABI/API observation; not complete ABI certification."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

SCHEMA = "aros-sdk-abi-observation-v1"
COMPARE_SCHEMA = "aros-sdk-abi-comparison-v1"
STRUCTS = {
    "List": ("struct List", ("lh_Head", "lh_Tail", "lh_TailPred", "lh_Type", "l_pad")),
    "Node": ("struct Node", ("ln_Succ", "ln_Pred", "ln_Type", "ln_Pri", "ln_Name")),
    "MinNode": ("struct MinNode", ("mln_Succ", "mln_Pred")),
}
FD_RE = re.compile(r"^([A-Za-z_][\w@$?]*)\((.*?)\)\((.*?)\)\s*$")


class AbiError(ValueError):
    pass


def _run(argv: list[str]) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(argv, capture_output=True, check=False, timeout=90)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AbiError(f"tool failed: {argv[0]}") from exc


def _flags(triple: str | None, abi: Mapping[str, Any]) -> list[str]:
    gnu = triple == "riscv-aros"
    flags = [] if gnu else ([f"--target={triple}"] if triple else [])
    if gnu:
        for key, prefix in (("isa", "-march="), ("abi", "-mabi="), ("code_model", "-mcmodel=")):
            if isinstance(abi.get(key), str) and abi[key]:
                flags.append(prefix + abi[key])
        flags.append("-mstrict-align")
    else:
        for key, prefix in (
            ("compiler_arch", "-march="),
            ("compiler_cpu", "-mcpu="),
            ("compiler_fpu", "-mfpu="),
            ("compiler_code_model", "-mcmodel="),
        ):
            if isinstance(abi.get(key), str) and abi[key]:
                flags.append(prefix + abi[key])
        if isinstance(abi.get("float_abi"), str) and abi["float_abi"]:
            flags.append("-mfloat-abi=" + abi["float_abi"])
        if abi.get("compiler_red_zone") is False:
            flags.append("-mno-red-zone")
        if abi.get("compiler_pic") is False:
            flags.append("-fno-pic")
        if abi.get("compiler_pie") is False:
            flags.append("-fno-pie")
    return flags


def _probe_source() -> str:
    lines = [
        "#include <stddef.h>",
        "#include <exec/lists.h>",
        "#include <exec/nodes.h>",
        "#define U __attribute__((used))",
    ]
    for name, (ctype, fields) in STRUCTS.items():
        lines += [
            f"unsigned char abi_{name}_size[sizeof({ctype})] U;",
            f"unsigned char abi_{name}_align[__alignof__({ctype}) + 1] U;",
        ]
        lines += [
            f"unsigned char abi_{name}_off_{i}[offsetof({ctype}, {field}) + 1] U;"
            for i, field in enumerate(fields)
        ]
    return "\n".join(lines) + "\n"


def _sizes(tool: str, obj: Path) -> dict[str, int]:
    result = _run([tool, "-Ws", str(obj)])
    if result.returncode:
        raise AbiError(result.stderr.decode(errors="replace")[-1000:])
    found = {}
    for line in result.stdout.decode(errors="replace").splitlines():
        f = line.split()
        if len(f) >= 8 and f[0].rstrip(":").isdigit() and f[-1].startswith("abi_"):
            try:
                found[f[-1]] = int(f[2])
            except ValueError:
                pass
    return found


def _layout(root: Path, compiler: Path, triple: str | None, abi: Mapping[str, Any]) -> dict[str, Any]:
    tool = (
        next(
            (
                str(compiler.with_name(n))
                for n in ("llvm-readelf", "readelf")
                if compiler.with_name(n).is_file()
            ),
            None,
        )
        or shutil.which("llvm-readelf")
        or shutil.which("readelf")
    )
    flags = _flags(triple, abi)
    if not tool:
        return {"status": "inconclusive", "reason": "readelf-unavailable", "flags": flags}
    with tempfile.TemporaryDirectory(prefix="aros-sdk-abi-") as td:
        src, obj = Path(td) / "probe.c", Path(td) / "probe.o"
        src.write_text(_probe_source(), encoding="utf-8")
        result = _run(
            [
                str(compiler),
                *flags,
                f"--sysroot={root}",
                "-x",
                "c",
                "-fno-common",
                "-O0",
                "-I",
                str(root / "include"),
                "-c",
                str(src),
                "-o",
                str(obj),
            ]
        )
        if result.returncode:
            return {
                "status": "inconclusive",
                "reason": "compile-failed",
                "flags": flags,
                "diagnostic": result.stderr.decode(errors="replace")[-2000:],
            }
        try:
            sizes = _sizes(tool, obj)
        except AbiError as exc:
            return {
                "status": "inconclusive",
                "reason": "readelf-failed",
                "flags": flags,
                "diagnostic": str(exc),
            }
        raw = obj.read_bytes()
        cls = raw[4] if len(raw) >= 20 and raw[:4] == b"\x7fELF" else None
        machine = int.from_bytes(raw[18:20], "little") if cls else None
        expected_cls = {32: 1, 64: 2}.get(abi.get("pointer_width"))
        expected_machine = abi.get("elf_machine")
        if triple == "riscv-aros":
            expected_cls, expected_machine = 1, 243
        if cls not in (1, 2) or raw[5] != 1 or expected_cls != cls or expected_machine != machine:
            return {
                "status": "inconclusive",
                "reason": "object-elf-identity-mismatch",
                "flags": flags,
                "object": {"elf_class": cls, "elf_machine": machine},
            }
    records = {}
    for name, (_, fields) in STRUCTS.items():
        size, align = sizes.get(f"abi_{name}_size"), sizes.get(f"abi_{name}_align")
        offsets = [sizes.get(f"abi_{name}_off_{i}") for i in range(len(fields))]
        if size is None or align is None or any(x is None for x in offsets):
            return {"status": "inconclusive", "reason": f"layout-symbols-incomplete:{name}", "flags": flags}
        records[name] = {
            "size": size,
            "alignment": align - 1,
            "members": dict(zip(fields, (x - 1 for x in offsets))),
        }
    return {"status": "observed", "flags": flags, "records": records}


def _defines(root: Path) -> dict[str, Any]:
    libraries, missing, examples = {}, 0, []
    for path in sorted((root / "include" / "defines").glob("*.h")):
        if path.name.endswith("_LVO.h"):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        lvos = {n: int(v) for n, v in re.findall(r"^\s*#define\s+LVO(\w+)\s+(\d+)\s*$", text, re.MULTILINE)}
        # Parse each call once. Calls with an unsupported signature leave an explicit gap.
        calls = {}
        for call in re.finditer(r"\bAROS_LC(\d+)(?:NR)?\([^,;]+,\s*(\w+)\s*,([^;]*?)\);", text):
            arity, name, arguments = call.groups()
            registers = re.findall(r",\s*([AD]\d+)\s*\)", arguments)
            if len(registers) == int(arity):
                calls[name] = (int(arity), [reg.lower() for reg in registers])
        rows = []
        for name, slot in lvos.items():
            if name not in calls:
                missing += 1
                if len(examples) < 4:
                    examples.append(f"{path.stem}:{name}")
                continue
            arity, registers = calls[name]
            rows.append({"name": name, "offset": slot * 6, "arity": arity, "registers": registers})
        if rows:
            libraries[path.stem] = rows
    reasons = ([f"defines-signatures-incomplete:{missing}:{','.join(examples)}"] if missing else []) + (
        [] if libraries else ["defines-surface-missing"]
    )
    return {
        "status": "observed" if libraries and not reasons else "inconclusive",
        "source": "defines",
        "libraries": libraries,
        "coverage": {
            "libraries": len(libraries),
            "vectors": sum(map(len, libraries.values())),
            "missing_signatures": missing,
        },
        "reasons": reasons,
    }


def _vectors(root: Path) -> dict[str, Any]:
    paths, libraries, bad = sorted((root / "SDK" / "fd").glob("*.fd")), {}, []
    for path in paths:
        if not path.is_file():
            continue
        bias, public, rows = None, False, []
        try:
            for lineno, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                line = line.strip()
                if not line or line.startswith(("*", "##base ")) or line == "##end":
                    continue
                if line.startswith("##bias"):
                    bias = int(line[6:].strip(), 0)
                elif line == "##public":
                    public = True
                elif line == "##private":
                    public = False
                else:
                    match = FD_RE.match(line)
                    if not match:
                        bad.append(f"unrecognised-fd-entry:{path.name}:{lineno}")
                        continue
                    name, args, regs = match.groups()
                    if bias is None:
                        bad.append(f"fd-incomplete:{path.name}:{lineno}")
                    if public and name != "private":
                        rows.append(
                            {
                                "name": name,
                                "offset": bias,
                                "arity": len([x for x in args.split(",") if x.strip()]),
                                "registers": [
                                    x.strip().lower() for x in re.split(r"[,/]", regs) if x.strip()
                                ],
                            }
                        )
                    if bias is not None:
                        bias += 6
        except (OSError, ValueError) as exc:
            bad.append(f"fd-invalid:{path.name}:{exc}")
        if len({r["name"] for r in rows}) != len(rows):
            bad.append(f"duplicate-vector-name:{path.name}")
        libraries[path.stem.removesuffix("_lib")] = rows
    return (
        {
            "status": "observed" if paths and not bad else "inconclusive",
            "source": "fd",
            "libraries": libraries,
            "reasons": bad,
        }
        if paths
        else _defines(root)
    )


def capture(sdk_root: Path, compiler: Path, identity: dict) -> dict:
    """Capture fixed List/Node/MinNode layout and public vector slots."""
    root, compiler = Path(sdk_root).resolve(), Path(compiler).resolve()
    if not root.is_dir() or not compiler.is_file() or not isinstance(identity, dict):
        raise AbiError("SDK root, compiler and identity are required")
    triple, abi = identity["target"]["target_triple"], identity["target"]["abi"]
    layout, vectors = _layout(root, compiler, triple, abi), _vectors(root)
    reasons = list(vectors.get("reasons", []))
    if layout["status"] != "observed":
        reasons.append(layout["reason"])
    ident = {k: identity[k] for k in ("sdk_id", "version", "tree_sha256") if k in identity}
    ident.update({"target_triple": triple, "abi": abi})
    return {
        "schema": SCHEMA,
        "status": "observed" if not reasons else "inconclusive",
        "target": {"target_triple": triple, "abi": abi},
        "identity": ident,
        "layout": layout,
        "vectors": vectors,
        "reasons": reasons,
    }


def compare_surfaces(previous: dict | None, current: dict) -> dict:
    """Compare complete like-for-like observations; identity envelope changes are ignored."""
    if previous is None:
        return {
            "schema": COMPARE_SCHEMA,
            "status": "no-baseline",
            "reasons": [{"kind": "info", "reason": "no-baseline"}],
        }
    reasons: list[dict[str, Any]] = []
    old_target, new_target = previous["identity"], current["identity"]
    if old_target["target_triple"] != new_target["target_triple"]:
        reasons.append({"kind": "breaking", "reason": "target-triple-changed"})
    old_abi, new_abi = old_target["abi"], new_target["abi"]
    calling_convention = {"pointer_width", "elf_machine", "abi", "float_abi", "arm_vfp_args"}
    for key in sorted(old_abi.keys() | new_abi.keys()):
        if old_abi.get(key) != new_abi.get(key):
            kind = (
                "breaking"
                if key in old_abi and key in new_abi and key in calling_convention
                else "inconclusive"
            )
            reasons.append({"kind": kind, "reason": f"target-fact-changed:{key}"})
    old, new = previous.get("layout", {}), current.get("layout", {})
    if old.get("status") != "observed" or new.get("status") != "observed":
        reasons.append({"kind": "inconclusive", "reason": "layout-surface-incomplete"})
    else:
        for name, (_, fields) in STRUCTS.items():
            if name not in old.get("records", {}) or name not in new.get("records", {}):
                reasons.append({"kind": "breaking", "reason": f"layout-missing:{name}"})
                continue
            for key in ("size", "alignment"):
                if old["records"][name].get(key) != new["records"][name].get(key):
                    reasons.append({"kind": "breaking", "reason": f"{name}.{key}-changed"})
            for field in fields:
                if old["records"][name].get("members", {}).get(field) != new["records"][name].get(
                    "members", {}
                ).get(field):
                    reasons.append({"kind": "breaking", "reason": f"{name}.{field}-offset-changed"})
    old, new = previous.get("vectors", {}), current.get("vectors", {})
    if old.get("source") != new.get("source"):
        reasons.append({"kind": "inconclusive", "reason": "vector-evidence-source-changed"})
    elif old.get("status") != "observed" or new.get("status") != "observed":
        reasons.append({"kind": "inconclusive", "reason": "fd-surface-incomplete"})
    else:
        for library in sorted(set(old.get("libraries", {})) | set(new.get("libraries", {}))):
            if library not in new["libraries"]:
                reasons.append({"kind": "breaking", "reason": f"library-removed:{library}"})
                continue
            if library not in old["libraries"]:
                reasons.append({"kind": "safe", "reason": f"library-added:{library}"})
                continue
            before = {x["name"]: x for x in old["libraries"][library]}
            after = {x["name"]: x for x in new["libraries"][library]}
            for name in sorted(set(before) | set(after)):
                if name not in after:
                    reasons.append({"kind": "breaking", "reason": f"vector-removed:{library}:{name}"})
                elif name not in before:
                    reasons.append({"kind": "safe", "reason": f"vector-added:{library}:{name}"})
                elif any(before[name].get(k) != after[name].get(k) for k in ("offset", "arity", "registers")):
                    reasons.append({"kind": "breaking", "reason": f"vector-changed:{library}:{name}"})
    status = (
        "breaking"
        if any(x["kind"] == "breaking" for x in reasons)
        else "inconclusive"
        if any(x["kind"] == "inconclusive" for x in reasons)
        else "no-break-observed"
    )
    return {"schema": COMPARE_SCHEMA, "status": status, "reasons": reasons}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    observe = commands.add_parser("observe")
    observe.add_argument("--sdk", type=Path, required=True)
    observe.add_argument("--compiler", type=Path, required=True)
    observe.add_argument("--identity", type=Path, required=True)
    observe.add_argument("--output", type=Path, required=True)
    compare = commands.add_parser("compare")
    compare.add_argument("--previous", type=Path)
    compare.add_argument("--current", type=Path, required=True)
    compare.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    load = lambda p: json.loads(p.read_text(encoding="utf-8"))
    result = (
        capture(args.sdk, args.compiler, load(args.identity))
        if args.command == "observe"
        else compare_surfaces(load(args.previous) if args.previous else None, load(args.current))
    )
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AbiError, OSError, ValueError) as exc:
        raise SystemExit(f"sdk-abi-surface failed: {exc}") from exc
