from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("sdk_abi_surface", ROOT / "sdk-abi-surface.py")
assert spec and spec.loader
abi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(abi)


class SurfaceTests(unittest.TestCase):
    def sdk(self, root: Path, fd: str | None = None) -> Path:
        include = root / "include" / "exec"
        include.mkdir(parents=True)
        (include / "nodes.h").write_text(
            "#ifndef NODES_H\n#define NODES_H\n"
            "typedef unsigned char UBYTE; typedef signed char BYTE;\n"
            "struct Node { struct Node *ln_Succ, *ln_Pred; UBYTE ln_Type; BYTE ln_Pri; char *ln_Name; };\n"
            "struct MinNode { struct MinNode *mln_Succ, *mln_Pred; };\n#endif\n",
            encoding="utf-8",
        )
        (include / "lists.h").write_text(
            "#include <exec/nodes.h>\nstruct List { struct Node *lh_Head, *lh_Tail, *lh_TailPred; UBYTE lh_Type; UBYTE l_pad; };\n",
            encoding="utf-8",
        )
        if fd is not None:
            fd_root = root / "SDK" / "fd"
            fd_root.mkdir(parents=True)
            (fd_root / "exec_lib.fd").write_text(fd, encoding="utf-8")
        return root

    def identity(self, **extra: object) -> dict:
        result = {
            "sdk_id": "pc",
            "version": "one",
            "target": {
                "target_triple": "x86_64-unknown-linux-gnu",
                "abi": {"elf_machine": 62, "pointer_width": 64},
            },
        }
        result.update(extra)
        return result

    def tools(self) -> tuple[str, str] | None:
        homebrew = Path("/opt/homebrew/opt/llvm/bin")
        cc = (
            str(homebrew / "clang")
            if (homebrew / "clang").is_file()
            else shutil.which("clang") or shutil.which("cc")
        )
        sibling = Path(cc).with_name("llvm-readelf") if cc else Path()
        readelf = (
            str(sibling) if sibling.is_file() else shutil.which("llvm-readelf") or shutil.which("readelf")
        )
        return (cc, readelf) if cc and readelf else None

    def test_fixed_layout_probe_and_shadow_identity(self) -> None:
        tools = self.tools()
        if tools is None:
            self.skipTest("compiler/readelf unavailable")
        fd = "##bias 30\n##public\nFirst(old)(d0)\nSecond()()\n"
        with tempfile.TemporaryDirectory() as temporary:
            one = self.sdk(Path(temporary) / "one", fd)
            two = self.sdk(Path(temporary) / "two", fd.replace("old", "renamed"))
            before = abi.capture(one, Path(tools[0]), self.identity(tree_sha256="a"))
            after = abi.capture(two, Path(tools[0]), self.identity(tree_sha256="b"))
            self.assertEqual(before["layout"]["status"], "observed")
            self.assertEqual(set(before["layout"]["records"]), {"List", "Node", "MinNode"})
            self.assertEqual(before["vectors"]["libraries"]["exec"][0]["arity"], 1)
            self.assertEqual(abi.compare_surfaces(before, after)["status"], "no-break-observed")

    def test_changed_member_offset_is_a_break_even_with_unchanged_vectors(self):
        tools = self.tools()
        if tools is None:
            self.skipTest("compiler/readelf unavailable")
        with tempfile.TemporaryDirectory() as directory:
            root = self.sdk(Path(directory) / "sdk", "##bias 30\n##public\nFirst(a)(d0)\n")
            before = abi.capture(root, Path(tools[0]), self.identity())
            lists = root / "include/exec/lists.h"
            lists.write_text(lists.read_text().replace("*lh_Head, *lh_Tail", "*lh_Tail, *lh_Head"))
            after = abi.capture(root, Path(tools[0]), self.identity())
            comparison = abi.compare_surfaces(before, after)
            self.assertEqual(comparison["status"], "breaking")
            self.assertIn("List.lh_Head-offset-changed", [r["reason"] for r in comparison["reasons"]])

    def test_vector_renumber_and_register_change_breaks(self) -> None:
        old = "##bias 30\n##public\nFirst(a)(d0)\nSecond()()\n"
        new = "##bias 30\n##public\nFirst(a,b)(a0)\nInserted()()\nSecond()()\n"
        tools = self.tools()
        if tools is None:
            self.skipTest("compiler/readelf unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            before = abi.capture(self.sdk(Path(temporary) / "old", old), Path(tools[0]), self.identity())
            after = abi.capture(self.sdk(Path(temporary) / "new", new), Path(tools[0]), self.identity())
            result = abi.compare_surfaces(before, after)
            self.assertEqual(result["status"], "breaking")
            self.assertTrue(any("vector-changed" in row["reason"] for row in result["reasons"]))

    def test_incomplete_surface_and_no_baseline(self) -> None:
        tools = self.tools()
        if tools is None:
            self.skipTest("compiler/readelf unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            current = abi.capture(self.sdk(Path(temporary) / "sdk"), Path(tools[0]), self.identity())
            self.assertEqual(abi.compare_surfaces(None, current)["status"], "no-baseline")
            self.assertEqual(abi.compare_surfaces(current, current)["status"], "inconclusive")

    def test_generated_defines_are_a_vector_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.sdk(Path(temporary) / "sdk")
            defines = root / "include" / "defines"
            defines.mkdir()
            (defines / "exec.h").write_text(
                "#define LVOSupervisor 5\n"
                "AROS_LC1(IPTR, Supervisor, AROS_LCA(void *, (__arg1), A5), struct ExecBase *, 5, Exec);\n",
                encoding="utf-8",
            )
            result = abi._vectors(root)
            self.assertEqual(result["status"], "observed")
            self.assertEqual(result["libraries"]["exec"][0]["offset"], 30)
            self.assertEqual(result["libraries"]["exec"][0]["arity"], 1)

    def test_abi_fact_and_evidence_source_changes_are_not_silent(self) -> None:
        records = {name: {"size": 1, "alignment": 1, "members": {}} for name in abi.STRUCTS}
        base = {
            "identity": {"target_triple": "x", "abi": {"float_abi": "hard"}},
            "layout": {"status": "observed", "records": records},
            "vectors": {"status": "observed", "source": "fd", "libraries": {}},
        }
        changed = json.loads(json.dumps(base))
        changed["identity"]["abi"]["float_abi"] = "soft"
        self.assertEqual(abi.compare_surfaces(base, changed)["status"], "breaking")
        changed = json.loads(json.dumps(base))
        changed["vectors"]["source"] = "defines"
        self.assertEqual(abi.compare_surfaces(base, changed)["status"], "inconclusive")


if __name__ == "__main__":
    unittest.main()
