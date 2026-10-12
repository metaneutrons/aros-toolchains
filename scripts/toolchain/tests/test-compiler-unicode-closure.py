#!/usr/bin/env python3
"""Bind every selected compiler's Unicode input to the owning source recipe.

Offline metadata probes only. The actual Makefile/fetch-bridge replay is a
separate native test; these probes neither download nor execute source code.
"""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import re
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[3]


def declaration(makefile: str, name: str) -> str:
    values = re.findall(rf"^{re.escape(name)}\s*:=\s*(\S+)\s*$", makefile, re.MULTILINE)
    if len(values) != 1:
        raise ValueError("Unicode source declaration must occur exactly once")
    return values[0]


def validate(selection: dict, locks: dict[str, dict], makefile: str) -> None:
    version = declaration(makefile, "GENCTBL_UCD_VERSION")
    digest = declaration(makefile, "GENCTBL_UCD_SHA256")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("Unicode source version or digest is malformed")
    for group in selection["groups"]:
        entries = [entry for entry in locks[group["id"]]["sources"]
                   if entry["component"] == "unicode-ucd"]
        expected = {
            "component": "unicode-ucd", "version": version,
            "purpose": "target-build-dependency", "filename": "UCD.zip",
            "url": f"https://www.unicode.org/Public/{version}/ucd/UCD.zip",
            "sha256": digest, "size": 9020779,
        }
        if entries != [expected]:
            raise ValueError("compiler Unicode lock differs from the exact source declaration")


class CompilerUnicodeClosureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        source = Path(os.environ["AROS_TEST_V2_SOURCE_ROOT"]).resolve()
        cls.selection = json.loads((ROOT / "toolchains/compiler-sdk-ci-selection-v2.json").read_text())
        commit = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
        if commit != cls.selection["source_commit"]:
            raise ValueError("Unicode test source must match the selected compiler and SDK commit")
        cls.makefile = (source / "tools/genctbl/Makefile").read_text()
        cls.locks = {group["id"]: json.loads((ROOT / group["source_lock"]).read_text())
                     for group in cls.selection["groups"]}

    def test_all_selected_compiler_groups_bind_the_source_unicode_archive(self) -> None:
        validate(self.selection, self.locks, self.makefile)

    def test_missing_llvm_unicode_entry_reproduces_the_incomplete_closure(self) -> None:
        locks = copy.deepcopy(self.locks)
        locks["llvm"]["sources"] = [entry for entry in locks["llvm"]["sources"]
                                    if entry["component"] != "unicode-ucd"]
        with self.assertRaisesRegex(ValueError, "compiler Unicode lock differs"):
            validate(self.selection, locks, self.makefile)

    def test_duplicate_or_substituted_unicode_entries_are_rejected(self) -> None:
        for group in self.selection["groups"]:
            for mutation in ("duplicate", "version", "purpose", "filename", "url", "sha256", "size", "patch"):
                with self.subTest(group=group["id"], mutation=mutation):
                    locks = copy.deepcopy(self.locks)
                    sources = locks[group["id"]]["sources"]
                    entry = next(entry for entry in sources if entry["component"] == "unicode-ucd")
                    if mutation == "duplicate":
                        sources.append(copy.deepcopy(entry))
                    elif mutation == "size":
                        entry[mutation] += 1
                    elif mutation == "sha256":
                        entry[mutation] = "0" * 64
                    else:
                        entry[mutation] = "substituted"
                    with self.assertRaisesRegex(ValueError, "compiler Unicode lock differs"):
                        validate(self.selection, locks, self.makefile)

    def test_changed_or_duplicate_source_declarations_are_rejected(self) -> None:
        for makefile in (
            self.makefile.replace("GENCTBL_UCD_VERSION := 16.0.0", "GENCTBL_UCD_VERSION := 99.0.0"),
            self.makefile + "\nGENCTBL_UCD_VERSION := 16.0.0\n",
        ):
            with self.subTest(makefile=makefile[-80:]), self.assertRaises(ValueError):
                validate(self.selection, self.locks, makefile)


if __name__ == "__main__":
    unittest.main(verbosity=2)
