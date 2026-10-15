#!/usr/bin/env python3
"""Bind each selected compiler lock to required Python imports in configure.in.

Offline metadata probes only. The extraction deliberately recognizes literal
PC_PYTHON_CHECK_MODULE invocations at shell if/fi nesting depth zero. It is a
targeted text check, not a complete M4 or shell parser.
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
SELECTION = "toolchains/compiler-sdk-ci-selection-v2.json"
MODULE_CALL = re.compile(
    r"\bPC_PYTHON_CHECK_MODULE\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,"
)


def required_python_modules(configure_in: str) -> list[str]:
    active_lines = [
        line
        for line in configure_in.splitlines()
        if re.match(r"^[ \t]*dnl(?:[ \t]|$)", line) is None
    ]
    modules = []
    conditional_depth = 0
    for line in active_lines:
        if re.match(r"^[ \t]*fi(?:[ \t;]|$)", line):
            conditional_depth -= 1
            if conditional_depth < 0:
                raise ValueError("configure.in shell conditional nesting is unbalanced")
        if conditional_depth == 0:
            modules.extend(MODULE_CALL.findall(line))
        if re.match(r"^[ \t]*if\b", line):
            conditional_depth += 1
    if conditional_depth != 0:
        raise ValueError("configure.in shell conditional nesting is unbalanced")
    if not modules:
        raise ValueError("configure.in has no unconditional literal PC_PYTHON_CHECK_MODULE imports")
    return modules


def validate(selection: dict, locks: dict[str, dict], configure_in: str) -> None:
    modules = required_python_modules(configure_in)
    groups = selection.get("groups")
    if not isinstance(groups, list) or not groups:
        raise ValueError("compiler selection must include selected source groups")

    for group in groups:
        group_id = group.get("id")
        lock = locks.get(group_id)
        if not isinstance(lock, dict):
            raise ValueError(f"compiler source lock is missing for selected group {group_id!r}")
        packages = lock.get("host_python_packages")
        if not isinstance(packages, list):
            raise ValueError(f"compiler Python package list is missing for selected group {group_id!r}")

        for module in modules:
            matches = [package for package in packages if package.get("name") == module]
            if len(matches) != 1:
                raise ValueError(
                    f"compiler group {group_id!r} must lock Python module {module!r} exactly once"
                )


class CompilerPythonClosureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        source = Path(os.environ["AROS_TEST_V2_SOURCE_ROOT"]).resolve()
        cls.selection = json.loads((ROOT / SELECTION).read_text(encoding="utf-8"))
        commit = subprocess.check_output(
            ["git", "-C", str(source), "rev-parse", "HEAD"], text=True
        ).strip()
        if commit != cls.selection["source_commit"]:
            raise ValueError("Python closure test source must match the selected compiler and SDK commit")
        cls.configure_in = (source / "configure.in").read_text(encoding="utf-8")
        cls.modules = required_python_modules(cls.configure_in)
        cls.locks = {
            group["id"]: json.loads((ROOT / group["source_lock"]).read_text(encoding="utf-8"))
            for group in cls.selection["groups"]
        }

    def test_selected_compiler_locks_include_each_required_python_module_once(self) -> None:
        validate(self.selection, self.locks, self.configure_in)

    def test_rejects_missing_llvm_yaml_dependency(self) -> None:
        locks = copy.deepcopy(self.locks)
        locks["llvm"]["host_python_packages"] = [
            package
            for package in locks["llvm"]["host_python_packages"]
            if package["name"] != "yaml"
        ]
        with self.assertRaisesRegex(ValueError, "Python module 'yaml'.*exactly once"):
            validate(self.selection, locks, self.configure_in)

    def test_rejects_each_missing_required_module_from_each_selected_group(self) -> None:
        for group in self.selection["groups"]:
            for module in self.modules:
                with self.subTest(group=group["id"], module=module):
                    locks = copy.deepcopy(self.locks)
                    packages = locks[group["id"]]["host_python_packages"]
                    locks[group["id"]]["host_python_packages"] = [
                        package for package in packages if package["name"] != module
                    ]
                    with self.assertRaisesRegex(ValueError, "exactly once"):
                        validate(self.selection, locks, self.configure_in)

    def test_rejects_duplicate_required_modules_in_each_selected_group(self) -> None:
        for group in self.selection["groups"]:
            for module in self.modules:
                with self.subTest(group=group["id"], module=module):
                    locks = copy.deepcopy(self.locks)
                    packages = locks[group["id"]]["host_python_packages"]
                    package = next(item for item in packages if item["name"] == module)
                    packages.append(copy.deepcopy(package))
                    with self.assertRaisesRegex(ValueError, "exactly once"):
                        validate(self.selection, locks, self.configure_in)

    def test_rejects_new_literal_import_added_to_configure(self) -> None:
        changed_configure = (
            self.configure_in
            + "\nPC_PYTHON_CHECK_MODULE(unlocked_test_module, [], [AC_MSG_FAILURE([missing])])\n"
        )
        with self.assertRaisesRegex(ValueError, "unlocked_test_module.*exactly once"):
            validate(self.selection, self.locks, changed_configure)

    def test_ignores_dnl_commented_module_call(self) -> None:
        commented_configure = (
            self.configure_in
            + "\ndnl PC_PYTHON_CHECK_MODULE(commented_test_module, [], [AC_MSG_FAILURE([missing])])\n"
        )
        self.assertEqual(required_python_modules(commented_configure), self.modules)

    def test_rejects_configure_without_literal_module_imports(self) -> None:
        with self.assertRaisesRegex(ValueError, "no unconditional literal"):
            required_python_modules("dnl PC_PYTHON_CHECK_MODULE(commented_module, [], [])\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
