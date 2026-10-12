#!/usr/bin/env python3
"""Pure preparation policy tests; native source verification remains separate."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location(
    "prepare_sdk_inputs", ROOT / "scripts/toolchain/prepare-compiler-sdk-inputs-v2.py"
)
MODULE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(MODULE)


class PreparationPolicyTests(unittest.TestCase):
    def selection(self):
        return json.loads((ROOT / "toolchains/compiler-sdk-ci-selection-v2.json").read_bytes())

    def test_committed_selection_is_structurally_valid(self):
        selected = MODULE.validate_selection(self.selection())
        self.assertEqual(len(selected["groups"]), 2)
        self.assertEqual(len(selected["sdks"]), 4)

    def test_duplicate_json_keys_and_nonfinite_numbers_are_rejected(self):
        for raw in (b'{"id":1,"id":2}', b'{"epoch":NaN}'):
            with self.assertRaises(MODULE.PreparationError):
                MODULE.parse_json(raw, "selection")

    def test_selection_rejects_schema_pins_unknown_fields_and_unsafe_paths(self):
        probes = []
        for key, value in (("schema", "legacy"), ("source_commit", "0" * 40),
                           ("tools_commit", "main"), ("unexpected", "ignored")):
            probe = self.selection()
            probe[key] = value
            probes.append(probe)
        for relative in ("/tmp/profiles.json", "toolchains/../profiles.json", "toolchains//profiles.json"):
            probe = self.selection()
            probe["groups"][0]["profiles"] = relative
            probes.append(probe)
        for probe in probes:
            with self.assertRaises(MODULE.PreparationError):
                MODULE.validate_selection(probe)

    def test_sdk_epoch_and_group_associations_are_explicit(self):
        for epoch in (True, -1, MODULE.MAX_SOURCE_DATE_EPOCH + 1):
            probe = self.selection()
            probe["sdks"][0]["source_date_epoch"] = epoch
            with self.assertRaises(MODULE.PreparationError):
                MODULE.validate_selection(probe)
        probe = self.selection()
        probe["sdks"][0]["compiler_profiles"][0]["group_id"] = "unselected"
        with self.assertRaises(MODULE.PreparationError):
            MODULE.validate_selection(probe)
        probe = self.selection()
        probe["sdks"].append(copy.deepcopy(probe["sdks"][0]))
        with self.assertRaises(MODULE.PreparationError):
            MODULE.validate_selection(probe)

    def test_existing_output_and_symbolic_links_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            existing = root / "existing"
            existing.mkdir()
            with self.assertRaises(MODULE.PreparationError):
                MODULE.absent_destination(str(existing), "output")
            linked = root / "linked"
            linked.symlink_to(existing, target_is_directory=True)
            with self.assertRaises(MODULE.PreparationError):
                MODULE.absolute_existing(str(linked), "source", "directory")
            self.assertEqual(MODULE.absent_destination(str(root / "fresh"), "output"), root / "fresh")


if __name__ == "__main__":
    unittest.main()
