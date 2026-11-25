"""Exercise pre-build predictions independently of the later native readback."""

import argparse
import hashlib
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("observe", HERE / "sdk-reuse-observation.py")
observation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observation)
origin = observation.origin


class ReuseTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        env = patch.dict(
            os.environ,
            {
                "GITHUB_REPOSITORY": "aros/test",
                "GITHUB_REPOSITORY_ID": "1",
                "GITHUB_SHA": "a" * 40,
                "GITHUB_REF": "refs/heads/main",
                "GITHUB_RUN_ID": "3",
                "GITHUB_RUN_ATTEMPT": "1",
            },
        )
        env.start()
        self.addCleanup(env.stop)
        self.context = origin.context_from_environment(origin.SPLIT_SDK_WORKFLOW)

    def write(self, name, value):
        path = self.root / name
        raw = origin.canonical(value)
        path.write_bytes(raw)
        return path, hashlib.sha256(raw).hexdigest()

    def fixture(self, previous=None, fingerprint="1" * 64):
        source = dict(self.context, run_id=2, workflow=origin.SPLIT_COMPILER_WORKFLOW)
        compiler, compiler_sha = self.write("compiler", {"context": source, "manifest_sha256": "9" * 64})
        baseline, _ = self.write("baseline", previous)
        inputs, _ = self.write(
            "inputs", {"pc-x86_64": {"input_sha256": fingerprint, "components": {"compiler": fingerprint}}}
        )
        args = argparse.Namespace(
            inputs=inputs, baseline=baseline, compiler_manifest=compiler, compiler_summary_sha256=compiler_sha
        )
        plan_path, plan_sha = self.write("plan", observation.predict(args))
        identity = {"sdk_id": "pc-x86_64", "source": {"commit": "b" * 40}}
        sdk = {
            "sdk_id": "pc-x86_64",
            "tree_sha256": "2" * 64,
            "archive_sha256": "3" * 64,
            "identity": identity,
        }
        claim = {
            "sdk_id": "pc-x86_64",
            "host": "linux-x86_64",
            "group_id": "llvm",
            "target_profile": "pc-x86_64",
            "generation_record_sha256": "4" * 64,
            "sdk_link_receipt_sha256": "5" * 64,
        }
        evidence, _ = self.write(
            "evidence",
            {
                "operation": "verify-release-evidence",
                "sdk_count": 1,
                "sdks": [sdk],
                "sdk_generations": [claim],
            },
        )
        representative = self.root / "surfaces" / "sdk-surface-llvm-pc-x86_64-1"
        representative.mkdir(parents=True, exist_ok=True)
        surface = {
            "identity": identity,
            "tree_sha256": sdk["tree_sha256"],
            "generation_record_sha256": claim["generation_record_sha256"],
            "sdk_link_receipt_sha256": claim["sdk_link_receipt_sha256"],
            "surface": {},
            "consumer": {"receipt_sha256": claim["sdk_link_receipt_sha256"]},
        }
        self.write(representative / "pc-x86_64.json", surface)
        return argparse.Namespace(
            baseline=baseline,
            plan=plan_path,
            plan_sha256=plan_sha,
            evidence=evidence,
            surfaces=representative.parent,
        )

    def test_capture_uses_the_extracted_compiler_and_native_link_tree(self):
        selections = []
        for sdk, schema in (
            ("pc", "aros-llvm-sdk-generation-record-v1"),
            ("rv32", "aros-sdk-generation-record-v1"),
        ):
            selections.append(json.dumps({"id": sdk}))
            operation = self.root / ("sdk-" + sdk)
            operation.mkdir()
            self.write(
                operation / "generation.json",
                {
                    "schema": schema,
                    "identity": {"sdk_id": sdk},
                    "sdk_inventory_sha256": "2" * 64,
                    "sdk_link_receipt_sha256": "5" * 64,
                },
            )
        (self.root / "sdk-selections.jsonl").write_text("\n".join(selections))
        output = self.root / "captured"
        with (
            patch.object(observation.abi, "capture", return_value={"layouts": {}}) as measure,
            patch.object(observation.runtime, "retain", return_value={"sha256": "6" * 64}) as retain,
        ):
            observation.capture(argparse.Namespace(lane=self.root, output=output))
        for i, (sdk, family, report, driver) in enumerate(
            (
                ("pc", "llvm", "llvm-sdk-links", "bin/clang"),
                ("rv32", "gnu", "native-sdk-links", "riscv-aros-gcc"),
            )
        ):
            operation = self.root / ("sdk-" + sdk)
            self.assertEqual(
                measure.call_args_list[i].args,
                (
                    operation / "reports" / report / "relocated-sdk",
                    operation / "first" / driver,
                    {"sdk_id": sdk},
                ),
            )
            self.assertEqual(retain.call_args_list[i].args, (operation, family, "5" * 64))
            entry = json.loads((output / (sdk + ".json")).read_bytes())
            raw = (operation / "generation.json").read_bytes()
            self.assertEqual(entry["generation_record_sha256"], hashlib.sha256(raw).hexdigest())

    def test_rejects_swapped_generation_receipt_and_missing_surface(self):
        args = self.fixture()
        (path,) = args.surfaces.glob("*/*.json")
        surface = json.loads(path.read_bytes())
        for field in ("tree_sha256", "sdk_link_receipt_sha256", "generation_record_sha256"):
            self.write(path, dict(surface, **{field: "9" * 64}))
            with self.subTest(field=field), self.assertRaisesRegex(origin.OriginError, "native evidence"):
                observation.observe(args)
        path.unlink()
        with self.assertRaisesRegex(origin.OriginError, "missing SDK ABI"):
            observation.observe(args)

    def test_measurement_from_a_different_lane_artifact_is_rejected(self):
        args = self.fixture()
        (directory,) = args.surfaces.iterdir()
        directory.rename(args.surfaces / "sdk-surface-llvm-other-1")
        with self.assertRaisesRegex(origin.OriginError, "native generation lane"):
            observation.observe(args)

    def test_bootstrap_repeated_and_changed_inputs(self):
        comparator = patch.object(
            observation.abi, "compare_surfaces", return_value={"status": "inconclusive"}
        )
        comparator.start()
        self.addCleanup(comparator.stop)
        first = observation.observe(self.fixture())
        self.assertEqual(first["targets"]["pc-x86_64"]["outcome"], "first-observation")
        previous = dict(first, context=dict(self.context, run_id=1))
        for key, old_tree, predicted, outcome in (
            ("1", "2", "reuse-candidate", "confirmed-reuse"),
            ("1", "4", "reuse-candidate", "false-reuse"),
            ("5", "2", "build", "conservative-build"),
            ("5", "4", "build", "confirmed-build"),
        ):
            with self.subTest(outcome=outcome):
                old = previous["targets"]["pc-x86_64"]
                old.update(tree_sha256=old_tree * 64, archive_sha256="8" * 64)
                row = observation.observe(self.fixture(previous, key * 64))["targets"]["pc-x86_64"]
                self.assertEqual((row["prediction"], row["outcome"]), (predicted, outcome))
                self.assertEqual(row["previous_archive_sha256"], "8" * 64)

    def test_substitution_after_plan_is_rejected(self):
        args = self.fixture()
        args.baseline.write_text("{}")
        with self.assertRaisesRegex(origin.OriginError, "digest differs"):
            observation.observe(args)
        args = self.fixture()
        args.plan.write_text("{}")
        with self.assertRaisesRegex(origin.OriginError, "digest differs"):
            observation.observe(args)

    def test_incomplete_final_matrix_rejected(self):
        args = self.fixture()
        evidence = json.loads(args.evidence.read_bytes())
        evidence.update(sdk_count=0, sdks=[])
        args.evidence.write_bytes(origin.canonical(evidence))
        with self.assertRaisesRegex(origin.OriginError, "products differ"):
            observation.observe(args)


if __name__ == "__main__":
    unittest.main()
