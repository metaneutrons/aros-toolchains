"""Check the reviewed payload policy against committed compiler inputs.

These are declaration/counterprobe tests, not native package or execution proof.
"""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[3]
POLICY = ROOT / "toolchains/compiler-required-payload-v1.json"
SPEC = importlib.util.spec_from_file_location(
    "committed_required_payload_policy", ROOT / "scripts/toolchain/required-compiler-payload-v2.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def check_contract(policy):
    MODULE._validate_policy(policy)
    selection = json.loads((ROOT / "toolchains/compiler-sdk-ci-selection-v2.json").read_bytes())
    groups = {item["group_id"]: item for item in policy["groups"]}
    if set(groups) != {item["id"] for item in selection["groups"]}:
        raise ValueError("required-payload groups differ from committed selection")
    for selected in selection["groups"]:
        group = groups[selected["id"]]
        for field in ("source_lock", "profiles"):
            raw = (ROOT / selected[field]).read_bytes()
            if group[field + "_sha256"] != hashlib.sha256(raw).hexdigest():
                raise ValueError("required-payload document binding is stale")
        profiles = json.loads((ROOT / selected["profiles"]).read_bytes())["profiles"]
        if set(group["profiles"]) != {profile["name"] for profile in profiles}:
            raise ValueError("required-payload profile closure differs")

    gnu = set(groups["gnu-rv32"]["profiles"]["rv32-esp32p4"])
    required_gnu = {
        "riscv-aros-gcc", "riscv-aros-g++", "riscv-aros-collect-aros",
        "riscv-aros/bin/collect-aros", "riscv-aros/bin/ld", "riscv-aros/bin/strip",
        "aros-collector-tools.json", "riscv-aros/bin/aros-collector-tools.json",
        "toolchain-tools.json", "toolchain-manifest.json",
        "libexec/gcc/riscv-aros/16.2.0/cc1", "libexec/gcc/riscv-aros/16.2.0/cc1plus",
        "lib/gcc/riscv-aros/16.2.0/libgcc.a",
        "lib/gcc/riscv-aros/16.2.0/libstdc++.a",
        "lib/gcc/riscv-aros/16.2.0/libsupc++.a",
        "lib/gcc/riscv-aros/16.2.0/include/stdarg.h",
        "lib/gcc/riscv-aros/16.2.0/include/stddef.h",
        "lib/gcc/riscv-aros/16.2.0/include/c++/vector",
        "lib/gcc/riscv-aros/16.2.0/include/c++/riscv-aros/bits/c++config.h",
    }
    if not required_gnu <= gnu:
        raise ValueError("GNU executable/header/runtime policy is incomplete")
    if any(path.endswith(("/specs", "/collect2", "/libgcc_eh.a")) for path in gnu):
        raise ValueError("GNU policy requires an unselected conditional install output")
    for name, paths in groups["llvm"]["profiles"].items():
        paths = set(paths)
        if not {"bin/clang", "bin/clang++", "bin/ld.lld", "bin/aros-collect",
                "bin/collect-aros", "lib/libc++.a", "lib/libc++abi.a", "lib/libunwind.a",
                "include/c++/v1/vector", "toolchain-manifest.json"} <= paths:
            raise ValueError("LLVM executable/header/runtime policy is incomplete")
        if ("bin/collect-aros32" in paths) != (name == "pc-x86_64"):
            raise ValueError("LLVM multilib collector policy differs")
    pc = set(groups["llvm"]["profiles"]["pc-x86_64"])
    if not {"lib/clang/11.0.0/lib/aros/libclang_rt.builtins-i386.a",
            "lib/clang/11.0.0/lib/aros/libclang_rt.builtins-x86_64.a"} <= pc:
        raise ValueError("PC multilib runtime policy is incomplete")


def check_preparation_gate(workflow):
    preparation = workflow.split("  v2-prepare:\n", 1)[1].split("\n  v2-", 1)[0]
    selector = "python3 -B scripts/toolchain/required-compiler-payload-v2.py"
    scheduler = "python3 -B scripts/toolchain/select-release-matrix-v2.py"
    if selector not in preparation or preparation.index(selector) >= preparation.index(scheduler):
        raise ValueError("required payload policy must gate native scheduling")
    if '--policy-sha256 "$policy_sha"' not in preparation:
        raise ValueError("required payload policy must be independently hash-bound")
    if ('policy="$producer/toolchains/compiler-required-payload-v1.json"' not in preparation
            or 'policy_sha=$(sha256sum "$policy"' not in preparation):
        raise ValueError("required payload policy must come from the checked producer")
    if '> "$RUNNER_TEMP/diagnostic-required-paths.json"' not in preparation:
        raise ValueError("required payload selection must remain outside the native input inventory")
    if ("name: diagnostic-v2-required-paths" not in preparation
            or "path: ${{ runner.temp }}/diagnostic-required-paths.json" not in preparation):
        raise ValueError("required payload selection must be retained separately")


class CommittedPolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = MODULE._parse_json(POLICY.read_bytes(), "committed policy")

    def test_committed_policy_matches_selected_inputs_and_required_products(self):
        check_contract(self.policy)

    def test_missing_gnu_runtime_header_or_internal_compiler_is_rejected(self):
        paths = self.policy["groups"][0]["profiles"]["rv32-esp32p4"]
        for path in paths:
            if "libgcc.a" in path or "cc1plus" in path or "c++config.h" in path:
                altered = copy.deepcopy(self.policy)
                altered["groups"][0]["profiles"]["rv32-esp32p4"].remove(path)
                with self.assertRaisesRegex(ValueError, "GNU.*incomplete"):
                    check_contract(altered)

    def test_stale_input_binding_is_rejected(self):
        altered = copy.deepcopy(self.policy)
        altered["groups"][0]["profiles_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "binding is stale"):
            check_contract(altered)

    def test_missing_pc_multilib_collector_is_rejected(self):
        altered = copy.deepcopy(self.policy)
        altered["groups"][1]["profiles"]["pc-x86_64"].remove("bin/collect-aros32")
        with self.assertRaisesRegex(ValueError, "multilib collector"):
            check_contract(altered)

    def test_preparation_checks_policy_before_native_scheduling(self):
        workflow = (ROOT / ".github/workflows/toolchain-release.yml").read_text()
        check_preparation_gate(workflow)
        for old, new in (
            ("scripts/toolchain/required-compiler-payload-v2.py", "scripts/toolchain/removed.py"),
            ('--policy-sha256 "$policy_sha"', '--policy-sha256 "unbound"'),
            ('> "$RUNNER_TEMP/diagnostic-required-paths.json"',
             '> "$RUNNER_TEMP/diagnostic-inputs/unexpected.json"'),
            ('policy="$producer/toolchains/compiler-required-payload-v1.json"',
             'policy="$RUNNER_TEMP/unreviewed-policy.json"'),
            ('policy_sha=$(sha256sum "$policy"', 'policy_sha=$(sha256sum "$other"'),
            ("name: diagnostic-v2-required-paths", "name: unbound-artifact"),
        ):
            with self.subTest(mutation=old), self.assertRaises(ValueError):
                check_preparation_gate(workflow.replace(old, new))


if __name__ == "__main__":
    unittest.main()
