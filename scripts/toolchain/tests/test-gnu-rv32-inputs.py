#!/usr/bin/env python3
"""Review-scope regressions, not a replacement for the native input parser."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Callable


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
PROFILE_PATH = REPOSITORY_ROOT / "toolchains/profiles-gnu-rv32-v2.json"
SOURCE_LOCK_PATH = REPOSITORY_ROOT / "toolchains/gnu-16.2.0.sources.json"
COMPATIBILITY_PORTS_LOCK_PATH = REPOSITORY_ROOT / "toolchains/compatibility-ports-gnu-rv32-v3.json"
EXPECTED_PROFILE_SHA256 = "9d6b7db6d1bdb16c9d37dfa5a7ddc94ec0ee594afc1bda53c2a466a5e6f6f416"
EXPECTED_SOURCE_LOCK_SHA256 = "ced11b5c510c89a05fe3863be812f211362c08d550a8acdd46b6942b92c38c0b"
EXPECTED_COMPATIBILITY_PORTS_LOCK_SHA256 = "677374d2c5e85aee222c577d5e0feb988833bf9db4425ec69f2456f15dd240e4"

MEASURED_UCD_INPUT = {
    "id": "unicode-ucd-16-0-0",
    "cache_filename": "UCD.zip",
    "relative_path": "UCD.zip",
    "fetch_marker": "",
    "url": "https://www.unicode.org/Public/16.0.0/ucd/UCD.zip",
    "sha256": "c86dd81f2b14a43b0cc064aa5f89aa7241386801e35c59c7984e579832634eb2",
    "size": 9020779,
}

# The source's classic %fetch location is revision-scoped. CMake's separate
# mapping already names the same subtree under its build's portssources root.
ZLIB_CLASSIC_CACHE = "chromium-da752eb2a3660cf1bf8dac620f6380b89dd953a7"

COMPATIBILITY_PORTS_MAPPINGS = {
    "boost-1-89-0": (
        "portssources/boost_1_89_0.tar.gz",
        "9de758db755e8330a01d995b0a24d09798048400ac25c03fc5ea9be364b13c93",
        190099283,
    ),
    "codesets-6-22": (
        "portssources/codesets/6.22.tar.gz",
        "c4b11066b9c51c5670f69122efbdb1c58ddd69c4dbe1dcd480aac74577250cc1",
        206125,
    ),
}

SOURCE_VERSIONS = {
    "gcc": "16.2.0",
    "binutils": "2.47",
    "gmp": "6.3.0",
    "isl": "0.27",
    "mpfr": "4.2.2",
    "mpc": "1.4.1",
    "zstd": "1.5.7",
    "unicode-ucd": "16.0.0",
    "codesets": "6.22",
}
SOURCE_PATCHES = {
    "gcc": "tools/crosstools/gnu/gcc-16.2.0-aros.diff",
    "binutils": "tools/crosstools/gnu/binutils-2.47-aros.diff",
    "gmp": "tools/crosstools/gnu/gmp-6.3.0-aros.diff",
    "isl": None,
    "mpfr": None,
    "mpc": None,
    "zstd": None,
    "unicode-ucd": None,
    "codesets": "workbench/libs/codesets/6.22-aros.diff",
}
HOST_PYTHON_VERSIONS = {
    "mako": "1.3.10",
    "markupsafe": "3.0.2",
    "yaml": "6.0.3",
}


class ScopeError(AssertionError):
    """A release input falls outside the reviewed scope."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ScopeError(message)


def profile_mentions_rv64(profile: dict) -> bool:
    for key in (
        "name",
        "configure_target",
        "upstream_output_target",
        "target_triple",
        "cpu",
        "platform",
        "float_abi",
    ):
        value = profile.get(key)
        if isinstance(value, str) and "rv64" in value.lower():
            return True
    target = profile.get("target")
    if isinstance(target, dict):
        for key in ("isa", "abi", "architecture"):
            value = target.get(key)
            if isinstance(value, str) and "rv64" in value.lower():
                return True
    return False


def require_profile_scope(document: dict) -> None:
    profiles = document.get("profiles")
    require(isinstance(profiles, list), "GNU RV32 profiles must be a list")
    require(
        not any(isinstance(profile, dict) and profile_mentions_rv64(profile) for profile in profiles),
        "GNU RV32 release input must not include an RV64 profile",
    )
    require(
        len(profiles) == 1
        and isinstance(profiles[0], dict)
        and profiles[0].get("name") == "rv32-esp32p4",
        "GNU RV32 release input must contain exactly one rv32-esp32p4 profile",
    )

    profile = profiles[0]
    require(
        profile.get("cpu") == "riscv"
        and profile.get("platform") == "esp32p4"
        and profile.get("target_triple") == "riscv-aros",
        "rv32-esp32p4 must retain its reviewed RISC-V P4 target identity",
    )
    target = profile.get("target")
    require(isinstance(target, dict), "rv32-esp32p4 must declare its reviewed target")
    require(
        target.get("isa") == "rv32imafc_zicsr_zifencei_zaamo_zalrsc",
        "rv32-esp32p4 ISA differs from the reviewed P4 ISA",
    )
    require(
        profile.get("float_abi") == "ilp32f" and target.get("abi") == "ilp32f",
        "rv32-esp32p4 ABI must remain ilp32f",
    )
    require(
        target.get("code_model") == "medany",
        "rv32-esp32p4 code model must remain medany",
    )


def _records_by_name(records: object, expected: dict[str, str], label: str) -> dict[str, dict]:
    require(isinstance(records, list), f"GNU 16.2.0 {label} must be a list")
    names = [record.get("component" if label == "source lock" else "name") if isinstance(record, dict) else None
             for record in records]
    require(
        len(names) == len(expected)
        and all(isinstance(name, str) for name in names)
        and len(set(names)) == len(names)
        and set(names) == set(expected),
        f"GNU 16.2.0 {label} must contain exactly the measured {len(expected)} entries",
    )
    return {
        (record.get("component") if label == "source lock" else record.get("name")): record
        for record in records
    }


def require_source_lock_scope(document: dict) -> None:
    require(
        document.get("family") == "gnu" and document.get("version") == "16.2.0",
        "source lock must declare GNU 16.2.0",
    )
    sources = _records_by_name(document.get("sources"), SOURCE_VERSIONS, "source lock")
    for component, version in SOURCE_VERSIONS.items():
        record = sources[component]
        require(
            record.get("version") == version,
            f"source lock component {component} version differs from the measured input",
        )
        require(
            record.get("patch") == SOURCE_PATCHES[component],
            f"source lock component {component} patch differs from the measured input",
        )

    packages = _records_by_name(
        document.get("host_python_packages"), HOST_PYTHON_VERSIONS, "host Python closure"
    )
    for package, version in HOST_PYTHON_VERSIONS.items():
        require(
            packages[package].get("version") == version,
            f"host Python package {package} version differs from the measured input",
        )


def require_compatibility_ports_scope(document: dict) -> None:
    profiles = document.get("profiles")
    require(
        isinstance(profiles, list)
        and len(profiles) == 1
        and isinstance(profiles[0], dict)
        and profiles[0].get("name") == "rv32-esp32p4",
        "GNU RV32 compatibility ports lock must contain exactly one rv32-esp32p4 profile",
    )

    inputs = document.get("inputs")
    require(isinstance(inputs, list), "GNU RV32 compatibility ports lock inputs must be a list")
    require(
        all(isinstance(record, dict) for record in inputs),
        "GNU RV32 compatibility ports lock inputs must be objects",
    )
    input_ids = [record.get("id") for record in inputs]
    require(
        all(isinstance(input_id, str) and input_id for input_id in input_ids)
        and len(set(input_ids)) == len(input_ids),
        "GNU RV32 compatibility ports lock must have unique input IDs",
    )

    inputs_by_id = {record["id"]: record for record in inputs}
    zlib_input = inputs_by_id.get("chromium-zlib-da752eb2")
    require(
        zlib_input is not None
        and zlib_input.get("relative_path") == f"{ZLIB_CLASSIC_CACHE}/zlib.tar.gz"
        and zlib_input.get("fetch_marker") == f"{ZLIB_CLASSIC_CACHE}/.zlib-fetched"
        and zlib_input.get("cmake_cache_path") == f"portssources/{ZLIB_CLASSIC_CACHE}/zlib.tar.gz",
        "GNU RV32 zlib cache paths must match the revision-scoped upstream fetch location",
    )
    ucd_input = inputs_by_id.get(MEASURED_UCD_INPUT["id"])
    require(
        ucd_input is not None,
        "GNU RV32 compatibility ports lock must contain the measured Unicode UCD archive input",
    )
    require(
        ucd_input == MEASURED_UCD_INPUT,
        "GNU RV32 compatibility ports UCD archive differs from the measured input",
    )

    selected_inputs = profiles[0].get("inputs")
    require(
        isinstance(selected_inputs, list)
        and all(isinstance(input_id, str) and input_id for input_id in selected_inputs)
        and len(selected_inputs) == len(input_ids)
        and len(set(selected_inputs)) == len(selected_inputs)
        and set(selected_inputs) == set(input_ids),
        "GNU RV32 compatibility ports profile must select every locked input exactly once",
    )

    cache_paths = [record["cmake_cache_path"] for record in inputs if "cmake_cache_path" in record]
    require(
        all(isinstance(path, str) and path for path in cache_paths),
        "GNU RV32 compatibility ports lock CMake cache paths must be non-empty strings",
    )
    require(
        len(set(cache_paths)) == len(cache_paths),
        "GNU RV32 compatibility ports lock maps multiple inputs to one CMake cache path",
    )

    for input_id, (cache_path, sha256, size) in COMPATIBILITY_PORTS_MAPPINGS.items():
        record = inputs_by_id.get(input_id)
        require(
            record is not None and record.get("cmake_cache_path") == cache_path,
            f"GNU RV32 compatibility ports lock is missing required CMake cache mapping for {input_id}",
        )
        require(
            record.get("sha256") == sha256,
            f"GNU RV32 compatibility ports checksum for {input_id} differs from the measured input",
        )
        require(
            record.get("size") == size,
            f"GNU RV32 compatibility ports size for {input_id} differs from the measured input",
        )


def require_digest(raw: bytes, expected: str, label: str) -> None:
    actual = hashlib.sha256(raw).hexdigest()
    require(actual == expected, f"{label} bytes differ from the measured release input")


def expect_scope_failure(label: str, expected_message: str, action: Callable[[], None]) -> None:
    try:
        action()
    except ScopeError as error:
        require(
            str(error) == expected_message,
            f"{label} counterprobe failed for the wrong reason: {error}",
        )
    else:
        raise AssertionError(f"{label} counterprobe was accepted")


def load_document(path: Path) -> tuple[dict, bytes]:
    raw = path.read_bytes()
    document = json.loads(raw)
    require(isinstance(document, dict), f"{path.name} must contain a JSON object")
    return document, raw


def main() -> None:
    profiles, profile_raw = load_document(PROFILE_PATH)
    require_profile_scope(profiles)
    require_digest(profile_raw, EXPECTED_PROFILE_SHA256, "GNU RV32 profile")

    source_lock, source_lock_raw = load_document(SOURCE_LOCK_PATH)
    require_source_lock_scope(source_lock)
    require_digest(source_lock_raw, EXPECTED_SOURCE_LOCK_SHA256, "GNU source lock")

    compatibility_ports_lock, compatibility_ports_lock_raw = load_document(
        COMPATIBILITY_PORTS_LOCK_PATH
    )
    require_compatibility_ports_scope(compatibility_ports_lock)
    require_digest(
        compatibility_ports_lock_raw,
        EXPECTED_COMPATIBILITY_PORTS_LOCK_SHA256,
        "GNU RV32 compatibility ports lock",
    )

    expect_scope_failure(
        "changed lock bytes",
        "GNU source lock bytes differ from the measured release input",
        lambda: require_digest(source_lock_raw + b" ", EXPECTED_SOURCE_LOCK_SHA256, "GNU source lock"),
    )

    rv64_probe = copy.deepcopy(profiles)
    rv64_profile = copy.deepcopy(rv64_probe["profiles"][0])
    rv64_profile["name"] = "rv64-esp32p4"
    rv64_profile["target"]["isa"] = "rv64imafdc"
    rv64_probe["profiles"].append(rv64_profile)
    expect_scope_failure(
        "RV64 addition",
        "GNU RV32 release input must not include an RV64 profile",
        lambda: require_profile_scope(rv64_probe),
    )

    abi_probe = copy.deepcopy(profiles)
    abi_probe["profiles"][0]["target"]["abi"] = "ilp32d"
    expect_scope_failure(
        "ABI drift",
        "rv32-esp32p4 ABI must remain ilp32f",
        lambda: require_profile_scope(abi_probe),
    )

    omitted_source_probe = copy.deepcopy(source_lock)
    omitted_source_probe["sources"] = [
        record for record in omitted_source_probe["sources"] if record.get("component") != "gcc"
    ]
    expect_scope_failure(
        "omitted source entry",
        "GNU 16.2.0 source lock must contain exactly the measured 9 entries",
        lambda: require_source_lock_scope(omitted_source_probe),
    )

    changed_source_probe = copy.deepcopy(source_lock)
    next(record for record in changed_source_probe["sources"] if record["component"] == "gcc")[
        "version"
    ] = "16.2.1"
    expect_scope_failure(
        "changed source entry",
        "source lock component gcc version differs from the measured input",
        lambda: require_source_lock_scope(changed_source_probe),
    )

    missing_mapping_probe = copy.deepcopy(compatibility_ports_lock)
    next(record for record in missing_mapping_probe["inputs"] if record["id"] == "boost-1-89-0").pop(
        "cmake_cache_path"
    )
    expect_scope_failure(
        "missing compatibility CMake mapping",
        "GNU RV32 compatibility ports lock is missing required CMake cache mapping for boost-1-89-0",
        lambda: require_compatibility_ports_scope(missing_mapping_probe),
    )

    changed_checksum_probe = copy.deepcopy(compatibility_ports_lock)
    next(record for record in changed_checksum_probe["inputs"] if record["id"] == "codesets-6-22")[
        "sha256"
    ] = "0" * 64
    expect_scope_failure(
        "changed compatibility checksum",
        "GNU RV32 compatibility ports checksum for codesets-6-22 differs from the measured input",
        lambda: require_compatibility_ports_scope(changed_checksum_probe),
    )

    missing_ucd_probe = copy.deepcopy(compatibility_ports_lock)
    missing_ucd_probe["inputs"] = [
        record
        for record in missing_ucd_probe["inputs"]
        if record.get("id") != MEASURED_UCD_INPUT["id"]
    ]
    expect_scope_failure(
        "missing UCD archive input",
        "GNU RV32 compatibility ports lock must contain the measured Unicode UCD archive input",
        lambda: require_compatibility_ports_scope(missing_ucd_probe),
    )

    for field, value, label in (
        ("sha256", "0" * 64, "changed UCD archive checksum"),
        ("size", MEASURED_UCD_INPUT["size"] + 1, "changed UCD archive size"),
        ("relative_path", "UCD-renamed.zip", "changed UCD archive path"),
    ):
        changed_ucd_probe = copy.deepcopy(compatibility_ports_lock)
        next(
            record
            for record in changed_ucd_probe["inputs"]
            if record["id"] == MEASURED_UCD_INPUT["id"]
        )[field] = value
        expect_scope_failure(
            label,
            "GNU RV32 compatibility ports UCD archive differs from the measured input",
            lambda probe=changed_ucd_probe: require_compatibility_ports_scope(probe),
        )

    unselected_ucd_probe = copy.deepcopy(compatibility_ports_lock)
    unselected_ucd_probe["profiles"][0]["inputs"].remove(MEASURED_UCD_INPUT["id"])
    expect_scope_failure(
        "unselected UCD archive input",
        "GNU RV32 compatibility ports profile must select every locked input exactly once",
        lambda: require_compatibility_ports_scope(unselected_ucd_probe),
    )

    for field, value in (
        ("relative_path", "zlib.tar.gz"),
        ("fetch_marker", ".zlib-fetched"),
        ("cmake_cache_path", "portssources/zlib.tar.gz"),
    ):
        flat_zlib_probe = copy.deepcopy(compatibility_ports_lock)
        next(record for record in flat_zlib_probe["inputs"]
             if record["id"] == "chromium-zlib-da752eb2")[field] = value
        expect_scope_failure(
            f"flat zlib {field}",
            "GNU RV32 zlib cache paths must match the revision-scoped upstream fetch location",
            lambda probe=flat_zlib_probe: require_compatibility_ports_scope(probe),
        )

    duplicate_mapping_probe = copy.deepcopy(compatibility_ports_lock)
    next(record for record in duplicate_mapping_probe["inputs"] if record["id"] == "codesets-6-22")[
        "cmake_cache_path"
    ] = COMPATIBILITY_PORTS_MAPPINGS["boost-1-89-0"][0]
    expect_scope_failure(
        "duplicate compatibility CMake mapping",
        "GNU RV32 compatibility ports lock maps multiple inputs to one CMake cache path",
        lambda: require_compatibility_ports_scope(duplicate_mapping_probe),
    )

    changed_patch_probe = copy.deepcopy(source_lock)
    next(record for record in changed_patch_probe["sources"] if record["component"] == "gcc")[
        "patch"
    ] = "tools/crosstools/gnu/other.patch"
    expect_scope_failure(
        "changed patch input",
        "source lock component gcc patch differs from the measured input",
        lambda: require_source_lock_scope(changed_patch_probe),
    )

    print("GNU RV32 release input scope and counterprobes passed")


if __name__ == "__main__":
    main()
