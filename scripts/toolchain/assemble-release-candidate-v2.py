#!/usr/bin/env python3
"""Assemble a shared native family-v2 pre-index release candidate.

Run immediately after the authenticated compiler and SDK owner collectors in
the same job. The collectors authenticate the original owners; this adapter
reuses the reviewed byte selectors and native CLI for package staging, SDK
SBOMs, and the complete pre-attestation index. It does not qualify, admit,
sign, tag, or publish a release.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import signal
import stat
import subprocess
import sys
from typing import Any


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
MAX_NATIVE_OUTPUT = 4 * 1024 * 1024
NATIVE_TIMEOUT_SECONDS = 1800
MAX_METADATA = 16 * 1024 * 1024
MAX_RUNTIME = 1024 * 1024 * 1024
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
ROOT_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
FILE_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
CREATE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
MANIFEST_SCHEMA_NAME = "toolchain-manifest-v2.schema.json"
TREE_FIXTURE_NAME = "tree-digest-v1.fixture.json"
INDEX_NAME = "toolchain-index-v2.json"


class AssemblyError(ValueError):
    """The combined candidate failed a closed selection or output check."""


def _load_helper(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("required candidate assembly helper is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_COMPILER = _load_helper("release_candidate_compiler_assembly",
                         HERE / "assemble-compiler-candidate-v2.py")
_SDK = _load_helper("release_candidate_sdk_assembly",
                    HERE / "assemble-sdk-candidate-v2.py")
_STAGE = _COMPILER._STAGE
_ORIGIN = _COMPILER._ORIGIN


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AssemblyError(message)


def _digest(value: object, label: str) -> str:
    _require(isinstance(value, str) and HEX64.fullmatch(value) is not None,
             f"{label} must be a lowercase SHA-256 digest")
    return value


def _stat_fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
    return (_COMPILER._stat_fingerprint(metadata))


def _selector(path: Path, expected: dict | None = None,
              limit: int = MAX_METADATA) -> dict:
    measured = _STAGE.measure_file(path, limit, "owned selected output")
    if expected is not None:
        _require(measured == expected, "owned native result changed after selection")
    return {"path": str(path), **measured}


def _overlaps(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents


def _record_owned(path: Path, limit: int, selected_files: dict, label: str,
                  expected: dict | None = None) -> dict:
    measured = _STAGE.measure_file(path, limit, label)
    if expected is not None:
        _require(measured == expected, f"{label} differs from its independent selector")
    recorded, _ = _COMPILER._record_file(path, limit, label, selected_files)
    _require(recorded == measured, f"{label} changed between output observations")
    return measured


def _copy_to_release(source: Path, destination: Path, expected: dict,
                     release_dir: Path, claimed: dict[str, str], staged: dict) -> dict:
    _require(_STAGE.portable_component(destination.name),
             "selected release member name is not portable")
    _STAGE.exact_keys(expected, {"sha256", "size"}, "selected release member measurement")
    expected_sha = _digest(expected["sha256"], "selected release member digest")
    _require(type(expected["size"]) is int and expected["size"] >= 0,
             "selected release member size is invalid")
    folded = destination.name.casefold()
    _require(folded not in claimed,
             "selected release members collide under case folding")
    claimed[folded] = destination.name
    limit = _ORIGIN.MAX_PAYLOAD if destination.name.endswith(".tar.xz") else MAX_METADATA
    before = _STAGE.measure_file(source, limit, "selected release source")
    _require(before == expected and before["sha256"] == expected_sha,
             "selected release source differs from its held independent measurement")
    copied = _COMPILER._copy_regular(source, destination, expected)
    _require(copied == expected, "staged release member differs from selected bytes")
    staged[destination.name] = copied
    return copied


def _create_limited_file(path: Path):
    descriptor = os.open(path, CREATE_FLAGS, 0o600)
    metadata = os.fstat(descriptor)
    _require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
             and metadata.st_uid == os.geteuid(),
             "native result output is not an owned regular file")
    os.fchmod(descriptor, 0o600)
    return os.fdopen(descriptor, "wb")


def _limit_native_output() -> None:
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_NATIVE_OUTPUT, MAX_NATIVE_OUTPUT))


def _verify_runtime(runtime: Path, runtime_measurement: dict,
                    sdk_files: dict[Path, tuple[int, dict]]) -> None:
    measured = _STAGE.measure_file(runtime, MAX_RUNTIME, "selected native CLI")
    _require(measured == runtime_measurement and measured["size"] > 0,
             "selected native CLI changed during candidate assembly")
    sdk_record = sdk_files.get(runtime)
    _require(sdk_record is not None and sdk_record[1] == measured,
             "SDK selection no longer binds the selected native CLI")


def _run_native(runtime: Path, args: list[str], output_path: Path,
                selected_files: dict, sdk_files: dict,
                runtime_measurement: dict, label: str) -> dict:
    stderr_path = output_path.with_suffix(output_path.suffix + ".stderr.log")
    _require(not os.path.lexists(output_path) and not os.path.lexists(stderr_path),
             f"{label} native result paths are not fresh")
    _verify_runtime(runtime, runtime_measurement, sdk_files)
    _COMPILER._verify_selected_files(selected_files, include_payload=False)
    _SDK._verify_measurements(sdk_files)
    stdout_handle = _create_limited_file(output_path)
    stderr_handle = _create_limited_file(stderr_path)
    try:
        process = subprocess.Popen(
            [str(runtime), *args], stdin=subprocess.DEVNULL,
            stdout=stdout_handle, stderr=stderr_handle, close_fds=True,
            start_new_session=True, preexec_fn=_limit_native_output,
        )
        try:
            return_code = process.wait(timeout=NATIVE_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            raise AssemblyError(
                f"{label} native CLI timed out; its owned process group was terminated"
            ) from None
    finally:
        stdout_handle.close()
        stderr_handle.close()
    _verify_runtime(runtime, runtime_measurement, sdk_files)
    _COMPILER._verify_selected_files(selected_files, include_payload=False)
    _SDK._verify_measurements(sdk_files)
    stdout_measurement = _STAGE.measure_file(output_path, MAX_NATIVE_OUTPUT,
                                             f"{label} native result")
    stderr_measurement = _STAGE.measure_file(stderr_path, MAX_NATIVE_OUTPUT,
                                             f"{label} native diagnostics")
    _require(return_code == 0,
             f"{label} native CLI failed with exit status {return_code}; bounded diagnostics retained")
    _require(stdout_measurement["size"] > 0,
             f"{label} native CLI returned an empty result")
    _record_owned(output_path, MAX_NATIVE_OUTPUT, selected_files,
                  f"{label} native result", stdout_measurement)
    _record_owned(stderr_path, MAX_NATIVE_OUTPUT, selected_files,
                  f"{label} native diagnostics", stderr_measurement)
    measured, raw = _STAGE.read_bounded(output_path, MAX_NATIVE_OUTPUT,
                                        f"{label} native result")
    _require(measured == stdout_measurement,
             f"{label} native result changed while being parsed")
    envelope = _STAGE.parse_json(raw, f"{label} native result")
    _require(isinstance(envelope, dict), f"{label} native result must be a JSON object")
    return {"path": output_path, "sha256": measured["sha256"],
            "size": measured["size"], "stderr_path": stderr_path,
            "stderr_sha256": stderr_measurement["sha256"],
            "stderr_size": stderr_measurement["size"], "envelope": envelope}


def _capture_tree(root: Path) -> dict:
    directories = {}
    files = {}

    def visit(directory: Path) -> None:
        before = _STAGE.directory_fingerprint(directory, "owned stage directory")
        entries = _STAGE.directory_entries(directory, "owned stage directory")
        after = _STAGE.directory_fingerprint(directory, "owned stage directory")
        _require(before == after, "owned stage directory changed while being captured")
        directories[directory] = (after, entries)
        for name, kind in entries.items():
            path = directory / name
            if kind == "directory":
                visit(path)
            else:
                limit = _ORIGIN.MAX_PAYLOAD if name.endswith(".tar.xz") else MAX_METADATA
                measured = _STAGE.measure_file(path, limit, "owned stage member")
                files[path] = (limit, measured, _stat_fingerprint(path.lstat()))

    visit(root)
    return {"directories": directories, "files": files}


def _verify_tree(snapshot: dict) -> None:
    for directory, (fingerprint, entries) in snapshot["directories"].items():
        before = _STAGE.directory_fingerprint(directory, "owned stage directory")
        actual = _STAGE.directory_entries(directory, "owned stage directory")
        after = _STAGE.directory_fingerprint(directory, "owned stage directory")
        _require(before == after == fingerprint and actual == entries,
                 "owned stage layout changed before the combined output barrier")
    for path, (limit, expected, fingerprint) in snapshot["files"].items():
        actual = _STAGE.measure_file(path, limit, "owned stage member")
        _require(actual == expected and _stat_fingerprint(path.lstat()) == fingerprint,
                 "owned stage bytes changed before the combined output barrier")


def _join_tree_selector(tree: dict, selector: dict, label: str) -> dict:
    _STAGE.exact_keys(selector, {"path", "sha256", "size"}, label)
    path = Path(selector["path"])
    expected = {"sha256": _digest(selector["sha256"], f"{label} digest"),
                "size": selector["size"]}
    _require(type(expected["size"]) is int and expected["size"] >= 0,
             f"{label} size is invalid")
    selected = tree["files"].get(path)
    _require(selected is not None and selected[1] == expected
             and _STAGE.measure_file(path, selected[0], label) == expected,
             f"{label} does not rejoin the immediate held stage output")
    return expected


def _join_compiler_summary(result: dict, root: Path, tree: dict,
                           expected_asset_count: int) -> None:
    artifacts = result.get("artifacts")
    _require(type(artifacts) is dict, "compiler staging artifact selectors are invalid")
    for field in ("compiler_index_lanes", "compiler_evidence_fragment"):
        _join_tree_selector(tree, artifacts.get(field), f"compiler {field} selector")
    comparisons = artifacts.get("comparisons")
    native_verifications = artifacts.get("native_verifications")
    _require(type(comparisons) is dict and type(native_verifications) is dict
             and len(comparisons) == expected_asset_count
             and len(native_verifications) == expected_asset_count
             and set(comparisons) == set(native_verifications),
             "compiler report selectors do not cover the exact complete lane set")
    for asset, selector in comparisons.items():
        _join_tree_selector(tree, selector, f"compiler comparison selector for {asset}")
    for asset, selectors in native_verifications.items():
        _require(type(selectors) is list and len(selectors) == 2,
                 f"compiler native verification selectors are incomplete for {asset}")
        for selector in selectors:
            _join_tree_selector(tree, selector, f"compiler verification selector for {asset}")
    inventory = result.get("staged_inventory")
    _require(type(inventory) is dict, "compiler staged inventory is invalid")
    for name, expected in inventory.items():
        _STAGE.exact_keys(expected, {"sha256", "size"}, "compiler staged inventory member")
        path = root / "release" / name
        selected = tree["files"].get(path)
        _require(selected is not None and selected[1] == expected,
                 f"compiler staged member {name} differs from its held measured inventory")


def _join_sdk_summary(result: dict, root: Path, tree: dict) -> None:
    _require(result.get("staged_root") == str(root / "release"),
             "SDK staging summary names a different release directory")
    inventory = result.get("staged_inventory")
    _require(type(inventory) is dict, "SDK staged inventory is invalid")
    for name, expected in inventory.items():
        _STAGE.exact_keys(expected, {"sha256", "size"}, "SDK staged inventory member")
        path = root / "release" / name
        selected = tree["files"].get(path)
        _require(selected is not None and selected[1] == expected,
                 f"SDK staged member {name} differs from its held measured inventory")
    native_results = result.get("native_results")
    _require(type(native_results) is dict and set(native_results) == set(result["sdk_packages"]),
             "SDK native results do not cover the exact SDK set")
    for sdk_id, native in native_results.items():
        _STAGE.exact_keys(native, {"path", "sha256", "size", "diagnostics"},
                          f"SDK native result for {sdk_id}")
        _join_tree_selector(tree, {key: native[key] for key in ("path", "sha256", "size")},
                            f"SDK native result selector for {sdk_id}")
        _join_tree_selector(tree, native["diagnostics"],
                            f"SDK diagnostics selector for {sdk_id}")


def _validate_root(root: Path, protected: list[Path]) -> None:
    _require(root.is_absolute() and ".." not in root.parts
             and root.name not in ("", ".", ".."),
             "operation root must be an absolute normalized path")
    _require(_STAGE.path_is_canonical(root.parent, must_exist=True),
             "operation root parent is linked or noncanonical")
    _require(root.parent.lstat().st_uid == os.geteuid(),
             "operation root parent must be owned by the current user")
    _require(not os.path.lexists(root), "operation root must be absent")
    for path in protected:
        _require(not _overlaps(root, path),
                 "operation root overlaps a selected input or package source")


def _compiler_args(args: argparse.Namespace, root: Path) -> argparse.Namespace:
    return argparse.Namespace(
        aros=args.aros, aros_sha256=args.aros_sha256,
        plan=args.plan, plan_sha256=args.plan_sha256,
        inputs_dir=args.inputs_dir, inputs_sha256=args.inputs_sha256,
        producer_commit=args.producer_commit, tools_commit=args.tools_commit,
        source_context=args.source_context,
        source_context_sha256=args.source_context_sha256,
        fragment=args.compiler_fragment,
        fragment_sha256=args.compiler_fragment_sha256,
        owner_root=args.compiler_owner_root,
        required_paths=args.required_paths,
        required_paths_sha256=args.required_paths_sha256,
        release_id=args.release_id, forbidden_prefix=list(args.forbidden_prefix),
        root=root,
    )


def _sdk_args(args: argparse.Namespace, root: Path) -> argparse.Namespace:
    return argparse.Namespace(
        aros=args.aros, aros_sha256=args.aros_sha256,
        plan=args.plan, plan_sha256=args.plan_sha256,
        inputs_dir=args.inputs_dir, inputs_sha256=args.inputs_sha256,
        producer_commit=args.producer_commit, tools_commit=args.tools_commit,
        fragment=args.sdk_fragment,
        fragment_sha256=args.sdk_fragment_sha256,
        owner_root=args.sdk_owner_root,
        forbidden_prefix=[Path(prefix) for prefix in args.forbidden_prefix],
        root=root,
    )


def _assemble(args: argparse.Namespace) -> dict:
    _digest(args.aros_sha256, "selected native CLI digest")
    plan_sha = _digest(args.plan_sha256, "selected native plan digest")
    inputs_sha = _digest(args.inputs_sha256, "selected release-input digest")
    compiler_fragment_sha = _digest(args.compiler_fragment_sha256,
                                     "selected compiler collector-fragment digest")
    sdk_fragment_sha = _digest(args.sdk_fragment_sha256,
                               "selected SDK collector-fragment digest")
    required_sha = _digest(args.required_paths_sha256, "selected required-path digest")
    manifest_schema_sha = _digest(args.manifest_schema_sha256,
                                  "selected manifest-schema digest")
    tree_fixture_sha = _digest(args.tree_fixture_sha256,
                               "selected tree-fixture digest")
    _COMPILER._commit(args.producer_commit, "selected producer commit")
    _COMPILER._commit(args.tools_commit, "selected tools commit")
    release_id = _COMPILER._MATRIX._require_safe_id(args.release_id,
                                                     "selected release identifier")
    _require(isinstance(args.base_url, str) and 0 < len(args.base_url.encode("utf-8")) <= 4096
             and "\n" not in args.base_url and "\r" not in args.base_url,
             "selected release base URL is invalid")

    compiler_args = _compiler_args(args, args.root)
    sdk_args = _sdk_args(args, args.root)
    compiler_data = _COMPILER._read_bound_inputs(compiler_args)
    runtime_selection = compiler_data["selected_files"].get(args.aros)
    _require(runtime_selection is not None,
             "compiler input selection does not retain the selected native CLI")
    runtime_measurement = runtime_selection[1]
    compiler_rows = _COMPILER._transport_rows(compiler_data)
    sdk_selection_before = _SDK._selector_result(sdk_args)
    sdk_packages, sdk_locations = _SDK._selector_packages(sdk_selection_before)
    sdk_files: dict[Path, tuple[int, dict]] = {}
    sdk_directories: dict[Path, tuple[tuple[int, ...], dict[str, str]]] = {}
    sdk_plan, sdk_identities, sdk_source_context = _SDK._load_bound_documents(
        sdk_args, sdk_selection_before, sdk_files, sdk_directories
    )
    sdk_sources = _SDK._package_snapshots(
        sdk_packages, sdk_locations, sdk_files, sdk_directories
    )
    _require(sdk_plan == compiler_data["plan"]
             and sdk_source_context == compiler_data["fragment"]["source_context_sha256"],
             "compiler and SDK selections do not share one exact plan and source context")

    support_dir = _COMPILER._canonical_existing(args.support_dir,
                                                 "selected native support directory",
                                                 directory=True)
    _require(support_dir.parts[-4:] == ("crates", "aros-common", "tests", "fixtures"),
             "support directory is not the selected tools test-fixtures directory")
    support_files = {
        MANIFEST_SCHEMA_NAME: (support_dir / MANIFEST_SCHEMA_NAME, manifest_schema_sha),
        TREE_FIXTURE_NAME: (support_dir / TREE_FIXTURE_NAME, tree_fixture_sha),
    }
    support_snapshots = {}
    for name, (path, expected_sha) in support_files.items():
        measurement, _ = _COMPILER._record_file(
            path, MAX_METADATA, f"selected native support file {name}",
            compiler_data["selected_files"],
        )
        _require(measurement["sha256"] == expected_sha,
                 f"selected native support file {name} differs from its independent digest")
        support_snapshots[path] = (MAX_METADATA, measurement,
                                   _stat_fingerprint(path.lstat()))

    protected = [args.aros, args.plan, args.inputs_dir, args.compiler_fragment,
                 args.compiler_owner_root, args.sdk_fragment, args.sdk_owner_root,
                 args.required_paths, support_dir]
    protected.extend(row["package_dir"] for row in compiler_rows.values())
    protected.extend(source["package_dir"] for source in sdk_sources.values())
    _validate_root(args.root, protected)

    # Both original-owner selections are rechecked before creating any stage.
    _COMPILER._verify_transports(compiler_rows)
    _COMPILER._verify_selected_files(compiler_data["selected_files"])
    _COMPILER._verify_directories(compiler_data["snapshots"])
    _SDK._verify_measurements(sdk_files)
    _SDK._verify_directories(sdk_directories)
    for path, (limit, expected, fingerprint) in support_snapshots.items():
        _require(_STAGE.measure_file(path, limit, "selected native support file") == expected
                 and _stat_fingerprint(path.lstat()) == fingerprint,
                 "selected native support file changed before assembly")

    os.mkdir(args.root, mode=0o700)
    os.chmod(args.root, 0o700, follow_symlinks=False)
    _require(_STAGE.path_is_canonical(args.root, must_exist=True)
             and stat.S_IMODE(args.root.lstat().st_mode) == 0o700
             and args.root.lstat().st_uid == os.geteuid(),
             "owned combined operation root is not a private canonical directory")
    native_dir = args.root / "native"
    release_dir = args.root / "release"
    _COMPILER._ensure_directory(native_dir)
    _COMPILER._ensure_directory(release_dir)

    compiler_root = args.root / "compiler-stage"
    compiler_result = _COMPILER.assemble(_compiler_args(args, compiler_root))
    compiler_tree = _capture_tree(compiler_root)
    sdk_root = args.root / "sdk-stage"
    sdk_result = _SDK.assemble(_sdk_args(args, sdk_root))
    sdk_tree = _capture_tree(sdk_root)
    _join_sdk_summary(sdk_result, sdk_root, sdk_tree)
    _require(compiler_result.get("schema") == "aros-toolchain-compiler-candidate-assembly-v2"
             and sdk_result.get("schema") == "aros-sdk-package-candidate-assembly-v2",
             "reviewed package staging helper returned an unexpected summary")
    expected_lane_count = len(compiler_data["expected_lanes"])
    _join_compiler_summary(compiler_result, compiler_root, compiler_tree,
                           expected_lane_count)
    _require(compiler_result["bindings"]["plan_sha256"] == plan_sha
             and compiler_result["bindings"]["inputs_sha256"] == inputs_sha
             and compiler_result["bindings"]["fragment_sha256"] == compiler_fragment_sha
             and compiler_result["bindings"]["required_paths_sha256"] == required_sha
             and compiler_result["bindings"]["release_id"] == release_id
             and sdk_result["bindings"]["plan_sha256"] == plan_sha
             and sdk_result["bindings"]["inputs_sha256"] == inputs_sha
             and sdk_result["bindings"]["fragment_sha256"] == sdk_fragment_sha
             and sdk_result["bindings"]["aros_sha256"] == args.aros_sha256,
             "reviewed package staging summaries differ from explicit bindings")
    _require(set(sdk_result["sdk_packages"]) == {sdk["id"] for sdk in sdk_plan["sdks"]}
             and type(sdk_result["sdk_count"]) is int
             and sdk_result["sdk_count"] == len(sdk_plan["sdks"]),
             "SDK package staging summary differs from the exact native plan")

    lane_selector = compiler_result["artifacts"]["compiler_index_lanes"]
    _STAGE.exact_keys(lane_selector, {"path", "sha256", "size"},
                      "compiler lane-input selector")
    compiler_lane_path = Path(lane_selector["path"])
    _require(compiler_lane_path == compiler_root / "compiler-index-lanes.json",
             "compiler lane-input selector path differs from its stage output")
    compiler_lane_measurement, compiler_lane_raw = _STAGE.read_bounded(
        compiler_lane_path, MAX_METADATA, "compiler lane inputs"
    )
    _require(compiler_lane_measurement == {
        "sha256": lane_selector["sha256"], "size": lane_selector["size"]
    }, "compiler lane-input selector differs from its actual bytes")
    compiler_lane_doc = _STAGE.parse_json(compiler_lane_raw, "compiler lane inputs")
    _require(isinstance(compiler_lane_doc, dict), "compiler lane inputs must be an object")
    _STAGE.exact_keys(compiler_lane_doc, {"schema", "lanes"}, "compiler lane inputs")
    _require(compiler_lane_doc["schema"] == "aros-toolchain-index-lanes-v1"
             and type(compiler_lane_doc["lanes"]) is dict
             and len(compiler_lane_doc["lanes"]) == expected_lane_count
             and set(compiler_lane_doc["lanes"])
             == set(compiler_result["artifacts"]["comparisons"]),
             "compiler lane inputs do not cover the exact complete plan")
    merged_lane_doc = _COMPILER._copy_index_lanes(compiler_lane_doc["lanes"])
    merged_lane_doc["sdks"] = sdk_result["sdk_packages"]
    lane_path = args.root / "lane-inputs.json"
    lane_selector = _COMPILER._write_owned(
        lane_path, _ORIGIN.canonical(merged_lane_doc), "combined native index lane inputs"
    )
    lane_measurement = _record_owned(
        lane_path, MAX_METADATA, compiler_data["selected_files"],
        "combined native index lane inputs", {"sha256": lane_selector["sha256"],
                                               "size": lane_selector["size"]}
    )

    claimed: dict[str, str] = {}
    staged: dict[str, dict] = {}
    compiler_staged = compiler_result["staged_inventory"]
    sdk_staged = sdk_result["staged_inventory"]
    _require(type(compiler_staged) is dict and type(sdk_staged) is dict,
             "package staging inventories are invalid")
    _require(type(sdk_result["package_sources"]) is dict
             and set(sdk_result["package_sources"]) == set(sdk_result["sdk_packages"]),
             "SDK package source selectors do not cover the exact SDK set")
    for name, expected in sorted(compiler_staged.items()):
        _STAGE.exact_keys(expected, {"sha256", "size"}, "compiler staged member measurement")
        _copy_to_release(compiler_root / "release" / name, release_dir / name,
                         expected, release_dir, claimed, staged)
    for name, expected in sorted(sdk_staged.items()):
        _STAGE.exact_keys(expected, {"sha256", "size"}, "SDK staged member measurement")
        _copy_to_release(sdk_root / "release" / name, release_dir / name,
                         expected, release_dir, claimed, staged)

    collection_path = compiler_data["collection_path"]
    collection_measurement = compiler_data["selected_files"][collection_path][1]
    _require(collection_measurement["sha256"] == inputs_sha,
             "selected collection measurement differs from its explicit digest")
    _copy_to_release(collection_path, release_dir / collection_path.name,
                     collection_measurement, release_dir, claimed, staged)
    for group in compiler_data["plan"]["groups"]:
        for field in ("recipe", "source_lock", "profiles"):
            reference = group[field]
            source = compiler_data["group_refs"][group["group_id"]][field]
            _require(source.name == reference["file"],
                     f"selected {field} basename differs from the plan")
            source_measurement = compiler_data["selected_files"][source][1]
            _require(source_measurement["sha256"] == reference["sha256"],
                     f"selected {field} measurement differs from the plan")
            _copy_to_release(source, release_dir / reference["file"], source_measurement,
                             release_dir, claimed, staged)
    sdk_by_id = {sdk["id"]: sdk for sdk in sdk_plan["sdks"]}
    _require(set(sdk_identities) == set(sdk_by_id),
             "selected SDK identities differ from the complete plan")
    for sdk_id in sorted(sdk_by_id):
        reference = sdk_by_id[sdk_id]["identity"]
        source = sdk_identities[sdk_id]["path"]
        _require(source.name == reference["file"],
                 f"selected identity basename differs from the plan for {sdk_id}")
        source_measurement = sdk_files[source][1]
        _require(source_measurement["sha256"] == reference["sha256"],
                 f"selected SDK identity measurement differs from the plan for {sdk_id}")
        _copy_to_release(source, release_dir / reference["file"], source_measurement,
                         release_dir, claimed, staged)
    for name, (source, expected_sha) in support_files.items():
        support_measurement = support_snapshots[source][1]
        _require(support_measurement["sha256"] == expected_sha,
                 f"selected native support measurement differs for {name}")
        _copy_to_release(source, release_dir / name, support_measurement,
                         release_dir, claimed, staged)

    sdk_sbom_outputs = {}
    for sdk_id in sorted(sdk_result["sdk_packages"]):
        package = sdk_result["sdk_packages"][sdk_id]
        source = sdk_result["package_sources"].get(sdk_id)
        _require(isinstance(source, dict), f"verified SDK package source is missing for {sdk_id}")
        package_dir = Path(source["package_dir"])
        _require(package_dir == sdk_sources[sdk_id]["package_dir"],
                 f"SDK package directory changed after native readback for {sdk_id}")
        identity_ref = sdk_by_id[sdk_id]["identity"]
        identity_path = sdk_identities[sdk_id]["path"]
        archive = source["archive"]
        output = release_dir / f"{archive}.spdx.json"
        folded = output.name.casefold()
        _require(folded not in claimed,
                 "SDK SBOM output collides with a selected release member")
        claimed[folded] = output.name
        _require(not os.path.lexists(output), "SDK SBOM output must be absent")
        native_output = native_dir / f"sbom-{sdk_id}.json"
        command = [
            "sdk", "sbom", "--identity", str(identity_path),
            "--identity-sha256", identity_ref["sha256"],
            "--tree-sha256", package["tree_sha256"],
            "--package-dir", str(package_dir),
            "--archive-sha256", package["archive_sha256"],
            "--archive-size", str(package["archive_size"]),
        ]
        for prefix in args.forbidden_prefix:
            command.extend(("--forbidden-prefix", prefix))
        command.extend(("--output", str(output)))
        native = _run_native(args.aros, command, native_output,
                             compiler_data["selected_files"], sdk_files,
                             runtime_measurement, f"SDK {sdk_id} SBOM")
        envelope = _STAGE.exact_keys(
            native["envelope"], {"schema", "operation", "assurance", "result"},
            f"SDK {sdk_id} SBOM result envelope",
        )
        _require(envelope["schema"] == "aros-sdk-local-stage-v2"
                 and envelope["operation"] == "sdk.sbom"
                 and envelope["assurance"] == "local-byte-consistency-not-release-admission",
                 f"SDK {sdk_id} SBOM result schema, operation, or assurance differs")
        result = _STAGE.exact_keys(envelope["result"], {"output", "sha256", "size"},
                                   f"SDK {sdk_id} SBOM result")
        output_sha = _digest(result["sha256"], f"SDK {sdk_id} SBOM digest")
        _require(result["output"] == str(output) and type(result["size"]) is int
                 and result["size"] > 0,
                 f"SDK {sdk_id} SBOM result path or size differs")
        output_measurement = _STAGE.measure_file(output, MAX_METADATA,
                                                 f"SDK {sdk_id} SBOM output")
        _require(output_measurement == {"sha256": output_sha, "size": result["size"]},
                 f"SDK {sdk_id} SBOM bytes differ from the native result")
        staged[output.name] = output_measurement
        _record_owned(output, MAX_METADATA, compiler_data["selected_files"],
                      f"SDK {sdk_id} SBOM output", output_measurement)
        sdk_sbom_outputs[sdk_id] = {
            "output": {"path": str(output), **output_measurement},
            "native_result": {"path": str(native["path"]), "sha256": native["sha256"],
                              "size": native["size"]},
            "diagnostics": {"path": str(native["stderr_path"]),
                            "sha256": native["stderr_sha256"],
                            "size": native["stderr_size"]},
        }

    _require(_STAGE.directory_entries(release_dir, "pre-index release directory") == {
        name: "file" for name in staged
    }, "pre-index release members differ from the selected package and input closure")
    for name, expected in staged.items():
        limit = _ORIGIN.MAX_PAYLOAD if name.endswith(".tar.xz") else MAX_METADATA
        _require(_STAGE.measure_file(release_dir / name, limit,
                                    "measured pre-index release member") == expected,
                 "pre-index release member changed before native indexing")

    subject_path = args.root / "subject-manifest.json"
    _require(not os.path.lexists(subject_path),
             "pre-attestation subject-manifest output must be absent")
    native_index_path = native_dir / "index.json"
    index_command = [
        "toolchain", "producer", "index", "--directory", str(release_dir),
        "--release-id", release_id, "--base-url", args.base_url,
        "--release-format", "family-v2", "--lane-inputs", str(lane_path),
        "--subject-manifest", str(subject_path),
    ]
    for prefix in args.forbidden_prefix:
        index_command.extend(("--forbidden-prefix", prefix))
    index_command.extend(("--stage", "pre-attestation", "--format", "json"))
    native_index = _run_native(args.aros, index_command, native_index_path,
                               compiler_data["selected_files"], sdk_files,
                               runtime_measurement, "family-v2 pre-attestation index")
    result = _STAGE.exact_keys(native_index["envelope"], {
        "schema", "operation", "release_format", "stage", "release_id", "index",
        "index_sha256", "subject_manifest", "subject_manifest_sha256",
        "subject_manifest_size", "subject_count", "inventory_count", "lane_count",
        "sdk_count",
    }, "native family-v2 index result")
    index_path = release_dir / INDEX_NAME
    _require(result["schema"] == "aros-toolchain-producer-stage-v2"
             and result["operation"] == "index"
             and result["release_format"] == "family-v2"
             and result["stage"] == "pre-attestation"
             and result["release_id"] == release_id
             and result["index"] == str(index_path)
             and result["subject_manifest"] == str(subject_path),
             "native index result bindings or output paths differ")
    index_sha = _digest(result["index_sha256"], "native index digest")
    index_measurement = _STAGE.measure_file(index_path, MAX_METADATA,
                                            "native family-v2 index")
    _require(index_measurement["sha256"] == index_sha,
             "native index digest differs from the actual output bytes")
    subject_sha = _digest(result["subject_manifest_sha256"], "subject-manifest digest")
    _require(type(result["subject_manifest_size"]) is int
             and type(result["subject_count"]) is int
             and type(result["inventory_count"]) is int
             and type(result["lane_count"]) is int
             and type(result["sdk_count"]) is int,
             "native index counts and sizes must be integers")
    subject_measurement, subject_raw = _STAGE.read_bounded(
        subject_path, MAX_METADATA, "pre-attestation subject manifest"
    )
    _require(subject_measurement == {
        "sha256": subject_sha, "size": result["subject_manifest_size"]
    }, "subject-manifest digest or size differs from the actual output")
    subject_count = len(subject_raw.splitlines())
    _require(result["subject_count"] == subject_count == len(staged) + 1,
             "native subject count differs from its actual manifest and release outputs")
    lane_count = expected_lane_count
    sdk_count = len(sdk_plan["sdks"])
    _require(result["lane_count"] == lane_count == len(compiler_lane_doc["lanes"])
             and result["sdk_count"] == sdk_count == len(sdk_result["sdk_packages"]),
             "native index lane or SDK count differs from the complete captured plan")
    # The native index reports its complete inventory, including the two
    # post-attestation files; the pre-attestation subject list includes the
    # actual release files and the new index only.
    _require(result["inventory_count"] == subject_count + 2,
             "native index inventory count differs from the measured pre-index output closure")
    _record_owned(index_path, MAX_METADATA, compiler_data["selected_files"],
                  "native family-v2 index", index_measurement)
    _record_owned(subject_path, MAX_METADATA, compiler_data["selected_files"],
                  "pre-attestation subject manifest", subject_measurement)
    staged[INDEX_NAME] = index_measurement

    for name, expected in staged.items():
        limit = _ORIGIN.MAX_PAYLOAD if name.endswith(".tar.xz") else MAX_METADATA
        _require(_STAGE.measure_file(release_dir / name, limit,
                                    "final measured release member") == expected,
                 "release inventory member changed before the output barrier")
    expected_release_entries = {name: "file" for name in staged}
    _require(_STAGE.directory_entries(release_dir, "final release directory")
             == expected_release_entries,
             "final release directory contains unexpected or missing entries")
    _require(_STAGE.directory_entries(native_dir, "combined native result directory") == {
        **{f"sbom-{sdk_id}.json": "file" for sdk_id in sdk_sbom_outputs},
        **{f"sbom-{sdk_id}.json.stderr.log": "file" for sdk_id in sdk_sbom_outputs},
        "index.json": "file", "index.json.stderr.log": "file",
    }, "combined native result directory differs from its exact command outputs")
    _require(_STAGE.directory_entries(args.root, "combined operation root") == {
        "compiler-stage": "directory", "lane-inputs.json": "file",
        "native": "directory", "release": "directory",
        "sdk-stage": "directory", "subject-manifest.json": "file",
    }, "combined operation root contains unexpected or missing entries")
    output_layout = {}
    for directory in (args.root, native_dir, release_dir):
        before = _STAGE.directory_fingerprint(directory, "combined output directory")
        entries = _STAGE.directory_entries(directory, "combined output directory")
        after = _STAGE.directory_fingerprint(directory, "combined output directory")
        _require(before == after, "combined output directory changed while being captured")
        output_layout[directory] = (after, entries)
    lane_selector = _selector(lane_path, lane_measurement)
    subject_selector = _selector(subject_path, subject_measurement)
    index_selector = _selector(index_path, index_measurement, MAX_METADATA)
    native_index_selector = _selector(native_index_path, {
        "sha256": native_index["sha256"], "size": native_index["size"]
    }, MAX_NATIVE_OUTPUT)
    for directory, (fingerprint, entries) in output_layout.items():
        before = _STAGE.directory_fingerprint(directory, "combined output directory")
        actual = _STAGE.directory_entries(directory, "combined output directory")
        after = _STAGE.directory_fingerprint(directory, "combined output directory")
        _require(before == after == fingerprint and actual == entries,
                 "combined output layout changed before the result was recorded")

    # Final barrier: no child-stage selector or original-owner transport is
    # rebased after SDK SBOM/index work. Rejoin the exact held measurements.
    sdk_selection_after = _SDK._selector_result(sdk_args)
    _require(sdk_selection_after == sdk_selection_before,
             "SDK package selector result changed during combined assembly")
    _COMPILER._verify_transports(compiler_rows)
    _COMPILER._verify_selected_files(compiler_data["selected_files"])
    _COMPILER._verify_directories(compiler_data["snapshots"])
    _SDK._verify_measurements(sdk_files)
    _SDK._verify_directories(sdk_directories)
    _verify_tree(compiler_tree)
    _verify_tree(sdk_tree)
    _verify_runtime(args.aros, runtime_measurement, sdk_files)
    for path, (limit, expected, fingerprint) in support_snapshots.items():
        _require(_STAGE.measure_file(path, limit, "selected native support file") == expected
                 and _stat_fingerprint(path.lstat()) == fingerprint,
                 "selected native support file changed before the final output barrier")
    for name, expected in staged.items():
        limit = _ORIGIN.MAX_PAYLOAD if name.endswith(".tar.xz") else MAX_METADATA
        _require(_STAGE.measure_file(release_dir / name, limit,
                                    "final measured release member") == expected,
                 "release inventory member changed before the final output barrier")
    expected_native_entries = {
        **{f"sbom-{sdk_id}.json": "file" for sdk_id in sdk_sbom_outputs},
        **{f"sbom-{sdk_id}.json.stderr.log": "file" for sdk_id in sdk_sbom_outputs},
        "index.json": "file", "index.json.stderr.log": "file",
    }
    expected_root_entries = {
        "compiler-stage": "directory", "lane-inputs.json": "file",
        "native": "directory", "release": "directory",
        "sdk-stage": "directory", "subject-manifest.json": "file",
    }
    expected_entries = {
        args.root: expected_root_entries,
        native_dir: expected_native_entries,
        release_dir: {name: "file" for name in staged},
    }
    for directory, (fingerprint, _entries) in output_layout.items():
        before = _STAGE.directory_fingerprint(directory, "final combined output directory")
        actual = _STAGE.directory_entries(directory, "final combined output directory")
        after = _STAGE.directory_fingerprint(directory, "final combined output directory")
        _require(before == after == fingerprint and actual == expected_entries[directory],
                 "final combined output inventory or layout changed before return")
    try:
        final_source_event = _ORIGIN.observe_run_event(compiler_data["source_context"])
    except _ORIGIN.OriginError as error:
        raise AssemblyError(str(error)) from error
    _require(final_source_event == compiler_data["source_event"],
             "source run event changed during combined assembly")
    return {
        "schema": "aros-toolchain-release-candidate-assembly-v2",
        "operation": "shared-native-pre-index-inventory",
        "assurance": "complete-native-pre-index-inventory-no-admission",
        "bindings": {
            "aros_sha256": args.aros_sha256,
            "plan_sha256": plan_sha,
            "inputs_sha256": inputs_sha,
            "compiler_fragment_sha256": compiler_fragment_sha,
            "sdk_fragment_sha256": sdk_fragment_sha,
            "required_paths_sha256": required_sha,
            "manifest_schema_sha256": manifest_schema_sha,
            "tree_fixture_sha256": tree_fixture_sha,
            "producer_commit": args.producer_commit,
            "tools_commit": args.tools_commit,
            "source_context_sha256": sdk_source_context,
            "release_id": release_id,
            "base_url": args.base_url,
            "aros": str(args.aros),
            "plan": str(args.plan),
            "inputs_dir": str(args.inputs_dir),
            "compiler_fragment": str(args.compiler_fragment),
            "compiler_owner_root": str(args.compiler_owner_root),
            "sdk_fragment": str(args.sdk_fragment),
            "sdk_owner_root": str(args.sdk_owner_root),
            "required_paths": str(args.required_paths),
            "support_dir": str(support_dir),
        },
        "release_root": str(release_dir),
        "stage": "pre-attestation",
        "release_format": "family-v2",
        "outputs": {
            "index": index_selector,
            "lane_inputs": lane_selector,
            "subject_manifest": subject_selector,
            "native_index_result": native_index_selector,
            "sdk_sboms": sdk_sbom_outputs,
        },
        "release_inventory": {name: staged[name] for name in sorted(staged)},
        "counts": {
            "lane_count": lane_count,
            "sdk_count": sdk_count,
            "subject_count": subject_count,
            "inventory_count": result["inventory_count"],
        },
        "scope": {
            "sdk_factory_execution_complete": False,
            "release_admission": False,
            "publication": False,
        },
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--aros", type=Path, required=True)
    parser.add_argument("--aros-sha256", required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--plan-sha256", required=True)
    parser.add_argument("--inputs-dir", type=Path, required=True)
    parser.add_argument("--inputs-sha256", required=True)
    parser.add_argument("--producer-commit", required=True)
    parser.add_argument("--tools-commit", required=True)
    parser.add_argument("--source-context", type=Path, required=True)
    parser.add_argument("--source-context-sha256", required=True)
    parser.add_argument("--compiler-fragment", type=Path, required=True)
    parser.add_argument("--compiler-fragment-sha256", required=True)
    parser.add_argument("--compiler-owner-root", type=Path, required=True)
    parser.add_argument("--sdk-fragment", type=Path, required=True)
    parser.add_argument("--sdk-fragment-sha256", required=True)
    parser.add_argument("--sdk-owner-root", type=Path, required=True)
    parser.add_argument("--required-paths", type=Path, required=True)
    parser.add_argument("--required-paths-sha256", required=True)
    parser.add_argument("--support-dir", type=Path, required=True)
    parser.add_argument("--manifest-schema-sha256", required=True)
    parser.add_argument("--tree-fixture-sha256", required=True)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--forbidden-prefix", action="append", default=[])
    parser.add_argument("--root", type=Path, required=True)
    return parser


def _reject_repeated_options(argv: list[str]) -> None:
    seen = set()
    for argument in argv:
        if not argument.startswith("--"):
            continue
        option = argument.split("=", 1)[0]
        if option == "--forbidden-prefix":
            continue
        _require(option not in seen, f"repeated command-line option: {option}")
        seen.add(option)


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    try:
        _reject_repeated_options(arguments)
        args = _parser().parse_args(arguments)
        result = _assemble(args)
        sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=True, allow_nan=False) + "\n")
        return 0
    except SystemExit:
        raise
    except (_STAGE.StageError, _COMPILER._MATRIX.PlanError, _SDK._SELECT.SelectionError,
            _COMPILER.AssemblyError, _SDK.AssemblyError, AssemblyError, OSError,
            UnicodeError, RecursionError, ValueError, KeyError, TypeError) as error:
        sys.stderr.write(f"release candidate pre-index assembly failed: {error}\n")
        return 1
    except Exception:
        sys.stderr.write("release candidate pre-index assembly failed: closed byte boundary\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
