#!/usr/bin/env python3
"""Materialize a retained diagnostic SDK-owner ZIP as bounded private bytes.

The caller must independently verify the artifact origin before invoking this
helper. This module checks joins and byte consistency only; it does not verify
signatures, authenticate a job, or grant qualification or release authority.
Retained and output roots are expected to be quiescent and owned by the caller.
Readback checks do not isolate against a hostile concurrent writer.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import zipfile


_NATIVE_PATH = Path(__file__).with_name("native-lane-transport.py")
_NATIVE_SPEC = importlib.util.spec_from_file_location("native_lane_transport_for_sdk_owner", _NATIVE_PATH)
if _NATIVE_SPEC is None or _NATIVE_SPEC.loader is None:  # pragma: no cover - installation failure
    raise RuntimeError("native lane transport helper is unavailable")
native = importlib.util.module_from_spec(_NATIVE_SPEC)
_NATIVE_SPEC.loader.exec_module(native)
origin = native.origin

_STAGE_PATH = Path(__file__).with_name("stage-sdk-owner-payload-v2.py")
_STAGE_SPEC = importlib.util.spec_from_file_location("sdk_owner_payload_for_transport", _STAGE_PATH)
if _STAGE_SPEC is None or _STAGE_SPEC.loader is None:  # pragma: no cover - installation failure
    raise RuntimeError("SDK owner-payload schema helper is unavailable")
stage = importlib.util.module_from_spec(_STAGE_SPEC)
_STAGE_SPEC.loader.exec_module(stage)


SCHEMA = "aros-sdk-owner-transport-v2"
ASSURANCE = "transport-byte-readback-only"
OWNER_SCHEMA = "aros-sdk-owner-payload-v2"
OWNER_ASSURANCE = "staging-byte-consistency-only"
RETAINED_NAMES = native.RETAINED_NAMES
MAX_METADATA = origin.MAX_METADATA
MAX_PAYLOAD = origin.MAX_PAYLOAD
MAX_FILES = origin.MAX_FILES
SDK_ID = re.compile(r"[a-z0-9._+-]{1,96}\Z")
DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)


def _require(condition: bool, message: str) -> None:
    origin.require(condition, message)


def _stat_identity(entry: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (entry.st_dev, entry.st_ino, entry.st_size, entry.st_mtime_ns,
            entry.st_ctime_ns, entry.st_uid, stat.S_IMODE(entry.st_mode))


def _inode_identity(entry: os.stat_result) -> tuple[int, int]:
    return entry.st_dev, entry.st_ino


def _directory_identity(entry: os.stat_result) -> tuple[int, int, int, int]:
    return entry.st_dev, entry.st_ino, entry.st_uid, stat.S_IMODE(entry.st_mode)


def _private_directory(entry: os.stat_result) -> bool:
    return (stat.S_ISDIR(entry.st_mode) and entry.st_uid == os.geteuid()
            and stat.S_IMODE(entry.st_mode) == 0o700)


def _private_file(entry: os.stat_result) -> bool:
    return (stat.S_ISREG(entry.st_mode) and entry.st_uid == os.geteuid()
            and stat.S_IMODE(entry.st_mode) == 0o600 and entry.st_nlink == 1)


def _validate_request(*, sdk_ids: list[str], group: str, profile: str,
                      host: str, compiler_family: str) -> None:
    _require(isinstance(sdk_ids, list) and 1 <= len(sdk_ids) <= 32,
             "independent SDK selection must contain one to 32 IDs")
    _require(all(isinstance(sdk_id, str) and bool(SDK_ID.fullmatch(sdk_id))
                 and sdk_id not in (".", "..") for sdk_id in sdk_ids),
             "independent SDK selection contains an invalid ID")
    _require(sdk_ids == sorted(set(sdk_ids)),
             "independent SDK IDs must be sorted and unique")
    _require(isinstance(group, str) and bool(origin.SEGMENT.fullmatch(group)),
             "independent compiler group is invalid")
    _require(isinstance(profile, str) and bool(origin.PROFILE.fullmatch(profile))
             and profile not in (".", ".."), "independent target profile is invalid")
    _require(isinstance(host, str) and host in stage.NATIVE_HOSTS,
             "independent host is not a native SDK host")
    _require(compiler_family in ("gnu", "llvm"), "compiler family must be gnu or llvm")


def _validate_signed_inventory(files: object, sdk_ids: list[str]) -> dict[str, dict]:
    _require(isinstance(files, dict), "signed SDK owner file inventory is invalid")
    origin.require_portable_inventory(files)
    prefixes = {sdk_id: f"sdk-{sdk_id}/" for sdk_id in sdk_ids}
    expected_roots = {prefix[:-1] for prefix in prefixes.values()}
    actual_roots = {name.split("/", 1)[0] for name in files}
    _require(actual_roots == expected_roots,
             "signed SDK owner inventory differs from the independently selected IDs")

    total = 0
    checked = {}
    for name, value in files.items():
        measured = origin.exact_keys(value, {"sha256", "size"})
        size, sha256 = measured["size"], measured["sha256"]
        _require(type(size) is int and 0 <= size <= MAX_PAYLOAD
                 and isinstance(sha256, str) and bool(re.fullmatch(r"[0-9a-f]{64}", sha256)),
                 "signed SDK owner file measurement is invalid")
        total += size
        _require(total <= MAX_PAYLOAD, "signed SDK owner inventory exceeds its aggregate byte limit")
        checked[name] = measured
    return checked


def _read_metadata_member(archive: zipfile.ZipFile, members: dict[str, zipfile.ZipInfo],
                          name: str, expected: dict) -> bytes:
    member = members[name]
    _require(member.file_size == expected["size"] and member.file_size <= MAX_METADATA,
             "SDK owner metadata member exceeds its byte limit")
    chunks = []
    size = 0
    with archive.open(member, "r") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            size += len(block)
            _require(size <= MAX_METADATA and size <= member.file_size,
                     "SDK owner metadata member grew beyond its byte limit")
            chunks.append(block)
    raw = b"".join(chunks)
    _require(size == member.file_size == expected["size"]
             and hashlib.sha256(raw).hexdigest() == expected["sha256"],
             "SDK owner metadata bytes differ from the signed inventory")
    return raw


def _product_closures(files: dict[str, dict], sdk_ids: list[str]) -> dict[str, dict[str, dict]]:
    closures: dict[str, dict[str, dict]] = {}
    for sdk_id in sdk_ids:
        prefix = f"sdk-{sdk_id}/"
        product = {name[len(prefix):]: measured for name, measured in files.items()
                   if name.startswith(prefix)}
        _require(product and "sdk-lane.json" in product,
                 f"SDK owner product {sdk_id} is missing its lane marker")
        _require("generation.json" in product and "compatibility-inputs.json" in product,
                 f"SDK owner product {sdk_id} is missing a required root member")

        package_names = {name[len("package/"):] for name in product if name.startswith("package/")}
        archives = sorted(name for name in package_names if name.endswith(".tar.xz"))
        _require(len(package_names) == 3 and len(archives) == 1
                 and all("/" not in name for name in package_names),
                 f"SDK owner product {sdk_id} package closure is not one archive and two sidecars")
        archive_name = archives[0]
        _require(archive_name.startswith(f"aros-sdk-{sdk_id}-")
                 and f"{archive_name}.manifest.json" in package_names
                 and f"{archive_name}.sha256" in package_names
                 and package_names == {archive_name, f"{archive_name}.manifest.json",
                                       f"{archive_name}.sha256"},
                 f"SDK owner product {sdk_id} package sidecars do not match its archive")

        compatibility_names = {name[len("compatibility/"):] for name in product
                               if name.startswith("compatibility/")}
        _require(bool(compatibility_names)
                 and all("/" not in name for name in compatibility_names)
                 and "compatibility-measurement.json" in compatibility_names,
                 f"SDK owner product {sdk_id} compatibility closure is not flat")
        allowed = {
            "sdk-lane.json", "generation.json", "compatibility-inputs.json",
            *(f"package/{name}" for name in package_names),
            *(f"compatibility/{name}" for name in compatibility_names),
        }
        _require(set(product) == allowed,
                 f"SDK owner product {sdk_id} has an extra or missing member")

        for name, measured in product.items():
            if name in ("sdk-lane.json", "generation.json", "compatibility-inputs.json") \
                    or (name.startswith("package/")
                        and (name.endswith(".manifest.json") or name.endswith(".sha256"))) \
                    or name == "compatibility/compatibility-measurement.json":
                _require(measured["size"] <= MAX_METADATA,
                         "SDK owner metadata member exceeds its byte limit")
        closures[sdk_id] = product
    return closures


def _validate_markers(archive_path: Path, files: dict[str, dict], sdk_ids: list[str],
                      group: str, profile: str, host: str,
                      compiler_family: str) -> tuple[dict[str, dict], dict[str, dict]]:
    products = _product_closures(files, sdk_ids)
    marker_results: dict[str, dict] = {}
    with zipfile.ZipFile(archive_path, "r") as archive:
        members = {member.filename: member for member in archive.infolist()}
        _require(len(members) == len(files) and set(members) == set(files),
                 "payload member list changed after signed ZIP verification")
        for sdk_id in sdk_ids:
            prefix = f"sdk-{sdk_id}/"
            product = products[sdk_id]
            lane_raw = _read_metadata_member(archive, members, prefix + "sdk-lane.json",
                                             product["sdk-lane.json"])
            lane = origin.exact_keys(
                origin.parse_json(lane_raw),
                {"schema", "assurance", "sdk_id", "group_id", "target_profile", "host", "files"},
            )
            _require(lane["schema"] == OWNER_SCHEMA and lane["assurance"] == OWNER_ASSURANCE,
                     "SDK owner lane marker schema or assurance differs")
            _require(lane["sdk_id"] == sdk_id and lane["group_id"] == group
                     and lane["target_profile"] == profile and lane["host"] == host,
                     "SDK owner lane marker differs from the independent native selection")
            lane_files = lane["files"]
            _require(isinstance(lane_files, dict) and 0 < len(lane_files) <= MAX_FILES,
                     "SDK owner lane file inventory is invalid")
            origin.require_portable_inventory(lane_files)
            for relative, measured in lane_files.items():
                measured = origin.exact_keys(measured, {"sha256", "size"})
                _require(type(measured["size"]) is int and 0 <= measured["size"] <= MAX_PAYLOAD
                         and isinstance(measured["sha256"], str)
                         and bool(re.fullmatch(r"[0-9a-f]{64}", measured["sha256"])),
                         "SDK owner lane file measurement is invalid")
            expected_lane_files = {name: measured for name, measured in product.items()
                                   if name != "sdk-lane.json"}
            _require(lane_files == expected_lane_files,
                     "SDK owner lane inventory differs from the signed product members")

            generation_raw = _read_metadata_member(
                archive, members, prefix + "generation.json", product["generation.json"])
            generation, family = stage._generation(generation_raw, sdk_id)
            _require(family == compiler_family,
                     "SDK generation schema differs from the independently selected compiler family")

            package_prefix = "package/"
            package_names = sorted(name[len(package_prefix):] for name in product
                                   if name.startswith(package_prefix))
            archive_name = next(name for name in package_names if name.endswith(".tar.xz"))
            manifest_name = f"{archive_name}.manifest.json"
            manifest_raw = _read_metadata_member(
                archive, members, prefix + package_prefix + manifest_name,
                product[package_prefix + manifest_name])
            manifest, expected_archive_name = stage._package_manifest(manifest_raw, sdk_id)
            _require(archive_name == expected_archive_name
                     and generation["identity"] == manifest["identity"],
                     "SDK package manifest identity differs from its generation record")

            checksum_raw = _read_metadata_member(
                archive, members, prefix + package_prefix + f"{archive_name}.sha256",
                product[package_prefix + f"{archive_name}.sha256"])
            expected_checksum = (f"{product[package_prefix + archive_name]['sha256']}  "
                                 f"{archive_name}\n").encode()
            _require(checksum_raw == expected_checksum,
                     "SDK package checksum sidecar differs from its signed archive digest")

            inputs_raw = _read_metadata_member(
                archive, members, prefix + "compatibility-inputs.json",
                product["compatibility-inputs.json"])
            stage.parse_json(inputs_raw, "SDK compatibility inputs")

            compatibility_names = {name[len("compatibility/"):] for name in product
                                   if name.startswith("compatibility/")}
            measurement_raw = _read_metadata_member(
                archive, members, prefix + "compatibility/compatibility-measurement.json",
                product["compatibility/compatibility-measurement.json"])
            measurement = stage._measurement(measurement_raw, compatibility_names, compiler_family)
            for relative, expected in measurement["files"].items():
                _require(expected == product[f"compatibility/{relative}"],
                         f"compatibility measurement differs from signed file {relative}")
            marker_results[sdk_id] = {
                "generation": product["generation.json"],
                "compatibility_measurement": product["compatibility/compatibility-measurement.json"],
                "compatibility_inputs": product["compatibility-inputs.json"],
            }
    return products, marker_results


def _verified_transport(retained: Path, *, sdk_ids: list[str], group: str, profile: str,
                        host: str, compiler_family: str) -> tuple[dict, dict, dict, dict]:
    _require(isinstance(retained, Path) and retained.is_absolute() and ".." not in retained.parts,
             "retained directory must be absolute and normalized")
    inputs, contents, root_identity, names = native._validate_root(retained)
    selected, signed, artifact = native._validate_identity(
        contents["selection.json"], contents["origin.json"], required_role="diagnostic")
    lane = selected["selection"]
    _require(lane["group"] == group and lane["host"] == host and lane["profile"] == profile
             and lane["role"] == "diagnostic" and lane["copy"] == "none",
             "retained diagnostic selector differs from the independent native selection")
    files = _validate_signed_inventory(signed["files"], sdk_ids)
    origin.verify_zip(retained / "payload.zip", files,
                      artifact["sha256"], artifact["size_in_bytes"])
    products, marker_results = _validate_markers(
        retained / "payload.zip", files, sdk_ids, group, profile, host, compiler_family)
    return inputs, contents, {
        "selected": selected, "signed": signed, "artifact": artifact, "files": files,
        "products": products, "marker_results": marker_results,
    }, {"root_identity": root_identity, "names": names}


def _assert_retained_same(retained: Path, before: tuple[dict, dict, dict, dict], *,
                          sdk_ids: list[str], group: str, profile: str,
                          host: str, compiler_family: str) -> None:
    inputs_before, _, _, state_before = before
    inputs_after, _, _, state_after = _verified_transport(
        retained, sdk_ids=sdk_ids, group=group, profile=profile, host=host,
        compiler_family=compiler_family)
    _require(inputs_before == inputs_after
             and state_before["root_identity"] == state_after["root_identity"]
             and state_before["names"] == state_after["names"],
             "retained SDK owner transport changed during materialization")


def _expected_directories(sdk_ids: list[str]) -> dict[str, set[str]]:
    return {f"sdk-{sdk_id}": {"generation.json", "package", "compatibility-inputs.json",
                               "compatibility", "sdk-lane.json"}
            for sdk_id in sdk_ids}


def _scan_output(output: Path, files: dict[str, dict], sdk_ids: list[str], *,
                 expected_root_identity: tuple[int, ...] | None = None,
                 expected_directory_identities: dict[str, tuple[int, ...]] | None = None) -> tuple[dict, dict]:
    _require(output.is_absolute() and ".." not in output.parts and output == output.resolve()
             and output.name not in ("", ".", ".."),
             "SDK output directory must be absolute, canonical, and non-overlapping")
    root_before = output.lstat()
    _require(_private_directory(root_before),
             "SDK output root must be an owner-only directory owned by the current user")
    root_identity = _stat_identity(root_before)
    if expected_root_identity is not None:
        _require(_directory_identity(root_before) == expected_root_identity,
                 "SDK output root identity changed during materialization")
    expected = _expected_directories(sdk_ids)
    root_names = tuple(sorted(entry.name for entry in os.scandir(output)))
    _require(root_names == tuple(sorted(expected)),
             "SDK output root differs from the selected SDK set")

    directory_states: dict[str, tuple[int, ...]] = {".": root_identity}
    for product, product_names in expected.items():
        product_path = output / product
        product_stat = product_path.lstat()
        _require(_private_directory(product_stat), "SDK product output is not a private directory")
        product_identity = _stat_identity(product_stat)
        directory_states[product] = product_identity
        actual_names = tuple(sorted(entry.name for entry in os.scandir(product_path)))
        _require(actual_names == tuple(sorted(product_names)),
                 "SDK product output differs from the signed closure")
        for folder in ("package", "compatibility"):
            directory = product_path / folder
            directory_stat = directory.lstat()
            _require(_private_directory(directory_stat),
                     "SDK output member directory is not private and ordinary")
            relative_dir = f"{product}/{folder}"
            directory_states[relative_dir] = _stat_identity(directory_stat)
            actual = tuple(sorted(entry.name for entry in os.scandir(directory)))
            member_names = {name[len(relative_dir) + 1:] for name in files
                            if name.startswith(relative_dir + "/")}
            _require(actual == tuple(sorted(member_names)),
                     "SDK output member directory differs from the signed closure")

    if expected_directory_identities is not None:
        _require(set(directory_states) == set(expected_directory_identities)
                 and all(_directory_identity((output / relative).lstat()) == identity
                         for relative, identity in expected_directory_identities.items()),
                 "SDK output directory identities changed during materialization")

    output_measurements = {}
    for name, expected_measurement in sorted(files.items()):
        path = output / name
        named = path.lstat()
        _require(_private_file(named), "SDK output member is linked or not owner-only")
        measured, _ = origin.normalized_file(path, MAX_PAYLOAD)
        _require(measured == expected_measurement,
                 "SDK output member bytes differ from the signed inventory")
        output_measurements[name] = measured

    root_after = output.lstat()
    names_after = tuple(sorted(entry.name for entry in os.scandir(output)))
    _require(_stat_identity(root_after) == root_identity and root_names == names_after
             and _private_directory(root_after), "SDK output root changed during readback")
    for relative, identity in directory_states.items():
        if relative == ".":
            continue
        directory = output / relative
        current = directory.lstat()
        names_expected = (expected[relative] if relative in expected
                          else {name[len(relative) + 1:] for name in files
                                if name.startswith(relative + "/")})
        current_names = tuple(sorted(entry.name for entry in os.scandir(directory)))
        _require(_stat_identity(current) == identity and current_names == tuple(sorted(names_expected))
                 and _private_directory(current),
                 "SDK output directory changed during readback")
    return output_measurements, directory_states


def _result(output: Path, inputs: dict, transport: dict, output_measurements: dict[str, dict],
            sdk_ids: list[str], group: str, profile: str, host: str,
            compiler_family: str) -> dict:
    sdk_generations = []
    for sdk_id in sdk_ids:
        prefix = f"sdk-{sdk_id}"
        markers = transport["marker_results"][sdk_id]
        sdk_generations.append({
            "sdk_id": sdk_id,
            "group_id": group,
            "target_profile": profile,
            "host": host,
            "package_dir": str(output / prefix / "package"),
            "record": {
                "path": str(output / prefix / "generation.json"),
                "sha256": output_measurements[f"{prefix}/generation.json"]["sha256"],
            },
            "compatibility": {
                "directory": str(output / prefix / "compatibility"),
                "manifest_sha256": output_measurements[
                    f"{prefix}/compatibility/compatibility-measurement.json"]["sha256"],
                "inputs": {
                    "path": str(output / prefix / "compatibility-inputs.json"),
                    "sha256": output_measurements[
                        f"{prefix}/compatibility-inputs.json"]["sha256"],
                },
                "native_sdk_required": compiler_family == "gnu",
            },
        })
        _require(markers["generation"] == transport["products"][sdk_id]["generation.json"]
                 and markers["compatibility_measurement"] == transport["products"][sdk_id][
                     "compatibility/compatibility-measurement.json"],
                 "SDK result marker identity changed")
    return {
        "schema": SCHEMA,
        "assurance": ASSURANCE,
        "origin_sha256": inputs["origin.json"]["sha256"],
        "selection_sha256": inputs["selection.json"]["sha256"],
        "raw_zip_sha256": inputs["payload.zip"]["sha256"],
        "sdk_generations": sdk_generations,
    }


def _extract(retained: Path, output: Path, *, sdk_ids: list[str], group: str,
             profile: str, host: str, compiler_family: str) -> dict:
    _validate_request(sdk_ids=sdk_ids, group=group, profile=profile,
                      host=host, compiler_family=compiler_family)
    retained_before = _verified_transport(
        retained, sdk_ids=sdk_ids, group=group, profile=profile, host=host,
        compiler_family=compiler_family)
    inputs, _, transport, _ = retained_before
    files = transport["files"]
    output, parent_before = native._output_preflight(retained, output)

    parent_fd = os.open(output.parent, DIR_FLAGS)
    root_fd = None
    child_fds: dict[str, int] = {}
    directory_identities: dict[str, tuple[int, ...]] = {}
    try:
        parent_open = os.fstat(parent_fd)
        parent_named = output.parent.lstat()
        _require(_inode_identity(parent_open) == _inode_identity(parent_named)
                 and _directory_identity(parent_before) == _directory_identity(parent_named),
                 "SDK output parent changed after preflight")
        try:
            os.mkdir(output.name, mode=0o700, dir_fd=parent_fd)
        except FileExistsError:
            raise origin.OriginError("SDK output directory must remain fresh") from None
        root_named = os.stat(output.name, dir_fd=parent_fd, follow_symlinks=False)
        root_identity = _inode_identity(root_named)
        os.chmod(output.name, 0o700, dir_fd=parent_fd, follow_symlinks=False)
        root_fd = os.open(output.name, DIR_FLAGS, dir_fd=parent_fd)
        root_open = os.fstat(root_fd)
        _require(_inode_identity(root_open) == root_identity and _private_directory(root_open),
                 "SDK output root is not a private ordinary directory")
        directory_identities["."] = _directory_identity(root_open)

        for sdk_id in sdk_ids:
            product = f"sdk-{sdk_id}"
            product_fd, _ = native._create_directory(root_fd, product)
            child_fds[product] = product_fd
            directory_identities[product] = _directory_identity(os.fstat(product_fd))
            for folder in ("package", "compatibility"):
                folder_fd, _ = native._create_directory(product_fd, folder)
                key = f"{product}/{folder}"
                child_fds[key] = folder_fd
                directory_identities[key] = _directory_identity(os.fstat(folder_fd))

        created_files: dict[tuple[str, str], tuple[int, int]] = {}
        output_measurements = {}
        with zipfile.ZipFile(retained / "payload.zip", "r") as archive:
            members = {member.filename: member for member in archive.infolist()}
            _require(len(members) == len(files) and set(members) == set(files),
                     "payload member list changed after signed ZIP verification")
            for name in sorted(files):
                parts = name.split("/")
                if len(parts) == 2:
                    folder_key, basename = parts[0], parts[1]
                else:
                    folder_key, basename = "/".join(parts[:-1]), parts[-1]
                target_fd = child_fds.get(folder_key)
                _require(target_fd is not None, "SDK output path has no precreated directory")
                output_measurements[name] = native._write_member(
                    archive, members[name], target_fd, basename, files[name],
                    created_files, folder_key)
                identity = created_files[(folder_key, basename)]
                named_before_mode = os.stat(basename, dir_fd=target_fd, follow_symlinks=False)
                _require(stat.S_ISREG(named_before_mode.st_mode) and named_before_mode.st_nlink == 1
                         and named_before_mode.st_uid == os.geteuid()
                         and _inode_identity(named_before_mode) == identity,
                         "SDK output member identity changed before mode normalization")
                os.chmod(basename, 0o600, dir_fd=target_fd, follow_symlinks=False)
                named_after_mode = os.stat(basename, dir_fd=target_fd, follow_symlinks=False)
                _require(_private_file(named_after_mode)
                         and _inode_identity(named_after_mode) == identity,
                         "SDK output member changed during mode normalization")

        extracted, directory_identities = _scan_output(
            output, files, sdk_ids, expected_root_identity=directory_identities["."],
            expected_directory_identities=directory_identities)
        _require(output_measurements == extracted,
                 "SDK output readback differs from streamed archive members")
        _assert_retained_same(
            retained, retained_before, sdk_ids=sdk_ids, group=group, profile=profile,
            host=host, compiler_family=compiler_family)
        parent_final = output.parent.lstat()
        root_final = os.stat(output.name, dir_fd=parent_fd, follow_symlinks=False)
        _require(output.parent == output.parent.resolve()
                 and _directory_identity(parent_before) == _directory_identity(parent_final)
                 and _inode_identity(root_final) == root_identity and _private_directory(root_final),
                 "SDK output parent or root changed before completion")
        return _result(output, inputs, transport, extracted, sdk_ids, group, profile, host,
                       compiler_family)
    finally:
        for descriptor in child_fds.values():
            os.close(descriptor)
        if root_fd is not None:
            os.close(root_fd)
        os.close(parent_fd)


def extract(retained: Path, output: Path, *, sdk_ids: list[str], group: str,
            profile: str, host: str, compiler_family: str) -> dict:
    """Verify a diagnostic retained bundle and stream its exact SDK closure."""
    try:
        return _extract(retained, output, sdk_ids=sdk_ids, group=group, profile=profile,
                        host=host, compiler_family=compiler_family)
    except origin.OriginError:
        raise
    except stage.StageError as error:
        raise origin.OriginError(str(error)) from None
    except Exception as error:
        raise origin.OriginError("SDK owner transport extraction failed at a closed byte boundary") from error


def _verify_output(retained: Path, output: Path, *, sdk_ids: list[str], group: str,
                   profile: str, host: str, compiler_family: str) -> dict:
    _validate_request(sdk_ids=sdk_ids, group=group, profile=profile,
                      host=host, compiler_family=compiler_family)
    retained_before = _verified_transport(
        retained, sdk_ids=sdk_ids, group=group, profile=profile, host=host,
        compiler_family=compiler_family)
    inputs, _, transport, _ = retained_before
    _require(isinstance(output, Path) and output.is_absolute() and ".." not in output.parts
             and output == output.resolve() and output != retained
             and output not in retained.parents and retained not in output.parents,
             "verification output must be a canonical non-overlapping directory")
    parent = output.parent
    _require(parent == parent.resolve() and parent.is_dir() and not parent.is_symlink(),
             "verification output parent must be canonical")
    output_measurements, _ = _scan_output(output, transport["files"], sdk_ids)
    _assert_retained_same(
        retained, retained_before, sdk_ids=sdk_ids, group=group, profile=profile,
        host=host, compiler_family=compiler_family)
    return _result(output, inputs, transport, output_measurements, sdk_ids, group, profile,
                   host, compiler_family)


def verify_output(retained: Path, output: Path, *, sdk_ids: list[str], group: str,
                  profile: str, host: str, compiler_family: str) -> dict:
    """Read back a prior output and retained transport without writing anything."""
    try:
        return _verify_output(retained, output, sdk_ids=sdk_ids, group=group, profile=profile,
                              host=host, compiler_family=compiler_family)
    except origin.OriginError:
        raise
    except stage.StageError as error:
        raise origin.OriginError(str(error)) from None
    except Exception as error:
        raise origin.OriginError("SDK owner transport verification failed at a closed byte boundary") from error


def _parse_sdk_ids(raw: str) -> list[str]:
    try:
        value = origin.parse_json(raw.encode("utf-8"))
    except (UnicodeError, origin.OriginError):
        raise argparse.ArgumentTypeError("--sdk-ids must be a JSON array of SDK IDs") from None
    if not isinstance(value, list):
        raise argparse.ArgumentTypeError("--sdk-ids must be a JSON array of SDK IDs")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--retained-dir", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--output-dir", type=Path)
    mode.add_argument("--verify-output-dir", type=Path)
    parser.add_argument("--sdk-ids", type=_parse_sdk_ids, required=True,
                        help="sorted JSON array from the reviewed native plan")
    parser.add_argument("--group", required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--compiler-family", choices=("gnu", "llvm"), required=True)
    args = parser.parse_args(argv)
    try:
        options = {"sdk_ids": args.sdk_ids, "group": args.group, "profile": args.profile,
                   "host": args.host, "compiler_family": args.compiler_family}
        result = (extract(args.retained_dir, args.output_dir, **options)
                  if args.output_dir is not None
                  else verify_output(args.retained_dir, args.verify_output_dir, **options))
    except origin.OriginError as error:
        print(f"SDK owner transport rejected: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
