#!/usr/bin/env python3
"""Check that the selected SDK lock matches the native SoftFloat fetch recipe."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable


ROOT = Path(__file__).resolve().parents[3]
INPUT_ID = "softfloat-3e"
SDK_ID = "arm-raspi"
FETCH_TARGET = "linklibs-softfloat-fetch"
ARCHIVE = "SoftFloat-3e"
ARCHIVE_SUFFIX = "zip"
ARCHIVE_ORIGIN = "https://www.jhauser.us/arithmetic"
ARCHIVE_URL = f"{ARCHIVE_ORIGIN}/{ARCHIVE}.{ARCHIVE_SUFFIX}"
SOURCE_INPUTS = (
    "tools/genmf/genmf.py",
    "config/make.tmpl",
    "config/aros.cfg",
    "compiler/softfloat/mmakefile.src",
    "config/make.tail",
    "tools/genmodule/Makefile.deps",
    "config/make-autotools.tmpl",
    "config/make-cmake.tmpl",
    "config/make-meson.tmpl",
)
TEMPLATE_INCLUDE_CLOSURE = {
    "config/make.tmpl": (
        "config/make-autotools.tmpl",
        "config/make-cmake.tmpl",
        "config/make-meson.tmpl",
    ),
    "config/make-autotools.tmpl": (),
    "config/make-cmake.tmpl": (),
    "config/make-meson.tmpl": (),
}


class CheckFailure(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CheckFailure(message)


def unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise CheckFailure(f"duplicate JSON field {key!r}")
        result[key] = value
    return result


def read_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=unique_json_object
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CheckFailure(f"cannot read JSON document {path}: {error}") from error
    require(isinstance(value, dict), f"{path} must contain a JSON object")
    return value


def unique_by(items: object, field: str, value: str, label: str) -> dict[str, object]:
    require(isinstance(items, list), f"{label} must be an array")
    matches = [item for item in items if isinstance(item, dict) and item.get(field) == value]
    require(len(matches) == 1, f"{label} must contain exactly one {field}={value!r}")
    return matches[0]


def require_single_softfloat_selection(input_ids: object, label: str) -> None:
    require(
        isinstance(input_ids, list) and input_ids.count(INPUT_ID) == 1,
        f"{label} must declare exactly one {INPUT_ID!r} input",
    )


def selected_lock_and_entry(
    producer_root: Path,
) -> tuple[Path, dict[str, object], dict[str, object], dict[str, object]]:
    selection = read_json(producer_root / "toolchains/compiler-sdk-ci-selection-v2.json")
    require(
        selection.get("schema") == "aros-compiler-sdk-ci-selection-v2",
        "unexpected compiler SDK selection schema",
    )
    sdk = unique_by(selection.get("sdks"), "id", SDK_ID, "selected SDKs")
    source_preset = sdk.get("source_preset")
    require(isinstance(source_preset, str), f"SDK {SDK_ID} has no source preset")
    compiler_profiles = sdk.get("compiler_profiles")
    require(
        isinstance(compiler_profiles, list) and len(compiler_profiles) == 1,
        f"SDK {SDK_ID} must select exactly one compiler profile in this fixture",
    )
    compiler_profile = compiler_profiles[0]
    require(
        isinstance(compiler_profile, dict)
        and compiler_profile.get("profile") == source_preset,
        f"SDK {SDK_ID} compiler profile must match its source preset",
    )
    group_id = compiler_profile.get("group_id")
    require(isinstance(group_id, str), f"SDK {SDK_ID} has no compiler group")
    group = unique_by(selection.get("groups"), "id", group_id, "selected compiler groups")
    lock_name = group.get("ports_lock")
    require(isinstance(lock_name, str), f"selected compiler group {group_id} has no ports lock")
    lock_relative = PurePosixPath(lock_name)
    require(
        not lock_relative.is_absolute() and ".." not in lock_relative.parts,
        "selected ports lock path is unsafe",
    )
    lock_path = producer_root.joinpath(*lock_relative.parts)
    lock = read_json(lock_path)
    require(
        lock.get("schema") == "aros-toolchain-compatibility-ports-v3",
        "selected ports lock has an unexpected schema",
    )
    require(
        lock.get("upstream_commit") == selection.get("source_commit"),
        "selected ports lock differs from the selected source commit",
    )
    profile = unique_by(lock.get("profiles"), "name", source_preset, "selected ports profiles")
    require_single_softfloat_selection(profile.get("inputs"), "selected ports profile")
    entry = unique_by(lock.get("inputs"), "id", INPUT_ID, "selected ports inputs")
    return lock_path, lock, entry, profile


def require_marker_matches(entry: dict[str, object], source_marker: str) -> None:
    require(
        entry.get("fetch_marker") == source_marker,
        f"selected {INPUT_ID} fetch_marker {entry.get('fetch_marker')!r} "
        f"does not match the source recipe marker {source_marker!r}",
    )


def require_counterprobe_rejected(label: str, check: Callable[[], None]) -> None:
    try:
        check()
    except CheckFailure:
        return
    raise CheckFailure(f"{label} counterprobe was unexpectedly accepted")


def git_result(source_root: Path, arguments: list[str]) -> subprocess.CompletedProcess[str]:
    git_program = shutil.which("git")
    require(git_program is not None, "Git is required to verify the checked source tree")
    try:
        return subprocess.run(
            [git_program, *arguments],
            cwd=source_root,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CheckFailure(f"cannot inspect checked source Git state: {error}") from error


def verify_source_identity(source_root: Path, selected_commit: str) -> None:
    head = git_result(source_root, ["rev-parse", "--verify", "HEAD^{commit}"])
    require(head.returncode == 0, f"cannot read checked source HEAD: {head.stderr.strip()}")
    actual_commit = head.stdout.strip()
    require(
        actual_commit == selected_commit,
        f"checked source HEAD {actual_commit!r} does not match selected lock commit "
        f"{selected_commit!r}",
    )

    tracked = git_result(source_root, ["ls-files", "--error-unmatch", "--", *SOURCE_INPUTS])
    require(
        tracked.returncode == 0,
        f"selected source inputs are not all tracked at HEAD: {tracked.stderr.strip()}",
    )
    difference = git_result(source_root, ["diff", "--quiet", "HEAD", "--", *SOURCE_INPUTS])
    require(
        difference.returncode == 0,
        "selected source inputs differ from HEAD: " + ", ".join(SOURCE_INPUTS),
    )


def verify_exact_template_include_closure(source_root: Path) -> None:
    for template_relative, expected in TEMPLATE_INCLUDE_CLOSURE.items():
        template_path = source_root / template_relative
        try:
            template_text = template_path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            raise CheckFailure(f"cannot read GenMF template {template_path}: {error}") from error

        includes = []
        for line_number, line in enumerate(template_text.splitlines(), start=1):
            stripped = line.lstrip()
            if not re.match(r"%include(?:[ \t]|$)", stripped):
                continue
            match = re.fullmatch(r"%include[ \t]+([^ \t]+)[ \t]*", stripped)
            require(
                match is not None,
                f"malformed %include directive in {template_relative}:{line_number}",
            )
            child = PurePosixPath(match.group(1))
            require(
                not child.is_absolute() and ".." not in child.parts,
                f"unsafe %include path in {template_relative}:{line_number}",
            )
            includes.append((PurePosixPath(template_relative).parent / child).as_posix())
        require(
            tuple(includes) == expected,
            f"unexpected %include closure for {template_relative}: {tuple(includes)!r}",
        )


def verify_source_identity_counterprobes() -> None:
    def run_git(source_root: Path, arguments: list[str]) -> str:
        result = git_result(source_root, arguments)
        require(
            result.returncode == 0,
            f"Git fixture command {arguments!r} failed: {result.stderr.strip()}",
        )
        return result.stdout.strip()

    with tempfile.TemporaryDirectory(prefix="sdk-softfloat-source-identity-") as temporary:
        fixture = Path(temporary)
        run_git(fixture, ["init", "--quiet"])
        for relative in SOURCE_INPUTS:
            path = fixture / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            if relative == "config/make.tmpl":
                contents = "".join(
                    f"%include {PurePosixPath(child).name}\n"
                    for child in TEMPLATE_INCLUDE_CLOSURE[relative]
                )
            else:
                contents = f"fixture input: {relative}\n"
            path.write_text(contents, encoding="utf-8")
        unrelated = fixture / "unrelated.txt"
        unrelated.write_text("committed unrelated state\n", encoding="utf-8")
        run_git(fixture, ["add", "--", *SOURCE_INPUTS, "unrelated.txt"])
        run_git(
            fixture,
            [
                "-c", "user.name=SoftFloat marker test",
                "-c", "user.email=softfloat-marker-test@example.invalid",
                "commit", "--quiet", "-m", "source fixture",
            ],
        )
        original_commit = run_git(fixture, ["rev-parse", "--verify", "HEAD^{commit}"])
        verify_source_identity(fixture, original_commit)
        verify_exact_template_include_closure(fixture)

        unrelated.write_text("modified unrelated state\n", encoding="utf-8")
        (fixture / "unrelated-untracked.txt").write_text("untracked\n", encoding="utf-8")
        verify_source_identity(fixture, original_commit)

        run_git(fixture, ["add", "--", "unrelated.txt"])
        run_git(
            fixture,
            [
                "-c", "user.name=SoftFloat marker test",
                "-c", "user.email=softfloat-marker-test@example.invalid",
                "commit", "--quiet", "-m", "unrelated source commit",
            ],
        )
        current_commit = run_git(fixture, ["rev-parse", "--verify", "HEAD^{commit}"])
        require_counterprobe_rejected(
            "wrong source HEAD",
            lambda: verify_source_identity(fixture, original_commit),
        )
        verify_source_identity(fixture, current_commit)

        for relative in SOURCE_INPUTS:
            path = fixture / relative
            original_text = path.read_text(encoding="utf-8")
            path.write_text(original_text + "dirty selected input\n", encoding="utf-8")
            if relative == SOURCE_INPUTS[1]:
                run_git(fixture, ["add", "--", relative])
            require_counterprobe_rejected(
                f"dirty selected input {relative}",
                lambda: verify_source_identity(fixture, current_commit),
            )
            path.write_text(original_text, encoding="utf-8")
            if relative == SOURCE_INPUTS[1]:
                run_git(fixture, ["add", "--", relative])

        verify_source_identity(fixture, current_commit)
        verify_exact_template_include_closure(fixture)

        included_template = fixture / "config/make-autotools.tmpl"
        original_text = included_template.read_text(encoding="utf-8")
        included_template.write_text(original_text + "%include hidden.tmpl\n", encoding="utf-8")
        require_counterprobe_rejected(
            "unlisted nested template include",
            lambda: verify_exact_template_include_closure(fixture),
        )
        included_template.write_text(original_text, encoding="utf-8")


def verify_selection_counterprobes(profile: dict[str, object]) -> None:
    input_ids = profile.get("inputs")
    require(isinstance(input_ids, list), "selected ports profile inputs must be an array")
    missing = [input_id for input_id in input_ids if input_id != INPUT_ID]
    duplicate = [*input_ids, INPUT_ID]
    require_counterprobe_rejected(
        "missing SoftFloat input selection",
        lambda: require_single_softfloat_selection(missing, "counterprobe profile"),
    )
    require_counterprobe_rejected(
        "duplicate SoftFloat input selection",
        lambda: require_single_softfloat_selection(duplicate, "counterprobe profile"),
    )


def verify_marker_counterprobes(lock: dict[str, object], source_marker: str) -> None:
    for label, bad_marker in (
        ("removed marker", ""),
        ("wrong marker", f".{INPUT_ID}-wrong-fetched"),
    ):
        probe_lock = copy.deepcopy(lock)
        probe_entry = unique_by(probe_lock.get("inputs"), "id", INPUT_ID, "counterprobe inputs")
        probe_entry["fetch_marker"] = bad_marker
        require_counterprobe_rejected(
            label, lambda probe_entry=probe_entry: require_marker_matches(probe_entry, source_marker)
        )


def option_values(arguments: list[str], option: str) -> list[str]:
    return [
        arguments[index + 1]
        for index, argument in enumerate(arguments[:-1])
        if argument == option
    ]


def require_exact_option(arguments: list[str], option: str, expected: str) -> None:
    values = option_values(arguments, option)
    require(values == [expected], f"fetch recipe {option} must be exactly {expected!r}, got {values!r}")


def emitted_fetch_marker(source_root: Path, selected_commit: str) -> str:
    verify_source_identity(source_root, selected_commit)
    verify_exact_template_include_closure(source_root)
    make_program = shutil.which("gmake") or shutil.which("make")
    require(make_program is not None, "GNU make is required for the source macro probe")
    version = subprocess.run(
        [make_program, "--version"], capture_output=True, text=True, check=False, timeout=10
    )
    require(version.returncode == 0 and "GNU Make " in version.stdout,
            "the source macro probe requires GNU make")

    for relative in SOURCE_INPUTS:
        path = source_root / relative
        require(path.is_file() and not path.is_symlink(), f"missing regular source input: {path}")
    genmf = source_root / "tools/genmf/genmf.py"
    template = source_root / "config/make.tmpl"
    source_recipe = source_root / "compiler/softfloat/mmakefile.src"

    with tempfile.TemporaryDirectory(prefix="sdk-softfloat-marker-") as temporary:
        fixture = Path(temporary)
        top = fixture / "top"
        (top / "config").mkdir(parents=True)
        (top / "config/make.cfg").touch()
        ports_sources = fixture / "ports-sources"
        output_makefile = fixture / "softfloat.mk"
        generated = subprocess.run(
            [sys.executable, str(genmf), str(template), str(source_recipe), str(output_makefile)],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        require(
            generated.returncode == 0,
            f"GenMF failed for the native SoftFloat source recipe: {generated.stderr}",
        )
        make_result = subprocess.run(
            [
                make_program,
                "-n",
                "-f",
                str(output_makefile),
                FETCH_TARGET,
                f"TOP={top}",
                f"SRCDIR={source_root}",
                "CURDIR=compiler/softfloat",
                f"GENDIR={fixture / 'generated'}",
                f"PORTSDIR={fixture / 'ports'}",
                f"PORTSSOURCEDIR={ports_sources}",
                "FETCH=sdk-fetch-probe",
                "ECHO=echo",
                "IF=if",
                "TEST=test",
                "TOUCH=touch",
                "Q=",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        require(
            make_result.returncode == 0,
            f"GNU make could not expand {FETCH_TARGET}: {make_result.stderr}",
        )

        expanded = re.sub(r"\\\r?\n[ \t]*", " ", make_result.stdout)
        fetch_commands = []
        for line in expanded.splitlines():
            try:
                arguments = shlex.split(line)
            except ValueError as error:
                raise CheckFailure(f"cannot parse expanded fetch command: {error}") from error
            if arguments and arguments[0] == "sdk-fetch-probe":
                fetch_commands.append(arguments)
        require(len(fetch_commands) == 1, f"expected one expanded fetch command, got {fetch_commands!r}")
        fetch_arguments = fetch_commands[0]
        require_exact_option(fetch_arguments, "-ao", ARCHIVE_ORIGIN)
        require_exact_option(fetch_arguments, "-a", ARCHIVE)
        require_exact_option(fetch_arguments, "-s", ARCHIVE_SUFFIX)
        require_exact_option(fetch_arguments, "-l", str(ports_sources))
        require_exact_option(fetch_arguments, "-d", str(fixture / "ports/libsoftfloat"))
        require_exact_option(fetch_arguments, "-po", f"{source_root}/compiler/softfloat")

        touched = re.findall(r"(?<!\S)touch[ \t]+([^\s;\\]+)", make_result.stdout)
        require(len(touched) == 1, f"expected one generated fetch completion touch, found {touched!r}")
        touched_path = Path(touched[0])
        try:
            relative = touched_path.relative_to(ports_sources)
        except ValueError as error:
            raise CheckFailure("generated fetch marker is outside PORTSSOURCEDIR") from error
        marker = PurePosixPath(relative.as_posix())
        require(not marker.is_absolute() and ".." not in marker.parts,
                "generated fetch marker is not a safe relative path")
        require(
            marker.as_posix() == ".SoftFloat-3e-fetched",
            f"expanded SoftFloat-3e source recipe emitted an unexpected marker: {marker}",
        )
        return marker.as_posix()


def main() -> int:
    source_value = os.environ.get("AROS_TEST_V2_SOURCE_ROOT")
    require(source_value, "set AROS_TEST_V2_SOURCE_ROOT to the checked source tree")
    source_root = Path(source_value).resolve(strict=True)
    producer_root = ROOT.resolve(strict=True)
    require(source_root.is_dir() and producer_root.is_dir(), "test roots must be directories")

    lock_path, lock, entry, profile = selected_lock_and_entry(producer_root)
    selected_commit = lock.get("upstream_commit")
    require(isinstance(selected_commit, str), "selected ports lock has no upstream commit")
    verify_source_identity_counterprobes()
    marker = emitted_fetch_marker(source_root, selected_commit)
    require(entry.get("cache_filename") == f"{ARCHIVE}.{ARCHIVE_SUFFIX}",
            f"selected {INPUT_ID} cache filename changed unexpectedly")
    require(entry.get("relative_path") == f"{ARCHIVE}.{ARCHIVE_SUFFIX}",
            f"selected {INPUT_ID} relative path changed unexpectedly")
    require(entry.get("cmake_cache_path") == f"portssources/{ARCHIVE}.{ARCHIVE_SUFFIX}",
            f"selected {INPUT_ID} CMake cache path changed unexpectedly")
    require(entry.get("url") == ARCHIVE_URL,
            f"selected {INPUT_ID} URL does not match the exact source recipe {ARCHIVE_URL!r}")
    require_marker_matches(entry, marker)
    verify_marker_counterprobes(lock, marker)
    verify_selection_counterprobes(profile)

    print(f"PASS: {FETCH_TARGET} emits {marker} for {ARCHIVE}.{ARCHIVE_SUFFIX}")
    print(f"PASS: checked source HEAD and selected inputs match {selected_commit}")
    print("PASS: wrong-HEAD and dirty-selected-input counterprobes are rejected")
    print("PASS: unlisted nested GenMF template includes are rejected")
    print("PASS: unrelated source-tree changes are outside the selected-input check")
    print(f"PASS: selected {SDK_ID} {INPUT_ID} ports lock matches the generated marker")
    print("PASS: removed-marker and wrong-marker counterprobes are rejected in memory")
    print("PASS: missing and duplicate SoftFloat input selections are rejected")
    print(f"PASS: selected lock path is {lock_path.relative_to(producer_root)}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CheckFailure as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
