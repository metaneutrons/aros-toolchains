#!/usr/bin/env python3
"""Select a non-publishing V2 route; authenticate product tags before fan-out."""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys


SHA = re.compile(r"[0-9a-f]{40}")
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
BRANCH = re.compile(r"refs/heads/[A-Za-z0-9_./-]+")
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("v2_release_tag", HERE / "validate-release-tag.py")
TAG = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TAG)
ADMISSION_SPEC = importlib.util.spec_from_file_location(
    "v2_route_admission", HERE / "release-admission-v2.py"
)
ADMISSION = importlib.util.module_from_spec(ADMISSION_SPEC)
ADMISSION_SPEC.loader.exec_module(ADMISSION)
MAX_COMMAND_STDOUT = 8 * 1024 * 1024
MAX_COMMAND_STDERR = 64 * 1024


class RouteError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise RouteError(message)


def unique_object(pairs):
    result = {}
    for name, value in pairs:
        require(name not in result, "duplicate JSON field in route inputs")
        result[name] = value
    return result


def document(path):
    require(path.is_file() and not path.is_symlink(), "route input must be a regular file")
    require(path.stat().st_size <= 1024 * 1024, "route input exceeds its metadata limit")
    value = json.loads(path.read_bytes(), object_pairs_hook=unique_object)
    require(isinstance(value, dict), "route input must be a JSON object")
    return value


def command(arguments, *, allow_failure=False):
    environment = dict(os.environ)
    environment.pop("GOVERNANCE_TOKEN", None)
    try:
        captured = ADMISSION._bounded_subprocess(
            arguments, cwd=None, timeout=60,
            stdout_limit=MAX_COMMAND_STDOUT, stderr_limit=MAX_COMMAND_STDERR,
            env=environment, label="route identity command",
        )
    except ADMISSION.AdmissionError as error:
        raise RouteError(str(error)) from error
    result = subprocess.CompletedProcess(
        arguments, captured.returncode,
        captured.stdout.decode("utf-8", errors="strict"),
        captured.stderr.decode("utf-8", errors="strict"),
    )
    require(allow_failure or result.returncode == 0, "route identity command failed")
    return result


def git(root, *arguments):
    return command(["git", "-C", str(root), *arguments]).stdout.strip()


def api(repository, endpoint):
    result = command(["gh", "api", f"repos/{repository}/{endpoint}"])
    value = json.loads(result.stdout, object_pairs_hook=unique_object)
    require(isinstance(value, dict), "GitHub identity response must be an object")
    return value


def authenticate_tag(args, tools_commit):
    require(args.run_attempt == "1", "product tags cannot be requalified by rerunning an attempt")
    require(args.ref_type == "tag" and args.source_ref.startswith("refs/tags/"),
            "push qualification requires a tag ref")
    name = args.source_ref.removeprefix("refs/tags/")
    try:
        prerelease = TAG.classify_tag(name)
    except ValueError as error:
        raise RouteError("product tag is not canonical SemVer") from error
    require(args.mode == args.scope == args.group == "",
            "tag qualification does not accept diagnostic selectors")
    require(REPOSITORY.fullmatch(args.repository) is not None, "repository identity is invalid")

    # Reject the unpublished development snapshot before any network request or
    # expensive checkout/materialization. The runtime helper subsequently verifies
    # the complete lock, immutable release, signatures and native file inventory.
    runtime = document(args.runtime_lock)
    require(runtime.get("schema") == "aros-tools-runtime-v1"
            and runtime.get("source_commit") == tools_commit,
            "tag qualification requires the selected published runtime commit")

    require(git(args.producer_dir, "rev-parse", "HEAD") == args.producer_commit,
            "producer checkout differs from the event commit")
    require(git(args.producer_dir, "status", "--porcelain", "--untracked-files=normal") == "",
            "tag qualification requires a clean producer checkout")
    version = git(args.producer_dir, "show", f"{args.producer_commit}:version.txt")
    require(name.split("-rc.", 1)[0] == f"v{version}",
            "product tag differs from the committed Release Please version")
    require(git(args.producer_dir, "cat-file", "-t", args.source_ref) == "tag",
            "product tag must be annotated")
    require(git(args.producer_dir, "for-each-ref", "--format=%(tag)", args.source_ref) == name,
            "annotated tag name differs from its selected ref")
    tag_object = git(args.producer_dir, "rev-parse", f"{args.source_ref}^{{tag}}")
    require(SHA.fullmatch(tag_object) is not None, "annotated tag object is invalid")
    require(git(args.producer_dir, "rev-parse", f"{args.source_ref}^{{commit}}")
            == args.producer_commit, "product tag does not peel to the event commit")

    remote = api(args.repository, f"git/ref/tags/{name}")
    require(remote.get("ref") == args.source_ref
            and remote.get("object", {}).get("type") == "tag"
            and remote.get("object", {}).get("sha") == tag_object,
            "remote tag object differs from the selected annotated tag")
    annotated = api(args.repository, f"git/tags/{tag_object}")
    require(annotated.get("sha") == tag_object
            and annotated.get("object", {}).get("type") == "commit"
            and annotated.get("object", {}).get("sha") == args.producer_commit,
            "remote annotated tag does not directly select the event commit")

    main = api(args.repository, "branches/main")
    main_commit = main.get("commit", {}).get("sha")
    require(main.get("protected") is True and isinstance(main_commit, str)
            and SHA.fullmatch(main_commit) is not None,
            "product qualification requires the protected main branch")
    ancestry = api(args.repository, f"compare/{args.producer_commit}...{main_commit}")
    require(ancestry.get("base_commit", {}).get("sha") == args.producer_commit
            and ancestry.get("merge_base_commit", {}).get("sha") == args.producer_commit
            and ancestry.get("status") in ("ahead", "identical"),
            "product tag commit is not in protected main history")

    # Only an actual 404 proves absence. Authentication failures, rate limits,
    # transport errors and successful existing-release reads all fail closed.
    absence = command(["gh", "api", "--include", "--silent",
                       f"repos/{args.repository}/releases/tags/{name}"], allow_failure=True)
    statuses = re.findall(r"(?m)^HTTP/\S+\s+(\d{3})(?:\s|$)", absence.stdout)
    require(absence.returncode != 0 and statuses == ["404"],
            "GitHub did not prove that the product release is absent")
    epoch = git(args.producer_dir, "for-each-ref", "--format=%(taggerdate:unix)", args.source_ref)
    require(re.fullmatch(r"[1-9][0-9]*", epoch) is not None,
            "annotated tag timestamp is invalid")
    return {"release_id": name, "prerelease": str(prerelease).lower(),
            "tag_object": tag_object, "tag_epoch": epoch}


def select(args):
    require(re.fullmatch(r"[1-9][0-9]*", args.run_attempt) is not None,
            "workflow attempt is invalid")
    require(SHA.fullmatch(args.producer_commit) is not None, "producer commit is invalid")
    selection = document(args.selection)
    require(selection.get("schema") == "aros-compiler-sdk-ci-selection-v2",
            "compiler/SDK selection schema is invalid")
    for field in ("source_commit", "tools_commit"):
        value = selection.get(field)
        require(isinstance(value, str) and SHA.fullmatch(value) is not None,
                "selected source or tools commit is invalid")
    outputs = {field: selection[field] for field in ("source_commit", "tools_commit")}
    if args.event == "push":
        outputs.update(authenticate_tag(args, selection["tools_commit"]))
        outputs.update(event="push", scope="full", full_qualification="false",
                       runtime_kind="released", full_matrix="true")
    else:
        require(args.event == "workflow_dispatch" and args.ref_type == "branch"
                and BRANCH.fullmatch(args.source_ref) is not None,
                "diagnostics require a branch workflow dispatch")
        require(git(args.producer_dir, "check-ref-format", args.source_ref) == "",
                "diagnostic branch ref is invalid")
        require((args.mode, args.scope) in (("qualify-v2", "linux-x86_64"),
                                          ("qualify-v2-full", "full")),
                "diagnostic mode or host scope is unsupported")
        full = args.mode == "qualify-v2-full"
        require(not full or args.group == "", "full qualification cannot select one group")
        outputs.update(event="workflow_dispatch", scope=args.scope,
                       full_qualification=str(full).lower(), runtime_kind="development",
                       full_matrix=str(full).lower(),
                       release_id=f"toolchain-dev-{args.producer_commit[:12]}")
    return outputs


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    for name in ("event", "ref-type", "source-ref", "repository", "producer-commit", "run-attempt"):
        result.add_argument(f"--{name}", required=True)
    for name in ("producer-dir", "selection", "runtime-lock", "github-output"):
        result.add_argument(f"--{name}", type=Path, required=True)
    for name in ("mode", "scope", "group"):
        result.add_argument(f"--{name}", default="")
    return result


def main():
    args = parser().parse_args()
    try:
        outputs = select(args)
        # No output mutation occurs until all tag identity/absence gates pass.
        with args.github_output.open("a", encoding="utf-8") as output:
            for name, value in outputs.items():
                output.write(f"{name}={value}\n")
    except (OSError, ValueError, TypeError, AttributeError, subprocess.SubprocessError) as error:
        print(f"compiler/SDK route rejected: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
