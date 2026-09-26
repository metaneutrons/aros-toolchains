#!/usr/bin/env bash
# shellcheck disable=SC2016
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

script_dir=$(cd "$(dirname "$0")" && pwd -P)
source_root=$(cd "$script_dir/../../.." && pwd -P)
: "${AROS_TEST_SOURCE_ROOT:?AROS_TEST_SOURCE_ROOT must name the AROS source checkout}"
for obsolete in producer.py build-release.sh compatibility.sh offline-fetch.py host-python-env.py; do
    if [[ -e "$source_root/scripts/toolchain/$obsolete" || -L "$source_root/scripts/toolchain/$obsolete" ]]; then
        echo "obsolete producer entry point remains in the active tree: $obsolete" >&2
        exit 1
    fi
done
python3 - "$source_root/.github/workflows/toolchain-release.yml" <<'PY'
from pathlib import Path
import json
import re
import sys

workflow_path = Path(sys.argv[1])
source_root = workflow_path.parents[2]
workflow = workflow_path.read_text(encoding="utf-8")


def fail(message: str) -> None:
    raise SystemExit(message)


executor = source_root / "toolchains/producer-executor-v1.toml"
if not executor.is_file() or executor.is_symlink():
    fail("native toolchain plan requires one regular producer executor contract")

release_please = (source_root / ".github/workflows/release-please.yml").read_text(
    encoding="utf-8"
)
release_please_config = json.loads(
    (source_root / "release-please-config.json").read_text(encoding="utf-8")
)
if (
    release_please_config.get("release-type") != "simple"
    or release_please_config.get("initial-version") != "0.1.0"
    or release_please_config.get("include-component-in-tag") is not False
    or release_please_config.get("skip-github-release") is not True
    or "skip-github-release: true" not in release_please
    or "repositories: aros-toolchains" not in release_please
    or "environment: release-please" not in release_please
    or "gh release " in release_please
    or "git tag " in release_please
):
    fail("Release Please must prepare repository-scoped version PRs only")
if "      - v*" not in workflow or "startsWith(github.ref, 'refs/tags/v')" not in workflow:
    fail("only canonical SemVer tag candidates may reach the release workflow")
if (source_root / "version.txt").read_text(encoding="utf-8").strip() != json.loads(
    (source_root / ".release-please-manifest.json").read_text(encoding="utf-8")
)["."]:
    fail("Release Please version file and manifest disagree")
if "## Changelog" in (source_root / "CHANGELOG.md").read_text(encoding="utf-8"):
    fail("Release Please changelog contains a duplicate bootstrap section")


def blocks(text: str, prefix: str) -> list[str]:
    """Return indentation-delimited YAML blocks at one workflow level."""
    lines = text.splitlines()
    starts = [index for index, line in enumerate(lines) if line.startswith(prefix)]
    result = []
    for position, start in enumerate(starts):
        end = starts[position + 1] if position + 1 < len(starts) else len(lines)
        result.append("\n".join(lines[start:end]))
    return result


def job_blocks(text: str) -> list[tuple[str, str]]:
    matches = list(re.finditer(r"^  ([A-Za-z0-9][A-Za-z0-9_-]*):\s*$", text, re.MULTILINE))
    result = []
    for position, match in enumerate(matches):
        name = match.group(1)
        if name in {"jobs", "env", "permissions", "concurrency"}:
            continue
        end = matches[position + 1].start() if position + 1 < len(matches) else len(text)
        result.append((name, text[match.start():end]))
    return result


def command_blocks(text: str, needle: str) -> list[str]:
    lines = text.splitlines()
    result = []
    for index, line in enumerate(lines):
        if needle not in line:
            continue
        command = [line]
        cursor = index
        while lines[cursor].rstrip().endswith("\\") and cursor + 1 < len(lines):
            cursor += 1
            command.append(lines[cursor])
        result.append("\n".join(command))
    return result


def runtime_command_bound(command: str) -> bool:
    first_line = command.splitlines()[0]
    return bool(
        re.search(r"\$aros\b", first_line)
        or re.search(r"steps\.[A-Za-z0-9_-]+\.outputs\.root[^\n]*/bin/aros", first_line)
    )


steps = blocks(workflow, "      - ")
jobs = job_blocks(workflow)
artifact_uploads = [block for block in steps if "actions/upload-artifact@" in block]
artifact_downloads = [block for block in steps if "actions/download-artifact@" in block]

# The release producer is bootstrapped from the signed runtime release. A
# source-built aros executable, the legacy shell/Python producer, or an
# unbound `aros` variable would silently change the producer implementation.
if "uses: ./.github/actions/materialize-aros-tools-runtime" not in workflow:
    fail("release workflow must materialize the released aros-tools runtime")
if "build-release.sh" in workflow:
    fail("release workflow must not invoke legacy build-release.sh")
if "scripts/toolchain/producer.py" in workflow or "scripts/toolchain/compatibility.sh" in workflow:
    fail("release workflow must use native aros producer commands, not legacy scripts")
if re.search(r"steps\.[A-Za-z0-9_-]+\.outputs\.aros", workflow):
    fail("every release aros command must use the released runtime, not a source-built executable")
if re.search(r"(?:target/(?:debug|release)|cargo\s+run).*\baros\b", workflow):
    fail("release workflow must not execute a source-built aros executable")
if re.search(r"^\s*['\"]?aros['\"]?\s+(?:cache|toolchain)\b", workflow, re.MULTILINE):
    fail("release workflow must not resolve aros from PATH")
if not re.search(r"(?:\$aros|/bin/aros)", workflow):
    fail("release workflow does not contain a native aros command")
for name, job in jobs:
    if not re.search(r"(?:/bin/aros|\$aros\b|\baros\s+(?:cache|toolchain)\b|toolchain\s+(?:plan|build|producer))", job):
        continue
    if "uses: ./.github/actions/materialize-aros-tools-runtime" not in job:
        fail(f"job {name} runs aros without materializing the released runtime")
for block in steps:
    if "/bin/aros" in block and "steps.runtime.outputs.root" not in block:
        fail("direct aros executable path is not bound to steps.runtime.outputs.root")

# A native recipe is allowed to inspect a separately checked-out tools tree,
# but that tree must be an exact commit and must be checked before use. The
# workflow may express this inline or through the repository's locked source
# checkout action; both forms must prove the same commit/tree/cleanliness.
repository = re.search(r"^  AROS_TOOLS_REPOSITORY:\s*(\S+)", workflow, re.MULTILINE)
commit = re.search(r"^  AROS_TOOLS_COMMIT:\s*([0-9a-f]{40})\s*$", workflow, re.MULTILINE)
locked_tools_use = "uses: ./.github/actions/checkout-locked-aros-tools-source" in workflow
tools_action_path = source_root / ".github/actions/checkout-locked-aros-tools-source/action.yml"
if repository is not None or commit is not None:
    if repository is None or repository.group(1) != "metaneutrons/aros-tools":
        fail("release workflow must declare the canonical aros-tools repository")
    if commit is None:
        fail("release workflow must pin AROS_TOOLS_COMMIT to a full Git revision")
elif not locked_tools_use:
    fail("release workflow must use a locked, separate aros-tools Git checkout")
if locked_tools_use:
    if not tools_action_path.is_file() or tools_action_path.is_symlink():
        fail("locked aros-tools checkout action must be one regular local action")
    tools_action = tools_action_path.read_text(encoding="utf-8")
    for required in (
        "repository: metaneutrons/aros-tools",
        "commit=$(jq -er '.source_commit' \"$lock\")",
        "tree=$(jq -er '.source_tree' \"$lock\")",
        "ref: ${{ steps.identity.outputs.commit }}",
        "actions/checkout@",
        '"$(git rev-parse HEAD)" != "$EXPECTED_COMMIT"',
        '"$(git show -s --format=%T HEAD)" != "$EXPECTED_TREE"',
        'git status --porcelain --untracked-files=all',
    ):
        if required not in tools_action:
            fail(f"locked aros-tools checkout lost its identity guard: {required}")
tools_checkouts = [
    block for block in steps
    if "path: dependencies/aros-tools" in block
    and (
        "uses: ./.github/actions/checkout-locked-aros-tools-source" in block
        or "repository: ${{ env.AROS_TOOLS_REPOSITORY }}" in block
        or "repository: metaneutrons/aros-tools" in block
    )
]
if not tools_checkouts:
    fail("release workflow must check out a separate pinned aros-tools tree")
for checkout in tools_checkouts:
    if not locked_tools_use and "ref: ${{ env.AROS_TOOLS_COMMIT }}" not in checkout:
        fail("every aros-tools checkout must use the pinned AROS_TOOLS_COMMIT")
    if not locked_tools_use and "actions/checkout@" not in checkout:
        fail("the pinned aros-tools tree must use the pinned checkout action")
validated_tools = [
    block for block in steps
    if "rev-parse HEAD" in block
    and "AROS_TOOLS_COMMIT" in block
    and "aros-tools" in block
]
if locked_tools_use:
    validated_tools = [tools_action]
if not validated_tools:
    fail("release workflow must validate the checked-out aros-tools commit")
if not locked_tools_use and not any(
    re.search(r"(?:\[\[|\btest\b)[^\n]*AROS_TOOLS_COMMIT", block)
    for block in validated_tools
):
    fail("release workflow must compare the measured tools commit with AROS_TOOLS_COMMIT")


def require_command(needle: str, required: tuple[str, ...], label: str) -> str:
    candidates = command_blocks(workflow, needle)
    if not candidates:
        fail(f"release workflow lost native {label} command")
    for candidate in candidates:
        if runtime_command_bound(candidate) and all(token in candidate for token in required):
            return candidate
    fail(f"native {label} command is missing one or more bound inputs")


require_command(
    "toolchain producer recipe",
    ("--source-dir", "--producer-dir", "--tools-dir", "--source-lock", "--profiles", "--output"),
    "producer recipe",
)
require_command(
    "toolchain plan",
    ("--preset", "--recipe", "--source-dir", "--producer-dir", "--tools-dir"),
    "producer plan",
)

# Cargo vendor generations are selected and verified by the released runtime,
# then published as host-keyed artifacts. A single unqualified cache would
# allow a different Cargo binary or target runner to consume it.
for operation in ("cache cargo fetch", "cache cargo verify"):
    candidates = command_blocks(workflow, operation)
    if not candidates:
        fail(f"release workflow must run released-runtime {operation}")
    if not any(runtime_command_bound(candidate) for candidate in candidates):
        fail(f"release workflow must bind {operation} to the released runtime")
    operation_steps = [step for step in steps if operation in step]
    if not any(
        all(token in step for token in ("--producer-dir", "--tools-dir", "--dir"))
        for step in operation_steps
    ):
        fail(f"{operation} must bind producer, tools, and cache roots")
cargo_artifacts = [
    block for block in artifact_uploads
    if re.search(r"^\s+name:.*cargo", block, re.IGNORECASE | re.MULTILINE)
    and "vendor" in block.lower()
]
if not cargo_artifacts:
    fail("release workflow must upload a verified Cargo vendor cache")
for block in cargo_artifacts:
    if not re.search(r"^\s+name:.*\$\{\{\s*matrix\.host\s*\}\}", block, re.IGNORECASE | re.MULTILINE):
        fail("verified Cargo vendor artifacts must be host-specific")
    if "if-no-files-found: error" not in block:
        fail("verified Cargo vendor artifacts must fail closed")
    if "include-hidden-files: true" not in block and "cargo-vendor.tar" not in block:
        fail("verified Cargo vendor artifacts must retain Cargo checksum files")
cargo_downloads = [
    block for block in artifact_downloads
    if re.search(r"^\s+name:.*cargo", block, re.IGNORECASE | re.MULTILINE)
]
if not cargo_downloads:
    fail("native build jobs must download the host-specific Cargo vendor cache")
if not any(
    re.search(r"^\s+name:.*\$\{\{\s*matrix\.host\s*\}\}", block, re.IGNORECASE | re.MULTILINE)
    for block in cargo_downloads
):
    fail("native build jobs must select Cargo vendor cache by matrix host")

build_jobs = [job for name, job in jobs if command_blocks(job, "toolchain build")]
if not build_jobs:
    fail("release workflow must run the native aros toolchain build")
build_job = build_jobs[0]
build_command = require_command(
    "toolchain build",
    (
        "--preset", "--recipe", "--source-dir", "--producer-dir", "--tools-dir",
        "--work-dir", "--output-dir", "--cache-dir", "--jobs", "--timeout-seconds",
        "--release-id",
    ),
    "toolchain build",
)
if "--cache-dir" not in build_command:
    fail("native toolchain build must consume a prepared Cargo/source cache")
if not any(
    re.search(r"^\s+name:.*cargo.*\$\{\{\s*matrix\.host\s*\}\}", block, re.IGNORECASE | re.MULTILINE)
    for block in blocks(build_job, "      - ")
    if "actions/download-artifact@" in block
):
    fail("native build job must download its host-specific verified Cargo cache")

environment_command = require_command(
    "toolchain producer environment", ("--host", "--output"), "producer environment"
)
for label in ("producer package", "producer verify-package"):
    require_command(
        f"toolchain {label}",
        (
            "--recipe", "--source-lock", "--profiles", "--preset", "--release-id",
            "--host", "--build-environment", "--input-dir", "--forbidden-prefix",
        ),
        label,
    )
if not any("toolchain producer environment" in job for job in build_jobs):
    fail("native build job must record its producer environment")
if not any("toolchain producer package" in job and "toolchain producer verify-package" in job for job in build_jobs):
    fail("native build job must package and read-back verify its candidate")
if "--host" not in environment_command:
    fail("native producer environment must be host-bound")

lifecycle_artifacts = [
    block for block in artifact_uploads
    if re.search(r"^\s+name: native-lifecycle-", block, re.MULTILINE)
]
if not lifecycle_artifacts:
    fail("release workflow must preserve one native lifecycle artifact per candidate")
for block in lifecycle_artifacts:
    if "native-lifecycle" not in block or not any(
        "native-lifecycle" in line and "receipts" in line
        for line in block.splitlines()
        if line.lstrip().startswith("path:")
    ):
        fail("native lifecycle artifact must upload the durable receipts directory")
    if "if-no-files-found: error" not in block:
        fail("native lifecycle publish.json upload must fail closed")
    if "if-no-files-found: warn" in block:
        fail("native lifecycle artifact upload may not downgrade missing publish.json to a warning")
if not any(
    "publish.json" in job and "test -s" in job and "jq -e" in job
    for name, job in jobs
    if command_blocks(job, "toolchain build")
):
    fail("native build jobs must validate the durable publish.json receipt before upload")

compatibility_artifacts = [
    block for block in artifact_uploads
    if re.search(r"^\s+name: compatibility-", block, re.MULTILINE)
]
if not compatibility_artifacts:
    fail("release workflow must preserve native compatibility evidence")
for block in compatibility_artifacts:
    if "if-no-files-found: error" not in block:
        fail("compatibility evidence upload must fail closed")
    if "if-no-files-found: warn" in block:
        fail("compatibility evidence upload may not downgrade missing reports to a warning")

# Source-cache uploads remain complete, including hidden marker files used by
# the native fetch bridge. This is intentionally structural rather than a
# count of individual source commands.
source_artifacts = [
    block for block in artifact_uploads
    if re.search(r"^\s+name:.*source", block, re.IGNORECASE | re.MULTILINE)
    and "source-cache" in block
]
if not source_artifacts:
    fail("release workflow must publish the verified source cache")
if not any("include-hidden-files: true" in block and "if-no-files-found: error" in block for block in source_artifacts):
    fail("verified source cache upload must retain hidden files and fail closed")
PY
grep -Fq -- '--python-cache-dir "$GITHUB_WORKSPACE/source-cache"' "$source_root/.github/workflows/toolchain-release.yml"
active_ccache_callers=(
    "$source_root/.github/workflows/ci.yml"
    "$source_root/.github/workflows/toolchain-release.yml"
    "$source_root/.github/workflows/toolchain-release-recovery.yml"
    "$source_root/.github/workflows/toolchain-compatibility-replay.yml"
)
if grep -n -F -- ' ccache' "${active_ccache_callers[@]}"; then
    echo "active native-producer callers must use aros cache compiler, not legacy aros ccache" >&2
    exit 1
fi
provenance_verifier="$source_root/scripts/toolchain/verify-provenance-attestation.sh"
[[ -f "$provenance_verifier" && ! -L "$provenance_verifier" ]]
bash -n "$provenance_verifier"
python3 - "$source_root/.github/workflows/toolchain-release.yml" \
    "$source_root/.github/workflows/toolchain-release-recovery.yml" \
    "$source_root/.github/workflows/toolchain-compatibility-replay.yml" <<'PY'
import json
from pathlib import Path
import re
import subprocess
import sys
from tempfile import TemporaryDirectory

release_path = Path(sys.argv[1])
source_root = release_path.parents[2]
workflow = release_path.read_text(encoding="utf-8")
recovery = Path(sys.argv[2]).read_text(encoding="utf-8")
replay = Path(sys.argv[3]).read_text(encoding="utf-8")
ports_lock = json.loads(
    (source_root / "toolchains" / "compatibility-ports-v2.json").read_text(encoding="utf-8")
)
expected_ports_inputs = {
    "unicode-data-16-0-0": (
        "UnicodeData.txt",
        "UnicodeData.txt",
        "",
        "https://www.unicode.org/Public/16.0.0/ucd/UnicodeData.txt",
        "ff58e5823bd095166564a006e47d111130813dcf8bf234ef79fa51a870edb48f",
        2175362,
    ),
    "unicode-special-casing-16-0-0": (
        "SpecialCasing.txt",
        "SpecialCasing.txt",
        "",
        "https://www.unicode.org/Public/16.0.0/ucd/SpecialCasing.txt",
        "8d5de354eef79f2395a54c9c7dcebbaf3d30fc962d0f85611ea97aa973a0c451",
        16809,
    ),
    "acpica-unix-20260408": (
        "acpica-unix-20260408.tar.gz",
        "acpica-unix-20260408.tar.gz",
        ".acpica-unix-20260408-fetched",
        "https://downloadmirror.intel.com/917611/acpica-unix-20260408.tar.gz",
        "e66ceb26d6d514ce164fe22f5a4f7ca165cc38349d7a97f41a21f19b364647a2",
        2044403,
    ),
    "boost-1-89-0": (
        "boost_1_89_0.tar.gz",
        "boost_1_89_0.tar.gz",
        ".boost_1_89_0-fetched",
        "https://archives.boost.io/release/1.89.0/source/boost_1_89_0.tar.gz",
        "9de758db755e8330a01d995b0a24d09798048400ac25c03fc5ea9be364b13c93",
        190099283,
    ),
    "bzip2-1-0-8": (
        "bzip2-1.0.8.tar.gz",
        "bzip2-1.0.8.tar.gz",
        ".bzip2-1.0.8-fetched",
        "https://sourceware.org/pub/bzip2/bzip2-1.0.8.tar.gz",
        "ab5a03176ee106d3f0fa90e381da478ddae405918153cca248e682cd0c4a2269",
        810029,
    ),
    "codesets-6-22": (
        "codesets-6.22.tar.gz",
        "codesets/6.22.tar.gz",
        "codesets/.6.22-fetched",
        "https://github.com/jens-maus/libcodesets/archive/refs/tags/6.22.tar.gz",
        "c4b11066b9c51c5670f69122efbdb1c58ddd69c4dbe1dcd480aac74577250cc1",
        206125,
    ),
    "expat-2-8-2": (
        "expat-2.8.2.tar.bz2",
        "expat-2.8.2.tar.bz2",
        ".expat-2.8.2-fetched",
        "https://github.com/libexpat/libexpat/releases/download/R_2_8_2/expat-2.8.2.tar.bz2",
        "69e7f52417d85b1c2b7fe855e176eec55d0b2d7d92d691372d833a1c7df7923b",
        660292,
    ),
    "freetype-2-14-3": (
        "freetype-2.14.3.tar.xz",
        "freetype-2.14.3.tar.xz",
        ".freetype-2.14.3-fetched",
        "https://download-mirror.savannah.gnu.org/releases/freetype/freetype-2.14.3.tar.xz",
        "36bc4f1cc413335368ee656c42afca65c5a3987e8768cc28cf11ba775e785a5f",
        2670220,
    ),
    "glu-9-0-2": (
        "glu-9.0.2.tar.xz",
        "glu-9.0.2.tar.xz",
        ".glu-9.0.2-fetched",
        "https://archive.mesa3d.org/glu/glu-9.0.2.tar.xz",
        "6e7280ff585c6a1d9dfcdf2fca489251634b3377bfc33c29e4002466a38d02d4",
        436176,
    ),
    "jpeg-9f": (
        "jpegsrc.v9f.tar.gz",
        "jpegsrc.v9f.tar.gz",
        ".jpegsrc.v9f-fetched",
        "https://ijg.org/files/jpegsrc.v9f.tar.gz",
        "04705c110cb2469caa79fb71fba3d7bf834914706e9641a4589485c1f832565b",
        1081470,
    ),
    "xz-5-8-3": (
        "xz-5.8.3.tar.gz",
        "xz-5.8.3.tar.gz",
        ".xz-5.8.3-fetched",
        "https://tukaani.org/xz/xz-5.8.3.tar.gz",
        "3d3a1b973af218114f4f889bbaa2f4c037deaae0c8e815eec381c3d546b974a0",
        2771455,
    ),
    "mbedtls-3-6-7": (
        "mbedtls-3.6.7.tar.bz2",
        "mbedtls-3.6.7.tar.bz2",
        ".mbedtls-3.6.7-fetched",
        "https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.7/mbedtls-3.6.7.tar.bz2",
        "a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6",
        5473689,
    ),
    "mesa-20-0-8": (
        "mesa-20.0.8.tar.xz",
        "mesa-20.0.8.tar.xz",
        ".mesa-20.0.8-fetched",
        "https://archive.mesa3d.org/older-versions/20.x/mesa-20.0.8.tar.xz",
        "6cf0c010df89680f9b2bc6432ff01400031795e39bceda7535fa00af06740b6c",
        12360736,
    ),
    "libpng-1-6-58": (
        "libpng-1.6.58.tar.gz",
        "libpng-1.6.58.tar.gz",
        ".libpng-1.6.58-fetched",
        "https://sourceforge.net/projects/libpng/files/libpng16/1.6.58/libpng-1.6.58.tar.gz/download",
        "8c9b05b675ca7301a458df2c2e46f26e1d41ff36b8863f8c33530bc58c2e6225",
        1582074,
    ),
    "tiff-4-7-2": (
        "tiff-4.7.2.tar.xz",
        "tiff-4.7.2.tar.xz",
        ".tiff-4.7.2-fetched",
        "https://download.osgeo.org/libtiff/tiff-4.7.2.tar.xz",
        "4996f0c4f93094719b1ca5c6279b20e588773ba8a247533e486416fb662ddb88",
        2409652,
    ),
    "utf8proc-2-11-3": (
        "utf8proc-v2.11.3.tar.gz",
        "utf8proc/v2.11.3.tar.gz",
        "utf8proc/.v2.11.3-fetched",
        "https://github.com/JuliaStrings/utf8proc/archive/refs/tags/v2.11.3.tar.gz",
        "abfed50b6d4da51345713661370290f4f4747263ee73dc90356299dfc7990c78",
        202535,
    ),
    "chromium-zlib-da752eb2": (
        "zlib.tar.gz",
        "zlib.tar.gz",
        ".zlib-fetched",
        "https://chromium.googlesource.com/chromium/src/+archive/da752eb2a3660cf1bf8dac620f6380b89dd953a7/third_party/zlib.tar.gz",
        "883d22e0b9aefc31a383c462adacdbd7941e6862559c5b27e59599db8114e783",
        2337668,
    ),
    "zstd-1-5-7": (
        "zstd-1.5.7.tar.gz",
        "zstd-1.5.7.tar.gz",
        ".zstd-1.5.7-fetched",
        "https://github.com/facebook/zstd/releases/download/v1.5.7/zstd-1.5.7.tar.gz",
        "eb33e51f49a15e023950cd7825ca74a4a2b43db8354825ac24fc1b7ee09e6fa3",
        2434947,
    ),
}
if ports_lock.get("schema") != "aros-toolchain-compatibility-ports-v2":
    raise SystemExit("compatibility source-input lock has an unsupported schema")
if ports_lock.get("upstream_commit") != "6722a0ae9e03fe5d26e32703360bd2059e0864cc":
    raise SystemExit("compatibility source-input lock lost its pinned upstream revision")
observed_ports_inputs = {
    input.get("id"): (
        input.get("cache_filename"), input.get("relative_path"), input.get("fetch_marker"), input.get("url"),
        input.get("sha256"), input.get("size"),
    )
    for input in ports_lock.get("inputs", [])
}
if observed_ports_inputs != expected_ports_inputs:
    raise SystemExit("compatibility source-input lock differs from the measured upstream closure")
expected_normalization = {
    "chromium-zlib-da752eb2": "canonical-tar-gzip-v1",
}
observed_normalization = {
    input.get("id"): input.get("normalization")
    for input in ports_lock.get("inputs", [])
    if "normalization" in input
}
if observed_normalization != expected_normalization:
    raise SystemExit("compatibility source-input lock has an unexpected payload normalization policy")
expected_profile_inputs = {
    "pc-x86_64": set(expected_ports_inputs),
    "arm-raspi": set(expected_ports_inputs),
    "rpi-aarch64": set(expected_ports_inputs),
}
observed_profiles = {entry.get("name"): set(entry.get("inputs", [])) for entry in ports_lock.get("profiles", [])}
if observed_profiles != expected_profile_inputs:
    raise SystemExit("compatibility source-input lock must declare the exact measured closure for every active profile")
patterns = (
    "verified-*-pc-x86_64",
    "verified-*-arm-raspi",
    "verified-*-rpi-aarch64",
)
for pattern in patterns:
    if workflow.count(f"pattern: {pattern}") != 1:
        raise SystemExit(f"draft release must select exactly one {pattern} artifact family")
    if recovery.count(f"pattern: {pattern}") != 1:
        raise SystemExit(f"recovery must select exactly one {pattern} artifact family")
if "pattern: verified-*\n" in workflow or "pattern: verified-*\n" in recovery:
    raise SystemExit("release assembly must not merge the verified source cache")
if workflow.count("--stage final") != 1 or recovery.count("--stage final") != 1:
    raise SystemExit("every final release inventory must require provenance")
if workflow.count('"${assets[@]}"') != 1 or recovery.count('"${assets[@]}"') != 1:
    raise SystemExit("release upload must use the validated regular-file inventory")
for required in (
    "qualified-final-release",
    "qualification-evidence",
    "packaging-only recovery must execute the reviewed workflow from protected main",
    "verify-provenance-attestation.sh",
    "prepare-recovery",
    "validate-recovery",
    "toolchain producer repackage",
    "--source-release-id",
    "--recovery-release-id",
    "recovery tag must be pre-created by a trusted maintainer credential",
    'printf \'%s\\n\' "$recovery_tag_object" > "$RUNNER_TEMP/recovery-tag-object.sha"',
    "recovery tag object changed during assembly",
    "recovery tag target changed during assembly",
):
    if required not in recovery:
        raise SystemExit(f"recovery workflow lost fail-closed contract: {required}")
if workflow.count("verify-provenance-attestation.sh") != 1:
    raise SystemExit("producer draft must verify the complete signed pre-attestation inventory once")
if recovery.count("verify-provenance-attestation.sh") != 2:
    raise SystemExit("recovery must verify both source and recovered signed inventories")
if "--exclude-subject toolchain-provenance.sigstore.json" not in recovery:
    raise SystemExit("recovery must exclude only the self-referential provenance bundle from signed subjects")
if "gh attestation verify" in workflow or "gh attestation verify" in recovery:
    raise SystemExit("workflows must verify the retained provenance bundle offline, not an unrelated final checksum document")
for candidate in (workflow, recovery):
    if candidate.count("subject-checksums: release/SHA256SUMS") != 1:
        raise SystemExit("each release assembly must attest exactly its pre-attestation checksum inventory")
for forbidden in (
    "producer.py", "build-release.sh", "compatibility.sh", "offline-fetch.py", "host-python-env.py",
    'git push origin "refs/tags/$RELEASE_TAG"',
):
    if forbidden in recovery:
        raise SystemExit(f"native recovery workflow still references legacy producer material: {forbidden}")
if recovery.count("run-id: ${{ inputs.source_run_id }}") != 5:
    raise SystemExit("recovery must obtain every closed input artifact from one run")
if recovery.count("github-token: ${{ github.token }}") != 5:
    raise SystemExit("recovery cross-run downloads require the scoped GitHub token")
for required in (
    "pattern: native-lifecycle-*",
    "pattern: comparison-*",
    "pattern: compatibility-*",
    "name: qualified-final-release",
    "name: qualification-evidence",
    "record-qualification",
):
    if required not in workflow:
        raise SystemExit(f"producer draft workflow lost closed qualification evidence: {required}")
if "uses: ./.github/workflows/toolchain-release-recovery.yml" not in workflow:
    raise SystemExit("registered producer workflow must expose the recovery workflow")
if "inputs.mode == 'recover'" not in workflow:
    raise SystemExit("producer workflow recovery entry point is not mode-gated")
if '          - all' in workflow:
    raise SystemExit("manual producer dispatch must not offer the full host matrix")
if 'manual scope must be linux-x86_64 or linux' not in workflow:
    raise SystemExit("manual producer dispatch must fail closed outside diagnostic host tiers")
if 'the complete active three-host A/B matrix is tag-only' not in workflow:
    raise SystemExit("complete A/B qualification must remain tag-only")
for required in (
    "remote release tag identity differs from the triggering annotated tag",
    "release tag changed during qualification; refusing to create a draft",
    "cannot prove that the release is absent",
    'gh api -i "repos/$GITHUB_REPOSITORY/releases/tags/$GITHUB_REF_NAME"',
):
    if required not in workflow:
        raise SystemExit(f"tagged release lost its remote identity/absence guard: {required}")
if workflow.count('git ls-remote --tags origin "refs/tags/$GITHUB_REF_NAME"') != 2:
    raise SystemExit("tagged release must recheck its remote annotated tag before preparation and draft creation")
tag_validator = source_root / "scripts/toolchain/validate-release-tag.py"
if not tag_validator.is_file() or tag_validator.is_symlink():
    raise SystemExit("release-tag policy must have one regular shared validator")
for name, candidate in (("producer", workflow), ("recovery", recovery)):
    if "python3 scripts/toolchain/validate-release-tag.py" not in candidate:
        raise SystemExit(f"{name} workflow must use the shared release-tag validator")
    if candidate.count("prerelease_args=(--prerelease)") != 1:
        raise SystemExit(f"{name} workflow must add the prerelease flag only through channel classification")
    if candidate.count('"${prerelease_args[@]}"') != 1:
        raise SystemExit(f"{name} workflow must pass the validated release-channel argument array once")
    if re.search(r"gh release create[^\n]*(?:\\\n[^\n]*){0,8}--prerelease", candidate):
        raise SystemExit(f"{name} workflow must not unconditionally create prereleases")
if "prerelease: ${{ steps.release_tag.outputs.prerelease || 'false' }}" not in workflow:
    raise SystemExit("producer release job must consume the validated tag's channel classification")
if "RELEASE_PRERELEASE: ${{ needs.plan.outputs.prerelease }}" not in workflow:
    raise SystemExit("draft creation must receive the release-channel classification")
if '"$RELEASE_TAG" "$GITHUB_ENV"' not in recovery:
    raise SystemExit("recovery must classify the fresh recovery tag before publishing its draft")
with TemporaryDirectory(prefix="aros-release-tag-test-") as temporary:
    output_path = Path(temporary) / "github-output"
    for tag, expected_prerelease in (
        ("v0.1.0", False),
        ("v1.0.0", False),
        ("v0.1.0-rc.1", True),
        ("v0.1.0-rc.12", True),
    ):
        result = subprocess.run(
            [sys.executable, str(tag_validator), tag, str(output_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        expected = f"prerelease={str(expected_prerelease).lower()}\n"
        if result.returncode != 0 or output_path.read_text(encoding="utf-8") != expected:
            raise SystemExit(f"release tag was rejected or misclassified: {tag}: {result.stderr}")
        output_path.unlink()

    for invalid_tag in (
        "toolchain-v1-20260924",
        "v0.01.0",
        "v00.1.0",
        "v0.1.00",
        "v0.1.0-rc.0",
        "v0.1.0-rc.01",
        "v0.1.0-rc1",
        "v0.1.0-stable",
        "v0.1.0+build.1",
        "v٠.١.٠",
    ):
        result = subprocess.run(
            [sys.executable, str(tag_validator), invalid_tag, str(output_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0 or output_path.exists():
            raise SystemExit(f"invalid release tag was accepted or emitted output: {invalid_tag}")
if workflow.count("netpbm") != 2:
    raise SystemExit("both producer runner families must install netpbm")
if workflow.count("libpng-dev") != 1 or workflow.count("gnu-sed") != 1:
    raise SystemExit("producer prerequisites lost Linux libpng or macOS GNU sed")
recursive_checkout = source_root / ".github/actions/checkout-pinned-recursive-source/action.yml"
if not recursive_checkout.is_file() or recursive_checkout.is_symlink():
    raise SystemExit("recursive source checkout must use one regular local composite action")
recursive_action = recursive_checkout.read_text(encoding="utf-8")
for required in (
    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
    "submodules: false",
    'EXPECTED_COMMIT: ${{ inputs.ref }}',
    "^[0-9a-f]{40}$",
    "git submodule sync --recursive",
    "for attempt in 1 2 3 4 5; do",
    "submodule update --init --recursive --jobs 1",
    "git submodule status --recursive",
    "exhausted five network attempts",
):
    if required not in recursive_action:
        raise SystemExit(f"recursive source checkout lost closed retry contract: {required}")
if workflow.count("uses: ./.github/actions/checkout-pinned-recursive-source") != 4:
    raise SystemExit("release workflow must use the shared recursive checkout action for every source tree")
if replay.count("uses: ./.github/actions/checkout-pinned-recursive-source") != 2:
    raise SystemExit("compatibility replay must use the shared recursive checkout action for every source tree")
if "submodules: recursive" in workflow or "submodules: recursive" in replay:
    raise SystemExit("release workflows must not delegate recursive submodule retries to actions/checkout")
for required in (
    "Probe the released source-cache command contract",
    "cache sources list \\",
    '--source-lock "$GITHUB_WORKSPACE/$SOURCE_LOCK"',
    '--compatibility-ports-lock "$GITHUB_WORKSPACE/$COMPATIBILITY_PORTS_LOCK"',
):
    if required not in workflow:
        raise SystemExit("release plan must prove the pinned runtime exposes both source-cache selector contracts")
apt_source_action = source_root / ".github/actions/disable-google-chrome-apt-source/action.yml"
action = apt_source_action.read_text(encoding="utf-8")
for required in (
    "/etc/apt/sources.list.d/google-chrome.list",
    "/etc/apt/sources.list.d/google-chrome.list.save",
    "/etc/apt/sources.list.d/google-chrome.sources",
    "dl.google.com/linux/chrome",
    "unexpected Google Chrome APT source remains after isolation",
):
    if required not in action:
        raise SystemExit("Ubuntu APT source isolation lost its fail-closed Chrome guard")
apt_source_use = "uses: ./.github/actions/disable-google-chrome-apt-source"
if workflow.count(apt_source_use) != 2:
    raise SystemExit("release builds and compatibility must isolate the Chrome APT source")
first_release_isolation = workflow.index(apt_source_use)
second_release_isolation = workflow.index(apt_source_use, first_release_isolation + 1)
if first_release_isolation > workflow.index(
    "      - name: Install pinned-lane build prerequisites (Linux)"
):
    raise SystemExit("release build must isolate the Chrome APT source before apt-get")
if second_release_isolation > workflow.index("      - name: Install audited consumer prerequisites"):
    raise SystemExit("release compatibility must isolate the Chrome APT source before apt-get")
if replay.count(apt_source_use) != 1:
    raise SystemExit("compatibility replay must isolate the Chrome APT source")
if replay.index(apt_source_use) > replay.index("      - name: Install audited consumer prerequisites"):
    raise SystemExit("compatibility replay must isolate the Chrome APT source before apt-get")
consumer_start = workflow.index("      - name: Install audited consumer prerequisites")
consumer_end = workflow.index("      - name: Execute two-root native compatibility qualification", consumer_start)
consumer = workflow[consumer_start:consumer_end]
if "bash dependencies/aros/scripts/ci/install-build-prerequisites.sh" not in consumer:
    raise SystemExit("toolchain consumers must use the checked-out AROS prerequisite contract")
if workflow.count('toolchain producer compatibility-host-tools') != 1:
    raise SystemExit("release compatibility must obtain its host-tool roles from the selected executor")
if workflow.count('compatibility-host-tools --host "${{ matrix.host }}"') != 1:
    raise SystemExit("release compatibility must select the host-specific executor closure")
if workflow.count('host_tool_args=()') != 1 or workflow.count('"${host_tool_args[@]}"') != 1:
    raise SystemExit("release compatibility must materialize and pass one complete measured host-tool closure")
if workflow.count('type -P gmake || type -P make || true') != 1:
    raise SystemExit("release compatibility must map the stable make role to an explicit host executable")
if workflow.count('--compatibility-ports-lock "$GITHUB_WORKSPACE/$COMPATIBILITY_PORTS_LOCK"') != 4:
    raise SystemExit("release must probe, acquire, offline-prove, and hash-verify the compatibility source closure")
if workflow.count('--ports-lock "$GITHUB_WORKSPACE/$COMPATIBILITY_PORTS_LOCK"') != 1:
    raise SystemExit("release compatibility must bind the declared source-input lock to its native executor")
if workflow.count('--ports-cache-dir "$GITHUB_WORKSPACE/source-cache"') != 1:
    raise SystemExit("release compatibility must materialize source inputs only from the verified cache")
if workflow.count('--ports-sources-dir "$work/ports-sources"') != 1:
    raise SystemExit("release compatibility must pass one owned source-input directory to upstream")
if workflow.count('xcrun_program="$(type -P xcrun || true)"') != 2:
    raise SystemExit("release compatibility must measure xcrun before resolving Darwin aliases")
if workflow.count('"$xcrun_program" --find ar') != 1 or workflow.count('"$xcrun_program" --find ranlib') != 1:
    raise SystemExit("release compatibility must seal Darwin aliases to real Xcode binutils, not xcrun shims")
if 'host_cc_program=' in workflow or '--host-tool "cc=$host_cc_program"' in workflow:
    raise SystemExit("release compatibility must not retain the incomplete three-tool closure")
if "name: native-lifecycle-${{ matrix.host }}-${{ matrix.profile }}-${{ matrix.copy }}" not in workflow:
    raise SystemExit("each producer must retain native lifecycle receipts outside the release archive")
PY
python3 - "$AROS_TEST_SOURCE_ROOT" \
    "$source_root/toolchains/compatibility-ports-v2.json" \
    "$source_root/.github/workflows/ci.yml" \
    "$source_root/.github/workflows/toolchain-release.yml" \
    "$source_root/.github/workflows/toolchain-compatibility-replay.yml" <<'PY'
import json
from pathlib import Path
import re
import subprocess
import sys

aros_source = Path(sys.argv[1]).resolve()
ports_lock = Path(sys.argv[2])
workflows = [Path(item) for item in sys.argv[3:]]
if not aros_source.is_dir() or aros_source.is_symlink():
    raise SystemExit("AROS source contract checkout must be a regular directory")
source_commit = subprocess.check_output(
    ["git", "-C", str(aros_source), "rev-parse", "HEAD"], text=True
).strip()
if re.fullmatch(r"[0-9a-f]{40}", source_commit) is None:
    raise SystemExit("AROS source contract checkout must resolve to a full Git commit")

freetype_recipe = aros_source / "workbench/libs/freetype2/mmakefile.src"
if not freetype_recipe.is_file() or freetype_recipe.is_symlink():
    raise SystemExit("AROS source contract must provide the regular Freetype recipe")
expected_origin = "https://download-mirror.savannah.gnu.org/releases/freetype"
recipe_origins = re.findall(
    r"^\s*(https://[^\s]+)\s*$", freetype_recipe.read_text(encoding="utf-8"), re.MULTILINE
)
if recipe_origins != [expected_origin]:
    raise SystemExit("AROS Freetype recipe must declare exactly the verified Savannah mirror")

lock = json.loads(ports_lock.read_text(encoding="utf-8"))
freetype = next((item for item in lock.get("inputs", []) if item.get("id") == "freetype-2-14-3"), None)
if freetype is None:
    raise SystemExit("compatibility source-input lock must retain the Freetype input")
if freetype.get("url") != f"{expected_origin}/freetype-2.14.3.tar.xz":
    raise SystemExit("Freetype lock URL must derive from the pinned AROS source recipe")

for workflow_path in workflows:
    workflow = workflow_path.read_text(encoding="utf-8")
    match = re.search(r"^  AROS_SOURCE_COMMIT: ([0-9a-f]{40})$", workflow, re.MULTILINE)
    if match is None or match.group(1) != source_commit:
        raise SystemExit(f"{workflow_path.name} must pin the checked-out AROS source contract")
PY
python3 - "$source_root/.github/workflows/toolchain-compatibility-replay.yml" <<'PY'
from pathlib import Path
import sys

workflow = Path(sys.argv[1]).read_text(encoding="utf-8")
if workflow.count("run-id: ${{ inputs.source_run_id }}") != 3:
    raise SystemExit("compatibility replay must source recipe, verified package, and locked sources from one run")
if workflow.count("github-token: ${{ github.token }}") != 3:
    raise SystemExit("cross-run artifact downloads require the scoped GitHub token")
if "  source-closure:\n" not in workflow:
    raise SystemExit("compatibility replay must prepare one shared verified source closure before its matrix")
if "    needs: source-closure\n" not in workflow:
    raise SystemExit("every compatibility lane must wait for the shared verified source closure")
if workflow.count("name: replay-verified-source-closure") != 2:
    raise SystemExit("compatibility replay must publish and consume one uniquely named verified source closure")
if "name: verified-toolchain-sources\n          path: source-cache\n          github-token: ${{ github.token }}\n          run-id: ${{ inputs.source_run_id }}" not in workflow:
    raise SystemExit("the shared replay source closure must start from the named producer source artifact")
if "name: replay-verified-source-closure\n          path: source-cache\n      - id: runtime" not in workflow:
    raise SystemExit("compatibility lanes must consume the shared closure instead of fetching sources independently")
if workflow.count("profile:") != 9:
    raise SystemExit("compatibility replay must cover the complete active nine-lane matrix")
if workflow.count("bash dependencies/aros/scripts/ci/install-build-prerequisites.sh") != 1:
    raise SystemExit("compatibility replay must use the shared host prerequisite contract")
if workflow.count('toolchain producer compatibility-host-tools') != 1:
    raise SystemExit("compatibility replay must obtain its host-tool roles from the selected executor")
if workflow.count('compatibility-host-tools --host "${{ matrix.host }}"') != 1:
    raise SystemExit("compatibility replay must select the host-specific executor closure")
if workflow.count('host_tool_args=()') != 1 or workflow.count('"${host_tool_args[@]}"') != 1:
    raise SystemExit("compatibility replay must materialize and pass one complete measured host-tool closure")
if workflow.count('type -P gmake || type -P make || true') != 1:
    raise SystemExit("compatibility replay must map the stable make role to an explicit host executable")
if workflow.count('--compatibility-ports-lock "$GITHUB_WORKSPACE/$COMPATIBILITY_PORTS_LOCK"') != 3:
    raise SystemExit("compatibility replay must offline-verify its shared compatibility source closure before every lane")
if workflow.count('--ports-lock "$GITHUB_WORKSPACE/$COMPATIBILITY_PORTS_LOCK"') != 1:
    raise SystemExit("compatibility replay must bind the declared source-input lock to its native executor")
if workflow.count('--ports-cache-dir "$GITHUB_WORKSPACE/source-cache"') != 1:
    raise SystemExit("compatibility replay must materialize source inputs only from the verified cache")
if workflow.count('--ports-sources-dir "$work/ports-sources"') != 1:
    raise SystemExit("compatibility replay must pass one owned source-input directory to upstream")
if workflow.count('xcrun_program="$(type -P xcrun || true)"') != 2:
    raise SystemExit("compatibility replay must measure xcrun before resolving Darwin aliases")
if workflow.count('"$xcrun_program" --find ar') != 1 or workflow.count('"$xcrun_program" --find ranlib') != 1:
    raise SystemExit("compatibility replay must seal Darwin aliases to real Xcode binutils, not xcrun shims")
if 'host_cc_program=' in workflow or '--host-tool "cc=$host_cc_program"' in workflow:
    raise SystemExit("compatibility replay must not retain the incomplete three-tool closure")
PY
python3 - "$source_root/.github/workflows/ci.yml" \
    "$source_root/.github/workflows/toolchain-release.yml" \
    "$source_root/.github/workflows/toolchain-release-recovery.yml" \
    "$source_root/.github/workflows/toolchain-compatibility-replay.yml" <<'PY'
from pathlib import Path
import sys

contracts = Path(sys.argv[1]).read_text(encoding="utf-8")
release = Path(sys.argv[2]).read_text(encoding="utf-8")
recovery = Path(sys.argv[3]).read_text(encoding="utf-8")
replay = Path(sys.argv[4]).read_text(encoding="utf-8")

for name, workflow in {
    "ordinary producer contracts": contracts,
    "release qualification": release,
    "release recovery": recovery,
    "compatibility replay": replay,
}.items():
    if "macos-15-intel" in workflow or "macos-x86_64" in workflow:
        raise SystemExit(f"{name} must not consume suspended Intel macOS capacity")
if release.count('itertools.product(verify, ["a", "b"])') != 1:
    raise SystemExit("tag-only release must retain A/B expansion for every active host/profile lane")
if "macOS Intel is not a release target" not in release:
    raise SystemExit("release policy must state that macOS Intel is outside the release target set")
for name, workflow in {
    "release qualification": release,
    "release recovery": recovery,
    "compatibility replay": replay,
}.items():
    if "uses: ./.github/actions/materialize-aros-tools-runtime" not in workflow:
        raise SystemExit(f"{name} must materialize the released runtime at every executable boundary")
    if "TOOLS_RUNTIME_LOCK: toolchains/aros-tools-runtime-v1.json" not in workflow:
        raise SystemExit(f"{name} must bind the one committed aros-tools runtime lock")
    if name != "release qualification" and (
        "AROS_TOOLS_REPOSITORY" in workflow or "AROS_TOOLS_COMMIT" in workflow
    ):
        raise SystemExit(f"{name} must not retain a source-checkout runtime pin")
runtime_action = (Path(sys.argv[2]).parents[1] / "actions" / "materialize-aros-tools-runtime" / "action.yml")
action = runtime_action.read_text(encoding="utf-8")
for required in (
    "sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6",
    "sleep 20",
    "materialize-aros-tools-runtime.py",
    "GH_TOKEN: ${{ github.token }}",
):
    if required not in action:
        raise SystemExit(f"released runtime materializer lost required trust boundary: {required}")
PY
python3 -B "$script_dir/test-llvm-patch.py"
python3 -B "$script_dir/test-crosstools-release.py"
python3 -B "$script_dir/test-aros-tools-runtime.py"
temporary=$(mktemp -d "${TMPDIR:-/tmp}/aros-toolchain-producer-test.XXXXXX")
case "$temporary" in
    "${TMPDIR:-/tmp}"/aros-toolchain-producer-test.*) ;;
    *) echo "refusing unsafe temporary directory: $temporary" >&2; exit 1 ;;
esac
trap 'rm -rf "$temporary"' EXIT

mkdir -p "$temporary/provenance-inventory" "$temporary/provenance-bin"
printf '%s\n' 'first attested payload' > "$temporary/provenance-inventory/first.bin"
printf '%s\n' 'second attested payload' > "$temporary/provenance-inventory/second.json"
printf '%s\n' 'retained provenance bundle' > "$temporary/provenance-inventory/toolchain-provenance.sigstore.json"
first_digest=$(shasum -a 256 "$temporary/provenance-inventory/first.bin" | awk '{print $1}')
second_digest=$(shasum -a 256 "$temporary/provenance-inventory/second.json" | awk '{print $1}')
bundle_digest=$(shasum -a 256 "$temporary/provenance-inventory/toolchain-provenance.sigstore.json" | awk '{print $1}')
printf '%s  %s\n' "$first_digest" first.bin > "$temporary/provenance-inventory/SHA256SUMS"
printf '%s  %s\n' "$second_digest" second.json >> "$temporary/provenance-inventory/SHA256SUMS"
printf '%s  %s\n' "$bundle_digest" toolchain-provenance.sigstore.json >> "$temporary/provenance-inventory/SHA256SUMS"
jq -n --arg first "$first_digest" --arg second "$second_digest" '
    [{verificationResult: {statement: {subject: [
        {name: "first.bin", digest: {sha256: $first}},
        {name: "second.json", digest: {sha256: $second}}
    ]}}}]
' > "$temporary/provenance-response.json"
printf '%s\n' '{}' > "$temporary/provenance-bundle.json"
cat > "$temporary/provenance-bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == attestation && "$2" == verify ]]
cat "$FAKE_GH_ATTESTATION_RESPONSE"
EOF
chmod +x "$temporary/provenance-bin/gh"
FAKE_GH_ATTESTATION_RESPONSE="$temporary/provenance-response.json" \
PATH="$temporary/provenance-bin:$PATH" \
"$provenance_verifier" \
    --checksums "$temporary/provenance-inventory/SHA256SUMS" \
    --bundle "$temporary/provenance-bundle.json" \
    --exclude-subject toolchain-provenance.sigstore.json \
    --repository metaneutrons/aros-toolchains \
    --signer-workflow metaneutrons/aros-toolchains/.github/workflows/toolchain-release.yml \
    --source-digest 0123456789abcdef0123456789abcdef01234567 \
    --source-ref refs/tags/v0.1.0-fixture \
    --output "$temporary/verified-provenance.json" >/dev/null
jq -e 'type == "array" and length == 1' "$temporary/verified-provenance.json" >/dev/null
if FAKE_GH_ATTESTATION_RESPONSE="$temporary/provenance-response.json" \
    PATH="$temporary/provenance-bin:$PATH" \
    "$provenance_verifier" \
        --checksums "$temporary/provenance-inventory/SHA256SUMS" \
        --bundle "$temporary/provenance-bundle.json" \
        --repository metaneutrons/aros-toolchains \
        --signer-workflow metaneutrons/aros-toolchains/.github/workflows/toolchain-release.yml \
        --source-digest 0123456789abcdef0123456789abcdef01234567 \
        --source-ref refs/tags/v0.1.0-fixture \
        --output "$temporary/unexpected-provenance.json" >/dev/null 2>&1; then
    echo "provenance verifier accepted a final checksum inventory without excluding its bundle" >&2
    exit 1
fi

echo "native toolchain release contract test passed"
