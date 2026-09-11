#!/usr/bin/env bash
# shellcheck disable=SC2016
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

script_dir=$(cd "$(dirname "$0")" && pwd -P)
source_root=$(cd "$script_dir/../../.." && pwd -P)
producer="$source_root/scripts/toolchain/producer.py"
: "${AROS_TEST_SOURCE_ROOT:?AROS_TEST_SOURCE_ROOT must name the AROS source checkout}"
: "${AROS_TEST_TOOLS_ROOT:?AROS_TEST_TOOLS_ROOT must name the native executor checkout}"
asset=aros-toolchain-v1-llvm11.0.0-linux-x86_64-pc-x86_64.tar.xz
grep -Fq -- '--with-toolchain=llvm' "$source_root/scripts/toolchain/compatibility.sh"
grep -Fq -- '--with-aros-toolchain=yes' "$source_root/scripts/toolchain/compatibility.sh"
grep -Fq -- 'host-python-env.py' "$source_root/scripts/toolchain/build-release.sh"
grep -Fq -- 'CMAKE_BUILD_PARALLEL_LEVEL' "$source_root/scripts/toolchain/build-release.sh"
grep -Fq -- 'AROS_TOOLCHAIN_REPRO_FLAGS' "$source_root/scripts/toolchain/build-release.sh"
grep -Fq -- 'cargo-vendor-config.toml' "$source_root/scripts/toolchain/build-release.sh"
grep -Fq -- '--remap-path-prefix=$source_cache=/usr/src/aros-sources' "$source_root/scripts/toolchain/build-release.sh"
grep -Fq -- '--forbid-prefix "$source_cache"' "$source_root/scripts/toolchain/build-release.sh"
grep -Fq -- '"$prefix/bin/aros-collect"' "$source_root/scripts/toolchain/build-release.sh"
grep -Fq -- 'ln -s aros-collect "$prefix/bin/collect-aros"' "$source_root/scripts/toolchain/build-release.sh"
grep -Fq -- 'rm -f "$prefix/bin/llvm-config"' "$source_root/scripts/toolchain/build-release.sh"
grep -Fq -- 'host-python-env.py' "$source_root/scripts/toolchain/compatibility.sh"
grep -Fq -- '--target-dir "$work_dir/rust-target"' "$source_root/scripts/toolchain/compatibility.sh"
grep -Fq -- '-p aros-ahi-runner' "$source_root/scripts/toolchain/compatibility.sh"
grep -Fq -- '-DAROS_RUST_TOOLS_DIR="$work_dir/rust-target/release"' "$source_root/scripts/toolchain/compatibility.sh"
grep -Fq -- '-DAROS_ENABLE_MMU=ON' "$source_root/scripts/toolchain/compatibility.sh"
grep -Fq -- 'for upstream_target in includes linklibs' "$source_root/scripts/toolchain/compatibility.sh"
grep -Fq -- 'profile["upstream_output_target"]' "$source_root/scripts/toolchain/compatibility.sh"
grep -Fq -- 'bin/$upstream_output_target/AROS/Developer' "$source_root/scripts/toolchain/compatibility.sh"
grep -Fq -- 'host-python-upstream-make-$upstream_target' "$source_root/scripts/toolchain/compatibility.sh"
grep -Fq -- 'PATH=/nonexistent "$toolchain/bin/clang"' "$source_root/scripts/toolchain/compatibility.sh"
grep -Fq -- '-fno-unwind-tables -fno-asynchronous-unwind-tables' "$source_root/scripts/toolchain/compatibility.sh"
grep -Fq -- '-ffreestanding -fno-exceptions' "$source_root/scripts/toolchain/compatibility.sh"
grep -Fq -- '${target_float_flag:+"$target_float_flag"}' "$source_root/scripts/toolchain/compatibility.sh"
grep -Fq -- 'env ac_cv_prog_cc_c23=' "$source_root/scripts/toolchain/compatibility.sh"
grep -Fq -- '--python-cache-dir "$GITHUB_WORKSPACE/source-cache"' "$source_root/.github/workflows/toolchain-release.yml"
python3 - "$source_root/.github/workflows/toolchain-release.yml" \
    "$source_root/.github/workflows/toolchain-release-recovery.yml" \
    "$source_root/.github/workflows/toolchain-compatibility-replay.yml" <<'PY'
from pathlib import Path
import sys

release_path = Path(sys.argv[1])
source_root = release_path.parents[2]
workflow = release_path.read_text(encoding="utf-8")
recovery = Path(sys.argv[2]).read_text(encoding="utf-8")
replay = Path(sys.argv[3]).read_text(encoding="utf-8")
fetch_start = workflow.index("      - name: Fetch and verify immutable toolchain and host Python sources")
fetch_end = workflow.index("\n      - name: Vendor locked Rust collector sources", fetch_start)
fetch_step = workflow[fetch_start:fetch_end]
cache_directory = 'mkdir -p "$GITHUB_WORKSPACE/source-cache"'
if cache_directory not in fetch_step:
    raise SystemExit("source cache fetch must explicitly create its selected cache directory")
if fetch_step.index(cache_directory) > fetch_step.index("toolchain producer cache"):
    raise SystemExit("source cache directory must exist before the native cache command")
if workflow.count('git worktree add --detach "$producer_dir" "$(git rev-parse HEAD)"') != 2:
    raise SystemExit("native recipe and build jobs must materialize distinct producer roots")
if workflow.count('--producer-dir "$AROS_PRODUCER_DIR"') != 2:
    raise SystemExit("native recipe and build jobs must bind the isolated producer root")
if '--producer-dir "$GITHUB_WORKSPACE"' in workflow:
    raise SystemExit("native recipe and build jobs must not overlap producer and dependency roots")
recipe_start = workflow.index("      - name: Validate committed inputs and compute native recipe identity")
recipe_end = workflow.index("\n\n      - id: matrix", recipe_start)
recipe_step = workflow[recipe_start:recipe_end]
for required in (
    '--source-lock "$AROS_PRODUCER_DIR/$SOURCE_LOCK"',
    '--profiles "$AROS_PRODUCER_DIR/$PROFILES"',
):
    if required not in recipe_step:
        raise SystemExit("native recipe must bind lock and profiles below its isolated producer root")
start = workflow.index("          name: verified-toolchain-sources")
end = workflow.index("\n\n  build:", start)
source_artifact = workflow[start:end]
if "          include-hidden-files: true" not in source_artifact:
    raise SystemExit("verified source artifact must retain Cargo checksum files")
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
    "gh attestation verify",
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
consumer_end = workflow.index("      - name: Build the exact native compatibility helpers externally", consumer_start)
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
if workflow.count('toolchain producer compatibility-ports') != 2:
    raise SystemExit("release must acquire and offline-verify the closed Unicode compatibility inputs")
if workflow.count('--ports-lock "$GITHUB_WORKSPACE/$COMPATIBILITY_PORTS_LOCK"') != 3:
    raise SystemExit("release compatibility must bind the same declared Unicode input lock at every stage")
if workflow.count('--ports-cache-dir "$GITHUB_WORKSPACE/source-cache"') != 1:
    raise SystemExit("release compatibility must materialize Unicode inputs only from the verified cache")
if workflow.count('--ports-sources-dir "$work/ports-sources"') != 1:
    raise SystemExit("release compatibility must pass one owned Unicode source directory to upstream")
if workflow.count('type -P ar || true') != 1 or workflow.count('type -P ranlib || true') != 1:
    raise SystemExit("release compatibility must seal Darwin ar and ranlib aliases from measured executables")
if 'host_cc_program=' in workflow or '--host-tool "cc=$host_cc_program"' in workflow:
    raise SystemExit("release compatibility must not retain the incomplete three-tool closure")
if "name: native-lifecycle-${{ matrix.host }}-${{ matrix.profile }}-${{ matrix.copy }}" not in workflow:
    raise SystemExit("each producer must retain native lifecycle receipts outside the release archive")
PY
python3 - "$source_root/.github/workflows/toolchain-compatibility-replay.yml" <<'PY'
from pathlib import Path
import sys

workflow = Path(sys.argv[1]).read_text(encoding="utf-8")
if workflow.count("run-id: ${{ inputs.source_run_id }}") != 3:
    raise SystemExit("compatibility replay must source recipe, verified package, and locked sources from one run")
if workflow.count("github-token: ${{ github.token }}") != 3:
    raise SystemExit("cross-run artifact downloads require the scoped GitHub token")
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
if workflow.count('toolchain producer compatibility-ports') != 2:
    raise SystemExit("compatibility replay must acquire and offline-verify the closed Unicode inputs")
if workflow.count('--ports-lock "$GITHUB_WORKSPACE/$COMPATIBILITY_PORTS_LOCK"') != 3:
    raise SystemExit("compatibility replay must bind the same declared Unicode input lock at every stage")
if workflow.count('--ports-cache-dir "$GITHUB_WORKSPACE/source-cache"') != 1:
    raise SystemExit("compatibility replay must materialize Unicode inputs only from the verified cache")
if workflow.count('--ports-sources-dir "$work/ports-sources"') != 1:
    raise SystemExit("compatibility replay must pass one owned Unicode source directory to upstream")
if workflow.count('type -P ar || true') != 1 or workflow.count('type -P ranlib || true') != 1:
    raise SystemExit("compatibility replay must seal Darwin ar and ranlib aliases from measured executables")
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
if "issue #27" not in release:
    raise SystemExit("release policy must record the explicit Intel macOS follow-up")
PY
python3 - "$source_root/scripts/toolchain/build-release.sh" <<'PY'
from pathlib import Path
import sys

script = Path(sys.argv[1]).read_text(encoding="utf-8")
contract_start = script.index('contract = {')
observation_start = script.index('observation = {', contract_start)
contract = script[contract_start:observation_start]
observation = script[observation_start:script.index("open(sys.argv[1]", observation_start)]
if "runner_image" in contract or "host_cc" in contract:
    raise SystemExit("observed runner facts must not enter the byte-compared release manifest")
for field in ("runner_image_version", "host_cc", "cmake", "make", "python", "rustc", "cargo"):
    if f'"{field}"' not in observation:
        raise SystemExit(f"build observation lost {field}")
PY
python3 -B "$script_dir/test-host-python-env.py"
python3 -B "$script_dir/test-llvm-patch.py"
python3 -B "$script_dir/test-crosstools-release.py"
python3 - "$source_root/toolchains/producer-executor-v1.toml" "$AROS_TEST_TOOLS_ROOT" \
    "$source_root/.github/workflows/toolchain-release.yml" \
    "$source_root/.github/workflows/toolchain-release-recovery.yml" \
    "$source_root/.github/workflows/toolchain-compatibility-replay.yml" \
    "$source_root/.github/workflows/ci.yml" <<'PY'
import hashlib
import re
import subprocess
import sys
import tomllib
from pathlib import Path

path = Path(sys.argv[1])
tools_root = Path(sys.argv[2]).resolve()
workflows = [Path(item) for item in sys.argv[3:]]
with path.open("rb") as stream:
    declaration = tomllib.load(stream)
expected = {
    "schema_version", "contract_id", "contract_path", "contract_sha256",
    "tools_commit", "source_lock", "profiles",
}
if set(declaration) != expected:
    raise SystemExit("native executor declaration must have one closed field set")
if declaration["schema_version"] != 1:
    raise SystemExit("native executor declaration has an unsupported schema")
if declaration["contract_id"] != "aros-toolchain-producer-v1":
    raise SystemExit("native executor declaration has an unexpected contract ID")
if declaration["contract_path"] != "contracts/toolchain-producer-v1.toml":
    raise SystemExit("native executor declaration has an unexpected contract path")
if declaration["source_lock"] != "toolchains/llvm-11.0.0.sources.json":
    raise SystemExit("native executor declaration has an unexpected source lock")
if declaration["profiles"] != "toolchains/profiles-v1.json":
    raise SystemExit("native executor declaration has an unexpected profile matrix")
for field, length in (("contract_sha256", 64), ("tools_commit", 40)):
    value = declaration[field]
    if not isinstance(value, str) or re.fullmatch(rf"[0-9a-f]{{{length}}}", value) is None:
        raise SystemExit(f"native executor declaration {field} must be a lowercase Git/hash identity")
contract = tools_root / declaration["contract_path"]
if not contract.is_file() or contract.is_symlink():
    raise SystemExit("native executor contract must be a regular file below the checked-out tools root")
if hashlib.sha256(contract.read_bytes()).hexdigest() != declaration["contract_sha256"]:
    raise SystemExit("native executor declaration contract digest differs from the checked-out contract")
tools_commit = subprocess.check_output(
    ["git", "-C", str(tools_root), "rev-parse", "HEAD"], text=True
).strip()
if tools_commit != declaration["tools_commit"]:
    raise SystemExit("native executor declaration tools commit differs from the checked-out executor")
for workflow in workflows:
    match = re.search(r"^  AROS_TOOLS_COMMIT: ([0-9a-f]{40})$", workflow.read_text(encoding="utf-8"), re.MULTILINE)
    if match is None or match.group(1) != declaration["tools_commit"]:
        raise SystemExit(f"{workflow.name} must pin the declared native executor commit")
PY
temporary=$(mktemp -d "${TMPDIR:-/tmp}/aros-toolchain-producer-test.XXXXXX")
case "$temporary" in
    "${TMPDIR:-/tmp}"/aros-toolchain-producer-test.*) ;;
    *) echo "refusing unsafe temporary directory: $temporary" >&2; exit 1 ;;
esac
trap 'rm -rf "$temporary"' EXIT

mkdir -p "$temporary/checkout"
git -C "$temporary/checkout" init -q
printf '%s\n' 'tracked fixture' > "$temporary/checkout/tracked.txt"
python3 - "$source_root/toolchains/llvm-11.0.0.sources.json" "$temporary/checkout" <<'PY'
import json
from pathlib import Path
import sys

lock = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
for source in lock["sources"]:
    patch = source.get("patch")
    if patch is None:
        continue
    path = Path(sys.argv[2]) / patch
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"fixture patch for {source['filename']}\n", encoding="utf-8")
PY
git -C "$temporary/checkout" add .
git -C "$temporary/checkout" \
    -c user.name='AROS Toolchain Fixture' \
    -c user.email=toolchain-producer@example.invalid \
    commit -q -m fixture
checkout_commit=$(git -C "$temporary/checkout" rev-parse HEAD)
checkout_tree=$(git -C "$temporary/checkout" rev-parse 'HEAD^{tree}')
checkout_epoch=$(git -C "$temporary/checkout" show -s --format=%ct HEAD)
printf '%s\n' 'source lock fixture' > "$temporary/checkout-lock.json"
printf '%s\n' 'profiles fixture' > "$temporary/checkout-profiles.json"
python3 - "$temporary/checkout-recipe.json" \
    "$checkout_commit" "$checkout_tree" "$checkout_epoch" \
    "$temporary/checkout-lock.json" "$temporary/checkout-profiles.json" <<'PY'
import hashlib
import json
from pathlib import Path
import sys
recipe = {
    "schema": "aros-toolchain-recipe-v2",
    "source_commit": sys.argv[2],
    "source_tree": sys.argv[3],
    "producer_commit": sys.argv[2],
    "producer_tree": sys.argv[3],
    "tools_commit": sys.argv[2],
    "tools_tree": sys.argv[3],
    "source_date_epoch": int(sys.argv[4]),
    "source_lock_sha256": hashlib.sha256(Path(sys.argv[5]).read_bytes()).hexdigest(),
    "profiles_sha256": hashlib.sha256(Path(sys.argv[6]).read_bytes()).hexdigest(),
    "patches": [],
}
canonical = (json.dumps(
    recipe, sort_keys=True, separators=(",", ":"), ensure_ascii=False
) + "\n").encode("utf-8")
recipe["recipe_sha256"] = hashlib.sha256(canonical).hexdigest()
Path(sys.argv[1]).write_text(json.dumps(recipe, sort_keys=True, indent=2) + "\n")
PY
python3 "$producer" verify-checkout \
    --source-root "$temporary/checkout" \
    --producer-root "$temporary/checkout" \
    --tools-root "$temporary/checkout" \
    --recipe "$temporary/checkout-recipe.json" \
    --lock "$temporary/checkout-lock.json" \
    --profiles "$temporary/checkout-profiles.json" >/dev/null
mkdir -p "$temporary/checkout/source-cache"
printf '%s\n' 'allowed untracked cache' > "$temporary/checkout/source-cache/input"
python3 "$producer" verify-checkout \
    --source-root "$temporary/checkout" \
    --producer-root "$temporary/checkout" \
    --tools-root "$temporary/checkout" \
    --recipe "$temporary/checkout-recipe.json" \
    --lock "$temporary/checkout-lock.json" \
    --profiles "$temporary/checkout-profiles.json" >/dev/null
printf '%s\n' 'mutated source lock fixture' > "$temporary/checkout-lock.json"
if python3 "$producer" verify-checkout \
    --source-root "$temporary/checkout" \
    --producer-root "$temporary/checkout" \
    --tools-root "$temporary/checkout" \
    --recipe "$temporary/checkout-recipe.json" \
    --lock "$temporary/checkout-lock.json" \
    --profiles "$temporary/checkout-profiles.json" >/dev/null 2>&1; then
    echo "producer accepted a source-lock mutation" >&2
    exit 1
fi
printf '%s\n' 'source lock fixture' > "$temporary/checkout-lock.json"
printf '%s\n' 'tracked mutation' >> "$temporary/checkout/tracked.txt"
if python3 "$producer" verify-checkout \
    --source-root "$temporary/checkout" \
    --producer-root "$temporary/checkout" \
    --tools-root "$temporary/checkout" \
    --recipe "$temporary/checkout-recipe.json" \
    --lock "$temporary/checkout-lock.json" \
    --profiles "$temporary/checkout-profiles.json" >/dev/null 2>&1; then
    echo "producer accepted a tracked checkout mutation" >&2
    exit 1
fi

make_fixture() {
    local root=$1
    mkdir -p \
        "$root/bin" \
        "$root/include/c++/v1" \
        "$root/lib/clang/11.0.0/lib/aros" \
        "$root/share/Größe"
    local tool
    for tool in clang clang++ ld.lld llvm-ar llvm-ranlib llvm-nm \
        llvm-strip llvm-objcopy llvm-objdump aros-collect; do
        cp "$script_dir/mock-tool.sh" "$root/bin/$tool"
    done
    ln -s aros-collect "$root/bin/collect-aros"
    ln -s aros-collect "$root/bin/collect-aros32"
    local header
    for header in algorithm cerrno cinttypes cstddef cstdint deque memory \
        string system_error vector; do
        printf '%s\n' '// deterministic producer fixture' \
            > "$root/include/c++/v1/$header"
    done
    local library
    for library in libc++.a libc++abi.a libunwind.a; do
        printf 'fixture %s\n' "$library" > "$root/lib/$library"
    done
    printf '%s\n' 'fixture x86_64 builtins' \
        > "$root/lib/clang/11.0.0/lib/aros/libclang_rt.builtins-x86_64.a"
    printf '%s\n' 'fixture i386 builtins' \
        > "$root/lib/clang/11.0.0/lib/aros/libclang_rt.builtins-i386.a"
    printf '%s\n' 'UTF-8 inventory fixture' > "$root/share/Größe/marker-ä.txt"
    ln -s '../include/c++/v1/vector' "$root/share/vector-link"
}

make_fixture "$temporary/root-a"
make_fixture "$temporary/root-b"
python3 "$producer" recipe \
    --source-root "$temporary/checkout" \
    --producer-root "$temporary/checkout" \
    --tools-root "$temporary/checkout" \
    --lock "$source_root/toolchains/llvm-11.0.0.sources.json" \
    --profiles "$source_root/toolchains/profiles-v1.json" \
    --output "$temporary/recipe.json" \
    --allow-dirty
python3 - "$source_root/toolchains/llvm-11.0.0.sources.json" \
    "$temporary/recipe.json" "$temporary/checkout" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

lock = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
recipe = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
checkout = Path(sys.argv[3])
declared = {
    source["patch"]: hashlib.sha256((checkout / source["patch"]).read_bytes()).hexdigest()
    for source in lock["sources"]
    if "patch" in source
}
observed = {patch["path"]: patch["sha256"] for patch in recipe["patches"]}
assert observed == declared
PY
python3 - "$producer" "$source_root/toolchains/llvm-11.0.0.sources.json" <<'PY'
import copy
import importlib.util
import json
from pathlib import Path
import sys

spec = importlib.util.spec_from_file_location("toolchain_producer", sys.argv[1])
producer = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(producer)
lock = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))

unsafe = copy.deepcopy(lock)
unsafe["sources"][0]["patch"] = "tools/crosstools/llvm/../escape-aros.diff"
try:
    producer.validate_source_lock(unsafe)
except SystemExit as error:
    assert "unsafe AROS patch path" in str(error)
else:
    raise AssertionError("producer accepted an escaping patch declaration")

duplicate = copy.deepcopy(lock)
duplicate["sources"][1]["patch"] = duplicate["sources"][0]["patch"]
try:
    producer.validate_source_lock(duplicate)
except SystemExit as error:
    assert "duplicate AROS patch path" in str(error)
else:
    raise AssertionError("producer accepted a duplicate patch declaration")
PY
python3 - "$source_root/toolchains/llvm-11.0.0.sources.json" \
    "$temporary/missing-patch-lock.json" <<'PY'
import json
from pathlib import Path
import sys

lock = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
lock["sources"][0]["patch"] = "tools/crosstools/llvm/missing-aros.diff"
Path(sys.argv[2]).write_text(
    json.dumps(lock, sort_keys=True, indent=2) + "\n", encoding="utf-8"
)
PY
if python3 "$producer" recipe \
    --source-root "$temporary/checkout" \
    --producer-root "$temporary/checkout" \
    --tools-root "$temporary/checkout" \
    --lock "$temporary/missing-patch-lock.json" \
    --profiles "$source_root/toolchains/profiles-v1.json" \
    --output "$temporary/missing-patch-recipe.json" \
    --allow-dirty >"$temporary/missing-patch.stdout" 2>"$temporary/missing-patch.stderr"; then
    echo "producer accepted a missing declared patch" >&2
    exit 1
fi
grep -Fq -- 'declared AROS patch is missing:' "$temporary/missing-patch.stderr"
printf '%s\n' '{"schema":"fixture-build-environment-v1"}' \
    > "$temporary/environment.json"

for copy in a b; do
    mkdir -p "$temporary/out-$copy"
    python3 "$producer" package \
        --root "$temporary/root-$copy" \
        --recipe "$temporary/recipe.json" \
        --lock "$source_root/toolchains/llvm-11.0.0.sources.json" \
        --profiles "$source_root/toolchains/profiles-v1.json" \
        --release-id toolchain-test-v1 \
        --host linux-x86_64 \
        --target-profile pc-x86_64 \
        --asset-name "$asset" \
        --output-dir "$temporary/out-$copy" \
        --build-environment "$temporary/environment.json" \
        --forbid-prefix "$temporary"
done

python3 "$producer" compare \
    --left "$temporary/out-a/$asset" \
    --right "$temporary/out-b/$asset" \
    --output-dir "$temporary/verified"
python3 "$producer" verify \
    --archive "$temporary/verified/$asset" \
    --fixtures "$source_root/scripts/toolchain/fixtures" \
    --host linux-x86_64 \
    --target-profile pc-x86_64
for copy in a b; do
    mkdir -p "$temporary/repack-$copy"
    python3 "$producer" repackage \
        --archive "$temporary/verified/$asset" \
        --recipe "$temporary/recipe.json" \
        --lock "$source_root/toolchains/llvm-11.0.0.sources.json" \
        --profiles "$source_root/toolchains/profiles-v1.json" \
        --source-release-id toolchain-test-v1 \
        --release-id toolchain-recovery-test-v1 \
        --output-dir "$temporary/repack-$copy" >/dev/null
done
python3 "$producer" compare \
    --left "$temporary/repack-a/$asset" \
    --right "$temporary/repack-b/$asset" \
    --output-dir "$temporary/repacked" >/dev/null
python3 - "$temporary/verified/$asset.manifest.json" \
    "$temporary/repacked/$asset.manifest.json" <<'PY'
import json, sys
source = json.load(open(sys.argv[1], encoding="utf-8"))
recovered = json.load(open(sys.argv[2], encoding="utf-8"))
assert source["release_id"] == "toolchain-test-v1"
assert recovered["release_id"] == "toolchain-recovery-test-v1"
for field in (
    "source_commit", "producer_commit", "tools_commit",
    "recipe_sha256", "source_lock_sha256",
    "profiles_sha256", "tree_sha256", "build_environment",
):
    assert recovered[field] == source[field]
PY
if python3 "$producer" repackage \
    --archive "$temporary/verified/$asset" \
    --recipe "$temporary/recipe.json" \
    --lock "$source_root/toolchains/llvm-11.0.0.sources.json" \
    --profiles "$source_root/toolchains/profiles-v1.json" \
    --source-release-id wrong-source-release \
    --release-id toolchain-recovery-test-v1 \
    --output-dir "$temporary/repack-invalid" >/dev/null 2>&1; then
    echo "producer repackaged an archive from the wrong source release" >&2
    exit 1
fi
python3 "$producer" index \
    --directory "$temporary/verified" \
    --base-url https://example.invalid/toolchain-test-v1
if python3 "$producer" index \
    --directory "$temporary/verified" \
    --base-url https://example.invalid/toolchain-test-v1 \
    --require-complete-v1 >/dev/null 2>&1; then
    echo "producer accepted a partial publish matrix" >&2
    exit 1
fi

python3 - "$producer" "$source_root/toolchains/tree-digest-v1.fixture.json" <<'PY'
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

spec = importlib.util.spec_from_file_location("toolchain_producer", sys.argv[1])
producer = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(producer)
fixture = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
entries = fixture["entries"]
assert entries == sorted(entries, key=lambda entry: entry["path"])
digest = hashlib.sha256()
for entry in entries:
    digest.update(producer.json_bytes(entry))
assert digest.hexdigest() == fixture["tree_sha256"]
file_entry = next(entry for entry in entries if entry["type"] == "file")
content = fixture["file_content_utf8"].encode("utf-8")
assert len(content) == file_entry["size"]
assert hashlib.sha256(content).hexdigest() == file_entry["sha256"]
PY

python3 - "$temporary/verified" "$asset" \
    "$source_root/toolchains/toolchain-manifest-v1.schema.json" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

directory = Path(sys.argv[1])
asset = sys.argv[2]
manifest = json.loads((directory / f"{asset}.manifest.json").read_text())
try:
    import jsonschema
except ImportError:
    pass
else:
    schema = json.loads(Path(sys.argv[3]).read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(manifest)
assert type(manifest["schema"]) is int and manifest["schema"] == 1
assert manifest["target_profile"] == "pc-x86_64"
assert manifest["target_triple"] == "x86_64-unknown-aros"

# Known-answer digest for the normalized filesystem fixture. Together with
# toolchains/tree-digest-v1.fixture.json this pins the documented algorithm.
assert manifest["tree_sha256"] == "f91796eac82733e14061e7727ab4054e0f73bbb82b469fd26db931b1382fe078"

spdx = json.loads((directory / f"{asset}.spdx.json").read_text())
assert spdx["documentDescribes"] == ["SPDXRef-Package-AROSToolchain"]
host_python = {
    package["name"]: package
    for package in spdx["packages"]
    if package["SPDXID"].startswith("SPDXRef-HostPython-")
}
assert host_python["mako"]["versionInfo"] == "1.3.10"
assert host_python["markupsafe"]["versionInfo"] == "3.0.2"
source_packages = {
    package["name"]: package
    for package in spdx["packages"]
    if package["SPDXID"].startswith("SPDXRef-Source-")
}
assert source_packages["llvm"]["versionInfo"] == "11.0.0"
build_dependencies = {
    relationship["spdxElementId"]
    for relationship in spdx["relationships"]
    if relationship["relationshipType"] == "BUILD_DEPENDENCY_OF"
}
assert build_dependencies == {
    "SPDXRef-HostPython-1",
    "SPDXRef-HostPython-2",
}

index = json.loads((directory / "toolchain-index-v1.json").read_text())
assert type(index["schema"]) is int and index["schema"] == 1
assert index["base_url"] == "https://example.invalid/toolchain-test-v1"
artifact = index["artifacts"][0]
assert artifact["asset"] == asset
assert artifact["enabled"] is True
assert artifact["strip_components"] == 1
assert "toolchain-manifest.json" in artifact["required_paths"]
for required in ("bin/aros-collect", "bin/collect-aros", "bin/collect-aros32"):
    assert required in artifact["required_paths"]
for header in (
    "algorithm", "cerrno", "cinttypes", "cstddef", "cstdint", "deque",
    "memory", "string", "system_error", "vector",
):
    assert f"include/c++/v1/{header}" in artifact["required_paths"]
checksums = {}
for line in (directory / "SHA256SUMS").read_text().splitlines():
    checksum, name = line.split("  ", 1)
    checksums[name] = checksum
expected = {
    asset,
    f"{asset}.sha256",
    f"{asset}.manifest.json",
    f"{asset}.spdx.json",
    "toolchain-index-v1.json",
}
assert set(checksums) == expected
for name, expected_digest in checksums.items():
    assert hashlib.sha256((directory / name).read_bytes()).hexdigest() == expected_digest
PY

# Exercise the positive publish gate with the active 3 hosts x 3 profiles
# catalog before the real workflow spends hours producing it.
printf '%s\n' 'fixture armhf builtins' \
    > "$temporary/root-a/lib/clang/11.0.0/lib/aros/libclang_rt.builtins-armhf.a"
printf '%s\n' 'fixture aarch64 builtins' \
    > "$temporary/root-a/lib/clang/11.0.0/lib/aros/libclang_rt.builtins-aarch64.a"
mkdir -p "$temporary/complete"
for host in linux-x86_64 linux-aarch64 macos-aarch64; do
    for profile in pc-x86_64 arm-raspi rpi-aarch64; do
        complete_asset="aros-toolchain-v1-llvm11.0.0-${host}-${profile}.tar.xz"
        python3 "$producer" package \
            --root "$temporary/root-a" \
            --recipe "$temporary/recipe.json" \
            --lock "$source_root/toolchains/llvm-11.0.0.sources.json" \
            --profiles "$source_root/toolchains/profiles-v1.json" \
            --release-id toolchain-test-v1 \
            --host "$host" \
            --target-profile "$profile" \
            --asset-name "$complete_asset" \
            --output-dir "$temporary/complete" \
            --build-environment "$temporary/environment.json" \
            --forbid-prefix "$temporary" >/dev/null
    done
done
cp "$temporary/recipe.json" "$temporary/complete/toolchain-recipe-v2.json"
cp "$source_root/toolchains/llvm-11.0.0.sources.json" "$temporary/complete/"
cp "$source_root/toolchains/profiles-v1.json" "$temporary/complete/"
cp "$source_root/toolchains/toolchain-manifest-v1.schema.json" "$temporary/complete/"
cp "$source_root/toolchains/tree-digest-v1.fixture.json" "$temporary/complete/"
mkdir "$temporary/complete/cargo-vendor"
if python3 "$producer" index \
    --directory "$temporary/complete" \
    --base-url https://example.invalid/toolchain-test-v1 \
    --require-complete-v1 >/dev/null 2>&1; then
    echo "producer accepted a directory in the complete release inventory" >&2
    exit 1
fi
rmdir "$temporary/complete/cargo-vendor"
printf '%s\n' 'unexpected source payload' > "$temporary/complete/clang-source.tar.xz"
if python3 "$producer" index \
    --directory "$temporary/complete" \
    --base-url https://example.invalid/toolchain-test-v1 \
    --require-complete-v1 >/dev/null 2>&1; then
    echo "producer accepted an unexpected file in the complete release inventory" >&2
    exit 1
fi
rm "$temporary/complete/clang-source.tar.xz"
python3 "$producer" index \
    --directory "$temporary/complete" \
    --base-url https://example.invalid/toolchain-test-v1 \
    --require-complete-v1
if python3 "$producer" index \
    --directory "$temporary/complete" \
    --base-url https://example.invalid/toolchain-test-v1 \
    --require-complete-v1 \
    --require-provenance >/dev/null 2>&1; then
    echo "producer accepted a final release without provenance" >&2
    exit 1
fi
printf '%s\n' '{}' > "$temporary/complete/toolchain-provenance.sigstore.json"
python3 "$producer" index \
    --directory "$temporary/complete" \
    --base-url https://example.invalid/toolchain-test-v1 \
    --require-complete-v1 \
    --require-provenance
python3 - "$temporary/complete/toolchain-index-v1.json" <<'PY'
import json
from pathlib import Path
import sys
path = Path(sys.argv[1])
index = json.load(path.open(encoding="utf-8"))
assert index["schema"] == 1
assert len(index["artifacts"]) == 9
assert all(artifact["enabled"] is True for artifact in index["artifacts"])
checksums = (path.parent / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
assert len(checksums) == 43
assert any(line.endswith("  toolchain-provenance.sigstore.json") for line in checksums)
PY

cp "$temporary/verified/$asset.manifest.json" "$temporary/good-manifest.json"
python3 - "$temporary/verified/$asset.manifest.json" <<'PY'
import json
from pathlib import Path
import sys
path = Path(sys.argv[1])
manifest = json.loads(path.read_text())
manifest["schema"] = "1"
path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
PY
if python3 "$producer" index \
    --directory "$temporary/verified" \
    --base-url https://example.invalid/toolchain-test-v1 >/dev/null 2>&1; then
    echo "producer accepted a string manifest schema" >&2
    exit 1
fi
cp "$temporary/good-manifest.json" "$temporary/verified/$asset.manifest.json"

echo "toolchain producer contract test passed"
