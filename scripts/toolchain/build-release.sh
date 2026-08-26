#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "usage: $0 --source-root DIR --work-dir DIR --source-cache DIR --recipe FILE --lock FILE --profiles FILE --profile NAME --host ID --release-id ID --output-dir DIR" >&2
    exit 2
}

source_root=
work_dir=
source_cache=
recipe=
lock=
profiles=
profile=
host_id=
release_id=
output_dir=
jobs="${AROS_TOOLCHAIN_JOBS:-2}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --source-root) source_root=$2; shift 2 ;;
        --work-dir) work_dir=$2; shift 2 ;;
        --source-cache) source_cache=$2; shift 2 ;;
        --recipe) recipe=$2; shift 2 ;;
        --lock) lock=$2; shift 2 ;;
        --profiles) profiles=$2; shift 2 ;;
        --profile) profile=$2; shift 2 ;;
        --host) host_id=$2; shift 2 ;;
        --release-id) release_id=$2; shift 2 ;;
        --output-dir) output_dir=$2; shift 2 ;;
        --jobs) jobs=$2; shift 2 ;;
        *) usage ;;
    esac
done

[[ -n "$source_root" && -n "$work_dir" && -n "$source_cache" && -n "$recipe" && \
   -n "$lock" && -n "$profiles" && -n "$profile" && -n "$host_id" && \
   -n "$release_id" && -n "$output_dir" ]] || usage

source_root=$(cd "$source_root" && pwd -P)
mkdir -p "$work_dir" "$source_cache" "$output_dir"
work_dir=$(cd "$work_dir" && pwd -P)
source_cache=$(cd "$source_cache" && pwd -P)
output_dir=$(cd "$output_dir" && pwd -P)
prefix="$work_dir/install/toolchain"
build_dir="$work_dir/build"

if [[ -e "$build_dir/Makefile" || -e "$prefix/bin/clang" ]]; then
    echo "toolchain release build refuses a reused build or install directory: $work_dir" >&2
    exit 1
fi

profile_values=$(python3 - "$profiles" "$profile" <<'PY'
import json, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
matches = [item for item in data["profiles"] if item["name"] == sys.argv[2]]
if len(matches) != 1:
    raise SystemExit("unknown or ambiguous toolchain profile")
print(matches[0]["configure_target"] + "|" + matches[0]["target_triple"])
PY
)
configure_target=${profile_values%%|*}
target_triple=${profile_values#*|}
llvm_version=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' "$lock")
source_epoch=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["source_date_epoch"])' "$recipe")

python3 "$source_root/scripts/toolchain/producer.py" verify-checkout \
    --source-root "$source_root" \
    --recipe "$recipe" \
    --lock "$lock" \
    --profiles "$profiles"

python3 - "$work_dir/build-environment.json" "$host_id" <<'PY'
import json, os, platform, subprocess, sys
def version(command):
    try:
        return subprocess.check_output(command, text=True, stderr=subprocess.STDOUT).splitlines()[0]
    except Exception:
        return "unavailable"
value = {
    "schema": "aros-ng-toolchain-build-environment-v1",
    "host": sys.argv[2],
    "runner_image": os.environ.get("ImageOS", "local"),
    "runner_image_version": os.environ.get("ImageVersion", "local"),
    "host_cc": version([os.environ.get("CC", "cc"), "--version"]),
    "cmake": version(["cmake", "--version"]),
    "make": version(["gmake" if subprocess.call(["sh", "-c", "command -v gmake >/dev/null"]) == 0 else "make", "--version"]),
    "python": platform.python_version(),
}
open(sys.argv[1], "w", encoding="utf-8").write(json.dumps(value, sort_keys=True, indent=2) + "\n")
PY

python3 "$source_root/scripts/toolchain/producer.py" prefetch \
    --lock "$lock" --destination "$source_cache" --offline

export LC_ALL=C
export LANG=C
export TZ=UTC
export SOURCE_DATE_EPOCH="$source_epoch"
export ZERO_AR_DATE=1
# LLVM 11 still declares CMake policies from 3.5.  Current CMake releases
# reject that project unless the externally supported compatibility floor is
# explicit.  Keep it fixed for every producer lane rather than relying on a
# runner-specific CMake version.
export CMAKE_POLICY_VERSION_MINIMUM=3.5
if [[ $(uname -s) == Linux ]]; then
    export ARFLAGS=crD
    export RANLIBFLAGS=-D
fi
export AROS_VERIFIED_SOURCE_INDEX="$source_cache/sources.verified.json"
export AROS_UPSTREAM_FETCH="$source_root/scripts/fetch.sh"
# `cmake --build` is not a GNU-make recursive recipe, so it cannot consume
# the outer jobserver. Keep all nested CMake stages at the requested producer
# parallelism instead of silently falling back to one job.
export CMAKE_BUILD_PARALLEL_LEVEL="$jobs"
prefix_maps="-ffile-prefix-map=$source_root=/usr/src/aros-ng -fdebug-prefix-map=$source_root=/usr/src/aros-ng -fmacro-prefix-map=$source_root=/usr/src/aros-ng -ffile-prefix-map=$work_dir=/usr/src/aros-build -fdebug-prefix-map=$work_dir=/usr/src/aros-build -fmacro-prefix-map=$work_dir=/usr/src/aros-build"
export CFLAGS="${CFLAGS:-} $prefix_maps"
export CXXFLAGS="${CXXFLAGS:-} $prefix_maps"
# The target runtime CMake invocations set CMAKE_{C,CXX,ASM}_FLAGS explicitly,
# so they do not inherit the environment flags above. Export the same maps
# under a producer-only name consumed by the LLVM MetaMake recipe.
export AROS_TOOLCHAIN_REPRO_FLAGS="$prefix_maps"
umask 022

mkdir -p "$build_dir" "$prefix"
host_python_runner=(
    python3 -B "$source_root/scripts/toolchain/host-python-env.py"
    --lock "$lock"
    --cache "$source_cache"
)
(
    cd "$build_dir"
    "${host_python_runner[@]}" --work-dir "$work_dir/host-python-configure" -- \
        "$source_root/configure" \
        --target="$configure_target" \
        --with-toolchain=llvm \
        --with-llvm-version="$llvm_version" \
        --enable-toolchain-release \
        --with-portssources="$source_cache" \
        --with-aros-toolchain-install="$prefix"
)

make_program="make"
if command -v gmake >/dev/null 2>&1; then
    make_program="gmake"
fi
"${host_python_runner[@]}" --work-dir "$work_dir/host-python-make" -- \
    "$make_program" -C "$build_dir" -j "$jobs" crosstools-release \
    AROS_TOOLCHAIN_DEFAULT_SYSROOT= \
    FETCH="$source_root/scripts/toolchain/offline-fetch.py"

# llvm-config and LLVM's CMake package are producer-side inputs for building
# the target runtimes. They are not part of the v1 consumer contract and LLVM
# 11 records its build directory in both, so retain neither after the last
# runtime has been installed.
rm -f "$prefix/bin/llvm-config"
rm -rf "$prefix/lib/cmake/llvm"

asset_name="aros-toolchain-v1-llvm${llvm_version}-${host_id}-${profile}.tar.xz"
python3 "$source_root/scripts/toolchain/producer.py" package \
    --root "$prefix" \
    --recipe "$recipe" \
    --lock "$lock" \
    --profiles "$profiles" \
    --release-id "$release_id" \
    --host "$host_id" \
    --target-profile "$profile" \
    --asset-name "$asset_name" \
    --output-dir "$output_dir" \
    --build-environment "$work_dir/build-environment.json" \
    --forbid-prefix "$source_root" \
    --forbid-prefix "$work_dir" \
    --forbid-prefix "$prefix"

echo "built $asset_name for $host_id -> $target_triple"
