#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 6 ]]; then
    echo "usage: $0 ARCHIVE HOST PROFILE PROFILES_JSON UPSTREAM_COMMIT WORK_DIR" >&2
    exit 2
fi

archive=$1
host_id=$2
profile=$3
profiles=$4
upstream_commit=$5
work_dir=$6
script_dir=$(cd "$(dirname "$0")" && pwd -P)
source_root=$(cd "$script_dir/../.." && pwd -P)

python3 "$script_dir/producer.py" verify \
    --archive "$archive" \
    --fixtures "$script_dir/fixtures" \
    --host "$host_id" \
    --target-profile "$profile"

profile_values=$(python3 - "$profiles" "$profile" <<'PY'
import json, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
matches = [item for item in data["profiles"] if item["name"] == sys.argv[2]]
if len(matches) != 1:
    raise SystemExit("unknown or ambiguous profile")
profile = matches[0]
print("|".join([
    profile["configure_target"],
    profile["cpu"],
    profile["platform"],
    profile.get("float_abi", ""),
]))
PY
)
IFS='|' read -r configure_target target_cpu target_platform float_abi <<< "$profile_values"

if [[ -e "$work_dir" ]]; then
    echo "compatibility probe refuses a reused work directory: $work_dir" >&2
    exit 1
fi
mkdir -p "$work_dir/extracted" "$work_dir/upstream-src" "$work_dir/upstream-build"
tar -xJf "$archive" -C "$work_dir/extracted"
llvm_version=$(python3 - "$work_dir/extracted/toolchain/toolchain-manifest.json" <<'PY'
import json, sys
manifest = json.load(open(sys.argv[1], encoding="utf-8"))
version = manifest.get("llvm_version")
if not isinstance(version, str) or not version:
    raise SystemExit("toolchain manifest lacks llvm_version")
print(version)
PY
)

# The NG consumer is deliberately independent of the historical configure
# probe below. It exercises the release manifest, prefix-owned tools, target
# selection, compiler checks, and a fresh top-level generation from the
# current checkout.
cmake -S "$source_root" -B "$work_dir/ng-build" -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE="$source_root/cmake/toolchains/AROS.cmake" \
    -DAROS_CROSS_TOOLCHAIN_ROOT="$work_dir/extracted/toolchain" \
    -DAROS_TARGET_CPU="$target_cpu" \
    -DAROS_TARGET_PLATFORM="$target_platform" \
    -DGCC_CONFIG_FLOAT_ABI="$float_abi" \
    -DAROS_ENABLE_MMU=OFF \
    -DCMAKE_BUILD_TYPE=Release

git -C "$work_dir/upstream-src" init -q
git -C "$work_dir/upstream-src" remote add origin https://github.com/aros-development-team/AROS.git
git -C "$work_dir/upstream-src" fetch -q --depth=1 origin "$upstream_commit"
git -C "$work_dir/upstream-src" checkout -q --detach FETCH_HEAD
(
    cd "$work_dir/upstream-build"
    "$work_dir/upstream-src/configure" \
        --target="$configure_target" \
        --with-toolchain=llvm \
        --with-llvm-version="$llvm_version" \
        --with-aros-toolchain=yes \
        --with-aros-toolchain-install="$work_dir/extracted/toolchain"
)
make_program="make"
if command -v gmake >/dev/null 2>&1; then
    make_program="gmake"
fi
"$make_program" -C "$work_dir/upstream-build" -j 2 includes linklibs

echo "AROS-NG CMake and upstream compatibility probes passed at $upstream_commit for $profile"
