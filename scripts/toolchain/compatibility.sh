#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 6 ]]; then
    echo "usage: AROS_TOOLCHAIN_SOURCE_CACHE=DIR $0 ARCHIVE HOST PROFILE PROFILES_JSON UPSTREAM_COMMIT WORK_DIR" >&2
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
source_cache=${AROS_TOOLCHAIN_SOURCE_CACHE:-}
source_lock=${AROS_TOOLCHAIN_SOURCE_LOCK:-"$source_root/toolchains/llvm-11.0.0.sources.json"}

if [[ -z "$source_cache" || ! -d "$source_cache" ]]; then
    echo "compatibility probe requires AROS_TOOLCHAIN_SOURCE_CACHE with verified host Python sources" >&2
    exit 1
fi
if [[ ! -f "$source_lock" ]]; then
    echo "compatibility probe cannot read the host Python source lock: $source_lock" >&2
    exit 1
fi
source_cache=$(cd "$source_cache" && pwd -P)
source_lock=$(cd "$(dirname "$source_lock")" && pwd -P)/$(basename "$source_lock")
python3 "$script_dir/producer.py" prefetch \
    --lock "$source_lock" --destination "$source_cache" --offline
host_python_runner=(
    python3 -B "$script_dir/host-python-env.py"
    --lock "$source_lock"
    --cache "$source_cache"
)

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
    profile["upstream_output_target"],
    profile["cpu"],
    profile["platform"],
    profile.get("float_abi", ""),
    profile["target_triple"],
]))
PY
)
IFS='|' read -r configure_target upstream_output_target target_cpu target_platform float_abi target_triple <<< "$profile_values"

if [[ -e "$work_dir" ]]; then
    echo "compatibility probe refuses a reused work directory: $work_dir" >&2
    exit 1
fi
mkdir -p "$work_dir/extracted" "$work_dir/upstream-src" "$work_dir/upstream-build"
tar -xJf "$archive" -C "$work_dir/extracted"

# A consumer probe must exercise the generators from this checkout, not an
# arbitrary binary left in the shared Cargo target directory by an older
# commit. Build the three configure-time tools into the isolated probe root and
# pass that root explicitly to CMake.
cargo build --release \
    --manifest-path "$source_root/tools/aros-tools/Cargo.toml" \
    --target-dir "$work_dir/rust-target" \
    -p aros-transpiler \
    -p aros-genmodule \
    -p aros-collect
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
    -DAROS_RUST_TOOLS_DIR="$work_dir/rust-target/release" \
    -DAROS_ENABLE_MMU=ON \
    -DCMAKE_BUILD_TYPE=Release

git -C "$work_dir/upstream-src" init -q
git -C "$work_dir/upstream-src" remote add origin https://github.com/aros-development-team/AROS.git
git -C "$work_dir/upstream-src" fetch -q --depth=1 origin "$upstream_commit"
git -C "$work_dir/upstream-src" checkout -q --detach FETCH_HEAD
# Autoconf 2.73 otherwise appends -std=gnu23 to CC before this upstream commit
# snapshots CC_BASE. The legacy configure logic then derives impossible host
# tool names such as llvm-argcc. Preserve the older no-extra-dialect behavior
# without patching the pinned upstream checkout.
(
    cd "$work_dir/upstream-build"
    "${host_python_runner[@]}" --work-dir "$work_dir/host-python-upstream-configure" -- \
        env ac_cv_prog_cc_c23= \
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
for upstream_target in includes linklibs; do
    "${host_python_runner[@]}" \
        --work-dir "$work_dir/host-python-upstream-make-$upstream_target" -- \
        "$make_program" -C "$work_dir/upstream-build" -j 2 "$upstream_target"
done

# Exercise the public Clang driver contract, not only CMake's direct partial
# linker path. PATH is deliberately unusable: Clang must find collect-aros
# beside itself, and the collector must find its sibling ld.lld/llvm-strip and
# all target inputs through the explicit Developer sysroot.
toolchain="$work_dir/extracted/toolchain"
developer="$work_dir/upstream-build/bin/$upstream_output_target/AROS/Developer"
mkdir -p "$work_dir/standalone"
standalone_triples=("$target_triple")
if [[ "$profile" == pc-x86_64 ]]; then
    standalone_triples+=("i386-unknown-aros")
fi
for triple in "${standalone_triples[@]}"; do
    suffix=${triple%%-*}
    target_flags=()
    if [[ "$float_abi" == hard && "$triple" == arm-* ]]; then
        target_flags+=("-mfloat-abi=hard")
    fi
    PATH=/nonexistent "$toolchain/bin/clang" \
        --target="$triple" --sysroot="$developer" "${target_flags[@]}" \
        -ffreestanding -fno-ident -g0 -nostdlib -nostartfiles \
        "$script_dir/fixtures/smoke.c" -o "$work_dir/standalone/c-$suffix.o"
    PATH=/nonexistent "$toolchain/bin/clang++" \
        --target="$triple" --sysroot="$developer" "${target_flags[@]}" \
        -ffreestanding -fno-ident -g0 -nostdlib -nostartfiles -nostdinc++ \
        "$script_dir/fixtures/smoke.cpp" -o "$work_dir/standalone/cxx-$suffix.o"
    "$toolchain/bin/llvm-nm" "$work_dir/standalone/c-$suffix.o" \
        | grep -q '__TOOLCHAIN_LIST__$'
    "$toolchain/bin/llvm-nm" "$work_dir/standalone/cxx-$suffix.o" \
        | grep -q '__INIT_ARRAY_LIST__$'
done
python3 - "$work_dir/standalone" <<'PY'
from pathlib import Path
import sys
outputs = sorted(Path(sys.argv[1]).glob("*.o"))
if not outputs:
    raise SystemExit("standalone collector probe produced no outputs")
for output in outputs:
    data = output.read_bytes()
    if data[:4] != b"\x7fELF" or data[7:9] != bytes((15, 1)):
        raise SystemExit(f"standalone collector output lacks AROS ELF identity: {output}")
print(f"standalone collector probe passed for {len(outputs)} C/C++ outputs")
PY

echo "AROS-NG CMake and upstream compatibility probes passed at $upstream_commit for $profile"
