#!/usr/bin/env bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

script_dir=$(cd "$(dirname "$0")" && pwd -P)
source_root=$(cd "$script_dir/../../.." && pwd -P)
producer="$source_root/scripts/toolchain/producer.py"
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
grep -Fq -- '-DAROS_RUST_TOOLS_DIR="$work_dir/rust-target/release"' "$source_root/scripts/toolchain/compatibility.sh"
grep -Fq -- '-DAROS_ENABLE_MMU=ON' "$source_root/scripts/toolchain/compatibility.sh"
grep -Fq -- 'for upstream_target in includes linklibs' "$source_root/scripts/toolchain/compatibility.sh"
grep -Fq -- 'host-python-upstream-make-$upstream_target' "$source_root/scripts/toolchain/compatibility.sh"
grep -Fq -- 'PATH=/nonexistent "$toolchain/bin/clang"' "$source_root/scripts/toolchain/compatibility.sh"
grep -Fq -- 'env ac_cv_prog_cc_c23=' "$source_root/scripts/toolchain/compatibility.sh"
grep -Fq -- 'AROS_TOOLCHAIN_SOURCE_CACHE' "$source_root/.github/workflows/toolchain-release.yml"
grep -Fq -- 'submodules: recursive' "$source_root/.github/workflows/toolchain-release.yml"
python3 - "$source_root/.github/workflows/toolchain-release.yml" <<'PY'
from pathlib import Path
import sys

workflow = Path(sys.argv[1]).read_text(encoding="utf-8")
start = workflow.index("          name: verified-toolchain-sources")
end = workflow.index("\n\n  build:", start)
source_artifact = workflow[start:end]
if "          include-hidden-files: true" not in source_artifact:
    raise SystemExit("verified source artifact must retain Cargo checksum files")
PY
python3 -B "$script_dir/test-host-python-env.py"
python3 -B "$script_dir/test-llvm-patch.py"
python3 -B "$script_dir/test-crosstools-release.py"
temporary=$(mktemp -d "${TMPDIR:-/tmp}/aros-toolchain-producer-test.XXXXXX")
case "$temporary" in
    "${TMPDIR:-/tmp}"/aros-toolchain-producer-test.*) ;;
    *) echo "refusing unsafe temporary directory: $temporary" >&2; exit 1 ;;
esac
trap 'rm -rf "$temporary"' EXIT

mkdir -p "$temporary/checkout"
git -C "$temporary/checkout" init -q
printf '%s\n' 'tracked fixture' > "$temporary/checkout/tracked.txt"
git -C "$temporary/checkout" add tracked.txt
git -C "$temporary/checkout" \
    -c user.name=AROS-NG \
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
    "schema": "aros-ng-toolchain-recipe-v1",
    "source_commit": sys.argv[2],
    "source_tree": sys.argv[3],
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
    --recipe "$temporary/checkout-recipe.json" \
    --lock "$temporary/checkout-lock.json" \
    --profiles "$temporary/checkout-profiles.json" >/dev/null
mkdir -p "$temporary/checkout/source-cache"
printf '%s\n' 'allowed untracked cache' > "$temporary/checkout/source-cache/input"
python3 "$producer" verify-checkout \
    --source-root "$temporary/checkout" \
    --recipe "$temporary/checkout-recipe.json" \
    --lock "$temporary/checkout-lock.json" \
    --profiles "$temporary/checkout-profiles.json" >/dev/null
printf '%s\n' 'mutated source lock fixture' > "$temporary/checkout-lock.json"
if python3 "$producer" verify-checkout \
    --source-root "$temporary/checkout" \
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
    printf '%s\n' '// deterministic producer fixture' > "$root/include/c++/v1/vector"
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
    --source-root "$source_root" \
    --lock "$source_root/toolchains/llvm-11.0.0.sources.json" \
    --profiles "$source_root/toolchains/profiles-v1.json" \
    --output "$temporary/recipe.json" \
    --allow-dirty
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
assert manifest["tree_sha256"] == "ebc8e4c29bf8eb78c54be3f719dfdcebf86008ebfb809f43bcc46cec830d8179"

spdx = json.loads((directory / f"{asset}.spdx.json").read_text())
assert spdx["documentDescribes"] == ["SPDXRef-Package-AROSToolchain"]
host_python = {
    package["name"]: package
    for package in spdx["packages"]
    if package["SPDXID"].startswith("SPDXRef-HostPython-")
}
assert host_python["mako"]["versionInfo"] == "1.3.10"
assert host_python["markupsafe"]["versionInfo"] == "3.0.2"
assert {
    relationship["spdxElementId"]
    for relationship in spdx["relationships"]
    if relationship["relationshipType"] == "BUILD_DEPENDENCY_OF"
} == {"SPDXRef-HostPython-1", "SPDXRef-HostPython-2"}

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

# Exercise the positive publish gate with the complete 4 hosts x 3 profiles
# catalog before the real workflow spends hours producing it.
printf '%s\n' 'fixture armhf builtins' \
    > "$temporary/root-a/lib/clang/11.0.0/lib/aros/libclang_rt.builtins-armhf.a"
printf '%s\n' 'fixture aarch64 builtins' \
    > "$temporary/root-a/lib/clang/11.0.0/lib/aros/libclang_rt.builtins-aarch64.a"
mkdir -p "$temporary/complete"
for host in linux-x86_64 linux-aarch64 macos-x86_64 macos-aarch64; do
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
cp "$temporary/recipe.json" "$temporary/complete/toolchain-recipe-v1.json"
cp "$source_root/toolchains/llvm-11.0.0.sources.json" "$temporary/complete/"
cp "$source_root/toolchains/profiles-v1.json" "$temporary/complete/"
cp "$source_root/toolchains/toolchain-manifest-v1.schema.json" "$temporary/complete/"
cp "$source_root/toolchains/tree-digest-v1.fixture.json" "$temporary/complete/"
python3 "$producer" index \
    --directory "$temporary/complete" \
    --base-url https://example.invalid/toolchain-test-v1 \
    --require-complete-v1
python3 - "$temporary/complete/toolchain-index-v1.json" <<'PY'
import json
import sys
index = json.load(open(sys.argv[1], encoding="utf-8"))
assert index["schema"] == 1
assert len(index["artifacts"]) == 12
assert all(artifact["enabled"] is True for artifact in index["artifacts"])
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
