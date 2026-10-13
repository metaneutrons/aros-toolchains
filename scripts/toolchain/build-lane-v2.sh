#!/usr/bin/env bash
# One cold native build and guarded package handoff. No transport authentication.
set -euo pipefail
set -C

fail() { printf 'V2 build handoff: %s\n' "$*" >&2; exit 1; }
digest() { shasum -a 256 "$1" | awk '{print $1}'; }
aros='' runtime_sha='' recipe='' source_lock='' profiles='' source_dir='' producer_dir=''
tools_dir='' cache_dir='' preset='' host='' release_id='' jobs='' timeout='' root=''
declare -a forbidden=()
seen='|'
while (( $# )); do
    key=$1
    (( $# >= 2 )) || fail "missing value for $key"
    value=$2
    [[ -n "$value" && "$value" != *$'\n'* && "$value" != *$'\r'* ]] || fail "invalid value for $key"
    if [[ "$key" != --forbidden-prefix ]]; then
        [[ "$seen" != *"|$key|"* ]] || fail "duplicate option $key"
        seen+="$key|"
    fi
    case "$key" in
        --aros) aros=$value;;
        --aros-sha256) runtime_sha=$value;;
        --recipe) recipe=$value;;
        --source-lock) source_lock=$value;;
        --profiles) profiles=$value;;
        --source-dir) source_dir=$value;;
        --producer-dir) producer_dir=$value;;
        --tools-dir) tools_dir=$value;;
        --cache-dir) cache_dir=$value;;
        --preset) preset=$value;;
        --host) host=$value;;
        --release-id) release_id=$value;;
        --jobs) jobs=$value;;
        --timeout-seconds) timeout=$value;;
        --root) root=$value;;
        --forbidden-prefix) forbidden+=("$value");;
        *) fail "unknown option $key";;
    esac
    shift 2
done
for required in aros runtime_sha recipe source_lock profiles source_dir producer_dir tools_dir cache_dir preset host release_id jobs timeout root; do
    [[ -n "${!required}" ]] || fail "missing required selector $required"
done
[[ "$runtime_sha" =~ ^[0-9a-f]{64}$ ]] || fail 'runtime digest is not lowercase SHA-256'
[[ "$jobs" =~ ^[1-9][0-9]*$ && "$timeout" =~ ^[1-9][0-9]*$ ]] || fail 'jobs/deadline must be positive decimal integers'
[[ "$preset" =~ ^[A-Za-z0-9._-]{1,128}$ && "$preset" != . && "$preset" != .. ]] || fail 'preset differs from the native profile identifier contract'
[[ "$release_id" =~ ^[a-z0-9][a-z0-9._-]*$ ]] || fail 'release ID is unsafe'
case "$host" in linux-x86_64|linux-aarch64|macos-aarch64) ;; *) fail 'unsupported build host';; esac
for file in "$aros" "$recipe" "$source_lock" "$profiles"; do
    [[ "$file" == /* && -f "$file" && ! -L "$file" ]] || fail 'inputs must be absolute regular files'
done
[[ -x "$aros" && "$(digest "$aros")" == "$runtime_sha" ]] || fail 'selected executable differs from the independently measured runtime'
for directory in "$source_dir" "$producer_dir" "$tools_dir" "$cache_dir"; do
    [[ "$directory" == /* && -d "$directory" && ! -L "$directory" ]] || fail 'inputs must be absolute directory roots'
done
for prefix in ${forbidden[@]+"${forbidden[@]}"}; do
    [[ "$prefix" == /* ]] || fail 'forbidden prefixes must be absolute'
done
[[ "$root" == /* && ! -e "$root" && ! -L "$root" ]] || fail 'operation root must be an absent absolute path'
name=${root##*/}
[[ -n "$name" && "$name" != . && "$name" != .. ]] || fail 'operation root has an invalid final component'
parent=${root%/*}
[[ -d "$parent" && ! -L "$parent" ]] || fail 'operation root needs an existing nonlinked parent'
canonical_parent=$(cd "$parent" && pwd -P)
[[ "$root" == "$canonical_parent/$name" ]] || fail 'operation root must use its canonical parent path'
for directory in "$source_dir" "$producer_dir" "$tools_dir" "$cache_dir"; do
    canonical=$(cd "$directory" && pwd -P)
    [[ "$root" != "$canonical" && "$root" != "$canonical/"* && "$canonical" != "$root/"* ]] || fail 'operation root overlaps a selected input root'
done
mkdir "$root" "$root/payload" "$root/payload/evidence"
evidence="$root/payload/evidence"
package="$root/payload/package"
work="$root/work"
candidate="$root/candidate"

# Keep all expensive lifecycle work native. No resume, clean, network population
# or compiler-cache fallback occurs in this adapter.
"$aros" toolchain build --preset="$preset" --recipe "$recipe" \
    --source-dir "$source_dir" --producer-dir "$producer_dir" --tools-dir "$tools_dir" \
    --work-dir "$work" --output-dir "$candidate" --cache-dir "$cache_dir" \
    --compiler-cache off --jobs "$jobs" --timeout-seconds "$timeout" \
    --release-id "$release_id" --format json > "$evidence/build-result.json"
build_sha=$(digest "$evidence/build-result.json")
"$aros" toolchain producer environment --host "$host" \
    --output "$evidence/environment.json" --format json > "$evidence/environment-result.json"
context=(--recipe "$recipe" --source-lock "$source_lock" --profiles "$profiles"
    --preset="$preset" --host "$host" --release-id "$release_id"
    --build-environment "$evidence/environment.json" --package-format family-v2
    --forbidden-prefix "$root" --forbidden-prefix "$source_dir"
    --forbidden-prefix "$producer_dir" --forbidden-prefix "$tools_dir")
for prefix in ${forbidden[@]+"${forbidden[@]}"}; do context+=(--forbidden-prefix "$prefix"); done
"$aros" toolchain producer package "${context[@]}" \
    --build-result "$evidence/build-result.json" --build-result-sha256 "$build_sha" \
    --build-work-dir "$work" --input-dir "$candidate/toolchain" \
    --output-dir "$package" --format json > "$evidence/package-result.json"
"$aros" toolchain producer verify-package "${context[@]}" \
    --input-dir "$package" --format json > "$evidence/package-verify.json"

# The native verifier checks archive closure and recipe/profile/host identity.
# Join its independently read-back output to the guarded packaging response.
jq -e --arg package "$package" --arg build_sha "$build_sha" \
    --arg host "$host" --arg preset "$preset" \
    --slurpfile verified "$evidence/package-verify.json" '
    .schema == "aros-toolchain-producer-stage-v1" and .operation == "package" and
    .package_dir == $package and (.archive | startswith($package + "/")) and
    (.archive | ltrimstr($package + "/") | test("^[A-Za-z0-9][A-Za-z0-9._-]*\\.tar\\.xz$")) and
    .manifest == (.archive + ".manifest.json") and .checksum == (.archive + ".sha256") and
    .sbom == (.archive + ".spdx.json") and ($verified | length) == 1 and
    $verified[0].schema == "aros-toolchain-producer-stage-v1" and
    $verified[0].operation == "verify-package" and $verified[0].manifest.schema == 2 and
    $verified[0].manifest.host == $host and $verified[0].manifest.target_profile == $preset and
    .sha256 == $verified[0].sha256 and .size == $verified[0].size and
    .finished_candidate.build_result_sha256 == $build_sha and
    .finished_candidate.package_tree_sha256 == $verified[0].manifest.tree_sha256 and
    (.finished_candidate.portable_measurement | type == "string" and length > 0) and
    (.finished_candidate.portable_measurement_sha256 | test("^[0-9a-f]{64}$"))
    ' "$evidence/package-result.json" >/dev/null || fail 'guarded package/readback join failed'

# The Rust serializer includes the terminal LF in this string. jq -r would add
# another LF and invalidate the exact digest retained by the native producer.
jq -j '.finished_candidate.portable_measurement' "$evidence/package-result.json" \
    > "$evidence/measurement.json"
measurement_sha=$(digest "$evidence/measurement.json")
expected_measurement=$(jq -er '.finished_candidate.portable_measurement_sha256' "$evidence/package-result.json")
[[ "$measurement_sha" == "$expected_measurement" ]] || fail 'portable measurement bytes differ from the native producer digest'
[[ "$(digest "$evidence/build-result.json")" == "$build_sha" ]] || fail 'build result changed during handoff'
[[ "$(digest "$aros")" == "$runtime_sha" ]] || fail 'runtime changed during handoff'

# Caller retains these independently measured selectors outside the payload.
# Owning-job upload/OIDC/signature and later protected admission are separate.
jq -n --arg root "$root" --arg runtime_sha "$runtime_sha" --arg build_sha "$build_sha" \
    --arg measurement_sha "$measurement_sha" --arg host "$host" --arg preset "$preset" \
    --arg release_id "$release_id" '{
    schema:"aros-toolchain-build-handoff-v2", assurance:"local-byte-readback-only",
    host:$host, target_profile:$preset, release_id:$release_id,
    payload_dir:($root+"/payload"), package_dir:($root+"/payload/package"),
    measurement:($root+"/payload/evidence/measurement.json"),
    environment:($root+"/payload/evidence/environment.json"),
    runtime_sha256:$runtime_sha, build_result_sha256:$build_sha,
    measurement_sha256:$measurement_sha
    }' > "$root/handoff.json"
