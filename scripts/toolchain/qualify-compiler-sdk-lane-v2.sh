#!/usr/bin/env bash
# Same-job diagnostic compiler A/B and source-bound SDK qualification.
# No upload is admitted as release evidence; this adapter cannot publish.
set -euo pipefail
set -C
fail() { printf 'Compiler/SDK diagnostic: %s\n' "$*" >&2; exit 1; }
digest() { shasum -a 256 "$1" | awk '{print $1}'; }
observe_gcc_inputs() {
    local compiler_root=$1 makefile='' makefiles='' matches=()
    makefiles=$(find "$compiler_root/work/native-lifecycle/build" -type f \
        -path '*/gcc/gcc/Makefile' -print)
    while IFS= read -r makefile; do
        if [[ -n "$makefile" ]]; then matches+=("$makefile"); fi
    done <<< "$makefiles"
    (( ${#matches[@]} == 1 )) || fail 'GNU checksum diagnostic requires exactly one generated GCC Makefile'
    python3 -B "$producer/scripts/toolchain/observe-gcc-checksum-inputs.py" \
        --gcc-build-dir "${matches[0]%/Makefile}" \
        --allowed-root "$compiler_root/work/native-lifecycle" \
        --output "${compiler_root%/*}/gcc-checksum-inputs-${compiler_root##*/}.json"
}
aros='' inputs='' selection='' source='' producer='' tools='' cache='' upstream=''
group='' preset='' host='' root='' jobs='' deadline='' runtime_sha=''
seen='|'
while (( $# )); do
    (( $# >= 2 )) || fail "missing value for $1"
    key=$1 value=$2
    [[ "$seen" != *"|$key|"* && -n "$value" && "$value" != *$'\n'* && "$value" != *$'\r'* ]] || fail 'duplicate or invalid option'
    seen+="$key|"
    case "$key" in
        --aros) aros=$value;; --runtime-sha256) runtime_sha=$value;;
        --inputs-dir) inputs=$value;; --selection) selection=$value;;
        --source-dir) source=$value;; --producer-dir) producer=$value;;
        --tools-dir) tools=$value;; --cache-dir) cache=$value;;
        --upstream-source-dir) upstream=$value;; --group) group=$value;;
        --preset) preset=$value;; --host) host=$value;; --root) root=$value;;
        --jobs) jobs=$value;; --timeout-seconds) deadline=$value;;
        *) fail "unknown option $key";;
    esac
    shift 2
done
for name in aros runtime_sha inputs selection source producer tools cache upstream group preset host root jobs deadline; do
    [[ -n "${!name}" ]] || fail "missing $name"
done
[[ "$runtime_sha" =~ ^[0-9a-f]{64}$ && "$jobs" =~ ^[1-9][0-9]*$ && "$deadline" =~ ^[1-9][0-9]*$ ]] || fail 'invalid digest or execution budget'
[[ "$host" == linux-x86_64 || "$host" == linux-aarch64 ]] || fail 'diagnostic host must be Linux'
[[ "$aros" == /* && -x "$aros" && -f "$aros" && ! -L "$aros" && "$(digest "$aros")" == "$runtime_sha" ]] || fail 'runtime bytes differ from selection'
for directory in "$inputs" "$source" "$producer" "$tools" "$cache" "$upstream"; do
    [[ "$directory" == /* && -d "$directory" && ! -L "$directory" ]] || fail 'input roots must be absolute nonlinked directories'
done
[[ "$selection" == /* && -f "$selection" && ! -L "$selection" ]] || fail 'selection must be an absolute regular file'
[[ "$root" == /* && ! -e "$root" && ! -L "$root" ]] || fail 'operation root must be absent'
parent=${root%/*}
[[ -d "$parent" && "$root" == "$(cd "$parent" && pwd -P)/${root##*/}" ]] || fail 'operation root must have a canonical existing parent'
for directory in "$inputs" "$source" "$producer" "$tools" "$cache" "$upstream"; do
    canonical=$(cd "$directory" && pwd -P)
    [[ "$root" != "$canonical" && "$root" != "$canonical/"* && "$canonical" != "$root/"* ]] || fail 'operation root overlaps selected input'
done
mkdir "$root"
collection_sha=$(digest "$inputs/toolchain-release-inputs-v2.json")
"$aros" toolchain producer release-plan --directory "$inputs" --inputs-sha256 "$collection_sha" --format json > "$root/plan.json"
selected_group=$(jq -ce --arg group "$group" '.groups | map(select(.group_id == $group)) | if length == 1 then .[0] else error("ambiguous group") end' "$root/plan.json")
jq -e --arg group "$group" --arg preset "$preset" --arg host "$host" 'any(.lanes[]; .group_id == $group and .target_profile == $preset and .host == $host)' "$root/plan.json" >/dev/null
recipe="$inputs/$(jq -r '.recipe.file' <<< "$selected_group")"
lock="$inputs/$(jq -r '.source_lock.file' <<< "$selected_group")"
compiler_family=$(jq -er '.family' "$lock")
profiles="$inputs/$(jq -r '.profiles.file' <<< "$selected_group")"
ports_relative=$(jq -er --arg group "$group" '.groups | map(select(.id == $group)) | if length == 1 then .[0].ports_lock else error("ambiguous ports selection") end' "$selection")
[[ "$ports_relative" =~ ^toolchains/[a-z0-9._-]+\.json$ ]] || fail 'unsafe ports selection'
ports="$producer/$ports_relative"
release_id="toolchain-dev-$(git -C "$producer" rev-parse --short=12 HEAD)"
for copy in a b; do
    bash "$producer/scripts/toolchain/build-lane-v2.sh" \
        --aros "$aros" --aros-sha256 "$runtime_sha" --recipe "$recipe" \
        --source-lock "$lock" --profiles "$profiles" --source-dir "$source" \
        --producer-dir "$producer" --tools-dir "$tools" --cache-dir "$cache" \
        --preset "$preset" --host "$host" --release-id "$release_id" \
        --jobs "$jobs" --timeout-seconds "$deadline" --root "$root/compiler-$copy" \
        --forbidden-prefix "$parent"
    if [[ "$compiler_family" == gnu ]]; then
        observe_gcc_inputs "$root/compiler-$copy"
    fi
done
"$aros" toolchain producer compare --left "$root/compiler-a/payload/package" \
    --right "$root/compiler-b/payload/package" --output "$root/comparison.json" --format json > "$root/comparison-result.json"
"$aros" toolchain producer materialize-engine-free-source --source-dir "$source" \
    --recipe "$recipe" --output-dir "$root/source-projection" --format json > "$root/source-projection.json"
host_tools=()
"$aros" toolchain producer compatibility-host-tools --host "$host" > "$root/host-tool-roles.txt"
while IFS= read -r role; do
    [[ -n "$role" ]] || continue
    case "$role" in make) program=$(type -P gmake || type -P make || true);; *) program=$(type -P "$role" || true);; esac
    [[ "$program" == /* && -f "$program" && -x "$program" ]] || fail "missing host role $role"
    host_tools+=(--host-tool "$role=$program")
done < "$root/host-tool-roles.txt"
(( ${#host_tools[@]} > 0 )) || fail 'empty host command closure'
jq -ce --arg group "$group" --arg preset "$preset" '.sdks[] | select(any(.compiler_profiles[]; .group_id == $group and .profile == $preset))' "$root/plan.json" > "$root/sdk-selections.jsonl"
[[ -s "$root/sdk-selections.jsonl" ]] || fail 'compiler lane has no selected SDK'
while IFS= read -r sdk; do
    id=$(jq -er '.id' <<< "$sdk")
    identity="$inputs/$(jq -r '.identity.file' <<< "$sdk")"
    identity_sha=$(jq -er '.identity.sha256' <<< "$sdk")
    source_preset=$(jq -er '.source_preset' <<< "$sdk")
    operation="$root/sdk-$id"
    mkdir "$operation" "$operation/engine-work"
    "$aros" sdk build --identity "$identity" --identity-sha256 "$identity_sha" \
        --source-dir "$source" --materialized-source-dir "$root/source-projection" \
        --source-preset "$source_preset" --recipe "$recipe" --source-lock "$lock" \
        --profiles "$profiles" --preset "$preset" --release-id "$release_id" --host "$host" \
        --build-environment "$root/compiler-a/payload/evidence/environment.json" \
        --package-dir "$root/compiler-a/payload/package" \
        --first-root "$operation/first" --second-root "$operation/second" \
        --engine-work-dir "$operation/engine-work" --helpers-dir "${aros%/*}" \
        --cmake-program "$(type -P cmake)" --ninja-program "$(type -P ninja)" \
        --upstream-source-dir "$upstream" --upstream-build-dir "$operation/upstream-build" \
        --python-cache-dir "$cache" --ports-lock "$ports" --ports-cache-dir "$cache" \
        --ports-sources-dir "$operation/ports" --python-environment-dir "$operation/python" \
        --host-tools-dir "$operation/host-tools" "${host_tools[@]}" \
        --cmake-build-dir "$operation/cmake" \
        --c-fixture "$producer/scripts/toolchain/fixtures/smoke.c" \
        --cxx-fixture "$producer/scripts/toolchain/fixtures/smoke.cpp" \
        --standalone-output-dir "$operation/standalone" --reports-dir "$operation/reports" \
        --jobs "$jobs" --timeout-seconds "$deadline" \
        --generation-record "$operation/generation.json" --output-dir "$operation/package" \
        --sdk-forbidden-prefix "$parent" --sdk-forbidden-prefix "$source" \
        --sdk-forbidden-prefix "$producer" --sdk-forbidden-prefix "$tools" \
        --sdk-forbidden-prefix "$upstream" --sdk-forbidden-prefix "$inputs" \
        --sdk-forbidden-prefix "$cache" --evidence-dir "$operation/local-evidence" --format json > "$operation/result.json"
done < "$root/sdk-selections.jsonl"
[[ "$(digest "$aros")" == "$runtime_sha" ]] || fail 'runtime changed during qualification'
printf 'Compiler A/B and SDK local generation completed. No release admission or publication.\n'
