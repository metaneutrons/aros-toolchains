#!/usr/bin/env bash
# Same-job compiler A/B by default; explicit owner mode reads authenticated
# independent builds before the same source-bound SDK qualification.
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
owner_a_selection='' owner_b_selection='' source_workflow='' source_ref=''
workflow='' job_name='' same_attempt=false owner_mode=false
requested_release_id=''
seen='|'
while (( $# )); do
    if [[ "$1" == --same-attempt ]]; then
        [[ "$same_attempt" == false ]] || fail 'duplicate same-attempt selector'
        same_attempt=true
        shift
        continue
    fi
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
        --owner-a-selection) owner_a_selection=$value;;
        --owner-b-selection) owner_b_selection=$value;;
        --source-workflow) source_workflow=$value;; --source-ref) source_ref=$value;;
        --workflow) workflow=$value;; --job-name) job_name=$value;;
        --release-id) requested_release_id=$value;;
        *) fail "unknown option $key";;
    esac
    shift 2
done
for name in aros runtime_sha inputs selection source producer tools cache upstream group preset host root jobs deadline; do
    [[ -n "${!name}" ]] || fail "missing $name"
done

# Owner selection is an explicit mode switch. Validate its complete caller
# context before checking the runtime bytes or creating the operation root so
# a malformed owner request can never fall through to diagnostic rebuilding.
owner_count=0
for name in owner_a_selection owner_b_selection source_workflow source_ref workflow job_name; do
    [[ -z "${!name}" ]] || ((owner_count += 1))
done
if (( owner_count > 0 )); then
    (( owner_count == 6 )) || fail 'compiler owner selectors must be supplied together'
    owner_mode=true
    for owner_selection in "$owner_a_selection" "$owner_b_selection"; do
        [[ "$owner_selection" == /* && -f "$owner_selection" && ! -L "$owner_selection" ]] || \
            fail 'owner selections must be absolute regular nonlinked files'
        owner_selection_parent=${owner_selection%/*}
        owner_selection_name=${owner_selection##*/}
        [[ -n "$owner_selection_parent" && -n "$owner_selection_name" &&
           "$owner_selection" == "$(cd "$owner_selection_parent" && pwd -P)/$owner_selection_name" ]] || \
            fail 'owner selections must use canonical paths'
        owner_selection_size=$(wc -c < "$owner_selection" | tr -d '[:space:]')
        if [[ ! "$owner_selection_size" =~ ^[0-9]{1,8}$ ]] || (( 10#$owner_selection_size > 16777216 )); then
            fail 'owner selection exceeds its byte limit'
        fi
    done
    [[ "$owner_a_selection" != "$owner_b_selection" ]] || fail 'owner selections must be distinct files'
    for selected_workflow in "$workflow" "$source_workflow"; do
        [[ "$selected_workflow" =~ ^\.github/workflows/[A-Za-z0-9_-]+\.yml$ ]] || \
            fail 'workflow selector is invalid'
    done
    (( ${#job_name} <= 256 )) || fail 'job name is too long'
    [[ "$source_ref" =~ ^refs/(heads|tags)/[A-Za-z0-9._/-]+$ ]] || fail 'source ref is invalid'
    ref_tail=${source_ref#refs/*/}
    [[ -n "$ref_tail" && "$ref_tail" != *'..'* && "$ref_tail" != *'@{'* &&
       "$ref_tail" != *//* && "$ref_tail" != */ && "$ref_tail" != *. && "$ref_tail" != *@ ]] || \
        fail 'source ref is not canonical'
    IFS='/' read -r -a ref_parts <<< "$ref_tail"
    for ref_part in "${ref_parts[@]}"; do
        [[ -n "$ref_part" && "$ref_part" != .* && "$ref_part" != *. && "$ref_part" != *.lock ]] || \
            fail 'source ref is not canonical'
    done
else
    [[ "$same_attempt" == false ]] || fail '--same-attempt requires explicit compiler owners'
fi
[[ "$runtime_sha" =~ ^[0-9a-f]{64}$ && "$jobs" =~ ^[1-9][0-9]*$ && "$deadline" =~ ^[1-9][0-9]*$ ]] || fail 'invalid digest or execution budget'
case "$host" in linux-x86_64|linux-aarch64|macos-aarch64) ;; *) fail 'unsupported native diagnostic host';; esac
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
default_release_id="toolchain-dev-$(git -C "$producer" rev-parse --short=12 HEAD)"
if [[ "$owner_mode" == true && "$source_ref" == refs/tags/* ]]; then
    [[ "$requested_release_id" == "${source_ref#refs/tags/}" ]] || fail 'tag-bound owner release ID differs from its source ref'
else
    [[ -z "$requested_release_id" || "$requested_release_id" == "$default_release_id" ]] || fail 'diagnostic release ID differs from its producer commit'
fi
release_id=${requested_release_id:-$default_release_id}
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
for copy in a b; do
    if [[ "$owner_mode" == true ]]; then
        owner_selection=$owner_a_selection
        if [[ "$copy" == b ]]; then owner_selection=$owner_b_selection; fi
        owner_selection_sha=$(digest "$owner_selection")
        owner_args=(--aros "$aros" --aros-sha256 "$runtime_sha" --recipe "$recipe"
            --recipe-file-sha256 "$(digest "$recipe")" --source-lock "$lock"
            --source-lock-sha256 "$(digest "$lock")" --profiles "$profiles"
            --profiles-sha256 "$(digest "$profiles")" --source-selection "$owner_selection"
            --source-selection-sha256 "$owner_selection_sha" --workflow "$workflow"
            --job-name "$job_name" --source-workflow "$source_workflow" --source-ref "$source_ref"
            --group "$group" --preset "$preset" --host "$host" --copy "$copy"
            --release-id "$release_id" --root "$root/compiler-$copy" --forbidden-prefix "$parent")
        if [[ "$same_attempt" == true ]]; then owner_args+=(--same-attempt); fi
        bash "$producer/scripts/toolchain/read-native-owner-v2.sh" "${owner_args[@]}"
    else
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
    case "$role" in
        make) program=$(type -P gmake || type -P make || true);;
        llvm-arcc|llvm-ranlibcc)
            # These are closure roles, not programs installed in PATH. Resolve
            # the real Xcode executable, as in the original compatibility lane;
            # the tools-owned closure restores its argv[0] before invocation.
            [[ "$host" == macos-aarch64 ]] || fail "Darwin host role on non-Darwin host: $role"
            xcrun_program=$(type -P xcrun || true)
            program=''
            if [[ "$xcrun_program" == /* && -f "$xcrun_program" && -x "$xcrun_program" ]]; then
                xcode_role=${role#llvm-}
                program=$("$xcrun_program" --find "${xcode_role%cc}" 2>/dev/null || true)
            fi
            ;;
        *) program=$(type -P "$role" || true);;
    esac
    [[ "$program" == /* && -f "$program" && -x "$program" ]] || fail "missing host role $role"
    host_tools+=(--host-tool "$role=$program")
done < "$root/host-tool-roles.txt"
(( ${#host_tools[@]} > 0 )) || fail 'empty host command closure'
jq -ce --arg group "$group" --arg preset "$preset" '.sdks[] | select(any(.compiler_profiles[]; .group_id == $group and .profile == $preset))' "$root/plan.json" > "$root/sdk-selections.jsonl"
[[ -s "$root/sdk-selections.jsonl" ]] || fail 'compiler lane has no selected SDK'
build_sdk_with_diagnostics() {
    local sdk_status
    if "$aros" sdk build --identity "$identity" --identity-sha256 "$identity_sha" \
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
        --sdk-forbidden-prefix "$cache" --evidence-dir "$operation/local-evidence" --format json \
        > "$operation/result.json"; then
        return 0
    else
        sdk_status=$?
        if ! python3 -B "$producer/scripts/toolchain/retain-sdk-config-logs.py" \
            --operation-dir "$operation"; then
            printf 'Compiler/SDK diagnostic: unable to retain upstream SDK config.log files\n' >&2
        fi
        exit "$sdk_status"
    fi
}
while IFS= read -r sdk; do
    id=$(jq -er '.id' <<< "$sdk")
    identity="$inputs/$(jq -r '.identity.file' <<< "$sdk")"
    identity_sha=$(jq -er '.identity.sha256' <<< "$sdk")
    source_preset=$(jq -er '.source_preset' <<< "$sdk")
    operation="$root/sdk-$id"
    mkdir "$operation" "$operation/engine-work"
    build_sdk_with_diagnostics
done < "$root/sdk-selections.jsonl"
[[ "$(digest "$aros")" == "$runtime_sha" ]] || fail 'runtime changed during qualification'
printf 'Compiler A/B and SDK local generation completed. No release admission or publication.\n'
