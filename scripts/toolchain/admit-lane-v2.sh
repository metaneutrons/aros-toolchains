#!/usr/bin/env bash
# Authenticate one original owning-job upload, then verify its native bytes.
# No compiler execution, comparison, compatibility or publication authority.
set -euo pipefail
set -C
umask 077

fail() { printf 'V2 lane admission: %s\n' "$*" >&2; exit 1; }
digest() { shasum -a 256 "$1" | awk '{print $1}'; }
script_dir=$(cd "$(dirname "$0")" && pwd -P)
aros='' runtime_sha='' recipe='' recipe_sha='' source_lock='' source_sha=''
profiles='' profiles_sha='' environment='' environment_sha='' selection='' selection_sha=''
workflow='' job_name='' source_workflow='' source_ref='' group='' preset='' host='' copy=''
release_id='' executor_sha='' executor_binary_sha='' root='' same_attempt=false
declare -a forbidden=()
seen='|'
while (( $# )); do
    key=$1
    if [[ "$key" == --same-attempt ]]; then
        [[ "$same_attempt" == false ]] || fail 'duplicate same-attempt selector'
        same_attempt=true; shift; continue
    fi
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
        --recipe-file-sha256) recipe_sha=$value;;
        --source-lock) source_lock=$value;;
        --source-lock-sha256) source_sha=$value;;
        --profiles) profiles=$value;;
        --profiles-sha256) profiles_sha=$value;;
        --build-environment) environment=$value;;
        --build-environment-sha256) environment_sha=$value;;
        --source-selection) selection=$value;;
        --source-selection-sha256) selection_sha=$value;;
        --workflow) workflow=$value;;
        --job-name) job_name=$value;;
        --source-workflow) source_workflow=$value;;
        --source-ref) source_ref=$value;;
        --group) group=$value;;
        --preset) preset=$value;;
        --host) host=$value;;
        --copy) copy=$value;;
        --release-id) release_id=$value;;
        --executor-contract-sha256) executor_sha=$value;;
        --executor-binary-sha256) executor_binary_sha=$value;;
        --root) root=$value;;
        --forbidden-prefix) forbidden+=("$value");;
        *) fail "unknown option $key";;
    esac
    shift 2
done
for required in aros runtime_sha recipe recipe_sha source_lock source_sha profiles profiles_sha environment environment_sha selection selection_sha workflow job_name source_workflow source_ref group preset host copy release_id executor_sha executor_binary_sha root; do
    [[ -n "${!required}" ]] || fail "missing required selector $required"
done
for hash in "$runtime_sha" "$recipe_sha" "$source_sha" "$profiles_sha" "$environment_sha" "$selection_sha" "$executor_sha" "$executor_binary_sha"; do
    [[ "$hash" =~ ^[0-9a-f]{64}$ ]] || fail 'digest is not lowercase SHA-256'
done
for file in "$aros" "$recipe" "$source_lock" "$profiles" "$environment" "$selection"; do
    [[ "$file" == /* && -f "$file" && ! -L "$file" ]] || fail 'selected inputs must be absolute regular files'
    [[ "$file" == "$(cd "$(dirname "$file")" && pwd -P)/${file##*/}" ]] || fail 'selected input parent is noncanonical'
done
[[ -x "$aros" ]] || fail 'selected runtime is not executable'
[[ "$group" =~ ^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$ ]] || fail 'group identifier is invalid'
[[ "$preset" =~ ^[A-Za-z0-9._-]{1,128}$ && "$preset" != . && "$preset" != .. ]] || fail 'profile identifier is invalid'
[[ "$release_id" =~ ^[a-z0-9][a-z0-9._-]*$ ]] || fail 'release identifier is invalid'
case "$host" in linux-x86_64|linux-aarch64|macos-aarch64) ;; *) fail 'unsupported release host';; esac
case "$copy" in a|b) ;; *) fail 'independent build copy must be a or b';; esac
for selected_workflow in "$workflow" "$source_workflow"; do
    [[ "$selected_workflow" =~ ^\.github/workflows/[A-Za-z0-9_-]+\.yml$ ]] || fail 'workflow selector is invalid'
done
[[ "$source_ref" =~ ^refs/(heads|tags)/[A-Za-z0-9._/-]+$ ]] || fail 'source ref is invalid'
for prefix in ${forbidden[@]+"${forbidden[@]}"}; do [[ "$prefix" == /* ]] || fail 'forbidden prefix must be absolute'; done
(( ${#forbidden[@]} > 0 )) || fail 'at least one independently selected forbidden build prefix is required'

check_inputs() {
    [[ "$(digest "$aros")" == "$runtime_sha" && "$(digest "$recipe")" == "$recipe_sha" &&
       "$(digest "$source_lock")" == "$source_sha" && "$(digest "$profiles")" == "$profiles_sha" &&
       "$(digest "$environment")" == "$environment_sha" && "$(digest "$selection")" == "$selection_sha" ]] || fail 'selected input bytes changed or differ'
}
check_inputs
# The source producer comes from the independently selected native recipe, not
# the origin record. Native Rust validates the complete recipe/lock/profile.
jq -e --arg workflow "$source_workflow" --arg ref "$source_ref" --arg group "$group" \
    --arg host "$host" --arg preset "$preset" --arg copy "$copy" --slurpfile recipe "$recipe" '
    .schema == "aros-toolchain-artifact-selection-v1" and
    .context.workflow == $workflow and .context.source_ref == $ref and
    ($recipe | length) == 1 and $recipe[0].schema == "aros-toolchain-recipe-v2" and
    ($recipe[0].producer_commit | test("^[0-9a-f]{40}$")) and
    .context.producer_commit == $recipe[0].producer_commit and
    .selection == {role:"build",group:$group,host:$host,profile:$preset,copy:$copy}
    ' "$selection" >/dev/null || fail 'source selection differs from the independently selected native lane'
[[ "$root" == /* && ! -e "$root" && ! -L "$root" ]] || fail 'operation root must be fresh and absolute'
parent=${root%/*}; name=${root##*/}
[[ -n "$name" && "$name" != . && "$name" != .. && -d "$parent" && ! -L "$parent" &&
   "$root" == "$(cd "$parent" && pwd -P)/$name" ]] || fail 'operation root parent is noncanonical'
for file in "$aros" "$recipe" "$source_lock" "$profiles" "$environment" "$selection"; do
    [[ "$file" != "$root/"* ]] || fail 'operation root overlaps a selected input'
done
mkdir "$root"
origin_args=(verify-source --workflow "$workflow" --job-name "$job_name"
    --source-selection "$selection" --verified-output-dir "$root/transport")
if [[ "$same_attempt" == true ]]; then origin_args+=(--same-attempt); fi
# Never accept a pre-existing retained directory as authentication. This exact
# invocation must authenticate the current reader and original successful job.
python3 -B "$script_dir/artifact-origin.py" "${origin_args[@]}" > "$root/origin-verification.log"
check_inputs
python3 -B "$script_dir/native-lane-transport.py" --retained-dir "$root/transport" \
    --output-dir "$root/payload" > "$root/transport-result.json"
cmp "$environment" "$root/payload/evidence/environment.json" >/dev/null || fail 'owning-host environment differs from independent selection'
measurement_sha=$(digest "$root/payload/evidence/measurement.json")
signed_measurement=$(jq -er '.files["evidence/measurement.json"].sha256' "$root/transport/origin.json")
[[ "$measurement_sha" == "$signed_measurement" ]] || fail 'extracted measurement differs from authenticated origin'
build_sha=$(digest "$root/payload/evidence/build-result.json")
archives=("$root/payload/package/"*.tar.xz)
if (( ${#archives[@]} != 1 )); then
    fail 'native transport does not select exactly one archive'
fi
if [[ ! -f "${archives[0]}" || -L "${archives[0]}" ]]; then
    fail 'native transport does not select exactly one archive'
fi
archive_sha=$(digest "${archives[0]}")
archive_size=$(wc -c < "${archives[0]}" | tr -d '[:space:]')
context=(--recipe "$recipe" --source-lock "$source_lock" --profiles "$profiles"
    --preset="$preset" --host "$host" --release-id "$release_id"
    --build-environment "$environment" --package-format family-v2
    --input-dir "$root/payload/package"
    --package-measurement "$root/payload/evidence/measurement.json"
    --package-measurement-sha256 "$signed_measurement"
    --executor-contract-sha256 "$executor_sha" --executor-binary-sha256 "$executor_binary_sha")
for prefix in ${forbidden[@]+"${forbidden[@]}"}; do context+=(--forbidden-prefix "$prefix"); done
"$aros" toolchain producer verify-package "${context[@]}" --format json > "$root/native-verification.json"
# Refuse a runtime that ignored portable readback selectors. Rust supplies the
# validated manifest and finished-package identity; shell does not rebuild it.
jq -se --arg host "$host" --arg preset "$preset" --arg sha "$signed_measurement" \
    --arg build_sha "$build_sha" --arg archive_sha "$archive_sha" --argjson archive_size "$archive_size" '
    length == 1 and (.[0] | type == "object" and
    .schema == "aros-toolchain-producer-stage-v1" and .operation == "verify-package" and
    .manifest.schema == 2 and .manifest.host == $host and .manifest.target_profile == $preset and
    .finished_candidate.schema == "aros-toolchain-portable-package-readback-v2" and
    .finished_candidate.assurance == "portable-byte-readback-only" and
    .finished_candidate.measurement_sha256 == $sha and
    .finished_candidate.build_result_sha256 == $build_sha and
    .sha256 == $archive_sha and .size == $archive_size and
    .finished_candidate.package_tree_sha256 == .manifest.tree_sha256)
    ' "$root/native-verification.json" >/dev/null || fail 'native portable verification result differs'
# Retained transport re-read is byte verification only. The authentication
# above remains mandatory, and no replacement upload or re-signing occurs.
python3 -B "$script_dir/native-lane-transport.py" --retained-dir "$root/transport" \
    --verify-output-dir "$root/payload" > "$root/transport-readback.json"
cmp "$root/transport-result.json" "$root/transport-readback.json" >/dev/null || fail 'transport changed during native verification'
check_inputs
jq -n --arg group "$group" --arg host "$host" --arg preset "$preset" --arg copy "$copy" \
    --arg release_id "$release_id" --arg runtime "$runtime_sha" --arg recipe "$recipe_sha" \
    --arg executor "$executor_sha" --arg binary "$executor_binary_sha" \
    --arg selection "$selection_sha" --slurpfile transport "$root/transport-result.json" \
    --slurpfile native "$root/native-verification.json" '{
    schema:"aros-toolchain-native-lane-admission-v2",
    assurance:"authenticated-transport-and-native-byte-readback-only",
    group:$group,host:$host,target_profile:$preset,copy:$copy,release_id:$release_id,
    reader_runtime_sha256:$runtime,recipe_file_sha256:$recipe,
    executor_contract_sha256:$executor,executor_binary_sha256:$binary,
    source_selection_sha256:$selection,transport:$transport[0],native:$native[0]
    }' > "$root/admission.json"
printf 'Authenticated original transport and native package bytes; release qualification remains separate.\n'
