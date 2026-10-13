#!/usr/bin/env bash
# Collect authenticated original compiler-owner observations as metadata only.
# This adapter does not independently execute or qualify compiler builds.
set -euo pipefail
set -C
umask 077

fail() { printf 'Compiler owner collection: %s\n' "$*" >&2; exit 1; }
digest() { shasum -a 256 "$1" | awk '{print $1}'; }

aros='' aros_sha='' inputs='' inputs_sha='' producer_commit='' tools_commit=''
source_context='' source_context_sha='' source_workflow='' source_ref=''
workflow='' job_name='' release_id='' root='' same_attempt=false seen='|'
forbidden=()
forbidden_seen='|'
while (( $# )); do
    key=$1
    if [[ "$key" == --same-attempt ]]; then
        [[ "$same_attempt" == false ]] || fail 'duplicate same-attempt selector'
        same_attempt=true
        shift
        continue
    fi
    (( $# >= 2 )) || fail "missing value for $key"
    value=$2
    [[ -n "$value" && "$value" != *$'\n'* && "$value" != *$'\r'* ]] || fail "invalid value for $key"
    [[ "$key" =~ ^--[a-z0-9-]+$ ]] || fail "invalid option $key"
    if [[ "$key" == --forbidden-prefix ]]; then
        [[ "$forbidden_seen" != *"|$value|"* ]] || fail 'duplicate forbidden prefix'
        forbidden_seen+="$value|"
        forbidden+=("$value")
        shift 2
        continue
    fi
    [[ "$seen" != *"|$key|"* ]] || fail "duplicate option $key"
    seen+="$key|"
    case "$key" in
        --aros) aros=$value;; --aros-sha256) aros_sha=$value;;
        --inputs-dir) inputs=$value;; --inputs-sha256) inputs_sha=$value;;
        --producer-commit) producer_commit=$value;; --tools-commit) tools_commit=$value;;
        --source-context) source_context=$value;; --source-context-sha256) source_context_sha=$value;;
        --source-workflow) source_workflow=$value;; --source-ref) source_ref=$value;;
        --workflow) workflow=$value;; --job-name) job_name=$value;;
        --release-id) release_id=$value;; --root) root=$value;;
        *) fail "unknown option $key";;
    esac
    shift 2
done

for name in aros aros_sha inputs inputs_sha producer_commit tools_commit source_context \
            source_context_sha source_workflow source_ref workflow job_name release_id root; do
    [[ -n "${!name}" ]] || fail "missing required selector $name"
done
[[ ${#forbidden[@]} -gt 0 ]] || fail 'at least one forbidden build prefix is required'
for prefix in "${forbidden[@]}"; do
    [[ "$prefix" == /* ]] || fail 'forbidden build prefixes must be absolute'
done

script_dir=$(cd "$(dirname "$0")" && pwd -P)
[[ "$aros_sha" =~ ^[0-9a-f]{64}$ && "$inputs_sha" =~ ^[0-9a-f]{64}$ &&
   "$source_context_sha" =~ ^[0-9a-f]{64}$ &&
   "$producer_commit" =~ ^[0-9a-f]{40}$ && "$tools_commit" =~ ^[0-9a-f]{40}$ ]] || \
    fail 'a selected digest or commit is not canonical lowercase hexadecimal'
for selected_workflow in "$workflow" "$source_workflow"; do
    [[ "$selected_workflow" =~ ^\.github/workflows/[A-Za-z0-9_-]+\.yml$ ]] || fail 'workflow selector is invalid'
done
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
[[ "$release_id" =~ ^[a-z0-9][a-z0-9._-]*$ ]] || fail 'release identifier is invalid'
python3 - "$job_name" <<'PY' || fail 'current job name is invalid'
import sys
raw = sys.argv[1].encode("utf-8")
if not 0 < len(raw) <= 256 or any(byte < 0x20 or byte == 0x7f for byte in raw):
    raise SystemExit(1)
PY

[[ "$aros" == /* && -f "$aros" && ! -L "$aros" && -x "$aros" ]] || \
    fail 'runtime must be an absolute regular executable file'
aros_parent=${aros%/*}; aros_name=${aros##*/}
[[ -n "$aros_parent" && -n "$aros_name" && "$aros" == "$(cd "$aros_parent" && pwd -P)/$aros_name" ]] || \
    fail 'runtime path is not canonical'
[[ "$(digest "$aros")" == "$aros_sha" ]] || fail 'runtime bytes differ from the selected digest'

[[ "$inputs" == /* && -d "$inputs" && ! -L "$inputs" && "$inputs" == "$(cd "$inputs" && pwd -P)" ]] || \
    fail 'inputs directory must be canonical and nonlinked'
collection="$inputs/toolchain-release-inputs-v2.json"
[[ -f "$collection" && ! -L "$collection" ]] || fail 'release-input collection must be a regular nonlinked file'
collection_size=$(wc -c < "$collection" | tr -d '[:space:]')
[[ "$collection_size" =~ ^[0-9]{1,8}$ ]] || fail 'release-input collection size is invalid'
if (( 10#$collection_size > 1048576 )); then fail 'release-input collection exceeds its metadata bound'; fi
[[ "$(digest "$collection")" == "$inputs_sha" ]] || fail 'release-input collection bytes differ from the selected digest'

[[ "$source_context" == /* && -f "$source_context" && ! -L "$source_context" ]] || \
    fail 'source context must be an absolute regular nonlinked file'
context_parent=${source_context%/*}; context_name=${source_context##*/}
[[ -n "$context_parent" && -n "$context_name" &&
   "$source_context" == "$(cd "$context_parent" && pwd -P)/$context_name" ]] || \
    fail 'source context path is not canonical'
context_producer=$(python3 -B - "$script_dir/artifact-origin.py" "$source_context" \
    "$source_context_sha" "$source_workflow" "$source_ref" "$producer_commit" <<'PY' || \
    fail 'source context is not bounded canonical metadata or differs from its selectors'
import importlib.util
import sys
from pathlib import Path

helper_path, context_path = Path(sys.argv[1]), Path(sys.argv[2])
expected_sha, workflow, ref, producer = sys.argv[3:]
spec = importlib.util.spec_from_file_location("compiler_owner_collection_origin", helper_path)
if spec is None or spec.loader is None:
    raise SystemExit(1)
origin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(origin)
measurement, raw = origin.normalized_file(context_path, origin.MAX_METADATA)
origin.require(raw is not None and measurement["sha256"] == expected_sha,
               "source context digest differs")
context = origin.validate_context(origin.parse_json(raw))
origin.require(origin.canonical(context) == raw, "source context is not canonical")
origin.require(context["producer_commit"] == producer and context["workflow"] == workflow
               and context["source_ref"] == ref,
               "source context selectors differ")
print(context["producer_commit"])
PY
)

[[ "$root" == /* && ! -e "$root" && ! -L "$root" ]] || fail 'operation root must be fresh and absolute'
root_parent=${root%/*}; root_name=${root##*/}
[[ -n "$root_parent" && -n "$root_name" && "$root_name" != . && "$root_name" != .. &&
   -d "$root_parent" && ! -L "$root_parent" && "$root" == "$(cd "$root_parent" && pwd -P)/$root_name" ]] || \
    fail 'operation root must have a canonical existing parent'
for selected_path in "$inputs" "$source_context" "$aros"; do
    [[ "$root" != "$selected_path" && "$root" != "$selected_path/"* && "$selected_path" != "$root/"* ]] || \
        fail 'operation root overlaps a selected input'
done

check_bound_inputs() {
    [[ -f "$aros" && ! -L "$aros" && -x "$aros" &&
       "$aros" == "$(cd "$aros_parent" && pwd -P)/$aros_name" &&
       "$(digest "$aros")" == "$aros_sha" ]] || fail 'runtime changed during collection'
    collection_size=$(wc -c < "$collection" | tr -d '[:space:]')
    [[ "$collection_size" =~ ^[0-9]{1,8}$ ]] || fail 'release-input collection size is invalid'
    if (( 10#$collection_size > 1048576 )); then fail 'release-input collection changed during collection'; fi
    [[ -d "$inputs" && ! -L "$inputs" && "$inputs" == "$(cd "$inputs" && pwd -P)" &&
       -f "$collection" && ! -L "$collection" && "$(digest "$collection")" == "$inputs_sha" ]] || \
        fail 'release-input collection changed during collection'
    context_size=$(wc -c < "$source_context" | tr -d '[:space:]')
    [[ "$context_size" =~ ^[0-9]{1,8}$ ]] || fail 'source context size is invalid'
    if (( 10#$context_size > 16777216 )); then fail 'source context changed during collection'; fi
    [[ -f "$source_context" && ! -L "$source_context" &&
       "$source_context" == "$(cd "$context_parent" && pwd -P)/$context_name" &&
       "$(digest "$source_context")" == "$source_context_sha" ]] || \
        fail 'source context changed during collection'
}
check_bound_inputs

scratch=''
cleanup_scratch() {
    status=$?
    trap - EXIT HUP INT TERM
    if [[ -n "$scratch" && -d "$scratch" && ! -L "$scratch" ]]; then
        cleanup_error=0
        command rm -f -- "$scratch/plan.json" "$scratch/matrix.json" \
            "$scratch/fragment.tmp.json" "$scratch/embedded-transport.json" \
            "$scratch/result-transport.json" "$scratch/reverify-transport.json" || cleanup_error=$?
        rmdir "$scratch" || { cleanup_status=$?; (( cleanup_error != 0 )) || cleanup_error=$cleanup_status; }
        if (( status == 0 && cleanup_error != 0 )); then status=$cleanup_error; fi
    fi
    exit "$status"
}
trap cleanup_scratch EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
scratch=$(mktemp -d "$root_parent/.compiler-owner-collection-v2.XXXXXXXX") || \
    fail 'cannot create bounded metadata workspace'

# Native release-plan validation is the first producer operation.
"$aros" toolchain producer release-plan --directory "$inputs" \
    --inputs-sha256 "$inputs_sha" --format json > "$scratch/plan.json" || fail 'native release-plan failed'
[[ -f "$scratch/plan.json" && ! -L "$scratch/plan.json" ]] || fail 'native release plan output is not a regular file'
plan_size=$(wc -c < "$scratch/plan.json" | tr -d '[:space:]')
[[ "$plan_size" =~ ^[0-9]{1,8}$ ]] || fail 'native release plan size is invalid'
if (( 10#$plan_size > 16777216 )); then fail 'native release plan exceeds its metadata bound'; fi
plan_sha=$(digest "$scratch/plan.json")
python3 -B "$script_dir/compiler-owner-matrix-v2.py" \
    --plan "$scratch/plan.json" --plan-sha256 "$plan_sha" \
    --inputs-dir "$inputs" --inputs-sha256 "$inputs_sha" \
    --producer-commit "$producer_commit" --tools-commit "$tools_commit" \
    --source-context "$source_context" --source-context-sha256 "$source_context_sha" \
    --source-workflow "$source_workflow" --source-ref "$source_ref" \
    > "$scratch/matrix.json" || fail 'native compiler-owner matrix derivation failed'
[[ -f "$scratch/matrix.json" && ! -L "$scratch/matrix.json" ]] || fail 'compiler-owner matrix output is not a regular file'
matrix_size=$(wc -c < "$scratch/matrix.json" | tr -d '[:space:]')
[[ "$matrix_size" =~ ^[0-9]{1,8}$ ]] || fail 'compiler-owner matrix size is invalid'
if (( 10#$matrix_size > 16777216 )); then fail 'compiler-owner matrix exceeds its metadata bound'; fi
python3 -c 'import json,sys; load=lambda pairs: dict(pairs) if len(dict(pairs))==len(pairs) else (_ for _ in ()).throw(ValueError("duplicate JSON field")); json.load(open(sys.argv[1],encoding="utf-8"),object_pairs_hook=load)' "$scratch/matrix.json" || \
    fail 'compiler-owner matrix JSON is invalid or contains duplicate fields'

jq -e --arg plan "$plan_sha" --arg inputs "$inputs_sha" --arg context "$source_context_sha" \
    --arg producer "$producer_commit" --arg tools "$tools_commit" '
    def safe_ref:
      type == "object" and (keys == ["file","sha256"]) and
      (.file | type == "string" and test("^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$") and
       (split("/") | all(.[]; . != "" and . != "." and . != ".."))) and
      (.sha256 | type == "string" and test("^[0-9a-f]{64}$"));
    type == "object" and
    (keys == ["assurance","expected_compiler_lanes","inputs_sha256","owners","plan_sha256",
              "producer_commit","schema","source_context_sha256","tools_commit"]) and
    .schema == "aros-compiler-owner-matrix-v2" and .assurance == "owner-selection-only" and
    .plan_sha256 == $plan and .inputs_sha256 == $inputs and .source_context_sha256 == $context and
    .producer_commit == $producer and .tools_commit == $tools and
    (.owners | type == "array" and length > 0 and length <= 256) and
    all(.owners[];
      type == "object" and
      (keys == ["copy","group_id","host","job_name","owner_id","payload_name","profile",
                "profiles","proof_name","recipe","source_lock"]) and
      (.owner_id | type == "string" and test("^[0-9a-f]{64}$")) and
      (.group_id | type == "string" and test("^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$")) and
      (.host == "linux-x86_64" or .host == "linux-aarch64" or .host == "macos-aarch64") and
      (.profile | type == "string" and test("^[A-Za-z0-9._-]{1,128}$") and . != "." and . != "..") and
      (.copy == "a" or .copy == "b") and
      .job_name == ("Native compiler (" + .group_id + ", " + .host + ", " + .profile + ", " + .copy + ")") and
      (.job_name | type == "string" and length <= 256 and (explode | all(.[]; . >= 32 and . != 127))) and
      (.payload_name | type == "string" and test("^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")) and
      (.proof_name | type == "string" and test("^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")) and
      .payload_name != .proof_name and
      (.recipe | safe_ref) and (.source_lock | safe_ref) and (.profiles | safe_ref)) and
    ([.owners[].owner_id] | unique | length) == (.owners | length) and
    ([.owners[].job_name] | unique | length) == (.owners | length) and
    ([.owners[].payload_name,.owners[].proof_name] | unique | length) == (2 * (.owners | length)) and
    ([.owners[].host] | unique | sort) == ["linux-aarch64","linux-x86_64","macos-aarch64"] and
    ([.expected_compiler_lanes[]? | .group_id] | length) > 0 and
    (.expected_compiler_lanes | type == "array" and length > 0 and length <= 128 and
     all(.[];
       type == "object" and (keys == ["group_id","host","target_profile"]) and
       (.group_id | type == "string" and test("^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$")) and
       (.target_profile | type == "string" and test("^[A-Za-z0-9._-]{1,128}$") and . != "." and . != "..") and
       (.host == "linux-x86_64" or .host == "linux-aarch64" or .host == "macos-aarch64")) and
     ([.[] | [.group_id,.host,.target_profile]] | unique | length) == length and
     ([.[] | [.group_id,.host,.target_profile]] == ([.[] | [.group_id,.host,.target_profile]] | sort))) and
    ([.owners[] | {group_id:.group_id,host:.host,target_profile:.profile}] |
      unique | sort_by(.group_id,.host,.target_profile)) ==
      (.expected_compiler_lanes | sort_by(.group_id,.host,.target_profile)) and
    (.owners | length) == (2 * (.expected_compiler_lanes | length)) and
    ([.owners[] | {key:[.group_id,.host,.profile],copy:.copy}] | group_by(.key) |
      all(.[]; ([.[].copy] | sort) == ["a","b"])) and
    ([.owners[] | {group_id:.group_id,recipe:.recipe,source_lock:.source_lock,profiles:.profiles}] |
      group_by(.group_id) | all(.[];
        ([.[].recipe] | unique | length) == 1 and
        ([.[].source_lock] | unique | length) == 1 and
        ([.[].profiles] | unique | length) == 1))
    ' "$scratch/matrix.json" >/dev/null || fail 'compiler-owner matrix is not a complete closed selection'

matrix_sha=$(digest "$scratch/matrix.json")
mkdir "$root"
mkdir "$root/owners"
command cp -p "$scratch/matrix.json" "$root/matrix.json" || fail 'cannot retain validated compiler-owner matrix'
[[ "$(digest "$root/matrix.json")" == "$matrix_sha" ]] || fail 'retained compiler-owner matrix bytes changed'

owners_jsonl=$(jq -ce '.owners[]' "$root/matrix.json") || fail 'cannot enumerate validated compiler-owner matrix'
owner_ids=()
selections=()
selection_shas=()
observations=()
observation_shas=()
transport_results=()
transport_shas=()
job_ids=()
reference_paths=()
reference_shas=()
seen_job_ids='|'

input_reference() {
    reference=$1
    label=$2
    reference_file=$(jq -er '.file' <<< "$reference") || fail "$label reference path is missing"
    reference_sha=$(jq -er '.sha256' <<< "$reference") || fail "$label reference digest is missing"
    [[ "$reference_file" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$ &&
       "$reference_file" != *//* && "$reference_file" != */ ]] || fail "$label reference path is invalid"
    IFS='/' read -r -a reference_parts <<< "$reference_file"
    for reference_part in "${reference_parts[@]}"; do
        [[ -n "$reference_part" && "$reference_part" != . && "$reference_part" != .. ]] || \
            fail "$label reference path is not normalized"
    done
    [[ "$reference_sha" =~ ^[0-9a-f]{64}$ ]] || fail "$label reference digest is invalid"
    reference_path="$inputs/$reference_file"
    reference_parent=${reference_path%/*}
    [[ -f "$reference_path" && ! -L "$reference_path" &&
       "$reference_parent" == "$(cd "$reference_parent" && pwd -P)" &&
       "$reference_path" == "$reference_parent/${reference_path##*/}" &&
       "$(digest "$reference_path")" == "$reference_sha" ]] || fail "$label reference bytes differ from the plan"
}

while IFS= read -r owner; do
    [[ -n "$owner" ]] || fail 'compiler-owner matrix contains an empty row'
    owner_id=$(jq -er '.owner_id' <<< "$owner")
    group=$(jq -er '.group_id' <<< "$owner")
    host=$(jq -er '.host' <<< "$owner")
    profile=$(jq -er '.profile' <<< "$owner")
    copy=$(jq -er '.copy' <<< "$owner")
    selected_job=$(jq -er '.job_name' <<< "$owner")
    payload_name=$(jq -er '.payload_name' <<< "$owner")
    proof_name=$(jq -er '.proof_name' <<< "$owner")
    input_reference "$(jq -ce '.recipe' <<< "$owner")" recipe
    recipe_path=$reference_path; recipe_sha=$reference_sha
    input_reference "$(jq -ce '.source_lock' <<< "$owner")" source-lock
    source_lock_path=$reference_path; source_lock_sha=$reference_sha
    input_reference "$(jq -ce '.profiles' <<< "$owner")" profiles
    profiles_path=$reference_path; profiles_sha=$reference_sha
    reference_paths+=("$recipe_path" "$source_lock_path" "$profiles_path")
    reference_shas+=("$recipe_sha" "$source_lock_sha" "$profiles_sha")

    owner_dir="$root/owners/$owner_id"
    mkdir "$owner_dir"
    selection="$owner_dir/selection.json"
    python3 -B "$script_dir/select-owner-artifacts-v2.py" \
        --source-context "$source_context" --source-context-sha256 "$source_context_sha" \
        --job-name "$selected_job" --payload-name "$payload_name" --proof-name "$proof_name" \
        --role build --group "$group" --host "$host" --profile "$profile" --copy "$copy" \
        > "$selection" || fail "original compiler artifact selection failed for $owner_id"
    [[ -f "$selection" && ! -L "$selection" ]] || fail "compiler artifact selection is not a regular file for $owner_id"
    selection_size=$(wc -c < "$selection" | tr -d '[:space:]')
    [[ "$selection_size" =~ ^[0-9]{1,8}$ ]] || fail "compiler selection size is invalid for $owner_id"
    if (( 10#$selection_size > 16777216 )); then fail "compiler selection exceeds its metadata bound for $owner_id"; fi
    selection_sha=$(digest "$selection")
    jq -e --arg workflow "$source_workflow" --arg ref "$source_ref" \
        --arg producer "$context_producer" --arg group "$group" --arg host "$host" \
        --arg profile "$profile" --arg copy "$copy" --arg job "$selected_job" \
        --arg payload "$payload_name" --arg proof "$proof_name" '
        .schema == "aros-toolchain-artifact-selection-v1" and
        .context.workflow == $workflow and .context.source_ref == $ref and
        .context.producer_commit == $producer and
        .selection == {role:"build",group:$group,host:$host,profile:$profile,copy:$copy} and
        .job.name == $job and (.job.id | type == "number" and floor == . and . > 0 and . <= 9007199254740991) and
        .artifact.name == $payload and .proof.name == $proof
        ' "$selection" >/dev/null || fail "compiler selector differs from its matrix row or source context for $owner_id"
    selected_job_id=$(jq -er '.job.id' "$selection") || fail "compiler job ID is missing for $owner_id"
    [[ "$seen_job_ids" != *"|$selected_job_id|"* ]] || fail 'original compiler owner job IDs are not unique'
    seen_job_ids+="$selected_job_id|"

    readback_root="$owner_dir/readback"
    reader_args=(--aros "$aros" --aros-sha256 "$aros_sha"
        --recipe "$recipe_path" --recipe-file-sha256 "$recipe_sha"
        --source-lock "$source_lock_path" --source-lock-sha256 "$source_lock_sha"
        --profiles "$profiles_path" --profiles-sha256 "$profiles_sha"
        --source-selection "$selection" --source-selection-sha256 "$selection_sha"
        --workflow "$workflow" --job-name "$job_name"
        --source-workflow "$source_workflow" --source-ref "$source_ref"
        --group "$group" --preset "$profile" --host "$host" --copy "$copy"
        --release-id "$release_id" --root "$readback_root")
    for prefix in "${forbidden[@]}"; do reader_args+=(--forbidden-prefix "$prefix"); done
    if [[ "$same_attempt" == true ]]; then reader_args+=(--same-attempt); fi
    bash "$script_dir/read-native-owner-v2.sh" "${reader_args[@]}" || \
        fail "authenticated native owner readback failed for $owner_id"

    observation="$readback_root/observation.json"
    transport_result="$readback_root/transport-result.json"
    [[ -f "$observation" && ! -L "$observation" && -f "$transport_result" && ! -L "$transport_result" ]] || \
        fail "native owner observation or transport is missing for $owner_id"
    observation_size=$(wc -c < "$observation" | tr -d '[:space:]')
    transport_size=$(wc -c < "$transport_result" | tr -d '[:space:]')
    [[ "$observation_size" =~ ^[0-9]{1,8}$ && "$transport_size" =~ ^[0-9]{1,8}$ ]] || \
        fail "native owner metadata size is invalid for $owner_id"
    if (( 10#$observation_size > 16777216 || 10#$transport_size > 16777216 )); then
        fail "native owner metadata exceeds its bound for $owner_id"
    fi
    payload="$readback_root/payload"
    package_dir="$payload/package"
    measurement="$payload/evidence/measurement.json"
    environment="$payload/evidence/environment.json"
    [[ -d "$package_dir" && ! -L "$package_dir" &&
       -f "$measurement" && ! -L "$measurement" && -f "$environment" && ! -L "$environment" ]] || \
        fail "native owner package or evidence paths are missing for $owner_id"
    environment_sha=$(digest "$environment")
    jq -e --arg workflow "$workflow" --arg job "$job_name" --arg source_workflow "$source_workflow" \
        --arg ref "$source_ref" --arg group "$group" --arg host "$host" --arg profile "$profile" \
        --arg copy "$copy" --arg release "$release_id" --arg runtime "$aros_sha" \
        --arg recipe_sha "$recipe_sha" --arg source_lock_sha "$source_lock_sha" \
        --arg profiles_sha "$profiles_sha" --arg selection_sha "$selection_sha" \
        --arg environment_sha256 "$environment_sha" \
        --arg payload "$payload" --slurpfile transport "$transport_result" '
        .schema == "aros-toolchain-original-owner-observation-v2" and
        .assurance == "authenticated-original-job-and-native-byte-readback-only" and
        .scope.original_owner_job_observation == true and .scope.native_package_byte_readback == true and
        .scope.independently_executed_collector == false and .scope.release_admission == false and
        .scope.publication == false and
        .current_workflow == $workflow and .current_job_name == $job and
        .source_workflow == $source_workflow and .source_ref == $ref and
        .group == $group and .host == $host and .target_profile == $profile and .copy == $copy and
        .release_id == $release and .reader_runtime_sha256 == $runtime and
        .recipe_file_sha256 == $recipe_sha and .source_lock_sha256 == $source_lock_sha and
        .profiles_sha256 == $profiles_sha and
        (.source_selection_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
        .source_selection_sha256 == $selection_sha and
        (.measurement_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
        (.environment_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
        .environment_sha256 == $environment_sha256 and
        .executor_contract_id == "aros-toolchain-producer-v1" and
        (.executor_contract_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
        (.executor_binary_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
        .transport == $transport[0] and
        .original_identity.host == $host and
        .original_identity.target_profile == $profile
        ' "$observation" >/dev/null || \
        fail "native owner observation differs from selected original job or caller for $owner_id"
    [[ "$(jq -er '.measurement_sha256' "$observation")" == "$(digest "$measurement")" ]] || \
        fail "authenticated compiler measurement bytes changed for $owner_id"
    jq -e --arg schema "aros-toolchain-native-lane-transport-v2" '
        type == "object" and .schema == $schema and .assurance == "transport-byte-readback-only" and
        (.files | type == "object" and length > 0)
        ' "$transport_result" >/dev/null || fail "native compiler transport metadata is invalid for $owner_id"
    check_bound_inputs
    for ref_index in 0 1 2; do
        path_index=$(( (${#reference_paths[@]} - 3) + ref_index ))
        [[ "$(digest "${reference_paths[$path_index]}")" == "${reference_shas[$path_index]}" ]] || \
            fail "plan-bound compiler reference changed during readback for $owner_id"
    done
    owner_ids+=("$owner_id")
    selections+=("$selection")
    selection_shas+=("$selection_sha")
    observations+=("$observation")
    observation_shas+=("$(digest "$observation")")
    transport_results+=("$transport_result")
    transport_shas+=("$(digest "$transport_result")")
    job_ids+=("$selected_job_id")
done <<< "$owners_jsonl"

owner_count=${#owner_ids[@]}
(( owner_count > 0 && owner_count == ${#selections[@]} && owner_count == ${#selection_shas[@]} &&
   owner_count == ${#observations[@]} && owner_count == ${#observation_shas[@]} &&
   owner_count == ${#transport_results[@]} && owner_count == ${#transport_shas[@]} &&
   owner_count == ${#job_ids[@]} )) || fail 'not every original compiler owner completed selection and readback'

for index in "${!owner_ids[@]}"; do
    owner_id=${owner_ids[$index]}
    owner=$(jq -ce --arg id "$owner_id" '.owners[] | select(.owner_id == $id)' "$root/matrix.json") || \
        fail "validated compiler owner disappeared from the retained matrix: $owner_id"
    readback_root="$root/owners/$owner_id/readback"
    reverify="$readback_root/transport-reverification.json"
    python3 -B "$script_dir/native-lane-transport.py" \
        --retained-dir "$readback_root/transport" --verify-output-dir "$readback_root/payload" \
        > "$reverify" || fail "native compiler transport remeasurement failed for $owner_id"
    cmp "${transport_results[$index]}" "$reverify" >/dev/null || \
        fail "native compiler transport changed during remeasurement for $owner_id"
    jq -cS '.transport' "${observations[$index]}" >| "$scratch/embedded-transport.json" || \
        fail "cannot project embedded native compiler transport for $owner_id"
    jq -cS . "${transport_results[$index]}" >| "$scratch/result-transport.json" || \
        fail "cannot normalize native compiler transport for $owner_id"
    jq -cS . "$reverify" >| "$scratch/reverify-transport.json" || \
        fail "cannot normalize remeasured compiler transport for $owner_id"
    if ! cmp "$scratch/embedded-transport.json" "$scratch/result-transport.json" >/dev/null ||
       ! cmp "$scratch/result-transport.json" "$scratch/reverify-transport.json" >/dev/null; then
        fail "native compiler transport does not join its observation and remeasurement for $owner_id"
    fi
done

# Rebind all prior owner data only after all later reads and transport checks.
for index in "${!owner_ids[@]}"; do
    owner_id=${owner_ids[$index]}
    [[ -f "${selections[$index]}" && ! -L "${selections[$index]}" &&
       "$(digest "${selections[$index]}")" == "${selection_shas[$index]}" ]] || \
        fail "original owner selection changed before fragment generation for $owner_id"
    [[ -f "${observations[$index]}" && ! -L "${observations[$index]}" &&
       "$(digest "${observations[$index]}")" == "${observation_shas[$index]}" ]] || \
        fail "original owner observation changed before fragment generation for $owner_id"
    [[ -f "${transport_results[$index]}" && ! -L "${transport_results[$index]}" &&
       "$(digest "${transport_results[$index]}")" == "${transport_shas[$index]}" ]] || \
        fail "original owner transport result changed before fragment generation for $owner_id"
done
[[ -f "$root/matrix.json" && ! -L "$root/matrix.json" && "$(digest "$root/matrix.json")" == "$matrix_sha" ]] || \
    fail 'retained compiler-owner matrix bytes changed before fragment generation'
check_bound_inputs
for index in "${!reference_paths[@]}"; do
    [[ -f "${reference_paths[$index]}" && ! -L "${reference_paths[$index]}" &&
       "$(digest "${reference_paths[$index]}")" == "${reference_shas[$index]}" ]] || \
        fail 'plan-bound compiler reference changed before fragment generation'
done

jq -s -e --slurpfile matrix "$root/matrix.json" --arg runtime "$aros_sha" \
    --arg plan "$plan_sha" --arg inputs "$inputs_sha" --arg context "$source_context_sha" \
    --arg source_producer "$context_producer" --arg source_workflow "$source_workflow" \
    --arg source_ref "$source_ref" --arg producer "$producer_commit" --arg tools "$tools_commit" \
    --arg workflow "$workflow" --arg job "$job_name" --arg release "$release_id" '
    ($matrix[0].owners | length) as $count |
    if (($matrix | length) == 1 and $count == length and
        ([$matrix[0].owners[] | [.group_id,.host,.profile,.copy]] | unique | length) == $count and
        ([range(0; length) as $i | .[$i] as $observation | $matrix[0].owners[$i] as $owner |
          ($observation.current_workflow == $workflow and $observation.current_job_name == $job and
           $observation.source_workflow == $source_workflow and $observation.source_ref == $source_ref and
           $observation.group == $owner.group_id and $observation.host == $owner.host and
           $observation.target_profile == $owner.profile and $observation.copy == $owner.copy and
           $observation.release_id == $release)] | all) and
        ([range(0; length) as $i | .[$i].transport] | length) == $count)
    then {
      schema:"aros-compiler-build-selection-fragment-v2",
      assurance:"authenticated-original-owner-selection-only",
      runtime_sha256:$runtime,plan_sha256:$plan,inputs_sha256:$inputs,
      source_context_sha256:$context,source_producer_commit:$source_producer,
      source_workflow:$source_workflow,source_ref:$source_ref,
      producer_commit:$producer,tools_commit:$tools,
      workflow:$workflow,job_name:$job,release_id:$release,
      owner_count:$count,expected_compiler_lanes:$matrix[0].expected_compiler_lanes,
      compiler_builds:[range(0; length) as $i | .[$i] as $observation | $matrix[0].owners[$i] as $owner | {
        group_id:$owner.group_id,host:$owner.host,target_profile:$owner.profile,copy:$owner.copy,
        package_dir:($root + "/owners/" + $owner.owner_id + "/readback/payload/package"),
        measurement:{path:($root + "/owners/" + $owner.owner_id + "/readback/payload/evidence/measurement.json"),
                    sha256:$observation.measurement_sha256},
        executor:{contract_sha256:$observation.executor_contract_sha256,
                  binary_sha256:$observation.executor_binary_sha256},
        environment:{path:($root + "/owners/" + $owner.owner_id + "/readback/payload/evidence/environment.json"),
                     sha256:$observation.environment_sha256},
        observation:{path:($root + "/owners/" + $owner.owner_id + "/readback/observation.json"),
                     sha256:$observation_sha256[$i]}}
      ] | sort_by(.group_id,.host,.target_profile,.copy),
      release_admission:false,publication:false
    }
    else error("original compiler observations do not rejoin the exact matrix") end
    ' --arg root "$root" --argjson observation_sha256 "$(printf '%s\n' "${observation_shas[@]}" | jq -Rsc 'split("\n")[:-1]')" \
    "${observations[@]}" > "$scratch/fragment.tmp.json" || {
        command rm -f -- "$scratch/fragment.tmp.json"
        fail 'compiler owner observations do not rejoin the exact complete lane matrix'
    }
[[ -f "$scratch/fragment.tmp.json" && ! -L "$scratch/fragment.tmp.json" ]] || \
    fail 'temporary compiler fragment is not a regular file'
fragment_size=$(wc -c < "$scratch/fragment.tmp.json" | tr -d '[:space:]')
[[ "$fragment_size" =~ ^[0-9]{1,8}$ ]] || fail 'temporary compiler fragment size is invalid'
if (( 10#$fragment_size > 16777216 )); then fail 'temporary compiler fragment exceeds its metadata bound'; fi
jq -e '
    .owner_count as $count |
    type == "object" and
    (keys == ["assurance","compiler_builds","expected_compiler_lanes","inputs_sha256","job_name",
              "owner_count","plan_sha256","producer_commit","publication","release_admission",
              "release_id","runtime_sha256","schema","source_context_sha256",
              "source_producer_commit","source_ref","source_workflow","tools_commit","workflow"]) and
    .schema == "aros-compiler-build-selection-fragment-v2" and
    .assurance == "authenticated-original-owner-selection-only" and
    .release_admission == false and .publication == false and
    (.compiler_builds | type == "array" and length == $count and
      all(.[ ];
        (keys == ["copy","environment","executor","group_id","host","measurement","observation",
                  "package_dir","target_profile"]) and
        (.copy == "a" or .copy == "b") and
        (.measurement | type == "object" and keys == ["path","sha256"] and (.sha256 | test("^[0-9a-f]{64}$"))) and
        (.environment | type == "object" and keys == ["path","sha256"] and (.sha256 | test("^[0-9a-f]{64}$"))) and
        (.executor | type == "object" and keys == ["binary_sha256","contract_sha256"] and
          (.binary_sha256 | test("^[0-9a-f]{64}$")) and (.contract_sha256 | test("^[0-9a-f]{64}$"))) and
        (.observation | type == "object" and keys == ["path","sha256"] and (.sha256 | test("^[0-9a-f]{64}$"))))) and
    (.expected_compiler_lanes | type == "array" and length > 0)
    ' "$scratch/fragment.tmp.json" >/dev/null || {
        command rm -f -- "$scratch/fragment.tmp.json"
        fail 'temporary compiler fragment does not have the exact metadata DTO schema'
    }
[[ ! -e "$root/selection-fragment.json" && ! -L "$root/selection-fragment.json" ]] || {
    command rm -f -- "$scratch/fragment.tmp.json"
    fail 'compiler fragment destination is not fresh'
}
command ln "$scratch/fragment.tmp.json" "$root/selection-fragment.json" || {
    command rm -f -- "$scratch/fragment.tmp.json"
    fail 'cannot install compiler fragment without replacing an existing file'
}
command rm -f -- "$scratch/fragment.tmp.json" || {
    command rm -f -- "$root/selection-fragment.json"
    fail 'cannot remove temporary compiler fragment after installation'
}
[[ -f "$root/selection-fragment.json" && ! -L "$root/selection-fragment.json" ]] || \
    fail 'compiler fragment was not emitted as a regular file'
printf 'Authenticated original compiler-owner observations collected; no independent execution, release admission, or publication claim.\n'
