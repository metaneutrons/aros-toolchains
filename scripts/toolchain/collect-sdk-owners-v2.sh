#!/usr/bin/env bash
# Collect complete native SDK-owner transport readbacks as metadata only.
# This adapter does not qualify SDKs or grant release/publication authority.
set -euo pipefail
set -C
umask 077

fail() { printf 'SDK owner collection: %s\n' "$*" >&2; exit 1; }
digest() { shasum -a 256 "$1" | awk '{print $1}'; }
check_bound_inputs() {
    [[ -f "$aros" && ! -L "$aros" && -x "$aros" &&
       "$aros" == "$(cd "${aros%/*}" && pwd -P)/${aros##*/}" &&
       "$(digest "$aros")" == "$aros_sha" ]] || fail 'runtime changed during collection'
    collection_size=$(wc -c < "$collection" | tr -d '[:space:]')
    [[ "$collection_size" =~ ^[0-9]{1,8}$ ]] || fail 'release-input collection size is invalid'
    if (( 10#$collection_size > 1048576 )); then fail 'release-input collection changed during collection'; fi
    [[ -d "$inputs" && ! -L "$inputs" && "$inputs" == "$(cd "$inputs" && pwd -P)" &&
       -f "$collection" && ! -L "$collection" &&
       "$(digest "$collection")" == "$inputs_sha" ]] || fail 'release-input collection changed during collection'
    context_size=$(wc -c < "$source_context" | tr -d '[:space:]')
    [[ "$context_size" =~ ^[0-9]{1,8}$ ]] || fail 'source context size is invalid'
    if (( 10#$context_size > 16777216 )); then fail 'source context changed during collection'; fi
    [[ -f "$source_context" && ! -L "$source_context" &&
       "$source_context" == "$(cd "${source_context%/*}" && pwd -P)/${source_context##*/}" &&
       "$(digest "$source_context")" == "$source_context_sha" ]] || fail 'source context changed during collection'
}

aros='' aros_sha='' inputs='' inputs_sha='' producer_commit='' tools_commit=''
source_context='' source_context_sha='' source_workflow='' source_ref=''
workflow='' job_name='' root='' same_attempt=false seen='|'
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
    [[ "$seen" != *"|$key|"* ]] || fail "duplicate option $key"
    seen+="$key|"
    case "$key" in
        --aros) aros=$value;; --aros-sha256) aros_sha=$value;;
        --inputs-dir) inputs=$value;; --inputs-sha256) inputs_sha=$value;;
        --producer-commit) producer_commit=$value;; --tools-commit) tools_commit=$value;;
        --source-context) source_context=$value;; --source-context-sha256) source_context_sha=$value;;
        --source-workflow) source_workflow=$value;; --source-ref) source_ref=$value;;
        --workflow) workflow=$value;; --job-name) job_name=$value;; --root) root=$value;;
        *) fail "unknown option $key";;
    esac
    shift 2
done
for name in aros aros_sha inputs inputs_sha producer_commit tools_commit source_context \
            source_context_sha source_workflow source_ref workflow job_name root; do
    [[ -n "${!name}" ]] || fail "missing required selector $name"
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
python3 - "$job_name" <<'PY' || fail 'job name is invalid'
import sys
raw = sys.argv[1].encode("utf-8")
if not 0 < len(raw) <= 256 or any(byte < 0x20 or byte == 0x7f for byte in raw):
    raise SystemExit(1)
PY

[[ "$aros" == /* && -f "$aros" && ! -L "$aros" && -x "$aros" ]] || fail 'runtime must be an absolute regular executable file'
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
   "$source_context" == "$(cd "$context_parent" && pwd -P)/$context_name" ]] || fail 'source context path is not canonical'
context_producer=$(python3 -B - "$script_dir/artifact-origin.py" "$source_context" \
    "$source_context_sha" "$source_workflow" "$source_ref" "$producer_commit" <<'PY' || \
    fail 'source context is not bounded canonical metadata or differs from its selectors'
import importlib.util
import sys
from pathlib import Path

helper_path, context_path = Path(sys.argv[1]), Path(sys.argv[2])
expected_sha, workflow, ref, producer = sys.argv[3:]
spec = importlib.util.spec_from_file_location("sdk_owner_collection_origin", helper_path)
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
               and context["source_ref"] == ref, "source context selectors differ")
print(context["producer_commit"])
PY
)

[[ "$root" == /* && ! -e "$root" && ! -L "$root" ]] || fail 'operation root must be absent and absolute'
root_parent=${root%/*}; root_name=${root##*/}
[[ -n "$root_parent" && -n "$root_name" && "$root_name" != . && "$root_name" != .. &&
   -d "$root_parent" && ! -L "$root_parent" && "$root" == "$(cd "$root_parent" && pwd -P)/$root_name" ]] || \
    fail 'operation root must have a canonical existing parent'
for selected_path in "$inputs" "$source_context" "$aros"; do
    [[ "$root" != "$selected_path" && "$root" != "$selected_path/"* && "$selected_path" != "$root/"* ]] || \
        fail 'operation root overlaps a selected input'
done
check_bound_inputs

scratch=''
cleanup_scratch() {
    status=$?
    trap - EXIT HUP INT TERM
    if [[ -n "$scratch" && -d "$scratch" && ! -L "$scratch" ]]; then
        cleanup_error=0
        command rm -f -- "$scratch/plan.json" "$scratch/matrix.json" \
            "$scratch/selection-fragment.tmp.json" "$scratch/embedded-transport.json" \
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
scratch=$(mktemp -d "$root_parent/.sdk-owner-collection-v2.XXXXXXXX") || fail 'cannot create bounded metadata workspace'

# Native plan validation precedes helper projection and all provider-backed calls.
"$aros" toolchain producer release-plan --directory "$inputs" \
    --inputs-sha256 "$inputs_sha" --format json > "$scratch/plan.json" || fail 'native release-plan failed'
[[ -f "$scratch/plan.json" && ! -L "$scratch/plan.json" ]] || fail 'native release-plan output is not a regular file'
plan_size=$(wc -c < "$scratch/plan.json" | tr -d '[:space:]')
[[ "$plan_size" =~ ^[0-9]{1,8}$ ]] || fail 'native release plan size is invalid'
if (( 10#$plan_size > 16777216 )); then fail 'native release plan exceeds its metadata bound'; fi
plan_sha=$(digest "$scratch/plan.json")
python3 -B "$script_dir/sdk-owner-matrix-v2.py" \
    --plan "$scratch/plan.json" --plan-sha256 "$plan_sha" \
    --inputs-dir "$inputs" --inputs-sha256 "$inputs_sha" \
    --producer-commit "$producer_commit" --tools-commit "$tools_commit" \
    --source-context "$source_context" --source-context-sha256 "$source_context_sha" \
    --source-workflow "$source_workflow" --source-ref "$source_ref" \
    > "$scratch/matrix.json" || fail 'native SDK-owner matrix derivation failed'
[[ -f "$scratch/matrix.json" && ! -L "$scratch/matrix.json" ]] || fail 'SDK-owner matrix output is not a regular file'
matrix_size=$(wc -c < "$scratch/matrix.json" | tr -d '[:space:]')
[[ "$matrix_size" =~ ^[0-9]{1,8}$ ]] || fail 'SDK-owner matrix size is invalid'
if (( 10#$matrix_size > 16777216 )); then fail 'SDK-owner matrix exceeds its metadata bound'; fi
python3 -c 'import json,sys; load=lambda pairs: dict(pairs) if len(dict(pairs))==len(pairs) else (_ for _ in ()).throw(ValueError("duplicate JSON field")); json.load(open(sys.argv[1],encoding="utf-8"),object_pairs_hook=load)' "$scratch/matrix.json" || \
    fail 'SDK-owner matrix JSON is invalid or contains duplicate fields'

# Validate the closed owner projection without reimplementing native plan parsing.
jq -e --arg plan "$plan_sha" --arg inputs "$inputs_sha" --arg context "$source_context_sha" \
    --arg producer "$producer_commit" --arg tools "$tools_commit" '
    type == "object" and
    (keys == ["assurance","expected_sdk_generations","inputs_sha256","owners","plan_sha256",
              "producer_commit","schema","source_context_sha256","tools_commit"]) and
    .schema == "aros-sdk-owner-matrix-v2" and .assurance == "owner-selection-only" and
    .plan_sha256 == $plan and .inputs_sha256 == $inputs and .source_context_sha256 == $context and
    .producer_commit == $producer and .tools_commit == $tools and
    (.owners | type == "array" and length > 0 and length <= 256) and
    all(.owners[];
      type == "object" and
      (keys == ["compiler_family","group_id","host","job_name","owner_id","payload_name","profile","proof_name","sdk_ids"]) and
      (.owner_id | type == "string" and test("^[0-9a-f]{64}$")) and
      (.group_id | type == "string" and test("^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")) and
      (.host == "linux-x86_64" or .host == "linux-aarch64" or .host == "macos-aarch64") and
      (.profile | type == "string" and test("^[A-Za-z0-9._-]{1,128}$") and . != "." and . != "..") and
      (.compiler_family == "gnu" or .compiler_family == "llvm") and
      (.sdk_ids | type == "array" and length > 0 and length <= 32 and
       all(.[]; type == "string" and test("^[-._+a-z0-9]{1,96}$") and . != "." and . != "..") and
       . == unique) and
      (.job_name | type == "string" and length > 0 and length <= 256 and (explode | all(.[]; . >= 32 and . != 127))) and
      (.payload_name | type == "string" and test("^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")) and
      (.proof_name | type == "string" and test("^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")) and
      .proof_name != .payload_name) and
    ([.owners[].owner_id] | unique | length) == (.owners | length) and
    ([.owners[].job_name] | unique | length) == (.owners | length) and
    ([.owners[].payload_name,.owners[].proof_name] | unique | length) == (2 * (.owners | length)) and
    ([.owners[].host] | unique | sort) == ["linux-aarch64","linux-x86_64","macos-aarch64"] and
    ([.owners[].compiler_family] | all(.[]; . == "gnu" or . == "llvm")) and
    (.expected_sdk_generations | type == "array" and length > 0 and length <= 6144 and
     all(.[];
       type == "object" and (keys == ["group_id","host","sdk_id","target_profile"]) and
       (.sdk_id | type == "string" and test("^[-._+a-z0-9]{1,96}$") and . != "." and . != "..") and
       (.group_id | type == "string" and test("^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")) and
       (.target_profile | type == "string" and test("^[A-Za-z0-9._-]{1,128}$") and . != "." and . != "..") and
       (.host == "linux-x86_64" or .host == "linux-aarch64" or .host == "macos-aarch64")) and
     ([.[] | [.sdk_id,.group_id,.target_profile,.host]] | unique | length) == length) and
    ([.owners[] as $o | $o.sdk_ids[] as $id |
      {sdk_id:$id,group_id:$o.group_id,target_profile:$o.profile,host:$o.host}] |
      sort_by(.sdk_id,.group_id,.target_profile,.host)) ==
    (.expected_sdk_generations | sort_by(.sdk_id,.group_id,.target_profile,.host))
    ' "$scratch/matrix.json" >/dev/null || fail 'SDK-owner matrix is not a complete closed selection'

matrix_sha=$(digest "$scratch/matrix.json")
mkdir "$root"
mkdir "$root/owners"
command cp -p "$scratch/matrix.json" "$root/matrix.json" || fail 'cannot retain the validated SDK-owner matrix'
[[ "$(digest "$root/matrix.json")" == "$matrix_sha" ]] || fail 'retained SDK-owner matrix bytes changed'

owners_jsonl=$(jq -ce '.owners[]' "$root/matrix.json") || fail 'cannot enumerate the validated owner matrix'
readbacks=()
selections=()
owner_ids=()
selection_shas=()
readback_shas=()
transport_shas=()
while IFS= read -r owner; do
    [[ -n "$owner" ]] || fail 'owner matrix contains an empty row'
    owner_id=$(jq -er '.owner_id' <<< "$owner")
    group=$(jq -er '.group_id' <<< "$owner")
    host=$(jq -er '.host' <<< "$owner")
    profile=$(jq -er '.profile' <<< "$owner")
    compiler_family=$(jq -er '.compiler_family' <<< "$owner")
    sdk_ids=$(jq -cer '.sdk_ids' <<< "$owner")
    selected_job=$(jq -er '.job_name' <<< "$owner")
    payload_name=$(jq -er '.payload_name' <<< "$owner")
    proof_name=$(jq -er '.proof_name' <<< "$owner")
    owner_dir="$root/owners/$owner_id"
    mkdir "$owner_dir"
    selection="$owner_dir/selection.json"
    python3 -B "$script_dir/select-owner-artifacts-v2.py" \
        --source-context "$source_context" --source-context-sha256 "$source_context_sha" \
        --job-name "$selected_job" --payload-name "$payload_name" --proof-name "$proof_name" \
        --role sdk --group "$group" --host "$host" --profile "$profile" --copy none \
        > "$selection" || fail "owner artifact selection failed for $owner_id"
    [[ -f "$selection" && ! -L "$selection" ]] || fail "owner selector output is not a regular file for $owner_id"
    selection_size=$(wc -c < "$selection" | tr -d '[:space:]')
    [[ "$selection_size" =~ ^[0-9]{1,8}$ ]] || fail "owner selection size is invalid for $owner_id"
    if (( 10#$selection_size > 16777216 )); then fail "owner selection exceeds its metadata bound for $owner_id"; fi
    selection_sha=$(digest "$selection")
    jq -e --arg workflow "$source_workflow" --arg ref "$source_ref" \
        --arg producer "$context_producer" --arg group "$group" --arg host "$host" \
        --arg profile "$profile" '
        .schema == "aros-toolchain-artifact-selection-v1" and
        .context.workflow == $workflow and .context.source_ref == $ref and
        .context.producer_commit == $producer and
        .selection == {role:"sdk",group:$group,host:$host,profile:$profile,copy:"none"}
        ' "$selection" >/dev/null || fail "owner selector differs from its independent matrix row for $owner_id"

    readback_root="$owner_dir/readback"
    reader_args=(--source-selection "$selection" --source-selection-sha256 "$selection_sha"
        --source-producer-commit "$context_producer" --source-workflow "$source_workflow"
        --source-ref "$source_ref" --workflow "$workflow" --job-name "$job_name"
        --sdk-ids "$sdk_ids" --group "$group" --preset "$profile" --host "$host"
        --compiler-family "$compiler_family" --owner-role sdk --root "$readback_root")
    if [[ "$same_attempt" == true ]]; then reader_args+=(--same-attempt); fi
    bash "$script_dir/read-sdk-owner-v2.sh" "${reader_args[@]}" || fail "authenticated owner readback failed for $owner_id"
    readback="$readback_root/readback.json"
    [[ -f "$readback" && ! -L "$readback" ]] || fail "owner readback output is missing for $owner_id"
    readback_size=$(wc -c < "$readback" | tr -d '[:space:]')
    [[ "$readback_size" =~ ^[0-9]{1,8}$ ]] || fail "owner readback size is invalid for $owner_id"
    if (( 10#$readback_size > 16777216 )); then fail "owner readback exceeds its metadata bound for $owner_id"; fi
    transport_result="$readback_root/transport-result.json"
    [[ -f "$transport_result" && ! -L "$transport_result" ]] || fail "owner transport result is missing for $owner_id"
    transport_size=$(wc -c < "$transport_result" | tr -d '[:space:]')
    [[ "$transport_size" =~ ^[0-9]{1,8}$ ]] || fail "owner transport result size is invalid for $owner_id"
    if (( 10#$transport_size > 16777216 )); then fail "owner transport result exceeds its metadata bound for $owner_id"; fi
    jq -e --arg workflow "$source_workflow" --arg ref "$source_ref" \
        --arg producer "$context_producer" --arg selection_sha "$selection_sha" \
        --arg group "$group" --arg host "$host" --arg profile "$profile" \
        --arg family "$compiler_family" --argjson ids "$sdk_ids" \
        --arg payload "$readback_root/payload" '
        .schema == "aros-sdk-owner-readback-v2" and
        .assurance == "authenticated-transport-and-sdk-payload-readback-only" and
        .source_workflow == $workflow and .source_ref == $ref and
        .source_producer_commit == $producer and .source_selection_sha256 == $selection_sha and
        .independent_selection == {sdk_ids:$ids,group:$group,profile:$profile,host:$host,
                                   compiler_family:$family,owner_role:"sdk"} and
        .sdk_owner_transport.schema == "aros-sdk-owner-transport-v2" and
        .sdk_owner_transport.assurance == "transport-byte-readback-only" and
        .sdk_owner_transport.owner_role == "sdk" and
        .sdk_owner_transport.selection_sha256 == $selection_sha and
        (.sdk_owner_transport.sdk_generations | type == "array" and length == ($ids | length) and
         (map(.sdk_id) == $ids) and
         all(.[];
           .group_id == $group and .target_profile == $profile and .host == $host and
           .package_dir == ($payload + "/sdk-" + .sdk_id + "/package") and
           .record.path == ($payload + "/sdk-" + .sdk_id + "/generation.json") and
           (.record.sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
           .compatibility.directory == ($payload + "/sdk-" + .sdk_id + "/compatibility") and
           .compatibility.inputs.path == ($payload + "/sdk-" + .sdk_id + "/compatibility-inputs.json") and
           (.compatibility.inputs.sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
           (.compatibility.manifest_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
           .compatibility.native_sdk_required == ($family == "gnu")))
        ' "$readback" >/dev/null || fail "owner readback differs from its matrix row or caller for $owner_id"
    [[ "$(digest "$selection")" == "$selection_sha" ]] || fail "owner selection bytes changed for $owner_id"
    check_bound_inputs
    owner_ids+=("$owner_id")
    selections+=("$selection")
    selection_shas+=("$selection_sha")
    readback_shas+=("$(digest "$readback")")
    transport_shas+=("$(digest "$transport_result")")
    readbacks+=("$readback")
done <<< "$owners_jsonl"
(( ${#readbacks[@]} > 0 && ${#readbacks[@]} == ${#owner_ids[@]} &&
   ${#owner_ids[@]} == ${#selections[@]} && ${#owner_ids[@]} == ${#selection_shas[@]} &&
   ${#owner_ids[@]} == ${#readback_shas[@]} && ${#owner_ids[@]} == ${#transport_shas[@]} )) || \
    fail 'not every matrix owner completed selection and readback'

# Reverify each exact retained transport after all selected readers have passed.
for index in "${!owner_ids[@]}"; do
    owner_id=${owner_ids[$index]}
    owner=$(jq -ce --arg id "$owner_id" '.owners[] | select(.owner_id == $id)' "$root/matrix.json") || \
        fail "validated owner disappeared from the retained matrix: $owner_id"
    group=$(jq -er '.group_id' <<< "$owner")
    host=$(jq -er '.host' <<< "$owner")
    profile=$(jq -er '.profile' <<< "$owner")
    compiler_family=$(jq -er '.compiler_family' <<< "$owner")
    sdk_ids=$(jq -cer '.sdk_ids' <<< "$owner")
    readback_root="$root/owners/$owner_id/readback"
    reverify="$readback_root/transport-reverification.json"
    python3 -B "$script_dir/sdk-owner-transport-v2.py" \
        --retained-dir "$readback_root/transport" --sdk-ids "$sdk_ids" \
        --group "$group" --profile "$profile" --host "$host" \
        --compiler-family "$compiler_family" --owner-role sdk \
        --verify-output-dir "$readback_root/payload" > "$reverify" || \
        fail "SDK transport remeasurement failed for $owner_id"
    cmp "$readback_root/transport-result.json" "$reverify" >/dev/null || \
        fail "SDK transport result changed during final remeasurement for $owner_id"
    [[ "$(digest "$readback_root/transport-result.json")" == "${transport_shas[$index]}" ]] || \
        fail "retained SDK transport result changed for $owner_id"
    jq -cS '.sdk_owner_transport' "${readbacks[$index]}" >| "$scratch/embedded-transport.json" || \
        fail "cannot project embedded SDK transport for $owner_id"
    jq -cS . "$readback_root/transport-result.json" >| "$scratch/result-transport.json" || \
        fail "cannot normalize retained SDK transport for $owner_id"
    jq -cS . "$reverify" >| "$scratch/reverify-transport.json" || \
        fail "cannot normalize remeasured SDK transport for $owner_id"
    if ! cmp "$scratch/embedded-transport.json" "$scratch/result-transport.json" >/dev/null ||
       ! cmp "$scratch/result-transport.json" "$scratch/reverify-transport.json" >/dev/null; then
        fail "SDK transport remeasurement does not exactly join its owner readback for $owner_id"
    fi
done

# Bind every earlier selector and readback again after all later readers and
# transport verifiers have run, not merely when each owner first completed.
for index in "${!owner_ids[@]}"; do
    owner_id=${owner_ids[$index]}
    [[ -f "${selections[$index]}" && ! -L "${selections[$index]}" &&
       "$(digest "${selections[$index]}")" == "${selection_shas[$index]}" ]] || \
        fail "owner selection changed before fragment generation for $owner_id"
    [[ -f "${readbacks[$index]}" && ! -L "${readbacks[$index]}" &&
       "$(digest "${readbacks[$index]}")" == "${readback_shas[$index]}" ]] || \
        fail "owner readback changed before fragment generation for $owner_id"
    readback_root="$root/owners/$owner_id/readback"
    [[ -f "$readback_root/transport-result.json" && ! -L "$readback_root/transport-result.json" &&
       "$(digest "$readback_root/transport-result.json")" == "${transport_shas[$index]}" ]] || \
        fail "owner transport result changed before fragment generation for $owner_id"
done

[[ -f "$root/matrix.json" && ! -L "$root/matrix.json" &&
   "$(digest "$root/matrix.json")" == "$matrix_sha" ]] || fail 'retained SDK-owner matrix bytes changed before fragment generation'
check_bound_inputs
jq -s -e --slurpfile matrix "$root/matrix.json" \
    --arg aros_sha "$aros_sha" --arg plan_sha "$plan_sha" --arg inputs_sha "$inputs_sha" \
    --arg context_sha "$source_context_sha" --arg producer "$producer_commit" \
    --arg tools "$tools_commit" --arg source_producer "$context_producer" \
    --arg source_workflow "$source_workflow" --arg source_ref "$source_ref" \
    --arg root "$root" \
    --argjson transport_sha "$(printf '%s\n' "${transport_shas[@]}" | jq -Rsc 'split("\n")[:-1]')" '
    ($matrix[0].owners | length) as $owner_count |
    ([.[] | .sdk_owner_transport.sdk_generations[]] |
      sort_by(.sdk_id,.group_id,.target_profile,.host)) as $rows |
    ([$rows[] | {sdk_id:.sdk_id,group_id:.group_id,target_profile:.target_profile,host:.host}] |
      sort_by(.sdk_id,.group_id,.target_profile,.host)) as $actual |
    ($matrix[0].expected_sdk_generations | sort_by(.sdk_id,.group_id,.target_profile,.host)) as $expected |
    if (($matrix | length) == 1 and $owner_count == length and
        ([$actual[] | [.sdk_id,.group_id,.target_profile,.host]] | unique | length) == ($actual | length) and
        $actual == $expected)
    then {schema:"aros-sdk-generation-selection-fragment-v2",
     assurance:"authenticated-owner-transport-selection-only",
     aros_sha256:$aros_sha,plan_sha256:$plan_sha,inputs_sha256:$inputs_sha,
     source_context_sha256:$context_sha,source_producer_commit:$source_producer,
     source_workflow:$source_workflow,source_ref:$source_ref,
     producer_commit:$producer,tools_commit:$tools,
     owner_count:($matrix[0].owners | length),sdk_generation_count:($actual | length),
     owner_transports:(reduce range(0; $owner_count) as $i ({};
       .[$matrix[0].owners[$i].owner_id] = {
         path:($root + "/owners/" + $matrix[0].owners[$i].owner_id + "/readback/transport-result.json"),
         sha256:$transport_sha[$i]})),
     sdk_generations:$rows,release_admission:false,publication:false}
    else error("owner readbacks do not rejoin the complete expected SDK tuple list") end
    ' "${readbacks[@]}" > "$scratch/selection-fragment.tmp.json" || {
        command rm -f -- "$scratch/selection-fragment.tmp.json"
        fail 'owner readbacks do not rejoin the exact complete expected SDK tuple list'
    }
[[ -f "$scratch/selection-fragment.tmp.json" && ! -L "$scratch/selection-fragment.tmp.json" ]] || \
    fail 'temporary selection fragment is not a regular file'
fragment_size=$(wc -c < "$scratch/selection-fragment.tmp.json" | tr -d '[:space:]')
[[ "$fragment_size" =~ ^[0-9]{1,8}$ ]] || fail 'temporary selection fragment size is invalid'
if (( 10#$fragment_size > 16777216 )); then fail 'temporary selection fragment exceeds its metadata bound'; fi
jq -e --arg root "$root" '
    .sdk_generation_count as $count |
    .owner_count as $owner_count |
    type == "object" and
    (keys == ["aros_sha256","assurance","inputs_sha256","owner_count","owner_transports","plan_sha256",
              "producer_commit","publication","release_admission","schema","sdk_generation_count",
              "sdk_generations","source_context_sha256","source_producer_commit","source_ref",
              "source_workflow","tools_commit"]) and
    .schema == "aros-sdk-generation-selection-fragment-v2" and
    .assurance == "authenticated-owner-transport-selection-only" and
    .release_admission == false and .publication == false and
    (.owner_transports | type == "object" and length == $owner_count and
      all(to_entries[];
        (.key | test("^[0-9a-f]{64}$")) and
        (.value | type == "object" and keys == ["path","sha256"]) and
        .value.path == ($root + "/owners/" + .key + "/readback/transport-result.json") and
        (.value.sha256 | type == "string" and test("^[0-9a-f]{64}$")))) and
    (.sdk_generations | type == "array" and length == $count and
     all(.[];
       (keys == ["compatibility","group_id","host","package_dir","record","sdk_id","target_profile"]) and
       (.record | type == "object" and keys == ["path","sha256"]) and
       (.compatibility | type == "object" and
        keys == ["directory","inputs","manifest_sha256","native_sdk_required"] and
        (.inputs | type == "object" and keys == ["path","sha256"]))))
    ' "$scratch/selection-fragment.tmp.json" >/dev/null || {
        command rm -f -- "$scratch/selection-fragment.tmp.json"
        fail 'temporary selection fragment is not the exact native SDK DTO schema'
    }
[[ ! -e "$root/selection-fragment.json" && ! -L "$root/selection-fragment.json" ]] || {
    command rm -f -- "$scratch/selection-fragment.tmp.json"
    fail 'selection fragment destination is not fresh'
}
command ln "$scratch/selection-fragment.tmp.json" "$root/selection-fragment.json" || {
    command rm -f -- "$scratch/selection-fragment.tmp.json"
    fail 'cannot install selection fragment without replacing an existing file'
}
command rm -f -- "$scratch/selection-fragment.tmp.json" || {
    command rm -f -- "$root/selection-fragment.json"
    fail 'cannot remove the temporary selection fragment after installation'
}
[[ -f "$root/selection-fragment.json" && ! -L "$root/selection-fragment.json" ]] || fail 'selection fragment was not emitted as a regular file'
printf 'SDK owner transports selected and re-read as metadata only; no qualification, admission, or publication.\n'
