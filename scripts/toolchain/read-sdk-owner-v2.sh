#!/usr/bin/env bash
# Authenticate the explicitly selected original SDK owner, then read back its
# independently selected SDK payload bytes. This grants no SDK qualification.
set -euo pipefail
set -C
umask 077

fail() { printf 'SDK owner readback: %s\n' "$*" >&2; exit 1; }
digest() { shasum -a 256 "$1" | awk '{print $1}'; }

selection='' selection_sha='' source_producer='' source_workflow='' source_ref=''
workflow='' job_name='' sdk_ids='' group='' profile='' host='' compiler_family=''
root='' same_attempt=false seen='|'
owner_role=diagnostic
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
    [[ "$seen" != *"|$key|"* ]] || fail "duplicate option $key"
    seen+="$key|"
    case "$key" in
        --source-selection) selection=$value;;
        --source-selection-sha256) selection_sha=$value;;
        --source-producer-commit) source_producer=$value;;
        --source-workflow) source_workflow=$value;;
        --source-ref) source_ref=$value;;
        --workflow) workflow=$value;;
        --job-name) job_name=$value;;
        --sdk-ids) sdk_ids=$value;;
        --group) group=$value;;
        --preset) profile=$value;;
        --host) host=$value;;
        --compiler-family) compiler_family=$value;;
        --owner-role) owner_role=$value;;
        --root) root=$value;;
        *) fail "unknown option $key";;
    esac
    shift 2
done

for name in selection selection_sha source_producer source_workflow source_ref workflow job_name \
            sdk_ids group profile host compiler_family root; do
    [[ -n "${!name}" ]] || fail "missing required selector $name"
done
[[ "$selection_sha" =~ ^[0-9a-f]{64}$ ]] || fail 'source selection digest is not lowercase SHA-256'
[[ "$source_producer" =~ ^[0-9a-f]{40}$ ]] || fail 'source producer commit is invalid'
for selected_workflow in "$workflow" "$source_workflow"; do
    [[ "$selected_workflow" =~ ^\.github/workflows/[A-Za-z0-9_-]+\.yml$ ]] || fail 'workflow selector is invalid'
done
(( ${#job_name} <= 256 )) || fail 'job name is too long'
[[ "$group" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] || fail 'group identifier is invalid'
[[ "$profile" =~ ^[A-Za-z0-9._-]{1,128}$ && "$profile" != . && "$profile" != .. ]] || fail 'profile identifier is invalid'
case "$host" in
    linux-x86_64|linux-aarch64|macos-aarch64) ;;
    *) fail 'host is not a native SDK host';;
esac
case "$compiler_family" in gnu|llvm) ;; *) fail 'compiler family must be gnu or llvm';; esac
case "$owner_role" in diagnostic|sdk) ;; *) fail 'SDK owner role must be diagnostic or sdk';; esac

# Match Git's ref-name constraints for the selected heads/tags namespace.
[[ "$source_ref" =~ ^refs/(heads|tags)/[A-Za-z0-9._/-]+$ ]] || fail 'source ref is invalid'
ref_tail=${source_ref#refs/*/}
[[ -n "$ref_tail" && "$ref_tail" != *'..'* && "$ref_tail" != *'@{'* &&
   "$ref_tail" != *//* && "$ref_tail" != */ && "$ref_tail" != *. && "$ref_tail" != *@ ]] || fail 'source ref is not canonical'
IFS='/' read -r -a ref_parts <<< "$ref_tail"
for part in "${ref_parts[@]}"; do
    [[ -n "$part" && "$part" != .* && "$part" != *. && "$part" != *.lock ]] || fail 'source ref is not canonical'
done

if ! jq -e 'type == "array" and length >= 1 and length <= 32 and
    all(.[]; type == "string" and test("^[-._+a-z0-9]{1,96}$") and . != "." and . != "..") and
    . == unique' <<< "$sdk_ids" >/dev/null 2>&1; then
    fail 'SDK IDs must be a sorted unique JSON array of one to 32 native SDK IDs'
fi

[[ "$selection" == /* && -f "$selection" && ! -L "$selection" ]] || fail 'source selection must be an absolute regular file'
selection_parent=${selection%/*}
selection_name=${selection##*/}
[[ -n "$selection_parent" && -n "$selection_name" ]] || fail 'source selection path is invalid'
[[ "$selection" == "$(cd "$selection_parent" && pwd -P)/$selection_name" ]] || fail 'source selection path is not canonical'
selection_size=$(wc -c < "$selection" | tr -d '[:space:]')
if [[ ! "$selection_size" =~ ^[0-9]{1,8}$ ]] || (( 10#$selection_size > 16777216 )); then
    fail 'source selection exceeds its byte limit'
fi

check_selection_digest() {
    [[ -f "$selection" && ! -L "$selection" && "$(digest "$selection")" == "$selection_sha" ]] || \
        fail 'source selection bytes changed or differ from the selected digest'
}
check_selection_digest
# The source workflow/ref/producer and the SDK owner role are independently
# selected by the caller before any operation directory is created.
jq -e --arg workflow "$source_workflow" --arg ref "$source_ref" \
    --arg producer "$source_producer" --arg group "$group" --arg host "$host" \
    --arg profile "$profile" --arg owner_role "$owner_role" '
    .schema == "aros-toolchain-artifact-selection-v1" and
    .context.workflow == $workflow and .context.source_ref == $ref and
    .context.producer_commit == $producer and
    .selection == {role:$owner_role,group:$group,host:$host,profile:$profile,copy:"none"}
    ' "$selection" >/dev/null || fail 'source selection differs from the independent SDK owner selector'
check_selection_digest

[[ "$root" == /* && ! -e "$root" && ! -L "$root" ]] || fail 'operation root must be absent and absolute'
root_parent=${root%/*}
root_name=${root##*/}
[[ -n "$root_parent" && -n "$root_name" && "$root_name" != . && "$root_name" != .. &&
   -d "$root_parent" && ! -L "$root_parent" &&
   "$root" == "$(cd "$root_parent" && pwd -P)/$root_name" ]] || fail 'operation root must have a canonical existing parent'
[[ "$selection" != "$root" && "$selection" != "$root/"* ]] || fail 'operation root overlaps the source selection'

script_dir=$(cd "$(dirname "$0")" && pwd -P)
mkdir "$root"

# Authentication is deliberately first: no retained directory from a prior
# invocation can stand in for this current source-owner/provider verification.
origin_args=(verify-source --workflow "$workflow" --job-name "$job_name"
    --source-selection "$selection" --verified-output-dir "$root/transport")
if [[ "$same_attempt" == true ]]; then origin_args+=(--same-attempt); fi
python3 -B "$script_dir/artifact-origin.py" "${origin_args[@]}" \
    > "$root/origin-verification.log" || fail 'original SDK owner authentication failed'
check_selection_digest

transport_args=(--retained-dir "$root/transport" --sdk-ids "$sdk_ids"
    --group "$group" --profile "$profile" --host "$host" --compiler-family "$compiler_family"
    --owner-role "$owner_role")
python3 -B "$script_dir/sdk-owner-transport-v2.py" "${transport_args[@]}" \
    --output-dir "$root/payload" > "$root/transport-result.json" || fail 'SDK payload extraction failed'
python3 -B "$script_dir/sdk-owner-transport-v2.py" "${transport_args[@]}" \
    --verify-output-dir "$root/payload" > "$root/transport-readback.json" || fail 'SDK payload readback failed'
cmp "$root/transport-result.json" "$root/transport-readback.json" >/dev/null || \
    fail 'SDK payload extraction and readback results differ'
check_selection_digest

# Rejoin the helper's result to the independent selectors before emitting a
# deliberately narrow byte-readback wrapper. The helper has no Rust semantics.
jq -se --argjson ids "$sdk_ids" --arg group "$group" --arg profile "$profile" \
    --arg host "$host" --arg compiler_family "$compiler_family" \
    --arg selection_sha "$selection_sha" --arg payload "$root/payload" --arg owner_role "$owner_role" '
    length == 1 and (.[0] |
      .schema == "aros-sdk-owner-transport-v2" and
      .assurance == "transport-byte-readback-only" and
      (if $owner_role == "diagnostic" then
         ((has("owner_role") | not) or .owner_role == $owner_role)
       else .owner_role == $owner_role end) and
      (.origin_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
      (.raw_zip_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
      .selection_sha256 == $selection_sha and
      (.selection_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
      (.sdk_generations | type == "array" and length == ($ids | length)) and
      ([.sdk_generations[].sdk_id] == $ids) and
      all(.sdk_generations[];
        .group_id == $group and .target_profile == $profile and .host == $host and
        .package_dir == ($payload + "/sdk-" + .sdk_id + "/package") and
        .record.path == ($payload + "/sdk-" + .sdk_id + "/generation.json") and
        (.record.sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
        .compatibility.directory == ($payload + "/sdk-" + .sdk_id + "/compatibility") and
        .compatibility.inputs.path == ($payload + "/sdk-" + .sdk_id + "/compatibility-inputs.json") and
        (.compatibility.native_sdk_required == ($compiler_family == "gnu")) and
        (.compatibility.manifest_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
        (.compatibility.inputs.sha256 | type == "string" and test("^[0-9a-f]{64}$"))))
    ' "$root/transport-result.json" >/dev/null || fail 'SDK helper result differs from independent selectors'

# Keep this check adjacent to wrapper creation so the emitted measurement is
# still bound to the exact caller-selected file after all helper readbacks.
check_selection_digest
readback_tmp="$root/readback.json"
jq -n --arg workflow "$source_workflow" --arg ref "$source_ref" \
    --arg producer "$source_producer" --arg selection_sha "$selection_sha" \
    --arg group "$group" --arg profile "$profile" --arg host "$host" \
    --arg compiler_family "$compiler_family" --argjson sdk_ids "$sdk_ids" \
    --arg owner_role "$owner_role" --slurpfile sdk_owner "$root/transport-result.json" '{
    schema:"aros-sdk-owner-readback-v2",
    assurance:"authenticated-transport-and-sdk-payload-readback-only",
    source_workflow:$workflow,
    source_ref:$ref,
    source_producer_commit:$producer,
    source_selection_sha256:$selection_sha,
    independent_selection:{sdk_ids:$sdk_ids,group:$group,profile:$profile,host:$host,
                           compiler_family:$compiler_family},
    sdk_owner_transport:$sdk_owner[0]
    } | if $owner_role == "sdk" then .independent_selection.owner_role = $owner_role else . end' \
    > "$readback_tmp" || fail 'SDK readback wrapper generation failed'

printf 'Authenticated original SDK owner and read back selected payload bytes; no SDK qualification or release authority.\n'
