#!/usr/bin/env bash
# Authenticate the original compiler-owning job, then read back its native
# package bytes. This is not independent compiler execution or release authority.
set -euo pipefail
set -C
umask 077

fail() { printf 'Native owner readback: %s\n' "$*" >&2; exit 1; }
digest() { shasum -a 256 "$1" | awk '{print $1}'; }
script_dir=$(cd "$(dirname "$0")" && pwd -P)

aros='' runtime_sha='' recipe='' recipe_sha='' source_lock='' source_sha=''
profiles='' profiles_sha='' selection='' selection_sha='' workflow='' job_name=''
source_workflow='' source_ref='' group='' preset='' host='' copy=''
release_id='' root='' same_attempt=false
declare -a forbidden=()
seen='|'
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
        --root) root=$value;;
        --forbidden-prefix) forbidden+=("$value");;
        *) fail "unknown option $key";;
    esac
    shift 2
done

for required in aros runtime_sha recipe recipe_sha source_lock source_sha profiles profiles_sha \
                selection selection_sha workflow job_name source_workflow source_ref group preset \
                host copy release_id root; do
    [[ -n "${!required}" ]] || fail "missing required selector $required"
done
for hash in "$runtime_sha" "$recipe_sha" "$source_sha" "$profiles_sha" "$selection_sha"; do
    [[ "$hash" =~ ^[0-9a-f]{64}$ ]] || fail 'digest is not lowercase SHA-256'
done
for file in "$aros" "$recipe" "$source_lock" "$profiles" "$selection"; do
    [[ "$file" == /* && -f "$file" && ! -L "$file" ]] || fail 'selected inputs must be absolute regular files'
    [[ "$file" == "$(cd "$(dirname "$file")" && pwd -P)/${file##*/}" ]] || fail 'selected input parent is noncanonical'
done
[[ -x "$aros" ]] || fail 'selected runtime is not executable'
[[ "$group" =~ ^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$ ]] || fail 'group identifier is invalid'
[[ "$preset" =~ ^[A-Za-z0-9._-]{1,128}$ && "$preset" != . && "$preset" != .. ]] || fail 'profile identifier is invalid'
[[ "$release_id" =~ ^[a-z0-9][a-z0-9._-]*$ ]] || fail 'release identifier is invalid'
case "$host" in linux-x86_64|linux-aarch64|macos-aarch64) ;; *) fail 'unsupported native release host';; esac
case "$copy" in a|b) ;; *) fail 'original compiler build copy must be a or b';; esac
for selected_workflow in "$workflow" "$source_workflow"; do
    [[ "$selected_workflow" =~ ^\.github/workflows/[A-Za-z0-9_-]+\.yml$ ]] || fail 'workflow selector is invalid'
done
(( ${#job_name} <= 256 )) || fail 'current reader job name is too long'
[[ "$job_name" != *[[:cntrl:]]* ]] || fail 'current reader job name contains a control character'
[[ "$source_ref" =~ ^refs/(heads|tags)/[A-Za-z0-9._/-]+$ ]] || fail 'source ref is invalid'
for prefix in ${forbidden[@]+"${forbidden[@]}"}; do [[ "$prefix" == /* ]] || fail 'forbidden prefix must be absolute'; done
(( ${#forbidden[@]} > 0 )) || fail 'at least one independently selected forbidden build prefix is required'

check_inputs() {
    [[ "$(digest "$aros")" == "$runtime_sha" && "$(digest "$recipe")" == "$recipe_sha" &&
       "$(digest "$source_lock")" == "$source_sha" && "$(digest "$profiles")" == "$profiles_sha" &&
       "$(digest "$selection")" == "$selection_sha" ]] || fail 'selected input bytes changed or differ'
}
check_inputs
# Use the same bounded and duplicate-free source-selection validator as the
# authentication boundary, then join only the independently chosen selectors.
python3 -B - "$script_dir/artifact-origin.py" "$selection" "$recipe" "$source_workflow" \
    "$source_ref" "$group" "$host" "$preset" "$copy" <<'PY'
import importlib.util
import re
import sys
from pathlib import Path

origin_path = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("artifact_origin", origin_path)
if spec is None or spec.loader is None:
    raise SystemExit("artifact-origin validation helpers are unavailable")
origin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(origin)
selection_path, recipe_path, workflow, ref, group, host, preset, copy = sys.argv[2:]
try:
    selected_raw = origin.normalized_file(Path(selection_path), origin.MAX_METADATA)[1]
    recipe_raw = origin.normalized_file(Path(recipe_path), origin.MAX_METADATA)[1]
    selected = origin.parse_json(selected_raw)
    selected = origin.source_selection(selected, selected["context"], same_attempt=True)
    recipe = origin.parse_json(recipe_raw)
    producer = recipe.get("producer_commit") if isinstance(recipe, dict) else None
    origin.require(recipe.get("schema") == "aros-toolchain-recipe-v2"
                   and isinstance(producer, str)
                   and re.fullmatch(r"[0-9a-f]{40}", producer) is not None,
                   "selected recipe producer identity is invalid")
    lane = {"role": "build", "group": group, "host": host,
            "profile": preset, "copy": copy}
    origin.require(selected["context"]["workflow"] == workflow
                   and selected["context"]["source_ref"] == ref
                   and selected["context"]["producer_commit"] == producer
                   and selected["selection"] == lane,
                   "source selection differs from the independently selected native lane")
except origin.OriginError as error:
    raise SystemExit(str(error)) from None
PY
[[ "$root" == /* && ! -e "$root" && ! -L "$root" ]] || fail 'operation root must be fresh and absolute'
parent=${root%/*}; name=${root##*/}
[[ -n "$name" && "$name" != . && "$name" != .. && -d "$parent" && ! -L "$parent" &&
   "$root" == "$(cd "$parent" && pwd -P)/$name" ]] || fail 'operation root parent is noncanonical'
for file in "$aros" "$recipe" "$source_lock" "$profiles" "$selection"; do
    [[ "$file" != "$root/"* ]] || fail 'operation root overlaps a selected input'
done

mkdir "$root"
origin_args=(verify-source --workflow "$workflow" --job-name "$job_name"
    --source-selection "$selection" --verified-output-dir "$root/transport")
if [[ "$same_attempt" == true ]]; then origin_args+=(--same-attempt); fi
# This exact invocation must authenticate its current job before artifact bytes
# or the signed execution result are opened by this reader.
python3 -B "$script_dir/artifact-origin.py" "${origin_args[@]}" \
    > "$root/origin-verification.log" || fail 'original compiler owner authentication failed'
check_inputs
python3 -B "$script_dir/native-lane-transport.py" --retained-dir "$root/transport" \
    --output-dir "$root/payload" > "$root/transport-result.json" || fail 'native owner payload extraction failed'

build_result="$root/payload/evidence/build-result.json"
environment="$root/payload/evidence/environment.json"
measurement="$root/payload/evidence/measurement.json"
# Only authenticated payload evidence may select original execution expectations.
# artifact-origin provides bounded, normalized, duplicate-free input parsing;
# the native CLI remains authoritative for the complete recipe/result schemas.
python3 -B - "$script_dir/artifact-origin.py" "$recipe" "$build_result" "$host" "$preset" \
    > "$root/original-expectations.json" <<'PY'
import hashlib
import importlib.util
import re
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("artifact_origin", Path(sys.argv[1]))
if spec is None or spec.loader is None:
    raise SystemExit("artifact-origin validation helpers are unavailable")
origin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(origin)
recipe_path, result_path, expected_host, expected_profile = sys.argv[2:]
try:
    recipe_raw = origin.normalized_file(Path(recipe_path), origin.MAX_METADATA)[1]
    result_raw = origin.normalized_file(Path(result_path), origin.MAX_METADATA)[1]
    recipe = origin.parse_json(recipe_raw)
    result = origin.parse_json(result_raw)
    origin.require(isinstance(recipe, dict) and recipe.get("schema") == "aros-toolchain-recipe-v2",
                   "selected recipe schema differs")
    origin.require(isinstance(result, dict)
                   and result.get("schema") == "aros-toolchain-result-v1"
                   and result.get("operation") == "build"
                   and result.get("qualification") == "local-only"
                   and result.get("commit_state") == "committed",
                   "signed original build result operation or local state differs")
    identity = result.get("identity")
    executor = identity.get("executor") if isinstance(identity, dict) else None
    origin.require(isinstance(identity, dict) and isinstance(executor, dict),
                   "signed original build result identity is missing")
    expected_git = (recipe.get("source_commit"), recipe.get("producer_commit"), recipe.get("tools_commit"))
    observed_git = (identity.get("source_commit"), identity.get("producer_commit"), identity.get("tools_commit"))
    origin.require(all(isinstance(item, str) and re.fullmatch(r"[0-9a-f]{40}", item)
                       for item in (*expected_git, *observed_git)),
                   "signed original source or tools identity is invalid")
    recipe_self = recipe.get("recipe_sha256")
    contract_sha = executor.get("contract_sha256")
    binary_sha = executor.get("binary_sha256")
    origin.require(isinstance(recipe_self, str) and re.fullmatch(r"[0-9a-f]{64}", recipe_self)
                   and identity.get("recipe_sha256") == recipe_self
                   and observed_git == expected_git
                   and identity.get("host") == expected_host
                   and identity.get("target_profile") == expected_profile,
                   "signed original build identity differs from the independent recipe, host or profile")
    origin.require(executor.get("contract_id") == "aros-toolchain-producer-v1"
                   and isinstance(contract_sha, str) and re.fullmatch(r"[0-9a-f]{64}", contract_sha)
                   and executor.get("tools_commit") == identity.get("tools_commit")
                   and isinstance(binary_sha, str) and re.fullmatch(r"[0-9a-f]{64}", binary_sha)
                   and executor.get("origin_evidence_sha256") is None,
                   "signed original executor identity differs")
except origin.OriginError as error:
    raise SystemExit(str(error)) from None

print(origin.json.dumps({
    "build_result_sha256": hashlib.sha256(result_raw).hexdigest(),
    "recipe_self_sha256": recipe_self,
    "source_commit": identity["source_commit"],
    "producer_commit": identity["producer_commit"],
    "tools_commit": identity["tools_commit"],
    "host": identity["host"],
    "target_profile": identity["target_profile"],
    "executor_contract_id": executor["contract_id"],
    "executor_contract_sha256": contract_sha,
    "executor_binary_sha256": binary_sha,
}, sort_keys=True, separators=(",", ":")))
PY
[[ -s "$root/original-expectations.json" ]] || fail 'signed native execution expectations are empty'
build_sha=$(jq -er 'select(type == "object") | .build_result_sha256 | select(test("^[0-9a-f]{64}$"))' \
    "$root/original-expectations.json") || fail 'signed native build result could not be selected'
executor_sha=$(jq -er '.executor_contract_sha256' "$root/original-expectations.json") || fail 'signed executor contract digest is missing'
executor_binary_sha=$(jq -er '.executor_binary_sha256' "$root/original-expectations.json") || fail 'signed executor binary digest is missing'
environment_sha=$(digest "$environment")
measurement_sha=$(digest "$measurement")
signed_measurement=$(jq -er '.files["evidence/measurement.json"].sha256' "$root/transport/origin.json") || \
    fail 'authenticated origin omits the native measurement digest'
[[ "$measurement_sha" == "$signed_measurement" ]] || fail 'native measurement differs from authenticated origin'
check_inputs

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
    --package-measurement "$measurement"
    --package-measurement-sha256 "$signed_measurement"
    --executor-contract-sha256 "$executor_sha" --executor-binary-sha256 "$executor_binary_sha")
for prefix in ${forbidden[@]+"${forbidden[@]}"}; do context+=(--forbidden-prefix "$prefix"); done
"$aros" toolchain producer verify-package "${context[@]}" --format json > "$root/native-verification.json" \
    || fail 'native portable package verification failed'
# The executor selectors above come from the authenticated pre-export result;
# the portable measurement contributes only its digest and joined bytes.
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
python3 -B "$script_dir/native-lane-transport.py" --retained-dir "$root/transport" \
    --verify-output-dir "$root/payload" > "$root/transport-readback.json" \
    || fail 'native transport readback failed'
cmp "$root/transport-result.json" "$root/transport-readback.json" >/dev/null || fail 'transport changed during native verification'
check_inputs
[[ "$(digest "$environment")" == "$environment_sha" && "$(digest "$measurement")" == "$measurement_sha" &&
   "$(digest "$build_result")" == "$build_sha" ]] || fail 'authenticated native evidence changed during verification'

jq -n --arg workflow "$workflow" --arg job_name "$job_name" --arg source_workflow "$source_workflow" \
    --arg source_ref "$source_ref" --arg group "$group" --arg host "$host" --arg preset "$preset" \
    --arg copy "$copy" --arg release_id "$release_id" --arg runtime "$runtime_sha" \
    --arg recipe_file "$recipe_sha" --arg source_sha "$source_sha" --arg profiles_sha "$profiles_sha" \
    --arg selection "$selection_sha" --arg build_result "$build_sha" \
    --arg environment "$environment_sha" --arg measurement "$signed_measurement" \
    --arg executor_contract "$executor_sha" --arg executor_binary "$executor_binary_sha" \
    --slurpfile execution "$root/original-expectations.json" \
    --slurpfile transport "$root/transport-result.json" --slurpfile native "$root/native-verification.json" '{
    schema:"aros-toolchain-original-owner-observation-v2",
    assurance:"authenticated-original-job-and-native-byte-readback-only",
    scope:{original_owner_job_observation:true,native_package_byte_readback:true,
           independently_executed_collector:false,release_admission:false,publication:false},
    current_workflow:$workflow,current_job_name:$job_name,
    source_workflow:$source_workflow,source_ref:$source_ref,
    group:$group,host:$host,target_profile:$preset,copy:$copy,release_id:$release_id,
    reader_runtime_sha256:$runtime,recipe_file_sha256:$recipe_file,
    source_lock_sha256:$source_sha,profiles_sha256:$profiles_sha,
    source_selection_sha256:$selection,build_result_sha256:$build_result,
    environment_sha256:$environment,measurement_sha256:$measurement,
    executor_contract_id:$execution[0].executor_contract_id,
    executor_contract_sha256:$executor_contract,executor_binary_sha256:$executor_binary,
    original_identity:{recipe_self_sha256:$execution[0].recipe_self_sha256,
       source_commit:$execution[0].source_commit,producer_commit:$execution[0].producer_commit,
       tools_commit:$execution[0].tools_commit,host:$execution[0].host,
       target_profile:$execution[0].target_profile},
    transport:$transport[0],native:$native[0]
    }' > "$root/observation.json" || fail 'native owner observation wrapper generation failed'
printf 'Authenticated original compiler-owner job and read back native package bytes; no independent execution, release admission or publication claim.\n'
