#!/usr/bin/env bash
# Read-only provider metadata join. This does not authenticate artifact bytes
# or prove which job uploaded an artifact; those require separate evidence.
set -euo pipefail

fail() {
    printf 'workflow job attempt verification failed: %s\n' "$*" >&2
    exit 1
}

pages=''
run_id=''
run_attempt=''
source_digest=''
seen=' '
while (($#)); do
    option=$1
    case "$option" in
        --pages|--run-id|--run-attempt|--source-digest)
            [[ "$seen" != *" $option "* ]] || fail "duplicate selector: $option"
            seen+="$option "
            (($# >= 2)) || fail "missing value: $option"
            [[ -n "$2" ]] || fail "empty value: $option"
            case "$option" in
                --pages) pages=$2 ;;
                --run-id) run_id=$2 ;;
                --run-attempt) run_attempt=$2 ;;
                --source-digest) source_digest=$2 ;;
            esac
            shift 2
            ;;
        *) fail "unknown argument: $option" ;;
    esac
done
[[ -f "$pages" && ! -L "$pages" ]] || fail 'pages must be a regular non-symlink file'
[[ "$run_id" =~ ^[1-9][0-9]*$ && "$run_attempt" =~ ^[1-9][0-9]*$ ]] \
    || fail 'run ID and attempt must be positive canonical decimal integers'
[[ "$source_digest" =~ ^[0-9a-f]{40}$ ]] || fail 'source digest must be a lowercase Git commit OID'
command -v jq >/dev/null 2>&1 || fail 'jq is required'

if ! jq -se --arg run "$run_id" --arg attempt "$run_attempt" --arg commit "$source_digest" '
    def positive_integer:
        type == "number" and . > 0 and . <= 9007199254740991 and . == floor;
    length == 1 and (.[0] |
    type == "array" and length > 0 and
    all(.[]; type == "object" and (.total_count | positive_integer) and (.jobs | type == "array")) and
    ([.[].total_count] | unique | length == 1) and
    ([.[].jobs[]] as $jobs |
        ($jobs | length) == .[0].total_count and
        all($jobs[];
            type == "object" and (.id | positive_integer) and
            (.name | type == "string" and length > 0) and
            (.run_id | positive_integer) and (.run_id | tostring) == $run and
            (.run_attempt | positive_integer) and (.run_attempt | tostring) == $attempt and
            .head_sha == $commit and .status == "completed" and
            (.conclusion | type == "string" and length > 0)
        ) and
        ([$jobs[].id] | unique | length) == ($jobs | length) and
        ([$jobs[].name] | unique | length) == ($jobs | length)
    ))
' "$pages" >/dev/null; then
    fail 'provider pages must contain every distinct completed job from the exact run, attempt and commit'
fi
