#!/usr/bin/env bash
# Policy tests for provider job/run joins. Synthetic pages exercise identity
# and completeness checks only; they are not cryptographic proof.
set -euo pipefail
umask 077

script_dir=$(cd "$(dirname "$0")" && pwd -P)
source_root=$(cd "$script_dir/../../.." && pwd -P)
verifier="$source_root/scripts/toolchain/verify-workflow-job-attempt.sh"
temporary=$(mktemp -d "${TMPDIR:-/tmp}/aros-workflow-job-attempt.XXXXXX")
trap 'command rm -rf -- "$temporary"' EXIT

fail() {
    printf 'workflow job attempt policy test failed: %s\n' "$*" >&2
    exit 1
}

command -v jq >/dev/null 2>&1 || fail 'jq is required'
[[ -f "$verifier" ]] || fail "verifier is unavailable: $verifier"

pages_dir="$temporary/pages"
helper_tmp="$temporary/helper-tmp"
fake_bin="$temporary/fake-bin"
stderr_file="$temporary/stderr"
gh_call_log="$temporary/gh-calls.log"
mkdir -p "$pages_dir" "$helper_tmp" "$fake_bin"

cat > "$fake_bin/gh" <<'FAKE_GH'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$GH_CALL_LOG"
exit 97
FAKE_GH
chmod +x "$fake_bin/gh"

run_id=12345
run_attempt=2
source_digest='0123456789abcdef0123456789abcdef01234567'
failure_prefix='workflow job attempt verification failed'
base_pages="$pages_dir/base.json"

# Include ordinary extra provider fields so success also confirms that the
# verifier does not reject GitHub job records merely for carrying extra data.
jq -n --arg digest "$source_digest" '
    [
      {
        total_count: 3,
        url: "https://api.github.example/runs/12345/jobs?page=1",
        jobs: [
          {id: 101, name: "Build Linux", run_id: 12345, run_attempt: 2,
           head_sha: $digest, status: "completed", conclusion: "success",
           html_url: "https://github.example/jobs/101"},
          {id: 102, name: "Build Windows", run_id: 12345, run_attempt: 2,
           head_sha: $digest, status: "completed", conclusion: "failure",
           labels: ["windows", "x64"]}
        ]
      },
      {
        total_count: 3,
        url: "https://api.github.example/runs/12345/jobs?page=2",
        jobs: [
          {id: 103, name: "Build macOS", run_id: 12345, run_attempt: 2,
           head_sha: $digest, status: "completed", conclusion: "skipped",
           workflow_name: "Build"}
        ]
      }
    ]
' > "$base_pages"

write_variant() {
    local name=$1
    local filter=$2
    jq "$filter" "$base_pages" > "$pages_dir/$name.json"
}

write_raw_pages() {
    local name=$1
    local contents=$2
    printf '%s\n' "$contents" > "$pages_dir/$name.json"
}

sha256_file() {
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    elif command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        fail 'neither shasum nor sha256sum is available'
    fi
}

pages_snapshot() {
    find "$pages_dir" -mindepth 1 -print | LC_ALL=C sort | while IFS= read -r path; do
        printf '%s\n' "${path#"$pages_dir"/}"
        if [[ -f "$path" && ! -L "$path" ]]; then
            printf '%s\n' "$(sha256_file "$path")"
        elif [[ -L "$path" ]]; then
            readlink "$path"
        fi
    done
}

assert_no_helper_side_effects() {
    local pages_before=$1
    local current_pages
    current_pages=$(pages_snapshot)
    [[ "$current_pages" == "$pages_before" ]] \
        || fail 'helper created or changed a pages input file'
    [[ -z $(find "$helper_tmp" -mindepth 1 -print -quit) ]] \
        || fail 'helper left files in its temporary directory'
    [[ ! -e "$gh_call_log" ]] || fail 'helper invoked gh instead of using the supplied pages'
}

last_status=0
invoke_helper() {
    local pages_before
    local stdout=''
    pages_before=$(pages_snapshot)
    : > "$stderr_file"
    if stdout=$(PATH="$fake_bin:$PATH" TMPDIR="$helper_tmp" GH_CALL_LOG="$gh_call_log" \
        bash "$verifier" "$@" 2> "$stderr_file"); then
        last_status=0
    else
        last_status=$?
    fi
    [[ -z "$stdout" ]] || fail "helper emitted stdout: $stdout"
    assert_no_helper_side_effects "$pages_before"
}

expect_failure() {
    local name=$1
    shift
    invoke_helper "$@"
    [[ "$last_status" != 0 ]] || fail "$name unexpectedly succeeded"
    local diagnostic=''
    IFS= read -r diagnostic < "$stderr_file" || true
    [[ "$diagnostic" == "$failure_prefix"* ]] \
        || fail "$name missed the expected diagnostic prefix: $diagnostic"
}

expect_success() {
    local name=$1
    shift
    invoke_helper "$@"
    [[ "$last_status" == 0 ]] || {
        cat "$stderr_file" >&2
        fail "$name unexpectedly failed"
    }
    [[ ! -s "$stderr_file" ]] || fail "$name emitted unexpected stderr"
}

expect_data_failure() {
    local name=$1
    local pages=$2
    expect_failure "$name" \
        --pages "$pages" --run-id "$run_id" --run-attempt "$run_attempt" \
        --source-digest "$source_digest"
}

expect_variant_failure() {
    local name=$1
    local filter=$2
    write_variant "$name" "$filter"
    expect_data_failure "$name" "$pages_dir/$name.json"
}

valid_args=(
    --pages "$base_pages"
    --run-id "$run_id"
    --run-attempt "$run_attempt"
    --source-digest "$source_digest"
)

# The two-page fixture has three globally distinct jobs, all completed and
# bound to the requested run, attempt, and source. Failure and skipped
# conclusions are intentionally accepted: workflow policy judges conclusions.
expect_success 'complete synthetic job set' "${valid_args[@]}"

# The joined identities must match exactly.
expect_variant_failure wrong-run '.[0].jobs[0].run_id = 12346'
expect_variant_failure wrong-attempt '.[0].jobs[0].run_attempt = 3'
expect_variant_failure wrong-head '.[1].jobs[0].head_sha = "ffffffffffffffffffffffffffffffffffffffff"'
expect_variant_failure repeated-id-across-pages '.[1].jobs[0].id = 101'
expect_variant_failure repeated-name-across-pages '.[1].jobs[0].name = "Build Linux"'
expect_variant_failure empty-job-name '.[1].jobs[0].name = ""'
expect_variant_failure in-progress-job '.[0].jobs[0].status = "in_progress"'
expect_variant_failure empty-conclusion '.[1].jobs[0].conclusion = ""'
expect_variant_failure non-string-conclusion '.[1].jobs[0].conclusion = 0'

# Every required job field is mandatory; provider-specific extras are allowed.
for field in id name run_id run_attempt head_sha status conclusion; do
    expect_variant_failure "missing-$field" "del(.[0].jobs[0].$field)"
done

# Job IDs and identity values must be positive safe JSON integers, not strings,
# fractions, zero, negatives, or values outside JavaScript's exact range.
expect_variant_failure zero-job-id '.[0].jobs[0].id = 0'
expect_variant_failure negative-job-id '.[0].jobs[0].id = -1'
expect_variant_failure string-job-id '.[0].jobs[0].id = "101"'
expect_variant_failure fractional-job-id '.[0].jobs[0].id = 101.5'
expect_variant_failure unsafe-job-id '.[0].jobs[0].id = 9007199254740992'
expect_variant_failure string-run-id '.[0].jobs[0].run_id = "12345"'
expect_variant_failure unsafe-run-attempt '.[0].jobs[0].run_attempt = 9007199254740992'

# Every returned page must be present and agree on a positive total_count that
# equals the number of joined jobs across all pages.
write_variant omitted-page '.[0:1]'
expect_data_failure omitted-page "$pages_dir/omitted-page.json"
write_variant wrong-total-count 'map(.total_count = 4)'
expect_data_failure wrong-total-count "$pages_dir/wrong-total-count.json"
write_variant inconsistent-total-count '.[1].total_count = 2'
expect_data_failure inconsistent-total-count "$pages_dir/inconsistent-total-count.json"
write_variant zero-total-count 'map(.total_count = 0 | .jobs = [])'
expect_data_failure zero-total-count "$pages_dir/zero-total-count.json"
write_variant string-total-count 'map(.total_count = "3")'
expect_data_failure string-total-count "$pages_dir/string-total-count.json"
write_variant missing-total-count 'del(.[1].total_count)'
expect_data_failure missing-total-count "$pages_dir/missing-total-count.json"
write_variant missing-jobs-array 'del(.[1].jobs)'
expect_data_failure missing-jobs-array "$pages_dir/missing-jobs-array.json"
write_variant non-array-jobs '.[1].jobs = {}'
expect_data_failure non-array-jobs "$pages_dir/non-array-jobs.json"
write_variant empty-jobs 'map(.jobs = [])'
expect_data_failure empty-jobs "$pages_dir/empty-jobs.json"
write_raw_pages no-pages '[]'
expect_data_failure no-pages "$pages_dir/no-pages.json"
write_raw_pages empty-file ''
expect_data_failure empty-file "$pages_dir/empty-file.json"
printf '[]\n[]\n' > "$pages_dir/multiple-json-documents.json"
expect_data_failure multiple-json-documents "$pages_dir/multiple-json-documents.json"
write_raw_pages non-array-pages '{"total_count":3,"jobs":[]}'
expect_data_failure non-array-pages "$pages_dir/non-array-pages.json"

# The pages input itself must be a regular, non-symlink file.
ln -s "$base_pages" "$pages_dir/symlink.json"
mkdir "$pages_dir/nonfile"
expect_failure symlink-pages \
    --pages "$pages_dir/symlink.json" --run-id "$run_id" \
    --run-attempt "$run_attempt" --source-digest "$source_digest"
expect_failure nonfile-pages \
    --pages "$pages_dir/nonfile" --run-id "$run_id" \
    --run-attempt "$run_attempt" --source-digest "$source_digest"

# Missing, blank, and repeated options are argument errors, even if a later
# duplicate would otherwise provide a valid value.
expect_failure missing-pages \
    --run-id "$run_id" --run-attempt "$run_attempt" --source-digest "$source_digest"
expect_failure missing-run-id \
    --pages "$base_pages" --run-attempt "$run_attempt" --source-digest "$source_digest"
expect_failure missing-run-attempt \
    --pages "$base_pages" --run-id "$run_id" --source-digest "$source_digest"
expect_failure missing-source-digest \
    --pages "$base_pages" --run-id "$run_id" --run-attempt "$run_attempt"
expect_failure blank-pages \
    --pages '' --run-id "$run_id" --run-attempt "$run_attempt" --source-digest "$source_digest"
expect_failure blank-run-id \
    --pages "$base_pages" --run-id '' --run-attempt "$run_attempt" --source-digest "$source_digest"
expect_failure blank-run-attempt \
    --pages "$base_pages" --run-id "$run_id" --run-attempt '' --source-digest "$source_digest"
expect_failure blank-source-digest \
    --pages "$base_pages" --run-id "$run_id" --run-attempt "$run_attempt" --source-digest ''
expect_failure duplicate-pages \
    --pages "$base_pages" --pages "$base_pages" --run-id "$run_id" \
    --run-attempt "$run_attempt" --source-digest "$source_digest"
expect_failure duplicate-run-id \
    --pages "$base_pages" --run-id "$run_id" --run-id "$run_id" \
    --run-attempt "$run_attempt" --source-digest "$source_digest"
expect_failure duplicate-run-attempt \
    --pages "$base_pages" --run-id "$run_id" --run-attempt "$run_attempt" \
    --run-attempt "$run_attempt" --source-digest "$source_digest"
expect_failure duplicate-source-digest \
    --pages "$base_pages" --run-id "$run_id" --run-attempt "$run_attempt" \
    --source-digest "$source_digest" --source-digest "$source_digest"
expect_failure leading-zero-run-id \
    --pages "$base_pages" --run-id 012345 --run-attempt "$run_attempt" \
    --source-digest "$source_digest"
expect_failure unsafe-run-id-argument \
    --pages "$base_pages" --run-id 9007199254740992 --run-attempt "$run_attempt" \
    --source-digest "$source_digest"
expect_failure uppercase-source-digest \
    --pages "$base_pages" --run-id "$run_id" --run-attempt "$run_attempt" \
    --source-digest '0123456789ABCDEF0123456789ABCDEF01234567'

printf 'workflow job attempt policy tests passed (synthetic pages only)\n'
