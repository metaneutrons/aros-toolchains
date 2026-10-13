#!/usr/bin/env bash
# Policy tests only: fake gh output exercises subject joins and input stability,
# not cryptographic validity or provenance of a real GitHub attestation.
set -euo pipefail
umask 077

script_dir=$(cd "$(dirname "$0")" && pwd -P)
source_root=$(cd "$script_dir/../../.." && pwd -P)
verifier="$source_root/scripts/toolchain/verify-provenance-attestation.sh"
temporary=$(mktemp -d "${TMPDIR:-/tmp}/aros-provenance-subject-manifest.XXXXXX")
trap 'command rm -rf -- "$temporary"' EXIT

fail() {
    printf 'subject-manifest policy test failed: %s\n' "$*" >&2
    exit 1
}

if command -v sha256sum >/dev/null 2>&1; then
    sha256_file() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
    sha256_file() { shasum -a 256 "$1" | awk '{print $1}'; }
else
    fail 'neither sha256sum nor shasum is available'
fi
command -v jq >/dev/null 2>&1 || fail 'jq is required'

fake_bin="$temporary/fake-bin"
mkdir -p "$fake_bin"
cat > "$fake_bin/gh" <<'FAKE_GH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$GH_CALL_LOG"
[[ ${1-} == attestation && ${2-} == verify ]] || exit 91
[[ -f ${3-} ]] || exit 92
[[ " $* " == *' --format json '* ]] || exit 93
if [[ -n ${GH_MUTATE_PATH:-} ]]; then
    printf '%s' "$GH_MUTATE_CONTENT" > "$GH_MUTATE_PATH"
fi
cat "$GH_RESPONSE"
FAKE_GH
chmod +x "$fake_bin/gh"

write_manifest() {
    {
        printf '%s  %s\n' "$(sha256_file "$index")" "$(basename "$index")"
        printf '%s  %s\n' "$(sha256_file "$package")" "$(basename "$package")"
    } > "$manifest"
}

refresh_common_args() {
    local manifest_hash
    manifest_hash=$(sha256_file "$manifest")
    common_args=(
        --subject-manifest "$manifest"
        --subject-manifest-sha256 "$manifest_hash"
        --subject-dir "$release"
        --bundle "$bundle"
        --repository "$repository"
        --signer-workflow "$workflow"
        --source-digest "$source_digest"
        --source-ref "$source_ref"
    )
}

write_response() {
    local mode=${1:-exact}
    local run_uri=${2:-$invocation}
    local subjects
    subjects=$(jq -n \
        --arg index "$(basename "$index")" \
        --arg index_hash "$(sha256_file "$index")" \
        --arg package "$(basename "$package")" \
        --arg package_hash "$(sha256_file "$package")" \
        '[{"name":$index,"digest":{"sha256":$index_hash}},
          {"name":$package,"digest":{"sha256":$package_hash}}]')
    if [[ "$mode" == subset ]]; then
        subjects=$(jq '.[0:1]' <<< "$subjects")
    fi
    jq -n --arg run_uri "$run_uri" --argjson subjects "$subjects" \
        '[{verificationResult:{statement:{subject:$subjects},
          signature:{certificate:{runInvocationURI:$run_uri}}}}]' > "$fake_response"
}

new_fixture() {
    local name=$1
    fixture="$temporary/$name"
    release="$fixture/release"
    fake_response="$fixture/gh-response.json"
    call_log="$fixture/gh-calls.log"
    stderr_file="$fixture/stderr"
    manifest="$fixture/subjects.sha256"
    bundle="$fixture/provenance.jsonl"
    index="$release/index.json"
    package="$release/toolchain-linux-x86_64.tar.xz"
    repository='example-owner/example-repo'
    workflow="$repository/.github/workflows/release.yml"
    source_digest='0123456789abcdef0123456789abcdef01234567'
    source_ref='refs/tags/v1.2.3'
    run_id=123456789
    run_attempt=2
    invocation="https://github.com/$repository/actions/runs/$run_id/attempts/$run_attempt"
    mkdir -p "$release"
    printf '{"schema":"synthetic-index"}\n' > "$index"
    printf 'synthetic package bytes; not a release artifact\n' > "$package"
    printf 'synthetic bundle placeholder; fake gh does not verify it\n' > "$bundle"
    : > "$call_log"
    write_manifest
    write_response exact
    refresh_common_args
}

snapshot_inputs() {
    printf '%s\n' \
        "$(sha256_file "$manifest")" \
        "$(sha256_file "$bundle")" \
        "$(sha256_file "$index")" \
        "$(sha256_file "$package")"
}

gh_call_count() {
    wc -l < "$call_log" | tr -d '[:space:]'
}

run_verifier() {
    local target=$1
    local mutate_path=${2-}
    local mutate_content=${3-}
    shift 3
    PATH="$fake_bin:$PATH" GH_CALL_LOG="$call_log" GH_RESPONSE="$fake_response" \
        GH_MUTATE_PATH="$mutate_path" GH_MUTATE_CONTENT="$mutate_content" \
        "$verifier" "$@" --output "$target"
}

expect_pregh_failure() {
    local name=$1
    local diagnostic=$2
    shift 2
    local target="$fixture/$name-output.json"
    local calls_before
    local inputs_before
    local stdout=''
    calls_before=$(gh_call_count)
    inputs_before=$(snapshot_inputs)
    : > "$stderr_file"
    if stdout=$(run_verifier "$target" '' '' "$@" 2> "$stderr_file"); then
        fail "$name unexpectedly succeeded"
    fi
    [[ -z "$stdout" ]] || fail "$name emitted success-shaped stdout: $stdout"
    grep -Fq -- "$diagnostic" "$stderr_file" \
        || fail "$name missed expected diagnostic: $diagnostic"
    [[ ! -e "$target" && ! -L "$target" ]] \
        || fail "$name created output despite verification failure"
    [[ $(gh_call_count) == "$calls_before" ]] \
        || fail "$name called fake gh before rejecting input"
    [[ $(snapshot_inputs) == "$inputs_before" ]] \
        || fail "$name changed an input before rejecting it"
}

expect_postgh_failure() {
    local name=$1
    local diagnostic=$2
    shift 2
    local target="$fixture/$name-output.json"
    local calls_before
    local inputs_before
    local stdout=''
    calls_before=$(gh_call_count)
    inputs_before=$(snapshot_inputs)
    : > "$stderr_file"
    if stdout=$(run_verifier "$target" '' '' "$@" 2> "$stderr_file"); then
        fail "$name unexpectedly succeeded"
    fi
    [[ -z "$stdout" ]] || fail "$name emitted success-shaped stdout: $stdout"
    grep -Fq -- "$diagnostic" "$stderr_file" \
        || fail "$name missed expected diagnostic: $diagnostic"
    [[ ! -e "$target" && ! -L "$target" ]] \
        || fail "$name created output despite verification failure"
    [[ $(gh_call_count) == "$((calls_before + 1))" ]] \
        || fail "$name did not call fake gh exactly once"
    [[ $(snapshot_inputs) == "$inputs_before" ]] \
        || fail "$name changed an input during verification"
}

# A valid external manifest authenticates the complete subject set.
new_fixture valid
inputs_before=$(snapshot_inputs)
output="$fixture/verified.json"
if ! stdout=$(run_verifier "$output" '' '' "${common_args[@]}" \
    --run-id "$run_id" --run-attempt "$run_attempt" 2> "$stderr_file"); then
    cat "$stderr_file" >&2
    fail 'matching external manifest should pass policy verification'
fi
[[ "$stdout" == 'verified 2 signed release subjects' ]] \
    || fail "success summary is unexpected: $stdout"
cmp -s "$output" "$fake_response" || fail 'success output differs from fake-gh response'
[[ $(gh_call_count) == 1 ]] || fail 'success did not call fake gh exactly once'
[[ $(snapshot_inputs) == "$inputs_before" ]] || fail 'success changed an input'

# Raw hash, size, syntax, exact-set, and argument errors reject before fake gh.
new_fixture wrong-manifest-hash
bad_args=("${common_args[@]}")
bad_args[3]='0000000000000000000000000000000000000000000000000000000000000000'
expect_pregh_failure wrong-raw-hash 'subject manifest SHA-256 differs' "${bad_args[@]}"

new_fixture malformed-manifest-hash
bad_args=("${common_args[@]}")
bad_args[3]='not-a-sha256'
expect_pregh_failure malformed-hash 'subject manifest SHA-256 must be 64 lowercase hexadecimal characters' \
    "${bad_args[@]}"

new_fixture oversized-manifest
printf '%1048577s' '' > "$manifest"
refresh_common_args
expect_pregh_failure oversized 'subject manifest exceeds the 1 MiB limit' "${common_args[@]}"

new_fixture empty-manifest
: > "$manifest"
refresh_common_args
expect_pregh_failure empty 'checksum document has no attestation subjects' "${common_args[@]}"

new_fixture missing-final-lf
printf '%s  %s' "$(sha256_file "$index")" "$(basename "$index")" > "$manifest"
refresh_common_args
expect_pregh_failure missing-lf 'subject manifest must end with LF' "${common_args[@]}"

new_fixture nul-manifest
printf '%s  index\0.json\n' "$(sha256_file "$index")" > "$manifest"
refresh_common_args
expect_pregh_failure nul 'subject manifest contains NUL bytes' "${common_args[@]}"

new_fixture duplicate-subject
{
    printf '%s  %s\n' "$(sha256_file "$index")" "$(basename "$index")"
    printf '%s  %s\n' "$(sha256_file "$index")" "$(basename "$index")"
} > "$manifest"
refresh_common_args
expect_pregh_failure duplicate 'repeats subject' "${common_args[@]}"

new_fixture path-escape
printf '%s  ../escape\n' "$(sha256_file "$index")" > "$manifest"
refresh_common_args
expect_pregh_failure escape 'noncanonical entry' "${common_args[@]}"

new_fixture blank-entry
printf '\n' > "$manifest"
refresh_common_args
expect_pregh_failure blank 'noncanonical entry' "${common_args[@]}"

new_fixture wrong-subject-bytes
printf 'changed before verification\n' > "$package"
expect_pregh_failure wrong-bytes 'checksum subject digest differs' "${common_args[@]}"

new_fixture symlink-manifest
real_manifest="$fixture/real-subjects.sha256"
command mv "$manifest" "$real_manifest"
ln -s "$real_manifest" "$manifest"
refresh_common_args
expect_pregh_failure symlink-manifest 'subject manifest must be a regular file' "${common_args[@]}"

new_fixture symlink-subject
outside_subject="$fixture/outside-package"
command mv "$package" "$outside_subject"
ln -s "$outside_subject" "$package"
expect_pregh_failure symlink-subject 'checksum subject is not a regular file' "${common_args[@]}"

new_fixture symlink-root
symlink_release="$fixture/release-link"
ln -s "$release" "$symlink_release"
bad_args=("${common_args[@]}")
bad_args[5]="$symlink_release"
expect_pregh_failure symlink-root 'subject directory must be a regular directory' "${bad_args[@]}"

for suffix in '/' '/.' '/./'; do
    bad_args=("${common_args[@]}")
    bad_args[5]="$symlink_release$suffix"
    expect_pregh_failure "symlink-root-suffix-${#suffix}" \
        'subject directory must be a regular directory' "${bad_args[@]}"
done

new_fixture real-root-trailing-directory-suffix
bad_args=("${common_args[@]}")
bad_args[5]="$release/./"
inputs_before=$(snapshot_inputs)
output="$fixture/verified.json"
if ! stdout=$(run_verifier "$output" '' '' "${bad_args[@]}" 2> "$stderr_file"); then
    cat "$stderr_file" >&2
    fail 'real directory with trailing directory suffix should pass'
fi
[[ "$stdout" == 'verified 2 signed release subjects' ]] || fail 'real-root success summary differs'
cmp -s "$output" "$fake_response" || fail 'real-root output differs from fake-gh response'
[[ $(gh_call_count) == 1 ]] || fail 'real-root verification did not call fake gh exactly once'
[[ $(snapshot_inputs) == "$inputs_before" ]] || fail 'real-root verification changed an input'

new_fixture manifest-inside-release
command mv "$manifest" "$release/subjects.sha256"
manifest="$release/subjects.sha256"
refresh_common_args
expect_pregh_failure inside-release 'subject manifest must be outside the subject directory' "${common_args[@]}"

new_fixture includes-provenance
release_bundle="$release/provenance.jsonl"
command mv "$bundle" "$release_bundle"
bundle="$release_bundle"
{
    printf '%s  %s\n' "$(sha256_file "$index")" "$(basename "$index")"
    printf '%s  %s\n' "$(sha256_file "$package")" "$(basename "$package")"
    printf '%s  %s\n' "$(sha256_file "$bundle")" "$(basename "$bundle")"
} > "$manifest"
refresh_common_args
expect_pregh_failure includes-provenance 'must not include the provenance bundle' "${common_args[@]}"

new_fixture excluded-subject
expect_pregh_failure exclusion '--exclude-subject is not allowed' \
    "${common_args[@]}" --exclude-subject index.json

# Fake gh mutates only an isolated fixture. The verifier must reject both
# changes after the signed result has been returned and must leave output absent.
new_fixture changed-manifest-after-gh
inputs_before=$(snapshot_inputs)
changed_manifest_content=$(printf '%s  %s\n' "$(sha256_file "$package")" "$(basename "$package")")
target="$fixture/changed-manifest-output.json"
: > "$stderr_file"
stdout=''
if stdout=$(PATH="$fake_bin:$PATH" GH_CALL_LOG="$call_log" GH_RESPONSE="$fake_response" \
    GH_MUTATE_PATH="$manifest" GH_MUTATE_CONTENT="$changed_manifest_content" \
    "$verifier" "${common_args[@]}" --output "$target" 2> "$stderr_file"); then
    fail 'manifest mutation during fake gh unexpectedly succeeded'
fi
[[ -z "$stdout" ]] || fail 'manifest mutation emitted success-shaped stdout'
grep -Fq -- 'subject manifest changed during attestation verification' "$stderr_file" \
    || fail 'manifest mutation missed its post-gh diagnostic'
[[ ! -e "$target" && ! -L "$target" ]] || fail 'manifest mutation created output'
[[ $(gh_call_count) == 1 ]] || fail 'manifest mutation did not call fake gh exactly once'
[[ $(sha256_file "$manifest") != "$(printf '%s\n' "$inputs_before" | sed -n '1p')" ]] \
    || fail 'fake gh did not change the isolated manifest fixture'
[[ $(sha256_file "$bundle") == "$(printf '%s\n' "$inputs_before" | sed -n '2p')" ]] \
    || fail 'manifest mutation unexpectedly changed the bundle'
[[ $(sha256_file "$index") == "$(printf '%s\n' "$inputs_before" | sed -n '3p')" ]] \
    || fail 'manifest mutation unexpectedly changed the index'
[[ $(sha256_file "$package") == "$(printf '%s\n' "$inputs_before" | sed -n '4p')" ]] \
    || fail 'manifest mutation unexpectedly changed the package'

new_fixture changed-subject-after-gh
inputs_before=$(snapshot_inputs)
target="$fixture/changed-subject-output.json"
: > "$stderr_file"
stdout=''
if stdout=$(PATH="$fake_bin:$PATH" GH_CALL_LOG="$call_log" GH_RESPONSE="$fake_response" \
    GH_MUTATE_PATH="$package" GH_MUTATE_CONTENT='changed during fake gh' \
    "$verifier" "${common_args[@]}" --output "$target" 2> "$stderr_file"); then
    fail 'subject mutation during fake gh unexpectedly succeeded'
fi
[[ -z "$stdout" ]] || fail 'subject mutation emitted success-shaped stdout'
grep -Fq -- 'subject digest changed during attestation verification' "$stderr_file" \
    || fail 'subject mutation missed its post-gh diagnostic'
[[ ! -e "$target" && ! -L "$target" ]] || fail 'subject mutation created output'
[[ $(gh_call_count) == 1 ]] || fail 'subject mutation did not call fake gh exactly once'
[[ $(sha256_file "$manifest") == "$(printf '%s\n' "$inputs_before" | sed -n '1p')" ]] \
    || fail 'subject mutation unexpectedly changed the manifest'
[[ $(sha256_file "$bundle") == "$(printf '%s\n' "$inputs_before" | sed -n '2p')" ]] \
    || fail 'subject mutation unexpectedly changed the bundle'
[[ $(sha256_file "$index") == "$(printf '%s\n' "$inputs_before" | sed -n '3p')" ]] \
    || fail 'subject mutation unexpectedly changed the index'
[[ $(sha256_file "$package") != "$(printf '%s\n' "$inputs_before" | sed -n '4p')" ]] \
    || fail 'fake gh did not change the isolated package fixture'

new_fixture mismatched-verified-set
write_response subset
expect_postgh_failure signed-set 'signed provenance subjects do not exactly match' "${common_args[@]}"

new_fixture mismatched-run-attempt
wrong_invocation="https://github.com/$repository/actions/runs/999999999/attempts/$run_attempt"
write_response exact "$wrong_invocation"
expect_postgh_failure run-attempt 'verified certificate invocation differs from the selected run attempt' \
    "${common_args[@]}" --run-id "$run_id" --run-attempt "$run_attempt"

new_fixture partial-options
expect_pregh_failure partial 'usage:' \
    --subject-manifest "$manifest" --bundle "$bundle" \
    --repository "$repository" --signer-workflow "$workflow" \
    --source-digest "$source_digest" --source-ref "$source_ref"

new_fixture mixed-options
expect_pregh_failure mixed 'mutually exclusive' \
    "${common_args[@]}" --checksums "$fixture/nonexistent-SHA256SUMS"

new_fixture dangling-output
output="$fixture/dangling-output.json"
ln -s "$fixture/no-such-target" "$output"
calls_before=$(gh_call_count)
inputs_before=$(snapshot_inputs)
: > "$stderr_file"
if stdout=$(run_verifier "$output" '' '' "${common_args[@]}" 2> "$stderr_file"); then
    fail 'dangling output symlink unexpectedly succeeded'
fi
[[ -z "$stdout" ]] || fail 'dangling-output rejection emitted stdout'
grep -Fq -- 'refusing to overwrite verification output' "$stderr_file" \
    || fail 'dangling-output rejection missed its diagnostic'
[[ -L "$output" ]] || fail 'dangling output symlink was replaced'
[[ $(gh_call_count) == "$calls_before" ]] || fail 'dangling-output rejection called fake gh'
[[ $(snapshot_inputs) == "$inputs_before" ]] || fail 'dangling-output rejection changed an input'

printf 'subject-manifest provenance policy tests passed (synthetic fake-gh responses only)\n'
