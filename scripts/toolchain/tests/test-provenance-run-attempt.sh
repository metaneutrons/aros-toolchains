#!/usr/bin/env bash
# Policy tests only: fake gh output exercises the verifier's joins, not the
# cryptographic validity or provenance of a real GitHub attestation.
set -euo pipefail
umask 077

script_dir=$(cd "$(dirname "$0")" && pwd -P)
source_root=$(cd "$script_dir/../../.." && pwd -P)
verifier="$source_root/scripts/toolchain/verify-provenance-attestation.sh"
temporary=$(mktemp -d "${TMPDIR:-/tmp}/aros-provenance-run-attempt.XXXXXX")
trap 'command rm -rf -- "$temporary"' EXIT

fail() {
    printf 'run-attempt policy test failed: %s\n' "$*" >&2
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

fixture="$temporary/release"
fake_bin="$temporary/fake-bin"
mkdir -p "$fixture" "$fake_bin"
checksums="$fixture/SHA256SUMS"
bundle="$fixture/provenance.jsonl"
index="$fixture/index.json"
package="$fixture/toolchain-linux-x86_64.tar.xz"
call_log="$temporary/gh-calls.log"
response="$temporary/gh-response.json"
stderr_file="$temporary/stderr"
output="$temporary/verified.json"
repository='example-owner/example-repo'
workflow="$repository/.github/workflows/release.yml"
source_digest='0123456789abcdef0123456789abcdef01234567'
source_ref='refs/tags/v1.2.3'
run_id=123456789
run_attempt=2
invocation="https://github.com/$repository/actions/runs/$run_id/attempts/$run_attempt"

printf '{"schema":"synthetic-index"}\n' > "$index"
printf 'synthetic package bytes; not a release artifact\n' > "$package"
printf 'synthetic bundle placeholder; fake gh does not verify it\n' > "$bundle"
{
    printf '%s  %s\n' "$(sha256_file "$index")" "$(basename "$index")"
    printf '%s  %s\n' "$(sha256_file "$package")" "$(basename "$package")"
} > "$checksums"
: > "$call_log"

cat > "$fake_bin/gh" <<'FAKE_GH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$GH_CALL_LOG"
[[ ${1-} == attestation && ${2-} == verify ]] || exit 91
[[ " $* " == *' --format json '* ]] || exit 92
cat "$GH_RESPONSE"
FAKE_GH
chmod +x "$fake_bin/gh"

write_verified_response() {
    local run_uri=${1-}
    local second_run_uri=${2-}
    local certificate_mode=${3:-present}
    local predicate_run_uri=${4-}
    local subjects
    subjects=$(jq -n \
        --arg index "$(basename "$index")" \
        --arg index_hash "$(sha256_file "$index")" \
        --arg package "$(basename "$package")" \
        --arg package_hash "$(sha256_file "$package")" \
        '[{"name":$index,"digest":{"sha256":$index_hash}},
          {"name":$package,"digest":{"sha256":$package_hash}}]')
    jq -n \
        --arg run_uri "$run_uri" \
        --arg second_run_uri "$second_run_uri" \
        --arg mode "$certificate_mode" \
        --arg predicate_run_uri "$predicate_run_uri" \
        --argjson subjects "$subjects" '
        def result($uri; $mode):
            {verificationResult: {
                statement: {
                    subject: $subjects,
                    predicate: {runInvocationURI: $predicate_run_uri}
                }
            }}
            + (if $mode == "missing" then {} else {
                verificationResult: {
                    statement: {
                        subject: $subjects,
                        predicate: {runInvocationURI: $predicate_run_uri}
                    },
                    signature: {certificate:
                        (if $mode == "missing-uri" then {} else {runInvocationURI: $uri} end)
                    }
                }
            } end);
        if $mode == "mixed" then [result($run_uri; "present"), result($second_run_uri; "present")]
        else [result($run_uri; $mode)] end
    ' > "$response"
}

snapshot_inputs() {
    printf '%s\n' \
        "$(sha256_file "$checksums")" \
        "$(sha256_file "$bundle")" \
        "$(sha256_file "$index")" \
        "$(sha256_file "$package")"
}

assert_inputs_unchanged() {
    [[ $(snapshot_inputs) == "$inputs_before" ]] \
        || fail 'verifier changed checksum, bundle, or subject inputs'
}

gh_call_count() {
    wc -l < "$call_log" | tr -d '[:space:]'
}

common_args=(
    --checksums "$checksums"
    --bundle "$bundle"
    --repository "$repository"
    --signer-workflow "$workflow"
    --source-digest "$source_digest"
    --source-ref "$source_ref"
)

expect_run_attempt_failure() {
    local name=$1
    local selected_run=$2
    local selected_attempt=$3
    local expected_diagnostic=$4
    local target="$temporary/$name-output.json"
    local calls_before
    calls_before=$(gh_call_count)
    : > "$stderr_file"
    local stdout=''
    if stdout=$(PATH="$fake_bin:$PATH" GH_CALL_LOG="$call_log" GH_RESPONSE="$response" \
        "$verifier" "${common_args[@]}" \
        --run-id "$selected_run" --run-attempt "$selected_attempt" \
        --output "$target" 2> "$stderr_file"); then
        fail "$name unexpectedly succeeded"
    fi
    [[ -z "$stdout" ]] || fail "$name emitted success-shaped stdout: $stdout"
    grep -Fq "$expected_diagnostic" "$stderr_file" \
        || fail "$name missed expected diagnostic: $expected_diagnostic"
    [[ ! -e "$target" ]] || fail "$name created output despite verification failure"
    [[ $(gh_call_count) == "$calls_before" ]] || fail "$name called fake gh before rejecting arguments"
    assert_inputs_unchanged
}

expect_verified_certificate_failure() {
    local name=$1
    local expected_diagnostic='verified certificate invocation differs from the selected run attempt'
    local target="$temporary/$name-output.json"
    local calls_before
    calls_before=$(gh_call_count)
    : > "$stderr_file"
    local stdout=''
    if stdout=$(PATH="$fake_bin:$PATH" GH_CALL_LOG="$call_log" GH_RESPONSE="$response" \
        "$verifier" "${common_args[@]}" \
        --run-id "$run_id" --run-attempt "$run_attempt" \
        --output "$target" 2> "$stderr_file"); then
        fail "$name unexpectedly succeeded"
    fi
    [[ -z "$stdout" ]] || fail "$name emitted success-shaped stdout: $stdout"
    grep -Fq "$expected_diagnostic" "$stderr_file" \
        || fail "$name missed expected diagnostic: $expected_diagnostic"
    [[ ! -e "$target" ]] || fail "$name created output despite certificate mismatch"
    [[ $(gh_call_count) == "$((calls_before + 1))" ]] \
        || fail "$name did not call fake gh exactly once"
    assert_inputs_unchanged
}

inputs_before=$(snapshot_inputs)

# Exact subject coverage plus the requested provider run attempt succeeds.
write_verified_response "$invocation"
if ! stdout=$(PATH="$fake_bin:$PATH" GH_CALL_LOG="$call_log" GH_RESPONSE="$response" \
    "$verifier" "${common_args[@]}" --run-id "$run_id" \
    --run-attempt "$run_attempt" --output "$output" 2> "$stderr_file"); then
    cat "$stderr_file" >&2
    fail 'matching run and attempt should pass policy verification'
fi
[[ "$stdout" == 'verified 2 signed release subjects' ]] \
    || fail "success summary is unexpected: $stdout"
cmp -s "$output" "$response" || fail 'success output is not the verified fake-gh response'
[[ $(gh_call_count) == 1 ]] || fail 'successful verification did not call fake gh exactly once'
assert_inputs_unchanged

# Certificate invocation URI is checked, not a similarly named workflow
# statement predicate. Every verified result must bind the selected attempt.
write_verified_response "https://github.com/$repository/actions/runs/999999999/attempts/$run_attempt"
expect_verified_certificate_failure wrong-run
write_verified_response "https://github.com/$repository/actions/runs/$run_id/attempts/3"
expect_verified_certificate_failure wrong-attempt
write_verified_response '' '' missing
expect_verified_certificate_failure missing-certificate
write_verified_response '' '' missing-uri "$invocation"
expect_verified_certificate_failure predicate-uri-only
write_verified_response "$invocation" "https://github.com/$repository/actions/runs/$run_id/attempts/3" mixed
expect_verified_certificate_failure mixed-certificates

# Paired values are validated before invoking the provider CLI.
write_verified_response "$invocation"
expect_run_attempt_failure run-id-only "$run_id" '' \
    'run ID and attempt must both be positive canonical decimal integers'
expect_run_attempt_failure attempt-only '' "$run_attempt" \
    'run ID and attempt must both be positive canonical decimal integers'
expect_run_attempt_failure explicit-empty-pair '' '' \
    'run ID and attempt must both be positive canonical decimal integers'
expect_run_attempt_failure zero-run 0 1 \
    'run ID and attempt must both be positive canonical decimal integers'
expect_run_attempt_failure zero-attempt 1 0 \
    'run ID and attempt must both be positive canonical decimal integers'
expect_run_attempt_failure leading-zero 01 2 \
    'run ID and attempt must both be positive canonical decimal integers'
expect_run_attempt_failure non-decimal 1x 2 \
    'run ID and attempt must both be positive canonical decimal integers'

# A pre-existing output is preserved, and rejection occurs before fake gh.
existing_output="$temporary/existing-output.json"
printf 'preserve this file\n' > "$existing_output"
existing_digest=$(sha256_file "$existing_output")
calls_before=$(gh_call_count)
: > "$stderr_file"
if stdout=$(PATH="$fake_bin:$PATH" GH_CALL_LOG="$call_log" GH_RESPONSE="$response" \
    "$verifier" "${common_args[@]}" --run-id "$run_id" \
    --run-attempt "$run_attempt" --output "$existing_output" 2> "$stderr_file"); then
    fail 'existing output path unexpectedly succeeded'
fi
[[ -z "$stdout" ]] || fail "existing-output rejection emitted stdout: $stdout"
grep -Fq 'refusing to overwrite verification output' "$stderr_file" \
    || fail 'existing-output rejection missed its diagnostic'
[[ $(sha256_file "$existing_output") == "$existing_digest" ]] \
    || fail 'existing output was overwritten'
[[ $(gh_call_count) == "$calls_before" ]] || fail 'existing-output rejection called fake gh'
assert_inputs_unchanged

printf 'run-attempt provenance policy tests passed (synthetic fake-gh responses only)\n'
