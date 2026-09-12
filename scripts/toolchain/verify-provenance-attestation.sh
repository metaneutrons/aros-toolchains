#!/usr/bin/env bash
# Verify one signed, checksum-addressed release inventory without relying on
# GitHub's eventually-consistent attestation lookup API. The provenance bundle
# signs every subject in the pre-attestation checksum document; the caller's
# final inventory separately checksums the bundle itself to avoid recursion.
set -euo pipefail
umask 077

usage() {
    cat >&2 <<'EOF'
usage: verify-provenance-attestation.sh \
  --checksums PATH --bundle PATH --repository OWNER/REPO \
  --signer-workflow OWNER/REPO/.github/workflows/WORKFLOW.yml \
  --source-digest GIT_COMMIT --source-ref GIT_REF --output PATH \
  [--exclude-subject BASENAME]
EOF
    exit 64
}

fail() {
    printf 'provenance inventory verification failed: %s\n' "$*" >&2
    exit 1
}

checksums=''
bundle=''
repository=''
signer_workflow=''
source_digest=''
source_ref=''
output=''
exclude_subject=''

while (($#)); do
    case "$1" in
        --checksums) checksums=${2-}; shift 2 ;;
        --bundle) bundle=${2-}; shift 2 ;;
        --repository) repository=${2-}; shift 2 ;;
        --signer-workflow) signer_workflow=${2-}; shift 2 ;;
        --source-digest) source_digest=${2-}; shift 2 ;;
        --source-ref) source_ref=${2-}; shift 2 ;;
        --output) output=${2-}; shift 2 ;;
        --exclude-subject) exclude_subject=${2-}; shift 2 ;;
        --help|-h) usage ;;
        *) usage ;;
    esac
done

[[ -n "$checksums" && -n "$bundle" && -n "$repository" ]] || usage
[[ -n "$signer_workflow" && -n "$source_digest" && -n "$source_ref" && -n "$output" ]] || usage
[[ "$repository" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]] \
    || fail 'repository must be OWNER/REPO'
[[ "$signer_workflow" == "$repository"/.github/workflows/*.yml ]] \
    || fail 'signer workflow must be a workflow in the stated repository'
[[ "$source_digest" =~ ^[0-9a-f]{40}$ ]] || fail 'source digest must be a lowercase Git SHA-1'
[[ "$source_ref" =~ ^refs/(heads|tags)/[A-Za-z0-9._/-]+$ ]] \
    || fail 'source ref is not a canonical Git branch or tag ref'
[[ -z "$exclude_subject" || "$exclude_subject" =~ ^[A-Za-z0-9._-]+$ ]] \
    || fail 'excluded subject must be a basename'
[[ -f "$checksums" && ! -L "$checksums" ]] || fail 'checksum document must be a regular file'
[[ -f "$bundle" && ! -L "$bundle" ]] || fail 'provenance bundle must be a regular file'
[[ ! -e "$output" ]] || fail "refusing to overwrite verification output: $output"

for tool in awk gh jq mktemp sort; do
    command -v "$tool" >/dev/null 2>&1 || fail "required command is unavailable: $tool"
done
if command -v shasum >/dev/null 2>&1; then
    sha256_file() { shasum -a 256 "$1" | awk '{print $1}'; }
elif command -v sha256sum >/dev/null 2>&1; then
    sha256_file() { sha256sum "$1" | awk '{print $1}'; }
else
    fail 'neither shasum nor sha256sum is available'
fi

checksum_dir=$(cd "$(dirname "$checksums")" && pwd -P)
temporary=$(mktemp -d "${TMPDIR:-/tmp}/aros-provenance.XXXXXX")
trap 'command rm -rf -- "$temporary"' EXIT
expected_lines="$temporary/expected.jsonl"
expected_json="$temporary/expected.json"
verified_json="$temporary/verified.json"

declare -A seen=()
first_subject=''
excluded_seen=0
subject_count=0
while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^([0-9a-f]{64})\ \ ([A-Za-z0-9._-]+)$ ]] \
        || fail "checksum document has a noncanonical entry: $line"
    digest=${BASH_REMATCH[1]}
    subject=${BASH_REMATCH[2]}
    [[ "$subject" != SHA256SUMS ]] || fail 'checksum document must not self-reference'
    [[ -z ${seen[$subject]+x} ]] || fail "checksum document repeats subject: $subject"
    seen[$subject]=1
    path="$checksum_dir/$subject"
    [[ -f "$path" && ! -L "$path" ]] || fail "checksum subject is not a regular file: $subject"
    [[ $(sha256_file "$path") == "$digest" ]] || fail "checksum subject digest differs: $subject"
    if [[ "$subject" == "$exclude_subject" ]]; then
        excluded_seen=1
        continue
    fi
    printf '{"name":"%s","digest":{"sha256":"%s"}}\n' "$subject" "$digest" >> "$expected_lines"
    if [[ -z "$first_subject" ]]; then
        first_subject=$subject
    fi
    ((subject_count += 1))
done < "$checksums"

((subject_count > 0)) || fail 'checksum document has no attestation subjects'
if [[ -n "$exclude_subject" && "$excluded_seen" != 1 ]]; then
    fail "excluded subject is absent from checksum document: $exclude_subject"
fi
jq -s 'sort_by(.name)' "$expected_lines" > "$expected_json"

gh attestation verify "$checksum_dir/$first_subject" \
    --bundle "$bundle" \
    --repo "$repository" \
    --signer-workflow "$signer_workflow" \
    --source-digest "$source_digest" \
    --source-ref "$source_ref" \
    --deny-self-hosted-runners \
    --format json > "$verified_json"

jq -e --slurpfile expected "$expected_json" '
    type == "array" and length > 0 and
    ([.[] | .verificationResult.statement.subject[]? |
        {name: .name, digest: .digest}] | unique | sort_by(.name)) == $expected[0]
' "$verified_json" >/dev/null \
    || fail 'signed provenance subjects do not exactly match the checksum inventory'

mkdir -p "$(dirname "$output")"
command mv "$verified_json" "$output"
printf 'verified %s signed release subjects\n' "$subject_count"
