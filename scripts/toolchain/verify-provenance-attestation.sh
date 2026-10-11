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
  (--checksums PATH | --subject-manifest PATH \
   --subject-manifest-sha256 SHA256 --subject-dir DIR) \
  --bundle PATH --repository OWNER/REPO \
  --signer-workflow OWNER/REPO/.github/workflows/WORKFLOW.yml \
  --source-digest GIT_COMMIT --source-ref GIT_REF --output PATH \
  [--exclude-subject BASENAME] [--run-id INTEGER --run-attempt INTEGER]
EOF
    exit 64
}

fail() {
    printf 'provenance inventory verification failed: %s\n' "$*" >&2
    exit 1
}

checksums=''
checksums_set=0
subject_manifest=''
subject_manifest_set=0
subject_manifest_sha256=''
subject_manifest_sha256_set=0
subject_dir_arg=''
subject_dir_set=0
bundle=''
repository=''
signer_workflow=''
source_digest=''
source_ref=''
output=''
exclude_subject=''
exclude_subject_set=0
run_id=''
run_attempt=''
run_selection_set=0

while (($#)); do
    case "$1" in
        --checksums) checksums_set=1; checksums=${2-}; shift 2 ;;
        --subject-manifest) subject_manifest_set=1; subject_manifest=${2-}; shift 2 ;;
        --subject-manifest-sha256)
            subject_manifest_sha256_set=1; subject_manifest_sha256=${2-}; shift 2 ;;
        --subject-dir) subject_dir_set=1; subject_dir_arg=${2-}; shift 2 ;;
        --bundle) bundle=${2-}; shift 2 ;;
        --repository) repository=${2-}; shift 2 ;;
        --signer-workflow) signer_workflow=${2-}; shift 2 ;;
        --source-digest) source_digest=${2-}; shift 2 ;;
        --source-ref) source_ref=${2-}; shift 2 ;;
        --output) output=${2-}; shift 2 ;;
        --exclude-subject) exclude_subject_set=1; exclude_subject=${2-}; shift 2 ;;
        --run-id) run_selection_set=1; run_id=${2-}; shift 2 ;;
        --run-attempt) run_selection_set=1; run_attempt=${2-}; shift 2 ;;
        --help|-h) usage ;;
        *) usage ;;
    esac
done

if [[ "$checksums_set" == 1 ]]; then
    [[ "$subject_manifest_set" == 0 && "$subject_manifest_sha256_set" == 0 \
        && "$subject_dir_set" == 0 ]] || fail 'checksum and subject-manifest modes are mutually exclusive'
    [[ -n "$checksums" ]] || usage
    subject_manifest_mode=0
else
    [[ "$subject_manifest_set" == 1 && "$subject_manifest_sha256_set" == 1 \
        && "$subject_dir_set" == 1 ]] || usage
    [[ -n "$subject_manifest" && -n "$subject_manifest_sha256" \
        && -n "$subject_dir_arg" ]] || usage
    [[ "$subject_manifest_sha256" =~ ^[0-9a-f]{64}$ ]] \
        || fail 'subject manifest SHA-256 must be 64 lowercase hexadecimal characters'
    [[ "$exclude_subject_set" == 0 ]] \
        || fail '--exclude-subject is not allowed with a subject manifest'
    subject_manifest_mode=1
fi
[[ -n "$bundle" && -n "$repository" ]] || usage
[[ -n "$signer_workflow" && -n "$source_digest" && -n "$source_ref" && -n "$output" ]] || usage
[[ "$repository" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]] \
    || fail 'repository must be OWNER/REPO'
[[ "$signer_workflow" == "$repository"/.github/workflows/*.yml ]] \
    || fail 'signer workflow must be a workflow in the stated repository'
[[ "$source_digest" =~ ^[0-9a-f]{40}$ ]] || fail 'source digest must be a lowercase Git SHA-1'
[[ "$source_ref" =~ ^refs/(heads|tags)/[A-Za-z0-9._/-]+$ ]] \
    || fail 'source ref is not a canonical Git branch or tag ref'
[[ "$subject_manifest_mode" == 1 || -z "$exclude_subject" \
    || "$exclude_subject" =~ ^[A-Za-z0-9._-]+$ ]] \
    || fail 'excluded subject must be a basename'
if [[ "$run_selection_set" == 1 ]]; then
    [[ "$run_id" =~ ^[1-9][0-9]*$ && "$run_attempt" =~ ^[1-9][0-9]*$ ]] \
        || fail 'run ID and attempt must both be positive canonical decimal integers'
fi
if [[ "$subject_manifest_mode" == 1 ]]; then
    [[ -f "$subject_manifest" && ! -L "$subject_manifest" ]] \
        || fail 'subject manifest must be a regular file'
    # -L follows a directory symlink when a slash or /. follows its name.
    # Remove only those trailing directory suffixes before checking the root;
    # do not lexically collapse .. across a potentially linked ancestor.
    while [[ "$subject_dir_arg" != '/' ]]; do
        case "$subject_dir_arg" in
            */) subject_dir_arg=${subject_dir_arg%/} ;;
            */.) subject_dir_arg=${subject_dir_arg%/.} ;;
            *) break ;;
        esac
    done
    [[ -d "$subject_dir_arg" && ! -L "$subject_dir_arg" ]] \
        || fail 'subject directory must be a regular directory'
else
    [[ -f "$checksums" && ! -L "$checksums" ]] \
        || fail 'checksum document must be a regular file'
fi
[[ -f "$bundle" && ! -L "$bundle" ]] || fail 'provenance bundle must be a regular file'
[[ ! -e "$output" && ! -L "$output" ]] \
    || fail "refusing to overwrite verification output: $output"

for tool in awk gh jq mktemp sort; do
    command -v "$tool" >/dev/null 2>&1 || fail "required command is unavailable: $tool"
done
if [[ "$subject_manifest_mode" == 1 ]]; then
    for tool in cmp cp tail tr wc; do
        command -v "$tool" >/dev/null 2>&1 || fail "required command is unavailable: $tool"
    done
fi
if command -v shasum >/dev/null 2>&1; then
    sha256_file() { shasum -a 256 "$1" | awk '{print $1}'; }
elif command -v sha256sum >/dev/null 2>&1; then
    sha256_file() { sha256sum "$1" | awk '{print $1}'; }
else
    fail 'neither shasum nor sha256sum is available'
fi

temporary=$(mktemp -d "${TMPDIR:-/tmp}/aros-provenance.XXXXXX")
trap 'command rm -rf -- "$temporary"' EXIT
expected_lines="$temporary/expected.jsonl"
expected_json="$temporary/expected.json"
verified_json="$temporary/verified.json"

declare -A seen=()
first_subject=''
excluded_seen=0
subject_count=0
subject_names=()
subject_hashes=()
if [[ "$subject_manifest_mode" == 1 ]]; then
    subject_dir=$(cd "$subject_dir_arg" && pwd -P)
    manifest_parent=$(cd "$(dirname "$subject_manifest")" && pwd -P) \
        || fail 'subject manifest parent directory is unavailable'
    manifest_path="$manifest_parent/$(basename "$subject_manifest")"
    if [[ "$subject_dir" == '/' || "$manifest_path" == "$subject_dir/"* ]]; then
        fail 'subject manifest must be outside the subject directory'
    fi

    manifest_size=$(wc -c < "$subject_manifest" | tr -d '[:space:]')
    [[ "$manifest_size" =~ ^[0-9]+$ ]] || fail 'could not measure subject manifest size'
    ((manifest_size <= 1048576)) || fail 'subject manifest exceeds the 1 MiB limit'
    [[ $(sha256_file "$subject_manifest") == "$subject_manifest_sha256" ]] \
        || fail 'subject manifest SHA-256 differs from the supplied digest'
    manifest_snapshot="$temporary/subject-manifest"
    command cp "$subject_manifest" "$manifest_snapshot"
    [[ $(sha256_file "$manifest_snapshot") == "$subject_manifest_sha256" ]] \
        || fail 'subject manifest changed while being read'
    snapshot_size=$(wc -c < "$manifest_snapshot" | tr -d '[:space:]')
    if [[ ! "$snapshot_size" =~ ^[0-9]+$ ]] || ((snapshot_size > 1048576)); then
        fail 'subject manifest exceeds the 1 MiB limit'
    fi
    manifest_without_nul="$temporary/subject-manifest-without-nul"
    LC_ALL=C tr -d '\000' < "$manifest_snapshot" > "$manifest_without_nul"
    cmp -s "$manifest_snapshot" "$manifest_without_nul" \
        || fail 'subject manifest contains NUL bytes'
    if ((snapshot_size > 0)); then
        final_newline_count=$(tail -c 1 "$manifest_snapshot" | wc -l | tr -d '[:space:]')
        [[ "$final_newline_count" == 1 ]] \
            || fail 'subject manifest must end with LF'
    fi
    inventory_file="$manifest_snapshot"
else
    checksum_dir=$(cd "$(dirname "$checksums")" && pwd -P)
    inventory_file="$checksums"
fi

while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^([0-9a-f]{64})\ \ ([A-Za-z0-9._-]+)$ ]] \
        || fail "checksum document has a noncanonical entry: $line"
    digest=${BASH_REMATCH[1]}
    subject=${BASH_REMATCH[2]}
    [[ "$subject" != SHA256SUMS ]] || fail 'checksum document must not self-reference'
    [[ -z ${seen[$subject]+x} ]] || fail "checksum document repeats subject: $subject"
    seen[$subject]=1
    if [[ "$subject_manifest_mode" == 1 ]]; then
        path="$subject_dir/$subject"
    else
        path="$checksum_dir/$subject"
    fi
    [[ -f "$path" && ! -L "$path" ]] || fail "checksum subject is not a regular file: $subject"
    if [[ "$subject_manifest_mode" == 1 && "$path" -ef "$bundle" ]]; then
        fail 'subject manifest must not include the provenance bundle'
    fi
    [[ $(sha256_file "$path") == "$digest" ]] || fail "checksum subject digest differs: $subject"
    if [[ "$subject" == "$exclude_subject" ]]; then
        excluded_seen=1
        continue
    fi
    printf '{"name":"%s","digest":{"sha256":"%s"}}\n' "$subject" "$digest" >> "$expected_lines"
    subject_names+=("$subject")
    subject_hashes+=("$digest")
    if [[ -z "$first_subject" ]]; then
        first_subject=$subject
    fi
    ((subject_count += 1))
done < "$inventory_file"

((subject_count > 0)) || fail 'checksum document has no attestation subjects'
if [[ -n "$exclude_subject" && "$excluded_seen" != 1 ]]; then
    fail "excluded subject is absent from checksum document: $exclude_subject"
fi
jq -s 'sort_by(.name)' "$expected_lines" > "$expected_json"

if [[ "$subject_manifest_mode" == 1 ]]; then
    gh_subject="$subject_dir/$first_subject"
else
    gh_subject="$checksum_dir/$first_subject"
fi
gh attestation verify "$gh_subject" \
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

if [[ -n "$run_id" ]]; then
    # This field comes from the verified Fulcio certificate, not the workflow-
    # controlled statement predicate. It binds this exact provider run attempt;
    # it does not authenticate an individual job or artifact upload by itself.
    invocation="https://github.com/$repository/actions/runs/$run_id/attempts/$run_attempt"
    jq -e --arg invocation "$invocation" '
        type == "array" and length > 0 and
        all(.[]; .verificationResult.signature.certificate.runInvocationURI == $invocation)
    ' "$verified_json" >/dev/null \
        || fail 'verified certificate invocation differs from the selected run attempt'
fi

if [[ "$subject_manifest_mode" == 1 ]]; then
    # The caller must keep this directory and manifest quiescent. These checks
    # detect ordinary changes during verification but do not make file reads
    # race-proof against a concurrent writer.
    [[ -d "$subject_dir_arg" && ! -L "$subject_dir_arg" \
        && -d "$subject_dir" && ! -L "$subject_dir" ]] \
        || fail 'subject directory changed during attestation verification'
    [[ $(cd "$subject_dir_arg" && pwd -P) == "$subject_dir" ]] \
        || fail 'subject directory changed during attestation verification'
    [[ -f "$subject_manifest" && ! -L "$subject_manifest" ]] \
        || fail 'subject manifest changed during attestation verification'
    manifest_size=$(wc -c < "$subject_manifest" | tr -d '[:space:]')
    if [[ ! "$manifest_size" =~ ^[0-9]+$ ]] || ((manifest_size > 1048576)); then
        fail 'subject manifest changed during attestation verification'
    fi
    if [[ $(sha256_file "$subject_manifest") != "$subject_manifest_sha256" ]] \
        || ! cmp -s "$manifest_snapshot" "$subject_manifest"; then
        fail 'subject manifest changed during attestation verification'
    fi
    for index in "${!subject_names[@]}"; do
        subject=${subject_names[$index]}
        path="$subject_dir/$subject"
        [[ -f "$path" && ! -L "$path" ]] \
            || fail "subject changed during attestation verification: $subject"
        [[ $(sha256_file "$path") == "${subject_hashes[$index]}" ]] \
            || fail "subject digest changed during attestation verification: $subject"
    done
fi

mkdir -p "$(dirname "$output")"
command mv "$verified_json" "$output"
printf 'verified %s signed release subjects\n' "$subject_count"
