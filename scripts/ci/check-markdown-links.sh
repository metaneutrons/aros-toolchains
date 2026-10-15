#!/usr/bin/env bash
set -euo pipefail

readonly LYCHEE_VERSION="0.24.2"
readonly LYCHEE_ARCHIVE="lychee-x86_64-unknown-linux-gnu.tar.gz"
readonly LYCHEE_URL="https://github.com/lycheeverse/lychee/releases/download/lychee-v${LYCHEE_VERSION}/${LYCHEE_ARCHIVE}"
readonly LYCHEE_SHA256="1f4e0ef7f6554a6ed33dd7ac144fb2e1bbed98598e7af973042fc5cd43951c9a"

fail() {
  printf 'check-markdown-links: %s\n' "$*" >&2
  exit 1
}

if (( $# > 1 )); then
  fail "usage: $0 [repository-directory]"
fi

repository=${1:-$PWD}
[[ -d "$repository" ]] || fail "repository directory does not exist"

if ! repository=$(git -C "$repository" rev-parse --show-toplevel 2>/dev/null); then
  fail "repository directory is not inside a Git worktree"
fi
repository=$(cd -- "$repository" && pwd -P)

[[ "$(uname -s)" == "Linux" ]] || fail "the pinned lychee binary requires Linux"
[[ "$(uname -m)" == "x86_64" ]] || fail "the pinned lychee binary requires x86_64"

for command_name in curl find git mktemp shasum tar; do
  command -v "$command_name" >/dev/null 2>&1 || fail "required command is unavailable: $command_name"
done

temp_root=${RUNNER_TEMP:-${TMPDIR:-/tmp}}
[[ "$temp_root" == /* ]] || fail "temporary directory root must be an absolute path"
[[ -d "$temp_root" && -w "$temp_root" ]] || fail "temporary directory root is not writable"

if ! temp_dir=$(mktemp -d "${temp_root%/}/check-markdown-links.XXXXXXXX"); then
  fail "could not create a temporary directory"
fi
trap 'command rm -rf "$temp_dir"' EXIT

tracked_paths="$temp_dir/tracked-markdown.nul"
git -C "$repository" ls-files -z -- ':(glob)**/*.md' >"$tracked_paths" \
  || fail "could not enumerate tracked Markdown files"

markdown_files=()
while IFS= read -r -d '' relative_path; do
  absolute_path="$repository/$relative_path"
  [[ ! -L "$absolute_path" ]] || fail "tracked Markdown path is a symlink: $relative_path"
  [[ -f "$absolute_path" ]] || fail "tracked Markdown path is missing or not a regular file: $relative_path"
  markdown_files+=("$absolute_path")
done <"$tracked_paths"

(( ${#markdown_files[@]} > 0 )) || fail "the repository has no tracked Markdown files"

archive="$temp_dir/$LYCHEE_ARCHIVE"
extract_dir="$temp_dir/extracted"
candidate_paths="$temp_dir/lychee-candidates.nul"

curl \
  --fail \
  --location \
  --silent \
  --show-error \
  --retry 2 \
  --retry-delay 1 \
  --retry-max-time 90 \
  --connect-timeout 10 \
  --max-time 60 \
  --output "$archive" \
  "$LYCHEE_URL"

checksum_output=$(shasum -a 256 "$archive") || fail "could not calculate lychee archive checksum"
actual_sha256=${checksum_output%%[[:space:]]*}
[[ "$actual_sha256" == "$LYCHEE_SHA256" ]] \
  || fail "lychee archive checksum mismatch (expected $LYCHEE_SHA256)"

mkdir -p "$extract_dir"
tar -xzf "$archive" -C "$extract_dir"
find "$extract_dir" -type f -name lychee -print0 >"$candidate_paths"

lychee_binary=
while IFS= read -r -d '' candidate; do
  [[ -z "$lychee_binary" ]] || fail "lychee archive contains multiple binaries"
  lychee_binary=$candidate
done <"$candidate_paths"

[[ -n "$lychee_binary" && -x "$lychee_binary" ]] \
  || fail "lychee binary was not found in the verified archive"

printf 'Checking %d tracked Markdown files with lychee v%s.\n' \
  "${#markdown_files[@]}" "$LYCHEE_VERSION"

# GITHUB_TOKEN, if provided by the workflow, is consumed by lychee from the
# environment. Do not place it in arguments or print the environment.
"$lychee_binary" \
  --no-progress \
  --timeout 20 \
  --max-retries 1 \
  --max-concurrency 8 \
  --include-fragments=anchor-only \
  --root-dir "$repository" \
  "${markdown_files[@]}"
