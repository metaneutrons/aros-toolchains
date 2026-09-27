#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo 'usage: seed-compatibility-zlib.sh LOCK CACHE_DIR SEED_ARCHIVE' >&2
  exit 2
fi

lock=$1
cache_dir=$2
seed=$3
entry=$(jq -ce '[.inputs[] | select(.id == "chromium-zlib-da752eb2")] | if length == 1 then .[0] else error("expected exactly one Chromium zlib input") end' "$lock")
filename=$(jq -er '.cache_filename' <<< "$entry")
expected_sha=$(jq -er '.sha256' <<< "$entry")
expected_size=$(jq -er '.size' <<< "$entry")

if [[ "$filename" != zlib.tar.gz || ! -f "$seed" || -L "$seed" || ! -d "$cache_dir" || -L "$cache_dir" ]]; then
  echo 'Chromium zlib seed has an unsafe path or the source lock changed' >&2
  exit 1
fi

actual_size=$(wc -c < "$seed" | tr -d ' ')
actual_sha=$(sha256sum "$seed" | cut -d ' ' -f 1)
if [[ "$actual_size" != "$expected_size" || "$actual_sha" != "$expected_sha" ]]; then
  echo 'Chromium zlib seed does not match the source lock size and SHA-256' >&2
  exit 1
fi

destination=$cache_dir/$filename
if [[ -e "$destination" || -L "$destination" ]]; then
  echo 'Chromium zlib cache destination must be absent before seeding' >&2
  exit 1
fi
install -m 0644 "$seed" "$destination"
if [[ "$(sha256sum "$destination" | cut -d ' ' -f 1)" != "$expected_sha" ]]; then
  echo 'Chromium zlib cache copy failed post-write verification' >&2
  exit 1
fi
echo 'Seeded lock-verified Chromium zlib source from repository snapshot'
