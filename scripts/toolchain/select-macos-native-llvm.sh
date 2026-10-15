#!/usr/bin/env bash
# Select installed Homebrew LLVM tools before native prerequisite discovery.
# This does not install packages or replace the producer's strict tool probes.
set -euo pipefail

if [[ "${RUNNER_OS:-}" != macOS || -z "${GITHUB_PATH:-}" ]]; then
    echo "macOS LLVM selection requires a macOS runner and GITHUB_PATH" >&2
    exit 1
fi
llvm_prefix=$(brew --prefix llvm)
if [[ "$llvm_prefix" != /* || "$llvm_prefix" == *$'\n'* ||
      "$llvm_prefix" == *$'\r'* || ! -d "$llvm_prefix/bin" ]]; then
    echo "Homebrew did not resolve an absolute LLVM binary directory" >&2
    exit 1
fi
for tool in llvm-ar llvm-ranlib; do
    if [[ ! -x "$llvm_prefix/bin/$tool" ]]; then
        echo "installed Homebrew LLVM is missing executable $tool" >&2
        exit 1
    fi
    "$llvm_prefix/bin/$tool" --version
done
printf '%s/bin\n' "$llvm_prefix" >> "$GITHUB_PATH"
