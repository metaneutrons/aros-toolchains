#!/usr/bin/env bash
# Check, without installing anything, that a local self-hosted runner has the
# host packages the source-owned install-build-prerequisites.sh would install.
# The package lists are read from that script, so they cannot drift from it.
# Local runners run as an unprivileged user that owns neither Homebrew nor apt.
set -euo pipefail
script=${1:?path to install-build-prerequisites.sh}
missing=()
case "${RUNNER_OS:-}" in
    macOS)
        packages=$(sed -n '/brew install/,/[^\\]$/p' "$script" | sed 's/brew install//; s/\\$//' | tr -s ' \n' ' ')
        # brew itself needs write access to its locks even for queries, so read the
        # install prefix directly instead of calling it.
        prefix=$(cd "$(dirname "$(command -v brew)")/.." && pwd -P)
        for package in $packages; do
            [[ -d "$prefix/opt/$package" ]] || missing+=("$package")
        done
        bison_prefix="$prefix/opt/bison"
        [[ -x "$bison_prefix/bin/bison" ]] || missing+=("bison-binary")
        printf '%s/bin\n' "$bison_prefix" >> "${GITHUB_PATH:?GITHUB_PATH is required}"
        ;;
    Linux)
        packages=$(sed -n '/apt-get install/,/[^\\]$/p' "$script" | sed 's/.*apt-get install//; s/-y --no-install-recommends//; s/\\$//' | tr -s ' \n' ' ')
        for package in $packages; do
            dpkg -s "$package" >/dev/null 2>&1 || missing+=("$package")
        done
        ;;
    *) printf 'unsupported runner OS: %s\n' "${RUNNER_OS:-<unset>}" >&2; exit 64;;
esac
if (( ${#missing[@]} )); then
    printf 'Missing host prerequisites on this local runner: %s\n' "${missing[*]}" >&2
    exit 1
fi
printf 'Host prerequisites present.\n'
