#!/bin/sh
set -eu

if [ "${1:-}" = "--version" ]; then
    echo "AROS-NG producer probe mock 1"
    exit 0
fi

output=
while [ "$#" -gt 0 ]; do
    if [ "$1" = "-o" ] && [ "$#" -ge 2 ]; then
        output=$2
        shift 2
    else
        shift
    fi
done

if [ -z "$output" ]; then
    echo "mock tool: missing -o" >&2
    exit 2
fi
printf 'AROS-NG deterministic relocation probe\n' > "$output"
