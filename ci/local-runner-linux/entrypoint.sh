#!/bin/sh
# Persistent runner. The registration (.runner, .credentials, .credentials_rsaparams)
# lives in /home/ci/state, a volume, so a container restart or recreation keeps the
# runner registered. RUNNER_TOKEN (a short-lived registration token) is only
# needed for the first start; it is never stored in an image or in the repository.
set -eu
: "${RUNNER_NAME:?RUNNER_NAME is required}"
STATE=/home/ci/state
cd /home/ci/actions-runner
FILES=".runner .credentials .credentials_rsaparams"
if [ ! -s "$STATE/.runner" ]; then
    : "${RUNNER_TOKEN:?RUNNER_TOKEN is required for the first registration}"
    ./config.sh --unattended --replace \
        --url https://github.com/metaneutrons/aros-toolchains \
        --token "$RUNNER_TOKEN" --name "$RUNNER_NAME" \
        --labels aros-local,linux-x86_64 --work _work
    for f in $FILES; do mv "$f" "$STATE/$f"; done
fi
for f in $FILES; do ln -sf "$STATE/$f" "$f"; done
exec ./run.sh
