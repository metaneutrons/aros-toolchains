#!/bin/sh
# Register one ephemeral runner with a short-lived registration token, run one
# job and exit. RUNNER_TOKEN comes from the environment at start, never from an
# image or a file in the repository.
set -eu
: "${RUNNER_TOKEN:?RUNNER_TOKEN is required}"
: "${RUNNER_NAME:?RUNNER_NAME is required}"
cd /home/ci/actions-runner
./config.sh --unattended --ephemeral --replace \
    --url https://github.com/metaneutrons/aros-toolchains \
    --token "$RUNNER_TOKEN" --name "$RUNNER_NAME" \
    --labels aros-local,linux-x86_64 --work _work
exec ./run.sh
