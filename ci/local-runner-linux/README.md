# Linux runner on a UGOS NAS

A persistent runner for `metaneutrons/aros-toolchains` (labels `aros-local`,
`linux-x86_64`). The registration lives in the `runner-state` volume, so restarts
and recreation keep the runner registered. UGOS hosts are managed with
`ugos-cli`, not with `docker compose` on the NAS.

First deployment (host `kirk`; use `picard` and `aros-toolchains-picard` for the other NAS):

```bash
export UGOS_HOST=kirk.schmieder.eu
docker build --platform linux/amd64 -t aros-toolchains-runner:local ci/local-runner-linux
docker save aros-toolchains-runner:local | gzip > runner.tar.gz
ugos-cli fs mkdir /volume1/docker/github-runner-aros-image
ugos-cli fs put runner.tar.gz /volume1/docker/github-runner-aros-image
ugos-cli docker load-path /volume1/docker/github-runner-aros-image/runner.tar.gz
# Render compose.yaml: replace ${RUNNER_NAME} and ${RUNNER_TOKEN:-} (token from
#   gh api -X POST repos/metaneutrons/aros-toolchains/actions/runners/registration-token --jq .token)
ugos-cli docker project-create github-runner-aros --file docker-compose.yaml
ugos-cli docker project-start github-runner-aros
```

Afterwards run `project-update` with the token removed from the file. The token
is single-use and expires after an hour; the registration stays in the volume.
