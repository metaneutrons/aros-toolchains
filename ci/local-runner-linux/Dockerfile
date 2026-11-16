# Linux runner for metaneutrons/aros-toolchains (label aros-local, linux-x86_64).
# Host packages are those of AROS-NX scripts/ci/install-build-prerequisites.sh
# plus what the runner and the workflow need. The runner user has no sudo and the
# container gets no Docker socket: it only ever runs owner-dispatched workflows.
FROM ubuntu:24.04
ARG RUNNER_VERSION=2.338.2
ARG RUNNER_SHA256=baebf204307bac6193480852732f0aba2ae97b6c5597c244f4d5558390147c40
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        autoconf automake bison build-essential clang cmake flex gawk \
        libpng-dev libtool lld llvm make netpbm ninja-build patch python3 xz-utils \
        ca-certificates curl git jq gh libicu74 libssl3t64 tar gzip unzip \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --create-home --uid 1001 ci \
    && mkdir -p /home/ci/state /home/ci/actions-runner/_work && chown -R ci:ci /home/ci
USER ci
WORKDIR /home/ci/actions-runner
RUN curl -fsSL -o runner.tgz "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz" \
    && echo "${RUNNER_SHA256}  runner.tgz" | sha256sum -c - \
    && tar -xzf runner.tgz && rm runner.tgz
COPY --chown=ci:ci entrypoint.sh /home/ci/entrypoint.sh
ENTRYPOINT ["/home/ci/entrypoint.sh"]
