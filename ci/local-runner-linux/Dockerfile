# Linux runner for metaneutrons/aros-toolchains (label aros-local, linux-x86_64).
# Host packages are those of AROS-NX scripts/ci/install-build-prerequisites.sh
# plus what the runner and the workflow need. The runner user has no sudo and the
# container gets no Docker socket: it only ever runs owner-dispatched workflows.
# Git is built from a digest-pinned release tarball because the planner calls
# `git --no-lazy-fetch` (Git 2.44 or newer) and Ubuntu 24.04 ships 2.43.
FROM ubuntu:24.04 AS git-build
ARG GIT_VERSION=2.56.1
ARG GIT_SHA256=f0b0bf89264b9bd2e1c640363e7529643989da76281600473c50745cd34a607f
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential ca-certificates curl libcurl4-openssl-dev libexpat1-dev libssl-dev xz-utils zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL -o /tmp/git.tar.xz "https://mirrors.edge.kernel.org/pub/software/scm/git/git-${GIT_VERSION}.tar.xz" \
    && echo "${GIT_SHA256}  /tmp/git.tar.xz" | sha256sum -c - \
    && tar -xJf /tmp/git.tar.xz -C /tmp \
    && make -C "/tmp/git-${GIT_VERSION}" -j"$(nproc)" prefix=/opt/git NO_GETTEXT=1 NO_TCLTK=1 NO_PERL=1 NO_PYTHON=1 NO_RUST=1 all \
    && make -C "/tmp/git-${GIT_VERSION}" prefix=/opt/git NO_GETTEXT=1 NO_TCLTK=1 NO_PERL=1 NO_PYTHON=1 NO_RUST=1 install

FROM ubuntu:24.04
ARG RUNNER_VERSION=2.338.2
ARG RUNNER_SHA256=baebf204307bac6193480852732f0aba2ae97b6c5597c244f4d5558390147c40
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        autoconf automake bison build-essential clang cmake flex gawk \
        libpng-dev libtool lld llvm make netpbm ninja-build patch python3 xz-utils \
        ca-certificates curl git jq gh libicu74 libssl3t64 libcurl4t64 libexpat1 tar gzip unzip \
    && rm -rf /var/lib/apt/lists/*
COPY --from=git-build /opt/git /opt/git
RUN useradd --create-home --uid 1001 ci \
    && mkdir -p /home/ci/state /home/ci/actions-runner/_work && chown -R ci:ci /home/ci
USER ci
WORKDIR /home/ci/actions-runner
RUN curl -fsSL -o runner.tgz "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz" \
    && echo "${RUNNER_SHA256}  runner.tgz" | sha256sum -c - \
    && tar -xzf runner.tgz && rm runner.tgz
# rustup is baked in with a pinned digest because the runner user cannot install
# packages. The workflow selects the exact Rust channel itself (rustup toolchain install).
ARG RUSTUP_VERSION=1.29.3
ARG RUSTUP_INIT_SHA256=b1c8cb14e30889e7e2999e6b69e62d9e9b9ffc0f4df8180564d306d9680e6c55
RUN curl -fsSL -o /tmp/rustup-init "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/x86_64-unknown-linux-gnu/rustup-init" \
    && echo "${RUSTUP_INIT_SHA256}  /tmp/rustup-init" | sha256sum -c - \
    && chmod +x /tmp/rustup-init \
    && /tmp/rustup-init -y --default-toolchain none --profile minimal --no-modify-path \
    && rm /tmp/rustup-init
ENV PATH=/opt/git/bin:/home/ci/.cargo/bin:$PATH
COPY --chown=ci:ci entrypoint.sh /home/ci/entrypoint.sh
ENTRYPOINT ["/home/ci/entrypoint.sh"]
