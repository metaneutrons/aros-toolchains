# AROS toolchains

[![Producer contracts](https://github.com/metaneutrons/aros-toolchains/actions/workflows/ci.yml/badge.svg)](https://github.com/metaneutrons/aros-toolchains/actions/workflows/ci.yml)
[![Releases](https://img.shields.io/github/v/release/metaneutrons/aros-toolchains?display_name=tag&include_prereleases&sort=semver)](https://github.com/metaneutrons/aros-toolchains/releases)
[![License: GPL-3.0-or-later](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)](LICENSE)

**The immutable AROS cross-toolchain release backend for
[`aros-tools`](https://github.com/metaneutrons/aros-tools).**

This repository produces, qualifies, and publishes the Clang/LLVM toolchain
archives that `aros-tools` installs and verifies. It is deliberately not a
second end-user CLI and not a fork of AROS. Keeping release engineering here
lets `aros-tools` remain a small, credential-free developer tool while this
repository owns the reviewed build recipe, supply-chain inputs, qualification
evidence, and immutable release assets.

> **Status:** release engineering is under active qualification. GitHub
> Releases contain immutable prerelease assets; a checkout may use an asset
> only when its reviewed `aros-toolchains.lock.toml` selects that exact
> release. Branch builds, workflow artifacts, and draft assets are never
> consumer channels.

## Start with `aros-tools`

For nearly every developer, `aros-tools` is the right entry point. It reads the
selected AROS checkout's lock, resolves the host and target profile, downloads
only the locked archive, and verifies the archive, manifest, payload tree, and
required executable layout before use.

After installing `aros-tools` and opening an AROS or AROS-NX checkout with a
reviewed toolchain lock:

```console
aros toolchain list
aros toolchain install --preset pc-x86_64
aros toolchain verify --preset pc-x86_64
aros toolchain path --preset pc-x86_64
```

Replace `pc-x86_64` with `arm-raspi` or `rpi-aarch64` as appropriate. The
commands fail closed when the checkout has no enabled artifact for the running
host and selected profile; they do not fall back to a host compiler or build a
compiler from source. See the [`aros-tools` installation guide](https://aros.metaneutrons.cc/aros-tools/getting-started/installation/)
and [toolchain command reference](https://aros.metaneutrons.cc/aros-tools/reference/cli/).

Direct archive consumption remains possible for downstream integrators, but it
is an advanced path: verify the release's `SHA256SUMS`, archive sidecar,
manifest, SBOM, provenance, and index before extracting anything. Do not use
unverified Actions artifacts or copy provisional data into a consumer lock.

## What is supported

The release schema has three target profiles:

| Profile | Target triple | Intended target | Notable capability |
| --- | --- | --- | --- |
| `pc-x86_64` | `x86_64-unknown-aros` | 64-bit PC AROS | C, C++, Objective-C, LLVM runtimes, and the matching i386 collector/runtime contract |
| `arm-raspi` | `arm-unknown-aros` | 32-bit Raspberry Pi AROS | hard-float C, C++, Objective-C, LLVM runtimes, and the collector |
| `rpi-aarch64` | `aarch64-unknown-aros` | 64-bit Raspberry Pi AROS | C, C++, Objective-C, LLVM runtimes, and the collector |

Current release qualification runs natively on the following build hosts:

| Build host | Status |
| --- | --- |
| Linux x86-64 | active |
| Linux ARM64 | active |
| macOS ARM64 | active |
| macOS x86-64 | deliberately suspended pending [issue #27](https://github.com/metaneutrons/aros-toolchains/issues/27) |

The schema retains macOS x86-64 identity so historical releases remain
describable, but it is not evidence for a current release. RISC-V is not a
released profile. The release index and a consumer's lock—not this table—are
authoritative for whether a specific host/profile archive is available.

## What a release proves

Each immutable release is a set of host-native compiler archives, not a full
AROS SDK or a bootable operating-system image. A release asset includes:

- Clang, Clang++, LLD, LLVM support tools, libc++, libc++abi, libunwind, and
  the AROS collector aliases required by its profile;
- a machine-readable `toolchain-manifest.json` and canonical payload-tree
  digest;
- an archive SHA-256 sidecar, release-wide `SHA256SUMS`, SPDX SBOMs, and a
  measured `toolchain-index-v1.json`; and
- GitHub/Sigstore provenance for the exact release workflow and tag.

The compiler prefix deliberately does **not** contain a target Developer
sysroot. Application and AROS builds supply a matching AROS Developer tree as
their sysroot. This separation lets the same host compiler work with reviewed
AROS-NX and upstream-compatible SDK contracts without conflating the two.

A release is published only after the active host/profile matrix has passed
independent normalized builds, byte-for-byte comparisons, relocation checks,
and AROS-NX plus upstream-AROS compatibility probes. If any gate fails, the
candidate remains unpublished and a later attempt uses a new immutable tag.

## Repository roles

| Repository | Owns | Does not own |
| --- | --- | --- |
| [`AROS-NX`](https://github.com/metaneutrons/AROS-NX) | AROS source, upstream-compatible patches, Configure/MetaMake rules, target runtime, and Developer sysroot | CLI distribution or release credentials |
| [`aros-tools`](https://github.com/metaneutrons/aros-tools) | the `aros` CLI, installation, verification, build workflows, diagnostics, and local toolchain candidates | release recipes, release publication, or toolchain-builder credentials |
| **`aros-toolchains`** | source locks, profiles, release workflows, deterministic producer inputs, qualification evidence, and immutable archives | a competing user-facing CLI or AROS source changes |

The dependency direction is intentional: `aros-tools` consumes a selected,
measured release; `aros-toolchains` builds it from exact AROS-NX and
`aros-tools` source identities. Neither repository silently substitutes a
branch name for an immutable identity.

## For contributors and release maintainers

Use this repository to change reviewed release inputs and policies—not to add
ordinary `aros` commands or modify AROS build semantics.

The offline contract suite needs the exact AROS source and `aros-tools`
checkouts selected by `toolchains/producer-executor-v1.toml`:

```console
AROS_TEST_SOURCE_ROOT=/path/to/AROS-NX \
AROS_TEST_TOOLS_ROOT=/path/to/aros-tools \
  scripts/toolchain/tests/test-producer.sh
```

This validates recipe, source-lock, patch, archive, deterministic-packaging,
relocation, and executor-identity contracts. It does not build a compiler.
The expensive active matrix is intentionally limited to an annotated
`toolchain-v1-*` release tag. Pull requests and ordinary merges never publish
assets; manual diagnostic producer runs are Linux-only and cannot stand in for
release qualification.

Before changing a lock, profile, workflow, or release schema, read the
[release contract](toolchains/README.md). It defines the fail-closed rules for
source acquisition, compatibility inputs, recovery, draft review, provenance,
and consumer promotion. [Migration provenance](docs/migration-provenance.md)
records the historical standalone-release boundary.

## Related resources

- [`aros-tools`](https://github.com/metaneutrons/aros-tools): user and
  developer CLI, including installation and command documentation.
- [AROS tools documentation](https://aros.metaneutrons.cc/aros-tools/):
  workflows for upstream AROS and AROS-NX.
- [GitHub Releases](https://github.com/metaneutrons/aros-toolchains/releases):
  the only canonical distribution channel for these archives.
- [`toolchains/README.md`](toolchains/README.md): complete release and
  recovery contract.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
