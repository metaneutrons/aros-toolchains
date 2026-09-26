# AROS Toolchains

[![Producer contracts](https://github.com/metaneutrons/aros-toolchains/actions/workflows/ci.yml/badge.svg)](https://github.com/metaneutrons/aros-toolchains/actions/workflows/ci.yml)

**Verified AROS cross-toolchain releases, built with
[`aros-tools`](https://github.com/metaneutrons/aros-tools).**

Most developers should start with [`aros-tools`](https://github.com/metaneutrons/aros-tools),
the user-facing `aros` CLI. This repository contains the pinned inputs and
qualification pipeline that turn its native toolchain builds into downloadable
releases. It contains neither a second compiler implementation nor AROS
source code.

[Install `aros-tools`](https://aros.metaneutrons.cc/aros-tools/getting-started/installation/) ·
[Toolchain guide](https://aros.metaneutrons.cc/aros-tools/workflows/toolchains/) ·
[Releases](https://github.com/metaneutrons/aros-toolchains/releases) ·
[Producer contract](toolchains/README.md)

## Which repository do I need?

| Component | Responsibility |
| --- | --- |
| [Upstream AROS](https://github.com/aros-development-team/AROS) or [AROS-NX](https://github.com/metaneutrons/AROS-NX) | Supplies the operating-system source, build rules, and matching Developer sysroot. A checkout may pin a released compiler in `aros-toolchains.lock.toml`. |
| [`aros-tools`](https://github.com/metaneutrons/aros-tools) | Supplies the `aros` command to build, install, and verify a toolchain. |
| **This repository** | Pins the producer inputs, runs independent build and compatibility checks, and publishes measured archives. |

The producer runs a verified, pinned `aros-tools` executable against exact
AROS and `aros-tools` source revisions. A new CLI version does not
automatically publish new toolchains. Consumer locks change only through a
separate reviewed update.

## Install from a reviewed AROS checkout

Install `aros-tools`, then run these commands inside an AROS checkout with a
reviewed toolchain lock:

```console
aros toolchain list
aros toolchain install --preset pc-x86_64
aros toolchain verify --preset pc-x86_64
aros toolchain path --preset pc-x86_64
```

Use `arm-raspi` or `rpi-aarch64` in place of `pc-x86_64` when the lock enables
that profile on your host. A pristine upstream checkout has no release lock;
the [upstream AROS guide](https://aros.metaneutrons.cc/aros-tools/workflows/upstream-aros/)
explains how to build an explicit local toolchain instead.

`aros-tools` selects the declared host and profile, checks the archive and
manifest, and verifies the installed prefix. An unpinned “latest” download or
an Actions artifact is not a substitute for the checkout's lock.

## Release matrix

The release workflow currently qualifies three **build hosts** and three
**AROS target profiles**:

| Build host | `pc-x86_64` | `arm-raspi` | `rpi-aarch64` |
| --- | :---: | :---: | :---: |
| Linux x86-64 | Yes | Yes | Yes |
| Linux AArch64 | Yes | Yes | Yes |
| macOS AArch64 | Yes | Yes | Yes |

macOS Intel and RISC-V are not release targets. The published index and
consumer lock determine actual availability; the table describes the
qualification matrix, not a promise that every checkout enables every
profile. Each release records its exact assets, checksums, SBOMs, and
provenance.

Each archive contains host-native Clang/LLVM tools, the AROS collector, C++
runtimes, and a machine-readable manifest. A matching Developer sysroot still
comes from the AROS build. These archives are not bootable images or complete
SDKs.

## How a release is made

[Release Please](https://github.com/googleapis/release-please-action) prepares
the version and changelog pull request. It never creates a tag or publishes a
GitHub Release. After review and merge, one new annotated tag on the exact
producer commit starts the full qualification:

1. Pin exact AROS, producer, and `aros-tools` commits and source trees.
2. Build each of the nine host/profile combinations twice and compare bytes.
3. Run compatibility and relocation checks, then assemble a draft with a
   closed asset inventory, checksums, SBOMs, and provenance.
4. Independently inspect the complete draft before publishing it unchanged.

Stable tags use `vMAJOR.MINOR.PATCH`; candidates use
`vMAJOR.MINOR.PATCH-rc.N`. Product version `v0.1.0` and artifact schema
`v1` describe different things. Failed candidates keep their tag and cannot
be repaired in place. Branch and manual runs are non-publishing diagnostics.
See the [producer contract](toolchains/README.md) for exact gates and recovery
rules.

## Contributing

Changes to AROS source semantics belong in AROS or AROS-NX; changes to the
`aros` CLI belong in `aros-tools`. Contribute here when the release recipe,
locked inputs, compatibility evidence or publication policy needs to change.

Pull requests run the producer contract suite. To run it locally, supply a
checkout matching the pinned AROS source contract:

```console
AROS_TEST_SOURCE_ROOT=/absolute/path/to/AROS-NX \
  scripts/toolchain/tests/test-producer.sh
```

This offline suite checks producer contracts. It does not run the costly
compiler matrix; that is reserved for a release tag. Source locks, profiles,
and schemas live in [`toolchains/`](toolchains/README.md); workflows and
contract tests live in [`.github/workflows/`](.github/workflows/ci.yml) and
[`scripts/toolchain/`](scripts/toolchain/).

## License

This repository contains the [AROS Public License 1.1](LICENSE). Consult the
licenses recorded in each release's SPDX SBOM for its included components.
