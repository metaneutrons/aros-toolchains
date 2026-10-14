[![AROS — source, tools and toolchains](https://aros.metaneutrons.cc/social-card.png)](https://aros.metaneutrons.cc/)

# <img src="https://metaneutrons.cc/brand/aros.svg" alt="" width="40" height="40"> AROS Toolchains

**Cross-compilers and Developer SDKs for AROS, built and managed with [aros-tools](https://github.com/metaneutrons/aros-tools).**

[Documentation](https://aros.metaneutrons.cc/aros-tools/) ·
[Installation](https://aros.metaneutrons.cc/aros-tools/getting-started/installation/) ·
[Toolchain guide](https://aros.metaneutrons.cc/aros-tools/workflows/toolchains/) ·
[SDK guide](https://aros.metaneutrons.cc/aros-tools/workflows/sdks/) ·
[Releases](https://github.com/metaneutrons/aros-toolchains/releases)

[![Producer contracts](https://github.com/metaneutrons/aros-toolchains/actions/workflows/ci.yml/badge.svg)](https://github.com/metaneutrons/aros-toolchains/actions/workflows/ci.yml)

## Purpose

This is the artifact and qualification repository for **aros-tools**. It contains
locked compiler inputs, target selections and the CI pipeline that produces
downloadable compiler and SDK packages. It contains neither the AROS operating
system nor a second implementation of the build tools.

Most developers should start with **[aros-tools](https://github.com/metaneutrons/aros-tools)**,
not clone this repository or build a cross-compiler themselves.

## Three repositories, separate responsibilities

| Repository | Responsibility |
| --- | --- |
| [AROS-NX](https://github.com/metaneutrons/AROS-NX) | Upstream-tracking operating-system sources, target/ABI profiles, SDK build contracts and consumer locks. Source fixes should remain suitable for upstream AROS where applicable. |
| [aros-tools](https://github.com/metaneutrons/aros-tools) | The aros CLI, source fetching, compiler and SDK generation, installation, management and verification. Start here for usage. |
| **aros-toolchains — this repository** | Pinned production inputs, compiler/SDK qualification and release artifacts. |

Source semantics belong in [upstream AROS](https://github.com/aros-development-team/AROS)
or AROS-NX. Build capabilities belong in aros-tools. This repository selects
and verifies those inputs; it does not replace either project.

## Availability

See [release status](https://aros.metaneutrons.cc/aros-tools/reference/release-status/)
and the [published releases](https://github.com/metaneutrons/aros-toolchains/releases)
for downloadable artifacts. A checkout's reviewed lock determines which package
is installed; there is no implicit latest selection.

The published compiler set covers PC x86-64, Raspberry Pi ARM32 and Raspberry Pi
ARM64. The next set adds **ESP32-P4 RV32 and four Developer SDKs**; it is under
[nonpublishing CI qualification](toolchains/compiler-sdk-ci-v2.md), not released.

| Target | Compiler profile | Published compiler | Initial SDK version, not yet published |
| --- | --- | :---: | --- |
| PC x86-64 | pc-x86_64 | Yes | 0.1.0 |
| Raspberry Pi ARM32 | arm-raspi | Yes | 0.1.0 |
| Raspberry Pi ARM64 | rpi-aarch64 | Yes | 0.1.0 |
| ESP32-P4 RV32 | rv32-esp32p4 | No | 0.1.0 |

The selected build hosts are **Linux x86-64, Linux ARM64 and macOS Apple silicon**.
macOS Intel is not a release target. Target profile identifiers are explicit
selectors, not aliases for every board using the same CPU architecture.

## Use with aros-tools

Install the complete [aros-tools suite](https://aros.metaneutrons.cc/aros-tools/getting-started/installation/),
then run these commands inside an AROS checkout with a reviewed toolchain lock:

```console
aros toolchain list
aros toolchain install --preset pc-x86_64
aros toolchain verify --preset pc-x86_64
aros toolchain path --preset pc-x86_64
```

Select arm-raspi or rpi-aarch64 when the checkout's lock enables that profile
on your host. For a pristine upstream checkout without a release lock, follow
the [upstream AROS guide](https://aros.metaneutrons.cc/aros-tools/workflows/upstream-aros/).

## Developer SDKs

A **compiler** runs on the build host. An **SDK** supplies target headers and
libraries for a particular source revision and ABI. Installing a compiler does
not install or select an SDK.

The current-source **aros sdk** interface supports:

- source-bound SDK generation and package verification;
- download, installation and verification through an explicit release lock;
- installed-SDK listing, verified paths and project selection.

See the [SDK guide](https://aros.metaneutrons.cc/aros-tools/workflows/sdks/)
for commands and the distinction between release locks and application project
locks. These capabilities do not imply that a public SDK package is available.

SDK products have independent versions. The initial PC x86-64, Raspberry Pi
ARM32, Raspberry Pi ARM64 and ESP32-P4 RV32 SDKs each start at **0.1.0** and are
intended to ship alongside compilers in one aros-toolchains release.

Compiler/SDK versions, ABI identities and artifact schema versions are different
contracts. Packages are not boot images or complete AROS distributions.

## Qualification and publication

The CLI and source revisions are pinned independently. A new aros-tools
release does not automatically publish compilers or change a consumer lock.

The complete diagnostic pipeline:

1. Verifies exact source contracts and locked inputs before scheduling builds.
2. Builds every selected host/profile compiler twice and compares bytes.
3. Generates each SDK on every selected host and verifies ordinary and relocated
   C/C++ application links, package contents and cross-host SDK equality.
4. Retains checksums, manifests, SBOMs, provenance and original-job evidence.

The complete three-host selection requires **24 compiler builds, 12 comparisons and 12 SDK
generations**. Passing a diagnostic is not publication authority. The protected
compiler/SDK publication route is not activated yet; release admission and an
independent final asset audit remain separate gates.

[Release Please](https://github.com/googleapis/release-please-action) prepares
the repository version and changelog PR. Stable releases use vMAJOR.MINOR.PATCH;
published tags and assets are immutable. See the
[producer contract](toolchains/README.md) and
[protected release-start design](toolchains/release-start-v2.md) for the
engineering boundaries.

## Contribute

Contribute here for locked inputs, qualification or publication policy. Report
CLI and build-engine problems in [aros-tools](https://github.com/metaneutrons/aros-tools/issues),
and operating-system source problems in [AROS-NX](https://github.com/metaneutrons/AROS-NX/issues).

PRs run the offline producer contract suite. Use source checkouts matching the
committed CI contract and
[compiler/SDK selection](toolchains/compiler-sdk-ci-selection-v2.json):

```sh
AROS_TEST_SOURCE_ROOT=/absolute/path/to/contract-source \
AROS_TEST_V2_SOURCE_ROOT=/absolute/path/to/compiler-sdk-source \
  scripts/toolchain/tests/test-producer.sh
```

Replace both paths with the corresponding pinned checkouts. This suite checks
contracts; the costly native matrix runs through an explicit qualification
request. Inputs and schemas live in [toolchains](toolchains/README.md), workflow
definitions in [.github/workflows](.github/workflows/ci.yml), and checks in
[scripts/toolchain](scripts/toolchain/).

## License and acknowledgements

This repository uses the [AROS Public License 1.1](LICENSE). Included compiler
and library components have their own licenses, recorded in release SPDX SBOMs.
It builds on the work of the AROS Development Team and compiler/toolchain
contributors.
