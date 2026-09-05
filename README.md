# AROS toolchains

Deterministic producer, verification, and release infrastructure for AROS
cross-toolchains. GitHub Releases in this repository are the canonical
distribution channel for new immutable toolchain archives.

The first standalone prerelease,
[`toolchain-v1-20260831-rc3`](https://github.com/metaneutrons/aros-toolchains/releases/tag/toolchain-v1-20260831-rc3),
was published on 31 August 2026. It provides twelve LLVM 11 archives for Linux
and macOS on x86-64 and ARM64, each covering `pc-x86_64`, `arm-raspi` and
`rpi-aarch64`. The release includes a measured index, checksums, manifests,
SPDX SBOMs and fresh GitHub provenance. RISC-V is not part of this release.

The older AROS-NG release remains historical evidence, not a required download
source for these archives. See [standalone release evidence](docs/migration-provenance.md#standalone-release).

## Three-repository build identity

Every new recipe binds three clean Git checkouts independently:

| Identity | Contents |
| --- | --- |
| producer | this repository's scripts, locks, schemas, and workflows |
| AROS source | `configure`, MetaMake sources, LLVM patches, and target runtime |
| aros-tools | the Rust collector and compatibility-test build tools |

The recipe records each checkout's full commit and tree. Toolchain manifests
retain `source_commit` for the AROS source and add mandatory
`producer_commit` and `tools_commit` fields. The archive epoch is the greatest
of the three commit timestamps. Release builds reject tracked changes or an
identity mismatch before compilation.

The current published standalone release records:

- AROS source: `metaneutrons/AROS-NX` at
  `f3cfc243a84065166a46da28b0a5b22bbd0f8869`;
- aros-tools: `metaneutrons/aros-tools` at
  `707037be4f8ff37300a1a89166c35f661c28bafe`;
- producer: `metaneutrons/aros-toolchains` at
  `c8039cf2b7291097ad62c6750bd7367e91a068f4`.

These identities are not moving branch aliases. A newer AROS-NX or tools
commit does not change the published release's provenance. Future releases
must qualify their own explicit source/tools/producer recipe; CI rejects
missing identities rather than falling back to branch names.

## Repository layout

- `scripts/toolchain/producer.py`: package, verify, compare, repackage, and
  release-index engine;
- `scripts/toolchain/build-release.sh`: isolated compiler/runtime producer;
- `scripts/toolchain/compatibility.sh`: relocation, AROS-NX CMake, and pinned
  vanilla-upstream consumer probes;
- `toolchains/`: immutable source locks, profiles, schemas, and known-answer
  vectors;
- `.github/workflows/`: full producer, compatibility replay, and packaging-only
  recovery workflows.

Consumer locks do not live here. AROS-NX and other consumers promote measured
values from a published `toolchain-index-v1.json` into their own locks only
after final release URLs verify.

## Local contract tests

Select an AROS checkout that contains the locked crosstools patch series:

```console
AROS_TEST_SOURCE_ROOT=/path/to/AROS \
  scripts/toolchain/tests/test-producer.sh
```

The test is offline and self-contained apart from that audited source contract.
It exercises source-lock validation, the LLVM patch fixture, MetaMake closure,
safe archive handling, deterministic A/B output, tree digests, relocation,
SBOMs, manifests, recovery repackaging, checksums, and the complete four-host
by three-profile publication inventory.

## Release invariants

- 24 independent builds: two per four-host/three-profile lane;
- 12 byte-identical comparisons;
- relocation and compatibility against both pinned AROS-NX and vanilla AROS;
- exactly 12 archives, manifests, checksum sidecars, and SBOMs;
- complete index and `SHA256SUMS`;
- fresh provenance for the exact repository and tag;
- immutable annotated tags, with no retargeting or asset replacement.

## Qualification execution policy

The full four-host by three-profile A/B matrix is a release gate, not routine
CI. It runs exactly once for an annotated `toolchain-v1-*` tag: each of the
twelve lanes produces two independent normalized archives, which must compare
byte-for-byte before its compatibility checks and draft assembly proceed.

Pull requests run the offline source, patch, MetaMake-closure, archive and
relocation contracts. Manual producer dispatches are deliberately limited to
the `linux-x86_64` or `linux` diagnostic tiers and never publish. They cannot
select all four hosts. A complete manual A/B prequalification is therefore not
a prerequisite for a tagged release and must not be repeated before one.

Rerun the full matrix only for a release tag, or after a failed release gate
once the narrow cause has been corrected. A scheduled reproducibility audit
may use the same tagged-equivalent matrix, but it is separate from ordinary
changes and releases.

See [the detailed release contract](toolchains/README.md) and
[migration provenance](docs/migration-provenance.md).
