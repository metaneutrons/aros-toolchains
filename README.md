# AROS toolchains

Deterministic producer, verification, and release infrastructure for AROS
cross-toolchains. GitHub Releases in this repository will be the canonical
distribution channel for new immutable toolchain archives.

This repository is currently a migration workspace. It does not yet publish a
standalone release. The verified historical RC3 remains immutable at
[`metaneutrons/AROS-NG`](https://github.com/metaneutrons/AROS-NG/releases/tag/toolchain-v1-20260829-rc3);
its artifacts and attestations are not copied or reissued here.

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

The first standalone qualification deliberately pins:

- AROS source: `metaneutrons/AROS-NX` at
  `5eda8ebd4da5412092528c2bb2323b90e19ef6d0`;
- aros-tools: `metaneutrons/aros-tools` at
  `8fc0eb2f3646f27db53a1552d2b0e10265dd4fc2`.

The AROS-NX source commit passed the standalone producer contracts and a
complete local `pc-x86_64` RC3 consumer build before promotion here. CI still
fails if either explicit pin is missing; there is no branch-name fallback.

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

See [the detailed release contract](toolchains/README.md) and
[migration provenance](docs/migration-provenance.md).
