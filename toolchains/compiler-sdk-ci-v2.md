# Compiler and SDK diagnostic qualification

The existing `toolchain-release.yml` workflow has one non-publishing
`qualify-v2` mode. The first tier is Linux x86-64 only. Its compiler groups,
SDK product versions and source selections are declared in
`compiler-sdk-ci-selection-v2.json`; source profiles and sealed consumer
contracts remain owned by AROS-NX.

## Execution

1. Build the exact selected development aros-tools checkout. This exception is
   restricted to the manual diagnostic graph. It is not a signed release runtime.
2. Use native recipe creation, source materialization and `sdk verify-source`
   to bind all compiler groups and SDK identity documents. Native `release-plan`
   validates the collection before the bounded scheduler projects its matrix.
3. Fetch and verify the selected compiler, compatibility, Python and Cargo
   inputs once. No native build phase is allowed to populate missing inputs.
4. In each owning job, build and read back two independent Family-V2 compiler
   packages, compare their bytes, then run `aros sdk build` against the selected
   package. That command includes the source-owned SDK roots, ordinary C/C++
   consumers, relocation, generation evidence and package readback.
5. Retain diagnostic packages and reports, including failure reports. These
   Actions artifacts are not authenticated release admission evidence.
   Retain native compiler process logs, lifecycle receipts and source-use logs
   even when packaging never starts, plus SDK CMake logs and configuration logs.
   Do not upload complete build trees, compiler intermediates or source caches
   as lane failure diagnostics.

The current selection derives eight compiler builds, four comparisons and
four SDK candidates on this host. The scheduler does not hardcode those counts.
All four SDK products start at `0.1.0`; this does not select a future repository
release version or rename public target profiles.

Both compiler production and classic compatibility use the selected clean
AROS-NX revision. This is not a claim of qualification against unmodified vanilla
AROS. SDK identities separately bind the source commit/tree, engine-free content,
sealed contract, ABI and explicitly selected reproducibility epoch.

## Safety and remaining release work

The diagnostic jobs have only `contents: read`, no publication environments,
no signing credentials and no release/tag writes. They cannot reach the retained
legacy release graph. Tag-triggered legacy production fails closed during this
V2 migration. Historical tags and published assets are unchanged.

After diagnostic qualification, publication still needs the released V2-capable
runtime, the complete three-host matrix, owning-job artifact admission, signed
combined compiler/SDK inventory, isolated candidate validation and release
immutability gates. A green diagnostic run does not satisfy those gates.

Dispatch only after both exact tools and source commits are remotely available,
the selected tools checks and producer contracts are green, and the source
SDK exporters, source-contract/hygiene and locked-source checks have passed.
The diagnostic deliberately qualifies a development CLI/source combination;
the ordinary AROS-NX product matrix must also pass before that source PR can
merge, but it may first need a newer published CLI. Do not remove source-owned
ABI contracts or suppress a failed product check to make an older CLI pass.

```sh
gh workflow run toolchain-release.yml --repo metaneutrons/aros-toolchains \
  --ref fix/compiler-sdk-ci-integration -f mode=qualify-v2 -f scope=linux-x86_64
```
