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
   Transfer this cache as one archive whose SHA-256 is retained by the source
   job. Safe restoration preserves file modes and empty directories before
   native verification: zipped directory artifacts normalize permissions,
   which invalidates the mode-bound Cargo vendor receipt. Do not repair the
   receipt or normalize the downloaded vendor files to bypass that failure.
4. In each owning job, build and read back two independent Family-V2 compiler
   packages, compare their bytes, then run `aros sdk build` against the selected
   package. That command includes the source-owned SDK roots, ordinary C/C++
   consumers, relocation, generation evidence and package readback.
5. After successful generation, stage every plan-selected SDK product as a
   closed payload: generation record, three package members, independently
   retained compatibility input observations and the complete flat compatibility
   export. Each product has a measured `sdk-lane.json` tuple. Upload this exact
   payload, record its numeric artifact ID, ZIP digest and full file inventory
   in the still-running original owner, sign that record using GitHub/Sigstore,
   then upload the record and unchanged signature separately. Failure at any
   step fails the owner job; failed jobs cannot qualify through source verification.
6. Retain diagnostic packages and reports, including failure reports. These
   Actions artifacts are not authenticated release admission evidence.
   Retain native compiler process logs, lifecycle receipts and source-use logs
   even when packaging never starts, plus SDK CMake logs and configuration logs.
   Do not upload complete build trees, compiler intermediates or source caches
   as lane failure diagnostics.

GNU lanes also retain `payload/evidence/gcc-checksum-inputs.json` before the
A/B comparison. The observer selects exactly one generated GCC Makefile and
records its ordered C++ checksum inputs, whole-file hashes and hashes after
the 16-byte prefix skipped by GCC's `genchecksum`. Bounded checksum-options
and generated checksum text accompany those observations. This metadata can
identify an intermediate input that differs even when the linked code matches;
it neither normalizes compiler bytes nor qualifies a release.

The current selection derives eight compiler builds, four comparisons and
four SDK candidates on this host. The scheduler does not hardcode those counts.
All four SDK products start at `0.1.0`; this does not select a future repository
release version or rename public target profiles.

Both compiler production and classic compatibility use the selected clean
AROS-NX revision. This is not a claim of qualification against unmodified vanilla
AROS. SDK identities separately bind the source commit/tree, engine-free content,
sealed contract, ABI and explicitly selected reproducibility epoch.

## Safety and remaining release work

Preparation jobs have only `contents: read`. SDK owning jobs additionally need
`actions: read`, `id-token: write` and `attestations: write` for original artifact
observation and keyless transport signing. They have no publication environment,
long-lived publication credential, contents-write permission or release/tag
mutation. They cannot reach the retained
legacy release graph. Tag-triggered legacy production fails closed during this
V2 migration. Historical tags and published assets are unchanged.

After diagnostic qualification, publication still needs the released V2-capable
runtime, the complete three-host matrix, owning-job artifact admission, signed
combined compiler/SDK inventory, isolated candidate validation and release
immutability gates. A green diagnostic run does not satisfy those gates.

Signing the diagnostic owner's payload is not release qualification. An
independent reader must select the reviewed original workflow/commit, successful
job and numeric payload/proof artifacts from provider observations; verify the
signature and complete ZIP through `artifact-origin.py verify-source`; safely
materialize the retained bytes; and join every SDK tuple to the native complete
compiler/SDK matrix. None of those reader or release-admission gates is replaced
by a signed `sdk-lane.json` claim or a package-only summary. See
[owning-job artifact transport](artifact-origin.md).

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

To investigate one compiler group without repeating unrelated native builds,
add `-f diagnostic_group=<exact-group-id-from-plan>`. The complete native plan
is still validated before projection. A narrowed diagnostic is explicitly
incomplete and cannot be used for a tag-triggered or full release selection.
Omitting the selector keeps every group in the diagnostic host scope.
