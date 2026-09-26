# AROS toolchain release contract

This directory defines the immutable inputs and target profiles used by the
GitHub toolchain producer. The verified `aros-tools` CLI drives the upstream
AROS contract (`configure` followed by `make crosstools`); it is not a second
toolchain implementation.

## Trust and bootstrap

`llvm-11.0.0.sources.json` pins the exact bytes served by the official LLVM
GitHub release, every external source reached by the producer's current AROS
target-build closure, and the small pure-Python host runtime needed by upstream
`configure`. Each entry records its own version and whether it is a toolchain
component or a target-build dependency, so the SBOM does not mislabel an AROS
port as LLVM. Each consumed AROS patch is declared explicitly by its
repository-relative `patch` field. A source without that field is intentionally
unpatched; the producer never derives hidden patch names from archive filenames.
The producer verifies both size and SHA-256 before allowing the
upstream fetcher to run, and release builds run through an offline guard. The
Mako runtime is extracted into a private work directory and exposed only via a
locked `PYTHONPATH`; it is never installed with pip or resolved from host site
packages. A new or changed source is rejected until its real digest is added
to a reviewed lock file. At the end of every producer lane, the observed fetch
inventory must equal the locked build-source inventory exactly; this rejects
both undeclared downloads and obsolete, no-longer-consumed pins. Do not insert
placeholders.

The source lock establishes deterministic resolution. Bit-for-bit build
reproducibility is a separate release gate: every host/profile lane is built
twice, normalized, and compared before compatibility tests or publication.
This active three-host by three-profile A/B matrix runs once for an annotated
release tag. Manual dispatches are limited to diagnostic Linux tiers and cannot
replace or precede the tag gate. macOS Intel is not a release target. The
producer still recognizes its archive identity solely so historical four-host
indexes remain valid; no current workflow selects an Intel runner.
Before either build starts, the producer also requires the checkout commit,
Git tree, source lock, profile document, released `aros-tools` runtime identity,
and locked `aros-tools` source commit/tree to match the signed-off recipe. It
rejects any tracked working-tree mutation; untracked transport caches do not
alter that identity.

`aros-tools-runtime-v1.json` is the bootstrap lock for the producer runtime.
It records the immutable GitHub Release ID, annotated tag object, peeled source
commit and tree, signer workflow identity, certificate issuer, and the exact
Linux x86_64, Linux AArch64 and macOS AArch64 archive/manifest/Sigstore bundle
closures. Before a workflow consumes one executable, the materialiser checks
the immutable release metadata, all asset sizes and digests, the remote
annotated tag and source tree, two Sigstore bundles, GitHub attestations, the
signed archive manifest and its complete ten-file inventory. It then extracts
only that closure. The lock is committed source material and therefore covered
by the producer tag provenance; its source commit and tree are recorded in the
recipe as `tools_commit` and `tools_tree`.

The release lock selects `aros-tools` v0.3.9. The workflow materialises the
host-matched signed binary for CLI execution and separately checks out the exact
locked source commit and Git tree. That source checkout supplies the native
source/collector code and Cargo metadata; it is verified clean and is never
silently replaced by a branch or by the executable archive.

## Offline compatibility source closure

`compatibility-ports-v3.json` is the single source of truth for the separate
upstream source closure exercised by native compatibility. It binds the exact
AROS revision and every measured external input reachable from the upstream
`includes` and `linklibs` graphs for each active target profile. An input
records an identifier, cache filename, safe materialized path, optional exact
CMake cache path, safe relative fetch-marker path, URL, SHA-256 and byte size.
The compatibility executor preloads every CMake source from verified cache
copies and runs CMake's fetcher offline. It refuses a source/profile mismatch,
a changed input, undeclared files, network access, or a source root modified
after materialization.
The release workflow makes at most three online attempts to fill this cache
after a transport failure, reporting incomplete entries between attempts.
Every attempt preserves existing objects; offline fetch and full hash
verification remain mandatory before a build can start.

Inputs use exact downloaded bytes unless their reviewed `normalization` field
says otherwise. Chromium Gitiles documents that its archive metadata is not
byte-stable even for an immutable commit. The one affected zlib input therefore
uses `canonical-tar-gzip-v1`: the executor rejects unsafe archive entries,
recreates a sorted gzip/tar tree with zeroed ownership and timestamps, and pins
the measured canonical bytes. This is an explicit representation rule, not a
hidden replacement pin; all other source locks continue to identify their
direct HTTPS response bytes.

The lock is derived from the selected revision's `includes` and `linklibs`
Make graphs. Every active profile requires the pinned Unicode data files:
`includes` builds the common `genctbl` host tool before it reaches the port
graph. The current revision reaches the sixteen reviewed Port archives in
addition to those two Unicode files. Each lane receives exactly this explicit
closure. Consequently, an upstream dependency change must update the reviewed
lock rather than being satisfied by an ambient download or a hidden pin.

Materialized payloads are read-only and their root is owner-private. The root
remains writable solely for upstream `fetch.sh` to create and remove its
transient lock and for the upstream Make rules to record explicitly declared
empty `.fetched` markers, including the few markers below nested cache paths.
The executor removes those declared final markers before revalidation; any
other residue or unexpected entry fails the lane. The measured host-tool
closure includes `tar` with its `gzip` and `xz`
decompressors for the selected upstream archive-unpacking path, and `gsed`
on macOS, where upstream configure explicitly requires GNU sed.

## Native producer pipeline

The release workflow uses two deliberately separate `aros-tools` materialisations.
The verified, pinned release binary executes every native `aros` command. The
exact source commit/tree from `aros-tools-runtime-v1.json` is checked out beside
it for the native source/collector implementation and Cargo metadata. The
source checkout is an input to the native producer, not a replacement for the
verified runtime executable.

The stages are ordered as follows:

1. The plan job binds clean AROS, producer, and `aros-tools` trees, generates
   the native recipe, and emits a ready native plan for each target profile.
2. A host-specific Cargo job selects the exact Rust toolchain from
   `toolchains/rust-toolchain.toml`, fetches the Cargo closure through the
   verified CLI, repeats the fetch offline, verifies it, and publishes a
   checksummed vendor archive for that host.
3. Each build lane restores and verifies its host vendor archive, runs
   `aros toolchain build`, and then runs `toolchain producer environment`,
   `package`, and `verify-package` against the candidate.
4. A successful build must leave
   `native-lifecycle/receipts/publish.json` with the native receipt schema,
   `phase: publish`, and a valid receipt digest. The workflow retains one
   lifecycle receipt for every host/profile/copy and refuses the later stages
   when any receipt is absent.
5. Only then do the existing byte comparisons and native compatibility lanes
   run. Index generation, provenance, qualification evidence, and draft
   creation follow after their complete receipt sets are present.

The release path is therefore the native `aros` CLI.

## Release invariants

- A stable asset has the native upstream `CROSSTOOLSDIR` layout.
- The v1 asset name is canonical and machine-readable:
  `aros-toolchain-v1-llvm<version>-<host>-<target-profile>.tar.xz`.
- The compiler contains no functional build-prefix dependency.
- Consumers provide their current AROS Developer directory as `--sysroot`.
- Every archive contains `toolchain/toolchain-manifest.json` with numeric
  `schema: 1`. Its required consumer contract is `release_id`, `host`,
  `target_profile`, `target_triple`, and `tree_sha256`; `llvm_version` and
  producer evidence are additive metadata.
- Every independent native build must pass `producer environment`, `package`,
  `verify-package`, and its lifecycle publish receipt before comparison.
- A tag build creates a draft GitHub Release only after all lifecycle receipts,
  comparisons, and compatibility gates. A plain SemVer tag marks the draft for
  the stable channel; an `-rc.N` tag marks it as a prerelease. Branch and manual
  runs never publish.
- GitHub caches and workflow artifacts are transport/acceleration only; they
  are not trusted release channels.

Each release also carries `toolchain-index-v1.json`. It deliberately uses the
same numeric-schema artifact contract as `aros-cli`: the release base URL,
archive and tree digests, extraction depth, capabilities expressed as required
paths, and host/profile/triple identity are publish-gated rather than copied
into a separate hand-maintained download lock.

### Provenance boundary

The pre-attestation `SHA256SUMS` inventory lists the 42 payload, manifest,
SBOM, support, and index subjects signed by GitHub/Sigstore. The final inventory
then adds `toolchain-provenance.sigstore.json` and checksums that retained bundle
as its 43rd subject. A signature cannot safely include its own bundle without a
recursive hash dependency. The producer and recovery workflows therefore verify
the signed pre-attestation inventory offline with
`scripts/toolchain/verify-provenance-attestation.sh`; the final inventory binds
the bundle itself. Reviewers use the same two-layer check rather than treating
the final `SHA256SUMS` file as an attestation subject.

## Review and promote a draft

1. Download the complete draft and verify every entry in `SHA256SUMS`, the
   GitHub/Sigstore provenance bundle, and all nine active-matrix SBOMs. Inspect
   every native lifecycle publish receipt in the producer run's retained
   workflow artifacts, along with the successful comparison, relocation,
   vanilla-upstream, and AROS-NX jobs for the tag. Do not replace an
   asset in place; rebuild under a new tag if anything differs.
2. Inspect `toolchain-index-v1.json`: it must contain the tag as `release_id`,
   the final GitHub release-download URL as `base_url`, and exactly nine active
   enabled host/profile artifacts. Each artifact must have its measured
   archive `sha256`, payload `tree_sha256`, `size`, `strip_components: 1`, and
   required paths. Zeroes, empty values, and provisional URLs are forbidden.
3. Publish the reviewed draft unchanged. Its channel follows the immutable tag:
   a plain SemVer tag is stable, while an `-rc.N` tag remains a prerelease. Never
   turn an RC tag into a stable release or retarget it. Before changing the
   repository lock, download at least one asset through its final `base_url`
   and recheck its SHA-256. The JSON catalog can also be exercised directly
   with `AROS_TOOLCHAIN_LOCK=/path/to/toolchain-index-v1.json`.
4. Promote the same data into the consuming repository's
   `aros-toolchains.lock.toml`: set its
   `release_id` and `base_url`, copy every artifact's asset name, archive SHA,
   tree SHA, size, LLVM version, extraction depth, and required paths, remove
   `disabled_reason`, and set `enabled = true`. Commit that lock change only
   after every final URL verifies; never enable a placeholder entry.

Published release assets and version-specific evidence remain available on the
[GitHub Releases page](https://github.com/metaneutrons/aros-toolchains/releases).

### Recover a packaging-only draft failure

An immutable producer run does not need to rebuild three active hosts merely because
its final draft assembly failed.  `.github/workflows/toolchain-release-recovery.yml`
accepts such a run only when `plan`, `sources`, all 18 independent builds, all
9 byte comparisons, all 9 compatibility lanes, and all 18 native lifecycle
publish receipts succeeded and `draft-release` is the sole failed job. The
source tag and partial draft stay untouched.

Before dispatch, a maintainer creates and pushes the new annotated recovery
tag with a credential permitted to reference commits that modify GitHub
workflows. Dispatch the recovery workflow only from protected `main`, so its
write-capable implementation is the reviewed version. The recovery job requires
that tag to resolve to the original
recipe commit, records its tag-object ID, and refuses to create the draft if
either the object or its peeled commit changes while the release is assembled.
The job token therefore never creates or retargets a release tag.

Recovery downloads only the nine active host/profile artifact families,
checks their archive sidecars, external and embedded manifests, recipe digest,
source commit, and canonical payload tree, then packages every payload twice
under a new release ID.  Both recovered copies must be byte-identical.  The
new annotated tag points to the original recipe commit, so each recovered
manifest's `source_commit` remains exact; only the release identity and its
derived archive/SBOM/checksum files change.  A new index, complete 44-file
inventory, and GitHub/Sigstore provenance bundle are generated before the new
draft is created. The fresh recovery tag selects its channel by the same rule:
no `-rc.N` suffix marks the draft for the stable channel; an `-rc.N` suffix
marks it as a prerelease. This path is not valid for a compiler-build,
comparison, relocation, upstream-compatibility, or AROS-NX-compatibility
failure.

`tree_sha256` is the SHA-256 of the canonical payload inventory, not of the
compressed archive. The producer walks every payload entry in path order,
including directories, but excludes `toolchain-manifest.json`. Each entry is
serialized as sorted-key compact JSON followed by one newline and fed to the
digest in that order. Entries record the normalized mode and type; files also
record size and SHA-256, while symlinks record their relative target. This
makes the digest independent of archive compression and lets consumers keep
installation-completion markers outside the payload directory.
`tree-digest-v1.fixture.json` is the shared cross-language known-answer vector;
it intentionally covers directories, a file, a relative symlink, and UTF-8
paths.

The v1 producer recognizes Linux x86_64/aarch64 and macOS x86_64/aarch64 hosts
for `pc-x86_64`, `arm-raspi` (`raspi-armhf` upstream), and `rpi-aarch64`.
New releases qualify Linux x86_64/aarch64 and macOS aarch64 only. Any future
macOS Intel reinstatement requires a separately approved issue and a complete
three-profile A/B qualification.

## Release trigger policy

A new `aros-toolchains` release is not created automatically when
`aros-tools` releases. Release Please prepares a version and changelog pull
request; it cannot create the tag or GitHub Release. After that PR is reviewed
and merged, a maintainer creates one fresh annotated tag on the exact producer
commit. The accepted tag grammar is:

- `vMAJOR.MINOR.PATCH` for a stable release;
- `vMAJOR.MINOR.PATCH-rc.N` for prerelease candidate `N`.

The tag is the product version. The `v1` in archive names and numeric schema
`1` identify separate artifact formats. Before product version 1.0,
incompatible changes and compatible new capabilities bump the minor version;
fixes bump the patch version. The workflow rejects leading zeroes and all
other tag variants before expensive work. Never retarget or reuse a tag. A
failed candidate requires a fresh prerelease number; a failed stable-tag
attempt requires a fresh product version and a new reviewed release PR.

Release inputs include:

- the pinned AROS-NX source or an upstream compatibility input;
- `aros-tools-runtime-v1.json` or a security-required runtime rebuild;
- source locks, profiles, producer/packaging code, or release policy.

Documentation-only changes and ordinary `aros-tools` releases do not warrant
the expensive matrix. The tag-triggered workflow first materialises the
verified pinned runtime and locked tools source, prepares the host-specific
Cargo closures, and runs the native recipe/plan/build/package/verify-package
stages. It then requires lifecycle receipts before the complete three-host by
three-profile A/B gate, compatibility, index, qualification, and draft stages.

Manual `workflow_dispatch` runs are staged diagnostics only:
`scope=linux-x86_64` selects the first host tier and `scope=linux` expands it
to both Linux hosts. They never publish and cannot replace the tag gate. Every failed
tag qualification is corrected under a new immutable tag, never by retargeting
an old tag or replacing assets.

`AROS Toolchain Compatibility Replay` reuses the verified packages and source
closure from a completed producer run without rebuilding compilers. Its `host`
and `profile` choices select either the complete nine-lane matrix or one exact
diagnostic lane. Replay never publishes. Both the replay and release workflows
retain per-phase compatibility logs when a lane fails; those logs are diagnostic
evidence, not permission to reuse a failed release tag.

## Locked CMake C++ consumer contract

A release prefix is a compiler/runtime distribution, not a copy of an AROS
Developer sysroot.  A locked CMake consumer creates its own Developer tree and
uses the prefix compiler only to compile target sources.  Its C++ *partial*
links deliberately invoke the prefix's `ld.lld` directly with that Developer
tree as `--sysroot`, the consumer-produced `cxx-startup.o`, and exactly these
prefix-owned archives in one linker group:

- `libc++.a`
- `libc++abi.a`
- `libunwind.a`
- the target-specific `libclang_rt.builtins-*.a`

This partial-link path remains intentionally independent of the host `PATH`.
It is the correct path for CMake modules such as Mesa's `alwayscxxlink=yes`
targets and is separate from the final-link collector contract below.

## Standalone final links and application SDK boundary

Every release ships the Rust `aros-collect` implementation and relative
`collect-aros` aliases next to Clang and LLD. The `pc-x86_64` profile also
ships `collect-aros32`. The collector locates only sibling `ld.lld` and
`llvm-strip`; it does not consult `PATH`, `COMPILER_PATH`, or a producer-local
prefix. Target libraries are resolved from the absolute Developer directory
that the caller supplies with `--sysroot` (`lib32` for `collect-aros32`). A
library-free compiler capability probe may omit the sysroot, matching upstream
AROS configure ordering; any collector-discovered target input still requires
it explicitly.

The collector preserves the upstream AROS two-pass final-link contract:
symbol-set and library-requirement publication, the conditional
`__cxa_pure_virtual`/pthread inputs, unresolved-symbol auditing, AROS ELF ABI
marking, and atomic output replacement. Release compatibility probes invoke
the packaged `clang` and `clang++` with a poisoned `PATH`, verify the resulting
structure and ABI, and exercise both x86-64 and i386 for `pc-x86_64`.

The release prefix is still a compiler/runtime distribution, not a complete
application SDK. Cross-developing an application therefore requires a
matching, separately produced Developer sysroot. A future `aros-cli`
application workflow should consume two immutable artifacts: this host/profile
toolchain and an upstream-compatible target SDK/sysroot. Keeping those
artifacts separate lets applications select or update an AROS system contract
without rebuilding the host compiler and lets AROS-NX coexist with vanilla
AROS SDKs.
