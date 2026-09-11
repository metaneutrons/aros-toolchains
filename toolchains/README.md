# AROS toolchain release contract

This directory defines the immutable inputs and target profiles used by the
GitHub toolchain producer. The producer deliberately invokes the historical
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
replace or precede the tag gate. Intel macOS is fully suspended until the
initial M7 release is published; the producer still recognizes its archive
identity and historical four-host indexes remain valid. See
[issue #27](https://github.com/metaneutrons/aros-toolchains/issues/27).
Before either build starts, the producer also requires the checkout commit,
Git tree, source lock, and profile document to match the signed-off recipe and
rejects any tracked working-tree mutation; untracked transport caches do not
alter that identity.

## Offline compatibility source closure

`compatibility-ports-v2.json` is the single source of truth for the separate
upstream source closure exercised by native compatibility. It binds the exact
AROS revision and every measured external input reachable from the upstream
`includes` and `linklibs` graphs for each active target profile. An input
records an identifier, cache filename, safe materialized path, safe relative
fetch-marker path, URL, SHA-256 and byte size. The compatibility executor
refuses a source/profile mismatch, a changed input, undeclared files, network
access, or a source root that has been modified after materialization.

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

## Native executor declaration

`producer-executor-v1.toml` selects the reviewed `aros-tools` implementation
for its native local lifecycle. It binds the exact tools commit, the measured
producer-contract digest, this source lock, and this profile document. The
native CLI rejects an absent, malformed, or mismatched declaration before it
creates a compiler work directory.

This declaration is a local-candidate input, not release provenance and not a
workflow cutover. The current Python producer remains the release path until
the separately reviewed CI migration accepts the same native implementation.
Changing any selected input requires a new declaration with measured values;
do not replace it with a branch name or a placeholder digest.

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
- A tag build creates a draft GitHub Release only after comparison and
  compatibility gates. Branch and manual runs never publish.
- GitHub caches and workflow artifacts are transport/acceleration only; they
  are not trusted release channels.

Each release also carries `toolchain-index-v1.json`. It deliberately uses the
same numeric-schema artifact contract as `aros-cli`: the release base URL,
archive and tree digests, extraction depth, capabilities expressed as required
paths, and host/profile/triple identity are publish-gated rather than copied
into a separate hand-maintained download lock.

## Review and promote a draft

1. Download the complete draft and verify every entry in `SHA256SUMS`, the
   GitHub/Sigstore provenance bundle, all nine active-matrix SBOMs, and the successful
   comparison, relocation, vanilla-upstream, and AROS-NX jobs for the tag. Do
   not replace an
   asset in place; rebuild under a new tag if anything differs.
2. Inspect `toolchain-index-v1.json`: it must contain the tag as `release_id`,
   the final GitHub release-download URL as `base_url`, and exactly nine active
   enabled host/profile artifacts. Each artifact must have its measured
   archive `sha256`, payload `tree_sha256`, `size`, `strip_components: 1`, and
   required paths. Zeroes, empty values, and provisional URLs are forbidden.
3. Publish the reviewed draft unchanged. Before changing the repository lock,
   download at least one asset through its final `base_url` and recheck its
   SHA-256. The JSON catalog can also be exercised directly with
   `AROS_TOOLCHAIN_LOCK=/path/to/toolchain-index-v1.json`.
4. Promote the same data into the consuming repository's
   `aros-toolchains.lock.toml`: set its
   `release_id` and `base_url`, copy every artifact's asset name, archive SHA,
   tree SHA, size, LLVM version, extraction depth, and required paths, remove
   `disabled_reason`, and set `enabled = true`. Commit that lock change only
   after every final URL verifies; never enable a placeholder entry.

The current standalone release is
[`toolchain-v1-20260831-rc3`](https://github.com/metaneutrons/aros-toolchains/releases/tag/toolchain-v1-20260831-rc3).
Its twelve four-host/three-profile entries are enabled in the AROS-NX consumer
lock; separate RISC-V declarations remain disabled because this release
contains no RISC-V artifacts. Its producer run and exact three-repository
identities are recorded in [migration provenance](../docs/migration-provenance.md#standalone-release).
The earlier `toolchain-v1-20260829-rc3` in AROS-NG is a distinct historical
release; its artifacts or attestations were not transplanted into this one.

### Recover a packaging-only draft failure

An immutable producer run does not need to rebuild three active hosts merely because
its final draft assembly failed.  `.github/workflows/toolchain-release-recovery.yml`
accepts such a run only when `plan`, `sources`, all 18 independent builds, all
9 byte comparisons, and all 9 compatibility lanes succeeded and
`draft-release` is the sole failed job.  The source tag and partial draft stay
untouched.

Before dispatch, a maintainer creates and pushes the new annotated recovery
tag with a credential permitted to reference commits that modify GitHub
workflows.  The recovery job requires that tag to resolve to the original
recipe commit, records its tag-object ID, and refuses to create the draft if
either the object or its peeled commit changes while the release is assembled.
The job token therefore never creates or retargets a release tag.

Recovery downloads only the nine active host/profile artifact families,
checks their archive sidecars, external and embedded manifests, recipe digest,
source commit, and canonical payload tree, then packages every payload twice
under a new release ID.  Both recovered copies must be byte-identical.  The
new annotated tag points to the original recipe commit, so each recovered
manifest's `source_commit` remains exact; only the release identity and its
derived archive/SBOM/checksum files change.  A new index, complete 56-file
inventory, and GitHub/Sigstore provenance bundle are generated before the new
draft is created.  This path is not valid for a compiler-build, comparison,
relocation, upstream-compatibility, or AROS-NX-compatibility failure.

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
New releases currently qualify Linux x86_64/aarch64 and macOS aarch64 only;
Intel macOS is deferred to [issue #27](https://github.com/metaneutrons/aros-toolchains/issues/27).

## Product qualification and CI migration

Before RC3, product CI could not silently fall back to a host compiler or
pretend that an unpublished toolchain was downloadable.  Manual
`ci-build-matrix.yml` runs therefore accepted an explicit completed producer
run and exercised `aros build --toolchain-dir` using its expiring
`verified-*` artifacts.  That evidence path remains useful for qualifying an
unpublished candidate.

The run ID is an explicit evidence reference, not a package pin. Producer
artifacts expire and are never a stable distribution channel.  RC3 is now
published and promoted.  Regular push, pull-request and input-free manual
product jobs therefore consume the checked-in lock through normal `aros build`
resolution.  Supplying `toolchain_source_run_id` deliberately switches only
the candidate download/extraction steps and the final `--toolchain-dir`
argument; the downloaded archive must pass `producer.py verify` first.

## Historical pre-release reproducibility proof

Historical manual GitHub Actions run
[`33020916404`](https://github.com/metaneutrons/AROS-NG/actions/runs/33020916404)
completed all 24 independent producers and all 12 A/B comparisons for the
four-host by three-profile matrix. Every pair is byte-identical. The exact
commit, tree, recipe, archive SHA-256 table and the successful 12-lane consumer
replay are recorded in the
[historical handoff](https://github.com/metaneutrons/AROS-NG/blob/a74b18a10f/HANDOFF.md).
This proves the release recipe
but does not publish artifacts. It is historical evidence, not a recurring
precondition: future full A/B qualification occurs exactly once in the
annotated-tag producer that creates the reviewed draft release.

Observed runner details are deliberately retained beside, rather than inside,
the stable byte-compared build contract. Each producer uploads a
`build-observation-*` artifact with the actual runner image and tool versions.
This keeps environmental evidence without making unrelated runner image
rollouts alter an otherwise identical archive.

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
AROS SDKs. See [HANDOFF.md](HANDOFF.md) for the current build-check state and
the exact continuation sequence.
