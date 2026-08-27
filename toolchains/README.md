# AROS-NG toolchain releases

This directory defines the immutable inputs and target profiles used by the
GitHub toolchain producer. The producer deliberately invokes the historical
AROS contract (`configure` followed by `make crosstools`); it is not a second
toolchain implementation.

## Trust and bootstrap

`llvm-11.0.0.sources.json` pins the exact bytes served by the official LLVM
GitHub release and the small pure-Python host runtime needed by upstream
`configure`. The producer verifies both size and SHA-256 before allowing the
upstream fetcher to run, and release builds run through an offline guard. The
Mako runtime is extracted into a private work directory and exposed only via a
locked `PYTHONPATH`; it is never installed with pip or resolved from host site
packages. A new or changed source is rejected until its real digest is added
to a reviewed lock file. Do not insert placeholders.

The source lock establishes deterministic resolution. Bit-for-bit build
reproducibility is a separate release gate: every host/profile lane is built
twice, normalized, and compared before compatibility tests or publication.
Before either build starts, the producer also requires the checkout commit,
Git tree, source lock, and profile document to match the signed-off recipe and
rejects any tracked working-tree mutation; untracked transport caches do not
alter that identity.

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

## Promote the first draft

1. Download the complete draft and verify every entry in `SHA256SUMS`, the
   GitHub/Sigstore provenance bundle, all twelve SBOMs, and the successful
   comparison/relocation/upstream/AROS-NG jobs for the tag. Do not replace an
   asset in place; rebuild under a new tag if anything differs.
2. Inspect `toolchain-index-v1.json`: it must contain the tag as `release_id`,
   the final GitHub release-download URL as `base_url`, and exactly twelve
   enabled host/profile artifacts. Each artifact must have its measured
   archive `sha256`, payload `tree_sha256`, `size`, `strip_components: 1`, and
   required paths. Zeroes, empty values, and provisional URLs are forbidden.
3. Publish the reviewed draft unchanged. Before changing the repository lock,
   download at least one asset through its final `base_url` and recheck its
   SHA-256. The JSON catalog can also be exercised directly with
   `AROS_TOOLCHAIN_LOCK=/path/to/toolchain-index-v1.json`.
4. Promote the same data into `aros-toolchains.lock.toml`: set its
   `release_id` and `base_url`, copy every artifact's asset name, archive SHA,
   tree SHA, size, LLVM version, extraction depth, and required paths, remove
   `disabled_reason`, and set `enabled = true`. Commit that lock change only
   after every final URL verifies; never enable a placeholder entry.

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

The v1 producer covers Linux x86_64/aarch64 and macOS x86_64/aarch64 hosts for
`pc-x86_64`, `arm-raspi` (`raspi-armhf` upstream), and `rpi-aarch64`.

## Current reproducibility proof

Manual GitHub Actions run
[`33020916404`](https://github.com/metaneutrons/AROS-NG/actions/runs/33020916404)
completed all 24 independent producers and all 12 A/B comparisons for the
four-host by three-profile matrix. Every pair is byte-identical. The exact
commit, tree, recipe, archive SHA-256 table and the successful 12-lane consumer
replay are recorded in [HANDOFF.md](HANDOFF.md). This proves the release recipe
but does not publish artifacts: a new tag must still pass the same fail-closed
gates and produce a reviewed draft release.

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
without rebuilding the host compiler and lets AROS-NG coexist with vanilla
AROS SDKs. See [HANDOFF.md](HANDOFF.md) for the current build-check state and
the exact continuation sequence.
