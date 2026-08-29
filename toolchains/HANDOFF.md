# Toolchain release handoff

Status date: 2026-08-29

## Verified product consumer matrix

Run
[`33220983286`](https://github.com/metaneutrons/AROS-NG/actions/runs/33220983286)
passed all three release-toolchain profiles on Linux x86-64 and macOS ARM64
through the public `aros build --toolchain-dir` path. The six lanes consumed
the matching byte-identical `verified-*` artifacts from producer run
`33020916404`; all four native fetch-host contracts and the complete quality
gate passed in the same run. This is product-consumer evidence, not a release:
the artifacts remain expiring workflow transport and the release lock remains
disabled.

The manual product workflow now requires the completed producer run ID and
skips product jobs on push/pull request until real release locks exist. Direct
`cmake --preset` product jobs were removed because the presets select host
Clang unless the CLI supplies the release toolchain contract. Predecessor run
`33218360446` confirmed five product lanes and found a FreeType generated
header race on Linux AArch64; `2234c516fb` added the missing direct-consumer
ordering and the corrected run is green 11/11.

## Consumer C++ header contract

The release payload contract now checks a representative libc++ surface, not
only `vector`: `algorithm`, `cerrno`, `cinttypes`, `cstddef`, `cstdint`,
`deque`, `memory`, `string`, `system_error` and `vector` must all exist. The
producer's embedded index, the AROS-NG CMake toolchain and `aros` legacy-prefix
discovery reject an incomplete prefix consistently. Existing run
`33020916404` artifacts satisfy the stricter contract unchanged.

Those exact macOS ARM64 archives build the real
`datatypes-heic-linklibs-de265` C++ target on `pc-x86_64`, `arm-raspi` and
`rpi-aarch64`. The accompanying AROS SDK fixes make `max_align_t` and
`offsetof` compatible with the Clang/GCC resource headers in either include
order and add the POSIX robust-mutex errno constants required by libc++
`system_error`. `cmake/tests/CxxRuntimeHeaderTest.cmake` preserves that SDK
side of the contract.

## Complete collector-inclusive reproducibility matrix

GitHub Actions producer run
[`33020916404`](https://github.com/metaneutrons/AROS-NG/actions/runs/33020916404)
built every host/profile lane twice from one immutable identity:

```text
source commit: a7add2698cca26115225a0ff65249513570ab443
source tree:   9b9188ca2360fc2522fbb9d4487a61e9cc2ba469
recipe sha256: 38a7e453b46659dbd8335dccad99d73d3898660db99f031330a071100dc03c77
source epoch:  1787784543
```

All 24 independent producers completed, and all 12 formal A/B comparisons
accepted byte-identical archives. The resulting archive SHA-256 values are:

| Host | `pc-x86_64` | `arm-raspi` | `rpi-aarch64` |
| --- | --- | --- | --- |
| `linux-x86_64` | `0f126072ef254aae2084647b21673006ed244c646564abe50a31f8405fe4f281` | `eafff4f329a6bc1161e5072c1aef5908a4f30b9d8b684078efed5555640ad211` | `b4583f282d1219628c09a6fa032c4647bcc414591933a0ebb022eafe4dfac251` |
| `linux-aarch64` | `e15493f7b63edb36f80e75cd28d6ab9253bf848d2992ae557b0caedc9b9e40c7` | `67d1d13b38c1b34f0e8e362ab040dc932e50cb8340ef782a6e69a26cfda02fbc` | `b89f4c8b84575091c54ecaa20e7a3fa847d92d905855f5a61ca5ae3de9647a6d` |
| `macos-x86_64` | `f59a412edc2845b71b88f4a5064d762d4ac007e588be8c9ff53fb326338b032c` | `774f94e2345f72c93d2d1b46a9add3dbe7577234d77782345794b78cbccbc730` | `e80e54bba62bf360e135ea7fb57413aa46f2391210a4954638df6148e53eacd1` |
| `macos-aarch64` | `f9446e2440f34dd330b3f7e44a571504d21ed576ae49e9cbeca239ebdc782f1a` | `6b6bed4e5347a0d12991d396a6bea719cf80fc70b29dbd264362bb1a689f63e8` | `691776ad8e83e1926a0eb8eb295d6e0d445e984ab063b330bdde0114a76d105f` |

Two nondeterminism defects were found and closed before this run. LLVM 11's
Clang attribute emitter ordered `Record` pointers by address; the AROS patch
now orders them by stable record name. Runner observations such as the GitHub
image version are evidence, not payload identity, and are retained in separate
`build-observation-*` artifacts instead of the byte-compared manifest. This
does not hide environmental differences: it separates the stable build
contract from the observed runner instance.

The original run's archive production and comparisons are authoritative. Its
first consumer phase exposed compatibility-harness defects after comparison,
not differing archives. Workflow
[`toolchain-compatibility-replay.yml`](../.github/workflows/toolchain-compatibility-replay.yml)
reuses those exact `verified-*` artifacts so consumer fixes can be proved
without rebuilding or replacing them. Replay run
[`33033043062`](https://github.com/metaneutrons/AROS-NG/actions/runs/33033043062),
at consumer fix commit `30fe824af7`, passed all 12 lanes: two-root relocation,
AROS-NG configuration, vanilla upstream `includes` and `linklibs`, and
standalone C/C++ collector links.

## Previous pre-collector reproducibility baseline

Before the collector was added, the first reproducibility lane was
`pc-x86_64` on the two locally available hosts. Its immutable inputs were:

```text
source commit: 9f84f550c018834013df0f002c79b497b1919989
source tree:   9bad08043b81b67a345a28e823f436f62516a0d3
recipe sha256: 2e8be353146fe97ff25f96fda62ab121fa2c2fa466956fa29321c804150a2350
source epoch:  1787759560
```

The two macOS ARM64 runs completed in these fresh roots:

```text
/tmp/aros-toolchain-9f84-macos-a.rH2eVP
/tmp/aros-toolchain-9f84-macos-b.dxDoxU
```

The two Linux x86_64 runs on `cachy` use:

```text
/home/fabian/aros-toolchain-9f84-linux.DxAgQa/a
/home/fabian/aros-toolchain-9f84-linux.DxAgQa/b
```

Both local host pairs are closed. The macOS archives and formal compare output
have SHA-256
`d7d7e735245faf06631da58af58c0549d02e2fdd0b8f7fa04391cfc6f5e63aac`;
the Linux archives and formal compare output have SHA-256
`dd9935e8a73579082f37d2332c9e80fe35cefdc58797cb57bca8d527ba9b6a57`.
Their verified directories are:

```text
/tmp/aros-toolchain-9f84-macos-verified.x7ekhv/verified
/home/fabian/aros-toolchain-9f84-linux-verified.N0eIk4/verified
```

Each compared archive passed package verification, two-root relocation, a
fresh AROS-NG configure and exact upstream `includes` plus `linklibs` at
`6e196552834ec338072dda8675cf0c3f1d2df0d6`. The final Linux compatibility
work root and log are under:

```text
/home/fabian/aros-toolchain-9f84-linux-compat.NKW3FK
```

This remains useful evidence for the producer before the collector entered its
payload. It does not close the current collector-inclusive lane and is not the
complete release matrix described below.

## Implemented release contract

- Normal upstream-compatible `make crosstools` remains separate. The opt-in
  `--enable-toolchain-release` / `crosstools-release` graph builds only the
  SDK/runtime closure required by a relocatable release.
- LLVM, Clang, LLD, compiler-rt, libc++, libc++abi, libunwind and the private
  Mako/MarkupSafe host runtime are content-locked and prefetched into a
  verified offline cache.
- The producer records a clean commit/tree recipe, normalizes timestamps,
  owners, modes and archive order, embeds SPDX/build provenance, scans all
  payload bytes for source/build/install prefixes, and verifies relocation in
  two extraction roots.
- Target runtime builds receive the same file/debug/macro prefix maps as host
  LLVM. Producer-only `llvm-config` and LLVM CMake package files are removed
  after the runtime build and before packaging.
- The release CMake toolchain selects only prefix-owned compilers, LLVM tools
  and C++ runtime archives. Its custom AROS root/CPU/platform variables are
  explicitly propagated into CMake `try_compile` projects.
- A top-level host-tool barrier builds `genmodule` exactly once before parallel
  target-header generation. This closes the Bus-error race exposed by the
  narrowed release graph.
- The broad verifier source digests and the transpiler's package/archive pins
  are gone. Structural facts are validated structurally; the remaining 14
  transpiler fingerprints cover only opaque recipes that expand into
  hard-coded jobs and fail with an update-required diagnostic on drift.

## Gates already proved

The following contracts pass on the current branch:

```text
cmake -P cmake/tests/ReleaseToolchainTest.cmake
cmake -P cmake/tests/CxxRuntimeHeaderTest.cmake
python3 -B scripts/toolchain/tests/test-crosstools-release.py
scripts/toolchain/tests/test-producer.sh
git diff --check
```

A fresh out-of-tree `gmake -j16 tools` built `genmodule` once. A predecessor
candidate (`f376c5582e`) first proved the prefix-clean packaging fix. It
remains diagnostic only; the final macOS proof is the `9f84f550c0` pair
recorded above. The final Linux proof is the independent `9f84f550c0` pair
recorded above as well.

Both pre-collector compared archives exercised the complete downstream path:

1. `producer.py verify` and its two-root relocation probe passed.
2. AROS-NG configured with C, C++, ASM and Objective-C from the extracted
   prefix and a freshly built, isolated set of Rust generators.
3. Exact upstream commit `6e196552834ec338072dda8675cf0c3f1d2df0d6`
   built `includes` and then `linklibs` against the extracted prefix.

The compatibility script deliberately builds its Rust generators into the
probe work directory, runs the two upstream targets sequentially, gives their
locked Python environments distinct work roots, and neutralizes Autoconf
2.73's added `-std=gnu23` suffix for this older upstream configure script.
It does not patch the upstream checkout.

## Historical local evidence

The completed local logs remain available without changing either build:

```bash
tail -40 /tmp/aros-toolchain-9f84-macos-a.rH2eVP/build.log
tail -40 /tmp/aros-toolchain-9f84-macos-b.dxDoxU/build.log
ssh cachy 'tail -40 /home/fabian/aros-toolchain-9f84-linux.DxAgQa/a/build.log'
ssh cachy 'tail -40 /home/fabian/aros-toolchain-9f84-linux.DxAgQa/b/build.log'
```

The equivalent local comparison command is:

```bash
python3 scripts/toolchain/producer.py compare \
  --left <copy-a-archive> \
  --right <copy-b-archive> \
  --output-dir <new-verified-directory>
```

`scripts/toolchain/compatibility.sh` then verifies the package, checks two-root
relocation, configures a fresh AROS-NG consumer and builds the pinned upstream
`includes` and `linklibs` targets. A reused compatibility work directory is
rejected. CI checkouts include recursive submodules.

## Remaining release work

- The complete four-host by three-profile v1 matrix is reproducible. Promotion
  still requires a new tag run, review of the draft release, provenance,
  SBOMs and generated index, followed by publication without replacing assets.
- The packaged collector now supports the tested standalone C/C++ final-link
  shapes without `PATH`, `COMPILER_PATH` or compiled-in producer paths. A
  complete application-development experience still needs a separately
  versioned Developer SDK/sysroot artifact and CLI lifecycle commands.
- The manual proof run is not itself a release, and the stale exploratory tag
  `toolchain-v1-20260826-rc1` predates the completed matrix. Do not promote or
  retarget it; create a new release tag from the reviewed final commit.
