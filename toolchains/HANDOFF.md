# Toolchain release handoff

Status date: 2026-08-26

## Exact current release candidate

The first reproducibility lane is `pc-x86_64` on the two locally available
hosts. Its immutable inputs are:

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

This proves the first target profile on the two locally available hosts. It is
not the complete release matrix described below.

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

The following contracts pass on the release-candidate branch:

```text
cmake -P cmake/tests/ReleaseToolchainTest.cmake
python3 -B scripts/toolchain/tests/test-crosstools-release.py
scripts/toolchain/tests/test-producer.sh
git diff --check
```

A fresh out-of-tree `gmake -j16 tools` built `genmodule` once. A predecessor
candidate (`f376c5582e`) first proved the prefix-clean packaging fix. It
remains diagnostic only; the final macOS proof is the `9f84f550c0` pair
recorded above. The final Linux proof is the independent `9f84f550c0` pair
recorded above as well.

Both final compared archives exercised the complete downstream path:

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

## Evidence and next completion sequence

The completed local logs remain available without changing either build:

```bash
tail -40 /tmp/aros-toolchain-9f84-macos-a.rH2eVP/build.log
tail -40 /tmp/aros-toolchain-9f84-macos-b.dxDoxU/build.log
ssh cachy 'tail -40 /home/fabian/aros-toolchain-9f84-linux.DxAgQa/a/build.log'
ssh cachy 'tail -40 /home/fabian/aros-toolchain-9f84-linux.DxAgQa/b/build.log'
```

For every remaining host/profile lane, compare its two fresh archives into a
new output directory:

```bash
python3 scripts/toolchain/producer.py compare \
  --left <copy-a-archive> \
  --right <copy-b-archive> \
  --output-dir <new-verified-directory>
```

Then run `scripts/toolchain/compatibility.sh` on that compared archive for the
matching host. The script verifies the package first, configures a fresh
AROS-NG consumer and builds the pinned upstream `includes` and `linklibs`
targets. A reused compatibility work directory is rejected. CI checkouts must
include recursive submodules; commit `db674e3040` makes that explicit in the
release workflow after the clean candidate snapshot exposed the dependency.

## Scope that remains open

- A green local result closes only macOS ARM64 and Linux x86_64 for the
  `pc-x86_64` profile. The release workflow still requires two byte-identical
  copies for every supported host/profile pair: four hosts times
  `pc-x86_64`, `arm-raspi` and `rpi-aarch64`.
- The prefix promises the locked CMake partial-link contract. Arbitrary final
  linking through standalone `clang`/`clang++` remains out of scope until
  `collect-aros` is relocatable and resolves sibling LLVM tools plus sysroot
  libraries without `PATH`, `COMPILER_PATH` or compiled-in producer paths.
- Publication must remain fail-closed: no release/index publication until the
  workflow's complete-matrix gate has accepted all 12 host/profile lanes.
