# Toolchain build-check handoff

Status date: 2026-08-22

## Deliberate pause point

The working tree is intentionally dirty and **no fresh, complete producer
artifact is claimed from this state**.  The macOS and Cachy producer attempts
that existed before the final locked-C++ linker change were stopped rather
than being treated as evidence.  Resume with new source snapshots only; do
not reuse their build or install directories.

The requested macOS and Linux checks therefore remain the next execution
step, not a completed release result.

## What is implemented and checked

- `--enable-toolchain-release` / `crosstools-release` selects the minimal
  release graph.  Ordinary upstream-compatible `make crosstools` remains a
  separate, unchanged route.
- The producer locks LLVM and its private host-Python dependencies, builds
  offline from a verified cache, normalizes the archive, scans it for build
  prefixes, and runs a two-root relocation probe.
- A locked CMake consumer takes compilers and `ld.lld` only from
  `AROS_CROSS_TOOLCHAIN_ROOT`.  C++ partial links use direct prefix `ld.lld`,
  a consumer-produced `Developer/lib/cxx-startup.o`, and the explicit
  `libc++`, `libc++abi`, `libunwind`, and compiler-rt archive group.  This
  avoids host `PATH` lookup and the build-local collector configuration.
- The following checks passed after that change:

  ```text
  cmake -P cmake/tests/ReleaseToolchainTest.cmake
  cmake -P cmake/tests/AlwaysCxxLinkTest.cmake
  python3 -B scripts/toolchain/tests/test-crosstools-release.py
  scripts/toolchain/tests/test-producer.sh
  git diff --check
  ```

- A Cachy smoke test used an actual prefix `clang++` for compilation and the
  actual prefix `ld.lld` with `PATH=/nonexistent` for the C++ relocatable
  link.  It produced an ELF64 relocatable object containing `__dso_handle`
  and the expected C++ symbols.  The test used target-side stand-in runtime
  archives because a final producer prefix did not yet exist; it is not a
  substitute for the fresh package/consumer gate below.

## Gate before committing

The five commands listed above are what passed for one particular change. They
have been read as the gate, and as a gate they were short by three checks:

```text
cargo fmt --all --check
cargo clippy --workspace --all-targets
cargo test --workspace
for t in cmake/tests/*Test.cmake; do cmake -P "$t" || echo "FAIL $t"; done
git diff --check
```

Run the first four from `tools/aros-tools`, the last two from the repository
root.

Why each of the three was added:

- `cargo test --workspace` covers `aros-verify`, which no list mentioned. Its
  suite was red for as long as one hand-pinned digest was stale, and while it
  was red the eight inventory counts behind that digest were never evaluated at
  all (OPEN-POINTS 7).
- `cargo fmt --all --check` was missing, and nine files had drifted from it
  (OPEN-POINTS 8).
- the fixture sweep was missing, and seven of the 21 fixtures were red, each
  from a commit that had passed the shorter gate (OPEN-POINTS 45). It costs
  about five minutes, 254 seconds of that `GrubBuildTest` alone; the other
  twenty take 45 seconds together, so run GrubBuildTest on its own schedule if
  that is what decides between running the sweep and skipping it.

`cargo clippy --workspace --all-targets` only started compiling again once
three deny-level lints were fixed, and cargo stops linting dependent crates
after the first failure, so a red clippy hides the rest of the workspace as
well.

## Refactoring the transpiler: the baseline

A refactor of `aros-transpiler` claims that moving code changed no generated
CMake. `aros golden` is what turns that claim into a check:

```text
cargo build --release -p aros-transpiler -p aros-cli
aros golden capture          # before the change
# ... refactor, rebuild the release binary ...
aros golden verify           # after each step
```

`capture` runs the transpiler twice per preset and refuses to store a baseline
if the two runs disagree, because a baseline from a producer that varies would
report noise as regression forever. It found exactly that on its first run: one
report file came out with the same bytes and the same line count in a different
order, from a candidate list built while iterating a `HashMap`.

`verify` names the file, the byte and line delta, and the first differing line,
and exits non-zero. `verify --update` accepts the new output as the baseline
when the change was the point.

Three properties are worth knowing before relying on it:

- **It is per preset.** The scoped arguments are derived during configuration
  and they change the output: pc-x86_64, arm-raspi and rpi-aarch64 produce
  3 419 144, 3 252 031 and 3 417 460 bytes. CMake records the argv it used in
  `generated_targets.cmake.invocation` next to its output, and `golden` replays
  that rather than re-deriving it.
- **The baseline is not in the repository.** It lives in `build/golden/`, which
  is ignored. A digest of a live output committed to the tree would be stale
  after every deliberate transpiler change, and a check that is nearly always
  red is not a check (see OPEN-POINTS 7 and 46 for the same coupling in two
  other places).
- **Capture cross-checks the record.** Its first run is compared against the
  file the build tree itself holds, so a recorded argv that has drifted from
  the call, or a build tree that predates a source change, is reported instead
  of trusted.

## Important open issue: standalone Clang driver

The release prefix currently promises the locked CMake partial-link contract,
not arbitrary standalone final linking through `clang`/`clang++`.

The AROS LLVM 11 driver selects `collect-aros` for every primary target and
selects `collect-aros32` when an x86_64 compiler is used for the i386
secondary target.  The present collector is not releasable: it embeds absolute
producer paths for `ld.lld` and other LLVM tools as well as `OBJLIBDIR`, and
some backend helpers still resolve tools through `PATH`.  Copying it into the
archive would be both non-relocatable and unsafe.

The upstream-compatible release-mode fix should be:

1. Install a native-host `collect-aros` beside the release compiler for every
   profile, plus `collect-aros32` only for `pc-x86_64`.
2. Resolve the collector's own executable directory at runtime (`/proc/self/exe`
   on Linux, `_NSGetExecutablePath` plus `realpath` on macOS), then require
   absolute sibling paths for `ld.lld`, `llvm-nm`, `llvm-objdump`, and
   `llvm-strip`.  Missing siblings must fail hard; neither `PATH` nor
   `COMPILER_PATH` may be a fallback.
3. Remove the compiled-in `OBJLIBDIR`.  Pass `--sysroot` from the Clang AROS
   driver also when it selects the collector; have the collector derive
   `<sysroot>/lib`, or `<sysroot>/lib32` for the i386 secondary target.
4. Extend package validation and poison-`PATH` functional tests to cover
   actual C and C++ final links.  For `pc-x86_64`, test both x86_64 and i386;
   for ARM and AArch64, test `collect-aros` only.

The direct `ld.lld` CMake route should remain after that work: it is a small,
explicit partial-link contract, while the collector serves the broader
standalone-driver contract.

## Resume sequence

### 1. Preserve and inspect the workspace

Do not reset or clean this shared working tree.  Start with:

```bash
cd /Volumes/Dev/Source/AROS-NG
git status --short
git diff --check
```

The status contains intended cross-cutting CMake, crosstool, producer, Rust
transpiler, workflow, and documentation changes.  `configure~` and Python
`__pycache__` are local by-products, not source changes to add deliberately.

### 2. Finish the standalone-collector work

Implement and test the four-item design above before claiming a generally
usable released `clang`/`clang++`.  Keep it behind the release mode so normal
AROS `crosstools` behaviour remains compatible with upstream.

### 3. Make a clean, throwaway source snapshot

`build-release.sh` intentionally rejects a dirty source tree.  Once the code
is ready, clone the current repository to a new temporary directory, overlay
the working-tree content (excluding `.git` and build products), create a
local-only snapshot commit there, and generate the recipe from that snapshot.
The snapshot's commit and tree must be the ones used by `recipe` and
`build-release`; never point one command at the shared dirty checkout and the
other at the snapshot.

The snapshot may be discarded after the run.  A release result is valid only
if `producer.py verify-checkout` reports its exact local snapshot commit/tree
and the package verification below succeeds.

Create the recipe immediately after the snapshot commit, for example:

```bash
python3 <clean-snapshot>/scripts/toolchain/producer.py recipe \
  --source-root <clean-snapshot> \
  --lock <clean-snapshot>/toolchains/llvm-11.0.0.sources.json \
  --profiles <clean-snapshot>/toolchains/profiles-v1.json \
  --output <clean-snapshot>/recipe.json
```

### 4. Run the first fresh producer pair

Use a newly empty work/install directory for each host and the current source
snapshot.  Start with `pc-x86_64` only:

```bash
scripts/toolchain/build-release.sh \
  --source-root <clean-snapshot> \
  --work-dir <new-empty-workdir> \
  --source-cache <verified-source-cache> \
  --recipe <clean-snapshot>/recipe.json \
  --lock <clean-snapshot>/toolchains/llvm-11.0.0.sources.json \
  --profiles <clean-snapshot>/toolchains/profiles-v1.json \
  --profile pc-x86_64 \
  --host macos-aarch64 \
  --release-id buildcheck-<new-id> \
  --output-dir <new-empty-outputdir> \
  --jobs 2
```

Run the same command on Cachy with `--host linux-x86_64`.  The source cache
may be shared only after its verified source index has been checked; work and
output directories must never be reused.  The producer performs the offline
prefetch and packaging scan itself.

### 5. Verify each package and exercise a real consumer

Run `producer.py verify` against each produced archive with the matching
host/profile and forbidden source/build/install prefixes, for example:

```bash
python3 <clean-snapshot>/scripts/toolchain/producer.py verify \
  --archive <output-dir>/aros-toolchain-v1-llvm11.0.0-<host>-pc-x86_64.tar.xz \
  --fixtures <clean-snapshot>/scripts/toolchain/fixtures \
  --host <host> \
  --target-profile pc-x86_64 \
  --forbid-prefix <clean-snapshot> \
  --forbid-prefix <new-empty-workdir> \
  --forbid-prefix <new-empty-workdir>/install/toolchain
```

Then extract the package at a new path and configure an AROS-NG CMake consumer
using:

```text
-DCMAKE_TOOLCHAIN_FILE=<source>/cmake/toolchains/AROS.cmake
-DAROS_CROSS_TOOLCHAIN_ROOT=<extracted-prefix>/toolchain
-DAROS_TARGET_CPU=x86_64
-DAROS_TARGET_PLATFORM=pc
-DAROS_RUST_TOOLS_DIR=<source>/tools/aros-tools/target/release
```

Build `linklibs-startup` and `mesa3dgl-library`.  Confirm in the verbose link
line that the extracted prefix's `ld.lld`, `Developer/lib/cxx-startup.o`, and
the four explicit runtime archives are used, with no `collect-aros` and no
host-path tool lookup.

Only after the two PC host lanes are green should the same procedure be run
for `arm-raspi` and `rpi-aarch64` on both hosts.  The complete release matrix
then requires each host/profile pair to be built twice and byte-compared by
the workflow before publication.
