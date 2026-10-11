# GNU RV32 release inputs

These documents stage the first GNU input group. They do not activate a release
workflow or qualify a compiler, SDK, board boot or publication.

- `gnu-16.2.0.sources.json` pins the measured GCC 16.2.0 / Binutils 2.47
  closure: nine source archives and three upstream host-Python archives. It is
  byte-identical to the lock used by the retained local GNU compiler proofs.
- `profiles-gnu-rv32-v2.json` selects only `rv32-esp32p4`, with the reviewed
  `ilp32f` ABI, `medany` code model and P4 ISA. RV64 is deliberately excluded
  from this release group. The GNU source closure itself is shared; the profile
  document determines the target scope.
- `compatibility-ports-gnu-rv32-v3.json` stages the 22 measured compatibility
  inputs used by the local GNU diagnostic. Boost and Codesets include their
  explicit CMake cache paths. All 16 fetch commands selected by the local
  `includes` / `linklibs` graph have a unique, checksum-matching offline cache
  mapping; the remaining records support upstream and host-Python phases.
  This input mapping check is not a completed SDK or compatibility proof.

The classic Chromium zlib cache path and its fetch marker retain the selected
revision subtree (`chromium-<revision>/`). Its independent CMake path names
that same subtree under `portssources/`. The cache filename, canonical bytes,
size and checksum are unchanged; no Rust-side zlib path alias is needed.

The source lock identifies downloaded bytes and source-owned patches. Native
`aros-tools` parses its semantics, verifies the cache and binds the exact
source, producer and tools trees into a recipe. The scope regression test is
not another lock parser and does not establish authenticated release evidence.

The staged profile still records the comparison baseline used by the retained
local proofs. It is not ready for a V2 release-input collection: that contract
requires each group's profile `upstream_commit` to equal its recipe's actual
clean source commit. Activation must bind the profile to the qualified source
revision, regenerate its exact-byte digest and recipe bindings, and update the
scope regression's expected digest. Do not weaken the native identity check or
substitute a prospective commit.

The staged compatibility lock also retains the local diagnostic's exact
upstream comparison commit. Before activation, qualify that baseline with the
selected package and source context. Do not treat the successful cache
verification or mapping audit as authentication of a release input group.

The current local compiler and SDK proofs used different source/package
contexts; they cannot be combined into a release qualification. Their required
source changes must first be integrated and qualified on the selected source
revision. Different compiler families may select different qualified source
commits, but each group's source/profile/recipe binding must agree.

The active workflow and executor still select the published LLVM/V1 runtime
and inputs. Do not advance the executor or runtime lock with prospective
versions, commit IDs, hashes or sizes. Activation requires an independently
verified V2-capable runtime, committed source fixes, exact group recipes and the
complete mixed three-host matrix. SDK headers, libraries and start objects must
match the selected target ABI; SDK qualification remains separate from compiler
packaging.
