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

The source lock identifies downloaded bytes and source-owned patches. Native
`aros-tools` parses its semantics, verifies the cache and binds the exact
source, producer and tools trees into a recipe. The scope regression test is
not another lock parser and does not establish authenticated release evidence.

The profile's `upstream_commit` records its upstream comparison baseline, not
the source commit of a future build. Each generated recipe must record the
actual clean source commit and tree separately. The current local compiler and
SDK proofs used different source/package contexts; they cannot be combined into
a release qualification. Their required source changes must first be integrated
and qualified on the selected source revision.

The active workflow and executor still select the published LLVM/V1 runtime
and inputs. Do not advance the executor or runtime lock with prospective
versions, commit IDs, hashes or sizes. Activation requires an independently
verified V2-capable runtime, committed source fixes, exact group recipes and the
complete mixed three-host matrix. SDK headers, libraries and start objects must
match the selected target ABI; SDK qualification remains separate from compiler
packaging.
