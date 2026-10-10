# Compiler-family workflow scheduling

`family-release-policy-v2.json` admits the first mixed release scope: GNU
`rv32-esp32p4` and LLVM `pc-x86_64`, `arm-raspi`, `rpi-aarch64` on the three
supported native hosts. RV64 and macOS Intel are not admitted. Changing the
scope requires a reviewed policy change, not a skipped or silently filtered lane.

## Authority boundaries

The native `aros toolchain producer release-plan` command owns validation of the
closed V2 collection and every referenced recipe, source lock and profile
document. The workflow adapter `scripts/toolchain/release-matrix-v2.py` calls
that command; it does not parse compiler recipes or implement target semantics.
It checks the projection against independently supplied input/runtime/producer
identities and the exact reviewed scheduling policy, then assigns runner labels
and A/B copies. Its output has `assurance: scheduling-only`.

The caller must authenticate the release runtime and select the collection and
policy digests from its trusted producer revision before invoking the composite
action `.github/actions/project-family-release-plan`. A policy that carries its
own computed digest is not independent admission. This action cannot establish
source, artifact, provider, signer or publication authority.

Each scheduled lane carries its own group identity, exact source/tree/upstream
commits and three document references. Downstream jobs must use those references;
they must not fall back to the existing global LLVM source lock or source commit.
The host matrix schedules shared host preparation, while the group matrix
schedules group-specific source preparation. Shared caches are acceleration,
never proof that the selected bytes match an input.

## Complete and diagnostic scopes

The complete matrix derives twelve lanes and twenty-four A/B builds from the
validated inputs and policy. `linux` selects eight lanes; `linux-x86_64` selects
four. Every scope first validates the **complete** native projection, so a
diagnostic host selection cannot hide a missing or extra target. Complete and
selected counts remain separate in the result. Diagnostic success cannot admit
a release or stand in for the remaining hosts.

Matrix order is deterministic. Duplicate lanes/documents, extra fields, unsafe
identifiers, stale runtime/input bindings, unreviewed profiles/hosts and matrices
exceeding the Actions limit fail before any matrix is emitted. The adapter
bounds native output and execution time. It writes neither inputs nor build
artifacts and performs no provider calls.

## Integration state

The adapter and composite action are tested scheduling components. The active
`toolchain-release.yml` still uses its published V1-compatible runtime and
nine-lane LLVM pipeline. This delivery does **not** activate a mixed release.
Activation additionally requires the released V2 runtime, committed RV32-only
group inputs/executor bindings, source/build/package/compare/compatibility job
wiring, exact owning-job artifact admission, V2 qualification/index/recovery and
independent final inventory verification. The final inventory and subject counts
remain the native indexer's responsibility, not Python matrix constants.

The scheduling tests use synthetic native projections and fake executables to
exercise contract failures; they are not compiler, SDK, provider-signature or
release qualification evidence. Real compilation and final SDK links remain
required for every admitted target ABI.
