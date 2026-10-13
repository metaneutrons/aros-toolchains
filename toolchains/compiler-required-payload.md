# Required compiler payload paths

`compiler-required-payload-v1.json` is an independent producer policy, not a
package inventory. It binds each selected source-lock and profiles digest and
declares sorted required file paths for every compiler profile. A changed input
requires review of this policy. No package manifest supplies its expectations.

`scripts/toolchain/required-compiler-payload-v2.py` binds the independently
selected policy and native-plan digests, checks complete group/profile coverage,
and projects these paths onto every native host lane. Its output has
`required-path-selection-only` assurance. It neither opens compiler packages nor
proves builds, comparisons, SDK execution, provenance or release qualification.
The final adapter must join its selections to native-derived archive identities
and independently retained owner environments before invoking the native index
writer. CI preparation checks and retains this complete selection before
scheduling native builds. The authenticated readback job derives the policy
selection again against its fresh native plan, then binds it to the compiler
candidate assembler. Neither selection grants package or release admission.

## Policy basis

- LLVM: the reviewed V1 tools, C++ headers/libraries and builtins contract is
  retained as declarative data. Only PC requires the 32-bit collector and i386
  builtins. The exact version remains bound to the locked LLVM source.
- GNU: the native collector installer defines flat target-prefixed programs,
  tuple-local linker/strip/collector aliases, both collector manifests and the
  closed tool-role document. Do not move these expectations under `bin/`.
- GCC: the AROS recipe enables C/C++ and version-specific runtime libraries.
  Neutral-prefix staging, GCC's `libsubdir`/`libexecsubdir`, and libstdc++'s
  version-specific include/install rules establish the explicit paths for
  `cc1`, `cc1plus`, builtin headers, public/generated C++ headers, `libgcc.a`,
  `libstdc++.a` and `libsupc++.a`. The selected AROS RISC-V configuration does
  not enable the ELF multilib fragment; no multilib suffix is selected.
- `specs` is explicitly removed by GCC installation; AROS disables `collect2`.
  `libgcc_eh.a` is a shared-runtime conditional output, not an unconditional
  requirement of the declared `libgcc`/`libstdcxx`/`libsupcxx` capability set.

Required paths are sentinels, not a replacement for the native closed package
inventory, hashes, executable confinement, SDK ABI checks or ordinary and
relocated C/C++ final links. Their presence has not yet been measured across
the complete compiler/SDK qualification matrix.

Run the generic selector and committed-policy counterprobes:

```sh
python3 -B scripts/toolchain/tests/test-required-compiler-payload-v2.py
python3 -B scripts/toolchain/tests/test-compiler-required-payload-policy.py
```
