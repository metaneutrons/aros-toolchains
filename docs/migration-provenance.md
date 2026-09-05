# Migration provenance

This repository was extracted on 30 August 2026 from
`metaneutrons/AROS-NG`, branch `integration/upstream-20260826`, at source
commit `a74b18a10f`.

The history filter retained exactly these paths:

- `scripts/toolchain/`;
- `toolchains/`;
- `.github/actions/setup-aros-rust/`;
- the three toolchain workflows;
- the historical root consumer lock; and
- the source license.

Before standalone edits, the result contained 26 files and 47 commits. Sorted
source and result manifests compared every Git blob ID and path without a
difference. The only message rewrite removed two exactly matched
automated-assistant co-author trailers; no human authorship, source byte, or
unrelated message byte was deliberately changed.

The filter-repo commit map, both blob manifests, and a complete filtered-history
bundle are preserved in the verified AROS-NG migration safety snapshot outside
this repository. The historical consumer lock was retained for extraction
proof and then removed from the current producer tree because consumer policy
belongs in AROS-NX and other downstream repositories.

## Standalone release

[`toolchain-v1-20260831-rc3`](https://github.com/metaneutrons/aros-toolchains/releases/tag/toolchain-v1-20260831-rc3)
was published as a prerelease on 31 August 2026 at 23:03:03 UTC. The
[tagged producer run](https://github.com/metaneutrons/aros-toolchains/actions/runs/33384787694)
is the provenance source; this is not a republished AROS-NG asset set.

The signed `toolchain-index-v1.json` records:

| Identity | Exact commit |
| --- | --- |
| AROS-NX source | `f3cfc243a84065166a46da28b0a5b22bbd0f8869` |
| aros-tools | `707037be4f8ff37300a1a89166c35f661c28bafe` |
| aros-toolchains producer | `c8039cf2b7291097ad62c6750bd7367e91a068f4` |

The release has 56 public assets. Its index enables exactly twelve archives:
Linux/macOS x86-64/ARM64 hosts crossed with `pc-x86_64`, `arm-raspi` and
`rpi-aarch64`. No RISC-V archive or physical-board boot proof is implied.

On 5 September 2026, the public index was independently downloaded again,
matched against `SHA256SUMS`, and its GitHub attestation verified with the
exact `toolchain-release.yml` signer, tag ref and producer commit, rejecting
self-hosted runners. The measured index size was 16,587 bytes and SHA-256 was
`31f8d4f91fbd69c3d112d3b401d3d4620c8dd4f3bc59a57fe3c881141c3a2abf`.
This follow-up is an index/provenance verification, not a claim that every
compiler archive was downloaded or independently rebuilt again that day.

For future releases, change the explicit recipe through review and repeat the
applicable release gates. Documentation updates never retarget this tag,
change its assets or substitute newer source identities into its provenance.
