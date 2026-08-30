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
