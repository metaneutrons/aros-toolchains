# Toolchain release handoff

Status date: 2026-09-12

## Current verified distribution

The immutable prerelease
[`toolchain-v1-20260912-rc8`](https://github.com/metaneutrons/aros-toolchains/releases/tag/toolchain-v1-20260912-rc8)
is the current M7 distribution candidate. Its annotated tag object is
`6b904632d5fda7fea8f9259de27b34e77c1556db`; it peels exactly to producer
commit `d018d11dd6f995fc1f37d0b2b431f94a6ec78fd5`. It was built against AROS-NX
`9369cc8f8ba4f7d320945c78788c6e2a6d0d1eab` and aros-tools
`253c11a52af6c4eff8d0e3db2ea2d33b740bef79`.

Producer run
[`34699919725`](https://github.com/metaneutrons/aros-toolchains/actions/runs/34699919725)
completed successfully with all 18 independent builds, all nine byte-identical
A/B comparisons, all nine compatibility/relocation lanes, and draft creation.
The active matrix is Linux x86-64, Linux AArch64, and macOS AArch64, each for
`pc-x86_64`, `arm-raspi`, and `rpi-aarch64`.

Two fresh isolated audits ran against the draft and against the published
prerelease. Each downloaded all release assets into a new root and verified:

- exactly 44 regular release assets: nine archives, nine manifests, nine SHA
  sidecars, nine SPDX 2.3 SBOMs, and eight shared files;
- `SHA256SUMS` over exactly 43 non-self assets; all checksums, sizes, index
  records, embedded manifests, required paths, and tree digests;
- qualification evidence for the complete 3×3 active matrix and its lifecycle,
  A/B comparison, and compatibility receipts;
- 42 signed pre-provenance subjects with GitHub/Sigstore provenance; and
- every final GitHub download URL.

The release was promoted unchanged only after the draft audit passed. RC6 and
RC7 remain immutable, unpublished historical candidates; do not delete,
retarget, publish, or reuse them.

## Consumer promotion

AROS-NX [PR #30](https://github.com/metaneutrons/AROS-NX/pull/30) contains the
measured RC8 lock promotion. It activates only the nine qualified artifacts,
suspends the three Intel macOS profiles pending
[aros-toolchains#27](https://github.com/metaneutrons/aros-toolchains/issues/27),
and preserves the four disabled RISC-V declarations. A fresh macOS AArch64
store passed `aros toolchain list`, online install, verification, and offline
re-install for all three active profiles. The exact lock commit is
`f5f968973d`.

Merge that narrow consumer-lock change normally. Do not alter the RC8 release
or replace its measured values while doing so.

## Resume safely

1. Recheck the immutable tag object, peeled producer commit, release state, and
   the current PR state before taking action.
2. Treat the release index and manifests as the only source for consumer-lock
   values. Never reconstruct hashes, sizes, or tree digests from a retained
   working directory.
3. Intel macOS is deliberately outside this release boundary until #27 is
   independently qualified. RISC-V requires its own release qualification.
4. Keep raw logs, temporary download roots, machine-specific paths, and
   credentials outside Git. This file records durable public evidence only.
