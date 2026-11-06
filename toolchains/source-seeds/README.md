# Chromium zlib source seed

`chromium-zlib-da752eb2.tar.gz` is the canonical, lock-verified snapshot of
`third_party/zlib` at Chromium commit
`da752eb2a3660cf1bf8dac620f6380b89dd953a7`. Its source and license are
inside the archive. The exact size and SHA-256 are declared in
`toolchains/compatibility-ports-v3.json`; the release producer verifies both
before placing it in the source cache and re-verifies the full cache closure.

The upstream Gitiles archive endpoint has returned HTTP 503 for real downloads
despite successful HEAD requests. This seed removes that single unreliable
network dependency from release qualification without changing the selected
source bytes. It was recovered from the successful, short-lived
`chromium-zlib-source` artifact of AROS-NX product run 36257648449 and checked
against the existing source lock before inclusion here.

`chromium-zlib-2b1b62fe.tar.gz` is the canonical snapshot of `third_party/zlib`
at Chromium commit `2b1b62fed03e8b8a64ea39a96d5cc74cd10e2429`, the revision
selected by AROS-NX pull request 120. Its exact size (3261973 bytes) and
SHA-256 (`3d56d66841a3380102abc6883fac7f756658417a9e6bc64af32a25aa57c3aeb6`)
are declared in `toolchains/compatibility-ports-sdk-v3.json`. It was fetched
with `aros cache sources fetch` from that source's `product-sources.plan.json`,
which verifies and canonicalizes the Gitiles response, and then re-checked with
`shasum`. The older seed above stays for the retained V1 locks.
