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
