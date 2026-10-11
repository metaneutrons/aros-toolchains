# Native V2 build handoff

The local `build-lane-v2.sh` adapter and `build-native-lane-v2` composite action
implement one build side, not the complete release workflow. They do not change
the active LLVM/V1 workflow, runtime lock, executor declaration or source pins.
Activation still requires an independently published V2-capable runtime and a
qualified native input collection. No prospective release values belong here.

## Native stage

Select the recipe, source lock, profiles, source/tools/producer checkouts and
prepared cache from the validated collection. Select the CLI digest from the
independently verified runtime inventory. The adapter accepts those explicit
paths and selectors; it does not reconstruct compiler semantics in shell.

Each group/host/profile/copy owns one absent canonical operation root:

```text
operation/
  work/                  original native lifecycle, not transported
  candidate/             original finished candidate, not transported
  payload/
    package/             only the four native package members
    evidence/
      build-result.json
      environment.json
      environment-result.json
      package-result.json
      package-verify.json
      measurement.json
  handoff.json           caller-retained local selectors, outside payload
  proof/                 added only by the owning-job action
    origin.json
    origin.sigstore.json
```

The cold build explicitly disables compiler caches and has no resume, clean or
online source-population fallback. Guarded `family-v2` packaging receives the
original work root, exact retained build-result file and its raw SHA-256.
Independent native `verify-package` must succeed before handoff. The adapter
joins archive size/hash, package paths, host/profile, schema-2 tree and exact
build-result digest to that readback. A failure retains diagnostics and emits
no success handoff; it never removes or adopts an earlier operation.

The portable measurement is a serialized native string that already contains
its terminal LF. Extraction uses `jq -j`, then checks the exact bytes against
the native producer's retained digest. `jq -r` would silently add a second LF.
Build-result and CLI bytes are remeasured before the local handoff is written.
Inputs and roots must remain quiescent and owned; this adapter is not an atomic
snapshot against concurrent writes.

The CLI's unchanged result envelope may still say `stage-v1` or `result-v1`.
The package format is explicitly `family-v2`, and the read-back manifest must
have schema 2. Schema revisions are contract-specific, not a global version.

## Owning-job transport

The composite action must execute directly in the selected build job. The
caller requires `contents: read`, `actions: read`, `attestations: write` and
`id-token: write`; no release-write permission is needed. The action rejects
missing runner OIDC request configuration before starting the native build.
That presence check does not prove provider access or authenticate a job.

After the native stage, the action uploads the original payload once, records
its numeric artifact ID/upload ZIP digest through `artifact-origin.py` in the
still-running owner, signs `origin.json`, and uploads the separate two-file
proof. Both names include the SHA-256 of the NUL-delimited, case-preserving
group/host/profile/copy tuple plus provider run/attempt. The names are computed
before compilation; legal long identifiers cannot exceed the transport name
limit or collide through ambiguous hyphen concatenation. Profile IDs retain
the native identifier contract, including uppercase letters and punctuation.
The record obtains the check ID from runner OIDC rather than caller metadata.
Its payload inventory includes exact measurement and build-environment bytes;
it does not recursively include the separate signature ZIP.

A later independent reader must select the completed successful owner and
original payload/proof numeric IDs and provider digests/sizes, authenticate both
ZIPs and the owning-job signature before admitting extracted bytes. Never use
the signed record being checked as the source of independent selectors.
Comparison jobs must not replace original build artifacts with a new upload
and claim the original owner proof authenticates that different artifact.

Each A/B side remains a distinct native execution and original artifact.
Transport authentication alone proves neither compiler independence nor byte
reproducibility, SDK compatibility, qualification or publication authority.
The complete V2 workflow must retain those separate gates and derive every
lane/count from the native release plan.

## Evidence boundary

Offline tests invoke fake CLI stages but real shell, `jq` and SHA-256 tools.
They establish sequencing, exact-byte handoff and negative-policy behavior,
not real compilation or cryptographic/provider admission. The separately
retained local RV32 compiler/package proof and live provider-origin probe do
not by themselves qualify this composite action on all release hosts.

The complete mixed production workflow, independent reader wiring, final
release qualification and recovery activation remain required work. Do not
enable production from this adapter's `local-byte-readback-only` handoff.
