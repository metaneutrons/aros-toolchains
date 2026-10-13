# Native V2 lane admission

`scripts/toolchain/admit-lane-v2.sh` joins original owning-job transport
authentication to native portable package readback. It does not build a compiler,
compare A/B packages, run compatibility tests, authorize publication, or activate
the production workflow.

## Independently selected inputs

The caller selects the reviewed source workflow/ref, original job and numeric
payload/proof artifact identities through the closed source-selection document.
It supplies that document's raw SHA-256, the native recipe/lock/profiles and
their raw SHA-256 values, group/host/profile/copy/release identity, exact owning
host environment bytes, approved executor contract and owning-host executor
binary digests. None of those identities comes from a package manifest being
checked. The original workflow producer commit must equal the selected recipe's
producer commit.

The reader CLI is selected separately by its executable digest. Its binary
need not equal an executor on a different host. Its portable Rust verifier still
checks the original executor identity against the separately selected contract
and executor binary digests. The caller must obtain an independently verified,
published V2-capable runtime before activating production.

Source workflow/ref selection is not an authorization mechanism. A protected
production caller must select a reviewed release workflow and commit, derive
every lane from its validated native plan, and enforce fresh-release/recovery
policy. A diagnostic branch passing this adapter is not a qualified release.

## Sequence

1. Validate selectors and input digests before creating an absent canonical
   owner-only operation root. Reject mismatched lane, workflow, ref or producer.
2. Invoke `artifact-origin.py verify-source` in this invocation. Authenticate
   the executing reader independently, then the original successful owning job,
   signed origin, provider identities and exact original ZIP bytes. Retain the
   four verified transport files under `transport/`. There is no option to adopt
   a previously retained directory instead of performing authentication.
3. Use `native-lane-transport.py` to read back the raw ZIP against the closed
   signed inventory, then extract exactly ten ordinary native handoff files into
   `payload/`. The extraction primitive grants no authentication or admission.
4. Require transported environment bytes to equal the caller's selected owning
   host environment. Obtain the measurement digest from the authenticated
   origin inventory, not a self-assertion inside that measurement.
5. Invoke the selected native CLI's `verify-package` with explicit `family-v2`,
   the exact portable measurement and all executor selectors. Rust validates
   recipe/lock/profile, package closure, archive tree, retained build/receipt
   bytes and original identity joins. Require the portable readback envelope;
   a runtime silently ignoring these selectors cannot pass.
6. Re-read transport and extracted bytes without writing, remeasure selected
   inputs/runtime, and only then write `admission.json`.

Explicit `--same-attempt` forwards the existing strict same-attempt reader mode.
It does not impersonate the owner: the completed source owner must still be a
different job from the current authenticated reader. Without this flag the
original cross-attempt policy applies.

The operation root retains diagnostics on a later failure but contains no
success admission. Existing roots are never adopted, overwritten or deleted.
Inputs and roots must stay quiescent in a caller-owned workspace; these byte
readbacks do not provide isolation from a hostile concurrent writer.

## Transport extraction boundary

The retained root contains exactly `payload.zip`, `origin.json`,
`origin.sigstore.json` and `selection.json`. Selection and origin are joined
before extraction. The payload contains one package archive plus its appended
manifest/checksum/SPDX sidecars, and exactly these six evidence files:

```text
build-result.json
environment.json
environment-result.json
package-result.json
package-verify.json
measurement.json
```

The transport primitive uses the existing bounded ZIP validator, exclusive
ordinary-file creation, streamed extraction, closed inventory and final byte
readback. It rejects unexpected entries, path aliases/traversal, duplicate
members, links, unsupported compression and invalid sizes/hashes. It never
extracts the tar payload or interprets compiler/SDK semantics. Its readonly
`--verify-output-dir` mode checks the same retained and extracted identities
without modifying them.

## Evidence and remaining release gates

The output assurance is
`authenticated-transport-and-native-byte-readback-only`. It is not cold-build
independence, byte reproducibility, SDK compatibility or release authority.
Retain both original A/B artifacts separately; comparison jobs must not replace
them with a new upload and attach an original owner proof to different bytes.

Offline process-boundary tests use fake provider and native CLI responses.
Transport tests use synthetic ZIP files. They establish sequencing and rejection
behavior, not actual compiler execution or cryptographic authentication. A live
native owning-job upload/readback exercise remains required, followed by the
complete selected mixed-family matrix, comparison/compatibility evidence,
closed release index, isolated signature/attestation audit and consumer cutover.

## Durable V2 qualification adapter

`record-complete-qualification-v2.py` is a product-tag recording adapter. The
workflow invokes it only after complete original-owner readback, genuine staged
provenance verification and final native evidence verification. It requires independently held runtime,
collection, index, selection, candidate-summary and external subject-list
digests. The candidate release ID and download URL must match the selected
SemVer tag and repository; diagnostic identities cannot be recorded through it.

The adapter rechecks the staged provenance bundle through the external verifier,
including the exact source commit, tag ref, run and attempt. It then invokes
native `record-qualification --release-format family-v2` and
`verify-qualification` against the complete original compiler and SDK evidence.
Returned counts, tuples, report and package digests must match the held
selectors. Only after both native operations pass does it expose the unchanged
qualification document and return its raw digest. Child files are bounded to
16 MiB; timeouts terminate the process group. Existing operation roots are
never adopted or overwritten, and failures retain diagnostics without a success
summary.

Place the fresh operation directory beneath an owned parent outside the release,
selected evidence and all forbidden build prefixes. In particular, an output
under `RUNNER_TEMP` cannot be used when that entire root is a forbidden prefix.

The workflow reauthenticates the tag against the preparation observation and
rechecks the released runtime immediately before recording. Its fresh evidence
directory is outside the forbidden workspace and temporary build roots. The
unchanged verified qualification document receives its own provenance attestation;
the record, policy, diagnostics and signature are retained together for 90 days.
Failed recordings retain separately named diagnostics, not success qualification.
The candidate qualification window is seven days and is never extended by this
step. Artifact retention is not permission to replay or publish expired evidence.

The protected caller authenticates original owning jobs, obtains genuine
provider/tag observations and independently verifies the released runtime.
Supplied tag-object metadata and a binary hash do not establish those properties.
This adapter neither creates tags/releases nor grants publication authority.
Its synthetic process-boundary tests exercise sequencing and rejection, not a
real signed-production invocation or successful compiler/SDK qualification.

## Independently observed V2 recovery request

`prepare-recovery-request-v2.py` accepts separate, hash-selected run, annotated
tag and attestation observations. It does not derive those observations from
the qualification document. The protected caller must first authenticate them
against the provider, Git repository and signature verifier.

Only `packaging-recovery` after `packaging`, or `compatibility-replay` after
`compatibility-harness`, is eligible. Compiler, configure, comparison, actual
compatibility and attestation failures are not recoverable through this route.
Packaging requires an independently observed absent handoff with a fresh
SemVer tag object peeling to the original producer commit. Replay forbids a
handoff. The adapter creates no tags and performs no recovery or publication.

The adapter invokes native `producer verify-recovery` on the original complete
compiler and SDK closure. It exposes the unchanged request only after the
native decision, selected digests and late input readbacks agree. Its synthetic
process-boundary tests establish rejection and sequencing, not authentication
or a successful production recovery. A published runtime, authenticated
original owners and complete isolated release audit remain separate gates.

The adapter joins selected package digests, product IDs, generation tuples and
qualification receipts. Additional detailed fields in `native_result` are
reported from the hash-selected native runtime, not independently re-derived
or authenticated by the Python adapter. They are not a publication decision.

## Read-only isolated V2 release audit

`audit-isolated-release-v2.py` checks an already isolated final inventory against
an independently held original qualification document. It reuses the closed V2
index, candidate summary and compiler/SDK selection; it does not assume the
historical 44-file inventory or a fixed replacement count.

The adapter verifies signed provenance for the exact selected tag, commit, run
and attempt, then invokes native `producer verify-qualification`. The explicit
current-time policy must respect the original qualification lifetime. It never
records replacement qualification, runs an index-writing stage, downloads or
publishes assets. Its fresh operation directory contains audit diagnostics and
policy only; the original release and evidence bytes remain unchanged.

Provider download selection, original-owner authentication, annotated-tag
observation and released-runtime authentication remain protected-caller gates.
The adapter's synthetic fixtures prove its local sequencing and failure
boundaries, not a signed production release or final public download URLs.

## Product-tag entry

`select-compiler-sdk-route-v2.py` admits a tag qualification only on its first
attempt. The canonical SemVer tag must match `version.txt` in the clean selected
commit, be annotated under its own name, and match GitHub's exact object and
peeled commit. The commit must belong to protected `main` history. Only a real
HTTP 404 establishes that its GitHub release is absent; authentication failures,
rate limits and transport errors do not establish absence.

Before any source checkout or runtime download, the selected tools commit must
match the published runtime lock. Tags use only that host-matched released
runtime. Branch diagnostics may use the explicitly selected development runtime;
there is no fallback from a failed released-runtime verification.

Runtime artifacts retain the signed manifest and receipt. Offline transport
verification checks the manifest's exact independently locked digest and size,
the complete file closure and every payload digest before restoring executable
modes lost during artifact transport. Ordinary verification remains read-only
and mode-strict. Symlinks, hardlinks, extra files and resealed forged manifests
are rejected before restoration.

The full native plan selects owning jobs and SDK generations. The validated tag
name reaches both compiler owners, combined assembly and the final index, while
SDK product versions remain source-owned and independent. These tag-bound byte
readbacks still do not issue publication authority. A product tag additionally
records and signs complete native qualification, but durable recovery readback,
the final Release Please production trigger and isolated publication audit must
still be wired and verified before publication. The retained V1 publisher cannot
receive a tag push.
