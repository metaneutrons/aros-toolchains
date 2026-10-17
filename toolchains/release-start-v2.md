# Protected V2 release start

Implementation design draft; this path is not activated. This document narrows
the remaining start boundary described in [compiler and SDK qualification](compiler-sdk-ci-v2.md).
It does not replace the acceptance criteria of [RV4](https://github.com/metaneutrons/aros-tools/issues/323),
count RV64 as qualified, or admit a compiler/SDK release.

## Authority and boundaries

Release Please owns the repository version and changelog through its reviewed
version PR. A separate future protected Release Please invocation must create
the private candidate draft after admission. The current PR-preparation workflow
remains PR-only (`skip-github-release: true`); it does not create this draft.
The future draft invocation and its configuration require independent
qualification before activation. There is no second
version calculator, manual production tag fallback, or conversion of a
development qualification into production evidence.

The existing read-only admission and runtime-interface helpers are supporting
checks, not release authority. The start controller must authenticate the
published runtime and governance independently. Native producers still own
compiler A/B execution, SDK generation, compatibility and package evidence.

Compiler owner selection reads the actual event from the exact provider run
attempt, validates its repository, workflow, commit and ref, and rechecks it
before emitting the owner matrix. Tag pushes and branch/tag dispatches are
distinct valid routes; branch pushes and unsupported events fail closed. This
does not activate tag dispatch or qualify the remaining candidate adapters.

Use repository-scoped workflow tokens for the required mutations, in protected
environments. Do not broaden the Release Please App or introduce a PAT as an
implicit fallback. Environment protection and credential access must be
confirmed separately before activation; a workflow referencing an environment
does not prove that protection exists.

### Governance credential qualification

Do not assume that `Administration: read` exposes all tag governance details.
The [repository ruleset API](https://docs.github.com/en/rest/repos/rules#get-a-repository-ruleset)
requires only metadata read access for the rule document, but documents that
`bypass_actors` is returned only when the caller has write access to the ruleset.
A successful GET therefore does not establish that the caller can prove an
empty bypass list. On 2026-10-13 the public read of the active tag ruleset
omitted that field, while the existing privileged operator read explicitly
returned an empty list. Neither observation qualifies a proposed read-only
installation token.

Before configuring a governance credential, probe its exact granted scope and
the complete response, including an explicit empty bypass list. Keep the current
missing-field rejection. Do not grant administrative write rights merely to
make this probe pass, silently substitute the operator's token, or infer no
bypasses from an omitted field. The fresh pre-mutation recheck must use a caller
whose visibility is independently proven; a saved receipt does not make hidden
current policy visible. The initial REST-only credential boundary was
unqualified. The independently measured GraphQL job-token reader below
supersedes that transport limitation; it does not qualify the complete start.

The existing contracts workflow has an opt-in `governance_visibility_probe`
dispatch. Its two jobs use only the automatically issued job token, with
`contents: read` and `contents: write` respectively, and perform bounded GETs.
They report whether the bypass field is visible, its count, and the public
policy digest; they do not expose actors or credentials. Neither report is an
admission receipt. This probe is intended to determine whether the normal
protected-start job token suffices before introducing another credential.
The write-capable job is restricted to protected main; its initial controlled
branch observation used the explicitly inspected source commit, not arbitrary
dispatch input code.
The read-only job additionally observes the documented GraphQL ruleset
connection's bypass count without actor identities. This is an alternative
visibility probe, not a fallback that admits a candidate. A reported zero
alone does not prove complete visibility; a known nonempty provider
counterprobe is required before this interface could replace governance reads.
It creates no tag, draft, release, dispatch claim or package publication.

The initial REST provider probe, run
[38456476174](https://github.com/metaneutrons/aros-toolchains/actions/runs/38456476174)
on inspected commit `36d300dc35ac69f8a015ccbb8107b7ba8ea25eff`, passed its
contracts and both visibility jobs. Both normal job tokens omitted
`bypass_actors`: `contents: read` and `contents: write` returned the same
public policy digest, but neither proved an empty bypass list. No credential
was created or copied and no tag/release was changed. The normal token is
therefore insufficient for the complete REST governance gate tested here.

### Qualified job-token governance reader (2026-10-14)

The ordinary workflow token can prove the bypass connection through a strict
GraphQL read. An isolated private fixture with one known bypass returned a
complete connection with count one while REST hid the actor. The temporary
fixture rule was removed and the fixture repository archived again. No product
tag, release, App or secret was changed by that counterprobe.

The production reader was then exercised with `contents: read` in
[run 38488885014](https://github.com/metaneutrons/aros-toolchains/actions/runs/38488885014).
It joined the exact numeric ruleset ID to its GraphQL node, required count zero,
an empty node list and no next page, and returned a live governance-only receipt.
PR #75 merged that reader and its rejection tests. The reader fails on GraphQL
errors, malformed or incomplete connections, mismatched identities and explicit
nonempty REST bypass data. Both initial admission and the pre-mutation recheck
use the job token; no separate governance secret is required by this reader.

These observations establish the governance transport, not runtime admission,
candidate creation, signed-start authenticity or exclusive native dispatch.

## Event sequence

1. The existing PR-only Release Please workflow prepares the version PR.
2. Successful main CI completion wakes a distinct protected start workflow.
   It executes reviewed main code, never event-supplied PR code or scripts
   downloaded from an upstream run. Admission binds the exact version merge,
   successful complete CI attempt, source inputs, runtime and governance.
3. A privileged recheck establishes tag absence and private-draft absence.
   The read-scoped admission lookup alone is insufficient for the latter.
4. The controller creates one fresh annotated tag on the admitted main commit.
   The separate protected Release Please draft invocation then creates only
   its exact private empty draft without
   changing that tag. Tag creation may suppress a push-triggered run when a
   workflow token is used; the explicit dispatch below must not depend on one.
5. The start workflow retains a signed, bounded start record and completes
   successfully. The record binds the producer commit, annotated tag object,
   draft ID, admitted inputs/runtime, original workflow/run/attempt/job and
   independent artifact selectors. It is not compiler or SDK qualification.
6. A separate dispatcher wakes only on that successful start completion. It
   authenticates the original record and provider state, then dispatches the
   native workflow at the immutable tag ref exactly once. Before dispatch it
   attests the exact canonical claim under its own original workflow/job and
   retains that signature separately from the sole private-draft claim asset.
   Native entry independently authenticates this dispatcher signature and
   successful original owner; unsigned claim fields alone are not causal proof.
7. The native workflow records the actual `workflow_dispatch` event and tag
   ref. It must not fabricate `push` claims, infer production from a branch
   diagnostic, or trust arbitrary caller-supplied run/tag/draft selectors.

Separate start and dispatcher workflow identities avoid a self-triggering
`workflow_run` completion loop. The dispatcher must reject duplicate start
events, unsuccessful or rerun starts, changed tag/draft/input/runtime identity,
and an already consumed native dispatch.

## Start acceptance criteria

- **START-A1:** The admitted version comes from one exact merged App-authored
  Release Please PR and protected main. All required main checks belong to the
  complete selected successful attempt. An ordinary non-release main update
  performs no tag, draft or dispatch mutation.
- **START-A2:** Every selected runtime asset passes immutable-release identity,
  exact bytes, signatures and provenance verification. Its exact executable
  also passes the V2 interface check. Matching a version string alone fails.
- **START-A3:** Privileged fresh reads prove no tag or private draft exists
  before creation. Authentication errors, rate limits, malformed responses and
  uncertain transport results are not absence or permission to retry mutation.
- **START-A4:** Create one annotated tag with the exact commit and timestamp;
  never replace a lightweight tag or change an existing tag object. Require
  the new Release Please draft to be private, empty and identity-matched.
- **START-A5:** Authenticate the signed start record against its successful
  original provider workflow, attempt and job before expensive native fan-out.
  Self-reported JSON, a local digest or an interface receipt is insufficient.
- **START-A6:** Native dispatch uses the actual immutable tag ref and event.
  Its frozen workflow/input identities remain distinct from the main-based
  controller identity. A later main update must not silently substitute code
  or input bytes in the tagged native execution.
- **START-A7:** Prove exclusive single consumption of a successful start.
  Concurrency configuration alone is not durable duplicate-dispatch evidence.
  Unknown mutation outcomes stop for diagnosis; no blind retry or retargeting.

Each criterion needs a positive probe and counterprobes for changed identities,
wrong events/refs/attempts, incomplete or failed provider jobs, occupied outputs,
existing candidates and ambiguous observations. Fixture tests establish adapter
behavior only. Before production activation, require a real nonpublishing
start/dispatch observation with authentic provider/signature evidence.

### Inactive start transport retention

`scripts/toolchain/seal-compiler-sdk-start-v2.py` copies selected record and
signature-bundle bytes into a fresh private directory. It requires the fixed
subject basename `compiler-sdk-release-start-v2.json` and an independently
selected record SHA-256. It preserves that basename, retains the bundle as
`compiler-sdk-release-start-v2.sigstore.json`, and enforces the reader's 128 KiB
record and 8 MiB bundle limits. Owned, singly linked regular input files and
nonlinked path components are checked before output creation; source identity
and bytes and exclusive private output files are checked again afterward.

This primitive neither signs nor verifies a signature. It does not authenticate
the start, provider or published runtime, select cross-run artifact pins, upload
an artifact or authorize a dispatch. No workflow calls it. The future caller
must keep its owned private output parent quiescent, supply the independently
captured digest and authenticate all original
provider and signature boundaries. A late failure may leave partial private
output: that output is unusable, must not be retried, and is not automatically
removed. The first directory identity is observed after exclusive creation;
these point-in-time checks do not atomically prove that identity against a
concurrent same-user or privileged writer. They are not an OS sandbox and do
not inspect ACLs. Local fixtures prove copying and rejection
behavior only; START-A5 and START-A7 remain open.

## Integration dependencies and unresolved checks

### Pinned library observations

The current action pin is `45996ed1f6d02564a971a2fa1b5860e934307cf7`.
Its [dependency lock](https://github.com/googleapis/release-please-action/blob/45996ed1f6d02564a971a2fa1b5860e934307cf7/package-lock.json)
selects Release Please 17.6.0; the matching upstream source commit is
`712fcf01effd08d7b0e7b1fd3861f2cb388bc8d1`.
Read-only inspection establishes the following code paths, not live GitHub
behavior or production qualification:

- The action's [manifest loader](https://github.com/googleapis/release-please-action/blob/45996ed1f6d02564a971a2fa1b5860e934307cf7/src/index.ts)
  does not override the manifest configuration's `skip-github-release` value
  from the action-level switch. The strategy's
  [release builder](https://github.com/googleapis/release-please/blob/712fcf01effd08d7b0e7b1fd3861f2cb388bc8d1/src/strategies/base.ts)
  returns no candidate when that configuration disables release creation.
  The future protected draft configuration must explicitly select
  `skip-github-release: false`, `draft: true` and
  `force-tag-creation: false`. If using the action, its inputs must also set
  `skip-github-release: false` and `skip-github-pull-request: true`: otherwise
  it can skip release creation or run the PR-creation phase afterward. The
  current preparation workflow remains PR-only through its action-level switch.
- The library's [release API adapter](https://github.com/googleapis/release-please/blob/712fcf01effd08d7b0e7b1fd3861f2cb388bc8d1/src/github-api.ts)
  calls Git ref creation only when `forceTag` is enabled. That branch suppresses
  every HTTP 422 from ref creation, not just an independently verified
  existing-tag result. Do not use that suppression as identity evidence.
  With `forceTag: false`, this adapter sends only the release-creation request;
  the controller must independently re-read the annotated tag afterward.
- The manifest's [release orchestration](https://github.com/googleapis/release-please/blob/712fcf01effd08d7b0e7b1fd3861f2cb388bc8d1/src/manifest.ts)
  groups candidates from pending merged PRs and changes their release labels
  after creation. Admission of one exact PR must therefore be enforced before
  invocation; an action output checked only afterward cannot prevent creation
  of additional candidates. Draft creation and label changes are not proof of
  compiler/SDK qualification. Qualify the exact-candidate invocation before
  activation, including multiple pending and historical terminal PRs.
  The protected invocation must set `skip-labeling: true`; its subsequent
  binding check requires the admitted PR to remain pending. Label transition
  is not an alternative admission route.

### Remaining integration proof

`scripts/toolchain/compiler-sdk-release-start-v2.py` is an inactive reader for
the future signed start. It verifies the independently selected original
main-based workflow/run/attempt and successful owning job, authenticates the
exact record subject through GitHub attestations, rereads the frozen input
blobs, and checks the annotated tag plus exact private empty draft. It repeats
run/job observations and record/bundle byte readbacks before returning.
Its offline fixtures do not prove a real signed start. No workflow currently
calls it, and it neither constructs a start nor consumes or dispatches one.
The reader also requires independently selected runtime paths and host: it
hashes the retained materialization and interface receipts, checks the exact
locked file closure, joins the executable to its manifest and interface
measurement, and repeats these byte checks after provider observations.
The original interface path is evidence, never a reader-supplied execution
path; the only executable inspected is the selected runtime's `bin/aros`.
These joins do not redo publication signatures or prove the start ran the
materializer. The future protected workflow must authenticate the published
runtime before constructing/signing the start and bind host selection to its
actual provider environment; a local receipt cannot replace those gates.
The retained closure check is point-in-time: held descriptors and directory
readbacks detect concurrent changes during inspection, but do not make a
mutable tree permanently immutable. The controller must keep runtime staging
private from unrelated writers throughout measurement and start construction.
Runtime materialization, fresh privileged absence, mutation outcome checks,
record signing/retention and exclusive consumption still require the complete
protected controller and a genuine provider observation.

`scripts/toolchain/prepare-release-draft-config-v2.py` derives an inactive draft
configuration from the committed `release-please-config.json`. It preserves the
reviewed version strategy and sole root package, changes only the three draft
settings above, and rejects conflicting package overrides or occupied output
paths. This offline adapter is not admission or release authority. No workflow
invokes it for publication; the action's two explicit switches and all protected
start gates still require integration and qualification.

The tagged native route must accept this exact fresh private draft instead of
its current visible-release-absence contract. It must also accept the actual
tag-ref manual event without weakening the branch diagnostic boundary. Original
owner collection, attestation verification and native evidence readback must
preserve that real event identity throughout the complete plan-derived matrix.

The artifact-origin reader now observes the exact provider run attempt and its
actual event. It binds the current reader's OIDC `event_name` to that observation
and rechecks the original source event and identity before retaining bytes.
Existing seven-field contexts and signed origin formats remain unchanged.
These transport checks do not yet bind native matrix projections to that event
or authorize a production tag dispatch; those caller integrations remain open.

Compiler owner selection and the compiler, combined-candidate and native-evidence
adapters now preserve the actual provider event with the canonical source
context. They reobserve the exact source attempt before emitting results.
This closes their event projection boundary, not START-A5 through START-A7 or
the production workflow entry.

### Provider observations (2026-10-13)

The pinned action was exercised in a separate private test repository with
its repository-scoped workflow token. It prepared an exact three-file version
PR, then created its private draft after an inspected merge and fresh annotated
test tag. No product repository, App, secret or published release was changed.

| Case | Measured result |
| :--- | :--- |
| Prepare PR only | Manifest, changelog and version file changed; no tag or release created. |
| Create draft with `force-tag-creation: false` | One private empty draft on the exact candidate commit; `releases_created` true. The annotated tag object, peeled commit and timestamp remained unchanged. |
| Wrong expected tag object | Caller admission failed; the Release Please step was skipped. Existing tag and draft remained unchanged. |
| Existing private draft | Caller admission failed; the Release Please step was skipped. No second draft or tag mutation. |
| Historical merged PR marked pending | The PR-only preparation phase aborted with the library's outstanding-untagged-PR diagnostic; it created no next PR. |
| Two merged pending PRs, including an otherwise valid fresh candidate | Caller admission failed before Release Please. No fresh draft was created; both annotated tags and the earlier private draft remained unchanged. |
| Archive the private fixture | Draft listing became empty and its numeric GET returned 404. Briefly unarchiving returned the same unchanged draft ID; the repository was then archived again. |

This proves the tested provider behavior and fixture guards, not production
START acceptance. The fixture used GitHub Actions' bot rather than the
production Release Please App; it did not authenticate a released runtime,
sign a start record, dispatch native qualification or prove durable consumption.
The test labels were restored and the private fixture repository archived
without publishing, deleting or retargeting either test version. Production
admission and dispatch still require independent qualification. Do not copy the older
lightweight-tag conversion sequence or retarget a tag to accommodate the library.
An archived repository's draft 404 is not evidence of absence: require an active
repository before using privileged absence checks.

The same isolated private fixture also exercised fixed-name draft asset
consumption without a native dispatch. A confirmed existing name rejected a
second upload with HTTP 422. A fresh-name parallel upload returned HTTP 201
and HTTP 404, with exactly one retained asset; numeric-ID downloads matched
the submitted bytes and the annotated test tags remained unchanged. The
expected 422 race-loser assertion failed: this is not a wholly successful
consumption proof. The fixture was archived again without publishing or
deleting its test assets.

The dispatcher must proceed only after its own confirmed HTTP 201 and exact
numeric asset readback. Any other or unknown mutation result, including 404,
stops that invocation without retry, deletion, replacement or an alternate
claim name. The fixed-name claim must bind the independently authenticated
original start and exact tag/draft/input identities and remain in the closed
candidate inventory. The provider uniqueness observation alone proves neither
that binding nor a successful exclusive native dispatch; START-A7 stays open.

`scripts/toolchain/compiler-sdk-dispatch-claim-v2.py` prepares only a closed
canonical payload for the fixed name `compiler-sdk-dispatch-claim-v2.json`.
It binds original start/signature byte hashes, source owner, exact tag/draft,
frozen input/runtime digests, and a distinct original main-based dispatcher
context/job. The dispatcher code commit may differ from the tagged producer
commit; its projected native target must still be the exact admitted tag.
The selected actual dispatcher event and complete triggering start context
are explicit inputs; only the `workflow_run` edge to that original start is
accepted and retained. The controller must authenticate this provider edge,
not derive it from the payload's own claims.
Changed selectors, extra fields and noncanonical byte readbacks are rejected.
This codec neither authenticates those contexts nor uploads/consumes anything.
The future controller must independently authenticate both provider identities
and the start before using it, then bind one confirmed HTTP 201 and numeric
asset readback to those exact bytes. No workflow calls the codec yet, and no
exclusive consumption or native dispatch has been qualified by its fixtures.

The codec also exposes an inactive read-only dispatcher-signature gate. It
requires exact selected claim/bundle byte hashes, canonical joins to the
original start bytes and independently selected dispatcher context, successful
original provider run/job observations, and a GitHub attestation bound to the
fixed dispatcher workflow, code commit, main ref and original run invocation.
The verifier uses private copies of the captured subject and bundle, reobserves
the owner afterward and rejects changed input bytes. This is only one native
entry prerequisite: the original start must still be independently authenticated,
the exact sole draft claim must be downloaded by numeric ID, and actual native
tag-dispatch identity must match. No workflow currently signs a dispatcher
claim or invokes this gate; fixture tests are not provider qualification.

`scripts/toolchain/compiler-sdk-claim-upload-v2.py` is an inactive internal
post-authentication primitive. It requires that exact canonical claim, rechecks
the active repository and exact empty private candidate, performs one bounded
upload call, and admits only a confirmed HTTP 201 with the expected numeric
asset identity, size, MIME type and digest. It then downloads by numeric ID and
requires the original bytes plus an exact private-draft/sole-claim readback.
All candidate observations use the same pinned GitHub.com job-token transport;
the active repository and exact annotated tag are rechecked after readback.
An occupied name, unknown outcome or failed readback stops without another
upload, rename, deletion or native dispatch. The future controller must
authenticate all provider/crypto boundaries before calling this primitive;
its return value alone is not dispatch authorization. No workflow calls it.
The CLI transport's numeric download was observed read-only against a public
checksum asset with HTTP 200 and exact byte count; this does not qualify a
real upload, job-token custody, private claim race or native dispatch.

`scripts/toolchain/compiler-sdk-dispatcher-auth-v2.py` is an inactive read-only
identity component for the future caller. It obtains the current check ID from
authenticated runner OIDC, selects its exact executing provider job, and binds
the actual bounded completion event to the independently selected original
start context. Current/source attempts and owning job are reobserved; changed
event bytes fail closed. All run/job reads use the fixed GitHub.com transport
and finite attempt-specific pagination. Its output explicitly qualifies only
dispatcher identity and the causal edge, not signed-start/runtime authenticity,
claim consumption, native dispatch or product qualification. No workflow calls
it, and its fixtures do not establish a genuine provider/OIDC observation.

`scripts/toolchain/compiler-sdk-authenticated-claim-v2.py` composes the inactive
identity, signed-start/runtime-evidence verification and one confirmed upload
primitive. It selects bounded original record/bundle bytes, passes both exact
SHA256 pins into cryptographic verification, derives the claim only from those
bytes, and repeats identity and start verification before mutation. The external
verifier receives private copies of captured bytes, preserving the signed
subject basename; it never reopens the caller's mutable record/bundle paths.
A temporary caller-path substitution regression verifies this boundary.
A partial
pin selection, semantically identical but different raw bytes, changed identity
or failed evidence gate rejects before upload. The caller must independently
materialize the authentic published runtime in private, quiescent staging;
this composition does not replace that publication-authentication gate. It has
no CLI/workflow entry point, dispatches nothing and reports only authenticated
claim-upload assurance, not native qualification or publication authority.

`scripts/toolchain/construct-compiler-sdk-start-v2.py` is an inactive unsigned
record constructor. Its current supported start host is the fixed hosted
`ubuntu-24.04` Linux x64 job. It derives the original context from runner
environment/OIDC and provider jobs; binds captured completion-event and source
CI repository IDs, exact CI attempt, clean checkout and frozen Git inputs;
derives runtime digests from retained files and rechecks candidate, runtime,
source and own job before returning. The signed-start reader independently
checks that fixed provider runner label in both job snapshots. Construction
does not create candidates, authenticate publication on behalf of the caller,
sign records, consume claims, or activate workflows. Its CLI bounds the
admission, tag and draft input files, repeats their byte checks after
construction, and writes only one canonical unsigned record to an absent
regular output path. An occupied or linked output, changed input or failed
constructor produces no record. This local output is not an attestation or
release authority. Those genuine
provider, admission/runtime-authentication and publication gates remain open.

`scripts/toolchain/create-compiler-sdk-candidate-v2.py` exposes two inactive
protected-controller commands. `create-tag` independently re-runs full admission,
authenticates and privately materializes the locked published runtime, measures
its V2 interface, and repeats job, governance, CI, input and runtime checks before
the tag object and ref mutations. Only two confirmed HTTP 201 results and exact
readbacks can produce its exclusive canonical tag handoff. Drift after the
first write stops without another write; drift after tag readback stops without
authorizing the separate Release Please action. No tag is retried or replaced.

`bind-draft` creates nothing. It requires the separate pinned action's exact
created/tag/commit/version/numeric-ID outputs, the unchanged annotation and one
private stable empty draft selected consistently by numeric ID, tag and bounded
listing. It rechecks pending PR, successful original CI, governance, source
inputs and existing private runtime without re-running the pre-tag absence gate.
Its exclusive output remains unsigned metadata, not release authority. An I/O
failure can leave a partial private output; a nonzero command is never an
authorized handoff, even when provider writes already succeeded.

The candidate tests exercise real controller/admission/materializer/interface
paths with isolated provider, OIDC and signature-verifier fixtures, including
late drift and unknown mutation results. They do not qualify live provider
mutation, draft creation, signing, native dispatch or publication. No workflow
invokes these commands until the complete protected path is qualified.

The released V2 runtime, source qualification and complete compiler/SDK matrix
remain prerequisites. This design neither changes source pins nor waives
missing source authorization. It creates no environments, grants, tags,
drafts, dispatches or publication.

## Qualification, publication and recovery

The successful start authorizes only one candidate qualification. It does not
authorize partial publication or promotion of diagnostic owner roles.

Final publication still requires all original compiler copies, comparisons,
real SDK generations and original/relocated C/C++ link evidence from the native
plan; cross-host SDK byte equality; the closed combined inventory; signatures
and provenance; durable complete qualification; and independent isolated draft
download/readback. Never use a fixed legacy asset count for V2.

Public URLs, immutable release state and fresh locked compiler/SDK consumer
installation must be verified afterward. Failed candidates remain untouched.
The V1 recovery workflow cannot consume V2 artifacts. V2 recovery must preserve
the original tagged owners, qualification and signatures while using a separate
authentic recovery caller; it cannot rebuild history or manufacture acceptance.
