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

Use repository-scoped workflow tokens for the required mutations, in protected
environments. Do not broaden the Release Please App or introduce a PAT as an
implicit fallback. Environment protection and credential access must be
confirmed separately before activation; a workflow referencing an environment
does not prove that protection exists.

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
   native workflow at the immutable tag ref exactly once.
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

## Integration dependencies and unresolved checks

The tagged native route must accept this exact fresh private draft instead of
its current visible-release-absence contract. It must also accept the actual
tag-ref manual event without weakening the branch diagnostic boundary. Original
owner collection, attestation verification and native evidence readback must
preserve that real event identity throughout the complete plan-derived matrix.

Prove, using the pinned Release Please implementation and an isolated test
repository, that draft creation preserves a pre-existing fresh annotated tag
and reports the exact candidate. Do not assume this behavior or copy the older
lightweight-tag conversion sequence. If it cannot be established, stop for an
explicit design decision; do not retarget a tag to accommodate the library.

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
