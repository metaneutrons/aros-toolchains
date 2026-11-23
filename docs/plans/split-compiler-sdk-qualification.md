# Initiative plan: split compiler and SDK qualification

Epic: [#161](https://github.com/metaneutrons/aros-toolchains/issues/161)
Decision state: accepted by the maintainer on 2026-11-23, with these decisions:

- binding policy (b), "same compiler inputs";
- the tag-bound product release also uses the split path, through a second dispatcher stage (D7);
- the monolithic `qualify-v2-full` mode is removed.

## Outcome and boundaries

Today `qualify-v2-full` in `.github/workflows/toolchain-release.yml` builds every
native compiler copy, compares the A/B copies, builds every SDK, and reads back,
assembles and indexes the release candidate in one workflow run attempt. Every
owner readback uses `--same-attempt`. A failure after the compiler phase
therefore repeats the compiler phase.

Measured baseline, run 45034602223 (main c98f248, 2026-11-22/23): the run
started at 14:46Z, the last compiler job ended at 03:02Z (12.3 h including
runner queueing), and the last SDK job ended at 12:20Z (9.3 h). The last three
full runs failed after the compiler phase: a non-transient API error in origin
recording (44849186858), the publication lock in compiler assembly
(44919460955), and an A/B difference caused by ISL (45034602223, found in the
SDK job because A/B comparison runs there).

Outcome: a compiler qualification run and an SDK qualification run. The SDK
run consumes the compiler run's owner artifacts across run boundaries. A defect
that is fixed after the compiler phase costs one SDK run (about 9 h measured)
instead of a full run (about 21.5 h measured). A compiler defect fails in the
compiler run, before any SDK job starts.

Scope: non-publishing qualification (today `qualify-v2-full`) and the
tag-bound product qualification (today `push` on `v*` with the step "Record
complete tag-bound V2 qualification"). Both use the split path. The monolithic
mode is removed once the split path is accepted.

Non-goals:

- The legacy `produce`/`recover` pipeline.
- Local (self-hosted) runners. Origin verification keeps
  `--deny-self-hosted-runners`.

## Design and decisions

### D1: two workflow files

`toolchain-compilers-v2.yml` runs prepare, sources, runtimes, Cargo catalog,
native compiler builds, per-lane A/B comparison and compiler candidate
assembly. `toolchain-sdk-v2.yml` takes `compiler_run_id` and runs its own
prepare, sources, runtimes and Cargo catalog, then SDK lanes, owner readback,
release candidate assembly, index and attestation.

Separate files are required by D3: the compiler workflow is a compiler input,
the SDK workflow is not. One file with two modes would make every SDK-stage
workflow edit invalidate the compiler run.

Alternative rejected: two modes in `toolchain-release.yml`. It would keep the
attestation signer path identical, but any edit of that file would count as a
compiler-input change.

### D2: compiler run manifest

The compiler run ends with one manifest artifact, recorded with
`artifact-origin.py record` and signed with `attest-build-provenance` like every
owner payload. It contains:

- the run context (`context_from_environment`)
- the release plan digest and `release_id`
- the inputs digest
- the runtime digest
- the compiler input closure digest (D3)
- for every lane copy, the owner job, payload and proof identities
- for every lane, the A/B comparison receipt digest

Retention 14 days, equal to the owner payloads.

### D3: compiler input closure (binding policy b)

The SDK run may run on a newer producer commit than the compiler run. It admits
the compiler run only if the compiler input closure digest it computes at its
own commit equals the digest in the manifest.

The closure is deny-by-default. `toolchains/compiler-input-classification-v2.json`
lists path patterns that are SDK-stage only, for example the SDK workflow,
SDK-only scripts and documentation. Every other tracked file is a compiler
input, including the compiler workflow, `.github/actions/*`, the shared scripts,
locks, profiles, the runtime lock, the AROS-NX pin and the classification file
itself. The digest covers the sorted (path, Git blob ID) pairs of the
closure, so it is content-addressed and does not depend on diff history.

A new or unclassified file therefore invalidates reuse. Classifying a file as
SDK-only is a reviewed change to the classification file, which is itself a
compiler input. The first SDK run after such a change needs a new compiler run.

Strongest objection: a misclassified file could let an SDK run accept
compilers built from different inputs. Mitigations:

- Deny-by-default, with no allowlist of compiler inputs that could miss a new
  file.
- Counterprobes: changing any non-SDK file must fail admission.
- The attestation of every compiler owner is still verified against the
  compiler run's own commit and workflow (`verify` uses the source context).
  The cryptographic provenance never depends on the classification. Only the
  "same inputs" claim does.

Alternative rejected: policy (a), same commit. It is simpler but makes every
SDK-stage fix, such as #159, repeat the compiler phase.

### D4: cross-run readback

`artifact-origin.py source_selection` already admits a different run of the same
repository when `same_attempt` is false. `verify` checks the attestation
against the source context's workflow and commit and the run invocation URI.
`ci.yml` exercises this path ("Verify prior-run artifact origin").

Required changes:

- **Compiler owner selection.** The SDK workflow builds the compiler owner
  selections from the manifest's source context, not from
  `context_from_environment`. It uses `select-owner-artifacts-v2.py` with that
  context.
- **Owner readers.** `read-native-owner-v2.sh`, `collect-compiler-owners-v2.sh`
  and `qualify-compiler-sdk-lane-v2.sh` gain a prior-run mode. The source
  context must name the compiler workflow, a `workflow_dispatch` on
  `refs/heads/main`, and the manifest's producer commit.
- **Release candidate assembly.** `assemble-release-candidate-v2.py`
  (:388-396) and `select-native-release-evidence-v2.py` (:688-695, :738, :778)
  require one source context for both fragments. They change to a compiler
  source context and an SDK source context, bound by the manifest digest.
- **Commit checks.** `--producer-commit` checks that compare against the
  source context (`collect-compiler-owners-v2.sh:126`,
  `assemble-compiler-candidate-v2.py:205`) use the compiler run's commit for
  compiler owners.

### D5: SDK-run inputs

The SDK run regenerates plan, inputs, sources, runtimes and its own Cargo
catalog in its own attempt. The Cargo catalog stays bound to the current run
(`collect-native-cargo-caches-v2.py:259`). Its prepare job requires:

- plan digest, `release_id`, inputs digest and runtime digest equal to the
  manifest's values;
- the compiler run's conclusion is `success`;
- its workflow path is `toolchain-compilers-v2.yml`;
- the manifest is younger than 13 days. Owner payloads expire after 14 days,
  and the 7-day diagnostic artifacts of the compiler run are not used.

### D6: A/B comparison moves to the compiler run

Today the comparison runs in the SDK job
(`qualify-compiler-sdk-lane-v2.sh:154-169`). It moves to a per-lane compiler job
that writes the receipt into the manifest. The SDK lane keeps verifying both
owners. It reads the receipt digest from the manifest instead of comparing
again. The ISL difference of run 45034602223 would then have failed the
compiler run.

### D7: tag-bound product qualification

The tag path follows the protected release start design in
`toolchains/release-start-v2.md` (aros-tools#526, aros-toolchains#106 and its
S5 sub-tasks). There, a main-based dispatcher sends exactly one
`workflow_dispatch` of the native workflow at the immutable tag ref, signs the
post-dispatch binding and consumes the start once (START-A7). START-A6 forbids a
later main update from substituting code in the tagged native execution.

The split keeps that structure and adds a second dispatcher stage:

1. The first dispatcher dispatches the compiler workflow at the tag ref, as
   designed for the single native workflow.
2. A second dispatcher stage, a main-based controller like the first, wakes
   only on the successful completion of exactly that bound compiler run. It
   authenticates the first binding and the compiler manifest.
3. It dispatches the SDK workflow once at the same tag ref, with its own
   signed binding and its own exclusive consumption marker on the START-A7
   pattern.

Both native workflows therefore execute the tag's code. A plain `workflow_run`
trigger of the SDK workflow is rejected because it executes the default
branch's workflow file, which violates START-A6. A `v*` tag push trigger is
rejected because S5.5 removes `on.push.tags`.

For tags, binding policy (b) degenerates to the same commit: both runs execute
the tag. The tag record moves from the push-only step in v2-readback
(`toolchain-release.yml:1299`) to the SDK run. It names both runs, their
attempts (both 1), both bindings and the manifest digest. A rerun of the
compiler run must not replace the compiler evidence of a tag.

## Delivery and acceptance

### M1: compiler input closure

Execution: [#162](https://github.com/metaneutrons/aros-toolchains/issues/162). Dependencies: none.

- M1-A1: A script computes the closure digest from a Git tree and the
  classification file. Unit tests cover:
  - SDK-only change: equal digest;
  - change of any other file, including the workflow, an action, a lock, the
    pin and the classification file: different digest;
  - new unclassified file: different digest;
  - rename across the boundary: different digest.
- M1-A2: The classification of the current tree is reviewed. Every SDK-only
  pattern is justified in the file.

### M2: compiler qualification workflow and manifest

Execution: [#163](https://github.com/metaneutrons/aros-toolchains/issues/163). Dependencies: M1.

- M2-A1: `toolchain-compilers-v2.yml` builds every compiler lane copy, compares
  A/B per lane and assembles the compiler candidate. It writes a signed manifest
  (D2). The publication lock and API retry fixes (#158, #159) are kept.
- M2-A2: Workflow contract tests cover the job graph, retention and the manifest
  schema, with counterprobes for missing lanes and a missing receipt.
- M2-A3: One dispatched compiler run on main is green. This needs a
  maintainer-approved dispatch; the measured cost is about 12 h.

### M3: cross-run owner consumption

Execution: [#164](https://github.com/metaneutrons/aros-toolchains/issues/164). Dependencies: M1. Can proceed in parallel with M2.

- M3-A1: The readers and the assembly accept a compiler source context from
  another run, as described in D4. The same-attempt path for SDK owners is
  unchanged.
- M3-A2: Negative tests cover:
  - same run as the source;
  - other repository;
  - other workflow path;
  - other ref or event;
  - manifest digest or closure digest mismatch;
  - expired or missing owner artifact;
  - substituted receipt.

### M4: SDK qualification workflow

Execution: [#165](https://github.com/metaneutrons/aros-toolchains/issues/165). Dependencies: M2, M3.

- M4-A1: `toolchain-sdk-v2.yml` admits a compiler run per D3 and D5. It builds
  every SDK lane, then reads back, assembles, indexes and attests the
  candidate.
- M4-A2: One SDK run against the M2-A3 compiler run is green. This needs a
  maintainer-approved dispatch; the measured cost is about 9 h.
- M4-A3: A second SDK run on a newer commit that changes only an SDK-only
  path admits the same compiler run. A run after a compiler-input change is
  rejected before any SDK job starts.

### M5: tag-bound product qualification on the split path

Execution: [#167](https://github.com/metaneutrons/aros-toolchains/issues/167), tracked as a sub-task of aros-toolchains#106 under
aros-tools#526, not under this plan's epic. Dependencies: M4 and the S5
sub-tasks of #106.

- M5-A1: `toolchains/release-start-v2.md` describes the second dispatcher
  stage (D7) with its own acceptance criteria, in the style of START-A5 to A7.
- M5-A2: The first dispatcher dispatches the compiler workflow at the tag ref.
  The second stage dispatches the SDK workflow exactly once for exactly the
  bound compiler run. The tag record names both runs, both bindings and the
  manifest digest.
- M5-A3: Counterprobes reject:
  - a different tag or commit in the compiler run;
  - a failed or cancelled compiler run;
  - a rerun attempt;
  - a second dispatch for the same compiler run;
  - a manual dispatch that claims a tag.
- M5-A4: The single-run tag-bound v2 path in `toolchain-release.yml` is
  removed.
- M5-A5: The real non-publishing observation of S5.6 covers both stages.

### M6: remove the monolithic qualification mode

Execution: [#166](https://github.com/metaneutrons/aros-toolchains/issues/166). Dependencies: M4.

- M6-A1: The `qualify-v2-full` mode is removed from `toolchain-release.yml`,
  together with scripts and tests used only by it. The same-attempt code
  paths that the SDK run still needs stay. The tag-bound single-run path is
  removed by M5.
- M6-A2: `compiler-sdk-ci-v2.md`, `toolchains/README.md` and `README.md`
  describe only the two-run procedure.

## Migration, risks and verification cost

`qualify-v2-full` stays usable until M4 is accepted, so a qualification run can
still be dispatched during the work. M6 removes it after M4. The tag-bound
single-run path stays until M5 replaces it.

Risks:

- Misclassification (D3). Deny-by-default and the counterprobes above address
  it.
- The 14-day owner retention bounds how long a compiler run can be reused.
- The assembly scripts encode the one-context assumption in several places
  (D4). Missing one fails closed, but costs an SDK run.

Verification cost: focused unit and contract tests during M1 to M3. Native
cost: M2-A3 (about 12 h) and M4-A2 (about 9 h) measured from run 45034602223.
Both are one-time costs, each dispatched only with the maintainer's approval.

Open questions: none at proposal time.

## Decision changes

None yet.
