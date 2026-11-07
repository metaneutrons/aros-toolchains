# Native tag-ref dispatch route

Design draft for START-A6 and the native entry (S5.5, aros-toolchains#106).
It activates nothing, changes no workflow and creates no tag, draft or release.
Statements marked "observed" were read on `main` at `7f2710a`; everything else is
a proposal that needs review and the counterprobes below before implementation.

## What the native workflow does today

Observed in `.github/workflows/toolchain-release.yml` and
`scripts/toolchain/select-compiler-sdk-route-v2.py`:

- The only tag trigger is `on: push: tags: [v*]`. The route selector accepts two
  events. A `push` on a tag runs `authenticate_tag` and selects the released
  runtime and the full matrix. A `workflow_dispatch` is accepted only on a
  branch with `(qualify-v2, linux-x86_64)` or `(qualify-v2-full, full)`.
- `authenticate_tag` proves that the tag is annotated, named like the committed
  Release Please version, peels to the event commit, matches the remote tag
  object, lies in protected `main` history and, as the last gate, that
  `releases/tags/<tag>` answers HTTP 404. GitHub's lookup by tag does not return
  draft releases, so this gate proves only that no public release exists and a
  private draft created by the start does not trip it (documented provider
  behavior, not yet observed on this repository). It cannot prove the draft.
- Four steps (complete qualification record, its signature and two follow-ups)
  and the legacy jobs `plan` and `draft-release` key on `github.event_name ==
  'push'`.
- The input `mode` is `required: true` with default `produce`, and the legacy
  `plan` job runs for `workflow_dispatch` with `mode == 'produce'`.
- `compiler-owner-matrix-v2.py` and `artifact-origin.py` already name
  `workflow_dispatch` on `refs/tags/` as a valid owner route. The dispatcher
  claim and binding codecs fix `workflow_dispatch` as the native event.

## Proposed route

**Dispatch call.** The dispatcher sends one `workflow_dispatch` at
`refs/tags/<tag>` with `mode=release-v2`, `scope=full`, `diagnostic_group` empty.

- A new `mode` value is needed because the input is required: omitting it would
  select `produce` and start the legacy graph. `release-v2` must never share a
  value with `produce`, `recover` or the diagnostics.
- The selector rejects every other combination on a tag ref and rejects
  `release-v2` on a branch ref.

**Selector.** A third branch in `select()` for `workflow_dispatch` with
`ref_type == tag` and `mode == release-v2`. It runs the existing tag checks,
including the public-release absence gate, unchanged, and returns the same
outputs as the `push` route (`runtime_kind=released`, `full_matrix=true`,
`tag_object`, `tag_epoch`, `release_id`) plus an explicit `route=tag` (and
`route=diagnostic` for branch dispatches). The selector does not look at the
draft: it needs no new provider access and cannot see a draft with a read-scoped
token anyway. The private draft, its numeric ID from the signed start and its
sole claim asset are established by the candidate authentication below, which
already observes them with the job token.

**Authentication before fan-out.** Before any source checkout or runtime
materialization, `v2-prepare` authenticates the dispatch in this order:

1. the selected claim and both signatures through
   `authenticate-compiler-sdk-native-candidate-v2.py`,
2. the signed dispatch-run binding through `verify-compiler-sdk-dispatch-binding-v2.py`
   against the run that is actually executing,
3. the executing run's own identity (runner, event file, OIDC-owned check,
   in-progress job) through `compiler-sdk-native-identity-v2.py`.

All three exist as libraries; none has a command line or a caller yet (S5.4a).
The inputs are selected by numeric ID from provider listings, never from the
payload being checked.

**Event conditions.** The four `github.event_name == 'push'` conditions become
`needs.v2-prepare.outputs.route == 'tag'`, so that the same steps run for the
dispatch route and no path is keyed on the event name alone. The artifact-origin
contexts carry the real `workflow_dispatch` event and tag ref; no `push` claim is
fabricated.

**Retire the push route.** At activation `on.push.tags` is removed. Otherwise a
tag creation could start a second qualification that no dispatcher authenticated,
and the design already notes that a workflow-token tag push may not trigger a run
at all, so nothing may depend on it. The legacy `plan` and `draft-release` jobs
become unreachable and are removed in the same change, not earlier.

## Counterprobes

The route needs a positive probe and each of these must be rejected before any
build runs:

| Case | Expected result |
|---|---|
| `release-v2` on a branch ref | rejected by the selector |
| tag ref with `mode` `produce`, `recover`, a diagnostic mode or empty | rejected |
| `scope` other than `full`, or a non-empty `diagnostic_group` | rejected |
| lightweight tag, tag outside `main`, tag differing from the committed version | rejected (existing gates) |
| public release for the tag | rejected by the selector (existing gate) |
| draft with a different numeric ID than the signed start | rejected by candidate authentication |
| draft with assets besides the claim, or two claim assets | rejected by candidate authentication |
| run attempt greater than 1 | rejected |
| binding for another native run, claim for another start, swapped signature | rejected by the binding and candidate gates |
| dispatch from an actor or workflow other than the authenticated dispatcher | rejected |
| unsigned or unverifiable binding | rejected, no fallback to the push route |

## Order of work

1. Route selector branch with fixtures: testable offline, inert while no workflow
   passes `mode=release-v2`. A manual `release-v2` dispatch on a tag must fail at
   authentication, which is the intended fail-closed behavior.
2. Controller commands for the three authentication steps (S5.4a).
3. Dispatcher call and binding (S5.4c), then the dispatcher template (S5.4d).
4. Switch the four conditions, remove `on.push.tags` and the legacy jobs.
5. One real non-publishing start and dispatch observation before activation.

## Open points

- Where the dispatcher retains the signed binding and how the native entry selects
  it by numeric ID (artifact on the dispatcher run versus a second draft asset).
- Whether `scope=full` should stay an input for this route or be fixed by the
  selector, which would shrink the surface.
- `toolchain-release-recovery.yml` consumes V1 artifacts only; a V2 recovery
  caller stays separate (S5.7, aros-toolchains#108).
