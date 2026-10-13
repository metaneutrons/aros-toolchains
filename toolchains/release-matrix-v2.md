# V2 release scheduling

`select-release-matrix-v2.py` projects runner labels and two independent job
copies from the exact JSON emitted by native `aros toolchain producer
release-plan`. It does not parse compiler recipes or maintain a second profile
list. The native CLI remains responsible for the closed input collection,
raw document digests, recipe bindings and complete group/host/profile set.

The caller must first run that CLI against its independently selected collection
digest. The scheduler then requires the raw plan digest, collection digest and
producer/tools commits selected by the caller. Hashing arbitrary JSON does not
substitute for running the native validator or authenticating its runtime.

For example, with those reviewed selectors and an absent `$PLAN` output:

```sh
"$AROS" toolchain producer release-plan \
  --directory "$INPUTS_DIR" --inputs-sha256 "$INPUTS_SHA256" \
  --format json > "$PLAN"
PLAN_SHA256=$(shasum -a 256 "$PLAN" | awk '{print $1}')
python3 scripts/toolchain/select-release-matrix-v2.py \
  --plan "$PLAN" --plan-sha256 "$PLAN_SHA256" \
  --inputs-sha256 "$INPUTS_SHA256" \
  --producer-commit "$PRODUCER_COMMIT" --tools-commit "$TOOLS_COMMIT" \
  --event push --scope full
```

## Policy boundary

The three supported host IDs map to reviewed runner labels. Target names and
group ownership come only from the native plan. Every profile must occur once
on each declared host; duplicate, unknown, unordered or incomplete lanes fail.
The complete matrix is limited by GitHub's 256-job matrix boundary after A/B
expansion. There is no Intel macOS mapping or target-specific runner exception.

The `push` scheduling path requires a full selection. Manual
`workflow_dispatch` permits the narrowed `linux-x86_64` or `linux` diagnostic
scope, or a full selection with explicit `--full-qualification`. The latter
requires the workflow's nonpublishing `qualify-v2-full` mode; a group filter is
not permitted. A partial push selection or implicit manual full selection is
rejected. Actual tag, protected workflow and publication checks remain separate
workflow gates; the helper's event argument does not authenticate a GitHub event.

`sdk_matrix` projects the native plan's validated SDK selections, including
identity file/hash, source preset and compiler group/profile associations. SDKs
are host-independent; a diagnostic host filter does not drop SDK selections.

`host_matrix`, `verify_matrix` and `build_matrix` derive from the same validated
lane list. Build entries add only copy `a` or `b`; counts are derived, not fixed
at nine or twelve lanes. Optional `--github-output` appends compact matrix
records to an existing regular file only after all input validation passes.
Invalid input must not change that file.
The output cannot alias the retained plan, including through a hard link.

`complete_selection` means that no diagnostic host filter was applied. It is
not a successful build, independent execution, compatibility result, signature
or release qualification. Every scheduler result retains the `scheduling-only`
assurance boundary.

## Integration boundary

The offline producer contract suite exercises this helper. The manual
[compiler/SDK diagnostic](compiler-sdk-ci-v2.md) consumes its narrowed Linux
or explicit full projection using an exactly pinned development runtime. This
is not production activation. The published runtime lock is unchanged and legacy tag publication
is blocked during migration. The complete V2 provenance, release and recovery
graph still requires the independently released V2-capable runtime and qualified
input collection.
