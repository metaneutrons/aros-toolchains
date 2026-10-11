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

The helper permits the full selection only for the `push` scheduling path.
Manual `workflow_dispatch` scheduling is limited to `linux-x86_64` or `linux`.
Manual full selection and a partial push selection are rejected. Actual tag,
protected workflow and publication checks remain separate workflow gates;
the helper's event argument does not authenticate a GitHub event.

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

The offline producer contract suite exercises this helper. The active release
workflow still selects the published LLVM/V1 runtime and nine-lane path; this
helper does not activate V2 or change any runtime/source pin. Wiring its output
into the complete V2 build, comparison, compatibility, provenance and recovery
workflow requires the independently released V2-capable runtime and qualified
input collection. No prospective runtime identity is admitted here.
