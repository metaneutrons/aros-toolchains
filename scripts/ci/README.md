# Development CI scope

Pull requests changing only regular, non-executable `.md` files run Markdown
lint and link checks instead of the complete producer contract suite. Additions,
deletions and Markdown-to-Markdown renames are included. Mixed changes, file-mode
changes, symlinks, unknown inputs and Git failures select the complete suite.
Pushes to `main` and manual dispatches always select the complete suite.

The required `contracts` check is always reported. It succeeds only when the
planner succeeds, the selected job succeeds and the unselected job is skipped.
Failed, cancelled or unexpectedly skipped selected jobs cannot pass the gate.
There are no workflow-level path filters.

Markdown lint uses the committed configuration. The link checker verifies a
fixed lychee archive digest before execution, checks tracked Markdown files,
local anchors and external links, and does not cache failures or ignore HTTP
errors. Its download wrapper requires Linux x86-64; its offline regression tests
also run on macOS.

Run the source-independent regression tests with:

```sh
python3 -B scripts/ci/tests/test-plan-changes.py
python3 -B scripts/ci/tests/test-markdown-links.py
python3 -B scripts/ci/tests/test-workflow-scope.py
```

This development-CI optimization does not change compiler/SDK qualification,
release admission, artifact transfers, native A/B independence or publication.
