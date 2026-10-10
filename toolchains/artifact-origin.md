# Owning-job artifact transport

`scripts/toolchain/artifact-origin.py` binds an Actions payload to its selected
owning job and measured transport bytes. It does not run a compiler, select a
release matrix, authorize recovery, or qualify a release.

## Writer and reader

The writer executes directly in the owning job, after its payload upload. It
obtains `check_run_id` from the authenticated runner OIDC issuer over HTTPS,
checks the exact repository, source commit, workflow, run and attempt claims,
and selects that check uniquely in the attempt-specific Jobs API. It never
reads an OIDC token from caller-supplied metadata or persists the token.
This direct issuance check is not a standalone JWT signature verifier.

The record contains the exact job identity, lane selection, numeric artifact
ID, API/upload ZIP digest and size, and a closed inventory of file sizes and
SHA-256 digests. The owning job signs the record with GitHub/Sigstore provenance.
Its signature bundle and record are uploaded separately from the payload,
avoiding a recursive checksum dependency.

An independent reader requires the selected repository, workflow, producer
commit, source ref, run, attempt, job name, artifact ID/name and lane. It:

1. Verifies the record's signature with the exact signer workflow and commit,
   source commit and ref, and GitHub-hosted runner requirement.
2. Requires the verified certificate's exact `runInvocationURI` and the one
   signed record subject. Workflow-controlled predicate fields are not a
   substitute for certificate identity.
3. Joins the signed check ID to exactly one completed successful provider job
   through the selected attempt's fully paginated Jobs API.
4. Checks the numeric artifact's provider repository/run/source identity and
   signed ZIP digest/size, downloads by numeric ID, and verifies every regular
   ZIP member against the signed closed file inventory without extraction.

Linked metadata, linked payload files, duplicate or case-aliased paths,
unexpected ZIP members, incomplete provider pages, changed bytes and unknown
record fields fail closed. Provider or authentication errors stop the check;
there is no credential fallback. Temporary raw ZIP downloads are removed.
Inputs must remain quiescent in owned roots while measured.

## Trust boundary

The provider artifact API does not expose an owning-job ID or run attempt.
Those fields are not fabricated from an artifact name, ordering or timestamps.
Attempt membership comes from the attempt-specific Jobs endpoint; a per-job
`run_attempt`, when supplied, must agree.

The verified signature authenticates the approved workflow implementation and
its record bytes. The current-job join relies on that implementation obtaining
the OIDC check ID directly in the owning job. It is not a certificate field
that makes arbitrary attacker-controlled workflow code trustworthy. Production
admission must independently select the reviewed release workflow and commit;
a diagnostic branch workflow cannot qualify a production build. Transport
authentication does not establish compiler independence, byte reproducibility,
compatibility, source closure or publication authority. Those remain separate
native CLI and release-policy gates.

The current helper consumes the executing workflow's independently supplied
`GITHUB_*` context. Cross-run recovery selection and complete compiler-family
workflow integration remain separate work; the existing release workflow does
not yet invoke this helper.

## Non-publishing provider probe

The `Producer contracts` workflow has a manual boolean input,
`artifact_origin_probe`, disabled by default. When explicitly enabled, one
Ubuntu job uploads the two committed smoke fixtures, records and signs their
origin, and a second read-only job verifies the completed owner and downloads
the original ZIP. An isolated one-byte-changed record must fail specifically
at signature authentication. Neither job has a release environment, tag or
release write permission, compiler build, or package publication step.

```console
gh workflow run ci.yml --repo OWNER/REPOSITORY --ref REVIEWED_BRANCH \
  -f artifact_origin_probe=true
```

Use an exact reviewed branch/commit and record the resulting run/attempt.
Local unit tests use synthetic provider and signature responses only; they do
not prove actual OIDC issuance, provider metadata or cryptographic verification.
An actual successful probe and its rejection evidence are required before using
this transport in a release gate.

## Provider contracts

- [GitHub OIDC claims](https://docs.github.com/en/actions/reference/security/oidc)
- [Attempt-specific workflow jobs](https://docs.github.com/en/rest/actions/workflow-jobs)
- [Actions artifact metadata](https://docs.github.com/en/rest/actions/artifacts)
