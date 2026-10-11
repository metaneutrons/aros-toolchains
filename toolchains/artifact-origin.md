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
When GitHub includes `job_workflow_ref` / `job_workflow_sha` on a direct job,
both must exactly equal the independently selected calling workflow and commit.
A different called workflow, incomplete pair or malformed claim is rejected;
no reusable-workflow admission policy is inferred from those claims.

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
   The download child has a kernel file-size limit of the selected ZIP size
   plus one byte before the GET; oversized responses cannot consume unbounded
   local disk. Exact size and digest checks still follow the download.

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

The `record` and `verify` commands consume the executing workflow's
independently supplied `GITHUB_*` context. `verify-source` keeps that current
caller context separate from an explicitly selected original run and attempt.
Complete compiler-family production workflow integration remains separate work;
the existing release workflow does not yet invoke this helper.

## Explicit prior-run verification

`verify-source --workflow CALLER_WORKFLOW --job-name CALLER_JOB` requires
an absolute `--source-selection` file path. It never
overrides `GITHUB_*` to impersonate the original run. The current caller's
workflow ref/commit, runner OIDC check ID and executing provider job are checked
independently. The diagnostic reader has no GitHub attestation-write or
release-write permissions. Its OIDC token access is not a publishing credential;
external OIDC relying parties must enforce their own workflow/audience policy.

The caller-owned selection is closed JSON with schema
`aros-toolchain-artifact-selection-v1` and these fields:

| Field | Independent selection |
| --- | --- |
| `context` | Exact `repository`, `repository_id`, `workflow`, `producer_commit`, `source_ref`, `run_id`, `run_attempt` |
| `selection` | Exact `role`, `group`, `host`, `profile`, `copy` |
| `job` | Provider unique numeric `id` and exact `name` |
| `artifact` | Payload numeric `id`, exact `name`, ZIP `sha256` and `size_in_bytes` |
| `proof` | Separate proof numeric `id`, exact `name`, ZIP `sha256` and `size_in_bytes` |

Obtain those selectors from the reviewed source plan and provider observations,
not the origin record or its signature predicate. A selector file is not an
authorization credential: production callers must admit only a reviewed source
workflow/commit and enforce protected recovery and fresh release policy.
Cross-repository sources and the current caller attempt are rejected.

The reader first selects the source job independently by its provider ID/name
from complete attempt-specific pages, then compares its check ID and full job
projection with the signed record. The proof ZIP must match its independently
selected provider digest/size and contain exactly `origin.json` and
`origin.sigstore.json`. Its download is kernel-capped at the selected ZIP size
plus one byte and each ordinary member is limited to 16 MiB before reading.
Only those two fixed files are materialized in a private temporary directory;
there is no general-purpose archive extraction before verification. Optionally
provide both `--origin` and `--bundle` absolute paths to also require byte
equality with an already retained local proof. Only then are
the original source workflow signature, certificate invocation, signed payload
identity, original payload ZIP and closed file inventory verified. The selection
and any supplied local proof files are remeasured before success. The private
download/materialization directory is removed on success or failure. No proof is re-signed,
no original artifact is replaced, and no compiler execution is inferred.

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

To test two distinct runs, supply an independently measured source selection
as the `artifact_origin_source` JSON input with `artifact_origin_probe=false`.
The read-only job accepts only the earlier CI diagnostic fixture owner, not a
release workflow. It verifies both original artifacts and authenticates its
own current reader job, then requires a deliberately wrong source-job selector
and modified isolated local proof bytes to fail at their respective identity
and ZIP-byte boundaries. Both modes are disabled by default and cannot be enabled together.
The source artifacts must remain available and unexpired. This is a transport
probe, not production release qualification.

## Release subject manifests

The V2 index command writes its pre-attestation subject manifest outside the
release directory. Pass those exact bytes directly to the pinned attestor's
`subject-checksums` input; do not relocate payloads, prefix subject names, or
copy a second checksum inventory into the release. The attestor reads the
manifest's basename/digest entries, not payload paths relative to the manifest.

`verify-provenance-attestation.sh` supports two exclusive input modes:

- Existing V1 callers use `--checksums PATH`, with subjects beside that file.
- V2 callers use `--subject-manifest PATH --subject-manifest-sha256 SHA256
  --subject-dir DIR`. Select the manifest's raw SHA-256 independently from the
  native index result and select the owned release root explicitly.

The V2 mode snapshots a regular manifest of at most 1 MiB, requires canonical
LF-terminated basename/digest entries, verifies every selected regular subject
under the explicit root, and rejects exclusions, duplicate names, symlinks,
self-reference and the provenance bundle as its own subject. It requires the
verified attestation's complete subject set to match, not just the one file
passed to `gh attestation verify`. Supply `--run-id` and `--run-attempt` to bind
the verified certificate invocation to the selected provider attempt.

Keep the manifest and release root quiescent during verification. The verifier
remeasures them before writing success, but is not a concurrent-writer security
boundary. Native index/readback gates separately enforce the complete release
inventory, canonical subject manifest and payload/receipt joins. Release
provenance does not replace owning-job transport authentication or publication
authorization. The local manifest tests use fake `gh` responses and establish
policy rejection only; actual cryptographic verification remains a release gate.

## Provider contracts

- [GitHub OIDC claims](https://docs.github.com/en/actions/reference/security/oidc)
- [Attempt-specific workflow jobs](https://docs.github.com/en/rest/actions/workflow-jobs)
- [Actions artifact metadata](https://docs.github.com/en/rest/actions/artifacts)
