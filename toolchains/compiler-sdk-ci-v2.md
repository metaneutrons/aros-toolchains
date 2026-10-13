# Compiler and SDK diagnostic qualification

The `toolchain-release.yml` workflow has a narrowed `qualify-v2` mode and a
complete `qualify-v2-full` mode; both are nonpublishing. The narrowed tier is
Linux x86-64 only. Its compiler groups,
SDK product versions and source selections are declared in
`compiler-sdk-ci-selection-v2.json`; source profiles and sealed consumer
contracts remain owned by AROS-NX.

## Execution

1. Build the exact selected development aros-tools checkout. This exception is
   restricted to the manual diagnostic graph. It is not a signed release runtime.
   Full qualification first checks its portable package-readback interface;
   a runtime lacking required owner-readback selectors fails before the native
   matrix starts. This structural check is not a compiler or receipt proof.
2. Use native recipe creation, source materialization and `sdk verify-source`
   to bind all compiler groups and SDK identity documents. Native `release-plan`
   validates the collection before the bounded scheduler projects its matrix.
   The independently hash-bound [required payload policy](compiler-required-payload.md)
   must cover the complete native compiler plan before scheduling starts. Its
   retained selection is metadata only, not package or release qualification.
3. Fetch and verify the selected compiler, compatibility, Python and Cargo
   inputs once. No native build phase is allowed to populate missing inputs.
   Transfer this cache as one archive whose SHA-256 is retained by the source
   job. Safe restoration preserves file modes and empty directories before
   native verification: zipped directory artifacts normalize permissions,
   which invalidates the mode-bound Cargo vendor receipt. Do not repair the
   receipt or normalize the downloaded vendor files to bypass that failure.
4. Narrow diagnostics build both Family-V2 compiler copies in one job. Full
   qualification builds each copy in its own original job; the SDK job
   authenticates and reads back both owners without rebuilding. Compare their
   bytes, then run `aros sdk build` against the selected
   package. That command includes the source-owned SDK roots, ordinary C/C++
   consumers, relocation, generation evidence and package readback.
5. After successful generation, stage every plan-selected SDK product as a
   closed payload: generation record, three package members, independently
   retained compatibility input observations and the complete flat compatibility
   export. Each product has a measured `sdk-lane.json` tuple. Upload this exact
   payload, record its numeric artifact ID, ZIP digest and full file inventory
   in the still-running original owner, sign that record using GitHub/Sigstore,
   then upload the record and unchanged signature separately. Failure at any
   step fails the owner job; failed jobs cannot qualify through source verification.
6. Retain diagnostic packages and reports, including failure reports. These
   Actions artifacts are not authenticated release admission evidence.
   Retain native compiler process logs, lifecycle receipts and source-use logs
   even when packaging never starts, plus SDK CMake logs and configuration logs.
   Do not upload complete build trees, compiler intermediates or source caches
   as lane failure diagnostics.

GNU lanes also retain `gcc-checksum-inputs-compiler-{a,b}.json` before the
A/B comparison. The observer selects exactly one generated GCC Makefile and
records its ordered C++ checksum inputs, whole-file hashes and hashes after
the 16-byte prefix skipped by GCC's `genchecksum`. Bounded checksum-options
and generated checksum text accompany those observations. This metadata can
identify an intermediate input that differs even when the linked code matches;
it neither normalizes compiler bytes nor qualifies a release.
These diagnostic files remain outside each compiler's closed `payload/`
inventory and are retained through the operation root's JSON upload. They must
not be added to an owning-job compiler transport or its admitted evidence set.

If SDK generation fails, the diagnostic also retains the upstream root and
target-feature Autoconf `config.log` files under that SDK's `reports/` directory,
when present. Only those two explicit files are selected; each is bounded to
4 MiB and must be a regular file with no linked path components. The original
SDK command remains failed. These logs explain subordinate compiler/linker
errors; they are not execution receipts or release evidence.

The current selection derives eight compiler builds, four comparisons and
four SDK candidates on this host. The scheduler does not hardcode those counts.
All four SDK products start at `0.1.0`; this does not select a future repository
release version or rename public target profiles.

Both compiler production and classic compatibility use the selected clean
AROS-NX revision. This is not a claim of qualification against unmodified vanilla
AROS. SDK identities separately bind the source commit/tree, engine-free content,
sealed contract, ABI and explicitly selected reproducibility epoch.

## Safety and remaining release work

Preparation jobs have only `contents: read`. SDK owning jobs additionally need
`actions: read`, `id-token: write` and `attestations: write` for original artifact
observation and keyless transport signing. They have no publication environment,
long-lived publication credential, contents-write permission or release/tag
mutation. They cannot reach the retained
legacy release graph. Tag-triggered legacy production fails closed during this
V2 migration. Historical tags and published assets are unchanged.

After diagnostic qualification, publication still needs the released V2-capable
runtime, the complete three-host matrix, owning-job artifact admission, signed
combined compiler/SDK inventory, isolated candidate validation and release
immutability gates. A green diagnostic run does not satisfy those gates.

Signing the diagnostic owner's payload is not release qualification. An
independent reader must select the reviewed original workflow/commit, successful
job and numeric payload/proof artifacts from provider observations; verify the
signature and complete ZIP through `artifact-origin.py verify-source`; safely
materialize the retained bytes; and join every SDK tuple to the native complete
compiler/SDK matrix. None of those reader or release-admission gates is replaced
by a signed `sdk-lane.json` claim or a package-only summary. See
[owning-job artifact transport](artifact-origin.md).

The narrowed diagnostic selects the explicit `diagnostic` transport role.
The full nonpublishing workflow selects `sdk` for its separate SDK owners.
Readers require the caller's exact role; no role is inferred or promoted from
a signed payload. Neither role substitutes for the complete native SDK matrix
and release-admission gates.

Dispatch only after both exact tools and source commits are remotely available,
the selected tools checks and producer contracts are green, and the source
SDK exporters, source-contract/hygiene and locked-source checks have passed.
The diagnostic deliberately qualifies a development CLI/source combination;
the ordinary AROS-NX product matrix must also pass before that source PR can
merge, but it may first need a newer published CLI. Do not remove source-owned
ABI contracts or suppress a failed product check to make an older CLI pass.

```sh
gh workflow run toolchain-release.yml --repo metaneutrons/aros-toolchains \
  --ref fix/compiler-sdk-ci-integration -f mode=qualify-v2 -f scope=linux-x86_64
```

To investigate one compiler group without repeating unrelated native builds,
add `-f diagnostic_group=<exact-group-id-from-plan>`. The complete native plan
is still validated before projection. A narrowed diagnostic is explicitly
incomplete and cannot be used for a tag-triggered or full release selection.
Omitting the selector keeps every group in the diagnostic host scope.

For the complete native non-publishing matrix, explicitly select
`mode=qualify-v2-full` and `scope=full` on a reviewed branch. The workflow rejects
a diagnostic group in this mode, and the scheduler validates the entire native
plan before selecting every host and compiler lane. It preserves the actual
manual event identity; it does not simulate a tag push.

Each selected host builds the exact development tools commit natively. Lanes
consume only their own host runtime and verify its checksums. Full qualification
uses separate original jobs and absolute build roots for compiler copies A and
B. Each job retains its native package and signed execution observations.
The subsequent SDK job independently selects both successful owners, verifies
their provenance and reads their package bytes back before comparison and SDK
generation; it never rebuilds the compilers. macOS Intel remains excluded.

The reader takes executor observations from the authenticated original native
build result, not from portable export metadata. Native `verify-package` remains
the authoritative receipt validator and must bind the exact original build-result
hash. This is authenticated original-job evidence, not a claim that the SDK job
executed the compiler build itself. Explicit caller-selected admission remains
available separately through `admit-lane-v2.sh`.

After every compiler and SDK owner succeeds, the readback job independently
derives the full compiler and SDK owner sets from fresh native release plans.
Each original A/B compiler job must have a distinct authenticated numeric owner;
the compiler collector preserves package, measurement, executor and environment
selections without rebuilding. It selects each
exact successful provider job and its SDK-role payload/proof names, authenticates
the original owner and reads the retained bytes back. Every SDK/group/profile/host
tuple must be present exactly once; no narrowed matrix or diagnostic owner role
can replace this closure.

The emitted compiler-build and SDK-generation selection fragments describe authenticated transport
paths and digests only. It grants no SDK generation, ABI or release qualification.
The native complete SDK-matrix factory must still reacquire those bytes with the
complete compiler evidence, establish cross-host equality and produce the combined
inventory. Selection metadata uploaded as diagnostics contains job-local paths;
it is not a portable publisher input. Final native acquisition must run in this
same readback job or independently reacquire the original owners.

`select-sdk-package-inputs-v2.py` projects the complete retained SDK matrix
into the native index's four host-independent package expectations. It binds
the native plan, release-input collection and collector fragment to explicit
digests, joins package bytes to each owner marker, and requires every selected
host copy to agree before choosing an explicit representative location.
The collector fragment retains exact `owner_transports` result digests. The
projection must rejoin each payload to that original transport before and after
selection; changing all host copies and their local lane markers cannot create
new authenticated package expectations.
This is package-byte selection only. Run it after authenticated collection in
the same invocation; its output cannot replace original-owner authentication,
native SDK package verification or complete generation/compatibility readback.

The same readback invocation runs `assemble-release-candidate-v2.py` after
deriving an independent required-payload selection from the committed policy
and its fresh native plan. It delegates package acquisition to the compiler
and SDK assembly stages rather than repeating those stages in the workflow.
The compiler stage rechecks retained original compiler transports,
invokes native portable `verify-package` for both copies, and invokes native
`compare` for each complete plan lane. Only unchanged copy-A package members
are staged. The generated compiler index-lane selection and evidence fragment
remain partial: SDK compatibility, SDK package staging, the combined signed
inventory and complete native release qualification are separate gates.
The diagnostic upload retains summaries and reports, not a publishable package
set. No build, original transport, package or receipt is normalized or replaced.

The SDK stage, `assemble-sdk-candidate-v2.py`, repeats the complete authenticated SDK byte
selection before and after native verification. Each explicitly selected
host-independent package must pass `aros sdk verify-package` against its
plan-bound identity and independently measured archive and tree digests before
its three unchanged members are staged. Its partial summary preserves the
native-index package expectations and verification-result selectors. This
package staging does not replace the complete twelve-generation readback,
ordinary and relocated link evidence, signed combined inventory or final
native release factory.

The combined stage copies unchanged package members and only the input
documents referenced by the native plan into one absent release directory.
The manifest schema and tree-digest fixture come from the exact selected
aros-tools checkout, with explicit independent digests; producer copies and
diagnostic plan/matrix files are not substituted. Native `aros sdk sbom`
generates one deterministic SDK SBOM per product. Native `producer index`
then verifies the complete shared inventory and writes the pre-attestation
index and an external subject manifest. The index input uses `sdks` for SDK
package expectations; native evidence selection uses `sdk_packages`.

After assembly, `select-native-release-evidence-v2.py` joins the measured
compiler lane metadata, A/B measurements and comparisons, all original SDK
generation records, and the exact candidate index. Compiler compatibility
selectors follow the unique SDK relation declared by the source-bound plan;
missing or ambiguous relations fail. The closed native evidence DTO is kept
outside the release inventory. This selection does not execute the final
native release factory or authenticate signatures.

The next diagnostic steps attest that exact external subject manifest using
GitHub's OIDC-backed provenance action. The external verifier checks the source
commit and branch ref, workflow, complete subject set and certificate run/attempt.
The original bundle is copied exclusively into the release inventory and verified
again there. Native `producer index --stage final` writes the final checksums;
native `verify-release-evidence` then reads back the complete compiler A/B,
compatibility and SDK-generation matrix. Held input, index, subject, selection
and runtime digests, exact asset/SDK tuple sets and native result counts remain
checked across these steps. The signing job needs `attestations: write`, but
keeps `contents: read` and never uses a publication environment.
This permission is job-wide: the manually selected repository branch and its
readback code are trusted, not code from a fork PR. Its certificate binds that
branch ref and run attempt; it cannot satisfy a production tag's source claims.
This diagnostic scope is not approval to reuse the job as a publication job.

The diagnostic base URL names a future candidate; it does not prove downloads
exist. No tag, draft, fabricated provenance or public release is created.
Branch attestation is not a tagged qualification record. The local Rust result
explicitly reports byte consistency only; original-owner authentication and
external signature verification remain separate gates. The production tag path,
durable qualification/recovery and independent isolated release audit still
require qualification before publication.

This full scheduling coverage is not release admission: the runtime is still a
development build, and original-owner verification, complete native matrix
readback, combined inventory, signatures and isolated release gates remain
required. Do not dispatch the full matrix while a known compiler A/B defect
still requires a narrowed diagnostic.
