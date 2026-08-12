# Release Process And Feature Freeze

AutomateSTIG is under a scanner-only feature freeze for `v0.3.0`. New product
features do not enter the release branch. Defect, security, test, documentation,
and operability changes may proceed when they are narrowly scoped and reviewed.

## Merge gates

`.github/release-freeze.json` is the machine-readable freeze state. On a pull
request, `scripts/validate-release-freeze.py` permits documentation and
governance-only changes. Any product-code path requires the
`release-freeze-approved` label from the release manager. This label approves
the exception for review; it does not approve the code itself.

Branch protection must require:

- a pull request and all CI checks, with every required status bound to the
  GitHub Actions App rather than accepted by name alone;
- two approvals from people other than the author;
- code-owner approval for compliance, collection, content, storage, signing,
  release, and audit paths;
- dismissal of stale approvals and approval after the latest push;
- resolved conversations, linear history, and no force pushes or deletion.

The exact required-context set is enforced by
`scripts/validate-release-evidence.py`. Keep `Test (windows-latest)` required
for portability, but do not configure a Windows `Build Release` context:
Windows artifacts are intentionally outside the supported release set. The
frontend job's required context is exactly `Scanner frontend contracts`, which
must stay aligned with the job name in `.github/workflows/ci.yml`.

Tag governance also requires the repository Actions secret
`AUTOMATESTIG_GOVERNANCE_TOKEN`. It must be a fine-grained token or GitHub App
installation token with read access to repository Administration, Actions,
Deployments, Environments, metadata, and pull requests. The normal
`GITHUB_TOKEN` cannot read all repository-control APIs validated at the tag
gate. Rotate this credential under the release manager's custody and never
expose it to pull-request jobs.

The pull-request template records the defect/freeze exception, decision and
provenance impact, negative tests, live-acceptance impact, and the independent
software and security reviewers.

## Reviewable change sequence

Large hardening work is split along review boundaries. Each pull request must
state its dependency and must remain independently understandable:

1. remove out-of-scope/dead product surfaces;
2. fail-closed collection and evidence v2;
3. device-specific semantic validators;
4. bounded archive and XCCDF parsing;
5. signed pack build, verify, import, and key storage;
6. durable library transactions and cross-process locking;
7. audit/provenance and strict result accounting;
8. CKL/CKLB and STIG Manager interoperability;
9. live acceptance, fuzzing, and security regression tests;
10. release provenance, operator runbooks, and governance.

A reviewer may ask for a smaller split. Do not combine a compliance-decision
change with unrelated formatting, generated corpus churn, or release plumbing.

## Tag gate

A repository tag ruleset restricts creation, replacement, and deletion of
matching `v*` release tags to exactly one named user release administrator with
an always bypass. The release validator rejects a broad repository-role,
additional actor, or different bypass mode. Granting normal write access to a
reviewer does not grant release-tag authority.

A release that introduces or changes a protected `workflow_dispatch` definition
uses two reviewed changes, because GitHub can dispatch that workflow only after
the definition exists on the default branch:

1. merge the independently approved product/hardening pull request; its final
   commit on `main` becomes `approved_commit`;
2. dispatch every protected technical-acceptance, first-use-study, recovery,
   and signing workflow at that exact `approved_commit`;
3. commit only the resulting bound files under
   `release-evidence/artifacts/<tag>/` and `release-evidence/<tag>.json` through
   a separately reviewed evidence pull request;
4. create the protected tag only after the connected validator passes.

The evidence change must not alter product code, workflow definitions, policy,
or test logic. The validator requires `approved_commit` to be the merge result
of the approved code pull request and rejects any subsequent tagged-tree change
outside the release-evidence paths. Therefore the pull request that first adds
these protected workflows is a merge candidate after its code-review and CI
gates pass; it cannot and need not contain evidence from workflows that were
not yet dispatchable. This exception permits the bootstrap sequence, not a
release without evidence.

A `v*` tag cannot publish unless `release-evidence/<tag>.json` passes
`scripts/validate-release-evidence.py`. It requires:

- distinct named software and security reviewers;
- passing ONTAP, FreeBSD, Cisco IOS-XE, STIG Viewer, and STIG Manager evidence
  no older than 90 days, with committed artifacts whose hashes and exact result
  sets are revalidated; every live device result binds its snapshotted inputs
  and the canonical effective check-pack/evaluation-plan digests to checklist
  provenance, while Cisco evidence additionally binds one signed organization
  policy by requiring the protected pin, snapshotted policy and signature,
  independent oracle, and verified checklist provenance to carry the same
  SHA-256 values and trusted signer identity;
- a passing transaction-recovery drill;
- a passing first-use UX study no older than 90 days, bound to the exact
  approved commit, intended product version, GUI bytes, prepared scenario and
  complete 5-to-100-person cohort; at least two analysts, two managers, and two
  experience bands must be represented, the exact full-cohort denominator is
  retained, and assisted or documentation-aided completions never enter the
  numerator;
- an approved content-signing fingerprint plus the fixed ceremony JSON, raw
  public key, and signed test pack, all byte-bound to a successful protected
  workflow at `approved_commit` with distinct custodian and approver identities;
- a producer-authenticated selected-run round trip: the exact bounded ZIP from
  approved-commit STIG Manager staging, a strict detached sidecar and
  independently conveyed public trust anchor, a non-secret protected-key
  custody record, and a successful trusted product-CLI verification on an
  identified protected receiver. The signing custodian and receiver approver
  must be distinct, the workflow artifact is byte-bound to every committed
  release-evidence file, and the private key never enters CI or scanner runtime;
- a merged, GitHub-verified code pull request with distinct software/security
  approvals on its final head, and no subsequent change except its bound
  release-evidence document and artifacts;
- non-expired, named risk acceptances (or an empty list).

The release workflow builds without privileged credentials. Each release build
hashes the CLI, GUI, and backup/restore utility before packaging, extracts the
completed archive, and refuses to finalize its target-specific
`release-equivalence-*.json` unless all three extracted SHA-256 values and sizes
exactly match the pre-package snapshot. CLI and GUI are runtime-tested
application binaries; the recovery utility is a separately identified,
byte-bound operational tool that is also executed through a backup/restore
round trip. The archive member set is closed and explicitly rejects
`automatestig-transition`: migration and producer-signing tooling remains a
source-built protected-host executable, not an analyst release payload.
A tag-only matrix then downloads each advertised Linux/macOS archive onto a
native runner for that operating system and architecture, rechecks the archive
checksum and manifest, and executes those exact extracted bytes. The CLI must
report the tagged version through `--version`; the GUI must start and report the
same version through `/api/status`. The Linux x86_64 CLI additionally must equal
the exact binary recorded by protected live-device acceptance. That live-device
binding is intentionally additive; it is not used as a substitute for proving
the GUI or the other three release targets. On every native target, the exact
archived recovery entrypoint must create and restore a SQLite-backed state set,
preserve recovery key material, and remove stored STIG Manager credentials.

The per-target SBOM records hashes for both application executables, the
recovery utility, the archive, and the equivalence-manifest identities. It also
states the analyst-product scope and that the transition CLI is absent.
Provenance independently binds the same archive, both application executable
digests, the recovery utility digest, SBOM, Cargo inventory, source commit, and
workflow run. The publication job
re-extracts all four archives, verifies every
checksum/signature/SBOM/provenance companion, and signs a hash-complete
`release-manifest.json`. It creates a draft, attaches every asset, and only then
publishes it. Repository-level immutable releases lock the published assets and
tag; reruns refuse to replace an existing release. A skipped platform or live
gate is a stopped release, not a pass.
