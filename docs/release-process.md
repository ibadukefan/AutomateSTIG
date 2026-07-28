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
Windows artifacts are intentionally outside the supported release set.

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
2. dispatch every protected acceptance, recovery, and signing workflow at that
   exact `approved_commit`;
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
- an approved content-signing fingerprint plus the fixed ceremony JSON, raw
  public key, and signed test pack, all byte-bound to a successful protected
  workflow at `approved_commit` with distinct custodian and approver identities;
- a merged, GitHub-verified code pull request with distinct software/security
  approvals on its final head, and no subsequent change except its bound
  release-evidence document and artifacts;
- non-expired, named risk acceptances (or an empty list).

The release workflow builds without privileged credentials. Before
publication, a tag-only equivalence job extracts the Linux x86_64 CLI from the
candidate archive and requires its SHA-256 to equal the exact binary recorded
by protected live-device acceptance; any toolchain or runner-dependent drift
stops the release. The publication job then attests those exact archives, verifies every
checksum/signature/SBOM/provenance companion, and signs a hash-complete
`release-manifest.json`. It creates a draft, attaches every asset, and only then
publishes it. Repository-level immutable releases lock the published assets and
tag; reruns refuse to replace an existing release. A skipped live gate is a
stopped release, not a pass.
