# Release Evidence

Each release tag requires `release-evidence/<tag>.json`, validated against
`schemas/release-evidence.schema.json` and by
`scripts/validate-release-evidence.py`.

Prepare it only after feature freeze and independent review. Set
`approved_commit` to the exact reviewed code commit, commit only the evidence
document and its redacted artifacts afterward, then tag that evidence commit.
Every `evidence_reference` must be a committed regular JSON file under
`release-evidence/artifacts/<tag>/`; the validator re-hashes it, validates its
gate-specific semantics, and rejects symlinks, URLs, missing files, and any
other post-approval path change.

For connected tag validation, each acceptance and recovery JSON must also be
byte-for-byte identical to the bounded artifact downloaded from its recorded
successful workflow run at `approved_commit`. A plausible run ID beside a
self-authored `passed: true` file is not release evidence.

Content signing has the same connected provenance requirement, but binds three
fixed files: `content-signing-ceremony.json`, the exact 32-byte
`content-signing-public-key.pub`, and
`content-signing-test-pack.stigpack`. Record all three references and SHA-256
digests in `content_signing_key`. The validator requires them to match the sole
fixed-name artifact from the successful Content Signing Ceremony run at
`approved_commit`, verifies that its actor was the recorded key custodian, and
checks that the protected environment's sole user reviewer is the distinct
recorded content approver.

Record the merged code pull-request number and the two reviewers' exact GitHub
logins and approval timestamps. Connected tag validation queries GitHub and
requires current software and security approvals on the final PR head, neither
from the author, with `approved_commit` equal to that PR's merge commit on
`main`. `--offline` exists only to test a draft evidence document locally; its
result is not release-eligible.

The device-gate `version` values are exact benchmark releases: ONTAP is
`V2R2`, FreeBSD is `V3R3`, and Cisco IOS-XE Router NDM is `V3R7`. The STIG
Viewer gate records the tested product version and uses its platform as the
environment. The STIG Manager gate records the tested product version and the
same staging-environment descriptor as its artifact. The recovery gate uses
`v1` and its protected artifact contains both the JSON result and the complete
log bound by `output_sha256`.

Do not invent a pass, reviewer, fingerprint, or evidence digest. ONTAP,
FreeBSD, Cisco IOS-XE, STIG Viewer, STIG Manager, and recovery must all have
real passing artifacts no older than 90 days. A risk acceptance documents a
residual risk; it cannot replace a required gate.
