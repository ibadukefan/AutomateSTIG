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

`first_use_ux` is also mandatory. Its protected artifact records the exact
approved commit, intended release tag, GUI digest, prepared-scenario hashes,
complete representative cohort, and exact unaided numerator/full denominator.
The observer must dispatch the protected workflow and a distinct named
approver must approve its environment. Unit tests validate this gate's
mechanics; they cannot substitute for the external human study described in
`docs/first-use-ux-study.md`.

Content signing has the same connected provenance requirement, but binds three
fixed files: `content-signing-ceremony.json`, the exact 32-byte
`content-signing-public-key.pub`, and
`content-signing-test-pack.stigpack`. Record all three references and SHA-256
digests in `content_signing_key`. The validator requires them to match the sole
fixed-name artifact from the successful Content Signing Ceremony run at
`approved_commit`, verifies that its actor was the recorded key custodian, and
checks that the protected environment's sole user reviewer is the distinct
recorded content approver.

Producer-authenticated selected-run handoff is a separate mandatory release
proof. Record the five fixed files from the successful protected Handoff
Receiver Ceremony run in `producer_authenticated_handoff`:

- `handoff-receiver-ceremony.json`;
- the raw 32-byte `handoff-producer-public-key.pub` trust anchor;
- the exact bounded `producer-handoff.zip` emitted by the approved-commit STIG
  Manager staging run;
- `producer-handoff.zip.signature.json`; and
- `handoff-key-custody-ceremony.json`, containing non-secret custody references
  and explicit confirmation that private key material entered neither CI nor
  the scanner runtime.

The validator re-hashes all five, binds the ZIP to the STIG Manager acceptance
artifact and approved commit, checks the strict detached-sidecar contract and
producer-key fingerprint, and requires a distinct key custodian and receiver
approver. Connected validation also requires byte-for-byte equality with the
sole protected workflow artifact, an identified protected receiver, successful
trusted CLI verification, and the exact non-bypassable environment approval.
An integrity-only `verify-handoff` result does not satisfy this gate.

Record the merged code pull-request number and the two reviewers' exact GitHub
logins and approval timestamps. Connected tag validation queries GitHub and
requires current software and security approvals on the final PR head, neither
from the author, with `approved_commit` equal to that PR's merge commit on
`main`. `--offline` exists only to test a draft evidence document locally; its
result is not release-eligible.

The device-gate `version` values are exact benchmark releases: ONTAP is
`V2R4`, FreeBSD is `V3R3`, and Cisco IOS-XE Router NDM is `V3R7`. The STIG
Viewer gate records the tested product version and uses its platform as the
environment. The STIG Manager gate records the tested product version and the
same staging-environment descriptor as its artifact. It must exercise the
verified sparse selected-run handoff into an existing exact assignment and
prove that AutomateSTIG made no asset, assignment, or direct changed-review
write. An exact remote no-op may be verified separately. The recovery gate
uses `v1` and its protected artifact contains both the JSON result and the
complete log bound by `output_sha256`.

Do not invent a pass, reviewer, participant, fingerprint, or evidence digest.
ONTAP, FreeBSD, Cisco IOS-XE, STIG Viewer, STIG Manager, first-use UX, and
recovery must all have real passing artifacts no older than 90 days. The
content and handoff signing ceremonies also require their real protected human
roles and public artifacts; no repository fixture or offline validation makes
a release eligible. A risk acceptance documents a residual risk; it cannot
replace a required gate.
