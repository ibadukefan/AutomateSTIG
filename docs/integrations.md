# STIG Manager Integration

AutomateSTIG integrates with STIG Manager only to select an authoritative scan
destination and hand off scanner-owned results. STIG Manager remains the system
of record. AutomateSTIG does not mirror or manage its collections, assets,
assignments, labels, human reviews, workflow, dashboards, or reports.

## Connection

The connection contains an HTTPS API URL, HTTPS OAuth token URL, client ID,
client secret, and TLS-verification policy. The client secret is encrypted at
rest and is never returned by the API. Device credentials are separate,
per-run inputs and are not stored with the STIG Manager connection.

Connected use requires a least-privilege service account that can:

- discover server capabilities;
- read available collections;
- read existing assets and their STIG assignments;
- read current reviews for conflict classification.

The current safety boundary does not require permission to create or update
reviews. A future direct-write adapter would require a separately approved,
tested atomic conditional-write contract and narrowly scoped write permission.

The scanner does not need permission to create/delete assets, change
assignments, edit labels, accept or reject reviews, or administer users. Remove
those privileges when the STIG Manager deployment supports that separation.

See [Security Model](security-model.md) for HTTPS-only endpoints, DNS pinning,
destination allowlists, redirect denial, TLS requirements, and encrypted-secret
limitations.

## Destination selection

The Scan workspace reads collections, assets, and assigned STIGs live from
STIG Manager. A runnable assignment must match one release-bundled scanner
profile by exact STIG identifier and revision. AutomateSTIG verifies the same
collection, asset, assignment, and revision before collection and before
handoff or no-op verification. It never creates a missing asset or assignment,
and it never infers the destination solely from checklist hostname text.

## Handoff and no-op verification contract

A sparse preview and selected-run handoff contain only complete scanner-owned
evaluations. The payload excludes manual, `NotReviewed`, collection-error,
imported, answer-file, edited, and out-of-profile findings.

Before preparing a handoff or verifying an exact no-op, the client compares the
proposed sparse reviews with current remote reviews and reports:

- **create** — no review exists for this scanner-owned rule;
- **update** — an older AutomateSTIG-owned review differs;
- **unchanged** — the same AutomateSTIG-owned result already exists; and
- **conflict** — a human-owned or otherwise incompatible review would be
  replaced.

Any conflict blocks no-op verification and writes no reviews. Manual and
out-of-scope reviews are never blanked or overwritten. Because the currently
published review endpoint has no ETag, revision token, `If-Match`, or equivalent
atomic precondition, AutomateSTIG also blocks every create and update after
preview.
Those rows use the selected-run handoff and are reconciled in STIG Manager.
Only a fully unchanged sparse result can be confirmed directly as a safe no-op.

Completing evaluation and creating a preview-ready handoff record is one local
transaction. The exact sparse payload and its SHA-256 remain immutable through
retries. Remote I/O afterward is limited to review classification and exact
no-op verification. The queue's internal pending, sending, and delivered states
describe that verification attempt; `delivered` means the identical result was
already remote, not that AutomateSTIG wrote a changed review. A successful
technical receipt contains the remote identifiers, response, timestamp, and a
deep link to continue in STIG Manager.

An identical result is an idempotent no-op after current remote state is read.
AutomateSTIG does not claim create/update delivery support unless a tested STIG
Manager version exposes a true atomic precondition or idempotency primitive.

## Disconnected handoff

Every complete selected run, connected or disconnected, may be
packaged as one integrity-hashed handoff containing the approved sparse review
payload, supplemental XCCDF 1.2 and CKLB projections, evidence/provenance
manifest, and content/build hashes. This is a delivery artifact, not a locally
managed checklist portfolio. The tested receiving path selects the existing
remote asset and exact assignment, then maps only the sparse JSON reviews to
the STIG Manager Review API.

Incomplete runs cannot be handed off as compliance results. A native GUI
XCCDF/CKLB/CKL file-import claim remains unsupported until its semantic round
trip passes acceptance for the declared STIG Viewer and STIG Manager versions.

## Supported-version posture

Capability discovery is version aware. A STIG Manager server/version pair is
supported for changed writes only after initial, identical, changed,
interrupted, partial/human-conflict, exact-revision, receipt, and deep-link
tests pass in staging with a real atomic write guard. Until that matrix is
published, changed reviews remain handoff-only and must not be treated as a
direct-write interoperability claim.

See [Scanner Operations](scanner-operations.md) for the full analyst and manager
flows and [Scanner-First Product Plan](scanner-product-plan.md) for migration
and release gates.
