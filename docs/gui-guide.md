# Scanner GUI Guide

Run the local GUI with:

```bash
cargo run --release --bin automatestig-gui
```

The browser opens on localhost and uses four workspaces: **Scan**,
**Deliveries**, **Scanner Content**, and **Connection**. STIG Manager remains
the system of record for assets, assignments, human findings, comments,
approval, dashboards, and reports.

## First open

The first screen offers two clear paths:

- **Connect to STIG Manager** for authoritative destination selection and a
  connected scan; or
- **Run disconnected** for an authorized air-gapped collection/evaluation and
  one selected-run handoff.

The same screen includes an operator-readiness checklist and a browser-only
sample result. The sample makes no API request, creates no run, cannot be
downloaded or delivered, and is visibly marked as training data. Use it to
learn the preview vocabulary before providing device credentials or evidence.

Connection is optional for scanning, but it is required for live authoritative
asset/assignment selection and remote ownership classification. The browser never stores API
tokens, STIG Manager secrets, device passwords, or key passphrases in local or
session storage.

## Scan

In connected mode, select in order:

1. a STIG Manager collection;
2. an existing asset in that collection;
3. an exact assigned STIG that maps to a scanner profile; and
4. a collection method and target endpoint or input file.

The assignment list explains why unsupported targets or revisions cannot run.
AutomateSTIG never offers an **Add asset** or **Assign STIG** action.

For ONTAP and FreeBSD, enter a one-time SSH password or absolute secure private
key path, or submit a native adapter-evidence envelope. A managed credential
reference is not offered because no server-side credential provider is
configured; device credentials are never saved for reuse. For IOS-XE, attach a
complete running configuration plus its asset/revision-bound organization
policy and detached signature. The policy-signing private key never belongs in
this GUI.

Run the **safety check** (the API calls this preflight) before starting a run.
Review:

- selected remote collection, asset, assignment, and revision;
- observed device identity and software compatibility;
- host-key or offline-artifact identity;
- content and plan bindings;
- required privilege; and
- every read-only command or offline operation.

A preflight token is short lived and bound to these nonsecret inputs. Changing
the target, input, profile, or destination requires a new preflight.

During collection, the page shows target connection, evidence collection,
completeness, evaluation, and delivery-preview stages separately. Permission,
timeout, transport, truncation, parser, version, or policy errors remain visible
collection errors. They cannot become passing findings.

## Delivery preview

After a complete run, Scan displays a read-only preview with scanner result
counts, evidence/provenance links, and the exact remote changes:

- create;
- update of an AutomateSTIG-owned review;
- unchanged AutomateSTIG review; or
- human-review conflict.

The preview also states how many manual and out-of-scope rules remain
untouched. **Automation coverage** describes the portion of the full benchmark
owned by the scanner; it is not a compliance score. There is no finding editor.
Use STIG Manager for human decisions.

If all rows are unchanged, **Confirm remote no-op** rechecks the authoritative
reviews and records a technical receipt without writing a review. If any row is
a create or update, download and verify the selected-run handoff, then reconcile
it in STIG Manager. AutomateSTIG does not directly write those changes because
the current STIG Manager API cannot atomically protect the preview from a
concurrent human edit. A conflict blocks no-op verification and remains visible
with the handoff and **Open in STIG Manager** link.

For changed reviews, the GUI shows the exact receiving command:

```bash
automatestig scanner verify-handoff <selected-run.zip>
```

AutomateSTIG has no native changed-review import into STIG Manager. After
verification, an authorized analyst reconciles only the sparse reviews with
the exact destination using the site's approved receiver workflow and records
the destination receipt.

## Deliveries

Deliveries is a technical queue, not a compliance dashboard. Each row shows:

- run and target identity;
- destination collection, asset, and exact assignment;
- collection completeness and sparse review counts;
- preview-ready, exact-no-op verified, retryable, conflicted, or rejected
  state;
- immutable payload digest;
- attempt timestamps and typed errors; and
- exact-no-op or reconciliation receipt, credential-free GUI base link, and exact destination identifiers.

Retry is available only when it is safe. It reuses the committed payload
digest and rechecks current remote state. Resolve human conflicts in STIG
Manager before retrying.

## Scanner Content

Scanner Content lists only release-bundled scanner profiles. It shows exact
STIG ID/revision, target family, compatible-version grammar, collection method,
profile/check-pack/benchmark hashes, scanner-owned/manual counts, trust, and
live-acceptance readiness.

It is not a general DISA catalog. Broad content fetch, arbitrary XCCDF import,
STIG assignment, and GUI content signing are not part of the scanner workflow.

## Connection

Connection saves or tests one STIG Manager destination. **Test these values**
uses the values currently in the form without silently persisting them. A blank
secret may reuse the saved secret only when the API URL, token URL, and client
ID are unchanged. **Disconnect** removes the active destination configuration
from the local database but cannot erase secrets from backups or snapshots.

The connection response shows sanitized server identity, version,
capabilities, and effective privileges. It never echoes the client secret.
The connected API adapter accepts only the exact retained tested STIG Manager
build `1.6.13+1`; it does not infer compatibility from a nearby semantic
version. Capability discovery rejects every other version before authenticated
asset or review operations. Use disconnected scanning and a verified
selected-run handoff with unsupported STIG Manager versions.

Configure the **STIG Manager GUI base URL** as a credential-free HTTPS URL on
the same origin, ending in `/`. The GUI deliberately labels the action **Open
STIG Manager** and shows collection, asset, and assignment IDs beside it:
STIG Manager `1.6.13+1` has no supported asset or review deep-link contract;
query/hash routes are OIDC behavior, not review navigation.

For live SSH, the Scan page can save and reuse a thin target profile containing
only profile, adapter, endpoint, port, optional opaque provider reference, and
last observed host key. It never stores device credentials. An opaque reference
is metadata-only unless a server-side credential provider is configured, so
every run and resume still requires fresh submitted credentials.

## Disconnected runs

Disconnected mode omits remote destination selection and ownership preview. A complete
run can download one selected-run integrity handoff containing the approved
sparse result plus native evidence/provenance. It does not create a local asset
inventory, editable checklist workspace, or portfolio export.

An incomplete run remains diagnostic and has no compliance handoff. CKLB and
XCCDF 1.2 are supplemental projections inside the verified handoff, not native
receiving mechanisms. The handoff's sparse JSON reviews are the canonical
STIG Manager Review API projection.

The same handoff is available for a complete connected run when create/update
rows are safety-gated. Connection does not make AutomateSTIG an alternate
review workspace.

## Legacy transition

Existing databases remain readable during one deprecation release. Preserved
pre-scanner asset, finding, input, and portfolio records are read-only
inventory/export sources; the scanner GUI does not let them create new
compliance state or feed them into scanner evaluation. No preserved result is
relabeled as scanner automation.

See [Scanner Operations](scanner-operations.md) for ownership, retention, and
sparse review rules.
