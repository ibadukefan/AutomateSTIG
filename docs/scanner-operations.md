# Scanner Operations

AutomateSTIG supplements STIG Manager with evidence and machine evaluations
for selected devices that are difficult to assess with Evaluate-STIG or
site-specific scripts. It is not a second compliance-management system.

## Product boundary

| AutomateSTIG | STIG Manager |
| --- | --- |
| Exact scanner profiles and target adapters | Collections and asset inventory |
| Read-only collection plans and target fingerprints | STIG assignments and labels |
| Offline configuration/evidence ingestion | Human review, comments, and overrides |
| Deterministic scanner-owned results | Submission, validation, acceptance, and rejection |
| Evidence, hashes, provenance, and collection errors | Dashboards, findings analysis, reports, and long-term history |
| Short-lived run history, handoff state, reconciliation, and receipts | Authoritative multi-user access and governance |
| One selected-run handoff for each complete run | Checklist import and portfolio workflows |

AutomateSTIG never creates a STIG Manager asset or assignment. A connected run
must bind to an existing collection, asset, assigned benchmark, and exact
revision before collection and again before delivery.

## Exact scanner profiles

The scanner-first release contains three immutable, release-bundled profiles:

| Profile | Exact benchmark | Version compatibility grammar | Full rules | Reviewed | Scanner-owned | Reviewed manual | Outside profile |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |
| NetApp ONTAP 9.x | `NetApp_ONTAP_DSC_9-x_STIG` V2R4 | ONTAP major version 9 | 29 | 22 | 15 | 7 | 7 |
| FreeBSD / GPOS | `General_Purpose_Operating_System` V3R3 | FreeBSD major versions 13–14 | 203 | 30 | 6 | 24 | 173 |
| Cisco IOS-XE Router NDM | `Cisco_IOS-XE_Router_NDM_STIG` V3R7 | IOS-XE major version 17 | 42 | 42 | 33 | 9 | 0 |

The version grammar is a rejection boundary, not live-device acceptance. The
profiles remain experimental until the release carries authorized live-device
evidence for its declared firmware matrix. The counts are curated reviewed
subsets; they are not complete benchmark-automation claims.

## Connected analyst flow

1. Open **Connection**, enter one STIG Manager destination, and test the
   submitted values. The saved response never returns the client secret.
2. Open **Scan**, select a live collection, existing asset, and exact assigned
   STIG. Unsupported assignments remain visible with a reason but cannot run.
3. Choose the profile and collection method. ONTAP and FreeBSD use a read-only
   SSH plan or strict evidence; IOS-XE uses an operator-provided complete
   running configuration and a trusted, asset-bound organization policy.
4. Run the safety check (preflight). Confirm target identity, observed software, privilege,
   destination binding, content hashes, and every command or offline operation.
5. Collect and evaluate. Missing, denied, timed-out, truncated, malformed, or
   semantically ambiguous evidence produces an incomplete run. It is never
   converted to a passing result.
6. Review the read-only delivery preview: creates, scanner-owned updates,
   unchanged reviews, conflicts, evidence references, and manual/out-of-scope
   rules that will remain untouched. Treat automation coverage as scanner
   scope, never as a compliance score.
7. Continue according to the preview. An exact remote no-op can be verified
   directly and receives a technical receipt. If any review would be created
   or updated, download the selected-run handoff and reconcile it at the
   destination. Direct changes are safety-gated because the current STIG
   Manager review API has no atomic conditional-write contract.
8. Use **Open in STIG Manager** to reconcile the sparse handoff and complete
   manual reviews, comments,
   submission, validation, findings analysis, and reporting.

The first-open training walkthrough exercises this review vocabulary without
creating a run or contacting a target. It cannot create a handoff and must not
be retained as assessment evidence.

The device password or key passphrase exists only for the submitted preflight
and run. It is cleared after submission or failure and is never written into a
target, run, delivery, or browser-storage record.

## Sparse review semantics

AutomateSTIG proposes only rules that it evaluated from accepted scanner
evidence. A sparse delivery may contain `Automated` live results and
scanner-attributed `Evidence` results. It excludes:

- manual and `NotReviewed` rules;
- collection errors and incomplete observations;
- imported checklist assertions;
- answer-file or locally edited reviewer decisions; and
- rules outside the exact scanner profile.

AutomateSTIG classifies every proposed review as create, update, unchanged, or
conflict. It never directly creates or updates a review through an API that
cannot atomically prove the preview is still current. A human conflict leaves
the delivery in `conflicted` state with no writes. A fully unchanged sparse
result is a safe remote no-op and receives a technical receipt. Create/update
rows remain `preview_ready` and use the selected-run handoff; partial remote
acceptance, if reported by a pilot destination, is preserved as a
reconciliation receipt and cannot be retried blindly.

## Disconnected flow

Choose **Run disconnected** when the scanner cannot reach STIG Manager. Scan,
version checks, evidence validation, and deterministic evaluation remain the
same. A complete run can produce one integrity-hashed handoff for that selected
run containing sparse review transport data, supplemental XCCDF 1.2 and CKLB
projections, evidence references, profile/content/build hashes, target
identity, and a provenance manifest.

An incomplete run produces diagnostic artifacts only and cannot produce a
compliance handoff. The receiving operator validates the handoff, selects the
existing STIG Manager asset and exact assignment, and maps only
`sparse-reviews.json` into the STIG Manager Review API. Omitted rules remain
untouched. `results.xccdf.xml` and `fallback.cklb` are verified supplemental
projections, not additional review sets to import. The browser-side STIG
Manager XCCDF import wizard remains a separate acceptance gate and is not
claimed by the current staging workflow. The operator completes human work in
STIG Manager. AutomateSTIG does not become an offline portfolio manager.

## Manager flow

A cybersecurity manager uses **Deliveries** to answer operational questions:

- Did collection complete, and which rules were in scanner scope?
- Which result is preview-ready, safely unchanged, conflicted, or awaiting
  reconciliation?
- Did a retry preserve the request digest?
- Which human/manual reviews were explicitly untouched?
- What exact-no-op or reconciliation receipt, GUI base link, and exact destination IDs identify the next action?

The manager uses STIG Manager—not AutomateSTIG—for compliance posture, CAT
rollups, assignment progress, reviewer performance, submission state, accepted
risk, and reports.

## Migration window

The scanner-first cutover preserves existing databases. For one transition
release, legacy local assets, imported/manual checklists, answer files, and
portfolio exports are read-only or available through a separate inventory and
one-time export utility. They are not promoted into scanner-owned reviews.

Migration rules are deliberately conservative:

- do not delete existing rows in place;
- do not create STIG Manager assets or assignments from local records;
- do not relabel `Manual`, `Imported`, or `AnswerFile` findings as automated;
- export before retention cleanup and verify the remote receipt first; and
- remove duplicated GUI mutations only after the scanner run/outbox path and
  migration inventory pass release acceptance.

After the deprecation window, asset governance, finding editing, answer-file
management, broad content browsing, historical checklist import, and portfolio
reporting remain outside the end-user scanner GUI.

## Security and retention

Raw command output and running configurations can disclose topology, account
names, management services, or security settings even when they contain no
password. Treat the local data directory as sensitive assessment material.

- Run the GUI on a single-user, owner-controlled host and keep it bound to
  localhost unless a separate TLS/authentication boundary is provided.
- Use least-privilege read-only device accounts, destination allowlists, and
  out-of-band SSH host-key enrollment.
- Keep organization-policy signing keys off the scanner host. The scanner only
  needs approved public keys and detached signatures.
- Configure a site-approved replay-evidence period with
  `AUTOMATESTIG_EVIDENCE_RETENTION_DAYS` (1–365 days; default 30) or
  `scanner.evidence_retention_days`. Expiry is measured from evidence sealing,
  not from delivery. Archive a retained-evidence handoff before the displayed
  expiry when policy requires it; the startup/access/periodic purge is one-way.
- Purge removes encrypted replay evidence and its wrapped data key, not the
  immutable result hashes, timestamps, audit events, attempt history, or
  receipt. A later handoff is therefore results-only and remains verifiable but
  cannot replay the original evidence.
- The GUI's **Purge replay evidence** action requires typing the exact run ID.
  It is irreversible. Terminal operational rows are retained only for the
  configured `scanner.operational_retention_days`/`AUTOMATESTIG_OPERATIONAL_RETENTION_DAYS`
  period (1–365 days, default 30), then swept in bounded batches only after an
  exact no-op or strict receiver-reconciliation receipt. The sweep leaves an
  append-only receipt/digest tombstone.
- A failed SSH job may resume only from encrypted successful-operation
  checkpoints. The operator runs a fresh preflight and supplies fresh
  credentials; profile, collection plan, device fingerprint, host key,
  endpoint, port, destination assignment, and saved target profile must all
  match exactly. Credentials are never checkpointed.
- Receiver reconciliation imports require the exact sparse payload digest,
  sorted scanner-owned rule set, destination IDs, independent readback digest,
  explicit operator confirmation, and the configured GUI base URL. Receipts
  are append-only and listed through bounded pages.
- Remember that backups and snapshots can retain deleted secrets or evidence.
  Apply the site's media-sanitization and records policy to those copies.
- Never treat AutomateSTIG's local queue as the authoritative compliance
  record or expose the local GUI as a multi-user service.

## Current limitations

- Only the three exact profiles above are in scanner scope.
- The profile firmware grammars have not yet been promoted to a tested live
  acceptance matrix.
- Scanner Content displays each profile's protected-device live-acceptance and
  measured false-pass status. `not_run` is not a pass claim.
- IOS-XE is configuration ingestion, not a live SSH scan.
- The current STIG Manager API does not expose an atomic conditional review
  write. Create/update proposals are handoff-only; direct confirmation is
  limited to exact no-ops.
- Manual-rule completion and organization-defined determinations remain in
  STIG Manager.
- The current tested STIG Manager interchange maps `sparse-reviews.json` to the
  Review API. XCCDF 1.2 and CKLB are supplemental projections; native GUI file
  import is not supported until semantic round-trip acceptance passes for each
  declared consumer version. CKL remains withheld under the same rule.
- A global “better than Evaluate-STIG” claim is unsupported. Use the measured,
  target-specific protocol in [Evaluate-STIG Comparison](evaluatestig-comparison.md).

The reproducible synthetic workflow corpus is documented in
[`fixtures/scanner_scenarios`](../fixtures/scanner_scenarios/README.md).
