# AutomateSTIG Scanner-First Product Plan

Status: product direction approved; implementation baseline updated 2026-08-08.

## Product Decision

AutomateSTIG is a specialized scanner and evidence producer for devices that are difficult to assess with Evaluate-STIG, SCAP, or one-off scripts. It is not an asset, checklist, review, reporting, or compliance-management system.

STIG Manager is the authoritative system of record for collections, assets, STIG assignments, human determinations, review status, acceptance and rejection, findings rollups, reporting, and long-term compliance history. AutomateSTIG collects authorized evidence, evaluates the rules it can defend, previews the proposed machine results, and produces a verified sparse handoff for the matching STIG Manager asset and STIG assignment.

The product promise is:

> Select an assigned asset, safely collect difficult-device evidence, understand every automated decision, and produce a verifiable sparse handoff without overwriting human work.

AutomateSTIG should become better than Evaluate-STIG on selected difficult-device targets, not claim to replace Evaluate-STIG for every platform. A target-specific claim is earned only through a controlled comparison with the current Evaluate-STIG package when the two tools support the same target.

## Current Baseline

The scanner contract currently contains three exact profiles: ONTAP V2R4,
FreeBSD/GPOS V3R3, and Cisco IOS-XE Router NDM V3R7. The exact denominators are:
ONTAP 15 automated/7 manual/22 reviewed/29 full, FreeBSD 6/24/30/203, and
Cisco IOS-XE 33/9/42/42. In total, 54 automated checks and 40 reviewed-manual
rules form a 94-rule reviewed profile within 274 full-benchmark rules. These
are not claims of complete benchmark automation, and the checked-in rule packs
remain experimental until the required live-device acceptance evidence is
attached.

The current nine-scenario synthetic matrix covers pass, finding, and incomplete
outcomes for all three profiles. It also covers create/update previews, an exact
remote no-op, human conflict, disconnected handoff, and fail-closed incomplete
collection. A safety review found that the published STIG Manager review API
does not provide an atomic conditional-write precondition. AutomateSTIG now
blocks direct creates/updates, permits only exact no-op confirmation, and makes
the selected-run handoff available for every complete run. No live authorized
ONTAP or FreeBSD SSH acceptance or current gated Evaluate-STIG A/B run has been
completed.

The controlled comparison runner and schemas are implemented in
`scripts/compare-commercial-scanners.py`. They enforce exact target/tool/content
hashes, independently adjudicated cases, repeated committed random ordering,
native XCCDF or independently normalized proprietary exports, explicit
deviations, and the zero-false-pass/incomplete-evidence gate. Licensed
comparator packages, representative devices, and independent live results are
still external inputs; implementation of the harness is not a measured win.

Encrypted replay-evidence retention and the receiver-side handoff verifier are
now implemented. Replay evidence is separately sealed with per-artifact keys,
expires under a configurable 1–365 day policy (30 days by default), and can be
purged only in one direction while result hashes and purge metadata remain.
Handoff v4 supports a canonical request binding, retained replay evidence, and a results-only post-purge
state; `automatestig scanner verify-handoff` validates its bounded ZIP shape,
hashes, bindings, sparse review transport, supplemental standards-based XCCDF
1.2 and CKLB projections, and retained evidence replay. The verifier keeps the exact legacy v2
contract for already-issued bundles without treating undeclared members as an
upgrade. The GUI handoff is still unsigned, so passing integrity verification is not
producer authentication. A protected CLI can now issue a detached,
domain-separated signature for the exact verified ZIP, and receiving analysts
can require an explicitly trusted handoff-producer key before decompression.
The GUI never holds that key. A protected-key signed consumer round-trip and
operational key-custody exercise remain release gates.

Therefore, the current build is a credible pilot, not yet evidence for a general “better than Evaluate-STIG” claim. The roadmap below turns these known limitations into release gates.

## Ownership Boundary

### AutomateSTIG owns

- Trusted scanner content, target adapters, and exact supported-version contracts.
- Authorized live collection and offline evidence or configuration ingestion.
- Transport safety, device fingerprinting, command and request plans, and collection diagnostics.
- Deterministic evaluation of scanner-owned rules.
- Rule-level evidence, hashes, provenance, and fail-closed handling of incomplete evidence.
- A short-lived scan job history and durable handoff/no-op verification state.
- Remote ownership classification, exact no-op confirmation, and a selected-run handoff for changed results.
- Technical delivery receipts and immutable scanner audit records.

### STIG Manager owns

- Collections, asset inventory, labels, ownership, lifecycle, and STIG assignments.
- Human evaluation, comments, overrides, Not Applicable decisions, and manual-rule completion.
- Saved, submitted, accepted, and rejected review workflow.
- Collection and portfolio dashboards, risk rollups, findings reports, POA&M-related output, and metrics exports.
- Review history, evaluator and validator attribution, access control, and the long-term compliance record.
- General STIG-library administration and historical checklist import.

This boundary follows STIG Manager's documented scope: its user guide already includes asset and assignment management, individual and collection review workspaces, acceptance and rejection, findings analysis, progress tracking, labels, and result export. AutomateSTIG should link to those capabilities instead of reimplementing them.

## Intended User Flow

The GUI should have four primary workspaces: **Scan**, **Deliveries**, **Scanner Content**, and **Connection**.

### Connected workflow

1. **Select the authoritative destination.** The user selects a STIG Manager collection, then an existing asset and assigned STIG. AutomateSTIG fetches these live and filters the list to scanner-ready assignments.
2. **Choose the collection method.** The user selects the target adapter, endpoint, and a temporary credential source or credential reference. Device secrets are not copied into the asset record.
3. **Run preflight.** AutomateSTIG verifies reachability, host identity, software version, privilege, exact benchmark and check-pack alignment, and shows every command or API operation before execution.
4. **Collect and evaluate.** The scanner retrieves reusable observations once, rejects incomplete or ambiguous collection, and deterministically evaluates scanner-owned rules.
5. **Review the delivery preview.** A read-only view shows coverage, automated results, collection errors, raw-evidence references, and exactly which remote reviews will change. It states how many manual or out-of-scope rules will remain untouched.
6. **Handoff safely.** AutomateSTIG confirms an exact remote no-op directly. A create/update preview remains safety-gated and produces a verifiable selected-run handoff; it is not written through an API that cannot atomically protect human work.
7. **Continue in STIG Manager.** The result screen provides the handoff, the credential-free STIG Manager GUI base link, and exact collection/asset/assignment IDs for reconciliation, manual completion, submission, validation, reporting, and governance. The tested STIG Manager build exposes no supported asset/review deep-link contract.

### Disconnected workflow

The scan and evaluation steps remain available without STIG Manager. The
output is one integrity-hashed handoff bundle for the selected run, containing
a sparse JSON review transport, supplemental XCCDF 1.2 and CKLB projections,
and the richer native evidence and provenance manifest. A protected signing host can attach producer
authentication without changing the GUI-produced ZIP; production release
still requires a signed receiving-workflow acceptance with governed key
custody. This is a delivery mechanism, not a local checklist portfolio or
reporting feature.

### First-open experience

- Lead with **Connect to STIG Manager** and **Run disconnected** choices.
- Explain in one sentence that STIG Manager remains the system of record.
- After connection, immediately offer collection, asset, and assigned-STIG selection.
- Show unsupported assignments with the exact reason and tested-version boundary; do not present them as runnable.
- Use “scan,” “run,” “delivery,” and “scanner result.” Avoid “manage assets,” “manage findings,” or language implying a complete compliance assessment.

## Feature Disposition

| Current capability | Decision | Scanner-first replacement |
|---|---|---|
| Local Assets page and asset CRUD | Remove as inventory; retain only thin target connection profiles | Select the authoritative STIG Manager asset live. Store only collection/asset IDs, endpoint/port, adapter, credential reference, last observed host fingerprint, and recent operational state. |
| Tags, notes, enable/disable, and bulk STIG assignment | Remove | Manage them in STIG Manager. |
| STIG Manager asset sync and diff | Remove mirrored inventory | Use live, refreshable collection/asset/assignment lookup with a minimal retry cache. |
| Assessments page | Refocus and rename **Scan** | Start a scan and show recent scanner jobs, not a long-term checklist portfolio. |
| Persistent assessment grouping | Reduce | Retain only run state, provenance, delivery state, retry history, and configurable technical-artifact retention. |
| Checklist detail | Reduce to read-only delivery preview | Show scanner-owned results, collection diagnostics, provenance, and pending remote changes. |
| Finding result/detail/comment editor | Remove | Human determination and editing occur in STIG Manager; offer a remote review link. |
| Global Findings page | Remove | Link to the chosen STIG Manager collection's findings workspace. Keep scanner errors under the relevant run. |
| Manual Not Reviewed work queue | Remove | Report the scanner boundary; complete manual rules in STIG Manager. |
| General answer-file editor and application | Remove | Human answers and overrides belong in STIG Manager. Retain only typed, signed scanner policy parameters when a rule genuinely depends on an organization-defined value; never relabel these as direct device evidence. |
| Import Existing Results for CKL, CKLB, or checklist JSON | Remove from the scanner GUI | Import historical or third-party checklists directly into STIG Manager. Keep a transition-only conversion utility for one deprecation release. |
| Individual CKL/CKLB export | Retain CKLB only as a supplemental selected-run projection | Use sparse JSON reviews as the staged STIG Manager transport, package XCCDF 1.2 and CKLB projections with the native provenance manifest, and keep native file-import compatibility behind supported-consumer acceptance gates. |
| Export All ZIP and portfolio reporting | Remove | Use STIG Manager exports and reports. |
| Native evidence/result bundle | Retain and strengthen | Make it the authoritative offline scanner artifact with evidence, plan, result, content, policy, and software hashes. |
| STIG Manager JSON output | Retain only as approved offline handoff | Include only scanner-owned evaluations and use the same ownership rules as the connected preview. |
| Legacy STIG Manager direct push | Retire changed-review writes | Retain preview, conflict handling, exact no-op verification, reconciliation receipts, version compatibility, a credential-free GUI base link plus exact IDs, and the verified selected-run handoff. A future changed-write adapter would require a real atomic precondition and a new release gate. |
| Push of all checklist findings | Removed | Hand off only rules evaluated from AutomateSTIG evidence. Never blank or overwrite manual and out-of-scope reviews. |
| STIG Manager configuration/test/collection picker | Retain and strengthen | Add API capability discovery, privilege checks, live asset/assignment selection, and supported-version messaging. |
| Broad Standards page and general catalog | Remove or delegate | Replace with **Scanner Content**, limited to supported adapters, exact STIG revisions, pack trust, coverage, firmware validation, and update readiness. |
| Exact supported XCCDF and signed `.stigpack` import | Remove raw XCCDF from the normal GUI; retain protected content tooling | Build release-bundled or separately signed scanner profiles containing only content needed by a supported scanner contract. |
| DISA browse/fetch-all | Remove | Perform targeted update checks for supported scanner contracts; use STIG Manager for the general catalog. |
| Offline-pack signing in the normal GUI | Remove | Keep a protected operator or CLI signing workflow; do not handle signing private keys in the everyday scanner UI. |
| Compliance dashboards and CAT totals | Remove | Use STIG Manager. Show only scanner operations: collection completeness, executable coverage, unresolved scope, run health, and delivery status. |
| Local audit API | Retain and expose under Runs/Deliveries | Record input hashes, device identity, plan, commands/requests, evaluator/content versions, delivery attempts, and receipt. |
| Checklist deletion | Replace with retention controls | Permit staged artifacts to expire or be removed after verified delivery while preserving the audit digest and receipt. |

The current GUI pages map to the new shell as follows:

| Current page | Target page |
|---|---|
| Assessments | Scan |
| Assets | Removed; authoritative asset picker moves into Scan |
| Standards | Scanner Content |
| Findings | Removed; link to STIG Manager |
| Settings | Connection |
| None | Deliveries |

## Local Data Contract

After migration, the local database should contain only:

- Scan job and step state.
- Target connection profile fields not owned by STIG Manager.
- Credential references, never reusable plaintext device passwords.
- Immutable evidence and result artifact metadata with integrity hashes.
- Scanner content, trust anchors, compatibility data, and coverage manifests.
- Handoff/outbox entries, verification attempts, conflicts, remote IDs, and receipts.
- Technical audit events and retention configuration.

It should not contain an authoritative copy of asset metadata, STIG assignments, labels, manual reviews, workflow status, manager comments, accepted risk, or portfolio history.

## Implementation Architecture and Cutover

Do not delete `Checklist` or the old storage tables in place. The retired STIG
Manager push implementation depended on a persisted checklist, so migration
preserves those records for inventory and one-time export while the exposed
runtime uses scanner runs and selected-run handoffs. Prune compatibility code
only after the new path passes staging and existing data remains exportable.

### Release-bundled scanner profiles

A fresh installation should be able to scan the declared targets without first becoming a general DISA-content manager. Ship each exact supported benchmark model, executable check pack, coverage manifest, compatibility matrix, and integrity hashes as one immutable scanner profile validated against `content/supported-targets.json`.

For the first scanner-first release, bundle those profiles with the signed application release. If faster air-gap content updates are required later, add a separately signed scanner-profile bundle. Do not restore arbitrary raw-XCCDF import to the normal scanner GUI.

### Shared scanner application service

Add a shared crate or application module used by both GUI and CLI:

- `profiles`: exact target, STIG revision, firmware, content, and trust resolution.
- `scan`: preflight, collect, strict assembly, and incomplete-run handling.
- `evaluate`: common deterministic evaluation and provenance binding.
- `delivery`: destination preflight, sparse review mapping, ownership classification, safe no-op confirmation, handoff, conflict handling, reconciliation, and receipt.
- `models`: immutable scan run, scan result, delivery, and delivery receipt types.

Move the production STIG Manager HTTP client out of the GUI into the integrations layer so GUI and CLI use the same URL validation, DNS pinning, redirect denial, response limits, authentication, review mapping, and version-compatibility behavior.

### Transactional handoff/outbox

Immutable `scan_runs` and `deliveries` records bind a completed evaluation and
its handoff state in one local transaction. Remote I/O after commit is limited
to current-review classification and exact no-op verification. The delivery
record preserves preview-ready, verified-no-op, conflicted, retryable, and
reconciliation states without becoming a remote review writer.

Persist the exact sparse-review payload and digest used by the selected-run
handoff. A restart can safely retry remote state verification without changing
that payload. Do not claim delivery or exactly-once semantics for changed rows;
their acceptance is established only by the receiver's Review API response and
independent readback from STIG Manager.

### New versioned API surface

The scanner-first API should converge on a small, versioned surface such as:

- `GET /api/v1/status`
- STIG Manager connection save, test, collection, asset, and assignment lookup
- `GET /api/v1/scanner/profiles`
- `POST /api/v1/runs/preflight`
- `POST /api/v1/runs/ssh`
- `POST /api/v1/runs/evidence`
- `GET /api/v1/runs/jobs/{id}`
- `GET /api/v1/runs`
- `GET /api/v1/runs/{id}`
- `POST /api/v1/runs/{id}/deliver`
- `GET /api/v1/runs/{id}/handoff`

Long-running collection returns a job identifier and supports progress
polling. Remote verification is bounded to an exact no-op; changed reviews use
the selected-run handoff. The destination collection and asset are selected
before collection, and the product must never infer or relabel the remote asset
solely from checklist hostname text.

After parity, retire the GUI routes for local asset CRUD and bulk assignment, asset sync/diff, finding edits, answer files, checklist import/delete, portfolio exports, broad library and DISA catalog management, and GUI pack signing. During the transition, removed mutations should return migration guidance rather than silently falling through to the single-page application.

Keep collection/evaluation commands in the end-user CLI, backed by the shared service. Move signing, broad content import, conversion, legacy export, and other transition or maintainer operations into a separate tool that is not presented as the AutomateSTIG user workflow.

## Migration Without Data Loss

Removing duplicated capabilities requires a transition, not destructive schema deletion.

1. Add a local inventory report that classifies records as completed scanner output, incomplete/audit-only, imported/unverified, manually edited, or answer-file-derived.
2. Offer one-time exports for verified scanner evidence, CKL/CKLB interoperability, manual/imported records, answer files, and local-to-STIG-Manager asset mappings.
3. Mark duplicated GUI functions read-only and deprecated for one transition release.
4. Never migrate `Manual`, `Imported`, or `AnswerFile` results as automated results.
5. Bind retained scanner jobs to STIG Manager collection, asset, assignment, and revision IDs where a valid match exists.
6. Verify remote receipt before applying local artifact-retention cleanup.
7. Remove deprecated routes and tables in the next major schema version, while retaining a documented, separate CLI conversion path for the transition period.

No existing local asset, checklist, answer file, or audit record should be silently deleted or automatically asserted in STIG Manager.

## Definition of “Better Than Evaluate-STIG”

The public NAVSEA description establishes Evaluate-STIG as a Windows PowerShell tool intended to automate STIG compliance documentation and reduce the manual Not Reviewed tail. Its current release, supported-target matrix, evidence model, and extension architecture are not fully observable from public resources. Therefore, absence from public documentation is not a valid competitive claim.

AutomateSTIG wins only on a specific target and STIG revision when measurement demonstrates one or more of the following without degrading safety:

- The target can be collected reliably where Evaluate-STIG cannot complete or requires bespoke scripting.
- A larger share of technically automatable rules is automated correctly.
- Fewer rules remain Not Reviewed because required device evidence is actually collected.
- Every machine result has stronger, replayable evidence and provenance.
- Permission, timeout, truncation, parser, and version errors fail closed instead of producing a false pass.
- A new or changed check requires less target-specific transport code and analyst scripting.
- Setup, runtime, and analyst intervention are lower.
- STIG Manager interchange leaves human reviews untouched and every changed row
  is mapped from a verified sparse handoff through the receiving Review API or
  a future proven atomic adapter.

The product should never advertise “better than Evaluate-STIG” globally. It should publish a scorecard for each directly compared target and say “not directly comparable” when no common target exists.

## Technical Differentiators to Build

### Collect once, evaluate many

An adapter should retrieve reusable device facts once—such as software identity, running configuration, management protocols, AAA servers, time sources, audit state, logging destinations, cryptographic mode, and banners. Rules consume normalized observations rather than executing duplicate transport commands.

### Adapter SDK instead of per-rule scripts

Create a versioned target-adapter interface with these responsibilities:

- Fingerprint device family, model, software, context, and HA role.
- Declare and preview a read-only collection plan.
- Collect through reusable SSH CLI, NETCONF/RESTCONF, HTTPS/vendor API, or offline-configuration transports.
- Detect authorization failures, truncation, paging, partial output, stale data, and unsupported versions.
- Redact secrets while recording a redaction manifest.
- Normalize raw responses into typed observations.
- Validate collection completeness before evaluation.

Rules should use a declarative predicate library for presence, equality, set membership, numeric ranges, ordered relationships, cross-field constraints, table rows, and structured configuration semantics. Reviewed target code remains available for checks that cannot be expressed safely in the DSL. Signed packs may load declarative content; they must not become an arbitrary-shell execution channel.

### Evidence-first decisions

Every automated finding must resolve to:

- Raw artifact hash and evidence-envelope identifier.
- Exact command or request, transport, privilege context, duration, status, truncation state, and error.
- Device identity, model, software version, context, and observed host or certificate fingerprint.
- Parser, observation, predicate, expected value, and observed value.
- STIG revision, rule ID, adapter version, check-pack digest, scanner build, and evaluation time.
- Applicable policy-parameter identifier, signature, and hash.

The evaluator must never turn missing evidence into `Not a Finding`. Unsupported versions, permission failures, malformed output, incomplete configuration, and missing observations produce an explicit collection error or Not Reviewed result and block the selected-run handoff for the affected run.

### Reliable STIG Manager handoff and verification

- Discover server capabilities and select a tested API adapter by STIG Manager version.
- Verify that the remote asset has the exact STIG assignment and revision before collection and again before handoff/no-op verification.
- Preview creates, updates, unchanged reviews, conflicts, and human-owned reviews that will be untouched.
- Use an immutable request digest so a handoff or retry cannot silently change.
- Confirm exact no-ops directly, but safety-gate creates and updates whenever
  the destination lacks an atomic conditional-write primitive.
- Persist remote responses, IDs, timestamps, partial acceptance, and supported GUI base links
  as technical or reconciliation receipts.
- Keep the queue operational and short lived; it must not become a second
  compliance database.

### Fast, testable target expansion

Each new adapter should ship with scaffolding, schema validation, replayable and redacted captures, golden parser tests, positive and negative rule fixtures, transport-error fixtures, a coverage inventory, and a compatibility matrix. A target is not “supported” merely because its XCCDF can be imported.

Prioritize targets using an evidence-based score:

1. Frequency and cost of Evaluate-STIG or script failure.
2. Analyst hours currently spent collecting and transcribing evidence.
3. Existence and currency of a DISA STIG.
4. Availability of a read-only CLI or structured API.
5. Access to representative hardware, licensed simulation, firmware, and an SME.
6. Reuse of an existing transport, parser, or observation model.
7. Number and severity of technically automatable rules.

Stabilize and validate the current ONTAP, FreeBSD/GPOS, and Cisco IOS-XE contracts before adding breadth. Then add no more than two device families in one release wave. Candidate discovery should consider high-pain network, security, storage, virtualization, and appliance targets, but the first wave must be selected from actual user failure data and available lab access rather than assumed demand.

## Release Scorecard and Gates

Every supported target gets a versioned scorecard. The denominators must be visible: total benchmark rules, technically automatable rules, implemented automated rules, manual rules, unsupported rules, and collection-error rules.

| Measure | Supported-target gate |
|---|---|
| Rule classification | 100% classified with rationale and required evidence |
| Automation depth | At least 80% of technically automatable rules implemented, or an approved target-specific exception |
| Safety | Zero false passes across the maintained negative, malformed, permission-denied, timeout, truncation, and unsupported-version corpus |
| Traceability | 100% of automated decisions resolve to raw evidence and content/build provenance |
| Collection reliability | At least 95% successful authorized collections across the declared firmware matrix |
| Version handling | Unsupported or mismatched device/STIG versions rejected before evaluation |
| Transport reuse | No more than 10% duplicate retrieval operations across rules |
| Declarative checks | At least 70% of new automations implemented without target-specific imperative evaluator code |
| Delivery integrity | Create/update rows remain handoff-only unless atomic-write tests pass; exact no-op, interruption, and partial/conflict cases preserve immutable identity and never overwrite human work |
| Human-review safety | Regression tests prove manual and out-of-scope remote reviews are never overwritten |
| Interchange | Sparse-review receiver mapping and Review API readback preserve the exact scanner-owned set; native STIG Manager GUI XCCDF import is claimed only after a supported-version file-import and semantic readback test; supplemental XCCDF and CKLB remain ownership-equivalent |
| First-use UX | At least 80% of representative first-time lab users complete a prepared scan without external documentation |
| Content maintenance | New STIG revision triaged within five business days and a validation plan published within fifteen |

For a direct Evaluate-STIG comparison, add these measures:

- False-pass count, treated as the primary safety metric.
- Precision and recall against SME-established ground truth.
- Implemented automation as a percentage of technically automatable rules.
- Reduction in the manual and Not Reviewed tail.
- Successful collection rate across identical firmware and privilege profiles.
- Median setup time, runtime, operator steps, and analyst intervention.
- Lines or modules of bespoke target script required.
- Time to adapt after a STIG revision.
- Evidence traceability, sparse Review API round-trip integrity, and semantic
  parity of the supplemental XCCDF/CKLB projections.

## Evaluate-STIG Comparison Protocol

A credible A/B comparison requires the current authorized Evaluate-STIG package and a genuinely overlapping target.

1. Record the exact Evaluate-STIG package version and hash; do not infer current behavior from older public material.
2. Pin identical hardware or VM, firmware, benchmark revision, device state, credentials, privilege, site-policy inputs, and assessment window.
3. Have two SMEs establish blinded ground truth from the STIG check text and the captured device state.
4. Exercise compliant state, one deliberate failure per automatable rule, permission denial, timeout, malformed and truncated response, stale configuration, unsupported version, HA or virtual context, and applicable policy overrides.
5. Run each case repeatedly and retain hashes for snapshots, evidence, packs, configurations, outputs, tool builds, and the comparison manifest.
6. Publish the scorecard, failures, exclusions, and unknowns. Do not convert unavailable or gated Evaluate-STIG behavior into a zero.

The runnable protocol is documented in
[Controlled Scanner Comparison](commercial-scanner-comparison.md). It supports
Evaluate-STIG and private-sector comparators such as Tenable or Nipper without
automatically authorizing a superiority claim.

## Delivery Roadmap

The sequence is more important than calendar estimates. Sprints assume engineering, a cybersecurity SME, STIG Manager staging access, and authorized device labs are available.

### Milestone 0 — Establish the boundary and protect existing data

Deliverables:

- Adopt this product contract in the README, GUI copy, architecture, and issue templates.
- Freeze new work on local asset governance, human finding editing, portfolio views, answer files, and general reporting.
- Add the migration inventory and one-time archive/export paths.
- Mark duplicated features read-only and deprecated.
- Define the scanner-owned review contract and exact origin/provenance mapping.

Exit criteria:

- Every current feature is assigned to AutomateSTIG, STIG Manager, transition-only tooling, or removal.
- Existing local data can be inventoried and exported without changing attribution.
- No deprecated path can create new human-owned compliance state.

### Milestone 1 — Make STIG Manager interchange trustworthy

This is the first production blocker, before visual redesign or new targets.

Deliverables:

- Add version-aware capability discovery and fail closed when an atomic review
  precondition is absent.
- Hand off only scanner-owned rules; never include blanket `NotReviewed`
  placeholders.
- Add create/update/unchanged/conflict preview and human-review protection.
- Add interruption recovery, immutable request digests, reconciliation
  receipts, credential-free destination links with exact IDs, and a receiver-side verification command.
- Use sparse JSON review mapping as the tested STIG Manager Review API
  interchange. Retain ownership-equivalent XCCDF 1.2 and CKLB as supplemental
  artifacts; claim native GUI file import only after its entity/text semantic
  round trip is proven for each supported version. Withhold CKL under the same
  gate.
- Test against every declared supported STIG Manager version.

Exit criteria:

- Exact no-op, changed-result handoff, interruption, tampering, duplicate/path
  traversal, partial acceptance, and conflict cases all pass.
- A regression suite proves no manual or out-of-scope review is overwritten.
- Exact remote collection, asset, assignment, STIG revision, and handoff digest
  are bound to every complete connected run.

Changed direct writes remain disabled until a declared STIG Manager adapter can
prove an atomic conditional-write contract in the complete staging matrix.

### Milestone 2 — Replace the GUI with the scanner workflow

Deliverables:

- Ship the Scan, Deliveries, Scanner Content, and Connection navigation.
- Add live STIG Manager collection/asset/assignment selection.
- Replace local assets with thin target connection profiles.
- Add command/request preflight, tested-version checks, expected duration, and privilege diagnostics.
- Add a read-only evidence/result preview and “Open STIG Manager.”
- Remove Findings, asset governance, answer-file editing, historical checklist import, and portfolio export from the GUI.
- Ship the exact supported scanner profiles so first use does not require importing raw DISA XCCDF.

Exit criteria:

- A first-time analyst can connect, choose an assigned asset, preflight, scan,
  understand the preview, verify/download the correct handoff, and continue in
  STIG Manager without external documentation.
- The GUI contains no workflow for assigning STIGs, editing human findings, accepting risk, or producing portfolio reports.
- Old routes redirect to a migration or STIG Manager destination instead of failing silently.

### Milestone 3 — Build the reusable adapter platform

Deliverables:

- Define the adapter, transport, evidence-envelope, normalized-observation, and compatibility schemas.
- Implement reusable SSH CLI, offline configuration, NETCONF/RESTCONF, and HTTPS/vendor-API transport contracts as target demand requires.
- Add plan preview, pagination/truncation detection, redaction manifests, resumable collection, and replay tooling.
- Expand the predicate library and signed pack format without allowing arbitrary commands from untrusted content.
- Add an adapter scaffolder, contract tests, fixture generators, and a per-target scorecard generator. The deterministic, non-claiming development tools are documented in [Target Adapter Development Tooling](adapter-tooling.md).

Exit criteria:

- A new target can reuse transport and observation infrastructure instead of embedding commands in each rule.
- All error classes are represented in contract tests and fail closed.
- A captured evidence envelope can be replayed to reproduce the same result and provenance.

### Milestone 3A — Cut over and prune the legacy runtime

Deliverables:

- Default to the scanner-first GUI and versioned API while retaining one read-only legacy/export window.
- Preserve existing databases and STIG Manager secrets; add new tables rather than dropping old ones in place.
- Remove the retired GUI routes and split the frontend into small router, API, scan, deliveries, content, and connection modules.
- Remove broad content, archive, checklist-conversion, answer-file, and local-inventory dependencies from the end-user runtime only after replacement paths are proven.
- Keep institutional knowledge and transition commands in maintainer/legacy documentation and tooling.

Exit criteria:

- Existing databases open without loss and produce the migration inventory and archives.
- The release binary no longer exposes duplicated manager workflows.
- Dependency, SBOM, rollback, route, CLI help/exit, and migration tests pass.

### Milestone 4 — Graduate the existing three targets

Deliverables:

- Reconcile each supported contract with the current official STIG revision.
- Complete the rule classification and technically-automatable inventory.
- Increase meaningful automated coverage, focusing first on the largest manual tail.
- Run positive, negative, semantic-counterexample, permission, timeout, truncation, and unsupported-version suites.
- Conduct authorized live-device acceptance across the declared firmware matrix.
- Publish target scorecards and explicit remaining manual scope.

Exit criteria:

- ONTAP, FreeBSD/GPOS, and IOS-XE meet the supported-target gates or are clearly labeled experimental/pilot rather than supported.
- Current exact revision, firmware evidence, coverage, false-pass results, and live-acceptance status are visible in the GUI.

### Milestone 5 — Add the first evidence-selected difficult targets

Deliverables:

- Collect user failure reports and baseline analyst scripting effort.
- Rank candidates with the target-priority score and choose at most two with lab access and SMEs.
- Build the first adapter and pack through the SDK, then repeat with a second target only after the first meets its safety gates.
- Test connected destination binding and disconnected/connected handoff against
  supported STIG Manager and STIG Viewer versions.

Exit criteria:

- Each new target has an exact STIG revision, representative live lab, compatibility matrix, complete classification, maintained negative corpus, documented manual tail, and signed content.
- Measured scanner success and analyst-effort reduction address the reported difficult-device problem.

### Milestone 6 — Prove the Evaluate-STIG advantage and pilot operations

Deliverables:

- Obtain the authorized current Evaluate-STIG package and select overlapping targets.
- Run the comparison protocol and publish target-specific scorecards.
- Conduct analyst and manager pilots with both connected and disconnected workflows.
- Measure scan completion, delivery reliability, review preservation, time saved, and support burden.

Exit criteria:

- “Better than Evaluate-STIG” claims are limited to dimensions and targets supported by measured evidence.
- Pilot users can complete difficult-device scans without bespoke collection scripts.
- Managers confirm that results arrive in STIG Manager with useful evidence and without a competing compliance workflow.

## Immediate Priorities

1. Graduate the implemented detached producer signature through a protected
   key-custody ceremony and signed receiver acceptance before any production
   authenticity claim.
2. Validate sparse Review API mapping/readback for every declared STIG Manager
   version. Separately test supplemental XCCDF and CKLB through each claimed
   STIG Manager or STIG Viewer file-import workflow; keep all unproven native
   import claims and CKL withheld until semantic round-trip passes.
3. Complete authorized live validation for ONTAP V2R4, FreeBSD/GPOS V3R3, and
   Cisco IOS-XE NDM V3R7 across the declared version matrices.
4. Have SMEs classify the technically automatable denominator, then close the
   highest-value manual tail—especially the deliberately narrow FreeBSD scope.
5. Run first-use analyst testing and require at least 80% unaided completion.
6. Obtain and hash the authorized current Evaluate-STIG package, then run the
   same-device, same-revision, SME-ground-truthed A/B protocol.
7. Publish target-specific scorecards only after zero false passes and measured
   collection, analyst-effort, scripting-burden, and interchange results.
8. Gather real difficult-device failure data and secure labs before adding any
   new target family.

## Required Product Inputs

These choices do not block boundary and delivery work, but they are required before target expansion:

- The two or three device families causing the most Evaluate-STIG or scripting failures.
- Representative firmware, virtual contexts, HA modes, and read-only access methods.
- Whether selected-run air-gap handoff is mandatory and which STIG Viewer/STIG Manager versions must consume it.
- Supported STIG Manager server versions and authentication patterns.
- Local evidence-retention and sanitization requirements.
- Authorized SMEs and lab owners for ground truth and negative-state testing.

## References

- [STIG Manager user guide](https://stig-manager.readthedocs.io/en/latest/user-guide/index.html)
- [STIG Manager common tasks](https://stig-manager.readthedocs.io/en/latest/features/common-tasks.html)
- [NAVSEA Evaluate-STIG overview](https://www.navsea.navy.mil/Media/News/Article-View/Article/1946720/nswc-crane-employee-develops-software-tool-to-increase-cybersecurity-cost-avoid/)
- [AutomateSTIG supported-target contract](supported-targets.md)
- [AutomateSTIG coverage policy](coverage-policy.md)
- [AutomateSTIG evaluation workflow](evaluation-workflow.md)
- [AutomateSTIG STIG Manager integration](integrations.md)
- [AutomateSTIG scanner operations](scanner-operations.md)
- [Measured Evaluate-STIG comparison protocol](evaluatestig-comparison.md)
- [Synthetic scanner workflow scenarios](../fixtures/scanner_scenarios/README.md)
