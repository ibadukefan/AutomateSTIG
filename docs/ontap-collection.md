# NetApp ONTAP Collection and Evaluation

AutomateSTIG evaluates NetApp ONTAP filers from read-only, plan-bound SSH evidence. ONTAP filers cannot run scanner scripts, so the workflow collects CLI state remotely and evaluates it against the DISA NetApp ONTAP DSC 9.x STIG.

The `netapp_ontap9` check pack targets DISA NetApp ONTAP DSC 9.x STIG V2R4,
which contains 29 rules. Its reviewed candidate inventory contains 22 rules:

- 15 rules automated by the `netapp_ontap9` check pack.
- 7 reviewed rules kept manual because the supported command evidence cannot
  prove the full requirement: `V-246925`, `V-246931`, `V-246932`, `V-246938`,
  `V-246940`, `V-246944`, and `V-246948`. V2R4 explicitly permits domain,
  public-key, or SAML authentication for `V-246940`; the prior domain-only
  query could therefore create a false finding and is no longer automated.

Seven additional benchmark rules are outside the current reviewed candidate
inventory and also remain `Not_Reviewed`: `V-246927`, `V-246930`, `V-246933`,
`V-246939`, `V-246945`, `V-246946`, and `V-246949`. Thus 14 of the 29 benchmark
rules require assessor review, while the governed candidate inventory is
exactly 22 reviewed/15 automated/7 manual.

## Collecting Evidence

Use one of these collection paths.

### Connected GUI Scan

On **Scan**, select a live existing STIG Manager asset with
`NetApp_ONTAP_DSC_9-x_STIG` V2R4 assigned, then select the release-bundled
`netapp_ontap9` profile. Preflight verifies the observed ONTAP 9 identity,
endpoint/host key, exact assignment, privilege, content hashes, and every
read-only command before collection.

The GUI runs the adapter's ONTAP plan through the shared fail-closed collector.
An incomplete collection persists diagnostic run state only and creates no
handoff. A complete run previews only the 15 scanner-owned rules. An identical
remote result can receive an exact-no-op receipt; any create or update uses the
selected-run handoff. Manual and out-of-profile STIG Manager reviews remain
untouched.

### Air-Gapped Transcript

From any host with SSH access to the cluster management LIF, run:

```bash
AUTOMATESTIG_SSH_PASSWORD='...' \
  scripts/collectors/ontap-collect.sh admin@filer filer-evidence.json
```

For key authentication, set `AUTOMATESTIG_SSH_KEY` to the private-key path instead. The shell script is only a thin wrapper around `automatestig collect`; it does not implement a second SSH/error-handling path. Transfer `filer-evidence.json` into the AutomateSTIG environment.

One read-only command requires ONTAP advanced privilege:

- `security config show`

The collector wraps those commands with:

```text
set -privilege advanced -confirmations off -stop-on-error true
```

Evidence is strict JSON with schema identifier `automatestig-evidence/v2`; see `schemas/evidence-v2.schema.json`. It separates stdout, stderr, exit status, duration, and typed error for every command and records the platform, exact collection-plan digest, collector version, and observed SSH server-key fingerprint. Target-controlled output cannot create command records.

The evaluator rejects duplicate records, incomplete JSON, missing statuses, an unexpected command, a different platform, and a stale plan digest. Marker-based plain-text evidence is rejected by the product CLI, GUI, and API with no unsafe override.

If automated collection is unavailable, record the needed evidence for manual review rather than manufacturing a successful v2 transport record.

## Evaluating

The scanner GUI uses its release-bundled exact benchmark subset. The following
raw-content import is a legacy CLI/maintainer transition path, not a normal GUI
prerequisite:

```bash
automatestig disa-import --input U_NetApp_ONTAP_DSC_9-x_V2R4_STIG.zip
```

Then evaluate the evidence document:

```bash
automatestig evaluate \
  --stig NetApp_ONTAP_DSC_9-x_STIG \
  --evidence filer-evidence.json \
  --output filer.scanner-result.json
```

The scanner-first delivery path does not merge answer files or prior checklists.
Human determinations and manual-rule completion occur in STIG Manager. The
native scanner-result JSON retains the exact evaluation and provenance. A
complete result may also be projected to CKLB explicitly; incomplete evidence
cannot produce a checklist projection.

If any required record failed collection or semantic validation, AutomateSTIG appends an `evaluation.incomplete` audit event, writes no checklist, and exits nonzero. Answer files and prior-checklist merges cannot override affected `Not_Reviewed` collection errors; failed stdout is diagnostic only and cannot satisfy `not_contains` or a broad regex.

## ONTAP Semantic Validation

ONTAP can report a CLI failure in text even when SSH returns status zero. AutomateSTIG rejects anchored `Error:` output before evaluation. Structured session-limit, audit-guarantee, NTP-authentication, and admin password-policy checks require canonical headers, a terminal `N entries were displayed` summary, and an exact match between that summary and every parsed row. Pagination, truncation, unknown values, and malformed rows become collection errors. Multirow predicates evaluate the least-compliant row rather than accepting one compliant row.

Rules whose current command output cannot prove the complete requirement remain manual. This includes remote receipt of account audit events, every-role lockout policy, the complete mandatory banner, timezone mapping, backup-on-change behavior, and every non-domain administrator authentication method. A matching fragment or stale artifact is not promoted to `NotAFinding`.

The `netapp_ontap9` check pack matches canonical ONTAP 9 CLI output. Unusual or truncated table layouts become `Not_Reviewed` rather than a pass. The pack is marked experimental; verify initial results against the manual STIG.

Manual-review rules always appear as `Not_Reviewed`.

## Chain of Custody

Every completed checklist evaluated from an evidence document records the SHA-256 of the exact input bytes in each finding's comments (`Supplied evidence provenance ... SHA-256: <hex>`). A reviewer can independently confirm the artifact with `sha256sum filer-evidence.json` (or `shasum -a 256`). Evidence v2 additionally binds each record to the requested command and the complete document to the installed collection plan and observed SSH server key.
