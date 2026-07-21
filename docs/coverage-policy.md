# STIG Coverage Policy

> **Scope note (2026-07-09):** This document predates the product pivot and is retained as a historical record. AutomateSTIG no longer pursues Evaluate-STIG replacement or every-DISA-STIG coverage. The product scope is now: evidence collection and deterministic evaluation for device classes that scripted scanners cannot reach — network devices (config-file evaluation), Linux/UNIX over SSH, NetApp ONTAP and FreeBSD via evidence transcripts — with results delivered to STIG Manager. Current content posture: 35 authoritative coverage manifests over 9,977 tracked rules (9,759 automated, 94 manual, 124 unsupported after the pivot content trim). Statements below about broader replacement goals, 100% automation, or platform breadth beyond the pivot scope are superseded.

AutomateSTIG must not advertise a STIG/platform as comprehensive unless every DISA rule for that release is represented in a coverage manifest.

## Rule Classification

Every rule in a supported STIG must be classified as one of:

- `automated` — AutomateSTIG executes a check and records evidence.
- `scanner_import` — AutomateSTIG maps an external scanner result such as SCC/OpenSCAP/ACAS.
- `manual` — Human review is required; the manifest explains why.
- `not_applicable` — Always not applicable for the supported platform profile; reason required.
- `unsupported` — Known gap; reason and tracking issue required.

## Supported vs Experimental

A check pack is **supported** only when:

1. The coverage manifest lists the DISA STIG release and every rule.
2. Every `automated` entry references an existing check definition.
3. Every manual/NA/unsupported entry includes a reason.
4. Fixture or unit tests validate the important status mappings.
5. CI runs the coverage validator.

A check pack without this proof is **experimental** even if it contains useful checks.

## Validation Command

Coverage manifests are validated with:

```bash
automatestig coverage validate --manifest content/coverage/<manifest>.json
```

The validator fails closed for internal inconsistencies, duplicate rule IDs, missing reasons, missing automation metadata, unsupported entries without `tracking_issue`, and automated/scanner-import entries that lack validation evidence references.

## Evidence Requirement

Automated checks must record evidence sufficient for an auditor to understand the result:

- check ID
- target asset
- source type
- command/query/file/registry path used
- expected value
- actual value
- timestamp
- normalized evidence summary

## Release Claims

Allowed:

> AutomateSTIG has validated replacement-ready support for Windows Server 2022 STIG VxRy and RHEL 8 STIG VxRy.

Not allowed without proof:

> AutomateSTIG comprehensively supports Windows, Linux, ACAS, SCC, and all DISA STIGs.
