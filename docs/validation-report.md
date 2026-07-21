# AutomateSTIG Replacement Validation Report

> **Scope note (2026-07-09):** This document predates the product pivot and is retained as a historical record. AutomateSTIG no longer pursues Evaluate-STIG replacement or every-DISA-STIG coverage. The product scope is now: evidence collection and deterministic evaluation for device classes that scripted scanners cannot reach — network devices (config-file evaluation), Linux/UNIX over SSH, NetApp ONTAP and FreeBSD via evidence transcripts — with results delivered to STIG Manager. Current content posture: 35 authoritative coverage manifests over 9,977 tracked rules (9,759 automated, 94 manual, 124 unsupported after the pivot content trim). Statements below about broader replacement goals, 100% automation, or platform breadth beyond the pivot scope are superseded.

Status: **not full production replacement-ready yet**, but now grounded against official public DISA benchmark inventories for the first flagship targets.

This report is the gate for claiming that AutomateSTIG is a better full replacement for Evaluate-STIG. Claims must be tied to fixtures, coverage manifests, workflow acceptance harnesses, and release/security controls.

## Current validation evidence

- Official public DISA Cyber Exchange benchmark ZIPs are recorded in `fixtures/authorized/manifest.example.json` with SHA-256 hashes:
  - Windows Server 2022 STIG V2R8 manual XCCDF ZIP.
  - Windows Server 2022 STIG SCAP 1.3 Benchmark V2R8 ZIP.
  - RHEL 8 STIG V2R7 manual XCCDF ZIP.
  - RHEL 8 STIG SCAP 1.3 Benchmark V2R7 ZIP.
- Authoritative DISA rule-inventory coverage manifests are generated from those XCCDF fixtures:
  - `content/coverage/windows_server_2022.disa-v2r8.json`: 282 DISA rules; 60 mapped to executable AutomateSTIG checks; 222 represented as manual-review workflow items.
  - `content/coverage/rhel8.disa-v2r7.json`: 366 DISA rules; 50 mapped to executable AutomateSTIG checks; 316 represented as manual-review workflow items.
- Sanitized SCC and OpenSCAP XCCDF result fixtures parse successfully and preserve pass/fail result evidence.
- Sanitized CKL and CKLB fixtures parse successfully.
- Example coverage manifests exist for Windows Server 2022 and RHEL 8, both marked `experimental`.
- Full experimental coverage inventory manifests enumerate every rule represented in the current Windows Server 2022 and RHEL 8 check packs.
- The authorized-fixture manifest harness validates fixture existence, safe paths, and SHA-256 digests.
- The external workflow harness validates offline contract fixtures for CKL, CKLB, STIG Manager, eMASS, and DISA XCCDF ZIP readability.
- STIG Manager and eMASS golden export fixtures are regression-tested for stable payload shape.
- Release build CI emits SHA-256 checksums, cargo dependency inventory, CycloneDX SBOMs, and provenance scaffold JSON for each platform artifact.
- WinRM SOAP addressing now matches the configured HTTPS/5986 endpoint instead of hard-coding HTTP/5985.
- `.stigpack` import rejects unsafe member paths and enforces entry-count, per-member, and total-uncompressed-size limits before extraction/import.

## Still required before full replacement-ready claims

1. SCC and OpenSCAP result fixtures from representative real Windows Server 2022 and RHEL 8 systems, with redaction/provenance approved for use.
2. Real CKL/CKLB round-trip acceptance against STIG Viewer and real reviewer workflows, not only offline parse/shape checks.
3. STIG Manager and eMASS payload acceptance against actual target deployments/contracts if those integrations remain in production scope.
4. Much higher automated/check coverage or a documented, accepted manual-review workflow for the remaining authoritative DISA rules.
5. Signed release artifacts and cryptographic SLSA/in-toto attestations using a production release identity.
6. Dependency advisory resolution or formal risk acceptance for the remaining transitive `RUSTSEC-2023-0071` issue.

## First flagship targets

- Windows Server 2022
- RHEL 8

Strategic rule: **narrow and complete first; broad later.**
