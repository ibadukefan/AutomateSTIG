# DISA 100% Automation Roadmap

> **Scope note (2026-07-09):** This document predates the product pivot and is retained as a historical record. AutomateSTIG no longer pursues Evaluate-STIG replacement or every-DISA-STIG coverage. The product scope is now: evidence collection and deterministic evaluation for device classes that scripted scanners cannot reach — network devices (config-file evaluation), Linux/UNIX over SSH, NetApp ONTAP and FreeBSD via evidence transcripts — with results delivered to STIG Manager. Current content posture: 35 authoritative coverage manifests over 9,977 tracked rules (9,759 automated, 94 manual, 124 unsupported after the pivot content trim). Statements below about broader replacement goals, 100% automation, or platform breadth beyond the pivot scope are superseded.

This roadmap implements the factory required to pursue every-DISA-STIG coverage.

## Milestones

1. **Corpus ingestion** — discover/fetch/record every public DISA STIG/SCAP artifact.
2. **Authoritative inventory** — extract every XCCDF rule into deterministic manifests.
3. **Implementation contracts** — require a rule implementation spec for every rule.
4. **Collector expansion** — add reusable collectors by platform family.
5. **Fixture validation** — pass/fail/NA/error fixtures for every machine-verifiable rule.
6. **External acceptance** — live STIG Viewer, STIG Manager, and eMASS validation.
7. **Production release** — signed, attested, SBOM-backed releases with verification docs.

## Current status

Completed factory layers:

- current check-pack coverage gates for all existing AutomateSTIG check packs;
- expanded seed authoritative DISA corpus for Windows 10, Windows 11, Windows Server 2019, Windows Server 2022, Windows Server 2025, RHEL 7, RHEL 8, RHEL 9, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04, Oracle Linux 8, Oracle Linux 9, SUSE Linux Enterprise Server 15, Google Chrome, Mozilla Firefox, Microsoft Edge, Adobe Acrobat Pro/Reader DC Continuous Track, Cisco NX-OS Switch, Apache Server 2.4 Windows, Apache Tomcat Application Server 9, Apple macOS 15, Microsoft SQL Server 2022, Microsoft IIS 10.0, Microsoft Office 365 ProPlus, Kubernetes, Crunchy Data PostgreSQL, Oracle Database 19c, and VMware vSphere artifacts;
- corpus indexing/fetch/extraction/diff scripts;
- scheduled corpus freshness workflow;
- generated per-rule implementation backlog specs for every currently unsupported authoritative DISA rule;
- conservative candidate check-template extraction from authoritative DISA prose for Windows registry, Windows Feature, Chrome/Windows registry policy, Linux sysctl, Linux package, Linux file-content, Linux service-state, and Linux file-permission patterns;
- deterministic pass/fail fixture evidence for generated Windows, Chrome policy, and Linux candidate check packs;
- canonical SCAP/manual Vuln ID alignment so SCAP XCCDF IDs such as `xccdf_mil.disa.stig_group_V-230239` map back to fixture-backed generated candidates for `V-230239` instead of remaining artificially unsupported;
- fixture-backed promotion of those candidates into experimental authoritative coverage without claiming live-asset production validation.

Current authoritative corpus tracked in-repo:

- authorized public DISA artifacts: 52
- authoritative coverage manifests: 52
- authoritative rules: 8,547
- mapped automated checks after fixture-backed candidate and SCAP/manual canonical promotion: 2,866
  - mapped before Linux/corpus expansion: 207
  - mapped before SCAP/manual canonical alignment and Windows 10/RHEL 7 expansion: 705
  - mapped before Ubuntu/Oracle Linux/Chrome expansion and Linux service/file-permission templates: 1,794
  - mapped before Chrome registry-policy inference: 2,159
  - mapped before Ubuntu 22.04/Oracle Linux 9/Microsoft Edge corpus expansion: 2,194
  - mapped before Cisco NX-OS/Apache/macOS corpus expansion: 2,559
  - mapped before Windows Server 2025/SQL Server/IIS/Office corpus expansion: 2,578
  - mapped before Firefox/Adobe/SUSE corpus expansion: 2,607
  - mapped before Kubernetes/PostgreSQL/Oracle DB/VMware corpus expansion: 2,780
  - generated candidate checks with deterministic pass/fail fixture evidence: 974
- remaining unsupported authoritative rules: 5,681
- generated planned specs for remaining unsupported rules: 5,681

The corpus grew from 46 to 52 authorized public DISA artifacts and from 8,077 to 8,547 authoritative rules in this expansion pass by adding Kubernetes V2R6 manual/V2R4 SCAP, Crunchy Data PostgreSQL V3R1, Oracle Database 19c V1R5, VMware vSphere 8.0 Y25M07, and VMware vSphere 7.0 Y25M04 artifacts. Fixture-backed candidate promotion increased mapped/automated rules from 2,780 to 2,866, while unsupported rules increased to 5,681 because the authoritative corpus is larger. This is still not production-complete or all-DISA complete. The production target remains zero unsupported rules across the full tracked public DISA corpus, with every rule classified as machine-verifiable automated, scanner-import-verifiable, automated manual-evidence workflow, or not-applicable-with-proof.

The next burn-down phase is to deepen SCAP/OVAL semantics and infer/fixture-validate additional reusable Linux, Windows, browser, and application templates, including auditd, sshd, PAM, crypto policy, kernel arguments, local security policy, audit policy, local users/groups, file ACLs, PowerShell, WMI/CIM, browser policy registry/plist/json sources, and application configuration collectors. Live-asset validation is still required before claiming any generated candidate as production validated.

## Immediate next implementation sequence

1. Implement a Windows collector spec compiler for registry, security policy, local/group membership, audit policy, service, and file-system evidence.
2. Implement a Linux collector spec compiler for file content, permissions, package, service, sysctl, auditd, sshd, and PAM evidence.
3. Expand SCAP/OVAL handling from canonical Vuln ID mapping into scanner-import-verifiable OVAL semantic extraction.
4. Add browser/application policy collectors for Chrome and similar non-OS STIGs.
5. Generate executable check definitions from implementation specs where collector/evaluator templates are known-safe.
6. Attach pass/fail/NA fixture requirements to every generated check.
7. Promote a rule from `planned` to `implemented` only when generated check execution passes fixtures.
8. Promote from `implemented` to `validated` only after authorized fixture and external workflow acceptance evidence exists.
