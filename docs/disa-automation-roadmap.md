# DISA 100% Automation Roadmap

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
- expanded seed authoritative DISA corpus for Windows 10, Windows 11, Windows Server 2019, Windows Server 2022, RHEL 7, RHEL 8, RHEL 9, Ubuntu 20.04, Ubuntu 24.04, Oracle Linux 8, and Google Chrome manual/SCAP artifacts;
- corpus indexing/fetch/extraction/diff scripts;
- scheduled corpus freshness workflow;
- generated per-rule implementation backlog specs for every currently unsupported authoritative DISA rule;
- conservative candidate check-template extraction from authoritative DISA prose for Windows registry, Windows Feature, Chrome/Windows registry policy, Linux sysctl, Linux package, Linux file-content, Linux service-state, and Linux file-permission patterns;
- deterministic pass/fail fixture evidence for generated Windows, Chrome policy, and Linux candidate check packs;
- canonical SCAP/manual Vuln ID alignment so SCAP XCCDF IDs such as `xccdf_mil.disa.stig_group_V-230239` map back to fixture-backed generated candidates for `V-230239` instead of remaining artificially unsupported;
- fixture-backed promotion of those candidates into experimental authoritative coverage without claiming live-asset production validation.

Current authoritative corpus tracked in-repo:

- authorized public DISA artifacts: 22
- authoritative coverage manifests: 22
- authoritative rules: 5,206
- mapped automated checks after fixture-backed candidate and SCAP/manual canonical promotion: 2,194
  - mapped before Linux/corpus expansion: 207
  - mapped before SCAP/manual canonical alignment and Windows 10/RHEL 7 expansion: 705
  - mapped before Ubuntu/Oracle Linux/Chrome expansion and Linux service/file-permission templates: 1,794
  - mapped before Chrome registry-policy inference: 2,159
  - generated candidate checks with deterministic pass/fail fixture evidence: 765
- remaining unsupported authoritative rules: 3,012
- generated planned specs for remaining unsupported rules: 3,012

The corpus grew from 14 to 22 authorized public DISA artifacts and from 3,828 to 5,206 authoritative rules in the prior expansion pass. Linux service-state/file-permission templates and Ubuntu/Oracle Linux/Chrome corpus coverage moved mapped/automated rules from 1,794 to 2,159. This pass adds conservative Chrome/Windows registry-policy inference for STIG prose that provides a concrete `regedit` path, value name, and expected value, moving mapped/automated rules to 2,194 and reducing unsupported rules to 3,012. This is still not production-complete or all-DISA complete. The production target remains zero unsupported rules across the full tracked public DISA corpus, with every rule classified as machine-verifiable automated, scanner-import-verifiable, automated manual-evidence workflow, or not-applicable-with-proof.

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
