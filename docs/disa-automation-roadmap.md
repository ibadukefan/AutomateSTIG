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
- expanded seed authoritative DISA corpus for Windows Server 2022, Windows Server 2019, Windows 11, RHEL 8, and RHEL 9 manual/SCAP artifacts;
- corpus indexing/fetch/extraction/diff scripts;
- scheduled corpus freshness workflow;
- generated per-rule implementation backlog specs for every currently unsupported authoritative DISA rule;
- conservative candidate check-template extraction from authoritative DISA prose for Windows registry, Windows Feature, Linux sysctl, Linux package, and Linux file-content patterns;
- deterministic pass/fail fixture evidence for generated Windows and Linux candidate check packs;
- fixture-backed promotion of those candidates into experimental authoritative coverage without claiming live-asset production validation.

Current authoritative corpus tracked in-repo:

- authorized public DISA artifacts: 10
- authoritative rules: 2,944
- mapped automated checks after fixture-backed candidate promotion: 705
  - mapped before this expansion/promotion pass: 207
  - generated candidate checks with deterministic pass/fail fixture evidence: 451
    - registry candidates: 286
    - Windows Feature candidates: 7
    - Linux sysctl candidates: 49
    - Linux package candidates: 38
    - Linux file-content candidates: 71
- remaining unsupported authoritative rules: 2,239
- generated planned specs for remaining unsupported rules: 2,239
- planned automated implementations remaining: 2,051
- planned manual-evidence workflows: 188

The corpus grew substantially in this pass, so the absolute unsupported count increased even though fixture-backed automation also increased from 207 to 705 mapped rules. This is expected and more honest: every newly indexed authoritative DISA rule is tracked, either mapped or explicitly unsupported, and the production target remains zero unsupported rules.

The next burn-down phase is to map SCAP/OVAL machine-check content and infer/fixture-validate additional reusable Linux and Windows templates, including service state, file permissions/ownership, auditd, sshd, PAM, crypto policy, local security policy, audit policy, local users/groups, file ACLs, PowerShell, and WMI/CIM. Live-asset validation is still required before claiming any generated candidate as production validated.

## Immediate next implementation sequence

1. Implement a Windows collector spec compiler for registry, security policy, local/group membership, audit policy, service, and file-system evidence.
2. Implement a Linux collector spec compiler for file content, permissions, package, service, sysctl, auditd, sshd, and PAM evidence.
3. Map SCAP/OVAL benchmark checks as scanner-import-verifiable or directly machine-verifiable coverage where feasible.
4. Generate executable check definitions from implementation specs where collector/evaluator templates are known-safe.
5. Attach pass/fail/NA fixture requirements to every generated check.
6. Promote a rule from `planned` to `implemented` only when generated check execution passes fixtures.
7. Promote from `implemented` to `validated` only after authorized fixture and external workflow acceptance evidence exists.
