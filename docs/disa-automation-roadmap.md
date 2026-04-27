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
- initial authoritative DISA manifests for Windows Server 2022 and RHEL 8 manual/SCAP artifacts;
- corpus indexing/fetch/extraction/diff scripts;
- scheduled corpus freshness workflow;
- generated per-rule implementation backlog specs for every currently unsupported authoritative DISA rule;
- conservative candidate check-template extraction from authoritative DISA prose for registry and Windows Feature patterns;
- deterministic pass/fail fixture evidence for the first Windows Server candidate check pack;
- fixture-backed promotion of those candidates into experimental authoritative coverage without claiming live-asset production validation.

Current authoritative corpus tracked in-repo:

- authoritative rules: 1,148
- mapped automated checks after fixture-backed candidate promotion: 207
  - existing automated checks: 111
  - generated Windows Server candidate checks with deterministic pass/fail fixture evidence: 96
- remaining unsupported authoritative rules: 941
- generated planned specs for remaining unsupported rules: 941
- planned automated implementations remaining: 855
- planned manual-evidence workflows: 86
- candidate executable checks promoted to `implemented` with fixture evidence: 96
  - registry candidates: 94
  - Windows Feature candidates: 2

The next burn-down phase is to infer and fixture-validate additional reusable templates, starting with Linux/RHEL sysctl, package, service, file-content, auditd, sshd, and PAM patterns, while adding live-asset validation before claiming any candidate as production validated. Reusable Windows and Linux collector families remain the high-leverage implementation path because they cover most remaining planned specs in the current corpus.

## Immediate next implementation sequence

1. Implement a Windows collector spec compiler for registry, security policy, local/group membership, audit policy, service, and file-system evidence.
2. Implement a Linux collector spec compiler for file content, permissions, package, service, sysctl, auditd, sshd, and PAM evidence.
3. Generate executable check definitions from implementation specs where collector/evaluator templates are known-safe.
4. Attach pass/fail/NA fixture requirements to every generated check.
5. Promote a rule from `planned` to `implemented` only when generated check execution passes fixtures.
6. Promote from `implemented` to `validated` only after authorized fixture and external workflow acceptance evidence exists.
