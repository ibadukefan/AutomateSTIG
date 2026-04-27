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
- generated per-rule implementation backlog specs for every currently unsupported authoritative DISA rule.

Current authoritative corpus tracked in-repo:

- authoritative rules: 1,148
- mapped to existing automated checks: 111
- generated planned specs for unsupported rules: 1,037
- planned automated implementations: 951
- planned manual-evidence workflows: 86

The next burn-down phase is to replace generated planned specs with validated implementations, starting with reusable Windows and Linux collector families because they cover 950 of the 1,037 planned specs in the current corpus.

## Immediate next implementation sequence

1. Implement a Windows collector spec compiler for registry, security policy, local/group membership, audit policy, service, and file-system evidence.
2. Implement a Linux collector spec compiler for file content, permissions, package, service, sysctl, auditd, sshd, and PAM evidence.
3. Generate executable check definitions from implementation specs where collector/evaluator templates are known-safe.
4. Attach pass/fail/NA fixture requirements to every generated check.
5. Promote a rule from `planned` to `implemented` only when generated check execution passes fixtures.
6. Promote from `implemented` to `validated` only after authorized fixture and external workflow acceptance evidence exists.
