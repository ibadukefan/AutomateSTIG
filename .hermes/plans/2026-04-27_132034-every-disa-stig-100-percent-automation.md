# Every DISA STIG 100% Automation Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Turn AutomateSTIG into a continuously maintained, validation-gated replacement platform that ingests every available DISA STIG, implements 100% automated/evidence-backed handling for every authoritative DISA rule, validates live STIG Viewer/STIG Manager/eMASS workflows, and ships signed/attested production releases.

**Architecture:** Build a factory, not a one-off rule sprint. Automate authoritative DISA corpus ingestion, rule inventory generation, rule classification, implementation backlog creation, evidence collector generation, acceptance testing, and release attestation. Treat every DISA benchmark rule as a tracked product requirement with CI gates that fail on drift, missing automation, missing evidence, or stale external acceptance.

**Tech Stack:** Rust workspace, Python repository scripts, DISA Cyber Exchange ZIP/XCCDF artifacts, SCC/OpenSCAP result fixtures, CKL/CKLB parsers, STIG Manager/eMASS integrations, GitHub Actions, Sigstore/cosign, CycloneDX SBOM, GitHub artifact attestations.

---

## Reality Check and Definition of “100% Automated”

The requested target is intentionally ambitious: **every authoritative DISA STIG, every authoritative DISA rule, 100% automated**.

This is possible only if “automated” is defined precisely and defensibly:

1. **Machine-verifiable automated check** — AutomateSTIG can collect evidence from the target and determine pass/fail/not-applicable without human judgment.
2. **Automated scanner-result acceptance** — AutomateSTIG can ingest SCC/OpenSCAP/vendor scanner results and preserve authoritative evidence/provenance, but does not itself perform low-level collection.
3. **Automated workflow/evidence capture for inherently manual rules** — AutomateSTIG cannot infer the answer, but it can force structured evidence, reviewer identity, timestamps, required artifacts, and export-compatible output. These rules must be labeled “manual-evidence automated workflow,” not “machine-verifiable.”

If leadership insists on “100% machine-verifiable pass/fail for every DISA rule,” that is likely not achievable for inherently procedural/policy/interview-based controls without privileged site-specific integrations. The plan below therefore aims for **100% rule coverage with the strongest possible automation classification**, while making the final metric transparent:

- `% machine-verifiable`
- `% scanner-import-verifiable`
- `% manual-evidence workflow`
- `% not applicable with proof`
- `% unsupported` — must be zero for production claims

---

## Current Baseline

Known current repository baseline after PR #1 hardening passes:

- Current AutomateSTIG check-pack definitions: **2,215** across **100** check packs.
- Current check-pack manifests validate at 100% for existing AutomateSTIG definitions.
- Authoritative flagship DISA baselines already ingested:
  - Windows Server 2022 DISA V2R8: **282 total**, **60 automated**, **222 manual workflow**.
  - RHEL 8 DISA V2R7: **366 total**, **50 automated**, **316 manual workflow**.
- Production release pipeline now has checksum, CycloneDX SBOM, provenance scaffold, GitHub artifact attestation, and cosign keyless signing hooks.
- Live external acceptance harness exists but requires real environment variables/endpoints/credentials to exercise STIG Viewer/STIG Manager/eMASS.

---

## Success Criteria

The project can claim “every DISA STIG, 100% automated replacement-ready” only when all of these are true:

1. **Corpus completeness**
   - Every public/current DISA STIG/SCAP benchmark ZIP that AutomateSTIG claims is ingested.
   - Each artifact has source URL, retrieval date, SHA-256, version/release, benchmark ID, and authorization metadata.
   - CI fails if the upstream DISA corpus changes and manifests are stale.

2. **Rule inventory completeness**
   - Every XCCDF `Group`/`Rule` is represented in exactly one manifest entry.
   - No missing, duplicate, stale, or orphaned rules.
   - All rules have stable tracking IDs and change history.

3. **Automation completeness**
   - No rule remains `unsupported`.
   - Every rule has one of:
     - `automated_check`
     - `scanner_import_check`
     - `manual_evidence_workflow`
     - `not_applicable_with_proof`
   - Every non-machine-verifiable rule has written rationale explaining why machine verification is infeasible or unsafe.

4. **Evidence completeness**
   - Every rule has test fixtures proving pass, fail, not-applicable, and error behavior where applicable.
   - Every generated finding contains source, target, collection method, timestamp, raw evidence, normalized evidence, and evaluator version.

5. **External acceptance completeness**
   - STIG Viewer import/export acceptance is run against current CKL/CKLB outputs.
   - STIG Manager live API acceptance passes against an approved test instance.
   - eMASS live/API or approved sandbox acceptance passes.
   - CI has offline gates and scheduled/live gates with secrets stored only in GitHub protected environments.

6. **Release completeness**
   - All release binaries are signed.
   - SBOMs are generated and attached.
   - SLSA/in-toto provenance is attached.
   - Verification instructions are published and tested.
   - Release requires protected branches, protected environments, reviewer approval, and green live acceptance.

---

## Phase 0 — Program Setup and Guardrails

### Task 0.1: Create the DISA automation program charter

**Objective:** Document the product definition, exact meaning of “100% automated,” and non-negotiable honesty rules.

**Files:**
- Create: `docs/disa-100-percent-automation-charter.md`
- Modify: `docs/replacement-readiness.md`

**Steps:**
1. Write the charter with the definitions above.
2. Add a matrix defining `automated_check`, `scanner_import_check`, `manual_evidence_workflow`, `not_applicable_with_proof`, and `unsupported`.
3. State that production claims require `unsupported == 0` and all live acceptance gates green.
4. Commit:
   ```bash
   git add docs/disa-100-percent-automation-charter.md docs/replacement-readiness.md
   git commit -m "docs: define every-DISA-STIG automation charter"
   ```

### Task 0.2: Add master roadmap tracking

**Objective:** Create an auditable backlog structure for thousands of rules.

**Files:**
- Create: `docs/disa-automation-roadmap.md`
- Create: `content/disa-corpus/README.md`
- Create: `content/disa-corpus/status.json`

**Steps:**
1. Add roadmap phases and acceptance criteria.
2. Add `status.json` with high-level counts initialized from current manifests.
3. Commit:
   ```bash
   git add docs/disa-automation-roadmap.md content/disa-corpus/README.md content/disa-corpus/status.json
   git commit -m "docs: add DISA automation roadmap"
   ```

---

## Phase 1 — Full DISA Corpus Ingestion

### Task 1.1: Build a DISA download indexer

**Objective:** Discover and normalize every public DISA Cyber Exchange STIG/SCAP download.

**Files:**
- Create: `scripts/disa_corpus/index_disa_downloads.py`
- Create: `scripts/disa_corpus/tests/test_index_disa_downloads.py`
- Create: `content/disa-corpus/download-index.schema.json`

**Implementation requirements:**
- Fetch DISA download metadata from public Cyber Exchange pages/API/endpoints.
- Extract title, URL, date, category, platform, release, and artifact type.
- Normalize artifact types: `manual_stig_zip`, `scap_benchmark_zip`, `scc_content`, `supporting_documentation`, `other`.
- Do not require authentication for public corpus discovery.
- Make network fetch layer injectable for tests.

**Verification:**
```bash
python3 -m pytest scripts/disa_corpus/tests/test_index_disa_downloads.py -q
python3 scripts/disa_corpus/index_disa_downloads.py --output content/disa-corpus/download-index.json
python3 -m json.tool content/disa-corpus/download-index.json >/dev/null
```

### Task 1.2: Build authorized artifact fetcher

**Objective:** Download every selected DISA artifact into an authorized corpus cache with SHA-256 metadata.

**Files:**
- Create: `scripts/disa_corpus/fetch_authorized_artifacts.py`
- Create: `content/disa-corpus/artifacts.manifest.json`
- Modify: `fixtures/authorized/manifest.example.json` or split into `content/disa-corpus/authorized-manifest.json`

**Implementation requirements:**
- Download artifacts to `content/disa-corpus/artifacts/<sha256>/<filename>` or an external cache if files are too large for Git.
- Record source URL, retrieval timestamp, SHA-256, size, classification, authorization, and license/terms notes.
- Support `--metadata-only` mode for artifacts not committed to Git.
- Refuse path traversal and unexpected file types.

**Verification:**
```bash
python3 scripts/disa_corpus/fetch_authorized_artifacts.py --index content/disa-corpus/download-index.json --metadata-only --output content/disa-corpus/artifacts.manifest.json
python3 scripts/validate-authorized-fixtures.py content/disa-corpus/artifacts.manifest.json --repo-root .
```

### Task 1.3: Add corpus freshness CI

**Objective:** Fail or warn when DISA publishes newer artifacts than the checked-in corpus metadata.

**Files:**
- Create: `.github/workflows/disa-corpus-watch.yml`
- Create: `scripts/disa_corpus/compare_corpus_freshness.py`

**Implementation requirements:**
- Scheduled weekly run.
- PR/comment or issue creation when upstream changes.
- No automatic production claims for new artifacts until coverage manifests are regenerated and validated.

---

## Phase 2 — Universal Rule Inventory Generation

### Task 2.1: Generalize XCCDF rule inventory extraction

**Objective:** Replace target-specific DISA manifest generation with a universal XCCDF inventory engine.

**Files:**
- Modify: `scripts/generate-disa-coverage.py`
- Create: `scripts/disa_corpus/extract_xccdf_inventory.py`
- Create: `scripts/disa_corpus/tests/test_extract_xccdf_inventory.py`

**Implementation requirements:**
- Support every observed DISA XCCDF structure.
- Preserve `Group id`, `Rule id`, `Rule/version`, title, severity, CCI refs, check-content, fix text, profile refs, and metadata.
- Correctly map `Group id` as Vuln ID when present.
- Emit deterministic JSON.

**Verification:**
```bash
python3 -m pytest scripts/disa_corpus/tests/test_extract_xccdf_inventory.py -q
python3 scripts/disa_corpus/extract_xccdf_inventory.py --artifact <zip> --output /tmp/inventory.json
python3 -m json.tool /tmp/inventory.json >/dev/null
```

### Task 2.2: Generate manifests for every DISA benchmark

**Objective:** Produce one authoritative coverage manifest per benchmark/release.

**Files:**
- Create directory: `content/coverage/disa-authoritative/`
- Create: `scripts/disa_corpus/generate_all_authoritative_manifests.py`

**Implementation requirements:**
- Iterate the corpus manifest.
- Extract inventory from every SCAP/manual XCCDF artifact.
- Generate `content/coverage/disa-authoritative/<normalized_stig_id>/<version>.json`.
- Initial classification defaults to `unsupported` unless mapped to existing automation or a formal manual workflow template.
- CI should permit `unsupported` in experimental manifests but forbid it in production manifests.

**Verification:**
```bash
python3 scripts/disa_corpus/generate_all_authoritative_manifests.py --corpus content/disa-corpus/artifacts.manifest.json --out content/coverage/disa-authoritative
python3 scripts/validate-all-coverage.py --repo-root .
```

### Task 2.3: Add rule-diff engine

**Objective:** Detect added, removed, renamed, and changed DISA rules across releases.

**Files:**
- Create: `scripts/disa_corpus/diff_rule_inventory.py`
- Create: `content/disa-corpus/rule-history/README.md`

**Verification:**
```bash
python3 scripts/disa_corpus/diff_rule_inventory.py --old <old-manifest> --new <new-manifest> --output /tmp/rule-diff.json
python3 -m json.tool /tmp/rule-diff.json >/dev/null
```

---

## Phase 3 — Rule Implementation Factory

### Task 3.1: Define a universal rule implementation spec

**Objective:** Give every rule a machine-readable implementation contract.

**Files:**
- Create: `schemas/rule-implementation.schema.json`
- Create: `content/rule-implementations/README.md`
- Create directory: `content/rule-implementations/`

**Spec fields:**
- `vuln_id`
- `rule_id`
- `stig_id`
- `platform_family`
- `classification`
- `collector_type`
- `collector_commands`
- `normalizer`
- `evaluator`
- `expected_values`
- `evidence_fields`
- `na_conditions`
- `remediation`
- `fixtures`
- `external_acceptance_refs`

### Task 3.2: Build implementation mapping validator

**Objective:** Ensure every authoritative rule has a valid implementation spec.

**Files:**
- Create: `scripts/validate-rule-implementations.py`
- Modify: `.github/workflows/ci.yml`

**Verification:**
```bash
python3 scripts/validate-rule-implementations.py --coverage-root content/coverage/disa-authoritative --implementation-root content/rule-implementations
```

Production readiness requires:
- no missing implementation spec;
- no unsupported classification;
- fixture references exist;
- external acceptance references exist for release-targeted STIGs.

### Task 3.3: Create collector plugin architecture

**Objective:** Avoid custom code per rule when a reusable collector can handle families of checks.

**Files:**
- Modify: `crates/core/src/checks/`
- Create: `crates/core/src/checks/collectors/`
- Create: `crates/core/src/checks/collectors/windows.rs`
- Create: `crates/core/src/checks/collectors/linux.rs`
- Create: `crates/core/src/checks/collectors/network.rs`
- Create: `crates/core/src/checks/collectors/database.rs`
- Create: `crates/core/src/checks/collectors/cloud.rs`

**Collector families:**
- Windows registry
- Windows security policy
- Windows audit policy
- Windows service
- Windows file ACL
- Windows PowerShell/WMI/CIM
- Windows IIS/SQL/Exchange/AD/GPO
- Linux file permissions
- Linux sysctl
- Linux package/service
- Linux PAM/SSHD/auditd
- Linux crypto policy
- Network device config parsing
- Database SQL query checks
- Kubernetes/cloud API checks

### Task 3.4: Add generated tests per rule

**Objective:** Every rule implementation must have pass/fail/not-applicable/error fixtures.

**Files:**
- Create: `scripts/generate-rule-tests.py`
- Create: `crates/tests/src/generated_rule_tests.rs`
- Modify: `crates/tests/src/lib.rs`

**Verification:**
```bash
python3 scripts/generate-rule-tests.py --implementation-root content/rule-implementations --out crates/tests/src/generated_rule_tests.rs
cargo test -p automatestig-tests generated_rule_tests
```

---

## Phase 4 — Prioritized Full Automation Rollout

Even though the target is every DISA STIG first, implementation still needs batching to stay reviewable.

### Batch ordering

1. Windows Server 2022 — close 222 missing authoritative rules.
2. RHEL 8 — close 316 missing authoritative rules.
3. Windows Server 2019/2025.
4. Windows 10/11.
5. RHEL 7/9 and Oracle Linux variants.
6. Ubuntu/SLES/Debian.
7. IIS/SQL Server/Exchange/AD/Edge/Chrome/Firefox.
8. Network devices: Cisco, Juniper, Palo Alto, F5, Arista.
9. Virtualization: VMware ESXi/vCenter/Hyper-V.
10. Containers/cloud/database/application STIGs.

### Task template for each batch

**Objective:** Convert one STIG from partial to production-level 100% rule coverage.

**Files:**
- Modify: `content/coverage/disa-authoritative/<stig>/<version>.json`
- Create/modify: `content/rule-implementations/<stig>/*.json`
- Modify collectors/evaluators under `crates/core/src/checks/`
- Add fixtures under `fixtures/rules/<stig>/`
- Add integration tests under `crates/tests/src/`

**Steps:**
1. Generate missing-rule report:
   ```bash
   python3 scripts/report-missing-automation.py --manifest content/coverage/disa-authoritative/<stig>/<version>.json
   ```
2. Group missing rules by collector family.
3. Implement the most reusable collector first.
4. Add generated tests.
5. Validate manifest.
6. Run full local gates.
7. Commit one collector family at a time.

**Exit criteria per STIG:**
```bash
python3 scripts/validate-rule-implementations.py --stig <stig> --require-production
cargo test -p automatestig-tests <stig>
python3 scripts/validate-all-coverage.py --repo-root . --require-production <stig>
```

---

## Phase 5 — Live External Acceptance Infrastructure

### Task 5.1: Provision test environments

**Objective:** Obtain real systems/services for acceptance validation.

**Required environments:**
- Windows host with STIG Viewer installed or automatable import/export harness.
- STIG Manager test instance with API token.
- eMASS sandbox/test API with approved key.
- SCC/OpenSCAP scanner runners for representative targets.

**Secrets:**
- Store only in GitHub protected environments.
- Never commit credentials.
- Add redaction tests/logging guards.

### Task 5.2: Make STIG Viewer acceptance non-optional for production STIG claims

**Files:**
- Modify: `scripts/run-live-external-acceptance.py`
- Create: `.github/workflows/live-acceptance.yml`

**Requirements:**
- Import generated CKL/CKLB into STIG Viewer.
- Export it back out.
- Parse exported artifact.
- Compare rule count, status mapping, comments, severity, finding details, and evidence fields.

### Task 5.3: Make STIG Manager live acceptance non-optional

**Requirements:**
- POST generated review payloads to test STIG Manager collection.
- GET reviews back.
- Verify round-trip consistency.
- Delete test collection or isolate by run ID.

### Task 5.4: Make eMASS live/sandbox acceptance non-optional

**Requirements:**
- Submit generated POA&M/control artifact to sandbox/test endpoint.
- Validate server response schema and accepted status.
- Record response metadata without secrets.

---

## Phase 6 — Production Release and Supply Chain Hardening

### Task 6.1: Replace scaffold provenance with SLSA/in-toto provenance

**Files:**
- Modify: `.github/workflows/ci.yml`
- Create: `docs/release-verification.md`

**Requirements:**
- Generate SLSA/in-toto provenance for every release artifact.
- Attach provenance to GitHub release.
- Document verification commands.

### Task 6.2: Enforce protected release environments

**Requirements:**
- Release job runs only from tags.
- Release requires protected environment approval.
- Artifacts must pass full corpus, rule implementation, live acceptance, audit, and signing gates.

### Task 6.3: Add release verification smoke test

**Requirements:**
- Download artifact, checksum, SBOM, attestation, cosign bundle.
- Verify all of them in CI or a release validation job.

---

## Phase 7 — Metrics, Dashboards, and Drift Control

### Task 7.1: Add coverage dashboard generator

**Files:**
- Create: `scripts/generate-coverage-dashboard.py`
- Create: `docs/coverage-dashboard.md`

**Metrics:**
- total DISA STIGs tracked;
- total rules;
- machine-verifiable count;
- scanner-import count;
- manual-evidence workflow count;
- unsupported count;
- stale artifact count;
- live acceptance status per STIG;
- release attestation status.

### Task 7.2: Add CI gates by maturity level

**Maturity levels:**
- `experimental`: inventory exists, may have unsupported rules.
- `complete-inventory`: no missing rule inventory.
- `workflow-complete`: unsupported == 0, but live acceptance optional.
- `production`: unsupported == 0, evidence fixtures complete, live acceptance green, signed release green.

---

## Staffing and Effort Estimate

This is a large program. Rough order of magnitude:

- Corpus ingestion/platform: 2–4 weeks.
- Universal rule implementation framework: 4–8 weeks.
- Windows Server 2022 full production automation: 6–12 weeks.
- RHEL 8 full production automation: 6–12 weeks.
- Every major OS/application/network/cloud STIG: many additional months.
- Live acceptance environment buildout: 2–6 weeks depending access.
- Full every-DISA-STIG steady-state maintenance: ongoing team responsibility.

A realistic team:

- 1 product/security lead.
- 2–4 Rust/backend engineers.
- 2–4 platform SMEs for Windows/Linux/network/cloud/database STIGs.
- 1 DevSecOps/release engineer.
- 1 QA/validation engineer.
- Access to STIG Manager/eMASS/STIG Viewer/SCC/OpenSCAP environments.

---

## Immediate Next Implementation Sprint

If executing this plan next, start with these concrete tasks:

1. Build full DISA corpus indexer.
2. Generate authoritative manifests for all discoverable DISA benchmarks.
3. Add corpus freshness CI.
4. Add rule implementation schema and validator.
5. Produce missing-rule reports for all STIGs.
6. Start Windows Server 2022 rule-family automation until unsupported/manual counts shrink.

Recommended first sprint acceptance:

```bash
python3 scripts/disa_corpus/index_disa_downloads.py --output content/disa-corpus/download-index.json
python3 scripts/disa_corpus/fetch_authorized_artifacts.py --metadata-only --index content/disa-corpus/download-index.json --output content/disa-corpus/artifacts.manifest.json
python3 scripts/disa_corpus/generate_all_authoritative_manifests.py --corpus content/disa-corpus/artifacts.manifest.json --out content/coverage/disa-authoritative
python3 scripts/validate-all-coverage.py --repo-root .
python3 scripts/validate-rule-implementations.py --coverage-root content/coverage/disa-authoritative --implementation-root content/rule-implementations
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

---

## Risks and Mitigations

| Risk | Impact | Mitigation |
|---|---:|---|
| DISA pages/API change | Corpus ingestion breaks | Keep cached metadata, tests, and fallback/manual URL ingest |
| Some rules are not machine-verifiable | Blocks literal 100% pass/fail automation | Use explicit `manual_evidence_workflow` classification with rationale and evidence requirements |
| External acceptance requires restricted systems | Cannot prove live acceptance from public CI | Use protected self-hosted runners or scheduled environment-gated workflows |
| Rule volume is huge | Implementation takes months | Build reusable collectors and generated tests; batch by platform families |
| False positives/negatives | Product trust failure | Require pass/fail/NA fixtures and cross-check against SCC/OpenSCAP where possible |
| Release signing misuse | Supply-chain risk | Use GitHub OIDC, protected environments, cosign, attestations, and verification docs |

---

## Final Definition of Done

The “every DISA STIG, 100% automated” objective is done when:

1. The DISA corpus index includes every current public DISA benchmark artifact.
2. Every benchmark has an authoritative manifest.
3. Every manifest has `unsupported == 0`.
4. Every rule has an implementation spec and evidence fixture set.
5. Every production-targeted STIG passes generated rule tests.
6. Live STIG Viewer, STIG Manager, and eMASS acceptance is green for release artifacts.
7. Release artifacts are signed, attested, checksummed, SBOM-backed, and independently verifiable.
8. CI blocks regressions, stale corpus, missing evidence, missing acceptance, and unsigned/unattested releases.
