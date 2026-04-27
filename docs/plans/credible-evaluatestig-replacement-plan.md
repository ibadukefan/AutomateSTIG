# AutomateSTIG Credible Evaluate-STIG Replacement Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Turn AutomateSTIG from a promising STIG automation framework into a credible, production-grade, better-than-Evaluate-STIG replacement.

**Architecture:** Keep the existing Rust workspace, but shift the product from broad/shallow feature coverage to validated end-to-end parity: real DISA content, real SCC/OpenSCAP/ACAS artifacts, complete platform check packs, secure local/enterprise modes, reproducible CI, and evidence-rich checklist generation. The replacement claim is credible only when AutomateSTIG can ingest the same inputs Evaluate-STIG users rely on, produce equal-or-better CKL/CKLB/STIG Manager outputs, preserve evidence, and prove correctness against fixtures.

**Tech Stack:** Rust workspace, SQLite, Axum GUI/API, embedded JS frontend, CKL/CKLB/XCCDF/STIGPACK parsers, GitHub Actions, real-world fixture corpus, golden-file regression tests.

---

## Definition of Done: “Credible Full Replacement”

AutomateSTIG is a credible full Evaluate-STIG replacement only when all of these are true:

1. **Input parity:** It can ingest real-world DISA XCCDF ZIPs, SCC XCCDF results, OpenSCAP results, CKL, CKLB, Cisco/config dumps, and ACAS/Nessus results if ACAS support is claimed.
2. **Output parity:** It can produce CKL and CKLB accepted by STIG Viewer/STIG Manager, plus STIG Manager-ready API payloads with correct result engine metadata.
3. **Coverage parity:** For each advertised platform, every DISA rule is classified as automated, manual, not applicable, external-tool-derived, or unsupported-with-reason. No platform is advertised as comprehensive without rule-by-rule coverage proof.
4. **Evidence parity:** Each automated finding includes source, command/query/check ID, raw evidence or normalized evidence, timestamp, target, and deterministic status mapping.
5. **Security readiness:** Desktop-local mode is safe by default; hosted/enterprise mode requires explicit secure configuration. No fixed demo auth, plaintext credential fallback, unsafe path writes, or default plaintext WinRM credentials.
6. **Regression proof:** CI validates fixtures, golden outputs, tests, formatting, clippy, frontend syntax, and dependency/security checks.
7. **Operational trust:** Docs distinguish production-supported features from experimental ones, include hardening guidance, and publish a supported-platform coverage matrix.

---

## Phase 0 — Reposition the Product Around Proof, Not Claims

### Task 0.1: Create a Replacement Readiness Matrix

**Objective:** Create the canonical matrix used to decide what AutomateSTIG can honestly claim.

**Files:**
- Create: `docs/replacement-readiness.md`
- Modify: `README.md`
- Modify: `docs/website/index.html`

**Implementation:**
Create a matrix with columns:

| Capability | Required for Evaluate-STIG Replacement | Current Status | Proof Artifact | Owner | Release Target |
|---|---|---|---|---|---|
| CKL parse/write | Yes | Present | parser tests + STIG Viewer import test | TBD | v0.2 |
| CKLB parse/write | Yes | Present | parser tests + STIG Viewer import test | TBD | v0.2 |
| SCC XCCDF result import | Yes | Partial | fixture corpus test | TBD | v0.3 |
| ACAS/Nessus import | If claimed | Missing/unknown | `.nessus` fixture test | TBD | v0.4 |
| Windows Server 2022 full STIG | Yes for advertised support | Partial | rule coverage manifest | TBD | v0.5 |

**Verification:**
- Run: `cargo test --workspace`
- Manually verify README no longer claims comprehensive replacement for unproven areas.

**Commit:**
```bash
git add README.md docs/website/index.html docs/replacement-readiness.md
git commit -m "docs: add Evaluate-STIG replacement readiness matrix"
```

### Task 0.2: Add a Supported Coverage Policy

**Objective:** Prevent future overclaiming by requiring rule-by-rule support declarations.

**Files:**
- Create: `docs/coverage-policy.md`
- Create: `schemas/coverage-manifest.schema.json`
- Create: `content/coverage/README.md`

**Coverage manifest shape:**
```json
{
  "stig_id": "Windows_Server_2022_STIG",
  "version": "V2R4",
  "source": "DISA",
  "total_rules": 310,
  "rules": [
    {
      "vuln_id": "V-254239",
      "rule_id": "SV-254239r958478_rule",
      "status": "automated",
      "check_pack": "content/check_packs/windows_server_2022.json",
      "check_id": "windows_server_2022/V-254239",
      "evidence_required": true,
      "notes": "Registry policy check. Validated against fixture ws2022-gpo-baseline-01."
    }
  ]
}
```

**Verification:**
- Validate schema with a sample manifest.
- CI later must reject check packs without coverage manifests.

**Commit:**
```bash
git add docs/coverage-policy.md schemas/coverage-manifest.schema.json content/coverage/README.md
git commit -m "docs: define STIG coverage support policy"
```

---

## Phase 1 — Fix Safety and Trust Blockers First

These are non-negotiable because a better Evaluate-STIG replacement must be safe to run in DoD-like environments.

### Task 1.1: Remove Insecure PORT-Based Demo Mode

**Objective:** Stop treating `PORT` as a signal to expose insecure demo mode.

**Files:**
- Modify: `crates/gui/src/main.rs`
- Test: `crates/gui/src/main.rs` or new `crates/gui/src/config.rs`

**Required behavior:**
- `PORT` only controls port.
- `AUTOMATESTIG_BIND=0.0.0.0:8080` or `--bind` controls bind address.
- `AUTOMATESTIG_DEMO=1` explicitly enables demo data.
- Demo mode must still require a random or configured auth token.
- If binding to non-localhost without `AUTOMATESTIG_AUTH_TOKEN`, fail startup with a clear error.

**Verification:**
```bash
cargo test -p automatestig-gui
PORT=8080 cargo run --bin automatestig-gui
# Expected: binds safely, no fixed demo token.
```

**Commit:**
```bash
git add crates/gui/src/main.rs
git commit -m "security: remove insecure port-based demo mode"
```

### Task 1.2: Add Central Safe Path Utilities

**Objective:** Prevent path traversal from benchmark IDs, answer file names, uploads, and extracted content.

**Files:**
- Create: `crates/core/src/path_safety.rs`
- Modify: `crates/core/src/lib.rs`
- Modify: `crates/core/src/library.rs`
- Modify: `crates/gui/src/api.rs`
- Tests: `crates/core/src/path_safety.rs`

**API:**
```rust
pub fn safe_filename(input: &str) -> Result<String>;
pub fn safe_join_under(base: &Path, child: &str) -> Result<PathBuf>;
pub fn ensure_under_base(base: &Path, candidate: &Path) -> Result<()>;
```

**Rules:**
- Reject empty strings.
- Reject `/`, `\`, `..`, absolute paths, NUL/control chars.
- Allow `[A-Za-z0-9._-]`.
- Convert spaces to `_` only after validation or normalization.
- Canonical containment check for existing parents.

**Verification:**
```bash
cargo test -p automatestig-core path_safety
cargo test --workspace
```

**Commit:**
```bash
git add crates/core/src/path_safety.rs crates/core/src/lib.rs crates/core/src/library.rs crates/gui/src/api.rs
git commit -m "security: add safe path handling for library writes"
```

### Task 1.3: Harden WinRM Defaults

**Objective:** Prevent accidental plaintext Windows credential transmission.

**Files:**
- Modify: `crates/gui/src/winrm.rs`
- Modify: `crates/gui/src/api.rs`
- Modify: frontend WinRM form in `crates/gui/frontend/app.js`
- Tests: `crates/gui/src/winrm.rs`

**Required behavior:**
- Default port: `5986`.
- Default `use_https`: `true`.
- Default `verify_tls`: `true`.
- HTTP/5985 requires explicit `allow_insecure=true` and warning evidence in audit log.
- SOAP `<wsa:To>` must match actual scheme/host/port.

**Verification:**
```bash
cargo test -p automatestig-gui winrm
```

**Commit:**
```bash
git add crates/gui/src/winrm.rs crates/gui/src/api.rs crates/gui/frontend/app.js
git commit -m "security: default WinRM scans to verified HTTPS"
```

### Task 1.4: Make SSH Host Key Verification Strict by Default

**Objective:** Replace default trust-on-first-use with explicit trust decisions.

**Files:**
- Modify: `crates/gui/src/ssh.rs`
- Modify: `crates/gui/src/api.rs`
- Modify: `crates/gui/frontend/app.js`
- Tests: `crates/gui/src/ssh.rs`

**Required behavior:**
- Unknown host keys fail by default.
- API can return fingerprint for user approval.
- Explicit `accept_unknown_host_key=true` is required to TOFU.
- Known-host mismatch always fails unless a specific replace workflow is used.

**Verification:**
```bash
cargo test -p automatestig-gui ssh
```

**Commit:**
```bash
git add crates/gui/src/ssh.rs crates/gui/src/api.rs crates/gui/frontend/app.js
git commit -m "security: require explicit SSH host key trust"
```

### Task 1.5: Remove Plaintext Credential Fallback

**Objective:** Ensure credential vault failures are loud and safe.

**Files:**
- Modify: `crates/gui/src/secrets.rs`
- Modify: `crates/gui/src/api.rs`
- Tests: `crates/gui/src/secrets.rs`

**Required behavior:**
- Encryption failure returns error.
- No fallback to plaintext JSON.
- Existing plaintext vaults trigger migration warning and require explicit user confirmation.
- Add storage marker: `vault_format: encrypted-v1`.

**Verification:**
```bash
cargo test -p automatestig-gui secrets
```

**Commit:**
```bash
git add crates/gui/src/secrets.rs crates/gui/src/api.rs
git commit -m "security: remove plaintext credential vault fallback"
```

### Task 1.6: Require Trusted Signatures for Production Stigpack Imports

**Objective:** Make signed-content claims true by default.

**Files:**
- Modify: `crates/stigpack/src/importer.rs`
- Modify: `crates/stigpack/src/verifier.rs`
- Modify: `crates/cli/src/commands/import.rs`
- Modify: GUI stigpack import handler in `crates/gui/src/api.rs`
- Tests: `crates/stigpack/src/importer.rs`

**Required behavior:**
- Default import requires trusted signature.
- `--allow-unsigned` is available for lab/dev use and emits a warning.
- GUI import must require explicit checkbox for unsigned imports.

**Verification:**
```bash
cargo test -p automatestig-stigpack
cargo run --bin automatestig -- import --pack unsigned.stigpack
# Expected: fails unless --allow-unsigned is passed.
```

**Commit:**
```bash
git add crates/stigpack/src/importer.rs crates/stigpack/src/verifier.rs crates/cli/src/commands/import.rs crates/gui/src/api.rs
git commit -m "security: require trusted stigpack signatures by default"
```

---

## Phase 2 — Establish CI and Quality Gates

### Task 2.1: Add Mandatory GitHub Actions CI

**Objective:** Ensure every PR proves the project builds, tests, formats, and lints.

**Files:**
- Create/replace: `.github/workflows/ci.yml`

**Jobs:**
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- `node --check crates/gui/frontend/app.js`
- `cargo deny check` or `cargo audit` if feasible

**Verification:**
```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
node --check crates/gui/frontend/app.js
```

**Commit:**
```bash
git add .github/workflows/ci.yml
git commit -m "ci: enforce tests formatting lint and frontend checks"
```

### Task 2.2: Fix Existing Formatting and Clippy Failures

**Objective:** Make quality gates pass locally before deeper feature work.

**Files:**
- Modify: all files touched by `cargo fmt`
- Modify: `crates/core/src/checks/executor.rs`

**Verification:**
```bash
cargo fmt --all
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

**Commit:**
```bash
git add .
git commit -m "chore: format codebase and satisfy clippy"
```

---

## Phase 3 — Build the Real-World Fixture Corpus

### Task 3.1: Create Fixture Directory and Metadata Format

**Objective:** Add a repeatable way to test against real-world STIG artifacts without exposing sensitive data.

**Files:**
- Create: `fixtures/README.md`
- Create: `fixtures/manifest.schema.json`
- Create: `fixtures/sanitized/README.md`
- Create: `crates/tests/src/fixtures.rs`

**Fixture metadata shape:**
```json
{
  "id": "scc-rhel8-sample-001",
  "type": "scc_xccdf_result",
  "source_tool": "SCC",
  "source_tool_version": "5.x",
  "stig_id": "RHEL_8_STIG",
  "classification": "sanitized-public",
  "expected": {
    "rules_total": 300,
    "mapped_results_minimum": 250,
    "statuses": {
      "open": 10,
      "not_a_finding": 200,
      "not_reviewed": 40
    }
  }
}
```

**Verification:**
```bash
cargo test -p automatestig-tests fixtures
```

**Commit:**
```bash
git add fixtures crates/tests/src/fixtures.rs
git commit -m "test: add sanitized fixture corpus framework"
```

### Task 3.2: Add Golden Roundtrip Tests for CKL and CKLB

**Objective:** Prove generated checklists are accepted and stable.

**Files:**
- Add sanitized fixtures under `fixtures/sanitized/ckl/`
- Add sanitized fixtures under `fixtures/sanitized/cklb/`
- Modify: `crates/tests/src/lib.rs`
- Create: `crates/tests/src/golden.rs`

**Tests:**
- Parse CKL -> internal model -> write CKL -> parse again -> compare canonical model.
- Parse CKLB -> internal model -> write CKLB -> parse again -> compare canonical model.
- CKL -> CKLB -> JSON -> CKL roundtrip preserves vuln IDs, statuses, comments, finding details, severity, CCI refs.

**Verification:**
```bash
cargo test -p automatestig-tests golden_ckl
cargo test -p automatestig-tests golden_cklb
```

**Commit:**
```bash
git add fixtures/sanitized crates/tests/src/golden.rs crates/tests/src/lib.rs
git commit -m "test: add CKL and CKLB golden roundtrip fixtures"
```

### Task 3.3: Add SCC/OpenSCAP XCCDF Result Fixtures

**Objective:** Prove scanner-result import works on real artifacts.

**Files:**
- Add sanitized fixtures under `fixtures/sanitized/xccdf-results/`
- Modify: `crates/parsers/src/xccdf.rs`
- Modify: `crates/tests/src/golden.rs`

**Tests:**
- SCC result imports target hostname.
- SCC result imports benchmark/profile metadata.
- Each `rule-result` maps to correct vuln/rule ID.
- Status translations are deterministic.
- Evidence/details are preserved where available.

**Verification:**
```bash
cargo test -p automatestig-parsers xccdf
cargo test -p automatestig-tests scc_xccdf
```

**Commit:**
```bash
git add fixtures/sanitized/xccdf-results crates/parsers/src/xccdf.rs crates/tests/src/golden.rs
git commit -m "test: validate SCC and OpenSCAP XCCDF result imports"
```

### Task 3.4: Add ACAS/Nessus Import Only If It Will Be Claimed

**Objective:** Either implement ACAS/Nessus support or remove the claim.

**Files if implementing:**
- Create: `crates/parsers/src/nessus.rs`
- Modify: `crates/parsers/src/lib.rs`
- Modify: `crates/cli/src/commands/evaluate.rs`
- Modify: `crates/gui/src/api.rs`
- Add fixtures: `fixtures/sanitized/acas/`

**Files if not implementing now:**
- Modify: `README.md`
- Modify: `docs/website/index.html`
- Modify: `docs/replacement-readiness.md`

**Required decision:**
- Do not claim ACAS support until `.nessus` or ACAS-specific fixture tests pass.

**Verification:**
```bash
cargo test --workspace
rg -n "ACAS|Tenable|Nessus" README.md docs/website/index.html docs/replacement-readiness.md
```

**Commit:**
```bash
git add .
git commit -m "feat: add validated ACAS import support"
# or
git commit -m "docs: mark ACAS import as planned until validated"
```

---

## Phase 4 — Create an Evidence-Rich Evaluation Model

### Task 4.1: Add First-Class Evidence Objects

**Objective:** Every automated status must carry inspectable evidence.

**Files:**
- Modify: `crates/core/src/models/finding.rs`
- Modify: `crates/core/src/checks/mod.rs`
- Modify: `crates/core/src/checks/executor.rs`
- Modify: `crates/parsers/src/xccdf.rs`
- Tests: `crates/core/src/checks/executor.rs`

**Evidence model:**
```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Evidence {
    pub source_type: EvidenceSourceType,
    pub source_id: String,
    pub collected_at: DateTime<Utc>,
    pub target: String,
    pub command_or_query: Option<String>,
    pub expected: serde_json::Value,
    pub actual: serde_json::Value,
    pub raw: Option<String>,
    pub normalized: Option<String>,
}
```

**Verification:**
```bash
cargo test -p automatestig-core evidence
cargo test --workspace
```

**Commit:**
```bash
git add crates/core/src/models/finding.rs crates/core/src/checks crates/parsers/src/xccdf.rs
git commit -m "feat: add structured evidence to automated findings"
```

### Task 4.2: Preserve Evidence in CKL/CKLB/STIG Manager Export

**Objective:** Ensure evidence appears where reviewers and STIG Manager can see it.

**Files:**
- Modify: `crates/parsers/src/ckl.rs`
- Modify: `crates/parsers/src/cklb.rs`
- Modify: `crates/integrations/src/stig_manager.rs`
- Tests: `crates/tests/src/golden.rs`

**Required behavior:**
- CKL `FINDING_DETAILS` includes normalized evidence summary.
- CKL `COMMENTS` includes source/check metadata if appropriate.
- CKLB equivalent fields preserve evidence.
- STIG Manager result includes result engine metadata and detail fields.

**Verification:**
```bash
cargo test -p automatestig-tests golden_evidence_export
```

**Commit:**
```bash
git add crates/parsers/src/ckl.rs crates/parsers/src/cklb.rs crates/integrations/src/stig_manager.rs crates/tests/src/golden.rs
git commit -m "feat: export structured evidence to checklist formats"
```

---

## Phase 5 — Replace Broad/Shallow Check Packs With Complete Supported Platforms

### Supported-platform strategy

Do not try to be comprehensive for 100 platforms immediately. To be credible, AutomateSTIG needs a small number of complete, validated platforms before many superficial ones.

**Initial supported platforms:**
1. Windows Server 2022
2. Windows Server 2019
3. Windows 10 or Windows 11
4. RHEL 8
5. RHEL 9
6. Ubuntu 22.04
7. Cisco IOS/NX-OS only if network-device parity matters immediately

Everything else should be labeled **experimental** or **community check pack** until it has coverage manifests and fixture validation.

### Task 5.1: Generate Rule Inventory From DISA XCCDF

**Objective:** Produce a complete list of rules for each target STIG.

**Files:**
- Create: `crates/cli/src/commands/coverage.rs`
- Modify: `crates/cli/src/main.rs`
- Create: `content/coverage/windows_server_2022.json`
- Create: `content/coverage/rhel8.json`

**CLI:**
```bash
automatestig coverage generate \
  --xccdf U_MS_Windows_Server_2022_STIG_V2R4_Manual-xccdf.xml \
  --check-pack content/check_packs/windows_server_2022.json \
  --output content/coverage/windows_server_2022.json
```

**Verification:**
```bash
cargo run --bin automatestig -- coverage generate --help
cargo test --workspace
```

**Commit:**
```bash
git add crates/cli/src/commands/coverage.rs crates/cli/src/main.rs content/coverage
git commit -m "feat: add STIG rule coverage manifest generation"
```

### Task 5.2: Add Coverage Gate Tests

**Objective:** CI should fail if an advertised supported platform has missing/unclassified rules.

**Files:**
- Create: `crates/tests/src/coverage.rs`
- Modify: `crates/tests/src/lib.rs`

**Rules:**
- `supported` platforms must have 100% rules classified.
- `automated` rules must reference an existing check ID.
- `manual` rules must include a reason.
- `unsupported` rules must include a reason and cannot appear in production-supported release claims.

**Verification:**
```bash
cargo test -p automatestig-tests coverage
```

**Commit:**
```bash
git add crates/tests/src/coverage.rs crates/tests/src/lib.rs
git commit -m "test: enforce coverage manifests for supported STIGs"
```

### Task 5.3: Complete Windows Server 2022 Check Pack

**Objective:** Make one flagship Windows platform actually comprehensive.

**Files:**
- Modify: `content/check_packs/windows_server_2022.json`
- Modify: `content/coverage/windows_server_2022.json`
- Modify as needed: `crates/core/src/checks/registry.rs`
- Modify as needed: `crates/core/src/checks/executor.rs`
- Modify as needed: `crates/gui/src/winrm.rs`
- Add fixtures: `fixtures/sanitized/windows-server-2022/`

**Work method:**
For each DISA rule:
1. Add coverage entry.
2. Determine if rule is automatable.
3. Add check definition or manual reason.
4. Add synthetic unit test for check behavior.
5. Add fixture/golden test where possible.

**Verification:**
```bash
cargo test -p automatestig-core checks::
cargo test -p automatestig-tests coverage_windows_server_2022
cargo test -p automatestig-tests golden_windows_server_2022
```

**Commit:**
```bash
git add content/check_packs/windows_server_2022.json content/coverage/windows_server_2022.json fixtures/sanitized/windows-server-2022 crates/core crates/gui crates/tests
git commit -m "feat: complete validated Windows Server 2022 STIG coverage"
```

### Task 5.4: Complete RHEL 8 Check Pack

**Objective:** Make one flagship Linux platform actually comprehensive.

**Files:**
- Modify: `content/check_packs/rhel8.json`
- Modify: `content/coverage/rhel8.json`
- Modify as needed: `crates/core/src/checks/linux.rs`
- Modify as needed: `crates/core/src/checks/executor.rs`
- Modify as needed: `crates/gui/src/ssh.rs`
- Add fixtures: `fixtures/sanitized/rhel8/`

**Verification:**
```bash
cargo test -p automatestig-core linux
cargo test -p automatestig-tests coverage_rhel8
cargo test -p automatestig-tests golden_rhel8
```

**Commit:**
```bash
git add content/check_packs/rhel8.json content/coverage/rhel8.json fixtures/sanitized/rhel8 crates/core crates/gui crates/tests
git commit -m "feat: complete validated RHEL 8 STIG coverage"
```

---

## Phase 6 — Make “Evaluate” Actually Evaluate

### Task 6.1: Rename Checklist Initialization Paths

**Objective:** Avoid misleading users by distinguishing blank checklist creation from evaluation.

**Files:**
- Modify: `crates/gui/src/api.rs`
- Modify: `crates/gui/frontend/app.js`
- Modify: `crates/cli/src/commands/evaluate.rs`

**Required behavior:**
- If no scan result, remote collection, answer file, or check pack execution occurs, call it `Create Checklist`, not `Evaluate`.
- Evaluation response must include:
  - `rules_total`
  - `automated_rules_run`
  - `scan_results_applied`
  - `answer_overrides_applied`
  - `not_reviewed_count`
  - `coverage_percent`

**Verification:**
```bash
cargo test --workspace
node --check crates/gui/frontend/app.js
```

**Commit:**
```bash
git add crates/gui/src/api.rs crates/gui/frontend/app.js crates/cli/src/commands/evaluate.rs
git commit -m "ux: distinguish checklist creation from evaluation"
```

### Task 6.2: Add Evaluation Quality Summary

**Objective:** Tell users whether the result is complete enough to trust.

**Files:**
- Modify: `crates/core/src/engine.rs`
- Modify: `crates/core/src/models/checklist.rs`
- Modify: `crates/gui/src/api.rs`
- Modify: `crates/gui/frontend/app.js`

**Quality levels:**
- `complete_automated`
- `partial_automated`
- `scan_import_only`
- `manual_review_required`
- `initialized_only`

**Verification:**
```bash
cargo test -p automatestig-core evaluation_quality
cargo test --workspace
```

**Commit:**
```bash
git add crates/core/src/engine.rs crates/core/src/models/checklist.rs crates/gui/src/api.rs crates/gui/frontend/app.js
git commit -m "feat: add evaluation completeness and quality summary"
```

---

## Phase 7 — Enterprise/Operational Mode

### Task 7.1: Split Desktop and Server Modes

**Objective:** Make local desktop safe and hosted/server explicit.

**Files:**
- Modify: `crates/gui/src/main.rs`
- Create: `crates/gui/src/config.rs`
- Modify: `README.md`

**Modes:**
- `desktop`: localhost bind, random token, opens browser, local-only assumptions.
- `server`: configured bind, required auth secret, no browser auto-open, hardened CORS, no demo defaults.

**Verification:**
```bash
cargo test -p automatestig-gui config
cargo run --bin automatestig-gui -- --mode desktop
AUTOMATESTIG_AUTH_TOKEN=test cargo run --bin automatestig-gui -- --mode server --bind 127.0.0.1:8080
```

**Commit:**
```bash
git add crates/gui/src/main.rs crates/gui/src/config.rs README.md
git commit -m "feat: separate desktop and server GUI modes"
```

### Task 7.2: Add Audit Log Events for Sensitive Operations

**Objective:** Record who/what/when for imports, evaluations, exports, credential use, and remote scans.

**Files:**
- Modify: `crates/storage/src/lib.rs`
- Modify: `crates/gui/src/api.rs`
- Modify: `crates/core/src/engine.rs`
- Tests: `crates/storage/src/lib.rs`

**Events:**
- content import
- stigpack verify/import
- remote SSH scan start/end
- remote WinRM scan start/end
- credential create/update/delete/use
- checklist export
- STIG Manager push

**Verification:**
```bash
cargo test -p automatestig-storage audit
cargo test --workspace
```

**Commit:**
```bash
git add crates/storage/src/lib.rs crates/gui/src/api.rs crates/core/src/engine.rs
git commit -m "feat: add audit events for sensitive operations"
```

---

## Phase 8 — Release Criteria for “Better Than Evaluate-STIG”

### Task 8.1: Create Public Validation Report

**Objective:** Publish evidence that AutomateSTIG is a replacement, not just an alternative.

**Files:**
- Create: `docs/validation/evaluatestig-replacement-validation.md`

**Report sections:**
1. Tested inputs
2. Tested outputs
3. Supported platforms
4. Rule coverage by platform
5. Scanner compatibility
6. Known gaps
7. Security hardening status
8. Comparison against Evaluate-STIG workflows

**Verification:**
- Validation report links to CI passing runs and fixture tests.

**Commit:**
```bash
git add docs/validation/evaluatestig-replacement-validation.md
git commit -m "docs: publish replacement validation report"
```

### Task 8.2: Update Marketing Claims Only After Proof Exists

**Objective:** Claim replacement only after the validation suite backs it.

**Files:**
- Modify: `README.md`
- Modify: `docs/website/index.html`

**Allowed claim once complete:**
> AutomateSTIG is a validated Evaluate-STIG replacement for the supported platforms listed in the coverage matrix. It adds native cross-platform binaries, CKLB support, signed offline content packs, structured evidence, STIG Manager export, and safer automation workflows.

**Disallowed until proven:**
- “Comprehensive support for all STIGs”
- “ACAS support” without fixtures
- “Full fidelity” without golden roundtrip tests
- “Signed content” if unsigned imports are accepted by default

**Verification:**
```bash
rg -n "comprehensive|ACAS|full fidelity|signed content|Evaluate-STIG" README.md docs/website/index.html
cargo test --workspace
```

**Commit:**
```bash
git add README.md docs/website/index.html
git commit -m "docs: update replacement claims based on validation evidence"
```

---

## Suggested Milestones

### Milestone A — Trustworthy Foundation

**Exit criteria:**
- Security blockers fixed.
- CI green.
- Formatting/clippy green.
- Docs no longer overclaim.

### Milestone B — Validated Input/Output Parity

**Exit criteria:**
- CKL/CKLB golden roundtrip suite.
- SCC/OpenSCAP XCCDF result fixture suite.
- ACAS claim removed or implemented with fixture tests.

### Milestone C — First Truly Supported Platforms

**Exit criteria:**
- Windows Server 2022 100% classified coverage manifest.
- RHEL 8 100% classified coverage manifest.
- Automated checks validated with fixtures.
- Evaluation quality summary included in outputs.

### Milestone D — Better-Than-Evaluate-STIG Release

**Exit criteria:**
- Public validation report.
- Secure desktop/server modes.
- Signed stigpack import policy enforced.
- STIG Manager export validated.
- Docs claim replacement only for validated platforms.

---

## The Strategic Product Rule

A better Evaluate-STIG replacement is not “more check packs.” It is:

1. **Same trusted workflows** Evaluate-STIG users need.
2. **More reliable outputs** with evidence and regression proof.
3. **Safer operation** in local, air-gapped, and enterprise contexts.
4. **Clearer coverage** so users know what is automated versus manual.
5. **Better UX** without hiding incompleteness.

Broad but shallow support makes AutomateSTIG look impressive in a demo but weak in an audit. Narrow, complete, validated support makes it credible.
