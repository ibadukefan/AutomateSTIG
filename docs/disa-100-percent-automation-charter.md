# Every DISA STIG 100% Automation Charter

AutomateSTIG's long-term replacement goal is to cover every current public DISA STIG rule with a validation-gated automation path.

## Definitions

| Classification | Meaning | Production claim rule |
|---|---|---|
| `automated` | AutomateSTIG collects target evidence and computes pass/fail/not-applicable without human judgment. | Preferred outcome for technical rules. |
| `scanner_import` | AutomateSTIG ingests SCC/OpenSCAP/vendor scanner evidence and preserves authoritative provenance. | Acceptable when a validated scanner is the source of truth. |
| `manual` | AutomateSTIG enforces structured reviewer evidence, required artifacts, identity, timestamps, and export-compatible comments for rules that cannot be safely machine-decided. | Acceptable only with rationale and required evidence fields. |
| `not_applicable` | AutomateSTIG proves the rule does not apply to the target/product/profile. | Must include a machine-verifiable or reviewer-approved NA condition. |
| `unsupported` | No acceptable automation/workflow exists. | Must be zero for any production-ready STIG claim. |

## Non-negotiable rules

- No marketing claim may say "100% production-ready" unless the relevant authoritative DISA manifest has zero unsupported rules, validation evidence for every rule, and live external acceptance where applicable.
- Machine-verifiable coverage and manual-evidence workflow coverage must be reported separately.
- DISA corpus changes must trigger regeneration/diffing before release claims are updated.
- Credentials, tokens, and live acceptance secrets are never committed.
