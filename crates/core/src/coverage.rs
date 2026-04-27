use std::collections::HashSet;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageManifest {
    pub stig_id: String,
    pub version: String,
    pub source: String,
    pub status: CoverageStatus,
    pub total_rules: usize,
    pub generated_from: Option<String>,
    pub generated_at: Option<String>,
    pub rules: Vec<CoverageRule>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageStatus {
    Experimental,
    Supported,
    Production,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageRule {
    pub vuln_id: String,
    pub rule_id: String,
    pub title: Option<String>,
    pub severity: Option<String>,
    pub classification: RuleCoverageClassification,
    pub check_pack: Option<String>,
    pub check_id: Option<String>,
    #[serde(default = "default_evidence_required")]
    pub evidence_required: bool,
    pub reason: String,
    pub tracking_issue: Option<String>,
    #[serde(default)]
    pub validated_by: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleCoverageClassification {
    Automated,
    ScannerImport,
    Manual,
    NotApplicable,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageValidationIssue {
    pub field: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageValidationReport {
    pub total_rules: usize,
    pub automated: usize,
    pub scanner_import: usize,
    pub manual: usize,
    pub not_applicable: usize,
    pub unsupported: usize,
    pub issues: Vec<CoverageValidationIssue>,
}

pub fn parse_coverage_manifest(json: &str) -> Result<CoverageManifest, serde_json::Error> {
    serde_json::from_str(json)
}

pub fn validate_coverage_manifest(manifest: &CoverageManifest) -> CoverageValidationReport {
    let mut report = CoverageValidationReport {
        total_rules: manifest.rules.len(),
        automated: 0,
        scanner_import: 0,
        manual: 0,
        not_applicable: 0,
        unsupported: 0,
        issues: Vec::new(),
    };

    if manifest.stig_id.trim().is_empty() {
        push_issue(&mut report, "stig_id", "stig_id is required");
    }
    if manifest.version.trim().is_empty() {
        push_issue(&mut report, "version", "version is required");
    }
    if manifest.total_rules != manifest.rules.len() {
        push_issue(
            &mut report,
            "total_rules",
            &format!(
                "total_rules declares {} but rules contains {} entries",
                manifest.total_rules,
                manifest.rules.len()
            ),
        );
    }

    let mut seen_vulns = HashSet::new();
    let mut seen_rules = HashSet::new();
    for (idx, rule) in manifest.rules.iter().enumerate() {
        let prefix = format!("rules[{}]", idx);
        match rule.classification {
            RuleCoverageClassification::Automated => report.automated += 1,
            RuleCoverageClassification::ScannerImport => report.scanner_import += 1,
            RuleCoverageClassification::Manual => report.manual += 1,
            RuleCoverageClassification::NotApplicable => report.not_applicable += 1,
            RuleCoverageClassification::Unsupported => report.unsupported += 1,
        }

        if rule.vuln_id.trim().is_empty() {
            push_issue(
                &mut report,
                &format!("{}.vuln_id", prefix),
                "vuln_id is required",
            );
        } else if !seen_vulns.insert(rule.vuln_id.trim().to_string()) {
            push_issue(
                &mut report,
                &format!("{}.vuln_id", prefix),
                "duplicate vuln_id",
            );
        }

        if rule.rule_id.trim().is_empty() {
            push_issue(
                &mut report,
                &format!("{}.rule_id", prefix),
                "rule_id is required",
            );
        } else if !seen_rules.insert(rule.rule_id.trim().to_string()) {
            push_issue(
                &mut report,
                &format!("{}.rule_id", prefix),
                "duplicate rule_id",
            );
        }

        if rule.reason.trim().is_empty() {
            push_issue(
                &mut report,
                &format!("{}.reason", prefix),
                "reason is required",
            );
        }

        if rule.classification == RuleCoverageClassification::Automated {
            if rule.check_pack.as_deref().unwrap_or("").trim().is_empty() {
                push_issue(
                    &mut report,
                    &format!("{}.check_pack", prefix),
                    "automated rules require check_pack",
                );
            }
            if rule.check_id.as_deref().unwrap_or("").trim().is_empty() {
                push_issue(
                    &mut report,
                    &format!("{}.check_id", prefix),
                    "automated rules require check_id",
                );
            }
        }

        if matches!(
            rule.classification,
            RuleCoverageClassification::Automated | RuleCoverageClassification::ScannerImport
        ) && (rule.validated_by.is_empty()
            || rule
                .validated_by
                .iter()
                .any(|reference| reference.trim().is_empty()))
        {
            push_issue(
                &mut report,
                &format!("{}.validated_by", prefix),
                "automated and scanner-import rules require non-empty validation evidence references",
            );
        }

        if rule.classification == RuleCoverageClassification::Unsupported
            && rule
                .tracking_issue
                .as_deref()
                .unwrap_or("")
                .trim()
                .is_empty()
        {
            push_issue(
                &mut report,
                &format!("{}.tracking_issue", prefix),
                "unsupported rules require a tracking_issue",
            );
        }
    }

    report
}

impl CoverageValidationReport {
    pub fn is_valid(&self) -> bool {
        self.issues.is_empty()
    }
}

fn default_evidence_required() -> bool {
    true
}

fn push_issue(report: &mut CoverageValidationReport, field: &str, message: &str) {
    report.issues.push(CoverageValidationIssue {
        field: field.to_string(),
        message: message.to_string(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_example_manifest_counts_and_evidence() {
        let manifest = parse_coverage_manifest(include_str!(
            "../../../content/coverage/windows_server_2022.example.json"
        ))
        .unwrap();

        let report = validate_coverage_manifest(&manifest);

        assert!(report.is_valid(), "unexpected issues: {:?}", report.issues);
        assert_eq!(report.total_rules, 2);
        assert_eq!(report.automated, 1);
        assert_eq!(report.scanner_import, 1);
    }

    #[test]
    fn rejects_inconsistent_or_unproven_coverage_manifest() {
        let manifest = parse_coverage_manifest(
            r#"{
              "stig_id": "Example_STIG",
              "version": "1",
              "source": "unit test",
              "status": "experimental",
              "total_rules": 4,
              "rules": [
                {
                  "vuln_id": "V-1",
                  "rule_id": "SV-1_rule",
                  "classification": "automated",
                  "reason": "missing check metadata"
                },
                {
                  "vuln_id": "V-1 ",
                  "rule_id": "SV-1_rule ",
                  "classification": "scanner_import",
                  "reason": "missing validation references",
                  "validated_by": [""]
                },
                {
                  "vuln_id": "V-2",
                  "rule_id": "SV-2_rule",
                  "classification": "unsupported",
                  "reason": "gap requires tracking issue"
                }
              ]
            }"#,
        )
        .unwrap();

        let report = validate_coverage_manifest(&manifest);

        assert!(!report.is_valid());
        assert!(report.issues.iter().any(|i| i.field == "total_rules"));
        assert!(report
            .issues
            .iter()
            .any(|i| i.message.contains("duplicate vuln_id")));
        assert!(report
            .issues
            .iter()
            .any(|i| i.message.contains("automated rules require check_pack")));
        assert!(report
            .issues
            .iter()
            .any(|i| i.message.contains("validation evidence")));
        assert!(report
            .issues
            .iter()
            .any(|i| i.message.contains("tracking_issue")));
    }

    #[test]
    fn rejects_unknown_manifest_fields() {
        let err = parse_coverage_manifest(
            r#"{
              "stig_id": "Example_STIG",
              "version": "1",
              "source": "unit test",
              "status": "experimental",
              "total_rules": 0,
              "unknown_field": true,
              "rules": []
            }"#,
        )
        .unwrap_err();

        assert!(err.to_string().contains("unknown field"));
    }
}
