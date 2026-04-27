//! eMASS (Enterprise Mission Assurance Support Service) export format.
//!
//! Generates eMASS-compatible test result exports for RMF POA&M
//! and control assessment workflows.

use serde::{Deserialize, Serialize};

use automatestig_core::models::checklist::Checklist;
use automatestig_core::models::finding::FindingStatus;
use automatestig_core::models::stig::Severity;

/// A single eMASS test result row.
#[derive(Debug, Serialize, Deserialize)]
pub struct EmassTestResult {
    /// Control Correlation Identifier.
    pub cci: String,

    /// Assessment procedure.
    pub assessment_procedure: String,

    /// Result: "Pass", "Fail", "Not Applicable".
    pub result: String,

    /// Result details / evidence.
    pub result_comment: String,

    /// STIG finding reference.
    pub stig_reference: String,

    /// Severity: "I", "II", "III".
    pub severity: String,

    /// Asset/system name.
    pub system_name: String,

    /// Assessment date.
    pub assessment_date: String,
}

/// Export checklist findings to eMASS test result format.
pub fn export_to_emass(checklist: &Checklist) -> Vec<EmassTestResult> {
    let mut results = Vec::new();

    for finding in &checklist.findings {
        // Only export findings with actual results (not "Not Reviewed").
        if finding.status == FindingStatus::NotReviewed {
            continue;
        }

        let result_str = match finding.status {
            FindingStatus::NotAFinding => "Pass",
            FindingStatus::Open => "Fail",
            FindingStatus::NotApplicable => "Not Applicable",
            FindingStatus::NotReviewed => continue,
        };

        let severity = match finding.severity_override.unwrap_or(finding.severity) {
            Severity::High => "I",
            Severity::Medium => "II",
            Severity::Low => "III",
        };

        for cci in &finding.cci_refs {
            results.push(EmassTestResult {
                cci: cci.clone(),
                assessment_procedure: format!("{} - {}", finding.vuln_id, finding.rule_title),
                result: result_str.to_string(),
                result_comment: finding.finding_details.clone(),
                stig_reference: format!(
                    "{} {} {}",
                    checklist.stig_info.title, finding.vuln_id, finding.rule_id,
                ),
                severity: severity.to_string(),
                system_name: checklist.asset.hostname.clone(),
                assessment_date: finding.evaluated_at.format("%Y-%m-%d").to_string(),
            });
        }
    }

    results
}

/// Export eMASS results as CSV.
pub fn export_emass_csv(results: &[EmassTestResult]) -> String {
    let mut csv = String::from("CCI,Assessment Procedure,Result,Result Comment,STIG Reference,Severity,System Name,Assessment Date\n");

    for r in results {
        csv.push_str(&format!(
            "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"\n",
            escape_csv(&r.cci),
            escape_csv(&r.assessment_procedure),
            escape_csv(&r.result),
            escape_csv(&r.result_comment),
            escape_csv(&r.stig_reference),
            escape_csv(&r.severity),
            escape_csv(&r.system_name),
            escape_csv(&r.assessment_date),
        ));
    }

    csv
}

fn escape_csv(s: &str) -> String {
    s.replace('"', "\"\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use automatestig_core::models::asset::Asset;
    use automatestig_core::models::checklist::{Checklist, ChecklistStigInfo};
    use automatestig_core::models::finding::{Finding, FindingStatus};
    use automatestig_core::models::stig::Severity;
    use chrono::TimeZone;

    fn golden_checklist() -> Checklist {
        let stig_info = ChecklistStigInfo {
            stig_id: "Golden_STIG".to_string(),
            title: "Golden STIG".to_string(),
            version: "1".to_string(),
            release: "1".to_string(),
            release_date: None,
            uuid: None,
            description: None,
            filename: None,
        };

        let mut cl = Checklist::new(Asset::new("golden-host"), stig_info);
        let mut f =
            Finding::new_not_reviewed("V-1", "SV-1r1_rule", "V-1", "Golden Rule", Severity::High);
        f.status = FindingStatus::Open;
        f.cci_refs = vec!["CCI-000068".to_string()];
        f.finding_details = "Scanner evidence: registry value missing".to_string();
        f.evaluated_at = chrono::Utc.with_ymd_and_hms(2026, 4, 27, 0, 0, 0).unwrap();
        cl.findings.push(f);
        cl
    }

    #[test]
    fn test_emass_export() {
        let stig_info = ChecklistStigInfo {
            stig_id: "Test_STIG".to_string(),
            title: "Test STIG".to_string(),
            version: "1".to_string(),
            release: "1".to_string(),
            release_date: None,
            uuid: None,
            description: None,
            filename: None,
        };

        let mut cl = Checklist::new(Asset::new("server01"), stig_info);

        let mut f = Finding::new_not_reviewed("V-1", "SV-1", "V-1", "Test Rule", Severity::High);
        f.status = FindingStatus::Open;
        f.cci_refs = vec!["CCI-000068".to_string()];
        f.finding_details = "Not configured".to_string();
        cl.findings.push(f);

        let results = export_to_emass(&cl);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].cci, "CCI-000068");
        assert_eq!(results[0].result, "Fail");
        assert_eq!(results[0].severity, "I");

        let csv = export_emass_csv(&results);
        assert!(csv.contains("CCI-000068"));
        assert!(csv.contains("Fail"));
    }

    #[test]
    fn test_emass_golden_payload() {
        let results = export_to_emass(&golden_checklist());
        let csv = export_emass_csv(&results);

        assert_eq!(
            csv,
            include_str!("../../../fixtures/exports/emass_golden.csv")
        );
    }
}
