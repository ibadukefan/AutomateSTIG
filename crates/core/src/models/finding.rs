use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::stig::Severity;

/// The status/result of evaluating a single STIG rule against an asset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FindingStatus {
    /// The system is compliant with this rule.
    #[serde(rename = "NotAFinding")]
    NotAFinding,

    /// The system is NOT compliant — this is an open finding.
    #[serde(rename = "Open")]
    Open,

    /// The rule does not apply to this system.
    #[serde(rename = "Not_Applicable")]
    NotApplicable,

    /// The rule has not been reviewed yet.
    #[serde(rename = "Not_Reviewed")]
    NotReviewed,
}

impl FindingStatus {
    /// Parse from CKL STATUS text.
    pub fn from_ckl_str(s: &str) -> Option<Self> {
        match s.trim() {
            "NotAFinding" | "Not A Finding" | "not_a_finding" => Some(Self::NotAFinding),
            "Open" | "open" => Some(Self::Open),
            "Not_Applicable" | "NotApplicable" | "not_applicable" => Some(Self::NotApplicable),
            "Not_Reviewed" | "NotReviewed" | "not_reviewed" => Some(Self::NotReviewed),
            _ => None,
        }
    }

    /// Convert to CKL STATUS text.
    pub fn as_ckl_str(&self) -> &'static str {
        match self {
            Self::NotAFinding => "NotAFinding",
            Self::Open => "Open",
            Self::NotApplicable => "Not_Applicable",
            Self::NotReviewed => "Not_Reviewed",
        }
    }

    /// Convert to STIG-Manager compliant result string.
    pub fn as_stig_manager_str(&self) -> &'static str {
        match self {
            Self::NotAFinding => "pass",
            Self::Open => "fail",
            Self::NotApplicable => "notapplicable",
            Self::NotReviewed => "notchecked",
        }
    }
}

impl std::fmt::Display for FindingStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAFinding => write!(f, "Not a Finding"),
            Self::Open => write!(f, "Open"),
            Self::NotApplicable => write!(f, "Not Applicable"),
            Self::NotReviewed => write!(f, "Not Reviewed"),
        }
    }
}

/// How a finding was determined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingSource {
    /// Determined by an automated check in the tool.
    #[serde(rename = "automated", alias = "custom_check")]
    Automated,

    /// Populated from an answer file template.
    #[serde(rename = "answer_file")]
    AnswerFile,

    /// Manually entered by a reviewer.
    #[serde(rename = "manual")]
    Manual,

    /// Imported from a previous checklist.
    #[serde(rename = "imported")]
    Imported,

    /// Evaluated from a supplied transcript/config whose collection transport
    /// was not authenticated by this process.
    #[serde(rename = "evidence")]
    Evidence,

    /// The rule could not be evaluated because required collection or
    /// evaluation data failed validation. This source is immutable to answer
    /// files and merge operations so an error cannot become a claimed result.
    #[serde(rename = "collection_error")]
    CollectionError,
}

/// A single finding — the result of evaluating one STIG rule against one asset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Unique finding identifier.
    pub id: Uuid,

    /// The Vuln ID of the evaluated rule (e.g., "V-254239").
    pub vuln_id: String,

    /// The Rule ID (e.g., "SV-254239r958388_rule").
    pub rule_id: String,

    /// Group ID / STIG ID.
    pub group_id: String,

    /// Original group title/SRG reference from the benchmark or checklist.
    #[serde(default)]
    pub group_title: String,

    /// Rule title (denormalized for reporting convenience).
    pub rule_title: String,

    /// Rule version from the source benchmark/checklist.
    #[serde(default)]
    pub rule_version: String,

    /// Rule weight from the source benchmark/checklist.
    #[serde(default)]
    pub weight: f64,

    /// Full rule discussion text.
    #[serde(default)]
    pub discussion: String,

    /// Procedure used to evaluate the rule.
    #[serde(default)]
    pub check_content: String,

    /// Procedure used to correct the rule.
    #[serde(default)]
    pub fix_text: String,

    /// Original STIG reference value, when present.
    #[serde(default)]
    pub stig_ref: Option<String>,

    /// Severity of the rule at evaluation time.
    pub severity: Severity,

    /// The compliance status.
    pub status: FindingStatus,

    /// How this finding was determined.
    pub source: FindingSource,

    /// Detailed finding text / evidence.
    pub finding_details: String,

    /// Comments from the reviewer or automation.
    pub comments: String,

    /// Override severity (if the reviewer changed it from the STIG default).
    pub severity_override: Option<Severity>,

    /// Justification for the severity override.
    pub severity_override_justification: Option<String>,

    /// When this finding was last evaluated.
    pub evaluated_at: DateTime<Utc>,

    /// Who or what performed the evaluation.
    pub evaluated_by: String,

    /// Raw evidence / command output from automated checks.
    pub evidence: Option<String>,

    /// CCI references (denormalized).
    pub cci_refs: Vec<String>,

    /// Legacy IDs (denormalized).
    pub legacy_ids: Vec<String>,

    /// Format-specific rule metadata retained to reduce CKL/CKLB round-trip loss.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format_metadata: Option<serde_json::Value>,
}

impl Finding {
    /// Create a new finding with default "Not Reviewed" status.
    pub fn new_not_reviewed(
        vuln_id: &str,
        rule_id: &str,
        group_id: &str,
        title: &str,
        severity: Severity,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            vuln_id: vuln_id.to_string(),
            rule_id: rule_id.to_string(),
            group_id: group_id.to_string(),
            group_title: group_id.to_string(),
            rule_title: title.to_string(),
            rule_version: String::new(),
            weight: severity.default_weight(),
            discussion: String::new(),
            check_content: String::new(),
            fix_text: String::new(),
            stig_ref: None,
            severity,
            status: FindingStatus::NotReviewed,
            source: FindingSource::Manual,
            finding_details: String::new(),
            comments: String::new(),
            severity_override: None,
            severity_override_justification: None,
            evaluated_at: Utc::now(),
            evaluated_by: String::new(),
            evidence: None,
            cci_refs: Vec::new(),
            legacy_ids: Vec::new(),
            format_metadata: None,
        }
    }
}

/// Summary statistics for a set of findings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FindingSummary {
    pub total: usize,
    pub open: usize,
    pub not_a_finding: usize,
    pub not_applicable: usize,
    pub not_reviewed: usize,
    pub cat_i_open: usize,
    pub cat_ii_open: usize,
    pub cat_iii_open: usize,
}

impl FindingSummary {
    /// Compute summary from a slice of findings.
    pub fn from_findings(findings: &[Finding]) -> Self {
        let mut summary = Self {
            total: findings.len(),
            ..Default::default()
        };
        for f in findings {
            match f.status {
                FindingStatus::Open => {
                    summary.open += 1;
                    match f.severity_override.unwrap_or(f.severity) {
                        Severity::High => summary.cat_i_open += 1,
                        Severity::Medium => summary.cat_ii_open += 1,
                        Severity::Low => summary.cat_iii_open += 1,
                    }
                }
                FindingStatus::NotAFinding => summary.not_a_finding += 1,
                FindingStatus::NotApplicable => summary.not_applicable += 1,
                FindingStatus::NotReviewed => summary.not_reviewed += 1,
            }
        }
        summary
    }

    /// Number of benchmark controls for which an assessment result exists.
    pub fn assessed(&self) -> usize {
        self.total.saturating_sub(self.not_reviewed)
    }

    /// Number of assessed controls that apply to this asset.
    pub fn applicable_assessed(&self) -> usize {
        self.open + self.not_a_finding
    }

    /// Pass rate among assessed controls that apply to this asset.
    ///
    /// `NotApplicable` and `NotReviewed` are both excluded from the pass-rate
    /// denominator. Coverage still counts a defensible `NotApplicable`
    /// determination as assessed and is represented separately by
    /// [`Self::benchmark_coverage_pct`].
    pub fn assessed_pass_pct(&self) -> f64 {
        self.assessed_pass_pct_opt().unwrap_or(0.0)
    }

    /// Pass rate when at least one assessed control applies to the asset.
    ///
    /// A zero denominator is not a failing score: all controls may have a
    /// defensible `NotApplicable` determination. Presentation and API layers
    /// should use this nullable form so they can render that state as `N/A`.
    pub fn assessed_pass_pct_opt(&self) -> Option<f64> {
        let applicable = self.applicable_assessed();
        (applicable > 0).then(|| (self.not_a_finding as f64 / applicable as f64) * 100.0)
    }

    /// Percentage of all benchmark controls that have been assessed.
    pub fn benchmark_coverage_pct(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        (self.assessed() as f64 / self.total as f64) * 100.0
    }

    /// Legacy name for the pass rate among assessed controls.
    ///
    /// New presentation code must label this value as an assessed-control pass
    /// rate and show [`Self::benchmark_coverage_pct`] alongside it.
    pub fn compliance_pct(&self) -> f64 {
        self.assessed_pass_pct()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_finding_status_roundtrip() {
        for status in [
            FindingStatus::NotAFinding,
            FindingStatus::Open,
            FindingStatus::NotApplicable,
            FindingStatus::NotReviewed,
        ] {
            let s = status.as_ckl_str();
            assert_eq!(FindingStatus::from_ckl_str(s), Some(status));
        }
    }

    #[test]
    fn test_finding_summary() {
        let findings = vec![
            Finding::new_not_reviewed("V-1", "SV-1", "V-1", "Rule 1", Severity::High),
            {
                let mut f =
                    Finding::new_not_reviewed("V-2", "SV-2", "V-2", "Rule 2", Severity::High);
                f.status = FindingStatus::Open;
                f
            },
            {
                let mut f =
                    Finding::new_not_reviewed("V-3", "SV-3", "V-3", "Rule 3", Severity::Medium);
                f.status = FindingStatus::NotAFinding;
                f
            },
            {
                let mut f =
                    Finding::new_not_reviewed("V-4", "SV-4", "V-4", "Rule 4", Severity::Low);
                f.status = FindingStatus::NotApplicable;
                f
            },
        ];

        let summary = FindingSummary::from_findings(&findings);
        assert_eq!(summary.total, 4);
        assert_eq!(summary.open, 1);
        assert_eq!(summary.not_a_finding, 1);
        assert_eq!(summary.not_applicable, 1);
        assert_eq!(summary.not_reviewed, 1);
        assert_eq!(summary.cat_i_open, 1);
        assert_eq!(summary.cat_ii_open, 0);
        // 1 pass out of 2 applicable assessed controls; the NotApplicable
        // determination still counts toward 3-of-4 benchmark coverage.
        assert_eq!(summary.assessed(), 3);
        assert_eq!(summary.applicable_assessed(), 2);
        assert!((summary.assessed_pass_pct() - 50.0).abs() < f64::EPSILON);
        assert_eq!(summary.assessed_pass_pct_opt(), Some(50.0));
        assert!((summary.benchmark_coverage_pct() - 75.0).abs() < f64::EPSILON);
        assert_eq!(summary.compliance_pct(), summary.assessed_pass_pct());
    }

    #[test]
    fn partial_benchmark_does_not_look_fully_assessed() {
        let summary = FindingSummary {
            total: 203,
            not_a_finding: 3,
            not_reviewed: 200,
            ..Default::default()
        };

        assert_eq!(summary.assessed(), 3);
        assert_eq!(summary.assessed_pass_pct(), 100.0);
        assert!((summary.benchmark_coverage_pct() - (3.0 / 203.0 * 100.0)).abs() < f64::EPSILON);
        assert!(summary.benchmark_coverage_pct() < 1.5);
    }

    #[test]
    fn empty_summary_has_zero_pass_rate_and_coverage() {
        let summary = FindingSummary::default();
        assert_eq!(summary.assessed(), 0);
        assert_eq!(summary.assessed_pass_pct(), 0.0);
        assert_eq!(summary.assessed_pass_pct_opt(), None);
        assert_eq!(summary.benchmark_coverage_pct(), 0.0);
    }

    #[test]
    fn all_not_applicable_is_fully_assessed_but_not_a_pass_claim() {
        let summary = FindingSummary {
            total: 2,
            not_applicable: 2,
            ..Default::default()
        };
        assert_eq!(summary.assessed(), 2);
        assert_eq!(summary.applicable_assessed(), 0);
        assert_eq!(summary.assessed_pass_pct(), 0.0);
        assert_eq!(summary.assessed_pass_pct_opt(), None);
        assert_eq!(summary.benchmark_coverage_pct(), 100.0);
    }
}
