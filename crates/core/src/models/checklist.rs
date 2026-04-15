use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::asset::Asset;
use super::finding::{Finding, FindingStatus, FindingSummary};
use super::stig::Severity;

/// A STIG checklist — the core output artifact (.ckl / .cklb).
///
/// Represents the evaluation of one STIG benchmark against one asset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checklist {
    /// Unique checklist identifier.
    pub id: Uuid,

    /// The asset being evaluated.
    pub asset: Asset,

    /// STIG benchmark metadata.
    pub stig_info: ChecklistStigInfo,

    /// Individual rule findings.
    pub findings: Vec<Finding>,

    /// When this checklist was created.
    pub created_at: DateTime<Utc>,

    /// When this checklist was last modified.
    pub modified_at: DateTime<Utc>,

    /// Tool that generated this checklist.
    pub generated_by: String,

    /// Format version of the checklist.
    pub format_version: String,

    /// Classification marking.
    pub classification: Classification,
}

impl Checklist {
    /// Create a new empty checklist for the given asset and STIG.
    pub fn new(asset: Asset, stig_info: ChecklistStigInfo) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            asset,
            stig_info,
            findings: Vec::new(),
            created_at: now,
            modified_at: now,
            generated_by: format!("AutomateSTIG {}", env!("CARGO_PKG_VERSION")),
            format_version: "1".to_string(),
            classification: Classification::Unclassified,
        }
    }

    /// Get a finding by Vuln ID.
    pub fn find_by_vuln_id(&self, vuln_id: &str) -> Option<&Finding> {
        self.findings.iter().find(|f| f.vuln_id == vuln_id)
    }

    /// Get a mutable finding by Vuln ID.
    pub fn find_by_vuln_id_mut(&mut self, vuln_id: &str) -> Option<&mut Finding> {
        self.findings.iter_mut().find(|f| f.vuln_id == vuln_id)
    }

    /// Get summary statistics.
    pub fn summary(&self) -> FindingSummary {
        FindingSummary::from_findings(&self.findings)
    }

    /// Get all open findings.
    pub fn open_findings(&self) -> Vec<&Finding> {
        self.findings.iter().filter(|f| f.status == FindingStatus::Open).collect()
    }

    /// Get all open findings of a specific severity.
    pub fn open_findings_by_severity(&self, severity: Severity) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|f| {
                f.status == FindingStatus::Open
                    && f.severity_override.unwrap_or(f.severity) == severity
            })
            .collect()
    }

    /// Get all findings that still need review.
    pub fn unreviewed_findings(&self) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|f| f.status == FindingStatus::NotReviewed)
            .collect()
    }

    /// Mark this checklist as modified.
    pub fn touch(&mut self) {
        self.modified_at = Utc::now();
    }
}

/// STIG benchmark metadata stored in a checklist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChecklistStigInfo {
    /// STIG ID / filename.
    pub stig_id: String,

    /// STIG title (e.g., "Microsoft Windows Server 2022 Security Technical Implementation Guide").
    pub title: String,

    /// Version string (e.g., "1").
    pub version: String,

    /// Release (e.g., "4").
    pub release: String,

    /// Release date.
    pub release_date: Option<String>,

    /// UUID for STIG-Manager compatibility.
    pub uuid: Option<String>,

    /// Description.
    pub description: Option<String>,

    /// Filename of the source STIG.
    pub filename: Option<String>,
}

/// Classification marking for checklists and reports.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Classification {
    #[default]
    #[serde(rename = "UNCLASSIFIED")]
    Unclassified,
    #[serde(rename = "CUI")]
    Cui,
    #[serde(rename = "CONFIDENTIAL")]
    Confidential,
    #[serde(rename = "SECRET")]
    Secret,
    #[serde(rename = "TOP SECRET")]
    TopSecret,
}

impl std::fmt::Display for Classification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unclassified => write!(f, "UNCLASSIFIED"),
            Self::Cui => write!(f, "CUI"),
            Self::Confidential => write!(f, "CONFIDENTIAL"),
            Self::Secret => write!(f, "SECRET"),
            Self::TopSecret => write!(f, "TOP SECRET"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::asset::Asset;

    fn make_stig_info() -> ChecklistStigInfo {
        ChecklistStigInfo {
            stig_id: "Windows_Server_2022_STIG".to_string(),
            title: "Microsoft Windows Server 2022 STIG".to_string(),
            version: "1".to_string(),
            release: "4".to_string(),
            release_date: Some("2024-07-24".to_string()),
            uuid: None,
            description: None,
            filename: None,
        }
    }

    #[test]
    fn test_new_checklist() {
        let cl = Checklist::new(Asset::new("server01"), make_stig_info());
        assert_eq!(cl.asset.hostname, "server01");
        assert_eq!(cl.stig_info.version, "1");
        assert!(cl.findings.is_empty());
    }

    #[test]
    fn test_checklist_summary() {
        let mut cl = Checklist::new(Asset::new("server01"), make_stig_info());
        cl.findings.push({
            let mut f = Finding::new_not_reviewed("V-1", "SV-1", "V-1", "R1", Severity::High);
            f.status = FindingStatus::Open;
            f
        });
        cl.findings.push({
            let mut f = Finding::new_not_reviewed("V-2", "SV-2", "V-2", "R2", Severity::Medium);
            f.status = FindingStatus::NotAFinding;
            f
        });

        let summary = cl.summary();
        assert_eq!(summary.total, 2);
        assert_eq!(summary.open, 1);
        assert_eq!(summary.not_a_finding, 1);
        assert_eq!(summary.cat_i_open, 1);
    }
}
