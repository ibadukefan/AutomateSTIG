//! Answer file system for AutomateSTIG.
//!
//! Answer files are JSON/YAML templates that pre-populate finding status,
//! details, and comments for specific STIG rules. They replace the tedious
//! XML answer files from Evaluate-STIG with a modern, version-controllable format.

use serde::{Deserialize, Serialize};
use std::io;
use std::path::Path;

use crate::models::finding::FindingStatus;
use crate::models::stig::Severity;
use crate::{Error, Result};

const ANSWER_FILE_SIZE_LIMIT_BYTES: u64 = 128 * 1024 * 1024;

fn read_to_string_capped(path: &Path, max_bytes: u64) -> io::Result<String> {
    if std::fs::metadata(path)?.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file exceeds 128 MB parse limit",
        ));
    }
    std::fs::read_to_string(path)
}

/// An answer file — a template of pre-determined finding results.
///
/// Answer files let organizations standardize responses for rules that are
/// consistently Not Applicable, always configured a certain way, or require
/// standard justification text.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnswerFile {
    /// Human-readable name for this answer file.
    pub name: String,

    /// Description of what this answer file covers.
    pub description: Option<String>,

    /// The STIG ID this answer file targets (None = applies to any STIG).
    pub stig_id: Option<String>,

    /// Answer file version (for tracking changes).
    pub version: String,

    /// Individual answer entries.
    pub entries: Vec<AnswerEntry>,
}

/// A single answer entry — the pre-determined result for one rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnswerEntry {
    /// Vuln ID of the rule (e.g., "V-254239").
    pub vuln_id: String,

    /// Pre-determined status.
    pub status: FindingStatus,

    /// Finding details text.
    pub finding_details: Option<String>,

    /// Comments.
    pub comments: Option<String>,

    /// Override severity (if different from STIG default).
    pub severity_override: Option<Severity>,

    /// Justification for severity override.
    pub severity_override_justification: Option<String>,

    /// Whether to override even if a scan result already set the status.
    #[serde(default)]
    pub force_override: bool,
}

impl AnswerFile {
    /// Create a new empty answer file.
    pub fn new(name: &str, stig_id: Option<&str>) -> Self {
        Self {
            name: name.to_string(),
            description: None,
            stig_id: stig_id.map(|s| s.to_string()),
            version: "1.0".to_string(),
            entries: Vec::new(),
        }
    }

    /// Add an entry to this answer file.
    pub fn add_entry(&mut self, entry: AnswerEntry) {
        self.entries.push(entry);
    }

    /// Load an answer file from a JSON file.
    pub fn load_json(path: &Path) -> Result<Self> {
        let content = read_to_string_capped(path, ANSWER_FILE_SIZE_LIMIT_BYTES)?;
        serde_json::from_str(&content).map_err(|e| Error::AnswerFileError(e.to_string()))
    }

    /// Load an answer file from a YAML file.
    pub fn load_yaml(path: &Path) -> Result<Self> {
        let content = read_to_string_capped(path, ANSWER_FILE_SIZE_LIMIT_BYTES)?;
        serde_yml::from_str(&content).map_err(|e| Error::AnswerFileError(e.to_string()))
    }

    /// Load an answer file, auto-detecting format from extension.
    pub fn load(path: &Path) -> Result<Self> {
        match path.extension().and_then(|e| e.to_str()) {
            Some("json") => Self::load_json(path),
            Some("yaml") | Some("yml") => Self::load_yaml(path),
            _ => Err(Error::AnswerFileError(format!(
                "Unsupported answer file format: {}",
                path.display()
            ))),
        }
    }

    /// Save this answer file as JSON.
    pub fn save_json(&self, path: &Path) -> Result<()> {
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Save this answer file as YAML.
    pub fn save_yaml(&self, path: &Path) -> Result<()> {
        let content =
            serde_yml::to_string(self).map_err(|e| Error::AnswerFileError(e.to_string()))?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Validate the answer file for consistency.
    pub fn validate(&self) -> Vec<String> {
        let mut issues = Vec::new();

        if self.name.is_empty() {
            issues.push("Answer file name is empty".to_string());
        }

        // Check for duplicate Vuln IDs.
        let mut seen = std::collections::HashSet::new();
        for entry in &self.entries {
            if !seen.insert(&entry.vuln_id) {
                issues.push(format!("Duplicate Vuln ID: {}", entry.vuln_id));
            }
        }

        // Severity override requires justification.
        for entry in &self.entries {
            if entry.severity_override.is_some() && entry.severity_override_justification.is_none()
            {
                issues.push(format!(
                    "{}: Severity override without justification",
                    entry.vuln_id
                ));
            }
        }

        issues
    }
}

/// Generate a template answer file from a checklist, extracting all findings
/// that have been manually reviewed.
pub fn generate_answer_template(
    checklist: &crate::models::Checklist,
    include_not_reviewed: bool,
) -> AnswerFile {
    let mut af = AnswerFile::new(
        &format!("{} Answer Template", checklist.stig_info.title),
        Some(&checklist.stig_info.stig_id),
    );
    af.description = Some(format!(
        "Generated from checklist for {} ({})",
        checklist.asset.hostname, checklist.stig_info.title,
    ));

    for finding in &checklist.findings {
        if !include_not_reviewed && finding.status == FindingStatus::NotReviewed {
            continue;
        }

        af.entries.push(AnswerEntry {
            vuln_id: finding.vuln_id.clone(),
            status: finding.status,
            finding_details: if finding.finding_details.is_empty() {
                None
            } else {
                Some(finding.finding_details.clone())
            },
            comments: if finding.comments.is_empty() {
                None
            } else {
                Some(finding.comments.clone())
            },
            severity_override: finding.severity_override,
            severity_override_justification: finding.severity_override_justification.clone(),
            force_override: false,
        });
    }

    af
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn make_answer_file() -> AnswerFile {
        let mut af = AnswerFile::new("Test Answers", Some("Test_STIG"));
        af.add_entry(AnswerEntry {
            vuln_id: "V-100001".to_string(),
            status: FindingStatus::NotApplicable,
            finding_details: Some("Not applicable to this environment".to_string()),
            comments: Some("Reviewed 2024-01-15".to_string()),
            severity_override: None,
            severity_override_justification: None,
            force_override: false,
        });
        af.add_entry(AnswerEntry {
            vuln_id: "V-100002".to_string(),
            status: FindingStatus::NotAFinding,
            finding_details: Some("Configured per site policy".to_string()),
            comments: None,
            severity_override: None,
            severity_override_justification: None,
            force_override: false,
        });
        af
    }

    #[test]
    fn test_answer_file_json_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("answers.json");

        let af = make_answer_file();
        af.save_json(&path).unwrap();
        let loaded = AnswerFile::load_json(&path).unwrap();

        assert_eq!(loaded.name, "Test Answers");
        assert_eq!(loaded.entries.len(), 2);
        assert_eq!(loaded.entries[0].vuln_id, "V-100001");
        assert_eq!(loaded.entries[0].status, FindingStatus::NotApplicable);
    }

    #[test]
    fn test_answer_file_yaml_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("answers.yaml");

        let af = make_answer_file();
        af.save_yaml(&path).unwrap();
        let loaded = AnswerFile::load_yaml(&path).unwrap();

        assert_eq!(loaded.name, "Test Answers");
        assert_eq!(loaded.entries.len(), 2);
    }

    #[test]
    fn test_answer_file_auto_detect() {
        let dir = TempDir::new().unwrap();

        let af = make_answer_file();

        let json_path = dir.path().join("answers.json");
        af.save_json(&json_path).unwrap();
        let loaded = AnswerFile::load(&json_path).unwrap();
        assert_eq!(loaded.entries.len(), 2);

        let yaml_path = dir.path().join("answers.yml");
        af.save_yaml(&yaml_path).unwrap();
        let loaded = AnswerFile::load(&yaml_path).unwrap();
        assert_eq!(loaded.entries.len(), 2);
    }

    #[test]
    fn test_read_to_string_capped_rejects_oversize() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"longer than eight bytes").unwrap();

        assert!(read_to_string_capped(file.path(), 8).is_err());
        assert_eq!(
            read_to_string_capped(file.path(), 128).unwrap(),
            "longer than eight bytes"
        );
    }

    #[test]
    fn test_answer_file_validation() {
        let mut af = AnswerFile::new("", None);
        af.add_entry(AnswerEntry {
            vuln_id: "V-1".to_string(),
            status: FindingStatus::Open,
            finding_details: None,
            comments: None,
            severity_override: Some(Severity::Low), // Override without justification
            severity_override_justification: None,
            force_override: false,
        });
        af.add_entry(AnswerEntry {
            vuln_id: "V-1".to_string(), // Duplicate
            status: FindingStatus::Open,
            finding_details: None,
            comments: None,
            severity_override: None,
            severity_override_justification: None,
            force_override: false,
        });

        let issues = af.validate();
        assert!(issues.iter().any(|i| i.contains("empty")));
        assert!(issues.iter().any(|i| i.contains("Duplicate")));
        assert!(issues.iter().any(|i| i.contains("justification")));
    }
}
