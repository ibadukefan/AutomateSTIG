use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

/// A STIG benchmark — the top-level container for a set of security rules.
///
/// Maps to a DISA STIG (e.g., "Windows Server 2022 STIG V1R4").
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StigBenchmark {
    /// Unique benchmark identifier (e.g., "Windows_Server_2022_STIG").
    pub id: String,

    /// Human-readable title.
    pub title: String,

    /// Benchmark description.
    pub description: String,

    /// STIG version (e.g., "1").
    pub version: String,

    /// Release number (e.g., "4").
    pub release: String,

    /// Release date from DISA.
    pub release_date: Option<NaiveDate>,

    /// The XCCDF/SCAP benchmark ID if sourced from SCAP content.
    pub xccdf_id: Option<String>,

    /// Target platform/technology.
    pub platform: Platform,

    /// All rules in this benchmark.
    pub rules: Vec<StigRule>,
}

impl StigBenchmark {
    /// Get the full version string (e.g., "V1R4").
    pub fn version_string(&self) -> String {
        format!("V{}R{}", self.version, self.release)
    }

    /// Find a rule by its Vuln ID (e.g., "V-254239").
    pub fn find_rule_by_vuln_id(&self, vuln_id: &str) -> Option<&StigRule> {
        self.rules.iter().find(|r| r.vuln_id == vuln_id)
    }

    /// Get rules filtered by severity.
    pub fn rules_by_severity(&self, severity: Severity) -> Vec<&StigRule> {
        self.rules.iter().filter(|r| r.severity == severity).collect()
    }
}

/// A single STIG rule (vulnerability check).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StigRule {
    /// Vulnerability ID (e.g., "V-254239").
    pub vuln_id: String,

    /// Rule ID (e.g., "SV-254239r958388_rule").
    pub rule_id: String,

    /// Group ID / STIG ID (e.g., "V-254239").
    pub group_id: String,

    /// Rule title.
    pub title: String,

    /// Full discussion/description of the vulnerability.
    pub discussion: String,

    /// Severity category.
    pub severity: Severity,

    /// Check content — the procedure to verify compliance.
    pub check_content: String,

    /// Fix text — the procedure to remediate.
    pub fix_text: String,

    /// CCI references (e.g., ["CCI-000068"]).
    pub cci_refs: Vec<String>,

    /// Legacy IDs (e.g., ["SV-103625", "V-93537"]).
    pub legacy_ids: Vec<String>,

    /// STIGRef string (e.g., "Windows Server 2022 STIG :: V1R4").
    pub stig_ref: Option<String>,

    /// Rule weight (typically matches severity: CAT I=10, CAT II=8, CAT III=2).
    pub weight: f64,

    /// Whether this rule can be checked automatically.
    pub automatable: CheckAutomation,

    /// Automated check definition (if automatable).
    pub automated_check: Option<AutomatedCheck>,

    /// Associated remediation script IDs.
    pub remediation_ids: Vec<String>,
}

/// Severity / Category for a STIG rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Severity {
    /// CAT I — High severity. Directly causes loss of Confidentiality, Integrity, or Availability.
    #[serde(rename = "high")]
    High,

    /// CAT II — Medium severity. Potential for loss of C/I/A.
    #[serde(rename = "medium")]
    Medium,

    /// CAT III — Low severity. Degrades measures to protect against loss of C/I/A.
    #[serde(rename = "low")]
    Low,
}

impl Severity {
    pub fn from_cat_str(s: &str) -> Option<Self> {
        match s.to_lowercase().trim() {
            "high" | "cat i" | "cat_i" | "cati" | "i" => Some(Self::High),
            "medium" | "cat ii" | "cat_ii" | "catii" | "ii" => Some(Self::Medium),
            "low" | "cat iii" | "cat_iii" | "catiii" | "iii" => Some(Self::Low),
            _ => None,
        }
    }

    pub fn as_cat_str(&self) -> &'static str {
        match self {
            Self::High => "CAT I",
            Self::Medium => "CAT II",
            Self::Low => "CAT III",
        }
    }

    pub fn as_xccdf_str(&self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }

    pub fn default_weight(&self) -> f64 {
        match self {
            Self::High => 10.0,
            Self::Medium => 8.0,
            Self::Low => 2.0,
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_cat_str())
    }
}

/// Whether a rule can be automatically checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckAutomation {
    /// Fully automatable — the tool can determine status without human input.
    #[serde(rename = "full")]
    Full,

    /// Partially automatable — requires some human review.
    #[serde(rename = "partial")]
    Partial,

    /// Manual only — requires human review.
    #[serde(rename = "manual")]
    Manual,
}

/// Definition of an automated check that can be executed deterministically.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutomatedCheck {
    /// Type of check to perform.
    pub check_type: CheckType,

    /// Platform-specific check parameters.
    pub parameters: serde_json::Value,

    /// Expected result for a "Not a Finding" determination.
    pub expected: serde_json::Value,
}

/// Types of automated checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CheckType {
    /// Check a Windows registry key/value.
    RegistryCheck,

    /// Check a Windows security policy setting.
    SecurityPolicy,

    /// Check a Windows audit policy setting.
    AuditPolicy,

    /// Check a file permission.
    FilePermission,

    /// Check a service status/configuration.
    ServiceCheck,

    /// Check file content against a pattern.
    FileContentMatch,

    /// Execute a command and check output.
    CommandOutput,

    /// Check a Cisco IOS/NX-OS configuration line.
    CiscoConfigCheck,

    /// Check a Linux configuration file.
    LinuxConfigCheck,

    /// Check an XCCDF/OVAL result.
    XccdfResult,

    /// Custom check via script.
    CustomScript,
}

/// Target platform for a STIG benchmark.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Platform {
    /// Platform family (e.g., "windows", "linux", "network", "application").
    pub family: String,

    /// Specific OS/platform (e.g., "Windows Server 2022", "RHEL 9", "Cisco IOS").
    pub name: String,

    /// CPE identifiers if available.
    pub cpe: Vec<String>,
}

impl Default for Platform {
    fn default() -> Self {
        Self {
            family: "unknown".to_string(),
            name: "Unknown Platform".to_string(),
            cpe: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_from_str() {
        assert_eq!(Severity::from_cat_str("high"), Some(Severity::High));
        assert_eq!(Severity::from_cat_str("CAT I"), Some(Severity::High));
        assert_eq!(Severity::from_cat_str("medium"), Some(Severity::Medium));
        assert_eq!(Severity::from_cat_str("CAT II"), Some(Severity::Medium));
        assert_eq!(Severity::from_cat_str("low"), Some(Severity::Low));
        assert_eq!(Severity::from_cat_str("CAT III"), Some(Severity::Low));
        assert_eq!(Severity::from_cat_str("invalid"), None);
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(format!("{}", Severity::High), "CAT I");
        assert_eq!(format!("{}", Severity::Medium), "CAT II");
        assert_eq!(format!("{}", Severity::Low), "CAT III");
    }

    #[test]
    fn test_benchmark_version_string() {
        let benchmark = StigBenchmark {
            id: "test".to_string(),
            title: "Test STIG".to_string(),
            description: "Test".to_string(),
            version: "1".to_string(),
            release: "4".to_string(),
            release_date: None,
            xccdf_id: None,
            platform: Platform::default(),
            rules: vec![],
        };
        assert_eq!(benchmark.version_string(), "V1R4");
    }
}
