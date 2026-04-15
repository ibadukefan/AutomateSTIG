//! Automated check system.
//!
//! Provides a data-driven framework for executing STIG checks against
//! collected system data. Checks are defined as JSON/YAML rules that the
//! engine interprets — no code changes needed when DISA updates STIGs.
//!
//! Check types:
//! - Windows: registry, security policy, audit policy, services, features
//! - Linux: file content, file permissions, services, packages, sysctl
//! - Network: Cisco IOS/NX-OS/ASA config line checks
//! - Generic: command output matching, file existence

pub mod registry;
pub mod linux;
pub mod network;
pub mod executor;

use serde::{Deserialize, Serialize};

use crate::models::finding::FindingStatus;

/// A check definition — describes how to evaluate a single STIG rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckDefinition {
    /// Vuln ID this check applies to (e.g., "V-254239").
    pub vuln_id: String,

    /// Platform this check runs on.
    pub platform: CheckPlatform,

    /// The check to perform.
    pub check: Check,

    /// Expected result for "Not a Finding".
    pub expected: ExpectedResult,

    /// Human-readable description of what this check verifies.
    pub description: Option<String>,
}

/// Platform a check targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckPlatform {
    Windows,
    Linux,
    CiscoIos,
    CiscoNxos,
    CiscoAsa,
    Generic,
}

/// A specific check to perform.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Check {
    /// Check a Windows registry value.
    Registry {
        path: String,
        value_name: String,
        #[serde(default)]
        value_type: Option<String>,
    },

    /// Check a Windows security policy setting (secedit).
    SecurityPolicy {
        section: String,
        key: String,
    },

    /// Check a Windows audit policy setting (auditpol).
    AuditPolicy {
        subcategory: String,
        setting: String,
    },

    /// Check a Windows/Linux service status.
    Service {
        name: String,
        expected_status: ServiceStatus,
    },

    /// Check if a Windows feature/role is installed.
    WindowsFeature {
        name: String,
        should_be_installed: bool,
    },

    /// Check a file's content against a pattern.
    FileContent {
        path: String,
        pattern: String,
        #[serde(default)]
        is_regex: bool,
    },

    /// Check file/directory permissions.
    FilePermission {
        path: String,
        owner: Option<String>,
        group: Option<String>,
        mode: Option<String>,
    },

    /// Check a Linux sysctl value.
    Sysctl {
        key: String,
    },

    /// Check if a Linux package is installed.
    Package {
        name: String,
        should_be_installed: bool,
    },

    /// Check a network device config line.
    ConfigLine {
        pattern: String,
        context: Option<String>,
        #[serde(default)]
        should_exist: bool,
    },

    /// Run a command and check the output.
    Command {
        command: String,
        #[serde(default)]
        shell: Option<String>,
    },

    /// Multiple checks that must all pass (AND logic).
    All {
        checks: Vec<Check>,
    },

    /// Multiple checks where any can pass (OR logic).
    Any {
        checks: Vec<Check>,
    },
}

/// Expected service status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceStatus {
    Running,
    Stopped,
    Disabled,
}

/// Expected result for comparison.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ExpectedResult {
    /// Value must equal this exactly.
    Equals { value: serde_json::Value },

    /// Value must match this regex.
    Matches { pattern: String },

    /// Value must be >= this number.
    GreaterOrEqual { value: f64 },

    /// Value must be <= this number.
    LessOrEqual { value: f64 },

    /// Value must contain this substring.
    Contains { substring: String },

    /// Value must NOT contain this.
    NotContains { substring: String },

    /// Check must return true (for boolean checks like file exists, service running).
    IsTrue,

    /// Check must return false.
    IsFalse,

    /// For compound checks — all sub-results must pass.
    AllPass,
}

/// Result of executing a check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    /// The Vuln ID.
    pub vuln_id: String,

    /// Whether the check passed.
    pub passed: bool,

    /// The actual value found.
    pub actual_value: String,

    /// The expected value.
    pub expected_value: String,

    /// Detailed evidence / command output.
    pub evidence: String,

    /// Error message if the check failed to execute.
    pub error: Option<String>,
}

impl CheckResult {
    pub fn to_finding_status(&self) -> FindingStatus {
        if self.error.is_some() {
            FindingStatus::NotReviewed
        } else if self.passed {
            FindingStatus::NotAFinding
        } else {
            FindingStatus::Open
        }
    }
}

/// Collected system data that checks run against.
/// Instead of running live checks, we collect data first, then evaluate.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SystemData {
    /// Windows registry values.
    #[serde(default)]
    pub registry: std::collections::HashMap<String, serde_json::Value>,

    /// Windows security policy settings (secedit output).
    #[serde(default)]
    pub security_policy: std::collections::HashMap<String, String>,

    /// Windows audit policy settings (auditpol output).
    #[serde(default)]
    pub audit_policy: std::collections::HashMap<String, String>,

    /// Service statuses.
    #[serde(default)]
    pub services: std::collections::HashMap<String, String>,

    /// Installed packages/features.
    #[serde(default)]
    pub packages: std::collections::HashMap<String, bool>,

    /// File contents (path -> content).
    #[serde(default)]
    pub file_contents: std::collections::HashMap<String, String>,

    /// File permissions (path -> {owner, group, mode}).
    #[serde(default)]
    pub file_permissions: std::collections::HashMap<String, FilePermData>,

    /// Sysctl values.
    #[serde(default)]
    pub sysctl: std::collections::HashMap<String, String>,

    /// Network device config (full running config).
    #[serde(default)]
    pub network_config: Option<String>,

    /// Command outputs (command -> output).
    #[serde(default)]
    pub command_outputs: std::collections::HashMap<String, String>,

    /// Platform identifier.
    #[serde(default)]
    pub platform: String,

    /// Hostname.
    #[serde(default)]
    pub hostname: String,
}

/// File permission data.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FilePermData {
    pub owner: Option<String>,
    pub group: Option<String>,
    pub mode: Option<String>,
    pub exists: bool,
}

/// A set of check definitions for a specific STIG.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckPack {
    /// STIG ID these checks apply to.
    pub stig_id: String,

    /// Platform.
    pub platform: CheckPlatform,

    /// Version of the check pack.
    pub version: String,

    /// Individual check definitions.
    pub checks: Vec<CheckDefinition>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_definition_json_roundtrip() {
        let check = CheckDefinition {
            vuln_id: "V-254239".to_string(),
            platform: CheckPlatform::Windows,
            check: Check::Registry {
                path: r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client".to_string(),
                value_name: "Enabled".to_string(),
                value_type: Some("REG_DWORD".to_string()),
            },
            expected: ExpectedResult::Equals {
                value: serde_json::json!(1),
            },
            description: Some("TLS 1.2 must be enabled".to_string()),
        };

        let json = serde_json::to_string_pretty(&check).unwrap();
        let parsed: CheckDefinition = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.vuln_id, "V-254239");
    }

    #[test]
    fn test_compound_check() {
        let check = CheckDefinition {
            vuln_id: "V-100001".to_string(),
            platform: CheckPlatform::Linux,
            check: Check::All {
                checks: vec![
                    Check::FileContent {
                        path: "/etc/ssh/sshd_config".to_string(),
                        pattern: "PermitRootLogin no".to_string(),
                        is_regex: false,
                    },
                    Check::Service {
                        name: "sshd".to_string(),
                        expected_status: ServiceStatus::Running,
                    },
                ],
            },
            expected: ExpectedResult::AllPass,
            description: None,
        };

        let json = serde_json::to_string(&check).unwrap();
        assert!(json.contains("all"));
    }

    #[test]
    fn test_check_pack_json() {
        let pack = CheckPack {
            stig_id: "Windows_Server_2022_STIG".to_string(),
            platform: CheckPlatform::Windows,
            version: "1.0.0".to_string(),
            checks: vec![CheckDefinition {
                vuln_id: "V-254239".to_string(),
                platform: CheckPlatform::Windows,
                check: Check::Registry {
                    path: "HKLM\\TEST".to_string(),
                    value_name: "Value1".to_string(),
                    value_type: None,
                },
                expected: ExpectedResult::Equals {
                    value: serde_json::json!(1),
                },
                description: None,
            }],
        };

        let json = serde_json::to_string_pretty(&pack).unwrap();
        let parsed: CheckPack = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.checks.len(), 1);
    }
}
