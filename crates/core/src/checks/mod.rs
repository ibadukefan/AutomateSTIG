//! Automated check system.
//!
//! Provides a data-driven framework for executing STIG checks against
//! collected system data. Checks are defined as JSON/YAML rules that the
//! engine interprets — no code changes needed when DISA updates STIGs.
//!
//! Check types:
//! - Cisco IOS-XE running-configuration line checks
//! - ONTAP and FreeBSD command-output matching

pub mod executor;
pub mod network;

use serde::{Deserialize, Serialize};

use crate::models::finding::FindingStatus;

/// A check definition — describes how to evaluate a single STIG rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckPlatform {
    #[serde(rename = "cisco_ios", alias = "ciscoios")]
    CiscoIos,
    Ontap,
    Bsd,
}

/// A specific check to perform.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Check {
    /// Check a Cisco IOS-XE running-configuration line.
    ConfigLine {
        pattern: String,
        context: Option<String>,
        #[serde(default)]
        should_exist: bool,
    },

    /// Check reviewed ONTAP or FreeBSD command output.
    Command {
        command: String,
        /// Optional predicate used by curated UNIX command checks.
        #[serde(default)]
        pattern: Option<String>,
        #[serde(default)]
        is_regex: bool,
    },

    /// Multiple checks that must all pass (AND logic).
    All { checks: Vec<Check> },

    /// Multiple checks where any can pass (OR logic).
    Any { checks: Vec<Check> },

    /// Organization-policy-bound concurrent VTY/HTTP management-session limit.
    CiscoVtySessionLimit,

    /// Organization-policy-bound IOS-XE in-memory audit buffer capacity.
    CiscoLoggingBufferCapacity,

    /// Effective IOS-XE remote logging severity includes critical events.
    CiscoLoggingTrapSeverity,
}

impl Check {
    pub fn requires_organization_policy(&self) -> bool {
        match self {
            Self::CiscoVtySessionLimit | Self::CiscoLoggingBufferCapacity => true,
            Self::All { checks } | Self::Any { checks } => {
                checks.iter().any(Self::requires_organization_policy)
            }
            _ => false,
        }
    }
}

/// Expected result for comparison.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExpectedResult {
    /// Value must match this regex.
    Matches { pattern: String },

    /// The regex `pattern` must match at least `min` times in the actual value.
    MatchCountAtLeast { pattern: String, min: usize },

    /// Value must NOT contain this.
    NotContains { substring: String },

    /// Check must return true (for boolean checks like file exists, service running).
    IsTrue,
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
    /// Whether every command required by the collection plan produced trusted evidence.
    #[serde(default)]
    pub collection_complete: bool,

    /// Collection failures keyed by the same data key used by the check plan.
    /// Diagnostic stdout is deliberately not stored here or in `command_outputs`.
    #[serde(default)]
    pub collection_errors: std::collections::HashMap<String, String>,

    /// Cisco IOS-XE running configuration.
    #[serde(default)]
    pub network_config: Option<String>,

    /// Command outputs (command -> output).
    #[serde(default)]
    pub command_outputs: std::collections::HashMap<String, String>,

    /// Verified, asset-bound organization parameters. Never deserialize this
    /// from a device evidence document.
    #[serde(skip)]
    pub organization_policy: Option<crate::organization_policy::VerifiedOrganizationPolicy>,
}

/// A set of check definitions for a specific STIG.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckPack {
    /// STIG ID these checks apply to.
    pub stig_id: String,

    /// Platform.
    pub platform: CheckPlatform,

    /// Version of the check pack.
    pub version: String,

    /// Precedence among check packs. Lower values take precedence.
    #[serde(default = "default_pack_priority")]
    pub priority: i32,

    /// Individual check definitions.
    pub checks: Vec<CheckDefinition>,
}

fn default_pack_priority() -> i32 {
    100
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_platforms_roundtrip() {
        assert_eq!(
            serde_json::from_str::<CheckPlatform>("\"cisco_ios\"").unwrap(),
            CheckPlatform::CiscoIos
        );
        assert_eq!(
            serde_json::from_str::<CheckPlatform>("\"ciscoios\"").unwrap(),
            CheckPlatform::CiscoIos
        );
        assert_eq!(
            serde_json::to_string(&CheckPlatform::CiscoIos).unwrap(),
            "\"cisco_ios\""
        );
        assert_eq!(
            serde_json::from_str::<CheckPlatform>("\"ontap\"").unwrap(),
            CheckPlatform::Ontap
        );
        assert_eq!(
            serde_json::from_str::<CheckPlatform>("\"bsd\"").unwrap(),
            CheckPlatform::Bsd
        );
        assert_eq!(
            serde_json::to_string(&CheckPlatform::Bsd).unwrap(),
            "\"bsd\""
        );
    }

    #[test]
    fn test_check_definition_json_roundtrip() {
        let check = CheckDefinition {
            vuln_id: "V-100001".to_string(),
            platform: CheckPlatform::Bsd,
            check: Check::Command {
                command: "sysctl kern.elf64.aslr.enable".to_string(),
                pattern: None,
                is_regex: false,
            },
            expected: ExpectedResult::Matches {
                pattern: "^0$".to_string(),
            },
            description: Some("IP forwarding must be disabled".to_string()),
        };

        let json = serde_json::to_string_pretty(&check).unwrap();
        let parsed: CheckDefinition = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.vuln_id, "V-100001");
    }

    #[test]
    fn test_compound_check() {
        let check = CheckDefinition {
            vuln_id: "V-100001".to_string(),
            platform: CheckPlatform::Bsd,
            check: Check::All {
                checks: vec![
                    Check::Command {
                        command: "cat /etc/ssh/sshd_config".to_string(),
                        pattern: Some("PermitRootLogin no".to_string()),
                        is_regex: false,
                    },
                    Check::Command {
                        command: "freebsd-version -k".to_string(),
                        pattern: Some("14".to_string()),
                        is_regex: false,
                    },
                ],
            },
            expected: ExpectedResult::IsTrue,
            description: None,
        };

        let json = serde_json::to_string(&check).unwrap();
        assert!(json.contains("all"));
    }

    #[test]
    fn test_check_pack_json() {
        let pack = CheckPack {
            stig_id: "General_Purpose_Operating_System".to_string(),
            platform: CheckPlatform::Bsd,
            version: "1.0.0".to_string(),
            priority: 100,
            checks: vec![CheckDefinition {
                vuln_id: "V-100001".to_string(),
                platform: CheckPlatform::Bsd,
                check: Check::Command {
                    command: "sysctl kern.elf64.aslr.enable".to_string(),
                    pattern: None,
                    is_regex: false,
                },
                expected: ExpectedResult::Matches {
                    pattern: "^1$".to_string(),
                },
                description: None,
            }],
        };

        let json = serde_json::to_string_pretty(&pack).unwrap();
        let parsed: CheckPack = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.checks.len(), 1);
    }
}
