//! Device configuration dump parser.
//!
//! Parses raw device configuration output (e.g., "show running-config" from
//! Cisco devices) and extracts structured data for STIG evaluation.

use automatestig_core::models::scan::ScanResult;

use crate::error::ParseResult;

/// Configuration dump type.
#[derive(Debug, Clone, Copy)]
pub enum ConfigType {
    /// Cisco IOS / IOS-XE "show running-config".
    CiscoIos,
    /// Cisco NX-OS "show running-config".
    CiscoNxos,
    /// Cisco ASA "show running-config".
    CiscoAsa,
    /// Generic Linux config files.
    Linux,
}

/// A parsed configuration line with context.
#[derive(Debug, Clone)]
pub struct ConfigLine {
    /// The raw line text.
    pub text: String,
    /// Indentation level (for hierarchical configs like Cisco).
    pub indent: usize,
    /// Line number in the original file.
    pub line_number: usize,
    /// Parent context (e.g., "interface GigabitEthernet0/0").
    pub context: Option<String>,
}

/// A parsed device configuration.
#[derive(Debug, Clone)]
pub struct DeviceConfig {
    /// Type of configuration.
    pub config_type: ConfigType,
    /// Hostname extracted from config.
    pub hostname: Option<String>,
    /// All configuration lines with context.
    pub lines: Vec<ConfigLine>,
    /// Raw configuration text.
    pub raw: String,
}

/// Parse a Cisco IOS-style configuration dump.
pub fn parse_cisco_config(raw: &str, config_type: ConfigType) -> ParseResult<DeviceConfig> {
    let mut lines = Vec::new();
    let mut hostname = None;
    let mut current_context: Option<String> = None;

    for (line_num, raw_line) in raw.lines().enumerate() {
        let indent = raw_line.len() - raw_line.trim_start().len();
        let trimmed = raw_line.trim();

        // Skip empty lines and comments.
        if trimmed.is_empty() || trimmed.starts_with('!') {
            continue;
        }

        // Extract hostname.
        if trimmed.starts_with("hostname ") {
            hostname = Some(trimmed.strip_prefix("hostname ").unwrap().trim().to_string());
        }

        // Track context (top-level blocks).
        if indent == 0 && !trimmed.starts_with("!") {
            // New top-level section — could be a context line like "interface ..." or "router ..."
            if is_context_line(trimmed) {
                current_context = Some(trimmed.to_string());
            } else {
                current_context = None;
            }
        }

        lines.push(ConfigLine {
            text: trimmed.to_string(),
            indent,
            line_number: line_num + 1,
            context: current_context.clone(),
        });
    }

    Ok(DeviceConfig {
        config_type,
        hostname,
        lines,
        raw: raw.to_string(),
    })
}

/// Check if a configuration section/line is present.
pub fn config_contains(config: &DeviceConfig, pattern: &str) -> bool {
    config
        .lines
        .iter()
        .any(|l| l.text.contains(pattern))
}

/// Find all lines matching a pattern, optionally within a context.
pub fn find_config_lines<'a>(
    config: &'a DeviceConfig,
    pattern: &str,
    context: Option<&str>,
) -> Vec<&'a ConfigLine> {
    config
        .lines
        .iter()
        .filter(|l| {
            let matches_pattern = l.text.contains(pattern);
            let matches_context = context
                .map(|ctx| {
                    l.context
                        .as_ref()
                        .map(|c| c.contains(ctx))
                        .unwrap_or(false)
                })
                .unwrap_or(true);
            matches_pattern && matches_context
        })
        .collect()
}

/// Evaluate a config check rule against a device configuration.
///
/// Returns a ScanResult indicating pass/fail based on whether
/// the expected configuration is present.
pub fn evaluate_config_check(
    config: &DeviceConfig,
    rule_ref: &str,
    expected_present: &[&str],
    expected_absent: &[&str],
    context: Option<&str>,
) -> ScanResult {
    let mut evidence_parts = Vec::new();
    let mut all_present = true;
    let mut all_absent = true;

    for pattern in expected_present {
        let found_lines = find_config_lines(config, pattern, context);
        if found_lines.is_empty() {
            all_present = false;
            evidence_parts.push(format!("MISSING: '{}'", pattern));
        } else {
            evidence_parts.push(format!(
                "FOUND: '{}' at line {}",
                pattern,
                found_lines[0].line_number
            ));
        }
    }

    for pattern in expected_absent {
        let found_lines = find_config_lines(config, pattern, context);
        if !found_lines.is_empty() {
            all_absent = false;
            evidence_parts.push(format!(
                "UNEXPECTED: '{}' found at line {}",
                pattern,
                found_lines[0].line_number
            ));
        }
    }

    let passed = all_present && all_absent;

    ScanResult {
        rule_ref: rule_ref.to_string(),
        passed: Some(passed),
        raw_result: if passed { "pass" } else { "fail" }.to_string(),
        evidence: Some(evidence_parts.join("\n")),
        benchmark_ref: None,
    }
}

fn is_context_line(line: &str) -> bool {
    let context_prefixes = [
        "interface ",
        "router ",
        "ip access-list ",
        "route-map ",
        "class-map ",
        "policy-map ",
        "crypto ",
        "line ",
        "vlan ",
        "spanning-tree ",
        "aaa ",
        "snmp-server ",
        "ntp ",
        "logging ",
        "banner ",
    ];
    context_prefixes.iter().any(|prefix| line.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_cisco_config() -> &'static str {
        r#"!
hostname CORE-RTR-01
!
service timestamps debug datetime msec
service timestamps log datetime msec
service password-encryption
!
enable secret 9 $9$hash
!
aaa new-model
aaa authentication login default local
!
interface GigabitEthernet0/0
 description Uplink to Distribution
 ip address 10.0.1.1 255.255.255.0
 no shutdown
!
interface GigabitEthernet0/1
 description Management
 ip address 192.168.1.1 255.255.255.0
 shutdown
!
ip ssh version 2
ip ssh time-out 60
!
banner login ^
Authorized users only. All activity is monitored.
^
!
line con 0
 exec-timeout 10 0
 logging synchronous
line vty 0 4
 exec-timeout 10 0
 transport input ssh
!
ntp server 10.0.0.100
!
end"#
    }

    #[test]
    fn test_parse_cisco_config() {
        let config = parse_cisco_config(sample_cisco_config(), ConfigType::CiscoIos).unwrap();

        assert_eq!(config.hostname.as_deref(), Some("CORE-RTR-01"));
        assert!(!config.lines.is_empty());
    }

    #[test]
    fn test_config_contains() {
        let config = parse_cisco_config(sample_cisco_config(), ConfigType::CiscoIos).unwrap();

        assert!(config_contains(&config, "service password-encryption"));
        assert!(config_contains(&config, "ip ssh version 2"));
        assert!(!config_contains(&config, "telnet"));
    }

    #[test]
    fn test_find_config_lines_with_context() {
        let config = parse_cisco_config(sample_cisco_config(), ConfigType::CiscoIos).unwrap();

        let ssh_lines = find_config_lines(&config, "transport input ssh", Some("line vty"));
        assert_eq!(ssh_lines.len(), 1);

        let all_shutdown = find_config_lines(&config, "shutdown", None);
        assert!(all_shutdown.len() >= 2); // "no shutdown" and "shutdown"
    }

    #[test]
    fn test_evaluate_config_check() {
        let config = parse_cisco_config(sample_cisco_config(), ConfigType::CiscoIos).unwrap();

        // Check: SSH v2 should be present, telnet should be absent.
        let result = evaluate_config_check(
            &config,
            "V-100001",
            &["ip ssh version 2"],
            &["transport input telnet"],
            None,
        );
        assert_eq!(result.passed, Some(true));

        // Check: Should fail if we require something missing.
        let result2 = evaluate_config_check(
            &config,
            "V-100002",
            &["ip ssh version 2", "nonexistent-command"],
            &[],
            None,
        );
        assert_eq!(result2.passed, Some(false));
    }
}
