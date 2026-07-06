//! XCCDF check-content to CheckDefinition converter.
//!
//! Parses the human-readable check-content text from DISA XCCDF benchmarks
//! and auto-generates executable CheckDefinition structs by pattern-matching
//! common phrases like:
//!
//! - "If the registry value ... is not set to 1, this is a finding"
//! - "If the output of `sysctl ...` is not 0, this is a finding"
//! - "If the line '...' is not in /etc/ssh/sshd_config, this is a finding"
//! - "If the service ... is not running, this is a finding"
//!
//! Rules that can't be pattern-matched are flagged as manual review.

use regex::Regex;
use std::sync::LazyLock;

use crate::checks::*;
use crate::models::stig::{StigBenchmark, StigRule};

/// Result of converting an XCCDF benchmark to a check pack.
#[derive(Debug)]
pub struct ConversionResult {
    /// The generated check pack.
    pub check_pack: CheckPack,

    /// Number of rules auto-converted to checks.
    pub automated: usize,

    /// Number of rules that couldn't be auto-converted.
    pub manual: usize,

    /// Details about conversion decisions.
    pub log: Vec<String>,
}

/// Convert an entire XCCDF benchmark into a check pack.
pub fn convert_benchmark(benchmark: &StigBenchmark) -> ConversionResult {
    let platform = detect_platform(benchmark);
    let mut checks = Vec::new();
    let mut automated = 0;
    let mut manual = 0;
    let mut log = Vec::new();

    for rule in &benchmark.rules {
        match convert_rule(rule, platform) {
            Some(check_def) => {
                checks.push(check_def);
                automated += 1;
            }
            None => {
                manual += 1;
                log.push(format!(
                    "{}: manual — no pattern match in check content",
                    rule.vuln_id
                ));
            }
        }
    }

    log.insert(
        0,
        format!(
            "Converted {}/{} rules ({:.0}% automated)",
            automated,
            automated + manual,
            if automated + manual > 0 {
                automated as f64 / (automated + manual) as f64 * 100.0
            } else {
                0.0
            }
        ),
    );

    ConversionResult {
        check_pack: CheckPack {
            stig_id: benchmark.id.clone(),
            platform,
            version: format!("auto-{}", chrono::Utc::now().format("%Y%m%d")),
            checks,
        },
        automated,
        manual,
        log,
    }
}

/// Try to convert a single STIG rule into a CheckDefinition.
fn convert_rule(rule: &StigRule, platform: CheckPlatform) -> Option<CheckDefinition> {
    let text = &rule.check_content;
    if text.is_empty() {
        return None;
    }

    // Try each pattern matcher in priority order.
    let check = match platform {
        CheckPlatform::Windows => try_windows_patterns(text),
        CheckPlatform::Linux => try_linux_patterns(text),
        CheckPlatform::CiscoIos | CheckPlatform::CiscoNxos | CheckPlatform::CiscoAsa => {
            try_network_patterns(text)
        }
        CheckPlatform::Generic => try_generic_patterns(text),
    };

    // If platform-specific didn't match, try generic.
    let check = check.or_else(|| try_generic_patterns(text));

    check.map(|(check, expected, desc)| CheckDefinition {
        vuln_id: rule.vuln_id.clone(),
        platform,
        check,
        expected,
        description: Some(desc),
    })
}

/// Detect the platform from benchmark metadata.
fn detect_platform(benchmark: &StigBenchmark) -> CheckPlatform {
    let id_lower = benchmark.id.to_lowercase();
    let title_lower = benchmark.title.to_lowercase();
    let combined = format!("{} {}", id_lower, title_lower);

    if combined.contains("windows") || combined.contains("win_") || combined.contains("microsoft") {
        CheckPlatform::Windows
    } else if combined.contains("rhel")
        || combined.contains("ubuntu")
        || combined.contains("linux")
        || combined.contains("suse")
        || combined.contains("centos")
        || combined.contains("debian")
        || combined.contains("oracle_linux")
        || combined.contains("amazon_linux")
    {
        CheckPlatform::Linux
    } else if combined.contains("cisco_ios") || combined.contains("ios_xe") {
        CheckPlatform::CiscoIos
    } else if combined.contains("nx-os") || combined.contains("nxos") {
        CheckPlatform::CiscoNxos
    } else if combined.contains("cisco_asa") || combined.contains("adaptive_security") {
        CheckPlatform::CiscoAsa
    } else if combined.contains("vmware") || combined.contains("esxi") {
        CheckPlatform::Linux // ESXi uses Linux-style checks
    } else {
        CheckPlatform::Generic
    }
}

// ---------------------------------------------------------------------------
// Windows pattern matchers
// ---------------------------------------------------------------------------

static RE_REGISTRY_BLOCK_HIVE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?im)^\s*Registry\s+Hive:\s*(HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)").unwrap()
});

static RE_REGISTRY_BLOCK_PATH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?im)^\s*Registry\s+Path:\s*([^\r\n]+)").unwrap());

static RE_REGISTRY_BLOCK_VALUE_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?im)^\s*Value\s+Name:\s*([^\r\n]+)").unwrap());

static RE_REGISTRY_BLOCK_TYPE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?im)^\s*(?:Value\s+)?Type:\s*(REG_\w+)").unwrap());

static RE_REGISTRY_BLOCK_VALUE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?im)^\s*Value:\s*(0x[0-9a-fA-F]+)\s*\((\d+)\)([^\r\n]*)").unwrap()
});

static RE_REGISTRY_SIMPLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:HKLM|HKEY_LOCAL_MACHINE)\\([\w\\ ]+?)[\s.,].*?(?:value\s+(?:name\s+)?)?(?:"|')?(\w{3,})(?:"|')?\s+(?:REG_\w+\s+)?(?:is\s+not\s+set\s+to|is\s+not\s+|must\s+be\s+|not\s+set\s+to\s+|set\s+to\s+).*?(\d+)"#).unwrap()
});

static RE_SECEDIT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:security\s+policy|secedit|local\s+security|password\s+policy|account\s+polic).*?(?:"|')?(\w+(?:Password\w*|Lockout\w*|Complexity|ClearText\w*|History\w*|Admin\w*|Guest\w*))(?:"|')?\s+.*?(?:is\s+not\s+|must\s+be\s+|not\s+set\s+to\s+)(?:set\s+to\s+|configured\s+to\s+|at\s+least\s+|no\s+(?:more|greater)\s+than\s+)?(?:"|')?(\d+)"#).unwrap()
});

static RE_AUDITPOL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:audit(?:pol|ing)?|audit\s+policy).*?(?:"|')?([\w /]+?)(?:"|')?\s+.*?(?:Success|Failure)"#).unwrap()
});

fn try_registry_block(text: &str) -> Option<(Check, ExpectedResult, String)> {
    let hive = RE_REGISTRY_BLOCK_HIVE.captures(text)?.get(1)?.as_str();
    let raw_path = RE_REGISTRY_BLOCK_PATH.captures(text)?.get(1)?.as_str();
    let value_name = RE_REGISTRY_BLOCK_VALUE_NAME
        .captures(text)?
        .get(1)?
        .as_str()
        .trim()
        .to_string();
    let value_type = RE_REGISTRY_BLOCK_TYPE.captures(text)?.get(1)?.as_str();

    if !value_type.eq_ignore_ascii_case("REG_DWORD") || value_name.is_empty() {
        return None;
    }

    let value_caps = RE_REGISTRY_BLOCK_VALUE.captures(text)?;
    let decimal = value_caps.get(2)?.as_str().parse::<i64>().ok()?;
    let tail = value_caps.get(3)?.as_str().to_lowercase();

    if tail.contains(" or 0x") || tail.contains(", 0x") {
        return None;
    }

    let expected = if tail.contains("or greater")
        || tail.contains("or more")
        || tail.contains("at least")
    {
        ExpectedResult::GreaterOrEqual {
            value: decimal as f64,
        }
    } else if tail.contains("or less") || tail.contains("or lower") || tail.contains("no more than")
    {
        ExpectedResult::LessOrEqual {
            value: decimal as f64,
        }
    } else if !tail.trim().is_empty() && tail.chars().any(|c| c.is_ascii_alphabetic()) {
        return None;
    } else {
        ExpectedResult::Equals {
            value: serde_json::json!(decimal),
        }
    };

    let hive_prefix = if hive.eq_ignore_ascii_case("HKEY_LOCAL_MACHINE") {
        "HKLM"
    } else if hive.eq_ignore_ascii_case("HKEY_CURRENT_USER") {
        "HKCU"
    } else {
        return None;
    };
    let path_trimmed = raw_path.trim();
    if path_trimmed.is_empty() {
        return None;
    }
    let path_trimmed = path_trimmed.strip_suffix('\\').unwrap_or(path_trimmed);
    let path = format!("{}\\{}", hive_prefix, path_trimmed.trim_start_matches('\\'));

    Some((
        Check::Registry {
            path,
            value_name: value_name.clone(),
            value_type: Some("REG_DWORD".to_string()),
        },
        expected,
        format!("Auto: registry check for {}", value_name),
    ))
}

fn try_windows_patterns(text: &str) -> Option<(Check, ExpectedResult, String)> {
    if let Some(result) = try_registry_block(text) {
        return Some(result);
    }

    // Pattern: Registry value with specific path and expected value.
    if let Some(caps) = RE_REGISTRY_SIMPLE.captures(text) {
        let path = format!("HKLM\\{}", &caps[1]);
        let value_name = caps[2].to_string();
        let expected_val: serde_json::Value = caps[3]
            .parse::<i64>()
            .map(|v| serde_json::json!(v))
            .unwrap_or(serde_json::json!(&caps[3]));

        return Some((
            Check::Registry {
                path,
                value_name: value_name.clone(),
                value_type: None,
            },
            ExpectedResult::Equals {
                value: expected_val,
            },
            format!("Auto: registry check for {}", value_name),
        ));
    }

    // Pattern: Security policy setting.
    if let Some(caps) = RE_SECEDIT.captures(text) {
        let key = caps[1].to_string();
        let value = caps[2].to_string();

        let expected = if text.to_lowercase().contains("at least")
            || text.to_lowercase().contains("or greater")
            || text.to_lowercase().contains("or more")
        {
            ExpectedResult::GreaterOrEqual {
                value: value.parse().unwrap_or(0.0),
            }
        } else if text.to_lowercase().contains("no more than")
            || text.to_lowercase().contains("or less")
            || text.to_lowercase().contains("not exceed")
        {
            ExpectedResult::LessOrEqual {
                value: value.parse().unwrap_or(0.0),
            }
        } else {
            ExpectedResult::Equals {
                value: serde_json::json!(value),
            }
        };

        return Some((
            Check::SecurityPolicy {
                section: "System Access".to_string(),
                key: key.clone(),
            },
            expected,
            format!("Auto: security policy check for {}", key),
        ));
    }

    // Pattern: Audit policy.
    if let Some(caps) = RE_AUDITPOL.captures(text) {
        let subcategory = caps[1].trim().to_string();
        return Some((
            Check::AuditPolicy {
                subcategory: subcategory.clone(),
                setting: "Success and Failure".to_string(),
            },
            ExpectedResult::Contains {
                substring: "Success".to_string(),
            },
            format!("Auto: audit policy check for {}", subcategory),
        ));
    }

    // Pattern: Service must be running/stopped.
    try_service_pattern(text)
}

// ---------------------------------------------------------------------------
// Linux pattern matchers
// ---------------------------------------------------------------------------

static RE_SYSCTL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)sysctl\s+(?:-[aw]\s+)?(?:"|'|`)?([a-z0-9_.]+)(?:"|'|`)?\s*.*?(?:is\s+not\s+|must\s+be\s+|=\s*|value\s+of\s+)(?:"|'|`)?(\d+)"#).unwrap()
});

static RE_SYSCTL_DISA_CMD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)sysctl\s+([a-z][a-z0-9_.]+)").unwrap());

static RE_SYSTEMCTL_DISA: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)systemctl\s+is-(?:enabled|active|failed)\s+([a-z0-9_.@-]+)").unwrap()
});

static RE_FILE_CONTENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:in\s+|file\s+)?(?:"|'|`)?(/etc/[\w/._-]+)(?:"|'|`)?\s*.*?(?:line|contains?|set\s+to|configured\s+(?:to|with))\s+(?:"|'|`)?([A-Za-z]\w+\s+\S+)"#).unwrap()
});

static RE_FILE_PERM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:permissions?|mode)\s+(?:of\s+|on\s+|for\s+)?(?:"|'|`)?(/[\w/._-]+?)(?:"|'|`)?[\s.,].*?(?:must\s+be|is\s+not|more\s+permissive\s+than)\s+(?:"|'|`)?(\d{3,4})"#).unwrap()
});

static RE_PACKAGE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:package|rpm|dpkg)\s+(?:"|'|`)?(\S+?)(?:"|'|`)?\s+(?:is\s+not\s+installed|must\s+be\s+installed|must\s+not\s+be\s+installed)"#).unwrap()
});

fn try_sysctl_disa(text: &str) -> Option<(Check, ExpectedResult, String)> {
    let key = RE_SYSCTL_DISA_CMD
        .captures(text)?
        .get(1)?
        .as_str()
        .to_string();
    let output_re = Regex::new(&format!(r"(?m)^\s*{}\s*=\s*(\S+)", regex::escape(&key))).ok()?;
    let value = output_re.captures(text)?.get(1)?.as_str();
    let expected = match value.parse::<i64>() {
        Ok(value) => ExpectedResult::Equals {
            value: serde_json::json!(value),
        },
        Err(_) => ExpectedResult::Equals {
            value: serde_json::json!(value),
        },
    };

    Some((
        Check::Sysctl { key: key.clone() },
        expected,
        format!("Auto: sysctl check for {}", key),
    ))
}

fn try_systemd_disa(text: &str) -> Option<(Check, ExpectedResult, String)> {
    let lower = text.to_lowercase();
    if lower.contains("ask the system administrator")
        || lower.contains("interview")
        || lower.contains("is documented")
        || lower.contains("operational requirement")
    {
        return None;
    }

    let service = RE_SYSTEMCTL_DISA.captures(text)?.get(1)?.as_str();
    let name = service
        .strip_suffix(".service")
        .unwrap_or(service)
        .to_string();
    let expected_status = if lower.contains("must be masked")
        || lower.contains("must be disabled")
        || lower.contains("must be inactive")
        || lower.contains("must be stopped")
        || lower.contains("must not be active")
        || lower.contains("must not be running")
        || lower.contains("must not be enabled")
        || lower.contains("is active, this is a finding")
        || lower.contains("is enabled, this is a finding")
        || lower.contains("is running, this is a finding")
    {
        ServiceStatus::Disabled
    } else if lower.contains("enabled and active")
        || lower.contains("enabled and running")
        || lower.contains("active and enabled")
        || lower.contains("must be enabled")
        || lower.contains("must be active")
        || lower.contains("must be running")
    {
        ServiceStatus::Running
    } else {
        return None;
    };

    Some((
        Check::Service {
            name: name.clone(),
            expected_status,
        },
        ExpectedResult::IsTrue,
        format!("Auto: service '{}' must be {:?}", name, expected_status),
    ))
}

fn try_linux_patterns(text: &str) -> Option<(Check, ExpectedResult, String)> {
    if let Some(r) = try_sysctl_disa(text) {
        return Some(r);
    }
    if let Some(r) = try_systemd_disa(text) {
        return Some(r);
    }

    let lower = text.to_lowercase();

    // Pattern: sysctl value.
    if let Some(caps) = RE_SYSCTL.captures(text) {
        let key = caps[1].to_string();
        let value = caps[2].to_string();
        return Some((
            Check::Sysctl { key: key.clone() },
            ExpectedResult::Equals {
                value: serde_json::json!(value),
            },
            format!("Auto: sysctl check for {}", key),
        ));
    }

    // Pattern: File content check.
    if let Some(caps) = RE_FILE_CONTENT.captures(text) {
        let path = caps[1].to_string();
        let pattern = caps[2].trim().to_string();
        return Some((
            Check::FileContent {
                path: path.clone(),
                pattern: pattern.clone(),
                is_regex: false,
            },
            ExpectedResult::IsTrue,
            format!("Auto: file content check in {} for '{}'", path, pattern),
        ));
    }

    // Pattern: File permissions.
    if let Some(caps) = RE_FILE_PERM.captures(text) {
        let path = caps[1].to_string();
        let mode = format!("0{}", &caps[2]);
        return Some((
            Check::FilePermission {
                path: path.clone(),
                owner: None,
                group: None,
                mode: Some(mode.clone()),
            },
            ExpectedResult::IsTrue,
            format!("Auto: file permission check for {} (mode {})", path, mode),
        ));
    }

    // Pattern: Package installed/not installed.
    if let Some(caps) = RE_PACKAGE.captures(text) {
        if !(lower.contains("ask the system administrator")
            || lower.contains("interview")
            || lower.contains("is documented")
            || lower.contains("operational requirement"))
        {
            let name = caps[1].to_string();
            let should_be_installed = !lower.contains("must not be installed")
                && !lower.contains("is not installed")
                && !lower.contains("should not be installed")
                && !lower.contains("remove");

            return Some((
                Check::Package {
                    name: name.clone(),
                    should_be_installed,
                },
                ExpectedResult::IsTrue,
                format!(
                    "Auto: package '{}' must {} installed",
                    name,
                    if should_be_installed { "be" } else { "not be" }
                ),
            ));
        }
    }

    // Pattern: Service must be running/enabled.
    try_service_pattern(text)
}

// ---------------------------------------------------------------------------
// Network pattern matchers
// ---------------------------------------------------------------------------

static RE_CONFIG_LINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:verify|check|ensure|confirm).*?(?:"|'|`)([\w\s-]+?)(?:"|'|`)\s+(?:is\s+)?(?:configured|present|enabled|set)"#).unwrap()
});

fn try_network_patterns(text: &str) -> Option<(Check, ExpectedResult, String)> {
    let lower = text.to_lowercase();

    // Pattern: Specific config line patterns.
    let config_patterns = [
        ("ssh version 2", "ip ssh version 2"),
        ("aaa new-model", "aaa new-model"),
        ("service password-encryption", "service password-encryption"),
        ("exec-timeout", "exec-timeout"),
        ("transport input ssh", "transport input ssh"),
        ("logging buffered", "logging buffered"),
        ("ntp server", "ntp server"),
        ("banner login", "banner login"),
        ("no ip source-route", "no ip source-route"),
        ("no ip http server", "no ip http server"),
        ("no cdp run", "no cdp run"),
        ("snmp-server group", "snmp-server group"),
    ];

    for (keyword, pattern) in &config_patterns {
        if lower.contains(keyword) {
            let should_exist = !lower.contains("must not")
                && !lower.contains("must be disabled")
                && !lower.contains("should not");

            return Some((
                Check::ConfigLine {
                    pattern: pattern.to_string(),
                    context: None,
                    should_exist,
                },
                ExpectedResult::IsTrue,
                format!("Auto: config line check for '{}'", pattern),
            ));
        }
    }

    // Generic config line from quoted text.
    if let Some(caps) = RE_CONFIG_LINE.captures(text) {
        let pattern = caps[1].trim().to_string();
        if pattern.len() > 3 {
            return Some((
                Check::ConfigLine {
                    pattern: pattern.clone(),
                    context: None,
                    should_exist: true,
                },
                ExpectedResult::IsTrue,
                format!("Auto: config line check for '{}'", pattern),
            ));
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Generic pattern matchers (work across platforms)
// ---------------------------------------------------------------------------

static RE_SERVICE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:service|daemon)\s+(?:"|'|`)?(\w[\w-]*)(?:"|'|`)?\s+.*?(?:must\s+be\s+|is\s+not\s+)(running|stopped|disabled|enabled|started|active)"#).unwrap()
});

fn try_service_pattern(text: &str) -> Option<(Check, ExpectedResult, String)> {
    if let Some(caps) = RE_SERVICE.captures(text) {
        let name = caps[1].to_string();
        let status_word = caps[2].to_lowercase();

        let expected_status = match status_word.as_str() {
            "running" | "started" | "active" | "enabled" => ServiceStatus::Running,
            "stopped" => ServiceStatus::Stopped,
            "disabled" => ServiceStatus::Disabled,
            _ => ServiceStatus::Running,
        };

        return Some((
            Check::Service {
                name: name.clone(),
                expected_status,
            },
            ExpectedResult::IsTrue,
            format!("Auto: service '{}' must be {:?}", name, expected_status),
        ));
    }
    None
}

fn try_generic_patterns(text: &str) -> Option<(Check, ExpectedResult, String)> {
    // Try service pattern.
    if let result @ Some(_) = try_service_pattern(text) {
        return result;
    }

    // Try sysctl (sometimes appears in non-Linux STIGs).
    if let Some(caps) = RE_SYSCTL.captures(text) {
        let key = caps[1].to_string();
        let value = caps[2].to_string();
        return Some((
            Check::Sysctl { key: key.clone() },
            ExpectedResult::Equals {
                value: serde_json::json!(value),
            },
            format!("Auto: sysctl {} = {}", key, value),
        ));
    }

    // Try file content.
    if let Some(caps) = RE_FILE_CONTENT.captures(text) {
        let path = caps[1].to_string();
        let pattern = caps[2].trim().to_string();
        return Some((
            Check::FileContent {
                path: path.clone(),
                pattern: pattern.clone(),
                is_regex: false,
            },
            ExpectedResult::IsTrue,
            format!("Auto: check {} for '{}'", path, pattern),
        ));
    }

    None
}

/// Serialize a ConversionResult's check pack to JSON.
pub fn check_pack_to_json(pack: &CheckPack) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(pack)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_platform() {
        let mut b = test_benchmark("Windows_Server_2022_STIG", "Windows Server 2022");
        assert!(matches!(detect_platform(&b), CheckPlatform::Windows));

        b.id = "RHEL_9_STIG".to_string();
        b.title = "Red Hat Enterprise Linux 9".to_string();
        assert!(matches!(detect_platform(&b), CheckPlatform::Linux));

        b.id = "Cisco_IOS_Router".to_string();
        b.title = "Cisco IOS Router".to_string();
        assert!(matches!(detect_platform(&b), CheckPlatform::CiscoIos));
    }

    #[test]
    fn test_registry_pattern() {
        let text = r#"Navigate to HKLM\SOFTWARE\Policies\Microsoft\Windows\System. If the value DontDisplayNetworkSelectionUI REG_DWORD is not set to 1, this is a finding."#;

        let result = try_windows_patterns(text);
        assert!(result.is_some());
        let (check, _, _) = result.unwrap();
        match check {
            Check::Registry {
                path, value_name, ..
            } => {
                assert!(path.contains("Policies"));
                assert_eq!(value_name, "DontDisplayNetworkSelectionUI");
            }
            _ => panic!("Expected Registry check"),
        }
    }

    #[test]
    fn test_registry_block_dword_equals() {
        let text = r#"Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\

Value Name: SMB1

Type: REG_DWORD
Value: 0x00000000 (0)"#;

        let result = try_windows_patterns(text);
        assert!(result.is_some());
        let (check, expected, _) = result.unwrap();
        match check {
            Check::Registry {
                path,
                value_name,
                value_type,
            } => {
                assert_eq!(
                    path,
                    "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters"
                );
                assert_eq!(value_name, "SMB1");
                assert_eq!(value_type, Some("REG_DWORD".to_string()));
            }
            _ => panic!("Expected Registry check"),
        }
        match expected {
            ExpectedResult::Equals { value } => assert_eq!(value, serde_json::json!(0)),
            _ => panic!("Expected Equals"),
        }
    }

    #[test]
    fn test_registry_block_ge() {
        let text = r#"Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Example\
Value Name: MinimumValue
Value Type: REG_DWORD
Value: 0x0000000f (15) (or greater)"#;

        let result = try_registry_block(text);
        assert!(result.is_some());
        let (_, expected, _) = result.unwrap();
        match expected {
            ExpectedResult::GreaterOrEqual { value } => assert_eq!(value, 15.0),
            _ => panic!("Expected GreaterOrEqual"),
        }
    }

    #[test]
    fn test_registry_block_skips_alternatives() {
        let text = r#"Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Example\
Value Name: Mode
Type: REG_DWORD
Value: 0x00000001 (1) or 0x00000002 (2)"#;

        assert!(try_registry_block(text).is_none());
    }

    #[test]
    fn test_registry_block_skips_reg_sz() {
        let text = r#"Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Example\
Value Name: Mode
Type: REG_SZ
Value: 0x00000001 (1)"#;

        assert!(try_registry_block(text).is_none());
    }

    #[test]
    fn test_sysctl_pattern() {
        let text = "Verify the value of sysctl net.ipv4.ip_forward is not 0. If the value is not 0, this is a finding.";
        let result = try_linux_patterns(text);
        assert!(result.is_some());
        let (check, expected, _) = result.unwrap();
        match check {
            Check::Sysctl { key } => assert_eq!(key, "net.ipv4.ip_forward"),
            _ => panic!("Expected Sysctl check"),
        }
        match expected {
            ExpectedResult::Equals { value } => assert_eq!(value, serde_json::json!("0")),
            _ => panic!("Expected Equals"),
        }
    }

    #[test]
    fn test_sysctl_disa_extracts_key_and_value() {
        let text = r#"$ sudo sysctl kernel.kexec_load_disabled
kernel.kexec_load_disabled = 1
If "kernel.kexec_load_disabled" is not set to "1" or is missing, this is a finding."#;

        let result = try_linux_patterns(text);
        assert!(result.is_some());
        let (check, expected, _) = result.unwrap();
        match check {
            Check::Sysctl { key } => assert_eq!(key, "kernel.kexec_load_disabled"),
            _ => panic!("Expected Sysctl check"),
        }
        match expected {
            ExpectedResult::Equals { value } => assert_eq!(value, serde_json::json!(1)),
            _ => panic!("Expected Equals"),
        }
    }

    #[test]
    fn test_systemd_disa_enabled_active() {
        let text = r#"Verify the rngd service is enabled and active with the following commands:
     $ sudo systemctl is-enabled rngd
     enabled
     $ sudo systemctl is-active rngd
     active
If the rngd service is not enabled and active, this is a finding."#;

        let result = try_linux_patterns(text);
        assert!(result.is_some());
        let (check, expected, _) = result.unwrap();
        match check {
            Check::Service {
                name,
                expected_status,
            } => {
                assert_eq!(name, "rngd");
                assert_eq!(expected_status, ServiceStatus::Running);
            }
            _ => panic!("Expected Service check"),
        }
        assert!(matches!(expected, ExpectedResult::IsTrue));
    }

    #[test]
    fn test_systemd_disa_disabled_when_active_is_finding() {
        let text =
            "Run `systemctl is-active telnet`. If the telnet service is active, this is a finding.";

        let result = try_systemd_disa(text);
        assert!(result.is_some());
        let (check, expected, _) = result.unwrap();
        match check {
            Check::Service {
                name,
                expected_status,
            } => {
                assert_eq!(name, "telnet");
                assert_eq!(expected_status, ServiceStatus::Disabled);
            }
            _ => panic!("Expected Service check"),
        }
        assert!(matches!(expected, ExpectedResult::IsTrue));
    }

    #[test]
    fn test_systemd_disa_ambiguous_command_only_returns_none() {
        let text = "Run `systemctl is-active foo` and review the result.";

        assert!(try_systemd_disa(text).is_none());
    }

    #[test]
    fn test_systemd_disa_skips_manual() {
        let text = r#"Verify the xorg service status with the following command:
     $ sudo systemctl is-enabled xorg
Ask the System Administrator if the use of xorg is documented."#;

        assert!(try_systemd_disa(text).is_none());
    }

    #[test]
    fn test_sysctl_disa_none_without_output_line() {
        let text = "Run sysctl foo.bar and review the output.";

        assert!(try_sysctl_disa(text).is_none());
    }

    #[test]
    fn test_file_permission_pattern() {
        let text = "Check the permissions of /etc/shadow. If the mode is more permissive than 0640, this is a finding.";
        let result = try_linux_patterns(text);
        assert!(result.is_some());
        let (check, _, _) = result.unwrap();
        match check {
            Check::FilePermission { path, mode, .. } => {
                assert_eq!(path, "/etc/shadow");
                assert_eq!(mode, Some("00640".to_string()));
            }
            _ => panic!("Expected FilePermission check"),
        }
    }

    #[test]
    fn test_package_pattern() {
        let text = "Verify the package telnet-server is not installed. If telnet-server must not be installed.";
        let result = try_linux_patterns(text);
        assert!(result.is_some());
        let (check, _, _) = result.unwrap();
        match check {
            Check::Package {
                name,
                should_be_installed,
            } => {
                assert_eq!(name, "telnet-server");
                assert!(!should_be_installed);
            }
            _ => panic!("Expected Package check"),
        }
    }

    #[test]
    fn test_service_pattern() {
        let text = "Verify the service auditd must be running. If the service is not running, this is a finding.";
        let result = try_service_pattern(text);
        assert!(result.is_some());
        let (check, _, _) = result.unwrap();
        match check {
            Check::Service {
                name,
                expected_status,
            } => {
                assert_eq!(name, "auditd");
                assert_eq!(expected_status, ServiceStatus::Running);
            }
            _ => panic!("Expected Service check"),
        }
    }

    #[test]
    fn test_network_config_pattern() {
        let text = "Verify that SSH version 2 is configured. If ip ssh version 2 is not present, this is a finding.";
        let result = try_network_patterns(text);
        assert!(result.is_some());
        let (check, _, _) = result.unwrap();
        match check {
            Check::ConfigLine {
                pattern,
                should_exist,
                ..
            } => {
                assert_eq!(pattern, "ip ssh version 2");
                assert!(should_exist);
            }
            _ => panic!("Expected ConfigLine check"),
        }
    }

    #[test]
    fn test_security_policy_pattern() {
        let text = "Open Local Security Policy. Navigate to Account Policies >> Password Policy. If MinimumPasswordLength is not set to at least 14, this is a finding.";
        let result = try_windows_patterns(text);
        assert!(result.is_some());
        let (check, expected, _) = result.unwrap();
        match check {
            Check::SecurityPolicy { key, .. } => {
                assert_eq!(key, "MinimumPasswordLength");
            }
            _ => panic!("Expected SecurityPolicy check"),
        }
        match expected {
            ExpectedResult::GreaterOrEqual { value } => assert_eq!(value, 14.0),
            _ => panic!("Expected GreaterOrEqual"),
        }
    }

    #[test]
    fn test_full_benchmark_conversion() {
        let benchmark = StigBenchmark {
            id: "Test_Linux_STIG".to_string(),
            title: "Test Linux STIG".to_string(),
            description: "Test".to_string(),
            version: "1".to_string(),
            release: "1".to_string(),
            release_date: None,
            xccdf_id: None,
            platform: crate::models::stig::Platform::default(),
            rules: vec![
                StigRule {
                    vuln_id: "V-1".to_string(),
                    rule_id: "SV-1".to_string(),
                    group_id: "V-1".to_string(),
                    title: "IP forwarding".to_string(),
                    discussion: "".to_string(),
                    severity: crate::models::stig::Severity::Medium,
                    check_content: "Verify sysctl net.ipv4.ip_forward is not 0.".to_string(),
                    fix_text: "Set to 0".to_string(),
                    cci_refs: vec![],
                    legacy_ids: vec![],
                    stig_ref: None,
                    weight: 8.0,
                    automatable: crate::models::stig::CheckAutomation::Full,
                    automated_check: None,
                    remediation_ids: vec![],
                },
                StigRule {
                    vuln_id: "V-2".to_string(),
                    rule_id: "SV-2".to_string(),
                    group_id: "V-2".to_string(),
                    title: "Manual check".to_string(),
                    discussion: "".to_string(),
                    severity: crate::models::stig::Severity::Low,
                    check_content: "Interview the ISSO and verify a documented policy exists."
                        .to_string(),
                    fix_text: "Create policy".to_string(),
                    cci_refs: vec![],
                    legacy_ids: vec![],
                    stig_ref: None,
                    weight: 2.0,
                    automatable: crate::models::stig::CheckAutomation::Manual,
                    automated_check: None,
                    remediation_ids: vec![],
                },
            ],
        };

        let result = convert_benchmark(&benchmark);
        assert_eq!(result.automated, 1);
        assert_eq!(result.manual, 1);
        assert_eq!(result.check_pack.checks.len(), 1);
        assert_eq!(result.check_pack.platform, CheckPlatform::Linux);
    }

    fn test_benchmark(id: &str, title: &str) -> StigBenchmark {
        StigBenchmark {
            id: id.to_string(),
            title: title.to_string(),
            description: String::new(),
            version: "1".to_string(),
            release: "1".to_string(),
            release_date: None,
            xccdf_id: None,
            platform: crate::models::stig::Platform::default(),
            rules: vec![],
        }
    }
}
