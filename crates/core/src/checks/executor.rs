//! Check executor — evaluates check definitions against collected system data.

use regex::Regex;

use super::*;

/// Execute a single check against collected system data.
pub fn execute_check(check_def: &CheckDefinition, data: &SystemData) -> CheckResult {
    let result = run_check(&check_def.check, data);
    let passed = match result {
        Ok(ref actual) => evaluate_expected(actual, &check_def.expected),
        Err(_) => false,
    };

    let (actual_value, evidence, error) = match result {
        Ok(actual) => (actual.clone(), actual, None),
        Err(e) => (String::new(), String::new(), Some(e)),
    };

    CheckResult {
        vuln_id: check_def.vuln_id.clone(),
        passed,
        actual_value,
        expected_value: format!("{:?}", check_def.expected),
        evidence,
        error,
    }
}

/// Execute all checks in a pack against system data.
pub fn execute_check_pack(pack: &CheckPack, data: &SystemData) -> Vec<CheckResult> {
    pack.checks
        .iter()
        .map(|check_def| execute_check(check_def, data))
        .collect()
}

/// Run a check and return the actual value as a string.
fn run_check(check: &Check, data: &SystemData) -> Result<String, String> {
    match check {
        Check::Registry {
            path, value_name, ..
        } => {
            let key = format!("{}\\{}", path, value_name);
            match data.registry.get(&key) {
                Some(val) => Ok(format!("{}", val)),
                None => {
                    // Try case-insensitive lookup.
                    let key_lower = key.to_lowercase();
                    data.registry
                        .iter()
                        .find(|(k, _)| k.to_lowercase() == key_lower)
                        .map(|(_, v)| format!("{}", v))
                        .ok_or_else(|| format!("Registry value not found: {}", key))
                }
            }
        }

        Check::SecurityPolicy { section, key } => {
            let lookup = format!("{}\\{}", section, key);
            data.security_policy
                .get(&lookup)
                .or_else(|| data.security_policy.get(key))
                .cloned()
                .ok_or_else(|| format!("Security policy not found: {}", lookup))
        }

        Check::AuditPolicy { subcategory, .. } => data
            .audit_policy
            .get(subcategory)
            .cloned()
            .ok_or_else(|| format!("Audit policy not found: {}", subcategory)),

        Check::Service {
            name,
            expected_status,
        } => {
            let status = data
                .services
                .get(name)
                .or_else(|| {
                    let lower = name.to_lowercase();
                    data.services
                        .iter()
                        .find(|(k, _)| k.to_lowercase() == lower)
                        .map(|(_, v)| v)
                })
                .cloned()
                .unwrap_or_else(|| "not_found".to_string());

            let is_match = match expected_status {
                ServiceStatus::Running => {
                    status == "running" || status == "Running" || status == "active"
                }
                ServiceStatus::Stopped => {
                    status == "stopped" || status == "Stopped" || status == "inactive"
                }
                ServiceStatus::Disabled => {
                    status == "disabled" || status == "Disabled" || status == "masked"
                }
            };

            Ok(if is_match { "true" } else { "false" }.to_string())
        }

        Check::WindowsFeature {
            name,
            should_be_installed,
        } => {
            let installed = data.packages.get(name).copied().unwrap_or(false);
            let matches = installed == *should_be_installed;
            Ok(if matches { "true" } else { "false" }.to_string())
        }

        Check::FileContent {
            path,
            pattern,
            is_regex,
        } => {
            let content = data
                .file_contents
                .get(path)
                .ok_or_else(|| format!("File not found: {}", path))?;

            if *is_regex {
                match Regex::new(pattern) {
                    Ok(re) => Ok(if re.is_match(content) {
                        "true".to_string()
                    } else {
                        "false".to_string()
                    }),
                    Err(e) => Err(format!("Invalid regex: {}", e)),
                }
            } else {
                Ok(if content.contains(pattern) {
                    "true".to_string()
                } else {
                    "false".to_string()
                })
            }
        }

        Check::FilePermission {
            path,
            owner,
            group,
            mode,
        } => {
            let perms = data
                .file_permissions
                .get(path)
                .ok_or_else(|| format!("File not found: {}", path))?;

            if !perms.exists {
                return Err(format!("File does not exist: {}", path));
            }

            let mut matches = true;
            let mut details = Vec::new();

            if let Some(expected_owner) = owner {
                let actual = perms.owner.as_deref().unwrap_or("unknown");
                if actual != expected_owner {
                    matches = false;
                    details.push(format!(
                        "owner: expected {}, got {}",
                        expected_owner, actual
                    ));
                }
            }

            if let Some(expected_group) = group {
                let actual = perms.group.as_deref().unwrap_or("unknown");
                if actual != expected_group {
                    matches = false;
                    details.push(format!(
                        "group: expected {}, got {}",
                        expected_group, actual
                    ));
                }
            }

            if let Some(expected_mode) = mode {
                let actual = perms.mode.as_deref().unwrap_or("unknown");
                if actual != expected_mode {
                    matches = false;
                    details.push(format!("mode: expected {}, got {}", expected_mode, actual));
                }
            }

            if matches {
                Ok("true".to_string())
            } else {
                Ok(format!("false ({})", details.join(", ")))
            }
        }

        Check::Sysctl { key } => data
            .sysctl
            .get(key)
            .cloned()
            .ok_or_else(|| format!("Sysctl key not found: {}", key)),

        Check::Package {
            name,
            should_be_installed,
        } => {
            let installed = data.packages.get(name).copied().unwrap_or(false);
            let matches = installed == *should_be_installed;
            Ok(if matches { "true" } else { "false" }.to_string())
        }

        Check::ConfigLine {
            pattern,
            context,
            should_exist,
        } => {
            let config = data
                .network_config
                .as_deref()
                .ok_or_else(|| "No network config data available".to_string())?;

            let found = if let Some(ctx) = context {
                network::config_line_in_context(config, ctx, pattern)
            } else {
                network::config_line_exists(config, pattern)
            };

            let matches = found == *should_exist;
            Ok(if matches { "true" } else { "false" }.to_string())
        }

        Check::Command { command, .. } => data
            .command_outputs
            .get(command)
            .cloned()
            .ok_or_else(|| format!("Command output not found: {}", command)),

        Check::All { checks } => {
            let results: Vec<Result<String, String>> =
                checks.iter().map(|c| run_check(c, data)).collect();
            let all_pass = results.iter().all(|r| match r {
                Ok(v) => v == "true",
                Err(_) => false,
            });
            Ok(if all_pass { "true" } else { "false" }.to_string())
        }

        Check::Any { checks } => {
            let results: Vec<Result<String, String>> =
                checks.iter().map(|c| run_check(c, data)).collect();
            let any_pass = results.iter().any(|r| match r {
                Ok(v) => v == "true",
                Err(_) => false,
            });
            Ok(if any_pass { "true" } else { "false" }.to_string())
        }
    }
}

/// Evaluate whether an actual value meets the expected result.
fn evaluate_expected(actual: &str, expected: &ExpectedResult) -> bool {
    match expected {
        ExpectedResult::Equals { value } => {
            let expected_str = match value {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            actual == expected_str || actual.trim() == expected_str.trim()
        }

        ExpectedResult::Matches { pattern } => Regex::new(pattern)
            .map(|re| re.is_match(actual))
            .unwrap_or(false),

        ExpectedResult::MatchCountAtLeast { pattern, min } => Regex::new(pattern)
            .map(|re| re.find_iter(actual).count() >= *min)
            .unwrap_or(false),

        ExpectedResult::GreaterOrEqual { value } => actual
            .trim()
            .parse::<f64>()
            .map(|v| v >= *value)
            .unwrap_or(false),

        ExpectedResult::LessOrEqual { value } => actual
            .trim()
            .parse::<f64>()
            .map(|v| v <= *value)
            .unwrap_or(false),

        ExpectedResult::Contains { substring } => actual.contains(substring),

        ExpectedResult::NotContains { substring } => !actual.contains(substring),

        ExpectedResult::IsTrue => actual == "true" || actual == "1" || actual == "yes",

        ExpectedResult::IsFalse => actual == "false" || actual == "0" || actual == "no",

        ExpectedResult::AllPass => actual == "true",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IPV4_LINE_PATTERN: &str = r"(?m)^\d{1,3}(\.\d{1,3}){3}";

    #[test]
    fn match_count_at_least_matches_two_ipv4_lines() {
        let expected = ExpectedResult::MatchCountAtLeast {
            pattern: IPV4_LINE_PATTERN.to_string(),
            min: 2,
        };

        assert!(evaluate_expected("192.0.2.1\n198.51.100.2\n", &expected));
    }

    #[test]
    fn match_count_at_least_rejects_one_ipv4_line() {
        let expected = ExpectedResult::MatchCountAtLeast {
            pattern: IPV4_LINE_PATTERN.to_string(),
            min: 2,
        };

        assert!(!evaluate_expected("192.0.2.1\n", &expected));
    }

    #[test]
    fn match_count_at_least_zero_always_matches() {
        let expected = ExpectedResult::MatchCountAtLeast {
            pattern: IPV4_LINE_PATTERN.to_string(),
            min: 0,
        };

        assert!(evaluate_expected("", &expected));
    }

    #[test]
    fn match_count_at_least_invalid_regex_returns_false() {
        let expected = ExpectedResult::MatchCountAtLeast {
            pattern: "[".to_string(),
            min: 0,
        };

        assert!(!evaluate_expected("192.0.2.1\n", &expected));
    }

    fn make_windows_data() -> SystemData {
        let mut data = SystemData {
            platform: "windows".to_string(),
            hostname: "testhost".to_string(),
            ..Default::default()
        };

        // Registry values.
        data.registry.insert(
            r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client\Enabled".to_string(),
            serde_json::json!(1),
        );
        data.registry.insert(
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows\System\DontDisplayNetworkSelectionUI"
                .to_string(),
            serde_json::json!(1),
        );

        // Services.
        data.services
            .insert("W32Time".to_string(), "Running".to_string());
        data.services
            .insert("Fax".to_string(), "Stopped".to_string());

        // Security policy.
        data.security_policy.insert(
            "System Access\\MinimumPasswordLength".to_string(),
            "14".to_string(),
        );

        // Audit policy.
        data.audit_policy.insert(
            "Logon/Logoff".to_string(),
            "Success and Failure".to_string(),
        );

        data
    }

    fn make_linux_data() -> SystemData {
        let mut data = SystemData {
            platform: "linux".to_string(),
            hostname: "linuxhost".to_string(),
            ..Default::default()
        };

        data.file_contents.insert(
            "/etc/ssh/sshd_config".to_string(),
            "PermitRootLogin no\nMaxAuthTries 4\nProtocol 2\n".to_string(),
        );

        data.file_permissions.insert(
            "/etc/shadow".to_string(),
            FilePermData {
                owner: Some("root".to_string()),
                group: Some("shadow".to_string()),
                mode: Some("0640".to_string()),
                exists: true,
            },
        );

        data.sysctl
            .insert("net.ipv4.ip_forward".to_string(), "0".to_string());
        data.sysctl
            .insert("kernel.randomize_va_space".to_string(), "2".to_string());

        data.services
            .insert("sshd".to_string(), "active".to_string());
        data.services
            .insert("firewalld".to_string(), "active".to_string());

        data.packages.insert("aide".to_string(), true);
        data.packages.insert("telnet-server".to_string(), false);

        data
    }

    #[test]
    fn test_registry_check_pass() {
        let data = make_windows_data();
        let check = CheckDefinition {
            vuln_id: "V-254239".to_string(),
            platform: CheckPlatform::Windows,
            check: Check::Registry {
                path: r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client".to_string(),
                value_name: "Enabled".to_string(),
                value_type: None,
            },
            expected: ExpectedResult::Equals { value: serde_json::json!(1) },
            description: None,
        };

        let result = execute_check(&check, &data);
        assert!(result.passed);
        assert!(result.error.is_none());
    }

    #[test]
    fn test_registry_check_missing() {
        let data = make_windows_data();
        let check = CheckDefinition {
            vuln_id: "V-999999".to_string(),
            platform: CheckPlatform::Windows,
            check: Check::Registry {
                path: "HKLM\\NONEXISTENT".to_string(),
                value_name: "Value".to_string(),
                value_type: None,
            },
            expected: ExpectedResult::Equals {
                value: serde_json::json!(1),
            },
            description: None,
        };

        let result = execute_check(&check, &data);
        assert!(!result.passed);
        assert!(result.error.is_some());
    }

    #[test]
    fn test_service_check() {
        let data = make_windows_data();

        let check = CheckDefinition {
            vuln_id: "V-1".to_string(),
            platform: CheckPlatform::Windows,
            check: Check::Service {
                name: "W32Time".to_string(),
                expected_status: ServiceStatus::Running,
            },
            expected: ExpectedResult::IsTrue,
            description: None,
        };

        let result = execute_check(&check, &data);
        assert!(result.passed);
    }

    #[test]
    fn test_security_policy_check() {
        let data = make_windows_data();
        let check = CheckDefinition {
            vuln_id: "V-2".to_string(),
            platform: CheckPlatform::Windows,
            check: Check::SecurityPolicy {
                section: "System Access".to_string(),
                key: "MinimumPasswordLength".to_string(),
            },
            expected: ExpectedResult::GreaterOrEqual { value: 14.0 },
            description: None,
        };

        let result = execute_check(&check, &data);
        assert!(result.passed);
    }

    #[test]
    fn test_linux_file_content_check() {
        let data = make_linux_data();
        let check = CheckDefinition {
            vuln_id: "V-3".to_string(),
            platform: CheckPlatform::Linux,
            check: Check::FileContent {
                path: "/etc/ssh/sshd_config".to_string(),
                pattern: "PermitRootLogin no".to_string(),
                is_regex: false,
            },
            expected: ExpectedResult::IsTrue,
            description: None,
        };

        let result = execute_check(&check, &data);
        assert!(result.passed);
    }

    #[test]
    fn test_linux_file_permission_check() {
        let data = make_linux_data();
        let check = CheckDefinition {
            vuln_id: "V-4".to_string(),
            platform: CheckPlatform::Linux,
            check: Check::FilePermission {
                path: "/etc/shadow".to_string(),
                owner: Some("root".to_string()),
                group: None,
                mode: Some("0640".to_string()),
            },
            expected: ExpectedResult::IsTrue,
            description: None,
        };

        let result = execute_check(&check, &data);
        assert!(result.passed);
    }

    #[test]
    fn test_sysctl_check() {
        let data = make_linux_data();
        let check = CheckDefinition {
            vuln_id: "V-5".to_string(),
            platform: CheckPlatform::Linux,
            check: Check::Sysctl {
                key: "net.ipv4.ip_forward".to_string(),
            },
            expected: ExpectedResult::Equals {
                value: serde_json::json!("0"),
            },
            description: None,
        };

        let result = execute_check(&check, &data);
        assert!(result.passed);
    }

    #[test]
    fn test_package_check() {
        let data = make_linux_data();

        // telnet-server should NOT be installed.
        let check = CheckDefinition {
            vuln_id: "V-6".to_string(),
            platform: CheckPlatform::Linux,
            check: Check::Package {
                name: "telnet-server".to_string(),
                should_be_installed: false,
            },
            expected: ExpectedResult::IsTrue,
            description: None,
        };

        let result = execute_check(&check, &data);
        assert!(result.passed);
    }

    #[test]
    fn test_compound_all_check() {
        let data = make_linux_data();
        let check = CheckDefinition {
            vuln_id: "V-7".to_string(),
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

        let result = execute_check(&check, &data);
        assert!(result.passed);
    }

    #[test]
    fn test_regex_file_content() {
        let data = make_linux_data();
        let check = CheckDefinition {
            vuln_id: "V-8".to_string(),
            platform: CheckPlatform::Linux,
            check: Check::FileContent {
                path: "/etc/ssh/sshd_config".to_string(),
                pattern: r"MaxAuthTries\s+[1-4]".to_string(),
                is_regex: true,
            },
            expected: ExpectedResult::IsTrue,
            description: None,
        };

        let result = execute_check(&check, &data);
        assert!(result.passed);
    }

    #[test]
    fn test_check_pack_execution() {
        let data = make_linux_data();
        let pack = CheckPack {
            stig_id: "RHEL_9_STIG".to_string(),
            platform: CheckPlatform::Linux,
            version: "1.0.0".to_string(),
            priority: 100,
            checks: vec![
                CheckDefinition {
                    vuln_id: "V-1".to_string(),
                    platform: CheckPlatform::Linux,
                    check: Check::FileContent {
                        path: "/etc/ssh/sshd_config".to_string(),
                        pattern: "PermitRootLogin no".to_string(),
                        is_regex: false,
                    },
                    expected: ExpectedResult::IsTrue,
                    description: None,
                },
                CheckDefinition {
                    vuln_id: "V-2".to_string(),
                    platform: CheckPlatform::Linux,
                    check: Check::Sysctl {
                        key: "kernel.randomize_va_space".to_string(),
                    },
                    expected: ExpectedResult::Equals {
                        value: serde_json::json!("2"),
                    },
                    description: None,
                },
            ],
        };

        let results = execute_check_pack(&pack, &data);
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.passed));
    }
}
