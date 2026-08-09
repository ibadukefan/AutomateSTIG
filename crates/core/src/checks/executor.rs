//! Check executor for the three supported target families.

use regex::Regex;

use super::*;

/// Execute a single check against collected system data.
pub fn execute_check(check_def: &CheckDefinition, data: &SystemData) -> CheckResult {
    let result = run_check(&check_def.check, data);
    let passed = match result {
        Ok(ref actual) => evaluate_expected(actual, &check_def.expected),
        Err(_) => false,
    };
    let not_applicable = passed
        && matches!(
            &check_def.check,
            Check::CiscoPersistentAuditModificationProtection
                | Check::CiscoPersistentAuditDeletionProtection
        )
        && result
            .as_ref()
            .is_ok_and(|actual| actual.starts_with("not_applicable:"));

    let (actual_value, evidence, error) = match result {
        Ok(actual) => (actual.clone(), actual, None),
        Err(error) => (
            String::new(),
            format!("Collection/evaluation error: {error}"),
            Some(error),
        ),
    };

    CheckResult {
        vuln_id: check_def.vuln_id.clone(),
        passed,
        actual_value,
        expected_value: format!("{:?}", check_def.expected),
        evidence,
        error,
        not_applicable,
    }
}

/// Execute all checks in a pack against system data.
pub fn execute_check_pack(pack: &CheckPack, data: &SystemData) -> Vec<CheckResult> {
    pack.checks
        .iter()
        .map(|check_def| execute_check(check_def, data))
        .collect()
}

fn run_check(check: &Check, data: &SystemData) -> Result<String, String> {
    match check {
        Check::ConfigLine {
            pattern,
            context,
            should_exist,
        } => {
            let config = data
                .network_config
                .as_deref()
                .ok_or_else(|| "No network config data available".to_string())?;
            let satisfied = if let Some(context) = context {
                network::config_line_context_satisfies(config, context, pattern, *should_exist)
            } else {
                network::config_line_exists(config, pattern) == *should_exist
            };
            Ok(satisfied.to_string())
        }
        Check::Command {
            command,
            pattern,
            is_regex,
        } => {
            if let Some(error) = data.collection_errors.get(command) {
                return Err(format!("Command collection failed: {error}"));
            }
            let output = data
                .command_outputs
                .get(command)
                .ok_or_else(|| format!("Command output not found: {command}"))?;
            if let Some(pattern) = pattern {
                let matches = if *is_regex {
                    Regex::new(pattern)
                        .map_err(|error| format!("Invalid command check regex: {error}"))?
                        .is_match(output)
                } else {
                    output.contains(pattern)
                };
                Ok(matches.to_string())
            } else {
                Ok(output.clone())
            }
        }
        Check::All { checks } => {
            let results: Result<Vec<String>, String> =
                checks.iter().map(|check| run_check(check, data)).collect();
            Ok(results?.iter().all(|value| value == "true").to_string())
        }
        Check::Any { checks } => {
            let results: Result<Vec<String>, String> =
                checks.iter().map(|check| run_check(check, data)).collect();
            Ok(results?.iter().any(|value| value == "true").to_string())
        }
        Check::BsdAuditClassSelection { classes } => {
            Ok(freebsd::audit_classes_selected(data, classes)?.to_string())
        }
        Check::BsdPfEnabled => Ok(freebsd::pf_enabled_from_system_data(data)?.to_string()),
        Check::CiscoVtySessionLimit => {
            let config = data
                .network_config
                .as_deref()
                .ok_or_else(|| "No network config data available".to_string())?;
            let policy = data
                .organization_policy
                .as_ref()
                .ok_or_else(|| "V-215807 requires a verified organization policy".to_string())?;
            Ok(network::vty_session_limit_observation(
                config,
                policy
                    .document()
                    .rules
                    .concurrent_management_sessions
                    .max_concurrent_management_sessions,
            ))
        }
        Check::CiscoLoggingBufferCapacity => {
            let config = data
                .network_config
                .as_deref()
                .ok_or_else(|| "No network config data available".to_string())?;
            let policy = data
                .organization_policy
                .as_ref()
                .ok_or_else(|| "V-215836 requires a verified organization policy".to_string())?;
            Ok(network::logging_buffer_observation(
                config,
                policy
                    .document()
                    .rules
                    .logging_buffer_capacity
                    .minimum_logging_buffer_bytes,
            ))
        }
        Check::CiscoLoggingTrapSeverity => {
            let config = data
                .network_config
                .as_deref()
                .ok_or_else(|| "No network config data available".to_string())?;
            Ok(network::logging_trap_observation(config))
        }
        Check::CiscoLoginBlockFor => {
            let config = data
                .network_config
                .as_deref()
                .ok_or_else(|| "No network config data available".to_string())?;
            Ok(network::login_block_for_observation(config))
        }
        Check::CiscoInterfaceAclDenyLogInput => {
            let config = data
                .network_config
                .as_deref()
                .ok_or_else(|| "No network config data available".to_string())?;
            Ok(network::interface_acl_deny_log_input_observation(config))
        }
        Check::CiscoSingleLocalFallbackAccount => {
            let config = data
                .network_config
                .as_deref()
                .ok_or_else(|| "No network config data available".to_string())?;
            Ok(network::single_local_fallback_account_observation(config))
        }
        Check::CiscoPasswordMinimumLength => {
            let config = data
                .network_config
                .as_deref()
                .ok_or_else(|| "No network config data available".to_string())?;
            Ok(network::password_minimum_length_observation(config))
        }
        Check::CiscoPersistentAuditModificationProtection
        | Check::CiscoPersistentAuditDeletionProtection => {
            let config = data
                .network_config
                .as_deref()
                .ok_or_else(|| "No network config data available".to_string())?;
            Ok(network::persistent_audit_file_protection_observation(
                config,
            ))
        }
        Check::CiscoFileSystemPrivilege => {
            let config = data
                .network_config
                .as_deref()
                .ok_or_else(|| "No network config data available".to_string())?;
            Ok(network::file_system_privilege_protection_observation(
                config,
            ))
        }
        Check::CiscoManagementIdleTimeout => {
            let config = data
                .network_config
                .as_deref()
                .ok_or_else(|| "No network config data available".to_string())?;
            Ok(network::management_idle_timeout_observation(config))
        }
        Check::CiscoRedundantAuthoritativeNtpSources => {
            let config = data
                .network_config
                .as_deref()
                .ok_or_else(|| "No network config data available".to_string())?;
            let policy = data
                .organization_policy
                .as_ref()
                .ok_or_else(|| "V-215838 requires a verified organization policy".to_string())?;
            Ok(network::redundant_authoritative_ntp_sources_observation(
                config,
                &policy
                    .document()
                    .rules
                    .authoritative_ntp_sources
                    .approved_authoritative_ntp_sources,
            ))
        }
        Check::CiscoNtpAuthentication => {
            let config = data
                .network_config
                .as_deref()
                .ok_or_else(|| "No network config data available".to_string())?;
            Ok(network::ntp_authentication_observation(config))
        }
        Check::CiscoSshMacAlgorithms => {
            let config = data
                .network_config
                .as_deref()
                .ok_or_else(|| "No network config data available".to_string())?;
            Ok(network::ssh_mac_algorithms_observation(config))
        }
        Check::CiscoSshEncryptionAlgorithms => {
            let config = data
                .network_config
                .as_deref()
                .ok_or_else(|| "No network config data available".to_string())?;
            Ok(network::ssh_encryption_algorithms_observation(config))
        }
        Check::CiscoSyslogServerCount => {
            let config = data
                .network_config
                .as_deref()
                .ok_or_else(|| "No network config data available".to_string())?;
            Ok(network::syslog_server_count_observation(config))
        }
    }
}

fn evaluate_expected(actual: &str, expected: &ExpectedResult) -> bool {
    match expected {
        ExpectedResult::Matches { pattern } => Regex::new(pattern)
            .map(|regex| regex.is_match(actual))
            .unwrap_or(false),
        ExpectedResult::MatchCountAtLeast { pattern, min } => Regex::new(pattern)
            .map(|regex| regex.find_iter(actual).count() >= *min)
            .unwrap_or(false),
        ExpectedResult::NotContains { substring } => !actual.contains(substring),
        ExpectedResult::IsTrue => actual == "true" || actual == "1" || actual == "yes",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IPV4_LINE_PATTERN: &str = r"(?m)^\d{1,3}(\.\d{1,3}){3}";

    fn command_check(command: &str, pattern: Option<&str>) -> CheckDefinition {
        CheckDefinition {
            vuln_id: "V-TEST".to_string(),
            platform: CheckPlatform::Bsd,
            check: Check::Command {
                command: command.to_string(),
                pattern: pattern.map(str::to_string),
                is_regex: false,
            },
            expected: ExpectedResult::IsTrue,
            description: None,
        }
    }

    #[test]
    fn match_count_at_least_contracts() {
        let expected = ExpectedResult::MatchCountAtLeast {
            pattern: IPV4_LINE_PATTERN.to_string(),
            min: 2,
        };
        assert!(evaluate_expected("192.0.2.1\n198.51.100.2\n", &expected));
        assert!(!evaluate_expected("192.0.2.1\n", &expected));

        let invalid = ExpectedResult::MatchCountAtLeast {
            pattern: "[".to_string(),
            min: 0,
        };
        assert!(!evaluate_expected("", &invalid));
    }

    #[test]
    fn command_collection_error_is_not_converted_to_false() {
        let definition = command_check("cat /etc/rc.conf", Some("auditd_enable=\"YES\""));
        let mut data = SystemData::default();
        data.collection_errors.insert(
            "cat /etc/rc.conf".to_string(),
            "permission denied".to_string(),
        );

        let result = execute_check(&definition, &data);
        assert!(!result.passed);
        assert!(result.error.is_some());
        assert_eq!(result.to_finding_status(), FindingStatus::NotReviewed);
    }

    #[test]
    fn command_pattern_checks_evaluate_collected_output() {
        let definition = command_check("cat /etc/rc.conf", Some("auditd_enable=\"YES\""));
        let mut data = SystemData::default();
        data.command_outputs.insert(
            "cat /etc/rc.conf".to_string(),
            "auditd_enable=\"YES\"".to_string(),
        );
        assert!(execute_check(&definition, &data).passed);
        data.command_outputs
            .insert("cat /etc/rc.conf".to_string(), String::new());
        assert!(!execute_check(&definition, &data).passed);
    }

    #[test]
    fn compound_checks_propagate_collection_errors() {
        let definition = CheckDefinition {
            vuln_id: "V-COMPOUND".to_string(),
            platform: CheckPlatform::Bsd,
            check: Check::All {
                checks: vec![
                    command_check("cat /etc/rc.conf", Some("auditd_enable")).check,
                    command_check("freebsd-version -k", Some("14")).check,
                ],
            },
            expected: ExpectedResult::IsTrue,
            description: None,
        };
        let mut data = SystemData::default();
        data.command_outputs.insert(
            "cat /etc/rc.conf".to_string(),
            "auditd_enable=\"YES\"".to_string(),
        );
        data.collection_errors
            .insert("freebsd-version -k".to_string(), "timeout".to_string());

        let result = execute_check(&definition, &data);
        assert!(result.error.is_some());
        assert_eq!(result.to_finding_status(), FindingStatus::NotReviewed);
    }

    #[test]
    fn cisco_config_and_pack_execution() {
        let definition = CheckDefinition {
            vuln_id: "V-CISCO".to_string(),
            platform: CheckPlatform::CiscoIos,
            check: Check::ConfigLine {
                pattern: "ip ssh version 2".to_string(),
                context: None,
                should_exist: true,
            },
            expected: ExpectedResult::IsTrue,
            description: None,
        };
        let pack = CheckPack {
            stig_id: "Cisco_IOS-XE_Router_NDM_STIG".to_string(),
            platform: CheckPlatform::CiscoIos,
            version: "test".to_string(),
            priority: 100,
            checks: vec![definition],
        };
        let data = SystemData {
            collection_complete: true,
            network_config: Some("ip ssh version 2\nend\n".to_string()),
            ..Default::default()
        };
        let results = execute_check_pack(&pack, &data);
        assert_eq!(results.len(), 1);
        assert!(results[0].passed);
    }
}
