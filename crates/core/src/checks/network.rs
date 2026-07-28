//! Network device check helpers.
//!
//! Parses Cisco IOS-XE running configurations for STIG compliance.

#[derive(Debug, Clone, Copy)]
struct ConfigCommand<'a> {
    text: &'a str,
    indented: bool,
}

/// Return the delimiter when `line` opens a multi-line IOS banner.
///
/// IOS permits any delimiter character and commonly renders control-C as the
/// two-character token `^C`. An inline banner contains the delimiter twice on
/// its command line and therefore does not open a multi-line payload.
fn multiline_banner_delimiter(line: &str) -> Option<String> {
    let after_banner = line.strip_prefix("banner ")?;
    let banner_type_end = after_banner.find(char::is_whitespace)?;
    let body = after_banner[banner_type_end..].trim_start();
    if body.is_empty() {
        return None;
    }

    let delimiter = if body.starts_with('^') {
        body.chars().take(2).collect::<String>()
    } else {
        body.chars().next()?.to_string()
    };
    let after_opening = body.strip_prefix(&delimiter)?;
    (!after_opening.contains(&delimiter)).then_some(delimiter)
}

/// Parse only IOS-XE configuration commands.
///
/// Banner payload is arbitrary operator-controlled prose. Treating it as
/// configuration allowed a banner containing text such as `min-length 15` to
/// satisfy an unrelated control. Comments have the same problem. Preserve the
/// banner declaration itself for potential banner-presence checks, but never
/// expose its payload to command matchers.
fn parse_config_commands(config: &str) -> (Vec<ConfigCommand<'_>>, Option<String>) {
    let mut commands = Vec::new();
    let mut banner_delimiter: Option<String> = None;

    for raw_line in config.lines() {
        let text = raw_line.trim();

        if let Some(delimiter) = banner_delimiter.as_deref() {
            if text == delimiter || text.ends_with(delimiter) {
                banner_delimiter = None;
            }
            continue;
        }

        if text.is_empty() || text.starts_with('!') {
            continue;
        }

        commands.push(ConfigCommand {
            text,
            indented: raw_line.chars().next().is_some_and(char::is_whitespace),
        });
        banner_delimiter = multiline_banner_delimiter(text);
    }

    (commands, banner_delimiter)
}

fn config_commands(config: &str) -> Vec<ConfigCommand<'_>> {
    parse_config_commands(config).0
}

/// Reject a running configuration whose final banner payload is unterminated.
///
/// Call this at the evidence boundary before evaluating any checks. In
/// particular, a terminal-looking `end` line inside an unterminated banner is
/// payload, not proof that collection reached the end of the running config.
pub fn validate_balanced_banners(config: &str) -> Result<(), String> {
    let (_, unterminated) = parse_config_commands(config);
    if unterminated.is_some() {
        Err("Cisco running-config contains an unterminated banner payload".to_string())
    } else {
        Ok(())
    }
}

/// Match complete command tokens from the start of the IOS command.
///
/// A pattern is a command prefix, not an arbitrary substring. This prevents a
/// fragment from matching a different command such as an interface
/// `description` while retaining IOS trailing arguments used by reviewed
/// checks (for example, `logging buffered 4096000 informational`).
fn command_starts_with(command: &str, pattern: &str) -> bool {
    let mut command_tokens = command.split_whitespace();
    let mut saw_pattern_token = false;
    for pattern_token in pattern.split_whitespace() {
        saw_pattern_token = true;
        if command_tokens.next() != Some(pattern_token) {
            return false;
        }
    }
    saw_pattern_token
}

fn line_enables(line: &str, pattern: &str) -> bool {
    let trimmed = line.trim();

    if trimmed.is_empty() || trimmed.starts_with('!') {
        return false;
    }

    // A positive pattern must not be satisfied by its explicit IOS negation.
    // Patterns that intentionally begin with `no` (for example `no shutdown`)
    // still describe the literal configured command and remain matchable.
    if !pattern.starts_with("no ") && trimmed.starts_with("no ") {
        return false;
    }

    command_starts_with(trimmed, pattern)
}

/// Check if a specific configuration line exists in the running config.
pub fn config_line_exists(config: &str, pattern: &str) -> bool {
    config_commands(config)
        .into_iter()
        .any(|command| line_enables(command.text, pattern))
}

/// Evaluate a line predicate across every matching configuration block.
///
/// Context-scoped STIG controls apply to every matching management block, not
/// merely the first compliant one. A missing context is also not evidence of
/// compliance. Comparing each block with `should_exist` is important for
/// negative predicates: a forbidden line in any one block must fail the rule.
pub fn config_line_context_satisfies(
    config: &str,
    context: &str,
    pattern: &str,
    should_exist: bool,
) -> bool {
    let mut current_block = None;
    let mut block_results = Vec::new();

    for command in config_commands(config) {
        let trimmed = command.text;

        if !command.indented && command_starts_with(trimmed, context) {
            if let Some(found) = current_block.replace(false) {
                block_results.push(found);
            }
            continue;
        }

        if current_block.is_some() {
            if !command.indented {
                block_results.push(current_block.take().expect("matching context block"));
            } else if line_enables(trimmed, pattern) {
                current_block = Some(true);
            }
        }
    }

    if let Some(found) = current_block {
        block_results.push(found);
    }

    !block_results.is_empty() && block_results.into_iter().all(|found| found == should_exist)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_CONFIG: &str = r#"hostname CORE-RTR-01
!
service password-encryption
service timestamps log datetime msec
!
aaa new-model
!
ip ssh version 2
ip ssh time-out 60
!
interface GigabitEthernet0/0
 description Uplink
 ip address 10.0.1.1 255.255.255.0
 no shutdown
!
interface GigabitEthernet0/1
 shutdown
!
ntp server 10.0.0.100
ntp server 10.0.0.101
!
banner login ^
Authorized users only.
^
!
"#;

    #[test]
    fn test_config_line_exists() {
        assert!(config_line_exists(SAMPLE_CONFIG, "ip ssh version 2"));
        assert!(!config_line_exists(SAMPLE_CONFIG, "ip ssh version 1"));
    }

    #[test]
    fn config_line_exists_finds_bare_enabled_line() {
        assert!(config_line_exists(
            "service password-encryption",
            "service password-encryption"
        ));
    }

    #[test]
    fn config_line_exists_rejects_negated_line() {
        assert!(!config_line_exists(
            "no service password-encryption",
            "service password-encryption"
        ));
    }

    #[test]
    fn config_line_exists_requires_token_boundaries() {
        assert!(!config_line_exists(
            "ip http secure-server",
            "ip http server"
        ));
    }

    #[test]
    fn config_line_exists_ignores_comment_lines() {
        assert!(!config_line_exists(
            "! service finger enabled for testing",
            "service finger"
        ));
    }

    #[test]
    fn config_line_exists_ignores_banner_payload_and_description_text() {
        let config = r#"banner login ^C
min-length 15
service password-encryption
^C
interface GigabitEthernet0/0
 description logging buffered
! login on-success log
end
"#;
        assert!(!config_line_exists(config, "min-length 15"));
        assert!(!config_line_exists(config, "service password-encryption"));
        assert!(!config_line_exists(config, "logging buffered"));
        assert!(!config_line_exists(config, "login on-success log"));
    }

    #[test]
    fn inline_banner_does_not_hide_following_commands() {
        let config = "banner motd #Authorized users only#\nlogging buffered 4096\n";
        assert!(config_line_exists(config, "logging buffered"));
    }

    #[test]
    fn banner_validation_rejects_fake_terminal_marker_inside_payload() {
        let unterminated = r#"version 17.9
hostname rtr01
banner login ^C
Authorized users only
end
"#;
        assert!(validate_balanced_banners(unterminated).is_err());

        let terminated = r#"version 17.9
hostname rtr01
banner login ^C
Authorized users only
^C
end
"#;
        assert!(validate_balanced_banners(terminated).is_ok());
        assert!(validate_balanced_banners("banner motd #Authorized users only#\nend\n").is_ok());
    }

    #[test]
    fn test_config_line_in_context() {
        assert!(config_line_context_satisfies(
            SAMPLE_CONFIG,
            "interface GigabitEthernet0/0",
            "no shutdown",
            true,
        ));
        assert!(!config_line_context_satisfies(
            SAMPLE_CONFIG,
            "interface GigabitEthernet0/1",
            "no shutdown",
            true,
        ));
    }

    #[test]
    fn context_checks_require_every_matching_block_and_at_least_one_block() {
        let config_with_vty_setting = "line vty 0 4\n session-limit 2\nline console 0";
        assert!(config_line_context_satisfies(
            config_with_vty_setting,
            "line vty",
            "session-limit",
            true,
        ));

        let config_with_setting_outside_vty = "session-limit 2\nline vty 0 4\n exec-timeout 10";
        assert!(!config_line_context_satisfies(
            config_with_setting_outside_vty,
            "line vty",
            "session-limit",
            true,
        ));

        let split_vty = "line vty 0 4\n session-limit 2\nline vty 5 15\n exec-timeout 5 0\nend";
        assert!(!config_line_context_satisfies(
            split_vty,
            "line vty",
            "session-limit",
            true,
        ));
        assert!(!config_line_context_satisfies(
            "line console 0\n exec-timeout 5 0\nend",
            "line vty",
            "exec-timeout 5 0",
            true,
        ));
    }

    #[test]
    fn negative_context_checks_fail_if_any_matching_block_enables_the_line() {
        let split_vty =
            "line vty 0 4\n no transport input telnet\nline vty 5 15\n transport input telnet\nend";
        assert!(!config_line_context_satisfies(
            split_vty,
            "line vty",
            "transport input telnet",
            false,
        ));
        let safe_vty =
            "line vty 0 4\n no transport input telnet\nline vty 5 15\n transport input ssh\nend";
        assert!(config_line_context_satisfies(
            safe_vty,
            "line vty",
            "transport input telnet",
            false,
        ));
    }

    #[test]
    fn global_checks_reject_weak_value_and_prefix_near_misses() {
        assert!(!config_line_exists(
            "login block-for 900 attempts 30 within 120",
            "attempts 3 within"
        ));
        assert!(!config_line_exists(
            "common-criteria policy STIG min-length 150",
            "min-length 15"
        ));
        assert!(!config_line_exists(
            "ip ssh server algorithm encryption aes256-ctr-legacy",
            "algorithm encryption aes256-ctr"
        ));
    }

    #[test]
    fn ambiguous_cisco_controls_have_no_executable_not_a_finding_path() {
        use crate::checks::{executor::execute_check_pack, CheckPack, SystemData};

        const MANUAL_RULES: [&str; 16] = [
            "V-215807", "V-215812", "V-215813", "V-215814", "V-215823", "V-215826", "V-215833",
            "V-215836", "V-215837", "V-215841", "V-215842", "V-215843", "V-215844", "V-215845",
            "V-215854", "V-215856",
        ];
        let pack: CheckPack = serde_json::from_str(include_str!(
            "../../../../content/check_packs/cisco_ios_xe_router_ndm.json"
        ))
        .expect("embedded Cisco pack fixture must parse");
        assert_eq!(pack.checks.len(), 18);
        for vuln_id in MANUAL_RULES {
            assert!(
                pack.checks.iter().all(|check| check.vuln_id != vuln_id),
                "{vuln_id} must remain manual"
            );
        }

        let data = SystemData {
            collection_complete: true,
            network_config: Some(
                include_str!(
                    "../../../../fixtures/network/ios_xe_router_semantic_counterexamples.txt"
                )
                .to_string(),
            ),
            ..Default::default()
        };
        let results = execute_check_pack(&pack, &data);
        assert_eq!(results.len(), 18);
        assert!(results
            .iter()
            .all(|result| !MANUAL_RULES.contains(&result.vuln_id.as_str())));
    }
}
