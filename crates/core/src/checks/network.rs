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

fn one_u32_after_prefix(command: &str, prefix: &str) -> Option<u32> {
    let command_tokens: Vec<_> = command.split_whitespace().collect();
    let prefix_tokens: Vec<_> = prefix.split_whitespace().collect();
    if command_tokens.len() != prefix_tokens.len() + 1
        || command_tokens[..prefix_tokens.len()] != prefix_tokens
    {
        return None;
    }
    command_tokens.last()?.parse().ok()
}

/// Evaluate the policy-bound `session-limit` path from the V3R7 procedure.
///
/// Every represented VTY block must carry one unambiguous positive limit. If
/// HTTP(S) management is enabled, its independent maximum must also be bound.
/// The alternative "disable surplus VTY lines" path is deliberately not
/// inferred from an ordinary running configuration.
pub fn vty_session_limit_observation(config: &str, maximum: u32) -> String {
    let commands = config_commands(config);
    let mut current_vty: Option<Vec<&str>> = None;
    let mut vty_blocks = Vec::new();
    for command in &commands {
        if !command.indented && command_starts_with(command.text, "line vty") {
            if let Some(block) = current_vty.replace(Vec::new()) {
                vty_blocks.push(block);
            }
        } else if let Some(block) = current_vty.as_mut() {
            if command.indented {
                block.push(command.text);
            } else {
                vty_blocks.push(current_vty.take().expect("active VTY block"));
            }
        }
    }
    if let Some(block) = current_vty {
        vty_blocks.push(block);
    }
    if vty_blocks.is_empty() {
        return "finding: no VTY management block is present".to_string();
    }
    let mut observed = Vec::new();
    for block in vty_blocks {
        let limits: Vec<_> = block
            .iter()
            .filter(|line| command_starts_with(line, "session-limit"))
            .map(|line| one_u32_after_prefix(line, "session-limit"))
            .collect();
        if limits.len() != 1 {
            return "finding: every VTY block must have exactly one session-limit".to_string();
        }
        if block
            .iter()
            .any(|line| command_starts_with(line, "no session-limit"))
        {
            return "finding: VTY session-limit configuration is contradictory".to_string();
        }
        let Some(limit) = limits[0] else {
            return "finding: VTY session-limit is malformed".to_string();
        };
        if limit == 0 || limit > maximum {
            return format!(
                "finding: VTY session-limit {limit} exceeds organization maximum {maximum}"
            );
        }
        observed.push(limit);
    }

    let http_enabled = config_line_exists(config, "ip http server")
        || config_line_exists(config, "ip http secure-server");
    let http_limits: Vec<_> = commands
        .iter()
        .filter(|command| {
            !command.indented && command_starts_with(command.text, "ip http max-connections")
        })
        .map(|command| one_u32_after_prefix(command.text, "ip http max-connections"))
        .collect();
    let http_reset = commands.iter().any(|command| {
        !command.indented && command_starts_with(command.text, "no ip http max-connections")
    });
    if !http_limits.is_empty() && http_reset {
        return "finding: HTTP(S) max-connections configuration is contradictory".to_string();
    }
    if http_enabled {
        if http_limits.len() != 1 {
            return "finding: enabled HTTP(S) management requires exactly one max-connections"
                .to_string();
        }
        let Some(limit) = http_limits[0] else {
            return "finding: HTTP(S) max-connections is malformed".to_string();
        };
        if limit == 0 || limit > maximum {
            return format!(
                "finding: HTTP(S) max-connections {limit} exceeds organization maximum {maximum}"
            );
        }
    } else if !http_limits.is_empty() {
        return "finding: orphaned or ambiguous HTTP max-connections configuration".to_string();
    }
    format!(
        "compliant: VTY limits {observed:?}; HTTP enabled={http_enabled}; organization maximum={maximum}"
    )
}

/// Evaluate the exact numeric `logging buffered <bytes> ...` capacity.
pub fn logging_buffer_observation(config: &str, minimum_bytes: u32) -> String {
    let commands = config_commands(config);
    let values: Vec<_> = commands
        .iter()
        .filter_map(|command| {
            if command.indented || !command_starts_with(command.text, "logging buffered") {
                return None;
            }
            let tokens: Vec<_> = command.text.split_whitespace().collect();
            Some(tokens.get(2).and_then(|value| value.parse::<u32>().ok()))
        })
        .collect();
    let reset = commands.iter().any(|command| {
        !command.indented && command_starts_with(command.text, "no logging buffered")
    });
    if !values.is_empty() && reset {
        return "finding: logging buffered capacity configuration is contradictory".to_string();
    }
    if values.len() != 1 {
        return "finding: exactly one numeric logging buffered capacity is required".to_string();
    }
    let Some(observed) = values[0] else {
        return "finding: logging buffered capacity is missing or malformed".to_string();
    };
    if observed < minimum_bytes {
        return format!(
            "finding: logging buffer {observed} bytes is below organization minimum {minimum_bytes}"
        );
    }
    format!("compliant: logging buffer={observed} bytes; organization minimum={minimum_bytes}")
}

fn logging_level(value: &str) -> Option<u8> {
    match value.to_ascii_lowercase().as_str() {
        "0" | "emergencies" => Some(0),
        "1" | "alerts" => Some(1),
        "2" | "critical" => Some(2),
        "3" | "errors" => Some(3),
        "4" | "warnings" => Some(4),
        "5" | "notifications" => Some(5),
        "6" | "informational" => Some(6),
        "7" | "debugging" => Some(7),
        _ => None,
    }
}

/// Resolve the effective trap threshold. IOS-XE defaults to informational
/// when the command is absent or explicitly reset with `no logging trap`.
pub fn logging_trap_observation(config: &str) -> String {
    if config_line_exists(config, "no logging on") {
        return "finding: logging is globally disabled".to_string();
    }
    let commands = config_commands(config);
    let positive: Vec<_> = commands
        .iter()
        .filter(|command| !command.indented && command_starts_with(command.text, "logging trap"))
        .collect();
    let reset_count = commands
        .iter()
        .filter(|command| !command.indented && command_starts_with(command.text, "no logging trap"))
        .count();
    if positive.len() + reset_count > 1 {
        return "finding: logging trap severity is ambiguous".to_string();
    }
    let (level, source) = if positive.is_empty() {
        (
            6,
            if reset_count == 1 {
                "explicit default"
            } else {
                "IOS default"
            },
        )
    } else {
        let tokens: Vec<_> = positive[0].text.split_whitespace().collect();
        if tokens.len() != 3 {
            return "finding: logging trap severity is malformed".to_string();
        }
        let Some(level) = logging_level(tokens[2]) else {
            return "finding: logging trap severity is unsupported".to_string();
        };
        (level, "configured")
    };
    if !(2..=6).contains(&level) {
        return format!(
            "finding: effective logging trap severity {level} omits or exceeds the reviewed range"
        );
    }
    format!("compliant: effective logging trap severity={level} ({source})")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};

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
    fn remaining_manual_cisco_controls_have_no_executable_not_a_finding_path() {
        use crate::checks::{executor::execute_check_pack, CheckPack, SystemData};

        const MANUAL_RULES: [&str; 13] = [
            "V-215812", "V-215813", "V-215814", "V-215823", "V-215826", "V-215833", "V-215841",
            "V-215842", "V-215843", "V-215844", "V-215845", "V-215854", "V-215856",
        ];
        let pack: CheckPack = serde_json::from_str(include_str!(
            "../../../../content/check_packs/cisco_ios_xe_router_ndm.json"
        ))
        .expect("embedded Cisco pack fixture must parse");
        assert_eq!(pack.checks.len(), 21);
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
            organization_policy: Some(test_organization_policy()),
            ..Default::default()
        };
        let results = execute_check_pack(&pack, &data);
        assert_eq!(results.len(), 21);
        assert!(results
            .iter()
            .all(|result| !MANUAL_RULES.contains(&result.vuln_id.as_str())));
        for vuln_id in ["V-215807", "V-215836", "V-215837"] {
            let result = results
                .iter()
                .find(|result| result.vuln_id == vuln_id)
                .expect("restored Cisco check result");
            assert!(
                !result.passed && result.error.is_none(),
                "{vuln_id} counterexample must be a finding: {result:?}"
            );
        }
    }

    fn test_organization_policy() -> crate::organization_policy::VerifiedOrganizationPolicy {
        let now = chrono::Utc::now();
        let document = serde_json::json!({
            "schema": "automatestig-organization-policy/v1",
            "policy_id": "network-unit-test",
            "policy_version": "1",
            "stig_id": "Cisco_IOS-XE_Router_NDM_STIG",
            "stig_release": "V3R7",
            "asset_hostname": "rtr-semantic-counterexamples",
            "effective_from": (now - chrono::Duration::days(1)).to_rfc3339(),
            "expires_at": (now + chrono::Duration::days(1)).to_rfc3339(),
            "rules": {
                "V-215807": {"max_concurrent_management_sessions": 2},
                "V-215836": {"minimum_logging_buffer_bytes": 4096000}
            }
        });
        let raw = serde_json::to_vec(&document).expect("test policy JSON");
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let signature = signing_key.sign(&Sha256::digest(&raw)).to_bytes();
        crate::organization_policy::VerifiedOrganizationPolicy::verify_and_parse(
            &raw,
            &signature,
            &[signing_key.verifying_key().to_bytes()],
            "Cisco_IOS-XE_Router_NDM_STIG",
            "V3R7",
            "rtr-semantic-counterexamples",
            now,
        )
        .expect("valid test policy")
    }

    #[test]
    fn policy_bound_session_limits_cover_every_vty_and_http_path() {
        let compliant = r#"line vty 0 4
 session-limit 2
line vty 5 15
 session-limit 1
ip http secure-server
ip http max-connections 2
end
"#;
        assert!(vty_session_limit_observation(compliant, 2).starts_with("compliant:"));
        for bad in [
            "line vty 0 4\n session-limit 3\nend\n",
            "line vty 0 4\n session-limit 2\n no session-limit\nend\n",
            "line vty 0 4\n session-limit 2\nline vty 5 15\n transport input ssh\nend\n",
            "line vty 0 4\n session-limit 2\nip http secure-server\nend\n",
            "line vty 0 4\n session-limit 2\nip http secure-server\nip http max-connections 2\nno ip http max-connections\nend\n",
            "line vty 0 4\n session-limit nope\nend\n",
        ] {
            assert!(vty_session_limit_observation(bad, 2).starts_with("finding:"));
        }
    }

    #[test]
    fn logging_buffer_uses_the_organization_numeric_threshold() {
        assert!(
            logging_buffer_observation("logging buffered 4096000 informational\n", 4096000)
                .starts_with("compliant:")
        );
        for bad in [
            "logging buffered 4096 informational\n",
            "logging buffered informational\n",
            "logging buffered 4096000 informational\nlogging buffered 8192000\n",
            "logging buffered 4096000 informational\nno logging buffered\n",
        ] {
            assert!(logging_buffer_observation(bad, 4096000).starts_with("finding:"));
        }
    }

    #[test]
    fn logging_trap_resolves_default_names_numbers_and_ambiguity() {
        for config in [
            "logging host 192.0.2.1\n",
            "no logging trap\n",
            "logging trap critical\n",
            "logging trap 6\n",
        ] {
            assert!(logging_trap_observation(config).starts_with("compliant:"));
        }
        for config in [
            "logging trap alerts\n",
            "logging trap debugging\n",
            "logging trap unknown\n",
            "logging trap critical\nlogging trap informational\n",
            "no logging on\n",
        ] {
            assert!(logging_trap_observation(config).starts_with("finding:"));
        }
    }
}
