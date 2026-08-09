//! Network device check helpers.
//!
//! Parses Cisco IOS-XE running configurations for STIG compliance.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

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

#[derive(Debug)]
struct ConfigBlock<'a> {
    header: &'a str,
    lines: Vec<&'a str>,
}

fn config_blocks(config: &str) -> Vec<ConfigBlock<'_>> {
    let mut blocks = Vec::new();
    let mut active: Option<ConfigBlock<'_>> = None;
    for command in config_commands(config) {
        if command.indented {
            if let Some(block) = active.as_mut() {
                block.lines.push(command.text);
            }
        } else {
            if let Some(block) = active.replace(ConfigBlock {
                header: command.text,
                lines: Vec::new(),
            }) {
                blocks.push(block);
            }
        }
    }
    if let Some(block) = active {
        blocks.push(block);
    }
    blocks
}

fn positive_top_level<'a>(config: &'a str, prefix: &str) -> Vec<&'a str> {
    config_commands(config)
        .into_iter()
        .filter(|command| {
            !command.indented
                && !command.text.starts_with("no ")
                && command_starts_with(command.text, prefix)
        })
        .map(|command| command.text)
        .collect()
}

/// Evaluate the V3R7 invalid-login threshold as numeric policy, not fragment
/// presence. More restrictive values pass: no more than three attempts, a
/// lockout of at least 900 seconds, and an observation window of at least the
/// reviewed 120-second example.
pub fn login_block_for_observation(config: &str) -> String {
    let commands = positive_top_level(config, "login block-for");
    if commands.len() != 1 || config_line_exists(config, "no login block-for") {
        return "finding: exactly one effective login block-for command is required".to_string();
    }
    let tokens: Vec<_> = commands[0].split_whitespace().collect();
    if tokens.len() != 7 || tokens[3] != "attempts" || tokens[5] != "within" {
        return "finding: login block-for syntax is malformed or ambiguous".to_string();
    }
    let Some(block_seconds) = tokens[2].parse::<u64>().ok() else {
        return "finding: login lockout duration is not numeric".to_string();
    };
    let Some(attempts) = tokens[4].parse::<u64>().ok() else {
        return "finding: invalid-login attempt limit is not numeric".to_string();
    };
    let Some(window_seconds) = tokens[6].parse::<u64>().ok() else {
        return "finding: invalid-login observation window is not numeric".to_string();
    };
    if block_seconds < 900 || !(1..=3).contains(&attempts) || window_seconds < 120 {
        return format!(
            "finding: login lockout observed block-for={block_seconds}s attempts={attempts} within={window_seconds}s; required >=900s, <=3, >=120s"
        );
    }
    format!(
        "compliant: login lockout block-for={block_seconds}s attempts={attempts} within={window_seconds}s"
    )
}

fn acl_deny_has_log_input(line: &str) -> Option<bool> {
    let tokens: Vec<_> = line.split_whitespace().collect();
    let mut index = usize::from(
        tokens
            .first()
            .is_some_and(|token| token.parse::<u64>().is_ok()),
    );
    if tokens.get(index) != Some(&"deny") {
        return None;
    }
    index += 1;
    Some(tokens[index..].contains(&"log-input"))
}

/// Review all IPv4/IPv6 ACLs actually bound to interfaces. Named ACLs,
/// sequence-numbered entries, and legacy numbered IPv4 ACLs are supported.
/// An unresolved binding is a finding; an installation with no interface ACL
/// deny entries has no drop event to which `log-input` can apply.
pub fn interface_acl_deny_log_input_observation(config: &str) -> String {
    let blocks = config_blocks(config);
    let mut bound = HashSet::new();
    let mut definitions: HashMap<String, Vec<&str>> = HashMap::new();
    let mut named_definitions = HashSet::new();

    for block in &blocks {
        let header: Vec<_> = block.header.split_whitespace().collect();
        if header.first() == Some(&"interface") {
            for line in &block.lines {
                let tokens: Vec<_> = line.split_whitespace().collect();
                if tokens.first() == Some(&"no") {
                    continue;
                }
                if tokens.get(0..2) == Some(&["ip", "access-group"]) {
                    if tokens.len() < 4 || !matches!(tokens[3], "in" | "out") {
                        return "finding: an interface IPv4 ACL binding is malformed".to_string();
                    }
                    bound.insert(format!("ip:{}", tokens[2]));
                } else if tokens.get(0..2) == Some(&["ipv6", "traffic-filter"]) {
                    if tokens.len() < 4 || !matches!(tokens[3], "in" | "out") {
                        return "finding: an interface IPv6 ACL binding is malformed".to_string();
                    }
                    bound.insert(format!("ipv6:{}", tokens[2]));
                }
            }
            continue;
        }

        let named = if header.get(0..3) == Some(&["ip", "access-list", "standard"])
            || header.get(0..3) == Some(&["ip", "access-list", "extended"])
        {
            header.get(3).map(|name| format!("ip:{name}"))
        } else if header.get(0..2) == Some(&["ipv6", "access-list"]) {
            header.get(2).map(|name| format!("ipv6:{name}"))
        } else {
            None
        };
        if let Some(key) = named {
            if !named_definitions.insert(key.clone()) {
                return format!("finding: interface ACL {key} has multiple definition blocks");
            }
            definitions.insert(key, block.lines.clone());
            continue;
        }

        if header.first() == Some(&"access-list") && header.len() >= 3 {
            definitions
                .entry(format!("ip:{}", header[1]))
                .or_default()
                .push(
                    block
                        .header
                        .strip_prefix("access-list ")
                        .unwrap_or(block.header),
                );
        }
    }

    let mut deny_count = 0_usize;
    for key in &bound {
        let Some(entries) = definitions.get(key) else {
            return format!("finding: interface-bound ACL {key} has no resolvable definition");
        };
        for entry in entries {
            let entry = if key.starts_with("ip:")
                && entry
                    .split_whitespace()
                    .next()
                    .is_some_and(|token| token == key.trim_start_matches("ip:"))
            {
                entry
                    .split_once(char::is_whitespace)
                    .map_or(*entry, |(_, rest)| rest)
            } else {
                *entry
            };
            if let Some(has_log_input) = acl_deny_has_log_input(entry) {
                deny_count += 1;
                if !has_log_input {
                    return format!(
                        "finding: interface-bound ACL {key} contains a deny entry without log-input"
                    );
                }
            }
        }
    }
    format!(
        "compliant: reviewed {} interface-bound ACL(s) and {deny_count} deny entry/entries",
        bound.len()
    )
}

fn remote_aaa_group_names(config: &str) -> HashSet<String> {
    positive_top_level(config, "aaa group server")
        .into_iter()
        .filter_map(|line| {
            let tokens: Vec<_> = line.split_whitespace().collect();
            (tokens.len() == 5 && matches!(tokens[3], "radius" | "tacacs+"))
                .then(|| tokens[4].to_string())
        })
        .collect()
}

fn remote_groups_then_local(methods: &[&str], named_remote_groups: &HashSet<String>) -> bool {
    if methods.last() != Some(&"local") {
        return false;
    }
    let remote_methods = &methods[..methods.len() - 1];
    if remote_methods.is_empty() {
        return false;
    }
    let mut groups = remote_methods.chunks_exact(2);
    if !groups.remainder().is_empty() {
        return false;
    }
    groups.all(|group| {
        group[0] == "group"
            && (matches!(group[1], "radius" | "tacacs+") || named_remote_groups.contains(group[1]))
    })
}

/// Require one and only one local username, a Common Criteria policy binding,
/// and only recognized remote group methods followed immediately by `local`
/// in every configured AAA login list.
pub fn single_local_fallback_account_observation(config: &str) -> String {
    let usernames = positive_top_level(config, "username");
    if usernames.len() != 1 {
        return format!(
            "finding: exactly one local username is required; observed {}",
            usernames.len()
        );
    }
    let username_tokens: Vec<_> = usernames[0].split_whitespace().collect();
    let common_criteria = username_tokens
        .iter()
        .position(|token| *token == "common-criteria-policy")
        .is_some_and(|index| username_tokens.get(index + 1).is_some());
    let credential = username_tokens
        .iter()
        .position(|token| matches!(*token, "password" | "secret"))
        .is_some_and(|index| username_tokens.get(index + 1).is_some());
    if !common_criteria || !credential {
        return "finding: the sole local account is not bound to a Common Criteria policy and credential"
            .to_string();
    }

    let named_remote_groups = remote_aaa_group_names(config);
    let login_lists = positive_top_level(config, "aaa authentication login");
    if login_lists.is_empty() {
        return "finding: no AAA login authentication list defines remote-first local fallback"
            .to_string();
    }
    for line in &login_lists {
        let tokens: Vec<_> = line.split_whitespace().collect();
        if tokens.len() < 6 {
            return "finding: an AAA login authentication list is malformed".to_string();
        }
        let methods = &tokens[4..];
        if !remote_groups_then_local(methods, &named_remote_groups) {
            return "finding: every AAA login list must contain only one or more defined RADIUS/TACACS group methods followed immediately by local"
                .to_string();
        }
    }
    format!(
        "compliant: one Common-Criteria-bound local account is the final fallback in {} AAA login list(s)",
        login_lists.len()
    )
}

/// Evaluate numeric `min-length` values inside every represented Common
/// Criteria password-policy block. A stronger minimum is accepted.
pub fn password_minimum_length_observation(config: &str) -> String {
    if !config_line_exists(config, "aaa new-model") {
        return "finding: aaa new-model is not enabled".to_string();
    }
    let policy_blocks: Vec<_> = config_blocks(config)
        .into_iter()
        .filter(|block| command_starts_with(block.header, "aaa common-criteria policy"))
        .collect();
    if policy_blocks.is_empty() {
        return "finding: no Common Criteria password policy is configured".to_string();
    }
    let mut observed = Vec::new();
    for block in policy_blocks {
        let values: Vec<_> = block
            .lines
            .iter()
            .filter(|line| !line.starts_with("no ") && command_starts_with(line, "min-length"))
            .map(|line| one_u32_after_prefix(line, "min-length"))
            .collect();
        if values.len() != 1
            || block
                .lines
                .iter()
                .any(|line| command_starts_with(line, "no min-length"))
        {
            return "finding: every Common Criteria policy needs one unambiguous min-length"
                .to_string();
        }
        let Some(value) = values[0] else {
            return "finding: Common Criteria min-length is malformed".to_string();
        };
        if value < 15 {
            return format!("finding: Common Criteria min-length {value} is below 15");
        }
        observed.push(value);
    }
    format!("compliant: Common Criteria minimum lengths={observed:?}")
}

fn file_system_privilege_observation(config: &str) -> String {
    let configured = positive_top_level(config, "file privilege");
    let reset = config_line_exists(config, "no file privilege");
    if configured.len() > 1 || (!configured.is_empty() && reset) {
        return "finding: file privilege configuration is ambiguous or contradictory".to_string();
    }
    if configured.is_empty() {
        return "compliant: effective file-system privilege is the IOS default level 15"
            .to_string();
    }
    let tokens: Vec<_> = configured[0].split_whitespace().collect();
    let Some(level) = (tokens.len() == 3)
        .then(|| tokens[2].parse::<u32>().ok())
        .flatten()
    else {
        return "finding: file privilege level is malformed".to_string();
    };
    if level != 15 {
        return format!(
            "finding: effective file-system privilege is {level}; required level is 15"
        );
    }
    "compliant: effective file-system privilege is explicitly level 15".to_string()
}

/// V-215822 applies regardless of persistent-logging state.
pub fn file_system_privilege_protection_observation(config: &str) -> String {
    file_system_privilege_observation(config)
}

/// V-215820/V-215821 are explicitly not applicable when persistent logging is
/// absent. When it is enabled, use the same effective privilege decision as
/// V-215822 and preserve the NotApplicable outcome for checklist projection.
pub fn persistent_audit_file_protection_observation(config: &str) -> String {
    let persistent = positive_top_level(config, "logging persistent");
    let reset = config_line_exists(config, "no logging persistent");
    if persistent.is_empty() {
        return "not_applicable: persistent logging is not enabled".to_string();
    }
    if persistent.len() != 1 || reset {
        return "finding: persistent logging configuration is ambiguous or contradictory"
            .to_string();
    }
    let persistent_tokens: Vec<_> = persistent[0].split_whitespace().collect();
    if persistent_tokens.len() < 4
        || persistent_tokens.get(2) != Some(&"url")
        || persistent_tokens[3].is_empty()
    {
        return "finding: persistent logging destination is malformed".to_string();
    }
    file_system_privilege_observation(config)
}

fn exec_timeout_seconds(lines: &[&str]) -> Result<u64, String> {
    let commands: Vec<_> = lines
        .iter()
        .filter(|line| !line.starts_with("no ") && command_starts_with(line, "exec-timeout"))
        .collect();
    if commands.len() != 1
        || lines
            .iter()
            .any(|line| command_starts_with(line, "no exec-timeout"))
    {
        return Err("exactly one effective exec-timeout is required".to_string());
    }
    let tokens: Vec<_> = commands[0].split_whitespace().collect();
    if !(2..=3).contains(&tokens.len()) {
        return Err("exec-timeout syntax is malformed".to_string());
    }
    let minutes = tokens[1]
        .parse::<u64>()
        .map_err(|_| "exec-timeout minutes are not numeric".to_string())?;
    let seconds = tokens
        .get(2)
        .unwrap_or(&"0")
        .parse::<u64>()
        .map_err(|_| "exec-timeout seconds are not numeric".to_string())?;
    if seconds > 59 {
        return Err("exec-timeout seconds must be 0..=59".to_string());
    }
    minutes
        .checked_mul(60)
        .and_then(|value| value.checked_add(seconds))
        .ok_or_else(|| "exec-timeout value overflows".to_string())
}

/// Require every represented console, VTY, and auxiliary line block to time
/// out in one through 300 seconds. Enabled HTTP(S) management receives the
/// same independent idle limit.
pub fn management_idle_timeout_observation(config: &str) -> String {
    let mut console_count = 0_usize;
    let mut vty_count = 0_usize;
    let mut reviewed = 0_usize;
    for block in config_blocks(config) {
        let tokens: Vec<_> = block.header.split_whitespace().collect();
        if tokens.first() != Some(&"line") || tokens.len() < 2 {
            continue;
        }
        match tokens[1] {
            "con" | "console" => console_count += 1,
            "vty" => vty_count += 1,
            "aux" | "auxiliary" => {}
            _ => continue,
        }
        reviewed += 1;
        let seconds = match exec_timeout_seconds(&block.lines) {
            Ok(value) => value,
            Err(error) => return format!("finding: {}: {error}", block.header),
        };
        if !(1..=300).contains(&seconds) {
            return format!(
                "finding: {} idle timeout is {seconds} seconds; required 1..=300",
                block.header
            );
        }
    }
    if console_count == 0 || vty_count == 0 {
        return "finding: at least one console and one VTY management block are required"
            .to_string();
    }

    let http_enabled = config_line_exists(config, "ip http server")
        || config_line_exists(config, "ip http secure-server");
    if http_enabled {
        let policies = positive_top_level(config, "ip http timeout-policy");
        if policies.len() != 1 || config_line_exists(config, "no ip http timeout-policy") {
            return "finding: enabled HTTP(S) management requires one timeout-policy".to_string();
        }
        let tokens: Vec<_> = policies[0].split_whitespace().collect();
        let idle_positions: Vec<_> = tokens
            .iter()
            .enumerate()
            .filter_map(|(index, token)| (*token == "idle").then_some(index))
            .collect();
        if idle_positions.len() != 1 {
            return "finding: HTTP timeout-policy has no unambiguous idle value".to_string();
        }
        let Some(idle) = tokens
            .get(idle_positions[0] + 1)
            .and_then(|value| value.parse::<u64>().ok())
        else {
            return "finding: HTTP idle timeout is malformed".to_string();
        };
        if !(1..=300).contains(&idle) {
            return format!("finding: HTTP(S) idle timeout is {idle} seconds; required 1..=300");
        }
    }
    format!(
        "compliant: {reviewed} line block(s) and HTTP enabled={http_enabled} terminate idle management sessions within five minutes"
    )
}

#[derive(Debug)]
struct NtpServer<'a> {
    endpoint: &'a str,
    key: Option<&'a str>,
}

fn ntp_servers(config: &str) -> Result<Vec<NtpServer<'_>>, String> {
    positive_top_level(config, "ntp server")
        .into_iter()
        .map(|line| {
            let tokens: Vec<_> = line.split_whitespace().collect();
            let endpoint_index = if tokens.get(2) == Some(&"vrf") { 4 } else { 2 };
            let endpoint = tokens
                .get(endpoint_index)
                .copied()
                .ok_or_else(|| "an NTP server endpoint is malformed".to_string())?;
            let key_positions: Vec<_> = tokens
                .iter()
                .enumerate()
                .skip(endpoint_index + 1)
                .filter_map(|(index, token)| (*token == "key").then_some(index))
                .collect();
            if key_positions.len() > 1 {
                return Err(format!("NTP server {endpoint} has ambiguous key bindings"));
            }
            let key = key_positions
                .first()
                .and_then(|index| tokens.get(index + 1))
                .copied();
            if !key_positions.is_empty() && key.is_none() {
                return Err(format!("NTP server {endpoint} has a malformed key binding"));
            }
            Ok(NtpServer { endpoint, key })
        })
        .collect()
}

/// Require at least two distinct configured NTP sources, and require every
/// configured source to be present in the asset-bound signed approval list.
pub fn redundant_authoritative_ntp_sources_observation(
    config: &str,
    approved_sources: &[String],
) -> String {
    let servers = match ntp_servers(config) {
        Ok(servers) => servers,
        Err(error) => return format!("finding: {error}"),
    };
    let approved: HashSet<_> = approved_sources
        .iter()
        .map(|source| source.to_ascii_lowercase())
        .collect();
    let observed: HashSet<_> = servers
        .iter()
        .map(|server| server.endpoint.to_ascii_lowercase())
        .collect();
    if observed.len() < 2 {
        return format!(
            "finding: {} distinct NTP source(s) configured; at least two are required",
            observed.len()
        );
    }
    let unapproved: Vec<_> = observed.difference(&approved).cloned().collect();
    if !unapproved.is_empty() {
        return format!(
            "finding: configured NTP sources are absent from signed approval list: {unapproved:?}"
        );
    }
    format!(
        "compliant: {} distinct configured NTP sources are organization-approved",
        observed.len()
    )
}

/// Verify global NTP authentication, SHA-2 key definitions, trusted-key
/// linkage, and a key binding on every configured server.
pub fn ntp_authentication_observation(config: &str) -> String {
    let authenticate = positive_top_level(config, "ntp authenticate");
    if authenticate.len() != 1
        || authenticate[0].split_whitespace().count() != 2
        || config_line_exists(config, "no ntp authenticate")
    {
        return "finding: one unambiguous ntp authenticate command is required".to_string();
    }

    let mut keys = HashMap::new();
    for line in positive_top_level(config, "ntp authentication-key") {
        let tokens: Vec<_> = line.split_whitespace().collect();
        if tokens.len() < 5 || tokens[3] != "hmac-sha2-256" {
            return "finding: every NTP authentication key must use hmac-sha2-256 and contain key material"
                .to_string();
        }
        if tokens[2]
            .parse::<u32>()
            .ok()
            .filter(|value| *value > 0)
            .is_none()
            || keys.insert(tokens[2], tokens[3]).is_some()
        {
            return "finding: NTP authentication key IDs are malformed or duplicated".to_string();
        }
    }
    if keys.is_empty() {
        return "finding: no SHA-2 NTP authentication key is configured".to_string();
    }

    let trusted_lines = positive_top_level(config, "ntp trusted-key");
    if trusted_lines.is_empty() {
        return "finding: no NTP trusted key is configured".to_string();
    }
    let mut trusted = HashSet::new();
    for line in trusted_lines {
        let tokens: Vec<_> = line.split_whitespace().collect();
        if tokens.len() < 3 {
            return "finding: NTP trusted-key syntax is malformed".to_string();
        }
        for token in &tokens[2..] {
            if token
                .parse::<u32>()
                .ok()
                .filter(|value| *value > 0)
                .is_none()
            {
                return "finding: NTP trusted-key IDs must be positive integers".to_string();
            }
            trusted.insert(*token);
        }
    }
    if trusted.iter().any(|key| !keys.contains_key(key)) {
        return "finding: a trusted NTP key has no approved SHA-2 definition".to_string();
    }

    let servers = match ntp_servers(config) {
        Ok(servers) => servers,
        Err(error) => return format!("finding: {error}"),
    };
    if servers.is_empty() {
        return "finding: no NTP server is configured".to_string();
    }
    for server in &servers {
        let Some(key) = server.key else {
            return format!("finding: NTP server {} has no key binding", server.endpoint);
        };
        if !trusted.contains(key) || !keys.contains_key(key) {
            return format!(
                "finding: NTP server {} key {key} is not linked to a trusted SHA-2 definition",
                server.endpoint
            );
        }
    }
    format!(
        "compliant: {} NTP server(s) use trusted hmac-sha2-256 keys",
        servers.len()
    )
}

fn ssh_algorithm_observation(config: &str, kind: &str, approved: &[&str]) -> String {
    let versions = positive_top_level(config, "ip ssh version");
    if versions.len() != 1
        || versions[0].split_whitespace().collect::<Vec<_>>() != ["ip", "ssh", "version", "2"]
        || config_line_exists(config, "no ip ssh version")
    {
        return "finding: SSH version 2 must be configured unambiguously".to_string();
    }
    let prefix = format!("ip ssh server algorithm {kind}");
    let algorithms = positive_top_level(config, &prefix);
    if algorithms.len() != 1
        || config_line_exists(config, &format!("no ip ssh server algorithm {kind}"))
    {
        return format!("finding: exactly one effective SSH {kind} allowlist is required");
    }
    let tokens: Vec<_> = algorithms[0].split_whitespace().collect();
    let values = &tokens[5..];
    if values.is_empty() {
        return format!("finding: SSH {kind} allowlist is empty");
    }
    let unique: HashSet<_> = values.iter().copied().collect();
    if unique.len() != values.len() || values.iter().any(|value| !approved.contains(value)) {
        return format!(
            "finding: SSH {kind} allowlist contains a duplicate or unapproved algorithm"
        );
    }
    format!("compliant: SSH {kind} allowlist={values:?}")
}

pub fn ssh_mac_algorithms_observation(config: &str) -> String {
    ssh_algorithm_observation(config, "mac", &["hmac-sha2-256", "hmac-sha2-512"])
}

pub fn ssh_encryption_algorithms_observation(config: &str) -> String {
    ssh_algorithm_observation(
        config,
        "encryption",
        &["aes128-ctr", "aes192-ctr", "aes256-ctr"],
    )
}

fn valid_syslog_endpoint(value: &str) -> bool {
    if value.parse::<IpAddr>().is_ok() {
        return true;
    }
    !value.is_empty()
        && value.len() <= 255
        && value.bytes().any(|byte| byte.is_ascii_alphabetic())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':'))
}

/// Count distinct modern `logging host` and legacy `logging <destination>`
/// directives without mistaking local logging controls for destinations.
pub fn syslog_server_count_observation(config: &str) -> String {
    const LOCAL_LOGGING_KEYWORDS: &[&str] = &[
        "buffered",
        "console",
        "discriminator",
        "facility",
        "history",
        "monitor",
        "on",
        "origin-id",
        "persistent",
        "rate-limit",
        "snmp-authfail",
        "source-interface",
        "trap",
        "userinfo",
    ];
    let mut destinations = HashSet::new();
    for command in config_commands(config) {
        if command.indented || command.text.starts_with("no ") {
            continue;
        }
        let tokens: Vec<_> = command.text.split_whitespace().collect();
        if tokens.first() != Some(&"logging") || tokens.len() < 2 {
            continue;
        }
        let target = if tokens[1] == "host" {
            let index = if tokens.get(2) == Some(&"vrf") { 4 } else { 2 };
            let Some(target) = tokens.get(index) else {
                return "finding: a logging host destination is malformed".to_string();
            };
            *target
        } else if LOCAL_LOGGING_KEYWORDS.contains(&tokens[1]) {
            continue;
        } else {
            tokens[1]
        };
        if !valid_syslog_endpoint(target) {
            return format!("finding: syslog destination {target:?} is malformed");
        }
        destinations.insert(target.to_ascii_lowercase());
    }
    if destinations.len() < 2 {
        return format!(
            "finding: {} distinct syslog destination(s) configured; at least two are required",
            destinations.len()
        );
    }
    format!(
        "compliant: {} distinct remote syslog destinations configured",
        destinations.len()
    )
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

        const MANUAL_RULES: [&str; 9] = [
            "V-215812", "V-215814", "V-215823", "V-215841", "V-215842", "V-215854", "V-215855",
            "V-215856", "V-220140",
        ];
        let pack: CheckPack = serde_json::from_str(include_str!(
            "../../../../content/check_packs/cisco_ios_xe_router_ndm.json"
        ))
        .expect("embedded Cisco pack fixture must parse");
        assert_eq!(pack.checks.len(), 33);
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
        assert_eq!(results.len(), 33);
        assert!(results
            .iter()
            .all(|result| !MANUAL_RULES.contains(&result.vuln_id.as_str())));
        for vuln_id in [
            "V-215807", "V-215813", "V-215818", "V-215820", "V-215821", "V-215822", "V-215824",
            "V-215826", "V-215833", "V-215836", "V-215837", "V-215838", "V-215843", "V-215844",
            "V-215845", "V-220139",
        ] {
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
        test_organization_policy_for("rtr-semantic-counterexamples")
    }

    fn test_organization_policy_for(
        hostname: &str,
    ) -> crate::organization_policy::VerifiedOrganizationPolicy {
        let now = chrono::Utc::now();
        let document = serde_json::json!({
            "schema": "automatestig-organization-policy/v1",
            "policy_id": "network-unit-test",
            "policy_version": "1",
            "stig_id": "Cisco_IOS-XE_Router_NDM_STIG",
            "stig_release": "V3R7",
            "asset_hostname": hostname,
            "effective_from": (now - chrono::Duration::days(1)).to_rfc3339(),
            "expires_at": (now + chrono::Duration::days(1)).to_rfc3339(),
            "rules": {
                "V-215807": {"max_concurrent_management_sessions": 2},
                "V-215836": {"minimum_logging_buffer_bytes": 4096000},
                "V-215838": {"approved_authoritative_ntp_sources": ["10.10.1.10", "10.10.1.11"]}
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
            hostname,
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

    #[test]
    fn expanded_rules_cover_compliant_finding_and_truncated_fixtures() {
        use crate::checks::{executor::execute_check_pack, CheckPack, CheckPlatform, SystemData};

        const ADDED_RULES: [&str; 12] = [
            "V-215813", "V-215818", "V-215820", "V-215821", "V-215824", "V-215826", "V-215833",
            "V-215838", "V-215843", "V-215844", "V-215845", "V-220139",
        ];
        let pack: CheckPack = serde_json::from_str(include_str!(
            "../../../../content/check_packs/cisco_ios_xe_router_ndm.json"
        ))
        .expect("Cisco pack must parse");

        for (config, hostname, should_pass) in [
            (
                include_str!("../../../../fixtures/network/ios_xe_router_compliant.txt"),
                "rtr-compliant-01",
                true,
            ),
            (
                include_str!("../../../../fixtures/network/ios_xe_router_findings.txt"),
                "rtr-findings-01",
                false,
            ),
        ] {
            crate::remote::validate_network_config(CheckPlatform::CiscoIos, config)
                .expect("complete Cisco fixture");
            let data = SystemData {
                collection_complete: true,
                network_config: Some(config.to_string()),
                organization_policy: Some(test_organization_policy_for(hostname)),
                ..Default::default()
            };
            let results = execute_check_pack(&pack, &data);
            assert_eq!(results.len(), 33);
            assert!(
                results
                    .iter()
                    .all(|result| { result.error.is_none() && result.passed == should_pass }),
                "full Cisco fixture did not produce a uniform expected result: {results:#?}"
            );
            for vuln_id in ADDED_RULES {
                let result = results
                    .iter()
                    .find(|result| result.vuln_id == vuln_id)
                    .unwrap_or_else(|| panic!("missing added check {vuln_id}"));
                assert!(result.error.is_none(), "{vuln_id}: {result:?}");
                assert_eq!(result.passed, should_pass, "{vuln_id}: {result:?}");
            }
        }

        let truncated =
            include_str!("../../../../fixtures/scanner_scenarios/inputs/cisco-truncated.cfg");
        assert!(
            crate::remote::validate_network_config(CheckPlatform::CiscoIos, truncated).is_err()
        );
        assert!(ADDED_RULES.iter().all(|vuln_id| {
            pack.checks
                .iter()
                .any(|definition| definition.vuln_id == *vuln_id)
        }));
    }

    #[test]
    fn login_and_timeout_checks_parse_numeric_semantics() {
        assert!(
            login_block_for_observation("login block-for 901 attempts 2 within 180\n")
                .starts_with("compliant:")
        );
        for bad in [
            "login block-for 899 attempts 3 within 120\n",
            "login block-for 900 attempts 4 within 120\n",
            "login block-for 900 attempts 3 within 60\n",
            "login block-for nine attempts 3 within 120\n",
        ] {
            assert!(login_block_for_observation(bad).starts_with("finding:"));
        }

        let complete = "line con 0\n exec-timeout 4 59\nline vty 0 4\n exec-timeout 5\nip http secure-server\nip http timeout-policy idle 300 life 86400 requests 100\nend\n";
        assert!(management_idle_timeout_observation(complete).starts_with("compliant:"));
        for bad in [
            "line con 0\n exec-timeout 5 0\nline vty 0 4\n exec-timeout 0 0\nend\n",
            "line con 0\n exec-timeout 5 0\nline vty 0 4\n exec-timeout 1 599\nend\n",
            "line con 0\n exec-timeout 5 0\nline vty 0 4\n exec-timeout 5 0\nip http secure-server\nend\n",
        ] {
            assert!(management_idle_timeout_observation(bad).starts_with("finding:"));
        }
    }

    #[test]
    fn acl_local_account_and_password_policy_checks_are_contextual() {
        let acl = "interface Gi0/0\n ip access-group EDGE in\nip access-list extended EDGE\n 10 deny ip any any log-input\nend\n";
        assert!(interface_acl_deny_log_input_observation(acl).starts_with("compliant:"));
        assert!(interface_acl_deny_log_input_observation(
            "interface Gi0/0\n ip access-group EDGE in\nip access-list extended EDGE\n deny ip any any\nend\n"
        )
        .starts_with("finding:"));
        assert!(interface_acl_deny_log_input_observation(
            "interface Gi0/0\n ip access-group MISSING in\nend\n"
        )
        .starts_with("finding:"));

        let fallback = "aaa authentication login default group radius local\nusername fallback common-criteria-policy STIG secret 9 X\nend\n";
        assert!(single_local_fallback_account_observation(fallback).starts_with("compliant:"));
        assert!(single_local_fallback_account_observation(
            "aaa authentication login default local group radius\nusername a password 7 X\nusername b password 7 X\nend\n"
        )
        .starts_with("finding:"));

        assert!(password_minimum_length_observation(
            "aaa new-model\naaa common-criteria policy STIG\n min-length 16\nend\n"
        )
        .starts_with("compliant:"));
        assert!(password_minimum_length_observation(
            "aaa new-model\naaa common-criteria policy STIG\n min-length 8\nend\n"
        )
        .starts_with("finding:"));
    }

    #[test]
    fn local_fallback_rejects_bypass_and_unsupported_method_stacks() {
        fn config_with_methods(methods: &str) -> String {
            format!(
                "aaa authentication login default {methods}\nusername fallback common-criteria-policy STIG secret 9 X\nend\n"
            )
        }

        for methods in ["group radius local", "group tacacs+ group radius local"] {
            let config = config_with_methods(methods);
            let observation = single_local_fallback_account_observation(&config);
            assert!(
                observation.starts_with("compliant:"),
                "{methods}: {observation}"
            );
        }

        let named_groups = "aaa group server radius PRIMARY\n server-private 192.0.2.10 auth-port 1812 acct-port 1813 key 7 X\naaa group server tacacs+ SECONDARY\n server-private 192.0.2.11 key 7 X\naaa authentication login default group PRIMARY group SECONDARY local\nusername fallback common-criteria-policy STIG secret 9 X\nend\n";
        let observation = single_local_fallback_account_observation(named_groups);
        assert!(
            observation.starts_with("compliant:"),
            "named groups: {observation}"
        );

        for methods in [
            "group radius none local",
            "group radius enable local",
            "group radius group UNKNOWN local",
            "group radius group local",
            "group tacacs local",
            "radius local",
            "group radius local none",
        ] {
            let config = config_with_methods(methods);
            let observation = single_local_fallback_account_observation(&config);
            assert!(
                observation.starts_with("finding:"),
                "{methods}: {observation}"
            );
        }
    }

    #[test]
    fn file_privilege_checks_accept_explicit_15_and_preserve_not_applicable() {
        use crate::checks::{executor::execute_check, Check, CheckDefinition, CheckPlatform};
        use crate::models::finding::FindingStatus;

        for config in ["end\n", "file privilege 15\nend\n"] {
            assert!(file_system_privilege_protection_observation(config).starts_with("compliant:"));
        }
        for config in [
            "file privilege 10\nend\n",
            "file privilege nope\nend\n",
            "file privilege 15\nno file privilege\nend\n",
        ] {
            assert!(file_system_privilege_protection_observation(config).starts_with("finding:"));
        }
        assert!(
            persistent_audit_file_protection_observation("file privilege 10\nend\n")
                .starts_with("not_applicable:")
        );
        assert!(persistent_audit_file_protection_observation(
            "logging persistent url disk0:/logfile\nfile privilege 15\nend\n"
        )
        .starts_with("compliant:"));
        assert!(persistent_audit_file_protection_observation(
            "logging persistent url disk0:/logfile\nfile privilege 10\nend\n"
        )
        .starts_with("finding:"));
        assert!(persistent_audit_file_protection_observation(
            "logging persistent\nfile privilege 15\nend\n"
        )
        .starts_with("finding:"));

        let definition = CheckDefinition {
            vuln_id: "V-215820".to_string(),
            platform: CheckPlatform::CiscoIos,
            check: Check::CiscoPersistentAuditModificationProtection,
            expected: crate::checks::ExpectedResult::Matches {
                pattern: "^(compliant|not_applicable):".to_string(),
            },
            description: None,
        };
        let data = crate::checks::SystemData {
            network_config: Some("end\n".to_string()),
            collection_complete: true,
            ..Default::default()
        };
        let result = execute_check(&definition, &data);
        assert!(result.passed);
        assert_eq!(result.to_finding_status(), FindingStatus::NotApplicable);

        let generic = CheckDefinition {
            vuln_id: "V-215820".to_string(),
            platform: CheckPlatform::Bsd,
            check: Check::Command {
                command: "generic-device-output".to_string(),
                pattern: None,
                is_regex: false,
            },
            expected: crate::checks::ExpectedResult::Matches {
                pattern: "^not_applicable:".to_string(),
            },
            description: None,
        };
        let mut generic_data = crate::checks::SystemData::default();
        generic_data.command_outputs.insert(
            "generic-device-output".to_string(),
            "not_applicable: device-controlled text".to_string(),
        );
        let generic_result = execute_check(&generic, &generic_data);
        assert!(generic_result.passed);
        assert_eq!(
            generic_result.to_finding_status(),
            FindingStatus::NotAFinding
        );
    }

    #[test]
    fn ntp_ssh_and_syslog_checks_validate_complete_relationships() {
        let ntp = "ntp authenticate\nntp authentication-key 1 hmac-sha2-256 X\nntp trusted-key 1\nntp server 10.10.1.10 key 1\nntp server 10.10.1.11 key 1\nend\n";
        assert!(ntp_authentication_observation(ntp).starts_with("compliant:"));
        assert!(redundant_authoritative_ntp_sources_observation(
            ntp,
            &["10.10.1.10".into(), "10.10.1.11".into()]
        )
        .starts_with("compliant:"));
        assert!(redundant_authoritative_ntp_sources_observation(
            ntp,
            &["10.10.1.10".into(), "10.10.1.12".into()]
        )
        .starts_with("finding:"));
        assert!(ntp_authentication_observation(
            "ntp authenticate\nntp authentication-key 1 md5 X\nntp trusted-key 1\nntp server 10.10.1.10 key 1\n"
        )
        .starts_with("finding:"));

        let ssh = "ip ssh version 2\nip ssh server algorithm mac hmac-sha2-512 hmac-sha2-256\nip ssh server algorithm encryption aes256-ctr aes128-ctr\nend\n";
        assert!(ssh_mac_algorithms_observation(ssh).starts_with("compliant:"));
        assert!(ssh_encryption_algorithms_observation(ssh).starts_with("compliant:"));
        assert!(ssh_mac_algorithms_observation(
            "ip ssh version 2\nip ssh server algorithm mac hmac-sha2-256 hmac-md5\n"
        )
        .starts_with("finding:"));
        assert!(ssh_encryption_algorithms_observation(
            "ip ssh version 2\nip ssh server algorithm encryption aes256-ctr 3des-cbc\n"
        )
        .starts_with("finding:"));

        assert!(syslog_server_count_observation(
            "logging host vrf MGMT 192.0.2.10\nlogging syslog.example.mil\n"
        )
        .starts_with("compliant:"));
        assert!(syslog_server_count_observation(
            "logging buffered 4096000\nlogging host 192.0.2.10\nlogging 192.0.2.10\n"
        )
        .starts_with("finding:"));
    }
}
