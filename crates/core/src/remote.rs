//! Read-only command plans and deterministic assembly for remote device evidence.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::checks::{Check, CheckDefinition, CheckPlatform, SystemData};

/// Return whether a fingerprint uses OpenSSH's canonical unpadded SHA-256
/// display format.
pub fn is_openssh_sha256_fingerprint(fingerprint: &str) -> bool {
    fingerprint.strip_prefix("SHA256:").is_some_and(|digest| {
        digest.len() == 43
            && digest
                .as_bytes()
                .last()
                .is_some_and(|byte| b"AEIMQUYcgkosw048".contains(byte))
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/'))
    })
}

/// Commands to collect system data, organized by platform.
#[derive(Debug, Clone)]
pub struct CollectionPlan {
    pub platform: CheckPlatform,
    pub commands: Vec<CollectionCommand>,
    /// Digest of the evaluation predicates which consume the collected data.
    /// This prevents old evidence being reinterpreted under changed checks.
    pub check_definitions_sha256: String,
}

/// A read-only collection command and the key used to retain its output.
#[derive(Debug, Clone)]
pub struct CollectionCommand {
    pub command: String,
    pub data_key: String,
    /// Exit statuses which describe a successfully observed target state.
    pub accepted_exit_codes: Vec<u32>,
    /// Output validation applied before the text can become evaluation evidence.
    pub output_policy: OutputPolicy,
}

/// Command-specific validation required before stdout is trusted as evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputPolicy {
    Any,
    OntapSessionLimit,
    OntapAuditGuarantee,
    OntapNtpAuthentication,
    OntapPasswordMinimumLength,
    OntapAdminNumericMinimum,
    OntapAdminBooleanAll,
    BsdAuditdStatus,
    BsdPfStatus,
}

/// A transport-level outcome. Only `Success` may be considered for evaluation,
/// and it is still subject to the command's output policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandStatus {
    Success,
    ExitFailure,
    MissingExitStatus,
    TransportError,
    Timeout,
    OutputLimit,
    ProtocolError,
    SemanticError,
    MissingEvidence,
}

/// Complete evidence for one planned remote command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandEvidence {
    pub data_key: String,
    pub command: String,
    pub status: CommandStatus,
    #[serde(default)]
    pub stdout: String,
    #[serde(default)]
    pub stderr: String,
    #[serde(default)]
    pub exit_code: Option<u32>,
    #[serde(default)]
    pub duration_ms: u64,
    #[serde(default)]
    pub error: Option<String>,
}

impl CommandEvidence {
    pub fn success(
        data_key: impl Into<String>,
        command: impl Into<String>,
        stdout: String,
        stderr: String,
        exit_code: u32,
        duration_ms: u64,
    ) -> Self {
        Self {
            data_key: data_key.into(),
            command: command.into(),
            status: CommandStatus::Success,
            stdout,
            stderr,
            exit_code: Some(exit_code),
            duration_ms,
            error: None,
        }
    }

    pub fn failed(
        data_key: impl Into<String>,
        command: impl Into<String>,
        status: CommandStatus,
        error: impl Into<String>,
    ) -> Self {
        debug_assert_ne!(status, CommandStatus::Success);
        Self {
            data_key: data_key.into(),
            command: command.into(),
            status,
            stdout: String::new(),
            stderr: String::new(),
            exit_code: None,
            duration_ms: 0,
            error: Some(error.into()),
        }
    }

    pub fn with_diagnostics(
        mut self,
        stdout: String,
        stderr: String,
        exit_code: Option<u32>,
        duration_ms: u64,
    ) -> Self {
        self.stdout = stdout;
        self.stderr = stderr;
        self.exit_code = exit_code;
        self.duration_ms = duration_ms;
        self
    }
}

/// Generate the smallest read-only collection plan needed by the selected
/// check definitions. This avoids unrelated command failures and ensures
/// every automated check has an explicit collection source.
pub fn generate_collection_plan(
    platform: CheckPlatform,
    checks: &[CheckDefinition],
) -> Result<CollectionPlan, String> {
    if platform == CheckPlatform::CiscoIos {
        return Err(
            "Cisco IOS-XE is config-file-only; SSH transcript collection is unsupported".into(),
        );
    }
    if let Some(definition) = checks
        .iter()
        .find(|definition| definition.platform != platform)
    {
        return Err(format!(
            "check {} targets {:?}, not requested platform {:?}",
            definition.vuln_id, definition.platform, platform
        ));
    }

    let mut commands = Vec::new();
    for definition in checks {
        add_check_commands(platform, &definition.check, &mut commands)?;
    }
    if commands.is_empty() {
        return Err("the selected STIG has no remotely collectable checks".into());
    }
    let check_definitions_sha256 = format!(
        "{:x}",
        Sha256::digest(
            serde_json::to_vec(checks)
                .map_err(|error| format!("failed to hash check definitions: {error}"))?
        )
    );
    Ok(CollectionPlan {
        platform,
        commands,
        check_definitions_sha256,
    })
}

fn command(platform: CheckPlatform, command: &str, data_key: &str) -> CollectionCommand {
    let output_policy = match (platform, data_key) {
        (CheckPlatform::Ontap, "security session limit show -interface cli") => {
            OutputPolicy::OntapSessionLimit
        }
        (CheckPlatform::Ontap, "vserver audit show -fields audit-guarantee") => {
            OutputPolicy::OntapAuditGuarantee
        }
        (CheckPlatform::Ontap, "cluster time-service ntp server show") => {
            OutputPolicy::OntapNtpAuthentication
        }
        (
            CheckPlatform::Ontap,
            "security login role config show -role admin -fields passwd-minlength",
        ) => OutputPolicy::OntapPasswordMinimumLength,
        (
            CheckPlatform::Ontap,
            "security login role config show -role admin -fields passwd-min-uppercase-chars"
            | "security login role config show -role admin -fields passwd-min-lowercase-chars"
            | "security login role config show -role admin -fields passwd-min-special-chars",
        ) => OutputPolicy::OntapAdminNumericMinimum,
        (
            CheckPlatform::Ontap,
            "security login role config show -role admin -fields passwd-alphanum",
        ) => OutputPolicy::OntapAdminBooleanAll,
        (CheckPlatform::Bsd, crate::checks::freebsd::AUDITD_STATUS_COMMAND) => {
            OutputPolicy::BsdAuditdStatus
        }
        (CheckPlatform::Bsd, crate::checks::freebsd::PF_STATUS_COMMAND) => {
            OutputPolicy::BsdPfStatus
        }
        _ => OutputPolicy::Any,
    };
    let accepted_exit_codes = if matches!(
        output_policy,
        OutputPolicy::BsdAuditdStatus | OutputPolicy::BsdPfStatus
    ) {
        vec![0, 1]
    } else {
        vec![0]
    };
    CollectionCommand {
        command: command.to_string(),
        data_key: data_key.to_string(),
        accepted_exit_codes,
        output_policy,
    }
}

impl CollectionPlan {
    /// Digest of the exact platform, keys, commands, and accepted statuses.
    pub fn digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"automatestig-collection-plan-v2\0");
        hasher.update(serde_json::to_vec(&self.platform).expect("platform serialization"));
        hasher.update([0]);
        hasher.update(self.check_definitions_sha256.as_bytes());
        for item in &self.commands {
            hasher.update([0]);
            hasher.update(item.data_key.as_bytes());
            hasher.update([0]);
            hasher.update(item.command.as_bytes());
            for code in &item.accepted_exit_codes {
                hasher.update(code.to_be_bytes());
            }
            hasher.update([0]);
            hasher.update(
                serde_json::to_vec(&item.output_policy).expect("output policy serialization"),
            );
        }
        format!("{:x}", hasher.finalize())
    }
}

fn push_unique(commands: &mut Vec<CollectionCommand>, item: CollectionCommand) {
    if !commands
        .iter()
        .any(|existing| existing.data_key == item.data_key)
    {
        commands.push(item);
    }
}

fn add_check_commands(
    platform: CheckPlatform,
    check: &Check,
    commands: &mut Vec<CollectionCommand>,
) -> Result<(), String> {
    let item = match check {
        Check::Predicate { program } => {
            program.validate()?;
            let value = program.observation_key().ok_or_else(|| {
                "network-config predicates consume an operator-supplied running config".to_string()
            })?;
            if !matches!(platform, CheckPlatform::Ontap | CheckPlatform::Bsd) {
                return Err(
                    "predicate observations are remotely collectable only for ONTAP and FreeBSD"
                        .into(),
                );
            }
            // The pure DSL names evidence only. At this separate collection
            // boundary, an exact reviewed observation key may map to the same
            // read-only operation; arbitrary keys remain non-executable.
            crate::check_packs::validate_read_only_command(platform, value)?;
            let executed = if platform == CheckPlatform::Ontap && value == "security config show" {
                format!("set -privilege advanced -confirmations off -stop-on-error true; {value}")
            } else {
                value.to_string()
            };
            Some(command(platform, &executed, value))
        }
        Check::ConfigLine { .. }
        | Check::CiscoVtySessionLimit
        | Check::CiscoLoginBlockFor
        | Check::CiscoInterfaceAclDenyLogInput
        | Check::CiscoPersistentAuditModificationProtection
        | Check::CiscoPersistentAuditDeletionProtection
        | Check::CiscoFileSystemPrivilege
        | Check::CiscoSingleLocalFallbackAccount
        | Check::CiscoPasswordMinimumLength
        | Check::CiscoManagementIdleTimeout
        | Check::CiscoLoggingBufferCapacity
        | Check::CiscoLoggingTrapSeverity
        | Check::CiscoRedundantAuthoritativeNtpSources
        | Check::CiscoNtpAuthentication
        | Check::CiscoSshMacAlgorithms
        | Check::CiscoSshEncryptionAlgorithms
        | Check::CiscoSyslogServerCount => {
            return Err("Cisco IOS-XE checks consume an operator-supplied running config".into());
        }
        Check::Command { command: value, .. } => {
            if !matches!(platform, CheckPlatform::Ontap | CheckPlatform::Bsd) {
                return Err("raw command checks are supported only for ONTAP and FreeBSD".into());
            }
            // Collection plans are an executable-content boundary in their own
            // right. Do not rely on a registry caller having validated the pack:
            // future and direct library callers must receive the same exact,
            // platform-specific read-only allowlist enforcement.
            crate::check_packs::validate_read_only_command(platform, value)?;
            let executed = if platform == CheckPlatform::Ontap && value == "security config show" {
                format!("set -privilege advanced -confirmations off -stop-on-error true; {value}")
            } else {
                value.clone()
            };
            Some(command(platform, &executed, value))
        }
        Check::BsdAuditClassSelection { .. } => {
            if platform != CheckPlatform::Bsd {
                return Err("typed FreeBSD checks require the FreeBSD platform".into());
            }
            for value in [
                crate::checks::freebsd::AUDITD_STATUS_COMMAND,
                crate::checks::freebsd::AUDIT_CONTROL_COMMAND,
                crate::checks::freebsd::AUDIT_USER_COMMAND,
                crate::checks::freebsd::AUDIT_CLASS_SHA256_COMMAND,
                crate::checks::freebsd::AUDIT_EVENT_SHA256_COMMAND,
            ] {
                crate::check_packs::validate_read_only_command(platform, value)?;
                push_unique(commands, command(platform, value, value));
            }
            None
        }
        Check::BsdPfEnabled => {
            let value = crate::checks::freebsd::PF_STATUS_COMMAND;
            crate::check_packs::validate_read_only_command(platform, value)?;
            Some(command(platform, value, value))
        }
        Check::All { checks } | Check::Any { checks } => {
            for nested in checks {
                add_check_commands(platform, nested, commands)?;
            }
            None
        }
    };
    if let Some(item) = item {
        push_unique(commands, item);
    }
    Ok(())
}

fn parse_ontap_entry_summary(line: &str) -> Option<usize> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    match fields.as_slice() {
        ["1", "entry", "was", "displayed."] => Some(1),
        [count, "entries", "were", "displayed."] => {
            let count = count.parse::<usize>().ok()?;
            (count != 1).then_some(count)
        }
        _ => None,
    }
}

fn ontap_header_matches(line: &str, expected: &[&str]) -> bool {
    let fields: Vec<&str> = line.split_whitespace().collect();
    fields.len() == expected.len()
        && fields
            .iter()
            .zip(expected)
            .all(|(actual, expected)| actual.eq_ignore_ascii_case(expected))
}

fn ontap_table_rows<'a>(
    stdout: &'a str,
    expected_header: &[&str],
    label: &str,
) -> Result<Vec<Vec<&'a str>>, String> {
    let lower = stdout.to_ascii_lowercase();
    for marker in ["--more--", "<--- more --->", "press space", "press <space>"] {
        if lower.contains(marker) {
            return Err(format!(
                "ONTAP {label} output contains a pagination marker: {marker}"
            ));
        }
    }

    let lines: Vec<&str> = stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    let summary_line = lines
        .last()
        .ok_or_else(|| format!("ONTAP {label} output is empty"))?;
    let expected_rows = parse_ontap_entry_summary(summary_line)
        .ok_or_else(|| format!("ONTAP {label} output has no canonical terminal entry summary"))?;
    if expected_rows == 0 {
        return Err(format!("ONTAP {label} output contains no data rows"));
    }

    let header_index = lines
        .iter()
        .position(|line| ontap_header_matches(line, expected_header))
        .ok_or_else(|| format!("ONTAP {label} output has no canonical header"))?;
    let separator_index = header_index + 1;
    let separator = lines
        .get(separator_index)
        .ok_or_else(|| format!("ONTAP {label} output is truncated after its header"))?;
    if !separator.contains('-')
        || !separator
            .chars()
            .all(|character| character == '-' || character.is_whitespace())
    {
        return Err(format!(
            "ONTAP {label} output has no canonical header separator"
        ));
    }
    let summary_index = lines.len() - 1;
    if separator_index >= summary_index {
        return Err(format!("ONTAP {label} output contains no data rows"));
    }

    let rows: Vec<Vec<&str>> = lines[(separator_index + 1)..summary_index]
        .iter()
        .map(|line| line.split_whitespace().collect())
        .collect();
    if rows.len() != expected_rows {
        return Err(format!(
            "ONTAP {label} output summary reports {expected_rows} row(s), but {} canonical row(s) were present",
            rows.len()
        ));
    }
    Ok(rows)
}

fn ontap_admin_numeric_minimum(stdout: &str, field: &str, label: &str) -> Result<String, String> {
    let rows = ontap_table_rows(stdout, &["vserver", "role", field], label)?;
    let mut values = Vec::with_capacity(rows.len());
    for row in rows {
        if row.len() != 3 || !row[1].eq_ignore_ascii_case("admin") {
            return Err(format!(
                "ONTAP {label} output contains a malformed admin-role row"
            ));
        }
        values.push(
            row[2]
                .parse::<u32>()
                .map_err(|_| format!("ONTAP {label} output contains a nonnumeric value"))?,
        );
    }
    Ok(values
        .into_iter()
        .min()
        .expect("canonical ONTAP table has at least one row")
        .to_string())
}

/// Validate and, where necessary, normalize stdout before evaluation. The
/// normalization deliberately retains only the fields a predicate is allowed
/// to inspect for the three ONTAP table checks.
pub fn validate_command_output(
    platform: CheckPlatform,
    command: &CollectionCommand,
    stdout: &str,
    stderr: &str,
) -> Result<String, String> {
    if platform == CheckPlatform::CiscoIos && command.data_key == "running_config" {
        validate_network_config(platform, stdout)?;
    }
    if platform == CheckPlatform::Ontap {
        if let Some(line) = [stdout, stderr]
            .into_iter()
            .flat_map(str::lines)
            .map(str::trim)
            .find(|line| {
                line.get(..6)
                    .map(|prefix| prefix.eq_ignore_ascii_case("error:"))
                    .unwrap_or(false)
            })
        {
            return Err(format!("ONTAP CLI reported a command error: {line}"));
        }
    }
    if platform == CheckPlatform::Bsd {
        if let Some(line) = [stdout, stderr]
            .into_iter()
            .flat_map(str::lines)
            .map(str::trim)
            .find(|line| {
                let lower = line.to_ascii_lowercase();
                lower == "permission denied"
                    || lower.starts_with("ssh:")
                    || lower.starts_with("cat:")
                    || lower.starts_with("sh:")
                    || lower.contains("command not found")
            })
        {
            return Err(format!("FreeBSD command reported an error: {line}"));
        }
    }

    match command.output_policy {
        OutputPolicy::Any => Ok(stdout.to_string()),
        OutputPolicy::OntapSessionLimit => {
            let rows = ontap_table_rows(
                stdout,
                &["Vserver", "Interface", "Category", "Max-Active-Limit"],
                "session-limit",
            )?;
            let mut all_exactly_three = true;
            for row in rows {
                if row.len() != 4 || !row[1].eq_ignore_ascii_case("cli") {
                    return Err("ONTAP session-limit output contains a malformed CLI row".into());
                }
                let value = row[3].parse::<u32>().map_err(|_| {
                    "ONTAP session-limit output contains a nonnumeric limit".to_string()
                })?;
                all_exactly_three &= value == 3;
            }
            Ok(all_exactly_three.to_string())
        }
        OutputPolicy::OntapAuditGuarantee => {
            let rows =
                ontap_table_rows(stdout, &["vserver", "audit-guarantee"], "audit-guarantee")?;
            let mut values = Vec::with_capacity(rows.len());
            for row in rows {
                if row.len() != 2 || !matches!(row[1], "true" | "false") {
                    return Err(
                        "ONTAP audit-guarantee output contains a malformed Boolean row".into(),
                    );
                }
                values.push(row[1]);
            }
            Ok(values.join("\n"))
        }
        OutputPolicy::OntapNtpAuthentication => {
            let rows = ontap_table_rows(
                stdout,
                &["Server", "Authentication", "Enabled"],
                "NTP authentication",
            )?;
            let mut normalized = Vec::with_capacity(rows.len());
            for row in rows {
                if row.len() != 2 || !matches!(row[1], "true" | "false") {
                    return Err("ONTAP NTP output contains a malformed server Boolean row".into());
                }
                normalized.push(format!("{} {}", row[0], row[1]));
            }
            Ok(normalized.join("\n"))
        }
        OutputPolicy::OntapPasswordMinimumLength => {
            ontap_admin_numeric_minimum(stdout, "passwd-minlength", "password minimum length")
        }
        OutputPolicy::OntapAdminNumericMinimum => {
            let field = match command.data_key.as_str() {
                "security login role config show -role admin -fields passwd-min-uppercase-chars" => {
                    "passwd-min-uppercase-chars"
                }
                "security login role config show -role admin -fields passwd-min-lowercase-chars" => {
                    "passwd-min-lowercase-chars"
                }
                "security login role config show -role admin -fields passwd-min-special-chars" => {
                    "passwd-min-special-chars"
                }
                _ => {
                    return Err(
                        "ONTAP numeric policy was applied to an unexpected command".into(),
                    )
                }
            };
            ontap_admin_numeric_minimum(stdout, field, field)
        }
        OutputPolicy::OntapAdminBooleanAll => {
            let rows = ontap_table_rows(
                stdout,
                &["vserver", "role", "passwd-alphanum"],
                "password alphanumeric policy",
            )?;
            let mut all_enabled = true;
            for row in rows {
                if row.len() != 3 || !row[1].eq_ignore_ascii_case("admin") {
                    return Err(
                        "ONTAP alphanumeric output contains a malformed admin-role row".into(),
                    );
                }
                match row[2].to_ascii_lowercase().as_str() {
                    "enabled" | "true" => {}
                    "disabled" | "false" => all_enabled = false,
                    _ => {
                        return Err(
                            "ONTAP alphanumeric output contains an unknown Boolean value".into(),
                        )
                    }
                }
            }
            Ok(all_enabled.to_string())
        }
        OutputPolicy::BsdAuditdStatus => {
            let lower = stdout.to_ascii_lowercase();
            if !lower.contains("auditd") || !lower.contains("running") {
                return Err("FreeBSD auditd status output is not recognized".into());
            }
            Ok(stdout.to_string())
        }
        OutputPolicy::BsdPfStatus => {
            crate::checks::freebsd::pf_enabled(stdout)?;
            Ok(stdout.to_string())
        }
    }
}

fn cisco_multiline_banner_delimiter(line: &str) -> Option<String> {
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

/// Extract the single top-level hostname command from a Cisco IOS-XE config.
///
/// Banner payload is arbitrary operator-controlled prose, so it is ignored.
/// Missing, malformed, or repeated hostname commands are ambiguous and fail
/// closed rather than allowing a caller to relabel another device's evidence.
pub fn cisco_config_hostname(config: &str) -> Result<String, String> {
    let mut banner_delimiter: Option<String> = None;
    let mut hostname: Option<String> = None;

    for raw_line in config.lines() {
        let line = raw_line.trim();
        if let Some(delimiter) = banner_delimiter.as_deref() {
            if line == delimiter || line.ends_with(delimiter) {
                banner_delimiter = None;
            }
            continue;
        }
        if line.is_empty() || line.starts_with('!') {
            continue;
        }
        if let Some(delimiter) = cisco_multiline_banner_delimiter(line) {
            banner_delimiter = Some(delimiter);
            continue;
        }
        if raw_line.chars().next().is_some_and(char::is_whitespace) {
            continue;
        }
        let Some(value) = line.strip_prefix("hostname ") else {
            continue;
        };
        let mut tokens = value.split_whitespace();
        let value = tokens.next().unwrap_or_default();
        let valid_hostname = value.len() <= 63
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            && value
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && value
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric);
        if !valid_hostname || tokens.next().is_some() {
            return Err("Cisco running-config has an invalid hostname command".into());
        }
        if hostname.replace(value.to_string()).is_some() {
            return Err("Cisco running-config has multiple hostname commands".into());
        }
    }

    if banner_delimiter.is_some() {
        return Err("Cisco running-config contains an unterminated banner payload".into());
    }
    hostname.ok_or_else(|| {
        "Cisco running-config has no unambiguous top-level hostname command".to_string()
    })
}

/// Establish that a Cisco running configuration reached its terminal marker.
/// Absence checks are otherwise unsafe: an empty, paginated, or truncated
/// transcript would make every forbidden directive appear absent.
pub fn validate_network_config(platform: CheckPlatform, config: &str) -> Result<(), String> {
    if platform != CheckPlatform::CiscoIos {
        return Err("running-config validation is defined only for Cisco IOS-XE".into());
    }

    crate::checks::network::validate_balanced_banners(config)?;

    let trimmed = config.trim();
    if trimmed.is_empty() {
        return Err("Cisco running-config output is empty".into());
    }
    let lower = trimmed.to_ascii_lowercase();
    for marker in [
        "--more--",
        "<--- more --->",
        "% invalid input",
        "% authorization failed",
        "% permission denied",
        "command not found",
        "<redacted>",
        "[redacted]",
        "configuration truncated",
    ] {
        if lower.contains(marker) {
            return Err(format!(
                "Cisco running-config output contains an error or pagination marker: {marker}"
            ));
        }
    }

    let lines: Vec<&str> = trimmed
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    if lines.len() < 2 {
        return Err("Cisco running-config output contains no configuration body".into());
    }
    if !lines.iter().any(|line| {
        line.strip_prefix("version ")
            .is_some_and(|value| !value.trim().is_empty())
    }) {
        return Err("Cisco running-config output has no recognizable version line".into());
    }
    cisco_config_hostname(config)?;
    let has_context_body = trimmed.lines().any(|line| {
        line.starts_with([' ', '\t'])
            && !line.trim().is_empty()
            && !line.trim_start().starts_with('!')
    });
    if lines.len() < 5 || !has_context_body {
        return Err(
            "Cisco running-config output has no recognizable line/context structure".into(),
        );
    }
    let terminal = lines.last().copied().unwrap_or_default();
    if terminal != "end" && terminal != ": end" {
        return Err(
            "Cisco running-config output is incomplete: terminal 'end' marker is missing".into(),
        );
    }
    Ok(())
}

/// Assemble evidence against its exact collection plan. Failed, missing,
/// mismatched, or semantically invalid records remain typed collection errors
/// and their stdout is never exposed to check predicates.
pub fn assemble_evidence_system_data(
    plan: &CollectionPlan,
    evidence: &[CommandEvidence],
) -> SystemData {
    let mut raw_outputs = HashMap::new();
    let mut collection_errors = HashMap::new();

    for command in &plan.commands {
        let Some(record) = evidence
            .iter()
            .find(|record| record.data_key == command.data_key)
        else {
            collection_errors.insert(
                command.data_key.clone(),
                "required command evidence is missing".to_string(),
            );
            continue;
        };

        if record.command != command.command {
            collection_errors.insert(
                command.data_key.clone(),
                "evidence command does not match the current collection plan".to_string(),
            );
            continue;
        }
        if record.status != CommandStatus::Success {
            collection_errors.insert(
                command.data_key.clone(),
                record
                    .error
                    .clone()
                    .unwrap_or_else(|| format!("collection ended with status {:?}", record.status)),
            );
            continue;
        }
        let Some(exit_code) = record.exit_code else {
            collection_errors.insert(
                command.data_key.clone(),
                "successful evidence record has no exit status".to_string(),
            );
            continue;
        };
        if !command.accepted_exit_codes.contains(&exit_code) {
            collection_errors.insert(
                command.data_key.clone(),
                format!("command exited with unaccepted status {exit_code}"),
            );
            continue;
        }
        match validate_command_output(plan.platform, command, &record.stdout, &record.stderr) {
            Ok(output) => {
                raw_outputs.insert(command.data_key.clone(), output);
            }
            Err(error) => {
                collection_errors.insert(command.data_key.clone(), error);
            }
        }
    }

    let mut data = normalize_system_data(plan.platform, &raw_outputs);
    data.collection_complete = collection_errors.is_empty();
    data.collection_errors = collection_errors;
    data
}

fn normalize_system_data(
    platform: CheckPlatform,
    raw_outputs: &HashMap<String, String>,
) -> SystemData {
    let mut data = SystemData {
        command_outputs: raw_outputs.clone(),
        ..Default::default()
    };

    match platform {
        CheckPlatform::CiscoIos => {
            data.network_config = raw_outputs.get("running_config").cloned();
        }
        CheckPlatform::Ontap | CheckPlatform::Bsd => {}
    }
    data
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openssh_sha256_fingerprint_requires_exact_unpadded_base64_grammar() {
        for final_character in "AEIMQUYcgkosw048".chars() {
            assert!(is_openssh_sha256_fingerprint(&format!(
                "SHA256:{}{final_character}",
                "A".repeat(42)
            )));
        }

        for invalid in [
            "SHA256:not-a-real-fingerprint".to_string(),
            format!("SHA256:{}", "A".repeat(42)),
            format!("SHA256:{}", "A".repeat(44)),
            format!("SHA256:{}B", "A".repeat(42)),
            format!("SHA256:{}=", "A".repeat(42)),
            format!("SHA256:{}-", "A".repeat(42)),
            format!("sha256:{}", "A".repeat(43)),
            format!("SHA256:{} ", "A".repeat(42)),
        ] {
            assert!(
                !is_openssh_sha256_fingerprint(&invalid),
                "accepted malformed fingerprint {invalid:?}"
            );
        }
    }

    #[test]
    fn cisco_running_config_requires_complete_unpaginated_output() {
        let unterminated_banner = "version 17.9\nhostname rtr01\nbanner login ^C\nline vty 0 4\n transport input ssh\nend";
        let error = validate_network_config(CheckPlatform::CiscoIos, unterminated_banner)
            .expect_err("an end marker inside banner payload must not complete collection");
        assert!(error.contains("unterminated banner"));

        for invalid in [
            "",
            "version 17.9",
            "version 17.9\nhostname rtr01\ninterface Gi1\nend",
            "version 17.9\nhostname rtr01\ninterface Gi1\n description uplink\n<redacted>\nend",
            "version 17.9\ninterface Gi1\n --More-- \nend",
            "% Invalid input detected at '^' marker.\nend",
        ] {
            assert!(validate_network_config(CheckPlatform::CiscoIos, invalid).is_err());
        }

        for valid in [
            "Building configuration...\nversion 17.9\nhostname rtr01\ninterface Gi1\n description uplink\nend\n",
            "!Command: show running-config\nversion 10.2\nhostname rtr02\nline vty 0 4\n transport input ssh\nend",
            "version 17.9\nhostname rtr03\nbanner login ^C\nAuthorized users only\n^C\nline vty 0 4\n transport input ssh\nend",
            "version 17.9\nhostname rtr04\nbanner motd #Authorized users only#\nline vty 0 4\n transport input ssh\nend",
        ] {
            assert!(validate_network_config(CheckPlatform::CiscoIos, valid).is_ok());
        }
    }

    #[test]
    fn cisco_hostname_extraction_ignores_banner_prose() {
        let config = "version 17.9\n\
                      hostname rtr01\n\
                      banner login ^C\n\
                      hostname attacker-controlled-prose\n\
                      ^C\n\
                      line vty 0 4\n\
                       transport input ssh\n\
                      end\n";
        assert_eq!(cisco_config_hostname(config).unwrap(), "rtr01");
        assert_eq!(
            cisco_config_hostname(
                "hostname EDGE-01\nbanner motd #hostname inline-prose#\nline vty 0 4\n transport input ssh\nend"
            )
            .unwrap(),
            "EDGE-01"
        );
    }

    #[test]
    fn cisco_hostname_extraction_rejects_ambiguous_or_untrusted_identity() {
        for invalid in [
            "",
            "banner login #hostname fake#\n",
            " hostname indented\n",
            "hostname rtr01 extra-token\n",
            "hostname ../../outside\n",
            "hostname router/name\n",
            "hostname -router\n",
            "hostname router-\n",
            "hostname router.example\n",
            "hostname rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr\n",
            "hostname rtr01\nhostname rtr02\n",
            "hostname rtr01\nbanner login ^C\nhostname hidden-in-prose\n",
        ] {
            assert!(
                cisco_config_hostname(invalid).is_err(),
                "accepted ambiguous config: {invalid:?}"
            );
        }
    }

    #[test]
    fn plan_digest_binds_evaluation_predicates_and_output_policy() {
        let definition = CheckDefinition {
            vuln_id: "V-1".to_string(),
            platform: CheckPlatform::Bsd,
            check: Check::Command {
                command: "service auditd onestatus".to_string(),
                pattern: Some("auditd is running".to_string()),
                is_regex: false,
            },
            expected: crate::checks::ExpectedResult::IsTrue,
            description: None,
            implementation_class: crate::checks::ImplementationClass::LegacyDeclarative,
            introduction_release: Some("0.3".to_string()),
        };
        let first = generate_collection_plan(CheckPlatform::Bsd, std::slice::from_ref(&definition))
            .expect("first plan");
        let mut changed = definition;
        if let Check::Command { pattern, .. } = &mut changed.check {
            *pattern = Some("auditd is not running".to_string());
        }
        let second =
            generate_collection_plan(CheckPlatform::Bsd, &[changed]).expect("changed plan");
        assert_ne!(first.digest(), second.digest());

        let mut policy_changed = first.clone();
        policy_changed.commands[0].output_policy = OutputPolicy::Any;
        assert_ne!(first.digest(), policy_changed.digest());
    }
    use crate::checks::ExpectedResult;

    fn definition(platform: CheckPlatform, check: Check) -> CheckDefinition {
        CheckDefinition {
            vuln_id: "V-1".to_string(),
            platform,
            check,
            expected: ExpectedResult::IsTrue,
            description: None,
            implementation_class: crate::checks::ImplementationClass::LegacyDeclarative,
            introduction_release: Some("0.3".to_string()),
        }
    }

    #[test]
    fn only_reviewed_read_only_commands_reach_collection_plans() {
        for (platform, approved) in [
            (CheckPlatform::Ontap, "system timeout show"),
            (CheckPlatform::Bsd, "service auditd onestatus"),
            (CheckPlatform::Bsd, "service pf onestatus"),
        ] {
            let checks = [definition(
                platform,
                Check::Command {
                    command: approved.to_string(),
                    pattern: None,
                    is_regex: false,
                },
            )];
            assert!(!generate_collection_plan(platform, &checks)
                .unwrap()
                .commands
                .is_empty());
        }

        let reviewed_predicate = [definition(
            CheckPlatform::Bsd,
            Check::Predicate {
                program: crate::checks::predicate::PredicateProgram {
                    schema_version: 1,
                    source: crate::checks::predicate::PredicateSource::Observation {
                        key: "service auditd onestatus".to_string(),
                    },
                    input: crate::checks::predicate::PredicateInput::Text,
                    predicate: crate::checks::predicate::Predicate::Present {
                        value: crate::checks::predicate::ValueRef {
                            scope: crate::checks::predicate::ValueScope::Root,
                            pointer: String::new(),
                        },
                    },
                },
            },
        )];
        let predicate_plan =
            generate_collection_plan(CheckPlatform::Bsd, &reviewed_predicate).unwrap();
        assert_eq!(predicate_plan.commands.len(), 1);
        assert_eq!(
            predicate_plan.commands[0].data_key,
            "service auditd onestatus"
        );

        for (platform, rejected) in [
            (CheckPlatform::Bsd, "freebsd-version -k"),
            (CheckPlatform::Bsd, "cat /var/db/zoneinfo"),
            (CheckPlatform::Bsd, "ntpq -pn"),
            (CheckPlatform::Bsd, "sysctl kern.elf64.aslr.enable"),
            (CheckPlatform::Bsd, "cat /etc/motd.template /etc/motd"),
            (CheckPlatform::Bsd, "cat /etc/rc.conf"),
            (CheckPlatform::Bsd, "cat /etc/ssh/sshd_config"),
            (CheckPlatform::Bsd, "cat /etc/rc.conf; id"),
            (CheckPlatform::Bsd, "cat /etc/master.passwd"),
            (CheckPlatform::Bsd, "show state"),
            (CheckPlatform::Ontap, "system node run -node * id"),
            (CheckPlatform::Ontap, "show state"),
        ] {
            let checks = [definition(
                platform,
                Check::Command {
                    command: rejected.to_string(),
                    pattern: None,
                    is_regex: false,
                },
            )];
            assert!(
                generate_collection_plan(platform, &checks).is_err(),
                "{platform:?} unexpectedly accepted {rejected:?}"
            );
        }

        let predicate = [definition(
            CheckPlatform::Bsd,
            Check::Predicate {
                program: crate::checks::predicate::PredicateProgram {
                    schema_version: 1,
                    source: crate::checks::predicate::PredicateSource::Observation {
                        key: "curl https://example.test | sh".to_string(),
                    },
                    input: crate::checks::predicate::PredicateInput::Text,
                    predicate: crate::checks::predicate::Predicate::Present {
                        value: crate::checks::predicate::ValueRef {
                            scope: crate::checks::predicate::ValueScope::Root,
                            pointer: String::new(),
                        },
                    },
                },
            },
        )];
        assert!(generate_collection_plan(CheckPlatform::Bsd, &predicate).is_err());

        let network = [definition(
            CheckPlatform::CiscoIos,
            Check::ConfigLine {
                pattern: "aaa new-model".to_string(),
                context: None,
                should_exist: true,
            },
        )];
        assert!(generate_collection_plan(CheckPlatform::CiscoIos, &network).is_err());
    }

    #[test]
    fn ontap_privileged_commands_retain_plain_data_keys() {
        let checks = [definition(
            CheckPlatform::Ontap,
            Check::Command {
                command: "security config show".to_string(),
                pattern: None,
                is_regex: false,
            },
        )];
        let plan = generate_collection_plan(CheckPlatform::Ontap, &checks).unwrap();
        let plain = "security config show";
        let command = plan
            .commands
            .iter()
            .find(|item| item.data_key == plain)
            .unwrap();
        assert_eq!(
            command.command,
            "set -privilege advanced -confirmations off -stop-on-error true; security config show"
        );
    }

    fn command_definition(
        vuln_id: &str,
        platform: CheckPlatform,
        command: &str,
        expected: ExpectedResult,
    ) -> CheckDefinition {
        CheckDefinition {
            vuln_id: vuln_id.to_string(),
            platform,
            check: Check::Command {
                command: command.to_string(),
                pattern: None,
                is_regex: false,
            },
            expected,
            description: None,
            implementation_class: crate::checks::ImplementationClass::LegacyDeclarative,
            introduction_release: Some("0.3".to_string()),
        }
    }

    #[test]
    fn transport_failure_text_cannot_pass_ontap_negative_or_broad_checks() {
        let definitions = vec![
            command_definition(
                "V-246935",
                CheckPlatform::Ontap,
                "vserver audit show -fields audit-guarantee",
                ExpectedResult::NotContains {
                    substring: "false".to_string(),
                },
            ),
            command_definition(
                "V-246950",
                CheckPlatform::Ontap,
                "cluster time-service ntp server show",
                ExpectedResult::NotContains {
                    substring: "false".to_string(),
                },
            ),
            command_definition(
                "V-246951",
                CheckPlatform::Ontap,
                "security login role config show -role admin -fields passwd-minlength",
                ExpectedResult::Matches {
                    pattern: r"(?m)\b(1[5-9]|[2-9]\d)\b".to_string(),
                },
            ),
        ];
        let plan = generate_collection_plan(CheckPlatform::Ontap, &definitions).unwrap();
        let evidence: Vec<_> = plan
            .commands
            .iter()
            .map(|item| {
                CommandEvidence::failed(
                    &item.data_key,
                    &item.command,
                    CommandStatus::TransportError,
                    "SSH transport failed",
                )
                .with_diagnostics(
                    "ssh: connect to host filer port 22: Connection refused".to_string(),
                    String::new(),
                    Some(255),
                    1,
                )
            })
            .collect();
        let data = assemble_evidence_system_data(&plan, &evidence);
        assert!(!data.collection_complete);
        for definition in &definitions {
            let result = crate::checks::executor::execute_check(definition, &data);
            assert_eq!(
                result.to_finding_status(),
                crate::models::finding::FindingStatus::NotReviewed,
                "{} must not pass transport failure text",
                definition.vuln_id
            );
        }
    }

    #[test]
    fn ontap_semantic_errors_and_malformed_tables_are_collection_errors() {
        let definitions = [command_definition(
            "V-246951",
            CheckPlatform::Ontap,
            "security login role config show -role admin -fields passwd-minlength",
            ExpectedResult::Matches {
                pattern: r"(?m)\b(1[5-9]|[2-9]\d)\b".to_string(),
            },
        )];
        let plan = generate_collection_plan(CheckPlatform::Ontap, &definitions).unwrap();
        for stdout in [
            "Error: command failed while connecting to port 22",
            "vserver role passwd-minlength\n-------- ----- ----------------",
            "",
        ] {
            let item = &plan.commands[0];
            let evidence = [CommandEvidence::success(
                &item.data_key,
                &item.command,
                stdout.to_string(),
                String::new(),
                0,
                1,
            )];
            let data = assemble_evidence_system_data(&plan, &evidence);
            assert!(!data.collection_complete);
            assert!(!data.command_outputs.contains_key(&item.data_key));
        }
    }

    #[test]
    fn ontap_tables_are_reduced_to_the_exact_evaluated_fields() {
        let definitions = vec![
            command_definition(
                "V-audit",
                CheckPlatform::Ontap,
                "vserver audit show -fields audit-guarantee",
                ExpectedResult::NotContains {
                    substring: "false".to_string(),
                },
            ),
            command_definition(
                "V-ntp",
                CheckPlatform::Ontap,
                "cluster time-service ntp server show",
                ExpectedResult::NotContains {
                    substring: "false".to_string(),
                },
            ),
            command_definition(
                "V-password",
                CheckPlatform::Ontap,
                "security login role config show -role admin -fields passwd-minlength",
                ExpectedResult::Matches {
                    pattern: r"^15$".to_string(),
                },
            ),
        ];
        let plan = generate_collection_plan(CheckPlatform::Ontap, &definitions).unwrap();
        let stdout = [
            "vserver audit-guarantee\n-------- ---------------\nsvm1 true\nsvm2 false\n2 entries were displayed.",
            "Server Authentication Enabled\n------ ----------------------\n10.0.0.1 true\n10.0.0.2 false\n2 entries were displayed.",
            "vserver role passwd-minlength\n------- ---- ----------------\ncluster1 admin 15\n1 entry was displayed.",
        ];
        let evidence: Vec<_> = plan
            .commands
            .iter()
            .zip(stdout)
            .map(|(item, stdout)| {
                CommandEvidence::success(
                    &item.data_key,
                    &item.command,
                    stdout.to_string(),
                    String::new(),
                    0,
                    1,
                )
            })
            .collect();
        let data = assemble_evidence_system_data(&plan, &evidence);
        assert!(data.collection_complete);
        assert_eq!(
            data.command_outputs["vserver audit show -fields audit-guarantee"],
            "true\nfalse"
        );
        assert_eq!(
            data.command_outputs["cluster time-service ntp server show"],
            "10.0.0.1 true\n10.0.0.2 false"
        );
        assert_eq!(
            data.command_outputs
                ["security login role config show -role admin -fields passwd-minlength"],
            "15"
        );
    }

    #[test]
    fn ontap_password_policy_uses_the_weakest_admin_row() {
        let definitions = [command_definition(
            "V-password",
            CheckPlatform::Ontap,
            "security login role config show -role admin -fields passwd-minlength",
            ExpectedResult::Matches {
                pattern: r"(?m)\b(1[5-9]|[2-9]\d)\b".to_string(),
            },
        )];
        let plan = generate_collection_plan(CheckPlatform::Ontap, &definitions).unwrap();
        let item = &plan.commands[0];
        let evidence = [CommandEvidence::success(
            &item.data_key,
            &item.command,
            "vserver role passwd-minlength\n------- ---- ----------------\ncluster1 admin 15\nsvm2 admin 8\n2 entries were displayed."
                .to_string(),
            String::new(),
            0,
            1,
        )];
        let data = assemble_evidence_system_data(&plan, &evidence);
        assert_eq!(data.command_outputs[&item.data_key], "8");
        assert_eq!(
            crate::checks::executor::execute_check(&definitions[0], &data).to_finding_status(),
            crate::models::finding::FindingStatus::Open
        );
    }

    #[test]
    fn ontap_table_summaries_must_match_every_parsed_row() {
        let cases = [
            (
                "V-246935",
                "vserver audit show -fields audit-guarantee",
                ExpectedResult::NotContains {
                    substring: "false".to_string(),
                },
                "vserver audit-guarantee\n-------- ---------------\nsvm1 true\n2 entries were displayed.",
            ),
            (
                "V-246950",
                "cluster time-service ntp server show",
                ExpectedResult::NotContains {
                    substring: "false".to_string(),
                },
                "Server Authentication Enabled\n------ ----------------------\n10.0.0.1 true\n10.0.0.2 true\n3 entries were displayed.",
            ),
            (
                "V-246951",
                "security login role config show -role admin -fields passwd-minlength",
                ExpectedResult::Matches {
                    pattern: r"^(1[5-9]|[2-9]\d|[1-9]\d{2,})$".to_string(),
                },
                "vserver role passwd-minlength\n------- ---- ----------------\ncluster1 admin 15\n2 entries were displayed.",
            ),
        ];

        for (vuln_id, command, expected, stdout) in cases {
            let definitions = [command_definition(
                vuln_id,
                CheckPlatform::Ontap,
                command,
                expected,
            )];
            let plan = generate_collection_plan(CheckPlatform::Ontap, &definitions).unwrap();
            let item = &plan.commands[0];
            let evidence = [CommandEvidence::success(
                &item.data_key,
                &item.command,
                stdout.to_string(),
                String::new(),
                0,
                1,
            )];
            let data = assemble_evidence_system_data(&plan, &evidence);
            assert!(!data.collection_complete, "{vuln_id} accepted truncation");
            assert!(!data.command_outputs.contains_key(command));
            assert_eq!(
                crate::checks::executor::execute_check(&definitions[0], &data).to_finding_status(),
                crate::models::finding::FindingStatus::NotReviewed
            );
        }
    }

    #[test]
    fn ontap_structured_tables_reject_pagination_and_noncanonical_headers() {
        let definitions = [command_definition(
            "V-246935",
            CheckPlatform::Ontap,
            "vserver audit show -fields audit-guarantee",
            ExpectedResult::NotContains {
                substring: "false".to_string(),
            },
        )];
        let plan = generate_collection_plan(CheckPlatform::Ontap, &definitions).unwrap();
        let item = &plan.commands[0];
        for stdout in [
            "vserver audit-guarantee\n-------- ---------------\nsvm1 true\n--More--\n1 entry was displayed.",
            "vserver wrong-column\n-------- ------------\nsvm1 true\n1 entry was displayed.",
            "vserver audit-guarantee\n-------- ---------------\nsvm1 true",
        ] {
            let evidence = [CommandEvidence::success(
                &item.data_key,
                &item.command,
                stdout.to_string(),
                String::new(),
                0,
                1,
            )];
            let data = assemble_evidence_system_data(&plan, &evidence);
            assert!(!data.collection_complete, "accepted malformed: {stdout}");
        }
    }

    #[test]
    fn ontap_multirow_policies_evaluate_the_weakest_row() {
        let definitions = vec![
            command_definition(
                "V-246922",
                CheckPlatform::Ontap,
                "security session limit show -interface cli",
                ExpectedResult::IsTrue,
            ),
            command_definition(
                "V-246952",
                CheckPlatform::Ontap,
                "security login role config show -role admin -fields passwd-min-uppercase-chars",
                ExpectedResult::Matches {
                    pattern: r"^[1-9]\d*$".to_string(),
                },
            ),
            command_definition(
                "V-246953",
                CheckPlatform::Ontap,
                "security login role config show -role admin -fields passwd-min-lowercase-chars",
                ExpectedResult::Matches {
                    pattern: r"^[1-9]\d*$".to_string(),
                },
            ),
            command_definition(
                "V-246954",
                CheckPlatform::Ontap,
                "security login role config show -role admin -fields passwd-alphanum",
                ExpectedResult::Matches {
                    pattern: r"^true$".to_string(),
                },
            ),
            command_definition(
                "V-246955",
                CheckPlatform::Ontap,
                "security login role config show -role admin -fields passwd-min-special-chars",
                ExpectedResult::Matches {
                    pattern: r"^[1-9]\d*$".to_string(),
                },
            ),
        ];
        let plan = generate_collection_plan(CheckPlatform::Ontap, &definitions).unwrap();
        let evidence: Vec<_> = plan
            .commands
            .iter()
            .map(|item| {
                let stdout = match item.data_key.as_str() {
                    "security session limit show -interface cli" => {
                        "Vserver Interface Category Max-Active-Limit\n--------- --------- ------------- ----------------\ncluster1 cli default 1\nsvm2 cli default 5\n2 entries were displayed."
                    }
                    "security login role config show -role admin -fields passwd-min-uppercase-chars" => {
                        "vserver role passwd-min-uppercase-chars\n-------- ----- --------------------------\ncluster1 admin 1\nsvm2 admin 0\n2 entries were displayed."
                    }
                    "security login role config show -role admin -fields passwd-min-lowercase-chars" => {
                        "vserver role passwd-min-lowercase-chars\n-------- ----- --------------------------\ncluster1 admin 1\nsvm2 admin 0\n2 entries were displayed."
                    }
                    "security login role config show -role admin -fields passwd-alphanum" => {
                        "vserver role passwd-alphanum\n-------- ----- ---------------\ncluster1 admin enabled\nsvm2 admin disabled\n2 entries were displayed."
                    }
                    "security login role config show -role admin -fields passwd-min-special-chars" => {
                        "vserver role passwd-min-special-chars\n-------- ----- ------------------------\ncluster1 admin 1\nsvm2 admin 0\n2 entries were displayed."
                    }
                    _ => unreachable!(),
                };
                CommandEvidence::success(
                    &item.data_key,
                    &item.command,
                    stdout.to_string(),
                    String::new(),
                    0,
                    1,
                )
            })
            .collect();
        let data = assemble_evidence_system_data(&plan, &evidence);
        assert!(data.collection_complete);
        let results = crate::checks::executor::execute_check_pack(
            &crate::checks::CheckPack {
                stig_id: "NetApp_ONTAP_DSC_9-x_STIG".to_string(),
                platform: CheckPlatform::Ontap,
                version: "V2R4".to_string(),
                priority: 0,
                checks: definitions,
            },
            &data,
        );
        assert!(results.iter().all(|result| !result.passed));
        assert!(results.iter().all(|result| result.error.is_none()));
    }

    #[test]
    fn bsd_effective_state_diagnostics_fail_closed_and_stopped_auditd_is_observed() {
        let definitions = [
            command_definition(
                "V-audit-control",
                CheckPlatform::Bsd,
                "cat /etc/security/audit_control",
                ExpectedResult::Matches {
                    pattern: r"(?m)^flags:".to_string(),
                },
            ),
            command_definition(
                "V-audit-user",
                CheckPlatform::Bsd,
                "cat /etc/security/audit_user",
                ExpectedResult::Matches {
                    pattern: r"(?m)^root:".to_string(),
                },
            ),
            command_definition(
                "V-auditd",
                CheckPlatform::Bsd,
                "service auditd onestatus",
                ExpectedResult::Matches {
                    pattern: r"(?i)\A\s*auditd\s+is\s+running(?:\s+as\s+pid\s+[1-9]\d*)?\.?\s*\z"
                        .to_string(),
                },
            ),
        ];
        let plan = generate_collection_plan(CheckPlatform::Bsd, &definitions).unwrap();
        let evidence: Vec<_> = plan
            .commands
            .iter()
            .map(|item| {
                let (stdout, code) = match item.data_key.as_str() {
                    "cat /etc/security/audit_control" => {
                        ("cat: /etc/security/audit_control: Permission denied", 0)
                    }
                    "cat /etc/security/audit_user" => ("sh: cat: command not found", 0),
                    "service auditd onestatus" => ("auditd is not running.", 1),
                    _ => unreachable!(),
                };
                CommandEvidence::success(
                    &item.data_key,
                    &item.command,
                    stdout.to_string(),
                    String::new(),
                    code,
                    1,
                )
            })
            .collect();
        let data = assemble_evidence_system_data(&plan, &evidence);
        assert!(data
            .collection_errors
            .contains_key("cat /etc/security/audit_control"));
        assert!(data
            .collection_errors
            .contains_key("cat /etc/security/audit_user"));
        for definition in &definitions[..2] {
            let result = crate::checks::executor::execute_check(definition, &data);
            assert_eq!(
                result.to_finding_status(),
                crate::models::finding::FindingStatus::NotReviewed
            );
        }
        let stopped = crate::checks::executor::execute_check(&definitions[2], &data);
        assert_eq!(
            stopped.to_finding_status(),
            crate::models::finding::FindingStatus::Open
        );
    }
}
