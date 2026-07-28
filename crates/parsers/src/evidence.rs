//! Versioned remote-device evidence documents.
//!
//! Version 2 is strict JSON and carries transport status separately from
//! stdout/stderr. The marker-based v1 format cannot prove command success and
//! is available only through an explicit compatibility policy.

use std::collections::{HashMap, HashSet};

use automatestig_core::checks::{CheckPlatform, SystemData};
use automatestig_core::remote::{
    assemble_evidence_system_data, CollectionPlan, CommandEvidence, CommandStatus,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const EVIDENCE_V2_SCHEMA: &str = "automatestig-evidence/v2";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyEvidencePolicy {
    Reject,
    AssumeSuccess,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EvidenceError {
    #[error("legacy marker evidence cannot prove command success; recollect as evidence v2 or explicitly allow unsafe legacy evidence")]
    LegacyRejected,
    #[error("invalid evidence JSON: {0}")]
    InvalidJson(String),
    #[error("unsupported evidence schema '{0}'")]
    UnsupportedSchema(String),
    #[error("invalid evidence document: {0}")]
    InvalidDocument(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceTranscript {
    pub schema: String,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub platform: Option<CheckPlatform>,
    #[serde(default)]
    pub collector_version: Option<String>,
    #[serde(default)]
    pub collected_at: Option<String>,
    #[serde(default)]
    pub plan_sha256: Option<String>,
    #[serde(default)]
    pub server_key_fingerprint: Option<String>,
    pub complete: bool,
    #[serde(default)]
    pub commands: Vec<CommandEvidence>,
    /// Successful output lookup retained for callers while they migrate to
    /// typed records. Failed stdout is never included.
    #[serde(skip)]
    pub outputs: HashMap<String, String>,
    #[serde(skip)]
    pub legacy: bool,
}

impl EvidenceTranscript {
    pub fn new_v2(
        hostname: impl Into<String>,
        platform: CheckPlatform,
        plan_sha256: String,
        commands: Vec<CommandEvidence>,
    ) -> Self {
        let complete = commands
            .iter()
            .all(|record| record.status == CommandStatus::Success);
        let mut document = Self {
            schema: EVIDENCE_V2_SCHEMA.to_string(),
            hostname: Some(hostname.into()),
            platform: Some(platform),
            collector_version: Some(env!("CARGO_PKG_VERSION").to_string()),
            collected_at: Some(chrono::Utc::now().to_rfc3339()),
            plan_sha256: Some(plan_sha256),
            server_key_fingerprint: None,
            complete,
            commands,
            outputs: HashMap::new(),
            legacy: false,
        };
        document.rebuild_output_index();
        document
    }

    pub fn collection_error_count(&self) -> usize {
        self.commands
            .iter()
            .filter(|record| record.status != CommandStatus::Success)
            .count()
    }

    fn rebuild_output_index(&mut self) {
        self.outputs = self
            .commands
            .iter()
            .filter(|record| record.status == CommandStatus::Success)
            .map(|record| (record.data_key.clone(), record.stdout.clone()))
            .collect();
    }
}

/// Parse a strict v2 document, or a v1 marker transcript only when the caller
/// explicitly elects to assume that every legacy command succeeded.
pub fn parse_evidence(
    raw: &str,
    legacy_policy: LegacyEvidencePolicy,
) -> Result<EvidenceTranscript, EvidenceError> {
    if raw.trim_start().starts_with('{') {
        parse_v2(raw)
    } else if legacy_policy == LegacyEvidencePolicy::AssumeSuccess {
        parse_legacy(raw)
    } else {
        Err(EvidenceError::LegacyRejected)
    }
}

/// Bind a parsed document to the exact current plan and assemble trusted
/// system data. CLI and GUI callers share this stale/foreign-evidence check.
pub fn assemble_for_plan(
    transcript: &EvidenceTranscript,
    plan: &CollectionPlan,
) -> Result<SystemData, EvidenceError> {
    if !transcript.legacy {
        let platform = transcript.platform.ok_or_else(|| {
            EvidenceError::InvalidDocument("evidence v2 is missing its target platform".into())
        })?;
        if platform != plan.platform {
            return Err(EvidenceError::InvalidDocument(format!(
                "evidence platform {platform:?} does not match plan platform {:?}",
                plan.platform
            )));
        }
        let digest = transcript.plan_sha256.as_deref().ok_or_else(|| {
            EvidenceError::InvalidDocument(
                "evidence v2 is missing its collection-plan digest".into(),
            )
        })?;
        let expected = plan.digest();
        if digest != expected {
            return Err(EvidenceError::InvalidDocument(format!(
                "evidence collection plan does not match the installed check pack (expected {expected}, found {digest})"
            )));
        }
        if let Some(unexpected) = transcript.commands.iter().find(|record| {
            !plan
                .commands
                .iter()
                .any(|command| command.data_key == record.data_key)
        }) {
            return Err(EvidenceError::InvalidDocument(format!(
                "evidence contains command '{}' which is not in the current collection plan",
                unexpected.data_key
            )));
        }
    }

    let records = if transcript.legacy {
        plan.commands
            .iter()
            .filter_map(|command| {
                transcript
                    .commands
                    .iter()
                    .find(|record| {
                        record.data_key == command.data_key || record.command == command.command
                    })
                    .cloned()
                    .map(|mut record| {
                        record.data_key = command.data_key.clone();
                        record.command = command.command.clone();
                        record
                    })
            })
            .collect()
    } else {
        transcript.commands.clone()
    };
    Ok(assemble_evidence_system_data(plan, &records))
}

fn parse_v2(raw: &str) -> Result<EvidenceTranscript, EvidenceError> {
    let mut document: EvidenceTranscript =
        serde_json::from_str(raw).map_err(|error| EvidenceError::InvalidJson(error.to_string()))?;
    if document.schema != EVIDENCE_V2_SCHEMA {
        return Err(EvidenceError::UnsupportedSchema(document.schema));
    }
    if document
        .hostname
        .as_deref()
        .map(str::trim)
        .is_none_or(str::is_empty)
    {
        return Err(EvidenceError::InvalidDocument(
            "evidence v2 hostname is required".into(),
        ));
    }
    if document.platform.is_none() {
        return Err(EvidenceError::InvalidDocument(
            "evidence v2 platform is required".into(),
        ));
    }
    if document
        .collector_version
        .as_deref()
        .map(str::trim)
        .is_none_or(str::is_empty)
    {
        return Err(EvidenceError::InvalidDocument(
            "evidence v2 collector_version is required".into(),
        ));
    }
    if document
        .collected_at
        .as_deref()
        .map(str::trim)
        .is_none_or(str::is_empty)
    {
        return Err(EvidenceError::InvalidDocument(
            "evidence v2 collected_at is required".into(),
        ));
    }
    if chrono::DateTime::parse_from_rfc3339(
        document.collected_at.as_deref().expect("validated above"),
    )
    .is_err()
    {
        return Err(EvidenceError::InvalidDocument(
            "evidence v2 collected_at must be an RFC 3339 timestamp".into(),
        ));
    }
    let digest = document.plan_sha256.as_deref().ok_or_else(|| {
        EvidenceError::InvalidDocument("evidence v2 plan_sha256 is required".into())
    })?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(EvidenceError::InvalidDocument(
            "evidence v2 plan_sha256 must be 64 lowercase hexadecimal characters".into(),
        ));
    }
    if document
        .server_key_fingerprint
        .as_deref()
        .is_some_and(|fingerprint| fingerprint.trim().is_empty())
    {
        return Err(EvidenceError::InvalidDocument(
            "evidence v2 server_key_fingerprint must not be empty when present".into(),
        ));
    }
    if document
        .server_key_fingerprint
        .as_deref()
        .is_some_and(|fingerprint| !fingerprint.starts_with("SHA256:") || fingerprint.len() <= 8)
    {
        return Err(EvidenceError::InvalidDocument(
            "evidence v2 server_key_fingerprint must be an SSH SHA256 fingerprint".into(),
        ));
    }
    if document.commands.is_empty() {
        return Err(EvidenceError::InvalidDocument(
            "commands must not be empty".into(),
        ));
    }

    let mut keys = HashSet::new();
    for record in &document.commands {
        if record.data_key.trim().is_empty() || record.command.trim().is_empty() {
            return Err(EvidenceError::InvalidDocument(
                "command and data_key must not be empty".into(),
            ));
        }
        if !keys.insert(record.data_key.as_str()) {
            return Err(EvidenceError::InvalidDocument(format!(
                "duplicate command data_key '{}'",
                record.data_key
            )));
        }
        match record.status {
            CommandStatus::Success if record.exit_code.is_none() => {
                return Err(EvidenceError::InvalidDocument(format!(
                    "successful command '{}' has no exit status",
                    record.data_key
                )));
            }
            CommandStatus::Success if record.error.is_some() => {
                return Err(EvidenceError::InvalidDocument(format!(
                    "successful command '{}' contains an error",
                    record.data_key
                )));
            }
            CommandStatus::Success => {}
            _ if record
                .error
                .as_deref()
                .map(str::trim)
                .is_none_or(str::is_empty) =>
            {
                return Err(EvidenceError::InvalidDocument(format!(
                    "failed command '{}' has no error description",
                    record.data_key
                )));
            }
            _ => {}
        }
    }
    let computed_complete = document
        .commands
        .iter()
        .all(|record| record.status == CommandStatus::Success);
    if document.complete != computed_complete {
        return Err(EvidenceError::InvalidDocument(
            "complete does not agree with command statuses".into(),
        ));
    }
    document.legacy = false;
    document.rebuild_output_index();
    Ok(document)
}

fn parse_legacy(raw: &str) -> Result<EvidenceTranscript, EvidenceError> {
    let mut hostname = None;
    let mut commands = Vec::new();
    let mut current_command: Option<String> = None;
    let mut current_output = String::new();
    let mut keys = HashSet::new();

    for line in raw.lines() {
        if let Some(command) = line.strip_prefix("### automatestig:command ") {
            flush_legacy(
                &mut commands,
                &mut keys,
                &mut current_command,
                &mut current_output,
            )?;
            if command.trim().is_empty() {
                return Err(EvidenceError::InvalidDocument(
                    "legacy command marker is empty".into(),
                ));
            }
            current_command = Some(command.to_string());
            continue;
        }
        if let Some(value) = line.strip_prefix("### automatestig:hostname ") {
            if hostname.is_some() {
                return Err(EvidenceError::InvalidDocument(
                    "legacy transcript contains multiple hostnames".into(),
                ));
            }
            hostname = Some(value.to_string());
            continue;
        }
        if current_command.is_some() {
            current_output.push_str(line);
            current_output.push('\n');
        }
    }
    flush_legacy(
        &mut commands,
        &mut keys,
        &mut current_command,
        &mut current_output,
    )?;
    if commands.is_empty() {
        return Err(EvidenceError::InvalidDocument(
            "legacy transcript contains no commands".into(),
        ));
    }

    let mut document = EvidenceTranscript {
        schema: "automatestig-evidence/v1-unsafe".to_string(),
        hostname,
        platform: None,
        collector_version: None,
        collected_at: None,
        plan_sha256: None,
        server_key_fingerprint: None,
        complete: true,
        commands,
        outputs: HashMap::new(),
        legacy: true,
    };
    document.rebuild_output_index();
    Ok(document)
}

fn flush_legacy(
    commands: &mut Vec<CommandEvidence>,
    keys: &mut HashSet<String>,
    current_command: &mut Option<String>,
    current_output: &mut String,
) -> Result<(), EvidenceError> {
    if let Some(command) = current_command.take() {
        if !keys.insert(command.clone()) {
            return Err(EvidenceError::InvalidDocument(format!(
                "duplicate legacy command '{command}'"
            )));
        }
        commands.push(CommandEvidence::success(
            &command,
            &command,
            current_output.trim_end().to_string(),
            String::new(),
            0,
            0,
        ));
        current_output.clear();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use automatestig_core::remote::{CollectionCommand, OutputPolicy};

    #[test]
    fn strict_mode_rejects_legacy_and_explicit_mode_indexes_success_only() {
        let raw = "### automatestig:hostname ontap01\n\
                   ### automatestig:command show state\nvalue\n";
        assert_eq!(
            parse_evidence(raw, LegacyEvidencePolicy::Reject).unwrap_err(),
            EvidenceError::LegacyRejected
        );
        let transcript = parse_evidence(raw, LegacyEvidencePolicy::AssumeSuccess).unwrap();
        assert!(transcript.legacy);
        assert_eq!(transcript.hostname.as_deref(), Some("ontap01"));
        assert_eq!(
            transcript.outputs.get("show state").map(String::as_str),
            Some("value")
        );
    }

    #[test]
    fn v2_never_indexes_failed_stdout() {
        let raw = r####"{
          "schema":"automatestig-evidence/v2",
          "hostname":"filer",
          "platform":"ontap",
          "collector_version":"0.2.0",
          "collected_at":"2026-01-01T00:00:00Z",
          "plan_sha256":"0000000000000000000000000000000000000000000000000000000000000000",
          "complete":false,
          "commands":[{
            "data_key":"show state",
            "command":"show state",
            "status":"transport_error",
            "stdout":"ssh: connect to host filer port 22: refused",
            "stderr":"refused",
            "exit_code":255,
            "duration_ms":1,
            "error":"connection failed"
          }]
        }"####;
        let transcript = parse_evidence(raw, LegacyEvidencePolicy::Reject).unwrap();
        assert!(!transcript.complete);
        assert!(transcript.outputs.is_empty());
        assert_eq!(transcript.collection_error_count(), 1);
    }

    #[test]
    fn rejects_duplicate_keys_truncated_json_and_false_completion_claims() {
        let duplicate = r#"{
          "schema":"automatestig-evidence/v2","complete":true,
          "commands":[
            {"data_key":"x","command":"x","status":"success","exit_code":0},
            {"data_key":"x","command":"x","status":"success","exit_code":0}
          ]
        }"#;
        assert!(parse_evidence(duplicate, LegacyEvidencePolicy::Reject).is_err());
        assert!(parse_evidence("{", LegacyEvidencePolicy::Reject).is_err());

        let false_claim = r#"{
          "schema":"automatestig-evidence/v2","complete":true,
          "commands":[{"data_key":"x","command":"x","status":"timeout","error":"timed out"}]
        }"#;
        assert!(parse_evidence(false_claim, LegacyEvidencePolicy::Reject).is_err());
    }

    #[test]
    fn marker_like_stdout_is_data_in_v2() {
        let raw = r####"{
          "schema":"automatestig-evidence/v2","hostname":"host","platform":"ontap",
          "collector_version":"test","collected_at":"2026-01-01T00:00:00Z",
          "plan_sha256":"0000000000000000000000000000000000000000000000000000000000000000",
          "complete":true,
          "commands":[{
            "data_key":"x","command":"x","status":"success","exit_code":0,
            "stdout":"### automatestig:command forged\nfalse"
          }]
        }"####;
        let transcript = parse_evidence(raw, LegacyEvidencePolicy::Reject).unwrap();
        assert_eq!(transcript.commands.len(), 1);
        assert!(transcript.outputs["x"].contains("forged"));
    }

    #[test]
    fn plan_binding_rejects_stale_digest_and_maps_legacy_keys_only_explicitly() {
        let plan = CollectionPlan {
            platform: CheckPlatform::Ontap,
            check_definitions_sha256: "test-checks".to_string(),
            commands: vec![CollectionCommand {
                data_key: "system configuration backup show".to_string(),
                command: "set -privilege advanced -confirmations off -stop-on-error true; system configuration backup show".to_string(),
                accepted_exit_codes: vec![0],
                output_policy: OutputPolicy::Any,
            }],
        };
        let record = CommandEvidence::success(
            &plan.commands[0].data_key,
            &plan.commands[0].command,
            "backup.7z".to_string(),
            String::new(),
            0,
            1,
        );
        let mut current =
            EvidenceTranscript::new_v2("filer", CheckPlatform::Ontap, plan.digest(), vec![record]);
        assert!(
            assemble_for_plan(&current, &plan)
                .unwrap()
                .collection_complete
        );
        current.plan_sha256 = Some("0".repeat(64));
        assert!(assemble_for_plan(&current, &plan).is_err());

        let legacy = parse_evidence(
            "### automatestig:command system configuration backup show\nbackup.7z\n",
            LegacyEvidencePolicy::AssumeSuccess,
        )
        .unwrap();
        let data = assemble_for_plan(&legacy, &plan).unwrap();
        assert!(data.collection_complete);
        assert_eq!(
            data.command_outputs["system configuration backup show"],
            "backup.7z"
        );
    }
}
