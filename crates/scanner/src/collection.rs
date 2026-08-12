//! Shared target-adapter collection and replay application service.
//!
//! The GUI and CLI call this module instead of independently deciding which
//! identity commands, adapter operations, evidence shape, or replay rules are
//! authoritative. Transport credentials remain caller-owned and ephemeral.

use automatestig_collector::{collect_plan, CollectionReport, SshConfig};
use automatestig_core::checks::CheckPlatform;
use automatestig_core::models::checklist::{EvaluationOrigin, OrganizationPolicyProvenance};
use automatestig_core::organization_policy::VerifiedOrganizationPolicy;
use automatestig_core::remote::{CollectionCommand, CollectionPlan, CommandStatus, OutputPolicy};
use automatestig_core::scanner_profiles::ScannerEvidenceMode;
use automatestig_core::target_adapters::{
    built_in_target_adapter, redact_cisco_running_configuration, AdapterEvidenceEnvelope,
    AdapterOperationEvidence, AdapterOperationStatus, AdapterRequest, BuiltInTargetAdapter,
    DeviceFingerprint, EvidenceRedactionField, EvidenceTransportIdentity, HaRole, OperatingContext,
    ReadOnlyOperationPlan, TransportKind,
};
use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};

use crate::{
    evaluate_profile, resolve_bundled_profile, EvaluationInput, EvidenceTraceContext,
    ScannerEvaluation,
};

/// The observed target identity and immutable operation plan approved before
/// an SSH scan. The server key is checked again after collection so a target
/// cannot change between preflight and evidence capture.
#[derive(Debug, Clone)]
pub struct SshScannerPreflight {
    pub profile_id: String,
    pub device: DeviceFingerprint,
    pub plan: ReadOnlyOperationPlan,
    pub server_key_fingerprint: String,
}

/// Observe the target identity over the same guarded SSH transport used by
/// collection and construct the exact release-bundled read-only operation
/// plan. No mutable content library participates in this decision.
pub async fn preflight_ssh(
    profile_id_or_stig_id: &str,
    config: &SshConfig,
) -> Result<SshScannerPreflight, String> {
    let profile = resolve_bundled_profile(profile_id_or_stig_id)?;
    if profile.evidence_mode() != ScannerEvidenceMode::SshTranscript {
        return Err(format!(
            "{} uses authorized running-configuration input, not SSH collection",
            profile.display_name()
        ));
    }
    let adapter = built_in_target_adapter(profile.target_key()).ok_or_else(|| {
        format!(
            "scanner profile '{}' has no release-bundled target adapter",
            profile.target_key()
        )
    })?;
    let identity_plan = identity_collection_plan(adapter, profile.digests().profile_sha256());
    let report = collect_plan(config, &identity_plan).await;
    let server_key_fingerprint = report.server_key_fingerprint.clone().ok_or_else(|| {
        "SSH preflight did not establish a verified server host-key fingerprint".to_string()
    })?;
    let device = device_from_identity_report(adapter, &report)?;
    let plan = adapter
        .preview(&device)
        .map_err(|error| error.to_string())?;
    Ok(SshScannerPreflight {
        profile_id: profile.target_key().to_string(),
        device,
        plan,
        server_key_fingerprint,
    })
}

/// Collect the exact reviewed operations and seal them into the native target
/// adapter envelope used by both front ends and by replay verification.
pub async fn collect_ssh_envelope(
    config: &SshConfig,
    preflight: &SshScannerPreflight,
) -> Result<AdapterEvidenceEnvelope, String> {
    let profile = resolve_bundled_profile(&preflight.profile_id)?;
    if profile.evidence_mode() != ScannerEvidenceMode::SshTranscript {
        return Err("SSH preflight no longer identifies an SSH scanner profile".to_string());
    }
    let adapter = built_in_target_adapter(profile.target_key())
        .ok_or_else(|| "SSH scanner profile has no bundled adapter".to_string())?;
    let expected_plan = adapter
        .preview(&preflight.device)
        .map_err(|error| error.to_string())?;
    if expected_plan != preflight.plan {
        return Err("SSH preflight operation plan no longer matches bundled content".to_string());
    }
    let requested_timeout_ms = config
        .timeout_secs
        .checked_mul(1_000)
        .ok_or_else(|| "SSH timeout overflowed the operation-plan duration contract".to_string())?;
    if expected_plan
        .operations
        .iter()
        .any(|operation| requested_timeout_ms > operation.maximum_duration_ms)
    {
        return Err(
            "SSH timeout exceeds the immutable per-operation maximum returned by preflight"
                .to_string(),
        );
    }

    let collection_plan = collection_plan_from_adapter(&preflight.plan)?;
    let report = collect_plan(config, &collection_plan).await;
    let observed_key = report.server_key_fingerprint.as_deref().ok_or_else(|| {
        "SSH collection did not establish a verified server host-key fingerprint".to_string()
    })?;
    if observed_key != preflight.server_key_fingerprint {
        return Err(
            "SSH server host key changed after preflight; no evidence was accepted".to_string(),
        );
    }
    let operations = operation_evidence_from_report(&preflight.plan, &report)?;
    AdapterEvidenceEnvelope::seal_now(
        &preflight.plan,
        preflight.device.clone(),
        EvidenceTransportIdentity::SshHostKey {
            fingerprint: preflight.server_key_fingerprint.clone(),
        },
        operations,
    )
    .map_err(|error| error.to_string())
}

/// Collect exactly one operation from an already verified immutable SSH plan.
///
/// This bounded primitive is used by the durable GUI coordinator to commit an
/// encrypted checkpoint after every successful operation. It never accepts an
/// arbitrary command: `operation_id` must identify one release-bundled plan
/// entry, and the returned record remains bound to that exact request.
///
/// `Ok` means that collection produced a structurally bound evidence record;
/// it does not mean the remote operation succeeded. Transport, permission,
/// timeout, response-limit, and semantic failures are returned as typed
/// `AdapterOperationEvidence` so the caller can report the exact failure. A
/// durable coordinator must accept a record into a resume checkpoint only
/// after `validate_successful_checkpoint_prefix` accepts the resulting prefix.
pub async fn collect_ssh_operation(
    config: &SshConfig,
    preflight: &SshScannerPreflight,
    operation_id: &str,
) -> Result<AdapterOperationEvidence, String> {
    validate_ssh_preflight_plan(preflight)?;
    let operation = preflight
        .plan
        .operations
        .iter()
        .find(|operation| operation.operation_id == operation_id)
        .ok_or_else(|| {
            format!("operation {operation_id:?} is not present in the immutable SSH plan")
        })?;
    let collection_plan = collection_plan_for_operations(&preflight.plan, [operation])?;
    let report = collect_plan(config, &collection_plan).await;
    let observed_key = report.server_key_fingerprint.as_deref().ok_or_else(|| {
        "SSH operation did not establish a verified server host-key fingerprint".to_string()
    })?;
    if observed_key != preflight.server_key_fingerprint {
        return Err(
            "SSH server host key changed after preflight; no checkpoint evidence was accepted"
                .to_string(),
        );
    }
    let mut evidence = operation_evidence_from_report_for_operations([operation], &report)?;
    evidence
        .pop()
        .ok_or_else(|| "collector returned no checkpoint operation evidence".to_string())
}

/// Accept only a non-empty, exact, successful prefix of an immutable operation
/// plan for durable resume checkpointing.
///
/// This is deliberately stricter than general envelope validation, which can
/// retain typed failure records for reporting. A resume checkpoint is a claim
/// that every retained operation can be skipped safely on the next attempt, so
/// failed, truncated, redacted, digest-invalid, out-of-order, or otherwise
/// incomplete evidence is rejected before it reaches durable storage.
pub fn validate_successful_checkpoint_prefix(
    plan: &ReadOnlyOperationPlan,
    operations: &[AdapterOperationEvidence],
) -> Result<(), String> {
    if operations.is_empty() {
        return Err("SSH checkpoint prefix must contain at least one operation".to_string());
    }
    if operations.len() > plan.operations.len() {
        return Err("SSH checkpoint contains more operations than its immutable plan".to_string());
    }

    for (index, (record, planned)) in operations.iter().zip(plan.operations.iter()).enumerate() {
        if record.operation_id != planned.operation_id || record.request != planned.request {
            return Err(format!(
                "SSH checkpoint operation {} is not the exact planned operation at prefix position {}",
                record.operation_id,
                index + 1
            ));
        }
        if record.status != AdapterOperationStatus::Success {
            return Err(format!(
                "SSH checkpoint operation {} is not successful",
                record.operation_id
            ));
        }
        if record.truncated {
            return Err(format!(
                "SSH checkpoint operation {} has a truncated response",
                record.operation_id
            ));
        }
        if record.error.is_some() {
            return Err(format!(
                "SSH checkpoint operation {} reports an error",
                record.operation_id
            ));
        }
        let status_code = record.status_code.ok_or_else(|| {
            format!(
                "SSH checkpoint operation {} has no transport status code",
                record.operation_id
            )
        })?;
        if !planned.accepted_status_codes.contains(&status_code) {
            return Err(format!(
                "SSH checkpoint operation {} has unaccepted transport status code {}",
                record.operation_id, status_code
            ));
        }
        if record
            .redactions
            .iter()
            .any(|redaction| redaction.field == EvidenceRedactionField::Response)
        {
            return Err(format!(
                "SSH checkpoint operation {} has a redacted evaluation response",
                record.operation_id
            ));
        }
        for redaction in &record.redactions {
            if redaction.reason.trim().is_empty() || !is_lowercase_sha256(&redaction.removed_sha256)
            {
                return Err(format!(
                    "SSH checkpoint operation {} has invalid redaction metadata",
                    record.operation_id
                ));
            }
        }
        let response = record.response.as_deref().ok_or_else(|| {
            format!(
                "SSH checkpoint operation {} has no response",
                record.operation_id
            )
        })?;
        let response_sha256 = record.response_sha256.as_deref().ok_or_else(|| {
            format!(
                "SSH checkpoint operation {} has no response digest",
                record.operation_id
            )
        })?;
        if !is_lowercase_sha256(response_sha256)
            || format!("{:x}", Sha256::digest(response.as_bytes())) != response_sha256
        {
            return Err(format!(
                "SSH checkpoint operation {} response digest does not match",
                record.operation_id
            ));
        }
    }
    Ok(())
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Seal the ordered union of successful checkpoint operations into the same
/// native immutable envelope used by an uninterrupted collection.
pub fn seal_resumed_ssh_envelope(
    preflight: &SshScannerPreflight,
    collected_at: DateTime<Utc>,
    operations: Vec<AdapterOperationEvidence>,
) -> Result<AdapterEvidenceEnvelope, String> {
    validate_ssh_preflight_plan(preflight)?;
    if operations.len() != preflight.plan.operations.len() {
        return Err(format!(
            "SSH checkpoint is incomplete: {} of {} operations are present",
            operations.len(),
            preflight.plan.operations.len()
        ));
    }
    validate_successful_checkpoint_prefix(&preflight.plan, &operations)?;
    AdapterEvidenceEnvelope::seal(
        &preflight.plan,
        preflight.device.clone(),
        EvidenceTransportIdentity::SshHostKey {
            fingerprint: preflight.server_key_fingerprint.clone(),
        },
        collected_at,
        operations,
    )
    .map_err(|error| error.to_string())
}

fn validate_ssh_preflight_plan(preflight: &SshScannerPreflight) -> Result<(), String> {
    let profile = resolve_bundled_profile(&preflight.profile_id)?;
    if profile.evidence_mode() != ScannerEvidenceMode::SshTranscript {
        return Err("SSH preflight no longer identifies an SSH scanner profile".to_string());
    }
    let adapter = built_in_target_adapter(profile.target_key())
        .ok_or_else(|| "SSH scanner profile has no bundled adapter".to_string())?;
    let expected_plan = adapter
        .preview(&preflight.device)
        .map_err(|error| error.to_string())?;
    if expected_plan != preflight.plan {
        return Err("SSH preflight operation plan no longer matches bundled content".to_string());
    }
    Ok(())
}

/// Validate and seal one authorized IOS-XE running configuration using the
/// same adapter envelope and secret-redaction contract as the GUI upload path.
pub fn configuration_envelope(
    profile_id_or_stig_id: &str,
    configuration: &[u8],
    collected_at: DateTime<Utc>,
) -> Result<AdapterEvidenceEnvelope, String> {
    let profile = resolve_bundled_profile(profile_id_or_stig_id)?;
    if profile.evidence_mode() != ScannerEvidenceMode::RunningConfiguration {
        return Err(format!(
            "{} requires native SSH adapter evidence, not a running configuration",
            profile.display_name()
        ));
    }
    let adapter = built_in_target_adapter(profile.target_key())
        .ok_or_else(|| "running-configuration profile has no bundled adapter".to_string())?;
    if adapter != BuiltInTargetAdapter::CiscoIosXeRouterNdm {
        return Err("only the IOS-XE adapter accepts running configurations".to_string());
    }
    let text = std::str::from_utf8(configuration)
        .map_err(|_| "IOS-XE running configuration must be UTF-8 text".to_string())?;
    automatestig_core::remote::validate_network_config(CheckPlatform::CiscoIos, text)?;
    let hostname = automatestig_core::remote::cisco_config_hostname(text)?;
    let version = configuration_version(text).ok_or_else(|| {
        "could not establish supported IOS-XE 17.x from the running configuration".to_string()
    })?;
    let device = DeviceFingerprint::new(hostname, "Cisco", "IOS-XE", version).with_context(
        OperatingContext::NetworkAppliance,
        HaRole::UnknownOrUnsupported,
    );
    let plan = adapter
        .preview(&device)
        .map_err(|error| error.to_string())?;
    let operation = plan
        .operations
        .first()
        .ok_or_else(|| "IOS-XE adapter plan contains no configuration operation".to_string())?;
    if plan.operations.len() != 1 {
        return Err("IOS-XE adapter plan must contain exactly one configuration operation".into());
    }
    let (sanitized, redactions) = redact_cisco_running_configuration(text);
    let mut evidence = AdapterOperationEvidence::success(operation, sanitized, 0);
    evidence.redactions = redactions;
    AdapterEvidenceEnvelope::seal(
        &plan,
        device,
        EvidenceTransportIdentity::offline_artifact(configuration),
        collected_at,
        vec![evidence],
    )
    .map_err(|error| error.to_string())
}

/// Replay a native adapter envelope and evaluate only the immutable bundled
/// profile. A verified policy may be attached in memory, but a serialized
/// provenance claim can never substitute for signature verification.
pub fn evaluate_adapter_envelope(
    profile_id_or_stig_id: &str,
    envelope: &AdapterEvidenceEnvelope,
    origin: EvaluationOrigin,
    verified_policy: Option<VerifiedOrganizationPolicy>,
) -> Result<ScannerEvaluation, String> {
    let profile = resolve_bundled_profile(profile_id_or_stig_id)?;
    if envelope.target_key != profile.target_key() {
        return Err("adapter evidence target does not match the selected scanner profile".into());
    }
    match (envelope.transport, origin) {
        (TransportKind::SshCli, EvaluationOrigin::LiveSsh | EvaluationOrigin::EvidenceFile)
        | (TransportKind::OfflineConfig, EvaluationOrigin::ConfigFile) => {}
        _ => return Err("evaluation origin does not match the adapter evidence transport".into()),
    }
    let adapter = built_in_target_adapter(profile.target_key())
        .ok_or_else(|| "scanner profile has no bundled adapter".to_string())?;
    let mut replay = adapter
        .replay(envelope)
        .map_err(|error| error.to_string())?;
    let organization_policy = verified_policy
        .as_ref()
        .map(|policy| OrganizationPolicyProvenance {
            policy_id: policy.document().policy_id.clone(),
            policy_version: policy.document().policy_version.clone(),
            policy_sha256: policy.sha256().to_string(),
            signer_fingerprint: policy.signer_fingerprint().to_string(),
            signature_verified: true,
        });
    replay.system_data.organization_policy = verified_policy;
    let server_key_fingerprint = match &envelope.transport_identity {
        EvidenceTransportIdentity::SshHostKey { fingerprint } => Some(fingerprint.clone()),
        _ => None,
    };
    let evidence_context = EvidenceTraceContext::from_envelope(envelope)?;
    evaluate_profile(EvaluationInput {
        profile_id: profile.target_key().to_string(),
        device: envelope.device.clone(),
        system_data: replay.system_data,
        origin,
        evidence_sha256: envelope.evidence_sha256.clone(),
        plan_sha256: envelope.plan_sha256.clone(),
        server_key_fingerprint,
        collector_version: Some(envelope.adapter_version.clone()),
        collected_at: envelope.collected_at.clone(),
        evidence_context,
        organization_policy,
    })
}

/// Enforce the common evidence timestamp acceptance window. Callers choose the
/// governed maximum age; the future-skew bound is fixed and fail-closed.
pub fn validate_evidence_age(
    envelope: &AdapterEvidenceEnvelope,
    now: DateTime<Utc>,
    maximum_age_hours: i64,
) -> Result<(), String> {
    if !(1..=720).contains(&maximum_age_hours) {
        return Err("maximum evidence age must be from 1 through 720 hours".to_string());
    }
    let collected_at = DateTime::parse_from_rfc3339(&envelope.collected_at)
        .map_err(|_| "evidence collected_at is not RFC 3339".to_string())?
        .with_timezone(&Utc);
    if collected_at > now + Duration::minutes(5) {
        return Err("evidence collection time is more than five minutes in the future".into());
    }
    if collected_at < now - Duration::hours(maximum_age_hours) {
        return Err(format!(
            "evidence is older than the configured {maximum_age_hours}-hour acceptance window"
        ));
    }
    Ok(())
}

fn identity_collection_plan(adapter: BuiltInTargetAdapter, profile_sha256: &str) -> CollectionPlan {
    let commands = match adapter {
        BuiltInTargetAdapter::NetAppOntap9 => vec![
            identity_command("version", "automatestig_identity_version"),
            identity_command("cluster identity show", "automatestig_identity_cluster"),
        ],
        BuiltInTargetAdapter::FreeBsdGpos => vec![
            identity_command("freebsd-version -ku", "automatestig_identity_version"),
            identity_command("hostname", "automatestig_identity_hostname"),
        ],
        BuiltInTargetAdapter::CiscoIosXeRouterNdm => Vec::new(),
    };
    CollectionPlan {
        platform: platform_for_adapter(adapter),
        commands,
        check_definitions_sha256: profile_sha256.to_string(),
    }
}

fn identity_command(command: &str, data_key: &str) -> CollectionCommand {
    CollectionCommand {
        command: command.to_string(),
        data_key: data_key.to_string(),
        accepted_exit_codes: vec![0],
        output_policy: OutputPolicy::Any,
    }
}

fn platform_for_adapter(adapter: BuiltInTargetAdapter) -> CheckPlatform {
    match adapter {
        BuiltInTargetAdapter::NetAppOntap9 => CheckPlatform::Ontap,
        BuiltInTargetAdapter::FreeBsdGpos => CheckPlatform::Bsd,
        BuiltInTargetAdapter::CiscoIosXeRouterNdm => CheckPlatform::CiscoIos,
    }
}

fn first_successful_output<'a>(report: &'a CollectionReport, key: &str) -> Result<&'a str, String> {
    let record = report
        .commands
        .iter()
        .find(|record| record.data_key == key)
        .ok_or_else(|| format!("identity preflight omitted {key}"))?;
    if record.status != CommandStatus::Success {
        return Err(record.error.clone().unwrap_or_else(|| {
            format!("identity preflight {key} failed with {:?}", record.status)
        }));
    }
    let value = record.stdout.trim();
    if value.is_empty() {
        return Err(format!("identity preflight {key} returned no value"));
    }
    Ok(value)
}

fn device_from_identity_report(
    adapter: BuiltInTargetAdapter,
    report: &CollectionReport,
) -> Result<DeviceFingerprint, String> {
    let version_output = first_successful_output(report, "automatestig_identity_version")?;
    match adapter {
        BuiltInTargetAdapter::NetAppOntap9 => {
            let (cluster_name, cluster_uuid) = ontap_cluster_identity(first_successful_output(
                report,
                "automatestig_identity_cluster",
            )?)?;
            let version = leading_version(version_output, 9)
                .ok_or_else(|| format!("could not identify ONTAP 9 from {version_output:?}"))?;
            let mut device = DeviceFingerprint::new(cluster_name, "NetApp", "ONTAP", version)
                .with_context(OperatingContext::StorageCluster, HaRole::Known);
            device.serial_number = Some(cluster_uuid);
            Ok(device)
        }
        BuiltInTargetAdapter::FreeBsdGpos => {
            let version = leading_version(version_output, 13)
                .or_else(|| leading_version(version_output, 14))
                .ok_or_else(|| {
                    format!(
                        "could not identify a supported FreeBSD 13/14 version from {version_output:?}"
                    )
                })?;
            Ok(DeviceFingerprint::new(
                first_successful_output(report, "automatestig_identity_hostname")?,
                "FreeBSD",
                "FreeBSD",
                version,
            ))
        }
        BuiltInTargetAdapter::CiscoIosXeRouterNdm => {
            Err("IOS-XE uses authorized offline configuration input".to_string())
        }
    }
}

fn leading_version(value: &str, required_major: u32) -> Option<String> {
    value
        .split(|character: char| !(character.is_ascii_alphanumeric() || character == '.'))
        .map(|token| token.trim_matches(|character: char| !character.is_ascii_digit()))
        .find(|token| {
            token
                .split('.')
                .next()
                .and_then(|major| major.parse::<u32>().ok())
                == Some(required_major)
        })
        .map(str::to_string)
}

fn configuration_version(config: &str) -> Option<String> {
    config.lines().find_map(|line| {
        let value = line.trim().strip_prefix("version ")?;
        leading_version(value, 17)
    })
}

fn ontap_cluster_identity(output: &str) -> Result<(String, String), String> {
    fn one_field(output: &str, label: &str) -> Result<String, String> {
        let values: Vec<_> = output
            .lines()
            .map(str::trim)
            .filter_map(|line| line.strip_prefix(label).map(str::trim))
            .filter(|value| !value.is_empty())
            .collect();
        match values.as_slice() {
            [value] if !value.chars().any(char::is_control) => Ok((*value).to_string()),
            [] => Err(format!("ONTAP identity output omitted {label}")),
            _ => Err(format!("ONTAP identity output contains ambiguous {label}")),
        }
    }
    let name = one_field(output, "Cluster Name:")?;
    let uuid = one_field(output, "Cluster UUID:")?;
    if name.len() > 255
        || !name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        return Err("ONTAP cluster name is not a safe asset identity".to_string());
    }
    if uuid.len() != 36
        || !uuid
            .chars()
            .all(|character| character.is_ascii_hexdigit() || character == '-')
    {
        return Err("ONTAP cluster UUID is malformed".to_string());
    }
    Ok((name, uuid.to_ascii_lowercase()))
}

fn collection_plan_from_adapter(plan: &ReadOnlyOperationPlan) -> Result<CollectionPlan, String> {
    collection_plan_for_operations(plan, plan.operations.iter())
}

fn collection_plan_for_operations<'a>(
    plan: &ReadOnlyOperationPlan,
    operations: impl IntoIterator<Item = &'a automatestig_core::target_adapters::ReadOnlyOperation>,
) -> Result<CollectionPlan, String> {
    let operations = operations.into_iter().collect::<Vec<_>>();
    if operations.is_empty() || operations.len() > plan.operations.len() {
        return Err(
            "SSH operation subset must contain at least one bounded plan entry".to_string(),
        );
    }
    let mut commands = Vec::with_capacity(operations.len());
    for operation in operations {
        if !plan
            .operations
            .iter()
            .any(|candidate| candidate == operation)
        {
            return Err(format!(
                "operation {} does not exactly match the immutable SSH plan",
                operation.operation_id
            ));
        }
        let AdapterRequest::SshCli { command } = &operation.request else {
            return Err(format!(
                "operation {} is not an SSH CLI request",
                operation.operation_id
            ));
        };
        commands.push(CollectionCommand {
            command: command.clone(),
            data_key: operation.data_key.clone(),
            accepted_exit_codes: operation.accepted_status_codes.clone(),
            output_policy: operation.output_policy,
        });
    }
    let platform = match plan.target_key.as_str() {
        "netapp_ontap9" => CheckPlatform::Ontap,
        "freebsd_gpos" => CheckPlatform::Bsd,
        other => return Err(format!("{other} is not an SSH scanner profile")),
    };
    Ok(CollectionPlan {
        platform,
        commands,
        check_definitions_sha256: plan.check_pack_sha256.clone(),
    })
}

fn operation_evidence_from_report(
    plan: &ReadOnlyOperationPlan,
    report: &CollectionReport,
) -> Result<Vec<AdapterOperationEvidence>, String> {
    operation_evidence_from_report_for_operations(plan.operations.iter(), report)
}

fn operation_evidence_from_report_for_operations<'a>(
    operations: impl IntoIterator<Item = &'a automatestig_core::target_adapters::ReadOnlyOperation>,
    report: &CollectionReport,
) -> Result<Vec<AdapterOperationEvidence>, String> {
    operations
        .into_iter()
        .map(|operation| {
            let Some(record) = report
                .commands
                .iter()
                .find(|record| record.data_key == operation.data_key)
            else {
                return AdapterOperationEvidence::failed(
                    operation,
                    AdapterOperationStatus::ProtocolError,
                    "collector returned no record for this planned operation",
                    0,
                )
                .map_err(|error| error.to_string());
            };
            let status = adapter_status(record.status);
            if status == AdapterOperationStatus::Success {
                let mut evidence = AdapterOperationEvidence::success(
                    operation,
                    record.stdout.clone(),
                    record.duration_ms,
                );
                evidence.status_code = record.exit_code;
                evidence.diagnostics = record.stderr.clone();
                Ok(evidence)
            } else {
                let mut evidence = AdapterOperationEvidence::failed(
                    operation,
                    status,
                    record
                        .error
                        .clone()
                        .unwrap_or_else(|| format!("collector returned {:?}", record.status)),
                    record.duration_ms,
                )
                .map_err(|error| error.to_string())?;
                evidence.diagnostics = record.stderr.clone();
                evidence.truncated = record.status == CommandStatus::OutputLimit;
                Ok(evidence)
            }
        })
        .collect()
}

fn adapter_status(status: CommandStatus) -> AdapterOperationStatus {
    match status {
        CommandStatus::Success => AdapterOperationStatus::Success,
        CommandStatus::Timeout => AdapterOperationStatus::Timeout,
        CommandStatus::TransportError => AdapterOperationStatus::TransportError,
        CommandStatus::OutputLimit => AdapterOperationStatus::ResponseLimit,
        CommandStatus::SemanticError => AdapterOperationStatus::SemanticError,
        CommandStatus::ExitFailure
        | CommandStatus::MissingExitStatus
        | CommandStatus::ProtocolError
        | CommandStatus::MissingEvidence => AdapterOperationStatus::ProtocolError,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use automatestig_core::remote::CommandEvidence;

    fn identity_report(commands: Vec<CommandEvidence>) -> CollectionReport {
        CollectionReport {
            commands,
            server_key_fingerprint: Some(
                "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            ),
        }
    }

    #[test]
    fn identity_parsers_bind_observed_device_versions() {
        let freebsd = identity_report(vec![
            CommandEvidence::success(
                "automatestig_identity_version",
                "freebsd-version -ku",
                "14.3-RELEASE\n14.3-RELEASE".to_string(),
                String::new(),
                0,
                1,
            ),
            CommandEvidence::success(
                "automatestig_identity_hostname",
                "hostname",
                "host01.example.test".to_string(),
                String::new(),
                0,
                1,
            ),
        ]);
        let device =
            device_from_identity_report(BuiltInTargetAdapter::FreeBsdGpos, &freebsd).unwrap();
        assert_eq!(device.hostname, "host01.example.test");
        assert_eq!(device.software_version, "14.3");

        let ontap = identity_report(vec![
            CommandEvidence::success(
                "automatestig_identity_version",
                "version",
                "NetApp Release 9.15.1P4".to_string(),
                String::new(),
                0,
                1,
            ),
            CommandEvidence::success(
                "automatestig_identity_cluster",
                "cluster identity show",
                "Cluster Name: filer01\nCluster UUID: 12345678-1234-1234-1234-123456789abc"
                    .to_string(),
                String::new(),
                0,
                1,
            ),
        ]);
        let device =
            device_from_identity_report(BuiltInTargetAdapter::NetAppOntap9, &ontap).unwrap();
        assert_eq!(device.hostname, "filer01");
        assert_eq!(device.software_version, "9.15.1P4");
        assert_eq!(
            device.serial_number.as_deref(),
            Some("12345678-1234-1234-1234-123456789abc")
        );
    }

    #[test]
    fn configuration_envelope_is_redacted_bound_and_replayable() {
        let raw = b"version 17.9\nhostname edge01\nusername admin secret 9 supersecret\nline vty 0 4\n transport input ssh\nend\n";
        let envelope = configuration_envelope(
            "cisco_ios_xe_router_ndm",
            raw,
            DateTime::parse_from_rfc3339("2026-08-11T12:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        )
        .unwrap();
        assert!(envelope.complete);
        assert_eq!(envelope.device.hostname, "edge01");
        let serialized = serde_json::to_string(&envelope).unwrap();
        assert!(!serialized.contains("supersecret"));
        assert!(serialized.contains("__AUTOMATESTIG_SECRET_REMOVED__"));
        let adapter = built_in_target_adapter(&envelope.target_key).unwrap();
        assert!(adapter.replay(&envelope).unwrap().completeness.complete);
    }

    #[test]
    fn evidence_age_rejects_stale_future_and_invalid_policy() {
        let raw = b"version 17.9\nhostname edge01\nline vty 0 4\n transport input ssh\nend\n";
        let collected = DateTime::parse_from_rfc3339("2026-08-11T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let envelope = configuration_envelope("cisco_ios_xe_router_ndm", raw, collected).unwrap();
        assert!(validate_evidence_age(&envelope, collected + Duration::hours(1), 168).is_ok());
        assert!(validate_evidence_age(&envelope, collected + Duration::hours(169), 168).is_err());
        assert!(validate_evidence_age(&envelope, collected - Duration::minutes(6), 168).is_err());
        assert!(validate_evidence_age(&envelope, collected, 0).is_err());
    }

    fn freebsd_checkpoint_preflight() -> SshScannerPreflight {
        let device = DeviceFingerprint::new("host01.example.test", "FreeBSD", "FreeBSD", "14.3");
        let plan = BuiltInTargetAdapter::FreeBsdGpos.preview(&device).unwrap();
        SshScannerPreflight {
            profile_id: "freebsd_gpos".to_string(),
            device,
            plan,
            server_key_fingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                .to_string(),
        }
    }

    #[test]
    fn operation_subset_is_bounded_to_the_immutable_plan() {
        let preflight = freebsd_checkpoint_preflight();
        let operation = preflight.plan.operations.first().unwrap();
        let subset = collection_plan_for_operations(&preflight.plan, [operation]).unwrap();
        assert_eq!(subset.commands.len(), 1);
        assert_eq!(subset.commands[0].data_key, operation.data_key);

        let mut foreign = operation.clone();
        foreign.operation_id.push_str("-tampered");
        assert!(collection_plan_for_operations(&preflight.plan, [&foreign]).is_err());
        assert!(collection_plan_for_operations(
            &preflight.plan,
            std::iter::empty::<&automatestig_core::target_adapters::ReadOnlyOperation>(),
        )
        .is_err());
    }

    #[test]
    fn resumed_checkpoint_seals_only_a_complete_exact_ordered_union() {
        let preflight = freebsd_checkpoint_preflight();
        let collected_at = DateTime::parse_from_rfc3339("2026-08-11T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let evidence = preflight
            .plan
            .operations
            .iter()
            .map(|operation| AdapterOperationEvidence::success(operation, "observed", 1))
            .collect::<Vec<_>>();
        let envelope =
            seal_resumed_ssh_envelope(&preflight, collected_at, evidence.clone()).unwrap();
        assert!(envelope.complete);
        assert_eq!(
            envelope
                .operations
                .iter()
                .map(|operation| operation.operation_id.as_str())
                .collect::<Vec<_>>(),
            preflight
                .plan
                .operations
                .iter()
                .map(|operation| operation.operation_id.as_str())
                .collect::<Vec<_>>()
        );

        let mut incomplete = evidence.clone();
        incomplete.pop();
        assert!(seal_resumed_ssh_envelope(&preflight, collected_at, incomplete).is_err());

        let mut reordered = evidence.clone();
        reordered.reverse();
        assert!(seal_resumed_ssh_envelope(&preflight, collected_at, reordered).is_err());

        let mut tampered = preflight
            .plan
            .operations
            .iter()
            .map(|operation| AdapterOperationEvidence::success(operation, "observed", 1))
            .collect::<Vec<_>>();
        tampered[0].request = AdapterRequest::SshCli {
            command: "uname -a".to_string(),
        };
        assert!(seal_resumed_ssh_envelope(&preflight, collected_at, tampered).is_err());
    }

    #[test]
    fn checkpoint_prefix_rejects_failed_or_incomplete_operation_evidence() {
        let preflight = freebsd_checkpoint_preflight();
        let first = &preflight.plan.operations[0];
        let second = &preflight.plan.operations[1];
        let successful_first = AdapterOperationEvidence::success(first, "observed", 1);
        assert!(validate_successful_checkpoint_prefix(
            &preflight.plan,
            std::slice::from_ref(&successful_first),
        )
        .is_ok());

        let failed = AdapterOperationEvidence::failed(
            first,
            AdapterOperationStatus::Timeout,
            "operation timed out",
            30_000,
        )
        .unwrap();
        assert!(validate_successful_checkpoint_prefix(&preflight.plan, &[failed]).is_err());

        let out_of_order = AdapterOperationEvidence::success(second, "observed", 1);
        assert!(validate_successful_checkpoint_prefix(&preflight.plan, &[out_of_order]).is_err());

        let mut truncated = successful_first.clone();
        truncated.truncated = true;
        assert!(validate_successful_checkpoint_prefix(&preflight.plan, &[truncated]).is_err());

        let mut unaccepted_status = successful_first.clone();
        unaccepted_status.status_code = Some(u32::MAX);
        assert!(
            validate_successful_checkpoint_prefix(&preflight.plan, &[unaccepted_status]).is_err()
        );

        let mut digest_mismatch = successful_first;
        digest_mismatch.response = Some("changed".to_string());
        assert!(
            validate_successful_checkpoint_prefix(&preflight.plan, &[digest_mismatch]).is_err()
        );
    }
}
