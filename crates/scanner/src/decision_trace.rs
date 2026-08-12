//! Sanitized, replay-comparable provenance for each automated determination.
//!
//! A trace intentionally never contains a command response, diagnostic, raw
//! error, credential, or organization-policy private key. Exact evidence stays
//! in the separately retained envelope. The trace does retain the exact
//! release-reviewed read-only request and expectation, plus domain-bound
//! digests, typed collection metadata, and a safe observation classification.

use std::collections::{BTreeMap, BTreeSet};

use automatestig_core::check_packs::canonical_json_sha256;
use automatestig_core::checks::{CheckPack, CheckResult};
use automatestig_core::models::checklist::{
    Checklist, EvaluationOrigin, OrganizationPolicyProvenance,
};
use automatestig_core::models::finding::FindingStatus;
use automatestig_core::organization_policy::VerifiedOrganizationPolicy;
use automatestig_core::target_adapters::{
    built_in_target_adapter, AdapterEvidenceEnvelope, AdapterOperationStatus, AdapterPrivilege,
    AdapterRequest, DeviceFingerprint, EvidenceTransportIdentity, ReadOnlyOperation,
    TargetAdapterContractVersion, TransportKind, DEVICE_FINGERPRINT_SCHEMA_V1,
    DEVICE_FINGERPRINT_SCHEMA_V2, TARGET_ADAPTER_CONTRACT_SCHEMA_V1,
    TARGET_ADAPTER_CONTRACT_SCHEMA_V2, TARGET_ADAPTER_EVIDENCE_SCHEMA_V1,
    TARGET_ADAPTER_EVIDENCE_SCHEMA_V2, TARGET_ADAPTER_IMPLEMENTATION_VERSION_V1,
    TARGET_ADAPTER_IMPLEMENTATION_VERSION_V2,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const DECISION_TRACE_SCHEMA_V1: &str = "automatestig.decision-trace.v1";
pub const DECISION_TRACE_SCHEMA_V2: &str = "automatestig.decision-trace.v2";
pub const DECISION_TRACE_SCHEMA: &str = DECISION_TRACE_SCHEMA_V2;
pub const SIGNED_POLICY_REPLAY_SCHEMA: &str = "automatestig.signed-policy-replay.v1";
const EVALUATOR_ID: &str = "automatestig-scanner";
const PARSER_CONTRACT_VERSION: &str = "1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPolicyReplayMaterial {
    pub schema: String,
    /// Exact signed bytes, hex encoded so whitespace and member ordering remain
    /// cryptographically replayable.
    pub policy_bytes_hex: String,
    pub detached_signature_hex: String,
    pub signer_public_key_hex: String,
    pub policy_sha256: String,
    pub signature_sha256: String,
    pub signer_fingerprint: String,
    pub verified_at: String,
}

impl SignedPolicyReplayMaterial {
    pub fn from_verified(policy: &VerifiedOrganizationPolicy) -> Self {
        Self {
            schema: SIGNED_POLICY_REPLAY_SCHEMA.to_string(),
            policy_bytes_hex: encode_hex(policy.raw_policy()),
            detached_signature_hex: encode_hex(policy.signature()),
            signer_public_key_hex: encode_hex(policy.signer_public_key()),
            policy_sha256: policy.sha256().to_string(),
            signature_sha256: sha256_hex(policy.signature()),
            signer_fingerprint: policy.signer_fingerprint().to_string(),
            verified_at: policy.verified_at().to_string(),
        }
    }

    pub fn material_sha256(&self) -> Result<String, String> {
        canonical_json_sha256(self)
            .map_err(|error| format!("failed to digest signed policy replay material: {error}"))
    }

    /// Re-establish the signature, signer identity, policy digest, scope, and
    /// original verification instant using public material only.
    pub fn verify_for_replay(
        &self,
        stig_id: &str,
        stig_release: &str,
        hostname: &str,
    ) -> Result<VerifiedOrganizationPolicy, String> {
        if self.schema != SIGNED_POLICY_REPLAY_SCHEMA {
            return Err("signed policy replay material has an unsupported schema".to_string());
        }
        let raw = decode_hex(&self.policy_bytes_hex, None, "policy_bytes_hex")?;
        let signature = decode_hex(
            &self.detached_signature_hex,
            Some(64),
            "detached_signature_hex",
        )?;
        let public_key = decode_hex(
            &self.signer_public_key_hex,
            Some(32),
            "signer_public_key_hex",
        )?;
        let public_key: [u8; 32] = public_key
            .try_into()
            .map_err(|_| "signer public key is not 32 bytes".to_string())?;
        if sha256_hex(&raw) != self.policy_sha256
            || sha256_hex(&signature) != self.signature_sha256
            || format!("SHA256:{}", sha256_hex(&public_key)) != self.signer_fingerprint
        {
            return Err(
                "signed policy replay material digest or signer binding changed".to_string(),
            );
        }
        let verified_at = DateTime::parse_from_rfc3339(&self.verified_at)
            .map_err(|_| "signed policy verified_at is not RFC 3339".to_string())?
            .with_timezone(&Utc);
        let verified = VerifiedOrganizationPolicy::verify_and_parse(
            &raw,
            &signature,
            &[public_key],
            stig_id,
            stig_release,
            hostname,
            verified_at,
        )?;
        if SignedPolicyReplayMaterial::from_verified(&verified) != *self {
            return Err("signed policy replay material is not canonical".to_string());
        }
        Ok(verified)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionValue {
    /// A bounded primitive may be shown; complex or target-identifying values
    /// remain absent and are represented only by the salted digest.
    pub safe_value: Option<String>,
    pub value_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionOperationStatus {
    Success,
    PermissionDenied,
    AuthenticationFailed,
    Timeout,
    TransportError,
    ProtocolError,
    ResponseLimit,
    SemanticError,
    Missing,
}

impl From<AdapterOperationStatus> for DecisionOperationStatus {
    fn from(value: AdapterOperationStatus) -> Self {
        match value {
            AdapterOperationStatus::Success => Self::Success,
            AdapterOperationStatus::PermissionDenied => Self::PermissionDenied,
            AdapterOperationStatus::AuthenticationFailed => Self::AuthenticationFailed,
            AdapterOperationStatus::Timeout => Self::Timeout,
            AdapterOperationStatus::TransportError => Self::TransportError,
            AdapterOperationStatus::ProtocolError => Self::ProtocolError,
            AdapterOperationStatus::ResponseLimit => Self::ResponseLimit,
            AdapterOperationStatus::SemanticError => Self::SemanticError,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionOperationTrace {
    pub operation_id: String,
    pub observation_key: String,
    pub request_kind: String,
    /// Exact non-secret request from the immutable release-reviewed operation
    /// plan. This is never copied from target output or operator input.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub request: String,
    pub request_sha256: String,
    pub transport: TransportKind,
    pub privilege: AdapterPrivilege,
    pub estimated_duration_ms: u64,
    pub maximum_duration_ms: u64,
    pub duration_ms: Option<u64>,
    pub status: DecisionOperationStatus,
    pub status_code: Option<u32>,
    pub truncated: bool,
    pub observation_sha256: Option<String>,
    pub diagnostics_present: bool,
    pub error_present: bool,
    /// Safe typed linkage only. The target-controlled error text remains in
    /// encrypted evidence and is never hashed into this result.
    pub error_class: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionPolicyBinding {
    pub policy_id: String,
    pub policy_version: String,
    pub policy_sha256: String,
    pub signer_fingerprint: String,
    pub signature_sha256: String,
    pub public_key_sha256: String,
    pub material_sha256: String,
    pub verified_at: String,
    /// Exact organization-policy parameter used by this rule. Values remain
    /// in signed replay material and are represented here by a digest.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub parameter_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub parameter_value_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionTrace {
    pub schema: String,
    pub stig_id: String,
    pub stig_revision: String,
    pub vuln_id: String,
    pub rule_id: String,
    pub profile_id: String,
    pub profile_sha256: String,
    pub benchmark_sha256: String,
    pub benchmark_model_sha256: String,
    pub check_pack_version: String,
    pub check_pack_sha256: String,
    pub evaluation_plan_sha256: String,
    pub collection_plan_sha256: String,
    pub evidence_envelope_sha256: String,
    pub evidence_envelope_json_sha256: String,
    pub source_artifact_sha256: Option<String>,
    pub transport_identity_sha256: String,
    pub device: DeviceFingerprint,
    pub device_fingerprint_sha256: String,
    pub adapter_contract_schema: String,
    pub adapter_contract_version: TargetAdapterContractVersion,
    pub evidence_envelope_schema: String,
    pub adapter_id: String,
    pub adapter_version: String,
    pub evaluator_id: String,
    pub evaluator_version: String,
    pub evaluator_build_sha256: String,
    pub evaluated_at: String,
    pub evaluation_origin: EvaluationOrigin,
    pub parser_id: String,
    pub parser_version: String,
    pub predicate_id: String,
    pub predicate_version: String,
    pub predicate_sha256: String,
    pub expected: DecisionValue,
    pub observed: DecisionValue,
    pub finding_status: FindingStatus,
    pub passed: bool,
    pub operations: Vec<DecisionOperationTrace>,
    pub policy: Option<DecisionPolicyBinding>,
    pub evaluation_error_class: Option<String>,
}

/// Sanitized evidence metadata captured before raw observations are passed to
/// predicates. This context is strict and digest-bound, but is not a second
/// evidence container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceTraceContext {
    pub adapter_contract_schema: String,
    pub adapter_contract_version: TargetAdapterContractVersion,
    pub evidence_envelope_schema: String,
    pub adapter_id: String,
    pub adapter_version: String,
    pub transport: TransportKind,
    pub device: DeviceFingerprint,
    pub device_fingerprint_sha256: String,
    pub evidence_envelope_sha256: String,
    pub evidence_envelope_json_sha256: String,
    pub source_artifact_sha256: Option<String>,
    pub transport_identity_sha256: String,
    pub operations: Vec<DecisionOperationTrace>,
}

impl EvidenceTraceContext {
    pub fn from_envelope(envelope: &AdapterEvidenceEnvelope) -> Result<Self, String> {
        let adapter = built_in_target_adapter(&envelope.target_key)
            .ok_or_else(|| "evidence has no release-bundled adapter".to_string())?;
        let plan = adapter
            .reconstruct_plan(&envelope.device, envelope.contract_version)
            .map_err(|error| format!("could not reconstruct trace operation plan: {error}"))?;
        if plan.plan_sha256 != envelope.plan_sha256
            || plan.adapter_id != envelope.adapter_id
            || plan.adapter_version != envelope.adapter_version
            || plan.transport != envelope.transport
        {
            return Err(
                "evidence trace context does not match the bundled operation plan".to_string(),
            );
        }
        let evidence_by_id: BTreeMap<_, _> = envelope
            .operations
            .iter()
            .map(|record| (record.operation_id.as_str(), record))
            .collect();
        let operations = plan
            .operations
            .iter()
            .map(|operation| {
                operation_trace(
                    operation,
                    envelope.transport,
                    evidence_by_id.get(operation.operation_id.as_str()).copied(),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let envelope_json = serde_json::to_vec(envelope)
            .map_err(|error| format!("failed to bind evidence envelope JSON: {error}"))?;
        let source_artifact_sha256 = match &envelope.transport_identity {
            EvidenceTransportIdentity::OfflineArtifact { sha256 } => Some(sha256.clone()),
            _ => None,
        };
        Ok(Self {
            adapter_contract_schema: plan.schema,
            adapter_contract_version: plan.contract_version,
            evidence_envelope_schema: envelope.schema.clone(),
            adapter_id: envelope.adapter_id.clone(),
            adapter_version: envelope.adapter_version.clone(),
            transport: envelope.transport,
            device: envelope.device.clone(),
            device_fingerprint_sha256: envelope.device_fingerprint_sha256.clone(),
            evidence_envelope_sha256: envelope.evidence_sha256.clone(),
            evidence_envelope_json_sha256: sha256_hex(&envelope_json),
            source_artifact_sha256,
            transport_identity_sha256: canonical_json_sha256(&envelope.transport_identity)
                .map_err(|error| format!("failed to digest transport identity: {error}"))?,
            operations,
        })
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_decision_traces(
    profile_id: &str,
    profile_sha256: &str,
    stig_id: &str,
    stig_revision: &str,
    benchmark_sha256: &str,
    benchmark_model_sha256: &str,
    check_pack_sha256: &str,
    evaluation_plan_sha256: &str,
    collection_plan_sha256: &str,
    origin: EvaluationOrigin,
    evaluated_at: &str,
    context: &EvidenceTraceContext,
    checklist: &Checklist,
    pack: &CheckPack,
    results: &[CheckResult],
    policy_provenance: Option<&OrganizationPolicyProvenance>,
    policy_material: Option<&SignedPolicyReplayMaterial>,
) -> Result<Vec<DecisionTrace>, String> {
    if pack.checks.len() != results.len() {
        return Err("decision trace inputs do not cover every automated check".to_string());
    }
    if context.evidence_envelope_sha256.is_empty()
        || context.device_fingerprint_sha256
            != context
                .device
                .sha256()
                .map_err(|error| format!("invalid decision-trace device: {error}"))?
    {
        return Err("decision trace evidence/device bindings are invalid".to_string());
    }
    let version_binding_valid = matches!(
        (
            context.adapter_contract_version,
            context.adapter_contract_schema.as_str(),
            context.evidence_envelope_schema.as_str(),
            context.device.schema.as_str(),
            context.adapter_version.as_str(),
        ),
        (
            TargetAdapterContractVersion::V1,
            TARGET_ADAPTER_CONTRACT_SCHEMA_V1,
            TARGET_ADAPTER_EVIDENCE_SCHEMA_V1,
            DEVICE_FINGERPRINT_SCHEMA_V1,
            TARGET_ADAPTER_IMPLEMENTATION_VERSION_V1,
        ) | (
            TargetAdapterContractVersion::V2,
            TARGET_ADAPTER_CONTRACT_SCHEMA_V2,
            TARGET_ADAPTER_EVIDENCE_SCHEMA_V2,
            DEVICE_FINGERPRINT_SCHEMA_V2,
            TARGET_ADAPTER_IMPLEMENTATION_VERSION_V2,
        )
    );
    if !version_binding_valid {
        return Err(
            "decision trace adapter/evidence/fingerprint versions do not match".to_string(),
        );
    }
    let build_identity = format!(
        "{EVALUATOR_ID}@{};decision-trace={DECISION_TRACE_SCHEMA};parser={PARSER_CONTRACT_VERSION}",
        env!("CARGO_PKG_VERSION")
    );
    let policy_binding = match (policy_provenance, policy_material) {
        (Some(provenance), Some(material)) => {
            if provenance.policy_sha256 != material.policy_sha256
                || provenance.signer_fingerprint != material.signer_fingerprint
                || !provenance.signature_verified
            {
                return Err("verified policy provenance and replay material differ".to_string());
            }
            Some(DecisionPolicyBinding {
                policy_id: provenance.policy_id.clone(),
                policy_version: provenance.policy_version.clone(),
                policy_sha256: provenance.policy_sha256.clone(),
                signer_fingerprint: provenance.signer_fingerprint.clone(),
                signature_sha256: material.signature_sha256.clone(),
                public_key_sha256: sha256_hex(&decode_hex(
                    &material.signer_public_key_hex,
                    Some(32),
                    "signer public key",
                )?),
                material_sha256: material.material_sha256()?,
                verified_at: material.verified_at.clone(),
                parameter_id: String::new(),
                parameter_value_sha256: String::new(),
            })
        }
        (None, None) => None,
        _ => {
            return Err(
                "policy provenance and replay material must be retained together".to_string(),
            )
        }
    };

    pack.checks
        .iter()
        .zip(results)
        .map(|(definition, result)| {
            let finding = checklist
                .find_by_vuln_id(&definition.vuln_id)
                .ok_or_else(|| {
                    format!(
                        "decision trace {} has no exact benchmark finding",
                        definition.vuln_id
                    )
                })?;
            let check_json = serde_json::to_value(&definition.check).map_err(|error| {
                format!("failed to inspect check {}: {error}", definition.vuln_id)
            })?;
            let parser_kind = check_json
                .get("type")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown");
            let expected_json = serde_json::to_value(&definition.expected).map_err(|error| {
                format!(
                    "failed to inspect expectation {}: {error}",
                    definition.vuln_id
                )
            })?;
            let predicate_kind = expected_json
                .get("type")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown");
            let (parser_id, parser_version, predicate_id, predicate_version) =
                if parser_kind == "predicate" {
                    let program = check_json
                        .get("program")
                        .unwrap_or(&serde_json::Value::Null);
                    let version = program
                        .get("schema_version")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or_default()
                        .to_string();
                    let input = program
                        .get("input")
                        .and_then(|input| input.get("type"))
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("unknown");
                    let predicate = program
                        .get("predicate")
                        .and_then(|predicate| predicate.get("op"))
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("unknown");
                    (
                        format!("automatestig.parser.predicate_{input}"),
                        version.clone(),
                        format!("automatestig.predicate.{predicate}"),
                        version,
                    )
                } else {
                    (
                        format!("automatestig.parser.{parser_kind}"),
                        PARSER_CONTRACT_VERSION.to_string(),
                        format!("automatestig.predicate.{predicate_kind}"),
                        PARSER_CONTRACT_VERSION.to_string(),
                    )
                };
            let required_keys = required_observation_keys(&check_json);
            let operations: Vec<_> = context
                .operations
                .iter()
                .filter(|operation| required_keys.contains(operation.observation_key.as_str()))
                .cloned()
                .collect();
            if operations.is_empty() {
                return Err(format!(
                    "automated rule {} has no decision-trace operation binding",
                    definition.vuln_id
                ));
            }
            let expected_descriptor = expected_descriptor(&expected_json)?;
            let observed_safe = safe_observation_descriptor(&result.actual_value);
            let status = result.to_finding_status();
            Ok(DecisionTrace {
                schema: DECISION_TRACE_SCHEMA.to_string(),
                stig_id: stig_id.to_string(),
                stig_revision: stig_revision.to_string(),
                vuln_id: definition.vuln_id.clone(),
                rule_id: finding.rule_id.clone(),
                profile_id: profile_id.to_string(),
                profile_sha256: profile_sha256.to_string(),
                benchmark_sha256: benchmark_sha256.to_string(),
                benchmark_model_sha256: benchmark_model_sha256.to_string(),
                check_pack_version: pack.version.clone(),
                check_pack_sha256: check_pack_sha256.to_string(),
                evaluation_plan_sha256: evaluation_plan_sha256.to_string(),
                collection_plan_sha256: collection_plan_sha256.to_string(),
                evidence_envelope_sha256: context.evidence_envelope_sha256.clone(),
                evidence_envelope_json_sha256: context.evidence_envelope_json_sha256.clone(),
                source_artifact_sha256: context.source_artifact_sha256.clone(),
                transport_identity_sha256: context.transport_identity_sha256.clone(),
                device: context.device.clone(),
                device_fingerprint_sha256: context.device_fingerprint_sha256.clone(),
                adapter_contract_schema: context.adapter_contract_schema.clone(),
                adapter_contract_version: context.adapter_contract_version,
                evidence_envelope_schema: context.evidence_envelope_schema.clone(),
                adapter_id: context.adapter_id.clone(),
                adapter_version: context.adapter_version.clone(),
                evaluator_id: EVALUATOR_ID.to_string(),
                evaluator_version: env!("CARGO_PKG_VERSION").to_string(),
                evaluator_build_sha256: sha256_hex(build_identity.as_bytes()),
                evaluated_at: evaluated_at.to_string(),
                evaluation_origin: origin,
                parser_id,
                parser_version,
                predicate_id,
                predicate_version,
                predicate_sha256: canonical_json_sha256(definition).map_err(|error| {
                    format!("failed to digest predicate {}: {error}", definition.vuln_id)
                })?,
                expected: DecisionValue {
                    safe_value: Some(expected_descriptor),
                    value_sha256: salted_value_sha256(
                        "expected",
                        &context.evidence_envelope_sha256,
                        &serde_json::to_string(&definition.expected)
                            .map_err(|error| error.to_string())?,
                    ),
                },
                observed: DecisionValue {
                    safe_value: observed_safe,
                    value_sha256: salted_value_sha256(
                        "observed",
                        &context.evidence_envelope_sha256,
                        &result.actual_value,
                    ),
                },
                finding_status: status,
                passed: result.passed,
                operations,
                policy: if definition.check.requires_organization_policy() {
                    Some(policy_binding_for_rule(
                        policy_binding.as_ref().ok_or_else(|| {
                            format!(
                                "rule {} requires organization policy provenance",
                                definition.vuln_id
                            )
                        })?,
                        policy_material.ok_or_else(|| {
                            format!(
                                "rule {} requires signed organization policy material",
                                definition.vuln_id
                            )
                        })?,
                        &definition.vuln_id,
                    )?)
                } else {
                    None
                },
                evaluation_error_class: result
                    .error
                    .as_ref()
                    .map(|error| safe_evaluation_error_class(error).to_string()),
            })
        })
        .collect()
}

fn operation_trace(
    operation: &ReadOnlyOperation,
    transport: TransportKind,
    record: Option<&automatestig_core::target_adapters::AdapterOperationEvidence>,
) -> Result<DecisionOperationTrace, String> {
    let request_kind = match &operation.request {
        AdapterRequest::SshCli { .. } => "ssh_cli",
        AdapterRequest::OfflineConfiguration { .. } => "offline_configuration",
        AdapterRequest::NetconfRpc { .. } => "netconf_rpc",
        AdapterRequest::RestconfGet { .. } => "restconf_get",
        AdapterRequest::HttpsApiGet { .. } => "https_api_get",
    };
    let request_sha256 = canonical_json_sha256(&operation.request)
        .map_err(|error| format!("failed to digest operation request: {error}"))?;
    let (
        duration_ms,
        status,
        status_code,
        truncated,
        observation_sha256,
        diagnostics_present,
        error_present,
        error_class,
    ) = match record {
        Some(record) => (
            Some(record.duration_ms),
            record.status.into(),
            record.status_code,
            record.truncated,
            record.response_sha256.clone(),
            !record.diagnostics.is_empty(),
            record.error.is_some(),
            record
                .error
                .as_ref()
                .map(|_| operation_error_class(record.status, record.truncated).to_string()),
        ),
        None => (
            None,
            DecisionOperationStatus::Missing,
            None,
            false,
            None,
            false,
            true,
            Some("missing_evidence".to_string()),
        ),
    };
    Ok(DecisionOperationTrace {
        operation_id: operation.operation_id.clone(),
        observation_key: operation.data_key.clone(),
        request_kind: request_kind.to_string(),
        request: request_descriptor(&operation.request)?,
        request_sha256,
        transport,
        privilege: operation.privilege,
        estimated_duration_ms: operation.estimated_duration_ms,
        maximum_duration_ms: operation.maximum_duration_ms,
        duration_ms,
        status,
        status_code,
        truncated,
        observation_sha256,
        diagnostics_present,
        error_present,
        error_class,
    })
}

fn required_observation_keys(check: &serde_json::Value) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    collect_observation_keys(check, &mut keys);
    keys
}

fn collect_observation_keys(value: &serde_json::Value, keys: &mut BTreeSet<String>) {
    let Some(object) = value.as_object() else {
        return;
    };
    match object.get("type").and_then(serde_json::Value::as_str) {
        Some("command") => {
            if let Some(command) = object.get("command").and_then(serde_json::Value::as_str) {
                keys.insert(command.to_string());
            }
        }
        Some("all" | "any") => {
            if let Some(checks) = object.get("checks").and_then(serde_json::Value::as_array) {
                for check in checks {
                    collect_observation_keys(check, keys);
                }
            }
        }
        Some("bsd_audit_class_selection") => {
            for key in [
                "service auditd onestatus",
                "cat /etc/security/audit_control",
                "cat /etc/security/audit_user",
                "sha256 -q /etc/security/audit_class",
                "sha256 -q /etc/security/audit_event",
            ] {
                keys.insert(key.to_string());
            }
        }
        Some("bsd_pf_enabled") => {
            keys.insert("service pf onestatus".to_string());
        }
        Some("predicate") => {
            if contains_network_config_source(value) {
                keys.insert("running_config".to_string());
            }
            collect_named_observation_keys(value, keys);
        }
        Some(_) | None => {
            // Typed Cisco and legacy ConfigLine checks consume the one complete
            // redacted running configuration.
            keys.insert("running_config".to_string());
        }
    }
}

fn contains_network_config_source(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(value) => value == "network_config",
        serde_json::Value::Array(values) => values.iter().any(contains_network_config_source),
        serde_json::Value::Object(values) => values.values().any(contains_network_config_source),
        _ => false,
    }
}

fn collect_named_observation_keys(value: &serde_json::Value, keys: &mut BTreeSet<String>) {
    match value {
        serde_json::Value::Array(values) => {
            for value in values {
                collect_named_observation_keys(value, keys);
            }
        }
        serde_json::Value::Object(values) => {
            if values.get("type").and_then(serde_json::Value::as_str) == Some("observation") {
                if let Some(key) = values.get("key").and_then(serde_json::Value::as_str) {
                    keys.insert(key.to_string());
                }
            }
            for value in values.values() {
                collect_named_observation_keys(value, keys);
            }
        }
        _ => {}
    }
}

fn expected_descriptor(expected: &serde_json::Value) -> Result<String, String> {
    let descriptor = serde_json::to_string(expected)
        .map_err(|error| format!("failed to serialize exact decision expectation: {error}"))?;
    if descriptor.is_empty() || descriptor.len() > 8 * 1024 {
        return Err("decision expectation exceeds the safe trace bound".to_string());
    }
    Ok(descriptor)
}

fn safe_observation_descriptor(value: &str) -> Option<String> {
    let value = value.trim();
    // Only closed boolean vocabulary is intrinsically safe without knowing
    // the target field's sensitivity. Numeric strings can be PINs, tokens, or
    // other low-entropy secrets and therefore remain digest-only.
    if matches!(value, "true" | "false" | "yes" | "no") {
        Some(value.to_string())
    } else if value.starts_with("compliant:") {
        Some("compliant".to_string())
    } else if value.starts_with("finding:") {
        Some("finding".to_string())
    } else if value.starts_with("not_applicable:") {
        Some("not_applicable".to_string())
    } else {
        None
    }
}

fn request_descriptor(request: &AdapterRequest) -> Result<String, String> {
    let descriptor = match request {
        AdapterRequest::SshCli { command } => command,
        AdapterRequest::OfflineConfiguration { document_kind } => document_kind,
        AdapterRequest::NetconfRpc { rpc } => rpc,
        AdapterRequest::RestconfGet { path } | AdapterRequest::HttpsApiGet { path } => path,
    }
    .trim();
    if descriptor.is_empty()
        || descriptor.len() > 8 * 1024
        || descriptor.chars().any(|character| character == '\0')
    {
        return Err(
            "release-reviewed operation request is not safe to retain in a trace".to_string(),
        );
    }
    Ok(descriptor.to_string())
}

fn policy_binding_for_rule(
    base: &DecisionPolicyBinding,
    material: &SignedPolicyReplayMaterial,
    vuln_id: &str,
) -> Result<DecisionPolicyBinding, String> {
    let parameter_id = match vuln_id {
        "V-215807" => "max_concurrent_management_sessions",
        "V-215836" => "minimum_logging_buffer_bytes",
        "V-215838" => "approved_authoritative_ntp_sources",
        _ => {
            return Err(format!(
                "rule {vuln_id} has no reviewed organization-policy parameter binding"
            ))
        }
    };
    let raw = decode_hex(&material.policy_bytes_hex, None, "policy_bytes_hex")?;
    let document: serde_json::Value = serde_json::from_slice(&raw)
        .map_err(|error| format!("signed organization policy is invalid JSON: {error}"))?;
    let value = document
        .get("rules")
        .and_then(|rules| rules.get(vuln_id))
        .and_then(|rule| rule.get(parameter_id))
        .ok_or_else(|| format!("signed organization policy omits {vuln_id}.{parameter_id}"))?;
    let mut binding = base.clone();
    binding.parameter_id = parameter_id.to_string();
    binding.parameter_value_sha256 = canonical_json_sha256(value).map_err(|error| {
        format!("failed to digest policy parameter {vuln_id}.{parameter_id}: {error}")
    })?;
    Ok(binding)
}

fn operation_error_class(status: AdapterOperationStatus, truncated: bool) -> &'static str {
    if truncated {
        return "truncated";
    }
    match status {
        AdapterOperationStatus::Success => "semantic_error",
        AdapterOperationStatus::PermissionDenied => "permission_denied",
        AdapterOperationStatus::AuthenticationFailed => "authentication_failed",
        AdapterOperationStatus::Timeout => "timeout",
        AdapterOperationStatus::TransportError => "transport_error",
        AdapterOperationStatus::ProtocolError => "protocol_error",
        AdapterOperationStatus::ResponseLimit => "response_limit",
        AdapterOperationStatus::SemanticError => "semantic_error",
    }
}

fn safe_evaluation_error_class(error: &str) -> &'static str {
    let lower = error.to_ascii_lowercase();
    if lower.contains("policy") {
        "policy_unavailable"
    } else if lower.contains("missing") || lower.contains("not found") || lower.contains("no ") {
        "observation_unavailable"
    } else if lower.contains("regex") || lower.contains("parse") || lower.contains("malformed") {
        "parser_error"
    } else {
        "evaluation_error"
    }
}

fn salted_value_sha256(domain: &str, evidence_sha256: &str, value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"AUTOMATESTIG-DECISION-TRACE-VALUE-V1\0");
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    hasher.update(evidence_sha256.as_bytes());
    hasher.update([0]);
    hasher.update(value.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn decode_hex(value: &str, expected_len: Option<usize>, label: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{label} must be lowercase hexadecimal"));
    }
    let bytes = value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).expect("hexadecimal is ASCII");
            u8::from_str_radix(text, 16).expect("hexadecimal pair was validated")
        })
        .collect::<Vec<_>>();
    if expected_len.is_some_and(|expected| bytes.len() != expected) {
        return Err(format!("{label} has the wrong byte length"));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn safe_observation_descriptor_never_copies_complex_observations() {
        assert_eq!(
            safe_observation_descriptor("true"),
            Some("true".to_string())
        );
        assert_eq!(
            safe_observation_descriptor("compliant: target details"),
            Some("compliant".to_string())
        );
        assert_eq!(safe_observation_descriptor("4096000"), None);
        assert_eq!(safe_observation_descriptor("123456"), None);
        assert_eq!(
            safe_observation_descriptor("username admin secret value"),
            None
        );
        assert_eq!(safe_observation_descriptor("192.0.2.1"), None);
    }

    #[test]
    fn hex_decoder_is_strict_and_bounded() {
        assert_eq!(decode_hex("00ff", Some(2), "test").unwrap(), [0, 255]);
        assert!(decode_hex("00FF", Some(2), "test").is_err());
        assert!(decode_hex("00", Some(2), "test").is_err());
    }

    #[test]
    fn signed_policy_material_replays_with_public_key_and_rejects_tampering() {
        let raw = br#"{"schema":"automatestig-organization-policy/v1","policy_id":"replay-test","policy_version":"1","stig_id":"Cisco_IOS-XE_Router_NDM_STIG","stig_release":"V3R7","asset_hostname":"router-01","effective_from":"2026-01-01T00:00:00Z","expires_at":"2027-01-01T00:00:00Z","rules":{"V-215807":{"max_concurrent_management_sessions":2},"V-215838":{"approved_authoritative_ntp_sources":["192.0.2.10","192.0.2.11"]},"V-215836":{"minimum_logging_buffer_bytes":4096000}}}"#;
        let signing_key = SigningKey::from_bytes(&[9; 32]);
        let signature = signing_key.sign(&Sha256::digest(raw)).to_bytes();
        let public_key = signing_key.verifying_key().to_bytes();
        let verified = VerifiedOrganizationPolicy::verify_and_parse(
            raw,
            &signature,
            &[public_key],
            "Cisco_IOS-XE_Router_NDM_STIG",
            "V3R7",
            "router-01",
            DateTime::parse_from_rfc3339("2026-08-11T12:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        )
        .unwrap();
        let material = SignedPolicyReplayMaterial::from_verified(&verified);
        assert_eq!(
            material
                .verify_for_replay("Cisco_IOS-XE_Router_NDM_STIG", "V3R7", "router-01")
                .unwrap(),
            verified
        );

        let mut tampered = material;
        tampered.detached_signature_hex.replace_range(0..2, "00");
        assert!(tampered
            .verify_for_replay("Cisco_IOS-XE_Router_NDM_STIG", "V3R7", "router-01")
            .is_err());
    }
}
