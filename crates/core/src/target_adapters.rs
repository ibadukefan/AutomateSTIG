//! Versioned, replayable target-adapter contracts.
//!
//! Adapters in this module describe read-only work; they do not execute shell
//! commands or perform network I/O. ONTAP and FreeBSD bridge the reviewed SSH
//! collection plans in [`crate::remote`]. IOS-XE bridges the existing strict
//! offline running-configuration validator. Evidence is accepted only when it
//! remains bound to the exact adapter, target profile, device fingerprint,
//! operation plan, requests, and content digests used to create it.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::check_packs::{canonical_json_sha256, embedded_check_pack_bytes, validate_pack};
use crate::checks::{CheckPack, CheckPlatform, SystemData};
use crate::remote::{
    assemble_evidence_system_data, cisco_config_hostname, generate_collection_plan,
    is_openssh_sha256_fingerprint, CollectionCommand, CollectionPlan, CommandEvidence,
    CommandStatus, OutputPolicy,
};
use crate::scanner_profiles::{bundled_scanner_profile, ScannerProfile, ScannerProfileReadiness};

pub const TARGET_ADAPTER_CONTRACT_SCHEMA: &str = "automatestig-target-adapter/v1";
pub const TARGET_ADAPTER_EVIDENCE_SCHEMA: &str = "automatestig-adapter-evidence/v1";
pub const NORMALIZED_OBSERVATIONS_SCHEMA: &str = "automatestig-observations/v1";

const ADAPTER_IMPLEMENTATION_VERSION: &str = "1.0.0";
const OFFLINE_RUNNING_CONFIG_REQUEST: &str = "cisco_ios_xe_complete_running_configuration";
const ENVELOPE_ERROR_KEY: &str = "__adapter_envelope__";

pub type AdapterResult<T> = std::result::Result<T, TargetAdapterError>;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TargetAdapterError {
    #[error("unsupported device for {target_key}: {reason}")]
    UnsupportedDevice { target_key: String, reason: String },
    #[error("invalid device fingerprint: {0}")]
    InvalidFingerprint(String),
    #[error("invalid adapter contract: {0}")]
    InvalidContract(String),
    #[error("invalid adapter evidence: {0}")]
    InvalidEvidence(String),
    #[error("adapter evidence integrity failure: {0}")]
    Integrity(String),
    #[error("target adapter internal error: {0}")]
    Internal(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetAdapterContractVersion {
    V1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportKind {
    SshCli,
    OfflineConfig,
    Netconf,
    Restconf,
    HttpsApi,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceFingerprint {
    pub hostname: String,
    pub vendor: String,
    pub product_family: String,
    pub software_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial_number: Option<String>,
}

impl DeviceFingerprint {
    pub fn new(
        hostname: impl Into<String>,
        vendor: impl Into<String>,
        product_family: impl Into<String>,
        software_version: impl Into<String>,
    ) -> Self {
        Self {
            hostname: hostname.into(),
            vendor: vendor.into(),
            product_family: product_family.into(),
            software_version: software_version.into(),
            model: None,
            serial_number: None,
        }
    }

    pub fn sha256(&self) -> AdapterResult<String> {
        validate_fingerprint_fields(self)?;
        canonical_json_sha256(self).map_err(internal_error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SoftwareVersionConstraint {
    /// The first numeric component must equal `major`.
    Major { major: u32 },
    /// The first numeric component must be inside this inclusive range.
    MajorRange { minimum: u32, maximum: u32 },
    /// The adapter requires an observed version but has no narrower release
    /// claim until live acceptance establishes one.
    AnyNonEmpty,
}

impl SoftwareVersionConstraint {
    pub fn supports(&self, version: &str) -> bool {
        let version = version.trim();
        match self {
            Self::Major { major } => leading_major(version) == Some(*major),
            Self::MajorRange { minimum, maximum } => {
                leading_major(version).is_some_and(|major| (*minimum..=*maximum).contains(&major))
            }
            Self::AnyNonEmpty => !version.is_empty() && !version.chars().any(char::is_control),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityMatrix {
    pub target_key: String,
    pub vendor: String,
    pub product_family: String,
    pub software_version: SoftwareVersionConstraint,
    /// Populated only by release acceptance evidence. Empty does not imply
    /// broad testing; profile readiness remains authoritative.
    #[serde(default)]
    pub accepted_tested_versions: Vec<String>,
}

impl CompatibilityMatrix {
    pub fn validate(&self, fingerprint: &DeviceFingerprint) -> AdapterResult<()> {
        validate_fingerprint_fields(fingerprint)?;
        if !fingerprint.vendor.trim().eq_ignore_ascii_case(&self.vendor) {
            return Err(TargetAdapterError::UnsupportedDevice {
                target_key: self.target_key.clone(),
                reason: format!(
                    "vendor '{}' does not match '{}'",
                    fingerprint.vendor, self.vendor
                ),
            });
        }
        if !fingerprint
            .product_family
            .trim()
            .eq_ignore_ascii_case(&self.product_family)
        {
            return Err(TargetAdapterError::UnsupportedDevice {
                target_key: self.target_key.clone(),
                reason: format!(
                    "product family '{}' does not match '{}'",
                    fingerprint.product_family, self.product_family
                ),
            });
        }
        if !self
            .software_version
            .supports(&fingerprint.software_version)
        {
            return Err(TargetAdapterError::UnsupportedDevice {
                target_key: self.target_key.clone(),
                reason: format!(
                    "software version '{}' is outside {:?}",
                    fingerprint.software_version, self.software_version
                ),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AdapterRequest {
    SshCli { command: String },
    OfflineConfiguration { document_kind: String },
    NetconfRpc { rpc: String },
    RestconfGet { path: String },
    HttpsApiGet { path: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterPrivilege {
    ReadOnly,
    AdvancedReadOnly,
    OperatorProvidedArtifact,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadOnlyOperation {
    pub operation_id: String,
    pub data_key: String,
    pub request: AdapterRequest,
    pub privilege: AdapterPrivilege,
    pub accepted_status_codes: Vec<u32>,
    pub output_policy: OutputPolicy,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadOnlyOperationPlan {
    pub schema: String,
    pub contract_version: TargetAdapterContractVersion,
    pub adapter_id: String,
    pub adapter_version: String,
    pub target_key: String,
    pub transport: TransportKind,
    pub read_only: bool,
    pub device_fingerprint_sha256: String,
    pub profile_sha256: String,
    pub check_pack_sha256: String,
    pub legacy_collection_plan_sha256: String,
    pub operations: Vec<ReadOnlyOperation>,
    pub plan_sha256: String,
}

#[derive(Serialize)]
struct PlanDigestBinding<'a> {
    schema: &'a str,
    contract_version: TargetAdapterContractVersion,
    adapter_id: &'a str,
    adapter_version: &'a str,
    target_key: &'a str,
    transport: TransportKind,
    read_only: bool,
    device_fingerprint_sha256: &'a str,
    profile_sha256: &'a str,
    check_pack_sha256: &'a str,
    legacy_collection_plan_sha256: &'a str,
    operations: &'a [ReadOnlyOperation],
}

impl ReadOnlyOperationPlan {
    fn compute_sha256(&self) -> AdapterResult<String> {
        canonical_json_sha256(&PlanDigestBinding {
            schema: &self.schema,
            contract_version: self.contract_version,
            adapter_id: &self.adapter_id,
            adapter_version: &self.adapter_version,
            target_key: &self.target_key,
            transport: self.transport,
            read_only: self.read_only,
            device_fingerprint_sha256: &self.device_fingerprint_sha256,
            profile_sha256: &self.profile_sha256,
            check_pack_sha256: &self.check_pack_sha256,
            legacy_collection_plan_sha256: &self.legacy_collection_plan_sha256,
            operations: &self.operations,
        })
        .map_err(internal_error)
    }

    pub fn validate_digest(&self) -> AdapterResult<()> {
        validate_lowercase_sha256("plan_sha256", &self.plan_sha256)?;
        let actual = self.compute_sha256()?;
        if self.plan_sha256 != actual {
            return Err(TargetAdapterError::Integrity(format!(
                "operation-plan digest mismatch: expected {}, got {}",
                self.plan_sha256, actual
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetAdapterDescriptor {
    pub schema: String,
    pub contract_version: TargetAdapterContractVersion,
    pub adapter_id: String,
    pub adapter_version: String,
    pub target_key: String,
    pub display_name: String,
    pub platform: CheckPlatform,
    pub transport: TransportKind,
    pub readiness: ScannerProfileReadiness,
    pub profile_sha256: String,
    pub check_pack_sha256: String,
    pub compatibility: CompatibilityMatrix,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuiltInTargetAdapter {
    NetAppOntap9,
    FreeBsdGpos,
    CiscoIosXeRouterNdm,
}

const BUILT_IN_ADAPTERS: [BuiltInTargetAdapter; 3] = [
    BuiltInTargetAdapter::NetAppOntap9,
    BuiltInTargetAdapter::FreeBsdGpos,
    BuiltInTargetAdapter::CiscoIosXeRouterNdm,
];

pub fn built_in_target_adapters() -> &'static [BuiltInTargetAdapter] {
    &BUILT_IN_ADAPTERS
}

pub fn built_in_target_adapter(target_key: &str) -> Option<BuiltInTargetAdapter> {
    BUILT_IN_ADAPTERS
        .iter()
        .copied()
        .find(|adapter| adapter.target_key() == target_key)
}

impl BuiltInTargetAdapter {
    pub const fn target_key(self) -> &'static str {
        match self {
            Self::NetAppOntap9 => "netapp_ontap9",
            Self::FreeBsdGpos => "freebsd_gpos",
            Self::CiscoIosXeRouterNdm => "cisco_ios_xe_router_ndm",
        }
    }

    pub const fn adapter_id(self) -> &'static str {
        match self {
            Self::NetAppOntap9 => "automatestig.netapp_ontap9.ssh_cli",
            Self::FreeBsdGpos => "automatestig.freebsd_gpos.ssh_cli",
            Self::CiscoIosXeRouterNdm => "automatestig.cisco_ios_xe_router_ndm.offline_config",
        }
    }

    pub const fn transport(self) -> TransportKind {
        match self {
            Self::NetAppOntap9 | Self::FreeBsdGpos => TransportKind::SshCli,
            Self::CiscoIosXeRouterNdm => TransportKind::OfflineConfig,
        }
    }

    pub fn compatibility(self) -> CompatibilityMatrix {
        // These are the deliberately narrow software-version grammars for the
        // v0.3 collectors. They do not claim live-device acceptance; that is
        // represented separately by `accepted_tested_versions` and profile
        // readiness, both of which remain unpromoted for this release.
        match self {
            Self::NetAppOntap9 => CompatibilityMatrix {
                target_key: self.target_key().to_string(),
                vendor: "NetApp".to_string(),
                product_family: "ONTAP".to_string(),
                software_version: SoftwareVersionConstraint::Major { major: 9 },
                accepted_tested_versions: Vec::new(),
            },
            Self::FreeBsdGpos => CompatibilityMatrix {
                target_key: self.target_key().to_string(),
                vendor: "FreeBSD".to_string(),
                product_family: "FreeBSD".to_string(),
                software_version: SoftwareVersionConstraint::MajorRange {
                    minimum: 13,
                    maximum: 14,
                },
                accepted_tested_versions: Vec::new(),
            },
            Self::CiscoIosXeRouterNdm => CompatibilityMatrix {
                target_key: self.target_key().to_string(),
                vendor: "Cisco".to_string(),
                product_family: "IOS-XE".to_string(),
                software_version: SoftwareVersionConstraint::Major { major: 17 },
                accepted_tested_versions: Vec::new(),
            },
        }
    }

    pub fn descriptor(self) -> AdapterResult<TargetAdapterDescriptor> {
        let profile = self.profile()?;
        Ok(TargetAdapterDescriptor {
            schema: TARGET_ADAPTER_CONTRACT_SCHEMA.to_string(),
            contract_version: TargetAdapterContractVersion::V1,
            adapter_id: self.adapter_id().to_string(),
            adapter_version: ADAPTER_IMPLEMENTATION_VERSION.to_string(),
            target_key: self.target_key().to_string(),
            display_name: profile.display_name().to_string(),
            platform: profile.platform(),
            transport: self.transport(),
            readiness: profile.readiness(),
            profile_sha256: profile.digests().profile_sha256().to_string(),
            check_pack_sha256: profile.digests().check_pack_sha256().to_string(),
            compatibility: self.compatibility(),
        })
    }

    pub fn preview(self, fingerprint: &DeviceFingerprint) -> AdapterResult<ReadOnlyOperationPlan> {
        self.compatibility().validate(fingerprint)?;
        let profile = self.profile()?;
        let collection_plan = self.collection_plan(profile)?;
        let operations = collection_plan
            .commands
            .iter()
            .map(|command| self.operation(command))
            .collect::<Vec<_>>();
        if operations.is_empty() {
            return Err(TargetAdapterError::InvalidContract(format!(
                "{} produced no read-only operations",
                self.target_key()
            )));
        }

        let mut plan = ReadOnlyOperationPlan {
            schema: TARGET_ADAPTER_CONTRACT_SCHEMA.to_string(),
            contract_version: TargetAdapterContractVersion::V1,
            adapter_id: self.adapter_id().to_string(),
            adapter_version: ADAPTER_IMPLEMENTATION_VERSION.to_string(),
            target_key: self.target_key().to_string(),
            transport: self.transport(),
            read_only: true,
            device_fingerprint_sha256: fingerprint.sha256()?,
            profile_sha256: profile.digests().profile_sha256().to_string(),
            check_pack_sha256: profile.digests().check_pack_sha256().to_string(),
            legacy_collection_plan_sha256: collection_plan.digest(),
            operations,
            plan_sha256: String::new(),
        };
        plan.plan_sha256 = plan.compute_sha256()?;
        Ok(plan)
    }

    pub fn replay(self, envelope: &AdapterEvidenceEnvelope) -> AdapterResult<AdapterReplay> {
        validate_envelope_header(self, envelope)?;
        let expected_plan = self.preview(&envelope.device)?;
        validate_envelope_bindings(&expected_plan, envelope)?;
        validate_transport_identity(envelope.transport, &envelope.transport_identity)?;
        validate_envelope_digest(envelope)?;

        let profile = self.profile()?;
        let collection_plan = self.collection_plan(profile)?;
        let evidence_by_operation = validate_operation_set(&expected_plan, envelope)?;
        let mut command_evidence = Vec::with_capacity(expected_plan.operations.len());
        let mut explicit_error_kinds = HashMap::new();

        for operation in &expected_plan.operations {
            let Some(record) = evidence_by_operation.get(operation.operation_id.as_str()) else {
                explicit_error_kinds.insert(
                    operation.data_key.clone(),
                    AdapterCollectionErrorKind::MissingEvidence,
                );
                continue;
            };
            validate_record_digest(record)?;
            if record.request != operation.request {
                return Err(TargetAdapterError::InvalidEvidence(format!(
                    "operation {} request does not match the read-only plan",
                    operation.operation_id
                )));
            }

            let response_redacted = record
                .redactions
                .iter()
                .any(|redaction| redaction.field == EvidenceRedactionField::Response);
            let failure = record_failure(record, operation, response_redacted);
            match failure {
                Some((kind, message)) => {
                    explicit_error_kinds.insert(operation.data_key.clone(), kind);
                    command_evidence.push(CommandEvidence::failed(
                        operation.data_key.clone(),
                        legacy_command_text(&operation.request),
                        command_status(record.status, record.truncated),
                        message,
                    ));
                }
                None => {
                    command_evidence.push(CommandEvidence::success(
                        operation.data_key.clone(),
                        legacy_command_text(&operation.request),
                        record.response.clone().unwrap_or_default(),
                        record.diagnostics.clone(),
                        record
                            .status_code
                            .expect("validated successful status code"),
                        record.duration_ms,
                    ));
                }
            }
        }

        let mut system_data = assemble_evidence_system_data(&collection_plan, &command_evidence);
        if self == Self::CiscoIosXeRouterNdm {
            bind_cisco_offline_identity(&envelope.device, &mut system_data)?;
            validate_offline_artifact_identity(envelope, &expected_plan)?;
        }

        if !envelope.complete && system_data.collection_errors.is_empty() {
            system_data.collection_errors.insert(
                ENVELOPE_ERROR_KEY.to_string(),
                "collector marked the evidence envelope incomplete".to_string(),
            );
            system_data.collection_complete = false;
            explicit_error_kinds.insert(
                ENVELOPE_ERROR_KEY.to_string(),
                AdapterCollectionErrorKind::EnvelopeIncomplete,
            );
        }

        let errors = normalized_collection_errors(&system_data, &explicit_error_kinds);
        let complete = envelope.complete && system_data.collection_complete && errors.is_empty();
        system_data.collection_complete = complete;
        let observations = normalized_observations(
            self,
            envelope,
            &system_data,
            &evidence_by_operation,
            CollectionCompleteness {
                complete,
                errors: errors.clone(),
            },
        )?;
        let replay_sha256 = canonical_json_sha256(&ReplayDigestBinding {
            observations: &observations,
            system_data: &system_data,
        })
        .map_err(internal_error)?;

        Ok(AdapterReplay {
            observations,
            system_data,
            completeness: CollectionCompleteness { complete, errors },
            replay_sha256,
        })
    }

    fn profile(self) -> AdapterResult<&'static ScannerProfile> {
        bundled_scanner_profile(self.target_key())
            .map_err(internal_error)?
            .ok_or_else(|| {
                TargetAdapterError::InvalidContract(format!(
                    "missing bundled scanner profile {}",
                    self.target_key()
                ))
            })
    }

    fn check_pack(self, profile: &ScannerProfile) -> AdapterResult<CheckPack> {
        let relative = profile
            .check_pack_path()
            .strip_prefix("content/check_packs/")
            .filter(|path| !path.contains('/') && !path.contains('\\'))
            .ok_or_else(|| {
                TargetAdapterError::InvalidContract(format!(
                    "unsafe bundled check-pack path {}",
                    profile.check_pack_path()
                ))
            })?;
        let bytes = embedded_check_pack_bytes(relative).ok_or_else(|| {
            TargetAdapterError::InvalidContract(format!(
                "embedded check pack {} is missing",
                profile.check_pack_path()
            ))
        })?;
        let mut pack: CheckPack = serde_json::from_slice(&bytes)
            .map_err(|error| TargetAdapterError::Internal(error.to_string()))?;
        validate_pack(&pack).map_err(internal_error)?;
        pack.priority = 0;
        Ok(pack)
    }

    fn collection_plan(self, profile: &ScannerProfile) -> AdapterResult<CollectionPlan> {
        let pack = self.check_pack(profile)?;
        if self == Self::CiscoIosXeRouterNdm {
            let check_definitions_sha256 = format!(
                "{:x}",
                Sha256::digest(
                    serde_json::to_vec(&pack.checks)
                        .map_err(|error| TargetAdapterError::Internal(error.to_string()))?
                )
            );
            return Ok(CollectionPlan {
                platform: CheckPlatform::CiscoIos,
                commands: vec![CollectionCommand {
                    command: OFFLINE_RUNNING_CONFIG_REQUEST.to_string(),
                    data_key: "running_config".to_string(),
                    accepted_exit_codes: vec![0],
                    output_policy: OutputPolicy::Any,
                }],
                check_definitions_sha256,
            });
        }
        generate_collection_plan(pack.platform, &pack.checks)
            .map_err(TargetAdapterError::InvalidContract)
    }

    fn operation(self, command: &CollectionCommand) -> ReadOnlyOperation {
        let (request, privilege, description) = match self.transport() {
            TransportKind::SshCli => {
                let advanced = command.command.starts_with("set -privilege advanced ");
                (
                    AdapterRequest::SshCli {
                        command: command.command.clone(),
                    },
                    if advanced {
                        AdapterPrivilege::AdvancedReadOnly
                    } else {
                        AdapterPrivilege::ReadOnly
                    },
                    format!(
                        "Collect reviewed read-only observation '{}'",
                        command.data_key
                    ),
                )
            }
            TransportKind::OfflineConfig => (
                AdapterRequest::OfflineConfiguration {
                    document_kind: OFFLINE_RUNNING_CONFIG_REQUEST.to_string(),
                },
                AdapterPrivilege::OperatorProvidedArtifact,
                "Read a complete operator-provided IOS-XE running configuration".to_string(),
            ),
            _ => unreachable!("built-in adapters currently use SSH CLI or offline config"),
        };
        ReadOnlyOperation {
            operation_id: command.data_key.clone(),
            data_key: command.data_key.clone(),
            request,
            privilege,
            accepted_status_codes: command.accepted_exit_codes.clone(),
            output_policy: command.output_policy,
            description,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EvidenceTransportIdentity {
    SshHostKey { fingerprint: String },
    OfflineArtifact { sha256: String },
    TlsCertificate { sha256: String },
}

impl EvidenceTransportIdentity {
    pub fn offline_artifact(bytes: &[u8]) -> Self {
        Self::OfflineArtifact {
            sha256: sha256_bytes(bytes),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterOperationStatus {
    Success,
    PermissionDenied,
    AuthenticationFailed,
    Timeout,
    TransportError,
    ProtocolError,
    ResponseLimit,
    SemanticError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceRedactionField {
    Response,
    /// A secret token was removed from an otherwise replayable response.
    ///
    /// Unlike `Response`, this does not make the observation incomplete: the
    /// redaction is deliberately limited to values which scanner predicates
    /// do not consume. The original whole-artifact digest remains the source
    /// binding; individual secret values are never hashed into the manifest,
    /// because low-entropy credential hashes would be dictionary-testable.
    ResponseSecret,
    Diagnostics,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRedaction {
    pub field: EvidenceRedactionField,
    pub reason: String,
    pub removed_sha256: String,
}

impl EvidenceRedaction {
    pub fn new(field: EvidenceRedactionField, reason: impl Into<String>, removed: &[u8]) -> Self {
        Self {
            field,
            reason: reason.into(),
            removed_sha256: sha256_bytes(removed),
        }
    }

    fn response_secret(reason: impl Into<String>) -> Self {
        Self {
            field: EvidenceRedactionField::ResponseSecret,
            reason: reason.into(),
            // Preserve the v1 wire field without creating a password oracle.
            // The envelope's OfflineArtifact digest binds the complete source;
            // this digest binds only the fixed structural placeholder.
            removed_sha256: sha256_bytes(b"__AUTOMATESTIG_SECRET_REMOVED__"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterOperationEvidence {
    pub operation_id: String,
    pub request: AdapterRequest,
    pub status: AdapterOperationStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<String>,
    #[serde(default)]
    pub diagnostics: String,
    pub duration_ms: u64,
    pub truncated: bool,
    #[serde(default)]
    pub redactions: Vec<EvidenceRedaction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl AdapterOperationEvidence {
    pub fn success(
        operation: &ReadOnlyOperation,
        response: impl Into<String>,
        duration_ms: u64,
    ) -> Self {
        let response = response.into();
        Self {
            operation_id: operation.operation_id.clone(),
            request: operation.request.clone(),
            status: AdapterOperationStatus::Success,
            status_code: operation.accepted_status_codes.first().copied(),
            response_sha256: Some(sha256_bytes(response.as_bytes())),
            response: Some(response),
            diagnostics: String::new(),
            duration_ms,
            truncated: false,
            redactions: Vec::new(),
            error: None,
        }
    }

    pub fn failed(
        operation: &ReadOnlyOperation,
        status: AdapterOperationStatus,
        error: impl Into<String>,
        duration_ms: u64,
    ) -> AdapterResult<Self> {
        if status == AdapterOperationStatus::Success {
            return Err(TargetAdapterError::InvalidEvidence(
                "failed operation evidence cannot use success status".to_string(),
            ));
        }
        Ok(Self {
            operation_id: operation.operation_id.clone(),
            request: operation.request.clone(),
            status,
            status_code: None,
            response: None,
            diagnostics: String::new(),
            duration_ms,
            truncated: false,
            redactions: Vec::new(),
            response_sha256: None,
            error: Some(error.into()),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterEvidenceEnvelope {
    pub schema: String,
    pub contract_version: TargetAdapterContractVersion,
    pub adapter_id: String,
    pub adapter_version: String,
    pub target_key: String,
    pub transport: TransportKind,
    pub device: DeviceFingerprint,
    pub device_fingerprint_sha256: String,
    pub transport_identity: EvidenceTransportIdentity,
    pub collected_at: String,
    pub profile_sha256: String,
    pub check_pack_sha256: String,
    pub plan_sha256: String,
    pub complete: bool,
    pub operations: Vec<AdapterOperationEvidence>,
    pub evidence_sha256: String,
}

#[derive(Serialize)]
struct EvidenceDigestBinding<'a> {
    schema: &'a str,
    contract_version: TargetAdapterContractVersion,
    adapter_id: &'a str,
    adapter_version: &'a str,
    target_key: &'a str,
    transport: TransportKind,
    device: &'a DeviceFingerprint,
    device_fingerprint_sha256: &'a str,
    transport_identity: &'a EvidenceTransportIdentity,
    collected_at: &'a str,
    profile_sha256: &'a str,
    check_pack_sha256: &'a str,
    plan_sha256: &'a str,
    complete: bool,
    operations: &'a [AdapterOperationEvidence],
}

impl AdapterEvidenceEnvelope {
    pub fn seal(
        plan: &ReadOnlyOperationPlan,
        device: DeviceFingerprint,
        transport_identity: EvidenceTransportIdentity,
        collected_at: DateTime<Utc>,
        operations: Vec<AdapterOperationEvidence>,
    ) -> AdapterResult<Self> {
        plan.validate_digest()?;
        let fingerprint_sha256 = device.sha256()?;
        if fingerprint_sha256 != plan.device_fingerprint_sha256 {
            return Err(TargetAdapterError::InvalidEvidence(
                "device fingerprint does not match the operation plan".to_string(),
            ));
        }
        validate_transport_identity(plan.transport, &transport_identity)?;
        validate_evidence_records_for_seal(plan, &operations)?;
        let complete = plan.operations.len() == operations.len()
            && plan.operations.iter().all(|operation| {
                operations
                    .iter()
                    .find(|record| record.operation_id == operation.operation_id)
                    .is_some_and(|record| record_is_complete(record, operation))
            });
        let mut envelope = Self {
            schema: TARGET_ADAPTER_EVIDENCE_SCHEMA.to_string(),
            contract_version: plan.contract_version,
            adapter_id: plan.adapter_id.clone(),
            adapter_version: plan.adapter_version.clone(),
            target_key: plan.target_key.clone(),
            transport: plan.transport,
            device,
            device_fingerprint_sha256: fingerprint_sha256,
            transport_identity,
            collected_at: collected_at.to_rfc3339(),
            profile_sha256: plan.profile_sha256.clone(),
            check_pack_sha256: plan.check_pack_sha256.clone(),
            plan_sha256: plan.plan_sha256.clone(),
            complete,
            operations,
            evidence_sha256: String::new(),
        };
        envelope.evidence_sha256 = envelope.compute_sha256()?;
        Ok(envelope)
    }

    pub fn seal_now(
        plan: &ReadOnlyOperationPlan,
        device: DeviceFingerprint,
        transport_identity: EvidenceTransportIdentity,
        operations: Vec<AdapterOperationEvidence>,
    ) -> AdapterResult<Self> {
        Self::seal(plan, device, transport_identity, Utc::now(), operations)
    }

    fn compute_sha256(&self) -> AdapterResult<String> {
        canonical_json_sha256(&EvidenceDigestBinding {
            schema: &self.schema,
            contract_version: self.contract_version,
            adapter_id: &self.adapter_id,
            adapter_version: &self.adapter_version,
            target_key: &self.target_key,
            transport: self.transport,
            device: &self.device,
            device_fingerprint_sha256: &self.device_fingerprint_sha256,
            transport_identity: &self.transport_identity,
            collected_at: &self.collected_at,
            profile_sha256: &self.profile_sha256,
            check_pack_sha256: &self.check_pack_sha256,
            plan_sha256: &self.plan_sha256,
            complete: self.complete,
            operations: &self.operations,
        })
        .map_err(internal_error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterCollectionErrorKind {
    MissingEvidence,
    PermissionDenied,
    AuthenticationFailed,
    Timeout,
    Transport,
    Protocol,
    Truncated,
    RedactedEvidence,
    ResponseLimit,
    Semantic,
    EnvelopeIncomplete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterCollectionError {
    pub operation_id: Option<String>,
    pub kind: AdapterCollectionErrorKind,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectionCompleteness {
    pub complete: bool,
    pub errors: Vec<AdapterCollectionError>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NormalizedObservationKind {
    CommandOutput,
    RunningConfiguration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizedObservation {
    pub key: String,
    pub kind: NormalizedObservationKind,
    pub value: String,
    pub source_operation_id: String,
    pub response_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizedObservationSet {
    pub schema: String,
    pub target_key: String,
    pub device_fingerprint_sha256: String,
    pub profile_sha256: String,
    pub check_pack_sha256: String,
    pub plan_sha256: String,
    pub evidence_sha256: String,
    pub completeness: CollectionCompleteness,
    pub observations: BTreeMap<String, NormalizedObservation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterReplay {
    pub observations: NormalizedObservationSet,
    pub system_data: SystemData,
    pub completeness: CollectionCompleteness,
    pub replay_sha256: String,
}

#[derive(Serialize)]
struct ReplayDigestBinding<'a> {
    observations: &'a NormalizedObservationSet,
    system_data: &'a SystemData,
}

fn validate_fingerprint_fields(fingerprint: &DeviceFingerprint) -> AdapterResult<()> {
    for (label, value) in [
        ("hostname", fingerprint.hostname.as_str()),
        ("vendor", fingerprint.vendor.as_str()),
        ("product_family", fingerprint.product_family.as_str()),
        ("software_version", fingerprint.software_version.as_str()),
    ] {
        let value = value.trim();
        if value.is_empty() || value.chars().any(char::is_control) {
            return Err(TargetAdapterError::InvalidFingerprint(format!(
                "{label} must be non-empty and contain no control characters"
            )));
        }
    }
    if fingerprint.hostname.len() > 255 {
        return Err(TargetAdapterError::InvalidFingerprint(
            "hostname exceeds 255 bytes".to_string(),
        ));
    }
    for (label, value) in [
        ("model", fingerprint.model.as_deref()),
        ("serial_number", fingerprint.serial_number.as_deref()),
    ] {
        if value.is_some_and(|value| value.trim().is_empty() || value.chars().any(char::is_control))
        {
            return Err(TargetAdapterError::InvalidFingerprint(format!(
                "{label} must not be blank or contain control characters when present"
            )));
        }
    }
    Ok(())
}

fn leading_major(version: &str) -> Option<u32> {
    let digits: String = version
        .trim()
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    (!digits.is_empty()).then(|| digits.parse().ok()).flatten()
}

fn validate_envelope_header(
    adapter: BuiltInTargetAdapter,
    envelope: &AdapterEvidenceEnvelope,
) -> AdapterResult<()> {
    if envelope.schema != TARGET_ADAPTER_EVIDENCE_SCHEMA {
        return Err(TargetAdapterError::InvalidEvidence(format!(
            "unsupported evidence schema {}",
            envelope.schema
        )));
    }
    if envelope.contract_version != TargetAdapterContractVersion::V1
        || envelope.adapter_version != ADAPTER_IMPLEMENTATION_VERSION
        || envelope.adapter_id != adapter.adapter_id()
        || envelope.target_key != adapter.target_key()
        || envelope.transport != adapter.transport()
    {
        return Err(TargetAdapterError::InvalidEvidence(
            "evidence adapter identity does not match the selected built-in adapter".to_string(),
        ));
    }
    DateTime::parse_from_rfc3339(&envelope.collected_at).map_err(|_| {
        TargetAdapterError::InvalidEvidence(
            "collected_at must be a valid RFC 3339 timestamp".to_string(),
        )
    })?;
    validate_lowercase_sha256(
        "device_fingerprint_sha256",
        &envelope.device_fingerprint_sha256,
    )?;
    validate_lowercase_sha256("profile_sha256", &envelope.profile_sha256)?;
    validate_lowercase_sha256("check_pack_sha256", &envelope.check_pack_sha256)?;
    validate_lowercase_sha256("plan_sha256", &envelope.plan_sha256)?;
    validate_lowercase_sha256("evidence_sha256", &envelope.evidence_sha256)?;
    Ok(())
}

fn validate_envelope_bindings(
    plan: &ReadOnlyOperationPlan,
    envelope: &AdapterEvidenceEnvelope,
) -> AdapterResult<()> {
    let actual_fingerprint = envelope.device.sha256()?;
    if envelope.device_fingerprint_sha256 != actual_fingerprint
        || envelope.device_fingerprint_sha256 != plan.device_fingerprint_sha256
    {
        return Err(TargetAdapterError::Integrity(
            "device fingerprint digest does not match evidence and plan".to_string(),
        ));
    }
    for (label, actual, expected) in [
        (
            "profile",
            envelope.profile_sha256.as_str(),
            plan.profile_sha256.as_str(),
        ),
        (
            "check pack",
            envelope.check_pack_sha256.as_str(),
            plan.check_pack_sha256.as_str(),
        ),
        (
            "operation plan",
            envelope.plan_sha256.as_str(),
            plan.plan_sha256.as_str(),
        ),
    ] {
        if actual != expected {
            return Err(TargetAdapterError::Integrity(format!(
                "{label} digest does not match the current adapter contract"
            )));
        }
    }
    Ok(())
}

fn validate_transport_identity(
    transport: TransportKind,
    identity: &EvidenceTransportIdentity,
) -> AdapterResult<()> {
    let valid = match (transport, identity) {
        (TransportKind::SshCli, EvidenceTransportIdentity::SshHostKey { fingerprint }) => {
            is_openssh_sha256_fingerprint(fingerprint)
        }
        (TransportKind::OfflineConfig, EvidenceTransportIdentity::OfflineArtifact { sha256 }) => {
            is_lowercase_sha256(sha256)
        }
        (TransportKind::Netconf, EvidenceTransportIdentity::SshHostKey { fingerprint }) => {
            is_openssh_sha256_fingerprint(fingerprint)
        }
        (
            TransportKind::Netconf | TransportKind::Restconf | TransportKind::HttpsApi,
            EvidenceTransportIdentity::TlsCertificate { sha256 },
        ) => is_lowercase_sha256(sha256),
        _ => false,
    };
    if !valid {
        return Err(TargetAdapterError::InvalidEvidence(format!(
            "transport identity is invalid for {transport:?}"
        )));
    }
    Ok(())
}

fn validate_evidence_records_for_seal(
    plan: &ReadOnlyOperationPlan,
    records: &[AdapterOperationEvidence],
) -> AdapterResult<()> {
    validate_operation_order(plan, records)?;
    let mut seen = BTreeSet::new();
    for record in records {
        if !seen.insert(record.operation_id.as_str()) {
            return Err(TargetAdapterError::InvalidEvidence(format!(
                "duplicate evidence operation {}",
                record.operation_id
            )));
        }
        let operation = plan
            .operations
            .iter()
            .find(|operation| operation.operation_id == record.operation_id)
            .ok_or_else(|| {
                TargetAdapterError::InvalidEvidence(format!(
                    "unexpected evidence operation {}",
                    record.operation_id
                ))
            })?;
        if record.request != operation.request {
            return Err(TargetAdapterError::InvalidEvidence(format!(
                "operation {} request differs from plan",
                record.operation_id
            )));
        }
        validate_record_digest(record)?;
        validate_redactions(record)?;
        validate_record_shape(record)?;
    }
    Ok(())
}

fn validate_operation_set<'a>(
    plan: &ReadOnlyOperationPlan,
    envelope: &'a AdapterEvidenceEnvelope,
) -> AdapterResult<BTreeMap<&'a str, &'a AdapterOperationEvidence>> {
    validate_operation_order(plan, &envelope.operations)?;
    let expected_ids: BTreeSet<_> = plan
        .operations
        .iter()
        .map(|operation| operation.operation_id.as_str())
        .collect();
    let mut records = BTreeMap::new();
    for record in &envelope.operations {
        if !expected_ids.contains(record.operation_id.as_str()) {
            return Err(TargetAdapterError::InvalidEvidence(format!(
                "unexpected evidence operation {}",
                record.operation_id
            )));
        }
        if records
            .insert(record.operation_id.as_str(), record)
            .is_some()
        {
            return Err(TargetAdapterError::InvalidEvidence(format!(
                "duplicate evidence operation {}",
                record.operation_id
            )));
        }
        validate_redactions(record)?;
        validate_record_shape(record)?;
    }
    Ok(records)
}

fn validate_operation_order(
    plan: &ReadOnlyOperationPlan,
    records: &[AdapterOperationEvidence],
) -> AdapterResult<()> {
    let positions: BTreeMap<_, _> = plan
        .operations
        .iter()
        .enumerate()
        .map(|(index, operation)| (operation.operation_id.as_str(), index))
        .collect();
    let mut previous = None;
    for record in records {
        let position = positions
            .get(record.operation_id.as_str())
            .copied()
            .ok_or_else(|| {
                TargetAdapterError::InvalidEvidence(format!(
                    "unexpected evidence operation {}",
                    record.operation_id
                ))
            })?;
        if previous.is_some_and(|previous| position <= previous) {
            return Err(TargetAdapterError::InvalidEvidence(
                "evidence operations must retain read-only plan order".to_string(),
            ));
        }
        previous = Some(position);
    }
    Ok(())
}

fn validate_record_shape(record: &AdapterOperationEvidence) -> AdapterResult<()> {
    if record.operation_id.trim().is_empty() {
        return Err(TargetAdapterError::InvalidEvidence(
            "operation_id must not be empty".to_string(),
        ));
    }
    if record.status == AdapterOperationStatus::Success {
        if record.response.is_none() || record.status_code.is_none() || record.error.is_some() {
            return Err(TargetAdapterError::InvalidEvidence(format!(
                "successful operation {} requires response/status_code and no error",
                record.operation_id
            )));
        }
    } else if record
        .error
        .as_deref()
        .is_none_or(|error| error.trim().is_empty())
    {
        return Err(TargetAdapterError::InvalidEvidence(format!(
            "failed operation {} requires a non-empty error",
            record.operation_id
        )));
    }
    Ok(())
}

fn validate_redactions(record: &AdapterOperationEvidence) -> AdapterResult<()> {
    for redaction in &record.redactions {
        if redaction.reason.trim().is_empty() {
            return Err(TargetAdapterError::InvalidEvidence(format!(
                "operation {} has a redaction without a reason",
                record.operation_id
            )));
        }
        validate_lowercase_sha256("redaction removed_sha256", &redaction.removed_sha256)?;
    }
    Ok(())
}

fn validate_record_digest(record: &AdapterOperationEvidence) -> AdapterResult<()> {
    match (&record.response, &record.response_sha256) {
        (Some(response), Some(expected)) => {
            validate_lowercase_sha256("response_sha256", expected)?;
            let actual = sha256_bytes(response.as_bytes());
            if &actual != expected {
                return Err(TargetAdapterError::Integrity(format!(
                    "operation {} response digest mismatch",
                    record.operation_id
                )));
            }
        }
        (None, None) => {}
        _ => {
            return Err(TargetAdapterError::InvalidEvidence(format!(
                "operation {} response and response_sha256 must appear together",
                record.operation_id
            )))
        }
    }
    Ok(())
}

fn validate_envelope_digest(envelope: &AdapterEvidenceEnvelope) -> AdapterResult<()> {
    let actual = envelope.compute_sha256()?;
    if actual != envelope.evidence_sha256 {
        return Err(TargetAdapterError::Integrity(format!(
            "evidence envelope digest mismatch: expected {}, got {actual}",
            envelope.evidence_sha256
        )));
    }
    Ok(())
}

fn record_is_complete(record: &AdapterOperationEvidence, operation: &ReadOnlyOperation) -> bool {
    record.status == AdapterOperationStatus::Success
        && !record.truncated
        && !record
            .redactions
            .iter()
            .any(|redaction| redaction.field == EvidenceRedactionField::Response)
        && record
            .status_code
            .is_some_and(|code| operation.accepted_status_codes.contains(&code))
}

fn record_failure(
    record: &AdapterOperationEvidence,
    operation: &ReadOnlyOperation,
    response_redacted: bool,
) -> Option<(AdapterCollectionErrorKind, String)> {
    if record.truncated {
        return Some((
            AdapterCollectionErrorKind::Truncated,
            "evidence response was truncated".to_string(),
        ));
    }
    if response_redacted {
        return Some((
            AdapterCollectionErrorKind::RedactedEvidence,
            "evaluation response was redacted".to_string(),
        ));
    }
    if record.status != AdapterOperationStatus::Success {
        return Some((
            collection_error_kind(record.status),
            record
                .error
                .clone()
                .unwrap_or_else(|| format!("collection ended with status {:?}", record.status)),
        ));
    }
    let Some(code) = record.status_code else {
        return Some((
            AdapterCollectionErrorKind::Protocol,
            "successful evidence has no transport status code".to_string(),
        ));
    };
    if !operation.accepted_status_codes.contains(&code) {
        return Some((
            AdapterCollectionErrorKind::Protocol,
            format!("transport status code {code} is not accepted"),
        ));
    }
    None
}

fn command_status(status: AdapterOperationStatus, truncated: bool) -> CommandStatus {
    if truncated {
        return CommandStatus::OutputLimit;
    }
    match status {
        AdapterOperationStatus::Success => CommandStatus::SemanticError,
        AdapterOperationStatus::PermissionDenied | AdapterOperationStatus::AuthenticationFailed => {
            CommandStatus::ProtocolError
        }
        AdapterOperationStatus::Timeout => CommandStatus::Timeout,
        AdapterOperationStatus::TransportError => CommandStatus::TransportError,
        AdapterOperationStatus::ProtocolError => CommandStatus::ProtocolError,
        AdapterOperationStatus::ResponseLimit => CommandStatus::OutputLimit,
        AdapterOperationStatus::SemanticError => CommandStatus::SemanticError,
    }
}

fn collection_error_kind(status: AdapterOperationStatus) -> AdapterCollectionErrorKind {
    match status {
        AdapterOperationStatus::Success | AdapterOperationStatus::SemanticError => {
            AdapterCollectionErrorKind::Semantic
        }
        AdapterOperationStatus::PermissionDenied => AdapterCollectionErrorKind::PermissionDenied,
        AdapterOperationStatus::AuthenticationFailed => {
            AdapterCollectionErrorKind::AuthenticationFailed
        }
        AdapterOperationStatus::Timeout => AdapterCollectionErrorKind::Timeout,
        AdapterOperationStatus::TransportError => AdapterCollectionErrorKind::Transport,
        AdapterOperationStatus::ProtocolError => AdapterCollectionErrorKind::Protocol,
        AdapterOperationStatus::ResponseLimit => AdapterCollectionErrorKind::ResponseLimit,
    }
}

fn normalized_collection_errors(
    data: &SystemData,
    explicit: &HashMap<String, AdapterCollectionErrorKind>,
) -> Vec<AdapterCollectionError> {
    let mut errors: Vec<_> = data
        .collection_errors
        .iter()
        .map(|(operation_id, message)| AdapterCollectionError {
            operation_id: (operation_id != ENVELOPE_ERROR_KEY).then(|| operation_id.clone()),
            kind: explicit
                .get(operation_id)
                .copied()
                .unwrap_or_else(|| infer_error_kind(message)),
            message: message.clone(),
        })
        .collect();
    errors.sort_by(|left, right| {
        left.operation_id
            .as_deref()
            .cmp(&right.operation_id.as_deref())
            .then_with(|| left.message.cmp(&right.message))
    });
    errors
}

fn infer_error_kind(message: &str) -> AdapterCollectionErrorKind {
    let lower = message.to_ascii_lowercase();
    if lower.contains("missing") {
        AdapterCollectionErrorKind::MissingEvidence
    } else if lower.contains("permission") || lower.contains("authorization") {
        AdapterCollectionErrorKind::PermissionDenied
    } else if lower.contains("truncat") || lower.contains("pagination") {
        AdapterCollectionErrorKind::Truncated
    } else if lower.contains("timeout") {
        AdapterCollectionErrorKind::Timeout
    } else {
        AdapterCollectionErrorKind::Semantic
    }
}

fn normalized_observations(
    adapter: BuiltInTargetAdapter,
    envelope: &AdapterEvidenceEnvelope,
    data: &SystemData,
    records: &BTreeMap<&str, &AdapterOperationEvidence>,
    completeness: CollectionCompleteness,
) -> AdapterResult<NormalizedObservationSet> {
    let mut observations = BTreeMap::new();
    for (key, value) in &data.command_outputs {
        let record = records.get(key.as_str()).ok_or_else(|| {
            TargetAdapterError::Internal(format!(
                "normalized observation {key} has no source evidence record"
            ))
        })?;
        let response_sha256 = record.response_sha256.clone().ok_or_else(|| {
            TargetAdapterError::Internal(format!(
                "normalized observation {key} has no source response digest"
            ))
        })?;
        observations.insert(
            key.clone(),
            NormalizedObservation {
                key: key.clone(),
                kind: if adapter == BuiltInTargetAdapter::CiscoIosXeRouterNdm
                    && key == "running_config"
                {
                    NormalizedObservationKind::RunningConfiguration
                } else {
                    NormalizedObservationKind::CommandOutput
                },
                value: value.clone(),
                source_operation_id: key.clone(),
                response_sha256,
            },
        );
    }
    Ok(NormalizedObservationSet {
        schema: NORMALIZED_OBSERVATIONS_SCHEMA.to_string(),
        target_key: adapter.target_key().to_string(),
        device_fingerprint_sha256: envelope.device_fingerprint_sha256.clone(),
        profile_sha256: envelope.profile_sha256.clone(),
        check_pack_sha256: envelope.check_pack_sha256.clone(),
        plan_sha256: envelope.plan_sha256.clone(),
        evidence_sha256: envelope.evidence_sha256.clone(),
        completeness,
        observations,
    })
}

fn bind_cisco_offline_identity(
    fingerprint: &DeviceFingerprint,
    data: &mut SystemData,
) -> AdapterResult<()> {
    let Some(config) = data.network_config.as_deref() else {
        return Ok(());
    };
    let hostname = cisco_config_hostname(config).map_err(TargetAdapterError::InvalidEvidence)?;
    if !hostname.eq_ignore_ascii_case(fingerprint.hostname.trim()) {
        data.network_config = None;
        data.command_outputs.remove("running_config");
        data.collection_errors.insert(
            "running_config".to_string(),
            format!(
                "Cisco running-config hostname {hostname} does not match device fingerprint {}",
                fingerprint.hostname
            ),
        );
        data.collection_complete = false;
    }
    Ok(())
}

fn validate_offline_artifact_identity(
    envelope: &AdapterEvidenceEnvelope,
    plan: &ReadOnlyOperationPlan,
) -> AdapterResult<()> {
    let EvidenceTransportIdentity::OfflineArtifact { sha256 } = &envelope.transport_identity else {
        return Err(TargetAdapterError::InvalidEvidence(
            "IOS-XE evidence requires an offline artifact digest".to_string(),
        ));
    };
    let Some(operation) = plan.operations.first() else {
        return Err(TargetAdapterError::Internal(
            "IOS-XE plan has no running-config operation".to_string(),
        ));
    };
    if let Some(record) = envelope
        .operations
        .iter()
        .find(|record| record.operation_id == operation.operation_id)
    {
        if let Some(response_sha256) = record.response_sha256.as_deref() {
            let secrets_redacted = record
                .redactions
                .iter()
                .any(|redaction| redaction.field == EvidenceRedactionField::ResponseSecret);
            if !secrets_redacted && sha256 != response_sha256 {
                return Err(TargetAdapterError::Integrity(
                    "offline artifact identity does not match running-config response".to_string(),
                ));
            }
        }
    }
    Ok(())
}

/// Remove common IOS/IOS-XE credential values without changing the command
/// structure consumed by scanner predicates.
///
/// The original configuration SHA-256 belongs in
/// [`EvidenceTransportIdentity::OfflineArtifact`]. Each removed location is
/// represented in the returned redaction manifest without hashing the secret
/// itself, while the returned text is safe to persist and remains replayable. This is purposely
/// conservative: it recognizes credential-bearing configuration commands,
/// not arbitrary occurrences of words such as `password` in banners or
/// descriptions.
pub fn redact_cisco_running_configuration(config: &str) -> (String, Vec<EvidenceRedaction>) {
    let mut output = String::with_capacity(config.len());
    let mut redactions = Vec::new();

    for (line_index, line_with_ending) in config.split_inclusive('\n').enumerate() {
        let (line, ending) = line_with_ending
            .strip_suffix("\r\n")
            .map(|line| (line, "\r\n"))
            .or_else(|| line_with_ending.strip_suffix('\n').map(|line| (line, "\n")))
            .unwrap_or((line_with_ending, ""));
        let tokens = token_ranges(line);
        let secret_index = cisco_secret_token_index(line, &tokens);
        if let Some(index) = secret_index {
            let (start, end) = tokens[index];
            output.push_str(&line[..start]);
            // Do not use generic `<redacted>`/`[redacted]` markers: the
            // running-config completeness validator correctly treats those
            // unbound placeholders as evidence truncation. This token is
            // accepted only because the typed redaction manifest above binds
            // every removed value.
            output.push_str("__AUTOMATESTIG_SECRET_REMOVED__");
            output.push_str(&line[end..]);
            redactions.push(EvidenceRedaction::response_secret(format!(
                "IOS-XE credential token removed from line {}",
                line_index + 1
            )));
        } else {
            output.push_str(line);
        }
        output.push_str(ending);
    }

    (output, redactions)
}

fn token_ranges(line: &str) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut start = None;
    for (index, character) in line.char_indices() {
        if character.is_whitespace() {
            if let Some(token_start) = start.take() {
                ranges.push((token_start, index));
            }
        } else if start.is_none() {
            start = Some(index);
        }
    }
    if let Some(token_start) = start {
        ranges.push((token_start, line.len()));
    }
    ranges
}

fn cisco_secret_token_index(line: &str, ranges: &[(usize, usize)]) -> Option<usize> {
    let tokens: Vec<String> = ranges
        .iter()
        .map(|(start, end)| line[*start..*end].to_ascii_lowercase())
        .collect();
    let first = tokens.first()?.as_str();
    if first.starts_with('!') || first == "banner" || first == "description" {
        return None;
    }

    let keyword = if matches!(first, "enable" | "username") {
        tokens
            .iter()
            .position(|token| matches!(token.as_str(), "secret" | "password"))
    } else if first == "snmp-server" && tokens.get(1).is_some_and(|value| value == "community") {
        Some(1)
    } else if matches!(first, "tacacs-server" | "radius-server") {
        tokens.iter().position(|token| token == "key")
    } else if matches!(
        first,
        "password" | "secret" | "key" | "key-string" | "pre-shared-key"
    ) {
        Some(0)
    } else if first == "neighbor" {
        tokens.iter().position(|token| token == "password")
    } else if first == "crypto" && tokens.get(1).is_some_and(|value| value == "isakmp") {
        tokens.iter().position(|token| token == "key")
    } else if first == "ip" && tokens.get(1).is_some_and(|value| value == "ospf") {
        tokens
            .iter()
            .position(|token| matches!(token.as_str(), "authentication-key" | "message-digest-key"))
    } else if first == "ntp"
        && tokens
            .get(1)
            .is_some_and(|value| value == "authentication-key")
    {
        Some(1)
    } else {
        None
    }?;

    let mut candidate = keyword + 1;
    if (first == "ntp"
        && tokens
            .get(keyword)
            .is_some_and(|value| value == "authentication-key"))
        || (first == "ip"
            && tokens
                .get(keyword)
                .is_some_and(|value| value == "message-digest-key"))
    {
        // `ntp authentication-key <id> <algorithm> <secret>` and
        // `ip ospf message-digest-key <id> <algorithm> <secret>`.
        candidate = keyword + 3;
    }
    if tokens
        .get(candidate)
        .is_some_and(|value| value.chars().all(|character| character.is_ascii_digit()))
        && tokens.get(candidate + 1).is_some()
    {
        candidate += 1;
    }
    tokens.get(candidate).map(|_| candidate)
}

fn legacy_command_text(request: &AdapterRequest) -> String {
    match request {
        AdapterRequest::SshCli { command } => command.clone(),
        AdapterRequest::OfflineConfiguration { .. } => OFFLINE_RUNNING_CONFIG_REQUEST.to_string(),
        AdapterRequest::NetconfRpc { rpc } => rpc.clone(),
        AdapterRequest::RestconfGet { path } | AdapterRequest::HttpsApiGet { path } => path.clone(),
    }
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_lowercase_sha256(label: &str, value: &str) -> AdapterResult<()> {
    if !is_lowercase_sha256(value) {
        return Err(TargetAdapterError::InvalidEvidence(format!(
            "{label} must be 64 lowercase hexadecimal characters"
        )));
    }
    Ok(())
}

fn sha256_bytes(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

fn internal_error(error: impl std::fmt::Display) -> TargetAdapterError {
    TargetAdapterError::Internal(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn timestamp() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-08-08T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn ssh_identity() -> EvidenceTransportIdentity {
        EvidenceTransportIdentity::SshHostKey {
            fingerprint: format!("SHA256:{}", "A".repeat(43)),
        }
    }

    fn ontap_fingerprint(version: &str) -> DeviceFingerprint {
        DeviceFingerprint::new("cluster01", "NetApp", "ONTAP", version)
    }

    fn freebsd_fingerprint() -> DeviceFingerprint {
        DeviceFingerprint::new("bsd01", "FreeBSD", "FreeBSD", "13.4-RELEASE-p9")
    }

    fn cisco_fingerprint() -> DeviceFingerprint {
        DeviceFingerprint::new("rtr01", "Cisco", "IOS-XE", "17.9.4a")
    }

    fn cisco_config() -> String {
        "version 17.9\nhostname rtr01\ninterface GigabitEthernet1\n description uplink\n no shutdown\n!\nend\n"
            .to_string()
    }

    fn cisco_envelope(
        mutate_record: impl FnOnce(&mut AdapterOperationEvidence),
    ) -> AdapterEvidenceEnvelope {
        let adapter = BuiltInTargetAdapter::CiscoIosXeRouterNdm;
        let fingerprint = cisco_fingerprint();
        let plan = adapter.preview(&fingerprint).unwrap();
        let config = cisco_config();
        let mut record = AdapterOperationEvidence::success(&plan.operations[0], config.clone(), 7);
        mutate_record(&mut record);
        AdapterEvidenceEnvelope::seal(
            &plan,
            fingerprint,
            EvidenceTransportIdentity::offline_artifact(config.as_bytes()),
            timestamp(),
            vec![record],
        )
        .unwrap()
    }

    #[test]
    fn built_ins_expose_versioned_read_only_plan_previews() {
        let inputs = [
            (
                BuiltInTargetAdapter::NetAppOntap9,
                ontap_fingerprint("9.12.1P8"),
                TransportKind::SshCli,
                13,
            ),
            (
                BuiltInTargetAdapter::FreeBsdGpos,
                freebsd_fingerprint(),
                TransportKind::SshCli,
                6,
            ),
            (
                BuiltInTargetAdapter::CiscoIosXeRouterNdm,
                cisco_fingerprint(),
                TransportKind::OfflineConfig,
                1,
            ),
        ];

        for (adapter, fingerprint, transport, expected_operations) in inputs {
            let descriptor = adapter.descriptor().unwrap();
            let plan = adapter.preview(&fingerprint).unwrap();
            assert_eq!(descriptor.target_key, adapter.target_key());
            assert_eq!(descriptor.transport, transport);
            assert_eq!(plan.transport, transport);
            assert!(plan.read_only);
            assert_eq!(plan.operations.len(), expected_operations);
            assert!(plan.operations.iter().all(|operation| {
                !operation.operation_id.trim().is_empty()
                    && !operation.accepted_status_codes.is_empty()
            }));
            plan.validate_digest().unwrap();
        }
        assert!(built_in_target_adapter("unsupported").is_none());
    }

    #[test]
    fn unsupported_device_versions_fail_before_plan_creation() {
        let error = BuiltInTargetAdapter::NetAppOntap9
            .preview(&ontap_fingerprint("8.3.2"))
            .unwrap_err();
        assert!(matches!(
            error,
            TargetAdapterError::UnsupportedDevice { ref target_key, .. }
                if target_key == "netapp_ontap9"
        ));

        let mut missing = freebsd_fingerprint();
        missing.software_version = " ".to_string();
        assert!(BuiltInTargetAdapter::FreeBsdGpos.preview(&missing).is_err());

        let freebsd_12 = DeviceFingerprint::new("bsd12", "FreeBSD", "FreeBSD", "12.4-RELEASE-p12");
        assert!(matches!(
            BuiltInTargetAdapter::FreeBsdGpos.preview(&freebsd_12),
            Err(TargetAdapterError::UnsupportedDevice { .. })
        ));

        let ios_16 = DeviceFingerprint::new("rtr16", "Cisco", "IOS-XE", "16.12.10a");
        assert!(matches!(
            BuiltInTargetAdapter::CiscoIosXeRouterNdm.preview(&ios_16),
            Err(TargetAdapterError::UnsupportedDevice { .. })
        ));
    }

    #[test]
    fn missing_and_permission_evidence_remain_collection_errors() {
        let adapter = BuiltInTargetAdapter::FreeBsdGpos;
        let fingerprint = freebsd_fingerprint();
        let plan = adapter.preview(&fingerprint).unwrap();
        let missing = AdapterEvidenceEnvelope::seal(
            &plan,
            fingerprint.clone(),
            ssh_identity(),
            timestamp(),
            Vec::new(),
        )
        .unwrap();
        let replay = adapter.replay(&missing).unwrap();
        assert!(!replay.completeness.complete);
        assert_eq!(replay.completeness.errors.len(), 6);
        assert!(replay
            .completeness
            .errors
            .iter()
            .all(|error| error.kind == AdapterCollectionErrorKind::MissingEvidence));
        assert!(replay.observations.observations.is_empty());

        let records = plan
            .operations
            .iter()
            .map(|operation| {
                AdapterOperationEvidence::failed(
                    operation,
                    AdapterOperationStatus::PermissionDenied,
                    "permission denied",
                    2,
                )
                .unwrap()
            })
            .collect();
        let denied =
            AdapterEvidenceEnvelope::seal(&plan, fingerprint, ssh_identity(), timestamp(), records)
                .unwrap();
        let replay = adapter.replay(&denied).unwrap();
        assert!(!replay.completeness.complete);
        assert!(replay
            .completeness
            .errors
            .iter()
            .all(|error| error.kind == AdapterCollectionErrorKind::PermissionDenied));
        assert!(replay.system_data.command_outputs.is_empty());
    }

    #[test]
    fn freebsd_adapter_reuses_reviewed_normalization_and_completes() {
        let adapter = BuiltInTargetAdapter::FreeBsdGpos;
        let fingerprint = freebsd_fingerprint();
        let plan = adapter.preview(&fingerprint).unwrap();
        let outputs = BTreeMap::from([
            (
                "service auditd onestatus",
                "auditd is running as pid 123.\n",
            ),
            (
                "cat /etc/security/audit_control",
                "flags:all\nnaflags:all\n",
            ),
            ("cat /etc/security/audit_user", "# no per-user exclusions\n"),
            (
                "sha256 -q /etc/security/audit_class",
                "834a1fde758a45269874a5c0655046ca7354a7afa3cf9aee8d29bbfe5d8ab2fd\n",
            ),
            (
                "sha256 -q /etc/security/audit_event",
                "124c60b738ec9eb36e497213fded40a7ed9023dc7854258f9c17d5cbcfffcff2\n",
            ),
            (
                "service pf onestatus",
                "Status: Enabled for 1 day 00:00:00\n",
            ),
        ]);
        let records = plan
            .operations
            .iter()
            .map(|operation| {
                AdapterOperationEvidence::success(
                    operation,
                    outputs[operation.data_key.as_str()],
                    3,
                )
            })
            .collect();
        let envelope =
            AdapterEvidenceEnvelope::seal(&plan, fingerprint, ssh_identity(), timestamp(), records)
                .unwrap();
        let replay = adapter.replay(&envelope).unwrap();
        assert!(
            replay.completeness.complete,
            "unexpected replay errors: {:?}",
            replay.completeness.errors
        );
        assert!(replay.system_data.collection_complete);
        assert_eq!(replay.observations.observations.len(), 6);
        assert_eq!(
            replay.system_data.command_outputs["service pf onestatus"],
            "Status: Enabled for 1 day 00:00:00\n"
        );
    }

    #[test]
    fn truncated_and_redacted_evaluation_payloads_never_reach_system_data() {
        let adapter = BuiltInTargetAdapter::CiscoIosXeRouterNdm;
        let truncated = cisco_envelope(|record| record.truncated = true);
        let replay = adapter.replay(&truncated).unwrap();
        assert!(!replay.completeness.complete);
        assert_eq!(
            replay.completeness.errors[0].kind,
            AdapterCollectionErrorKind::Truncated
        );
        assert!(replay.system_data.network_config.is_none());

        let redacted = cisco_envelope(|record| {
            record.redactions.push(EvidenceRedaction::new(
                EvidenceRedactionField::Response,
                "site secret",
                b"removed",
            ));
        });
        let replay = adapter.replay(&redacted).unwrap();
        assert!(!replay.completeness.complete);
        assert_eq!(
            replay.completeness.errors[0].kind,
            AdapterCollectionErrorKind::RedactedEvidence
        );
        assert!(replay.system_data.network_config.is_none());
    }

    #[test]
    fn cisco_secret_redaction_is_replayable_and_hash_bound() {
        let raw = concat!(
            "version 17.9\r\n",
            "hostname rtr01\r\n",
            "enable secret 9 $9$enable-value\r\n",
            "username auditor privilege 15 secret 8 user-value\r\n",
            "snmp-server community community-value RO\r\n",
            "neighbor 192.0.2.8 password 7 bgp-value\r\n",
            "ntp authentication-key 7 md5 ntp-value 7\r\n",
            "ip ospf message-digest-key 1 md5 ospf-value\r\n",
            "interface GigabitEthernet1\r\n",
            " description password words here are not credentials\r\n",
            " no shutdown\r\n",
            "!\r\n",
            "logging enable\r\n",
            "end\r\n",
        );
        let (sanitized, redactions) = redact_cisco_running_configuration(raw);
        for secret in [
            "$9$enable-value",
            "user-value",
            "community-value",
            "bgp-value",
            "ntp-value",
            "ospf-value",
        ] {
            assert!(!sanitized.contains(secret));
            assert!(redactions.iter().all(|redaction| {
                redaction.field == EvidenceRedactionField::ResponseSecret
                    && redaction.removed_sha256 == sha256_bytes(b"__AUTOMATESTIG_SECRET_REMOVED__")
                    && redaction.removed_sha256 != sha256_bytes(secret.as_bytes())
            }));
        }
        assert!(sanitized.contains("description password words here are not credentials"));
        assert!(sanitized.contains("logging enable"));
        assert!(sanitized.contains("\r\n"));

        let adapter = BuiltInTargetAdapter::CiscoIosXeRouterNdm;
        let fingerprint = cisco_fingerprint();
        let plan = adapter.preview(&fingerprint).unwrap();
        let mut record =
            AdapterOperationEvidence::success(&plan.operations[0], sanitized.clone(), 7);
        record.redactions = redactions;
        let envelope = AdapterEvidenceEnvelope::seal(
            &plan,
            fingerprint,
            EvidenceTransportIdentity::offline_artifact(raw.as_bytes()),
            timestamp(),
            vec![record],
        )
        .unwrap();
        let replay = adapter.replay(&envelope).unwrap();
        assert!(
            replay.completeness.complete,
            "unexpected replay errors: {:?}",
            replay.completeness.errors
        );
        assert_eq!(
            replay.system_data.network_config.as_deref(),
            Some(sanitized.as_str())
        );
        let raw_sha256 = sha256_bytes(raw.as_bytes());
        assert_ne!(
            envelope.operations[0].response_sha256.as_deref(),
            Some(raw_sha256.as_str())
        );
    }

    #[test]
    fn response_or_envelope_digest_tampering_is_rejected() {
        let adapter = BuiltInTargetAdapter::CiscoIosXeRouterNdm;
        let mut envelope = cisco_envelope(|_| {});
        envelope.operations[0]
            .response
            .as_mut()
            .unwrap()
            .push_str("! tampered\n");
        // Recompute only the outer digest to prove the inner response digest
        // remains an independent integrity boundary.
        envelope.evidence_sha256 = envelope.compute_sha256().unwrap();
        let error = adapter.replay(&envelope).unwrap_err();
        assert!(matches!(error, TargetAdapterError::Integrity(_)));

        let mut envelope = cisco_envelope(|_| {});
        envelope.evidence_sha256 = "0".repeat(64);
        let error = adapter.replay(&envelope).unwrap_err();
        assert!(matches!(error, TargetAdapterError::Integrity(_)));
    }

    #[test]
    fn replay_is_deterministic_and_binds_ios_identity() {
        let adapter = BuiltInTargetAdapter::CiscoIosXeRouterNdm;
        let envelope = cisco_envelope(|_| {});
        let first = adapter.replay(&envelope).unwrap();
        let second = adapter.replay(&envelope).unwrap();
        let round_tripped: AdapterEvidenceEnvelope =
            serde_json::from_str(&serde_json::to_string(&envelope).unwrap()).unwrap();
        let third = adapter.replay(&round_tripped).unwrap();
        assert!(first.completeness.complete);
        assert_eq!(first.replay_sha256, second.replay_sha256);
        assert_eq!(first.replay_sha256, third.replay_sha256);
        assert_eq!(
            serde_json::to_value(&first.observations).unwrap(),
            serde_json::to_value(&second.observations).unwrap()
        );
        assert_eq!(
            first.system_data.network_config.as_deref(),
            Some(cisco_config().as_str())
        );

        let fingerprint = DeviceFingerprint::new("other-router", "Cisco", "IOS-XE", "17.9.4a");
        let plan = adapter.preview(&fingerprint).unwrap();
        let config = cisco_config();
        let record = AdapterOperationEvidence::success(&plan.operations[0], config.clone(), 1);
        let envelope = AdapterEvidenceEnvelope::seal(
            &plan,
            fingerprint,
            EvidenceTransportIdentity::offline_artifact(config.as_bytes()),
            timestamp(),
            vec![record],
        )
        .unwrap();
        let replay = adapter.replay(&envelope).unwrap();
        assert!(!replay.completeness.complete);
        assert!(replay.system_data.network_config.is_none());
        assert!(replay.completeness.errors[0]
            .message
            .contains("does not match device fingerprint"));
    }
}
