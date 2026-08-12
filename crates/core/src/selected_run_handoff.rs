//! Shared wire contract for selected scanner-run handoff bundles.
//!
//! Archive safety limits and semantic verification belong to the consuming
//! command. This module owns only the immutable JSON vocabulary that the GUI
//! producer and CLI verifier must agree on byte-for-byte.

use serde::{Deserialize, Serialize};

pub const HANDOFF_SCHEMA_V2: &str = "automatestig.selected-run-handoff.v2";
pub const HANDOFF_SCHEMA_V3: &str = "automatestig.selected-run-handoff.v3";
pub const HANDOFF_SCHEMA_V4: &str = "automatestig.selected-run-handoff.v4";
pub const SCANNER_RUN_SCHEMA_V2: &str = "automatestig.scanner-run.v2";
pub const SCANNER_RUN_SCHEMA_V3: &str = "automatestig.scanner-run.v3";
/// Schema emitted by the current producer.
pub const SCANNER_RUN_SCHEMA: &str = SCANNER_RUN_SCHEMA_V3;

pub const HANDOFF_SIGNATURE_SCHEMA: &str = "automatestig.selected-run-handoff-signature.v1";
pub const HANDOFF_SIGNATURE_ALGORITHM: &str = "ed25519-sha256";
pub const HANDOFF_SIGNATURE_DOMAIN: &str = "AUTOMATESTIG-SELECTED-RUN-HANDOFF-SIGNATURE-V1";

pub const MANIFEST_ENTRY: &str = "manifest.json";
pub const INTEGRITY_ENTRY: &str = "integrity.json";
pub const SCANNER_RUN_ENTRY: &str = "scanner-run.json";
pub const RUN_REQUEST_ENTRY: &str = "run-request.json";
pub const SPARSE_REVIEWS_ENTRY: &str = "sparse-reviews.json";
pub const FALLBACK_CKLB_ENTRY: &str = "fallback.cklb";
pub const XCCDF_ENTRY: &str = "results.xccdf.xml";
pub const EVIDENCE_ENTRY: &str = "evidence-envelope.json";

pub const REQUIRED_ENTRIES_V2: [&str; 5] = [
    MANIFEST_ENTRY,
    INTEGRITY_ENTRY,
    SCANNER_RUN_ENTRY,
    SPARSE_REVIEWS_ENTRY,
    FALLBACK_CKLB_ENTRY,
];
pub const REQUIRED_ENTRIES_V3: [&str; 6] = [
    MANIFEST_ENTRY,
    INTEGRITY_ENTRY,
    SCANNER_RUN_ENTRY,
    SPARSE_REVIEWS_ENTRY,
    FALLBACK_CKLB_ENTRY,
    XCCDF_ENTRY,
];
pub const REQUIRED_ENTRIES_V4: [&str; 7] = [
    MANIFEST_ENTRY,
    INTEGRITY_ENTRY,
    RUN_REQUEST_ENTRY,
    SCANNER_RUN_ENTRY,
    SPARSE_REVIEWS_ENTRY,
    FALLBACK_CKLB_ENTRY,
    XCCDF_ENTRY,
];

pub const RUN_REQUEST_SCHEMA_V1: &str = "automatestig.scanner-run-request.v1";

pub const INTEGRITY_ALGORITHM_SHA256: &str = "sha256";
pub const HANDOFF_NOTE: &str = "Reconcile only into the existing exact STIG Manager assignment. sparse-reviews.json is the staged STIG Manager Review API transport; results.xccdf.xml and fallback.cklb are digest-bound supplemental projections. All three contain scanner-owned reviewed rules only; manual, Not Reviewed, and outside-profile rules are excluded. When evidence.included is false, this is a results-only package because replay evidence was purged under local retention policy.";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandoffManifest {
    pub schema: String,
    pub run_id: String,
    pub created_at: String,
    pub scanner_version: String,
    pub stig_id: String,
    pub stig_revision: String,
    pub files: HandoffFiles,
    pub scope: HandoffScope,
    pub evidence: HandoffEvidence,
    pub bindings: RunBindings,
    pub note: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandoffFiles {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "run-request.json"
    )]
    pub run_request: Option<String>,
    #[serde(rename = "scanner-run.json")]
    pub scanner_run: String,
    #[serde(rename = "sparse-reviews.json")]
    pub sparse_reviews: String,
    #[serde(rename = "fallback.cklb")]
    pub fallback_cklb: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "results.xccdf.xml"
    )]
    pub results_xccdf: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "evidence-envelope.json"
    )]
    pub evidence_envelope: Option<String>,
}

/// Sanitized immutable input statement for a scanner run. Field declaration
/// order intentionally matches the canonical JSON object order emitted by the
/// original v1 producer, so compact serialization is stable for its recorded
/// byte digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandoffRunRequest {
    pub collection_method: String,
    pub credential_persisted: bool,
    pub destination: Option<HandoffDestination>,
    pub device_fingerprint_sha256: String,
    pub endpoint: Option<HandoffEndpoint>,
    pub mode: String,
    pub pilot_acknowledged: bool,
    pub plan_sha256: String,
    pub profile_id: String,
    pub schema: String,
    pub source_artifact_sha256: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandoffDestination {
    pub asset_id: String,
    pub assignment_id: String,
    pub collection_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandoffEndpoint {
    pub host: String,
    pub port: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandoffScope {
    pub scanner_owned_reviews_included: usize,
    pub unreviewed_and_non_scanner_rules_excluded: usize,
    pub ownership_safe_sparse_handoff: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    Retained,
    Purged,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidencePurgeReason {
    RetentionExpired,
    OperatorRequested,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandoffEvidence {
    pub state: EvidenceState,
    pub included: bool,
    pub sha256: String,
    pub expires_at: String,
    pub purged_at: Option<String>,
    pub purge_reason: Option<EvidencePurgeReason>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunBindings {
    pub request_sha256: String,
    pub result_sha256: String,
    pub benchmark_sha256: String,
    pub check_pack_sha256: String,
    pub evaluation_plan_sha256: String,
    pub evidence_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_traces_sha256: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrityRecord {
    pub algorithm: String,
    pub manifest_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandoffSignatureEnvelope {
    pub schema: String,
    pub algorithm: String,
    pub handoff_schema: String,
    pub run_id: String,
    pub handoff_sha256: String,
    pub signing_key_fingerprint: String,
    pub signature: String,
}

/// Parse the manifest with unknown fields rejected at every protocol-owned
/// object boundary.
pub fn parse_handoff_manifest(bytes: &[u8]) -> serde_json::Result<HandoffManifest> {
    serde_json::from_slice(bytes)
}

/// Serialize a manifest through `serde_json::Value` so object keys retain the
/// same deterministic ordering as the GUI's original `json!` wire producer.
pub fn serialize_handoff_manifest(manifest: &HandoffManifest) -> serde_json::Result<Vec<u8>> {
    serialize_sorted_pretty(manifest)
}

pub fn parse_integrity_record(bytes: &[u8]) -> serde_json::Result<IntegrityRecord> {
    serde_json::from_slice(bytes)
}

pub fn serialize_integrity_record(record: &IntegrityRecord) -> serde_json::Result<Vec<u8>> {
    serialize_sorted_pretty(record)
}

pub fn parse_handoff_signature_sidecar(
    bytes: &[u8],
) -> serde_json::Result<HandoffSignatureEnvelope> {
    serde_json::from_slice(bytes)
}

/// Serialize the detached signature sidecar exactly as the existing CLI did:
/// struct field order, pretty JSON, and one trailing newline.
pub fn serialize_handoff_signature_sidecar(
    envelope: &HandoffSignatureEnvelope,
) -> serde_json::Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(envelope)?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Fixed, domain-separated signature input. The signature bytes themselves
/// are intentionally excluded from the signed statement.
pub fn handoff_signature_statement(envelope: &HandoffSignatureEnvelope) -> Vec<u8> {
    format!(
        "{HANDOFF_SIGNATURE_DOMAIN}\nsignature_schema={}\nalgorithm={}\nhandoff_schema={}\nrun_id={}\nhandoff_sha256={}\nsigning_key_fingerprint={}\n",
        envelope.schema,
        envelope.algorithm,
        envelope.handoff_schema,
        envelope.run_id,
        envelope.handoff_sha256,
        envelope.signing_key_fingerprint,
    )
    .into_bytes()
}

fn serialize_sorted_pretty<T: Serialize>(value: &T) -> serde_json::Result<Vec<u8>> {
    serde_json::to_vec_pretty(&serde_json::to_value(value)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(character: char) -> String {
        character.to_string().repeat(64)
    }

    fn v3_manifest() -> HandoffManifest {
        HandoffManifest {
            schema: HANDOFF_SCHEMA_V3.to_string(),
            run_id: "11111111-2222-4333-8444-555555555555".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            scanner_version: "0.3.0".to_string(),
            stig_id: "General_Purpose_Operating_System".to_string(),
            stig_revision: "V3R3".to_string(),
            files: HandoffFiles {
                run_request: None,
                scanner_run: digest('1'),
                sparse_reviews: digest('2'),
                fallback_cklb: digest('3'),
                results_xccdf: Some(digest('4')),
                evidence_envelope: Some(digest('5')),
            },
            scope: HandoffScope {
                scanner_owned_reviews_included: 6,
                unreviewed_and_non_scanner_rules_excluded: 197,
                ownership_safe_sparse_handoff: true,
            },
            evidence: HandoffEvidence {
                state: EvidenceState::Retained,
                included: true,
                sha256: digest('6'),
                expires_at: "2026-02-01T00:00:00Z".to_string(),
                purged_at: None,
                purge_reason: None,
            },
            bindings: RunBindings {
                request_sha256: digest('7'),
                result_sha256: digest('8'),
                benchmark_sha256: digest('9'),
                check_pack_sha256: digest('a'),
                evaluation_plan_sha256: digest('b'),
                evidence_sha256: digest('6'),
                decision_traces_sha256: Some(digest('c')),
            },
            note: HANDOFF_NOTE.to_string(),
        }
    }

    #[test]
    fn manifest_canonical_serialization_round_trips_strict_v3_contract() {
        let manifest = v3_manifest();
        let bytes = serialize_handoff_manifest(&manifest).unwrap();
        assert_eq!(parse_handoff_manifest(&bytes).unwrap(), manifest);

        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["schema"], HANDOFF_SCHEMA_V3);
        assert_eq!(value["files"][XCCDF_ENTRY], digest('4'));
        assert!(value["evidence"]["purged_at"].is_null());
    }

    #[test]
    fn protocol_parsers_reject_unknown_manifest_and_sidecar_fields() {
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&serialize_handoff_manifest(&v3_manifest()).unwrap()).unwrap();
        manifest["scope"]["unexpected"] = serde_json::json!(true);
        assert!(parse_handoff_manifest(&serde_json::to_vec(&manifest).unwrap()).is_err());

        let envelope = HandoffSignatureEnvelope {
            schema: HANDOFF_SIGNATURE_SCHEMA.to_string(),
            algorithm: HANDOFF_SIGNATURE_ALGORITHM.to_string(),
            handoff_schema: HANDOFF_SCHEMA_V3.to_string(),
            run_id: "11111111-2222-4333-8444-555555555555".to_string(),
            handoff_sha256: digest('c'),
            signing_key_fingerprint: format!("SHA256:{}", digest('d')),
            signature: "00".repeat(64),
        };
        let sidecar = serialize_handoff_signature_sidecar(&envelope).unwrap();
        assert_eq!(sidecar.last(), Some(&b'\n'));
        assert_eq!(parse_handoff_signature_sidecar(&sidecar).unwrap(), envelope);
        let mut value: serde_json::Value = serde_json::from_slice(&sidecar).unwrap();
        value["unexpected"] = serde_json::json!(true);
        assert!(parse_handoff_signature_sidecar(&serde_json::to_vec(&value).unwrap()).is_err());
    }

    #[test]
    fn signature_statement_is_stable_and_excludes_signature_bytes() {
        let mut envelope = HandoffSignatureEnvelope {
            schema: HANDOFF_SIGNATURE_SCHEMA.to_string(),
            algorithm: HANDOFF_SIGNATURE_ALGORITHM.to_string(),
            handoff_schema: HANDOFF_SCHEMA_V3.to_string(),
            run_id: "11111111-2222-4333-8444-555555555555".to_string(),
            handoff_sha256: digest('e'),
            signing_key_fingerprint: format!("SHA256:{}", digest('f')),
            signature: "00".repeat(64),
        };
        let statement = handoff_signature_statement(&envelope);
        envelope.signature = "11".repeat(64);
        assert_eq!(handoff_signature_statement(&envelope), statement);
        assert!(statement.starts_with(HANDOFF_SIGNATURE_DOMAIN.as_bytes()));
        assert!(!String::from_utf8(statement)
            .unwrap()
            .contains("signature=00"));
    }
}
