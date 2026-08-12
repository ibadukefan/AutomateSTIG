//! SQLite storage layer for AutomateSTIG.
//!
//! Provides persistent storage for:
//! - Evaluation history and audit logs
//! - Cached checklists and findings
//! - User configuration and preferences
//! - STIG library index

use std::path::Path;
use std::str::FromStr;
use std::time::Duration as StdDuration;

use chrono::{DateTime, SecondsFormat, Utc};
use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use automatestig_core::models::checklist::Checklist;
use automatestig_core::path_safety::SensitiveDirectoryGuard;

mod delivery;
mod records;
mod scanner;
mod schema;

const SCHEMA_VERSION: i64 = 7;

/// Scanner replay evidence is deliberately short lived. Sites may choose a
/// shorter or longer period for new runs, but AutomateSTIG never accepts an
/// unbounded local retention value.
pub const DEFAULT_SCAN_EVIDENCE_RETENTION_DAYS: u32 = 30;
pub const MIN_SCAN_EVIDENCE_RETENTION_DAYS: u32 = 1;
pub const MAX_SCAN_EVIDENCE_RETENTION_DAYS: u32 = 365;
pub const SCAN_EVIDENCE_ENCRYPTION_ALGORITHM: &str = "AES-256-GCM+HKDF-SHA256-v1";
const MAX_ENCRYPTED_SCAN_EVIDENCE_BYTES: usize = 80 * 1024 * 1024;
const MAX_ENCRYPTED_SCAN_CHECKPOINT_BYTES: usize = 80 * 1024 * 1024;

pub const MAX_TARGET_CONNECTION_PROFILES: usize = 128;
pub const MAX_OPERATIONAL_PAGE_SIZE: usize = 100;
pub const DEFAULT_OPERATIONAL_PAGE_SIZE: usize = 25;
pub const DEFAULT_OPERATIONAL_RETENTION_DAYS: u32 = 30;
pub const MIN_OPERATIONAL_RETENTION_DAYS: u32 = 1;
pub const MAX_OPERATIONAL_RETENTION_DAYS: u32 = 365;

const INTERRUPTED_SCAN_JOB_ERROR: &str = "Scan interrupted by an application restart. Credentials are never persisted; resubmit credentials and resume only when a verified operation checkpoint is available.";

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Unsafe database path: {0}")]
    UnsafePath(String),

    #[error("Incomplete evaluation cannot be persisted as a checklist: {0}")]
    IncompleteEvaluation(String),

    #[error("Invalid storage data: {0}")]
    InvalidData(String),

    #[error("Delivery {delivery_id} must be {expected}, but is {actual}")]
    InvalidDeliveryState {
        delivery_id: String,
        expected: String,
        actual: String,
    },

    #[error("Delivery claim was lost or superseded: {0}")]
    DeliveryClaimLost(String),

    #[error("Scan job {job_id} must be {expected}, but is {actual}")]
    InvalidScanJobState {
        job_id: String,
        expected: String,
        actual: String,
    },
}

pub type StorageResult<T> = std::result::Result<T, StorageError>;

/// A completed scanner run to be persisted as an immutable provenance record.
///
/// JSON digests are calculated by storage from the exact UTF-8 bytes supplied;
/// content/evidence digests are supplied by the scanner that read those bytes.
#[derive(Debug, Clone)]
pub struct NewScanRun {
    pub id: String,
    pub checklist_id: Option<String>,
    pub asset_hostname: String,
    pub scanner_version: String,
    pub scan_source: String,
    pub stig_id: String,
    pub stig_revision: String,
    pub benchmark_sha256: String,
    pub check_pack_sha256: String,
    pub evaluation_plan_sha256: String,
    pub evidence_sha256: String,
    pub request_json: String,
    pub result_json: String,
    pub completed_at: DateTime<Utc>,
}

/// A stored, immutable completed scanner run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanRunRecord {
    pub id: String,
    pub checklist_id: Option<String>,
    pub asset_hostname: String,
    pub scanner_version: String,
    pub scan_source: String,
    pub stig_id: String,
    pub stig_revision: String,
    pub benchmark_sha256: String,
    pub check_pack_sha256: String,
    pub evaluation_plan_sha256: String,
    pub evidence_sha256: String,
    pub request_json: String,
    pub request_sha256: String,
    pub result_json: String,
    pub result_sha256: String,
    pub completed_at: String,
    pub created_at: String,
}

/// Opaque encrypted replay evidence to insert atomically with a scanner run.
///
/// Cryptography belongs to the scanner boundary rather than this storage
/// crate. Storage verifies all bindings and byte digests before committing the
/// blobs, and intentionally does not implement `Debug` so callers cannot
/// accidentally log ciphertext or wrapped key material.
pub struct NewScanEvidenceArtifact {
    pub run_id: String,
    pub envelope_schema: String,
    pub evidence_sha256: String,
    pub plaintext_sha256: String,
    pub ciphertext_sha256: String,
    pub algorithm: String,
    pub key_id: String,
    pub wrapped_dek_sha256: String,
    pub ciphertext: Vec<u8>,
    pub wrapped_dek: Vec<u8>,
    pub sealed_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanEvidenceState {
    Retained,
    Purged,
}

impl FromStr for ScanEvidenceState {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "retained" => Ok(Self::Retained),
            "purged" => Ok(Self::Purged),
            _ => Err(format!("unknown scan evidence state {value:?}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanEvidencePurgeReason {
    RetentionExpired,
    OperatorRequested,
}

impl ScanEvidencePurgeReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::RetentionExpired => "retention_expired",
            Self::OperatorRequested => "operator_requested",
        }
    }
}

impl FromStr for ScanEvidencePurgeReason {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "retention_expired" => Ok(Self::RetentionExpired),
            "operator_requested" => Ok(Self::OperatorRequested),
            _ => Err(format!("unknown scan evidence purge reason {value:?}")),
        }
    }
}

/// Non-secret lifecycle metadata retained after encrypted replay evidence is
/// purged. Hashes remain immutable so the historical run keeps its provenance
/// binding without retaining the decryptable artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanEvidenceArtifactMetadata {
    pub run_id: String,
    pub state: ScanEvidenceState,
    pub envelope_schema: String,
    pub evidence_sha256: String,
    pub plaintext_sha256: String,
    pub ciphertext_sha256: String,
    pub ciphertext_size: u64,
    pub algorithm: String,
    pub key_id: String,
    pub wrapped_dek_sha256: String,
    pub sealed_at: String,
    pub expires_at: String,
    pub purged_at: Option<String>,
    pub purge_reason: Option<ScanEvidencePurgeReason>,
}

/// Retained encrypted bytes. This type deliberately has no `Debug` or serde
/// implementation so API projections cannot expose it by accident.
pub struct RetainedScanEvidenceArtifact {
    pub metadata: ScanEvidenceArtifactMetadata,
    pub ciphertext: Vec<u8>,
    pub wrapped_dek: Vec<u8>,
}

/// Exact encrypted replay-evidence custody row for a controlled transition or
/// backup snapshot.
///
/// Unlike the runtime loader, this representation does not enforce expiry or
/// mutate storage. A purged row has no encrypted bytes; a retained row carries
/// its ciphertext and wrapped data-encryption key. This type deliberately has
/// no `Debug` or serde implementation so callers must choose an explicit,
/// private archive representation and cannot accidentally serialize key
/// material through an API response.
pub struct ScanEvidenceCustodyRecord {
    pub metadata: ScanEvidenceArtifactMetadata,
    pub ciphertext: Option<Vec<u8>>,
    pub wrapped_dek: Option<Vec<u8>>,
}

/// A durable scanner job created before any device I/O begins.
///
/// `sanitized_request_json` must contain only non-secret scan coordinates and
/// booleans indicating whether ephemeral credentials were supplied. Storage
/// rejects common credential fields and credential material. The supplied
/// digest must match the exact UTF-8 JSON bytes.
#[derive(Debug, Clone)]
pub struct NewScanJob {
    pub id: String,
    pub sanitized_request_json: String,
    pub request_sha256: String,
}

impl NewScanJob {
    /// Build a job request and bind it to the exact sanitized JSON bytes.
    pub fn new(id: impl Into<String>, sanitized_request_json: impl Into<String>) -> Self {
        let sanitized_request_json = sanitized_request_json.into();
        let request_sha256 = sha256_hex(&sanitized_request_json);
        Self {
            id: id.into(),
            sanitized_request_json,
            request_sha256,
        }
    }
}

/// Durable states for long-running scanner collection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanJobState {
    Queued,
    Running,
    Completed,
    Failed,
}

impl ScanJobState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }
}

impl std::fmt::Display for ScanJobState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for ScanJobState {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "queued" => Ok(Self::Queued),
            "running" => Ok(Self::Running),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            _ => Err(format!("unknown scan job state {value:?}")),
        }
    }
}

/// The derived current state of one durable scanner job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanJobRecord {
    pub id: String,
    pub state: ScanJobState,
    pub sanitized_request_json: String,
    pub request_sha256: String,
    pub created_at: String,
    pub updated_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub run_id: Option<String>,
    pub error: Option<String>,
}

/// One immutable, append-only scanner job state transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanJobTransitionRecord {
    pub id: i64,
    pub job_id: String,
    pub state: ScanJobState,
    pub occurred_at: String,
    pub run_id: Option<String>,
    pub error: Option<String>,
}

/// Thin, opt-in coordinates for reconnecting to one difficult target.
///
/// This deliberately contains no asset, collection, assignment, review, or
/// other STIG Manager-owned metadata. `credential_reference` is an opaque
/// provider label and is never interpreted as reusable credential material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewTargetConnectionProfile {
    pub id: String,
    pub scanner_profile_id: String,
    pub adapter: String,
    pub endpoint: String,
    pub port: u16,
    pub credential_reference: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetConnectionProfileRecord {
    pub id: String,
    pub scanner_profile_id: String,
    pub adapter: String,
    pub endpoint: String,
    pub port: u16,
    pub credential_reference: Option<String>,
    pub last_observed_fingerprint: Option<String>,
    pub recent_operational_state: Option<String>,
    pub observed_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Encrypted, credential-free successful operation evidence for an interrupted
/// SSH job. The plaintext schema and all exact resume bindings are authenticated
/// as AEAD associated data by the scanner API before storage sees these bytes.
pub struct NewScanOperationCheckpoint {
    pub job_id: String,
    pub profile_id: String,
    pub plan_sha256: String,
    pub device_fingerprint_sha256: String,
    pub host_key_fingerprint: String,
    pub endpoint: String,
    pub port: u16,
    pub completed_operation_ids_json: String,
    pub plaintext_sha256: String,
    pub ciphertext_sha256: String,
    pub algorithm: String,
    pub key_id: String,
    pub wrapped_dek_sha256: String,
    pub ciphertext: Vec<u8>,
    pub wrapped_dek: Vec<u8>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanOperationCheckpointMetadata {
    pub job_id: String,
    pub profile_id: String,
    pub plan_sha256: String,
    pub device_fingerprint_sha256: String,
    pub host_key_fingerprint: String,
    pub endpoint: String,
    pub port: u16,
    pub completed_operation_ids: Vec<String>,
    pub plaintext_sha256: String,
    pub ciphertext_sha256: String,
    pub algorithm: String,
    pub key_id: String,
    pub wrapped_dek_sha256: String,
    pub created_at: String,
    pub updated_at: String,
    pub expires_at: String,
}

pub struct RetainedScanOperationCheckpoint {
    pub metadata: ScanOperationCheckpointMetadata,
    pub ciphertext: Vec<u8>,
    pub wrapped_dek: Vec<u8>,
}

/// Exact encrypted scanner-checkpoint custody row for a controlled transition
/// or backup snapshot.
///
/// Reading this type never applies retention cleanup. It deliberately has no
/// `Debug` or serde implementation so the encrypted checkpoint and wrapped key
/// cannot be exposed by generic logging or API serialization.
pub struct ScanOperationCheckpointCustodyRecord {
    pub metadata: ScanOperationCheckpointMetadata,
    pub ciphertext: Vec<u8>,
    pub wrapped_dek: Vec<u8>,
}

/// Strict receiver-side reconciliation proof imported after a disconnected or
/// handoff-only result is accepted and independently read back. The producer
/// authentication state is explicit; an operator-confirmed unsigned receipt is
/// never represented as signed.
#[derive(Debug, Clone)]
pub struct NewReconciliationReceipt {
    pub id: String,
    pub schema: String,
    pub run_id: String,
    pub payload_sha256: String,
    pub destination_kind: String,
    pub destination_instance_id: String,
    pub destination_collection_id: String,
    pub destination_asset_id: String,
    pub destination_assignment_id: String,
    pub stig_id: String,
    pub stig_revision: String,
    pub received_rule_ids_json: String,
    pub received_rule_set_sha256: String,
    pub independent_readback_sha256: String,
    pub independent_readback_at: DateTime<Utc>,
    pub receipt_json: String,
    pub receipt_sha256: String,
    /// Configured STIG Manager GUI base URL. STIG Manager 1.6.13 does not
    /// expose a safe asset/review deep-link contract.
    pub remote_url: String,
    pub producer_authentication: String,
    pub signer_fingerprint: Option<String>,
    pub detached_signature: Option<Vec<u8>>,
    pub operator_confirmed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconciliationReceiptRecord {
    pub id: String,
    pub schema: String,
    pub run_id: String,
    pub payload_sha256: String,
    pub destination_kind: String,
    pub destination_instance_id: String,
    pub destination_collection_id: String,
    pub destination_asset_id: String,
    pub destination_assignment_id: String,
    pub stig_id: String,
    pub stig_revision: String,
    pub received_rule_ids: Vec<String>,
    pub received_rule_set_sha256: String,
    pub independent_readback_sha256: String,
    pub independent_readback_at: String,
    pub receipt_sha256: String,
    pub remote_url: String,
    pub producer_authentication: String,
    pub signer_fingerprint: Option<String>,
    pub operator_confirmed: bool,
    pub imported_at: String,
}

/// Exact receiver receipt and optional detached signature for a controlled
/// transition or backup snapshot.
///
/// The ordinary receipt projection intentionally returns metadata only. This
/// custody type is not serializable or debug-printable so callers must place
/// the exact receipt and signature in explicitly protected archive members.
pub struct ReconciliationReceiptCustodyRecord {
    pub record: ReconciliationReceiptRecord,
    pub receipt_json: String,
    pub detached_signature: Option<Vec<u8>>,
}

/// Append-only digest/receipt record retained after eligible operational rows
/// have been irreversibly pruned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationalPurgeTombstone {
    pub id: i64,
    pub run_id: String,
    pub request_sha256: String,
    pub result_sha256: String,
    pub evidence_sha256: String,
    pub payload_sha256: String,
    pub destination_kind: String,
    pub destination_instance_id: String,
    pub destination_collection_id: String,
    pub destination_asset_id: String,
    pub destination_assignment_id: String,
    pub receipt_kind: String,
    pub receipt_id: String,
    pub receipt_sha256: String,
    pub receipt_json: String,
    pub remote_url: String,
    pub purged_at: String,
}

/// Append-only operator mapping for a retained pre-cutover scanner run. This
/// does not edit the run or create a delivery; it only binds the exact remote
/// destination selected during a protected migration workflow.
#[derive(Debug, Clone)]
pub struct NewMigrationRunBinding {
    pub id: String,
    pub run_id: String,
    pub destination_instance_id: String,
    pub destination_collection_id: String,
    pub destination_asset_id: String,
    pub destination_assignment_id: String,
    pub stig_id: String,
    pub stig_revision: String,
    pub observed_stig_manager_version: String,
    pub observed_server_identity: String,
    pub mapping_json: String,
    pub mapping_sha256: String,
    pub mapped_at: DateTime<Utc>,
    pub operator_source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationRunBindingRecord {
    pub id: String,
    pub run_id: String,
    pub destination_instance_id: String,
    pub destination_collection_id: String,
    pub destination_asset_id: String,
    pub destination_assignment_id: String,
    pub stig_id: String,
    pub stig_revision: String,
    pub observed_stig_manager_version: String,
    pub observed_server_identity: String,
    pub mapping_sha256: String,
    pub mapped_at: String,
    pub operator_source: String,
    pub created_at: String,
}

/// A durable delivery request created in the same transaction as its scan run.
#[derive(Debug, Clone)]
pub struct NewPendingDelivery {
    pub id: String,
    pub destination_kind: String,
    pub destination_instance_id: String,
    pub destination_collection_id: String,
    pub destination_asset_id: Option<String>,
    pub request_json: String,
    pub payload_json: String,
    pub not_before: Option<DateTime<Utc>>,
}

/// Durable outbox states. `sending` is always protected by an expiring lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryState {
    Pending,
    Sending,
    Delivered,
    Retryable,
    Conflicted,
    Rejected,
}

impl DeliveryState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Sending => "sending",
            Self::Delivered => "delivered",
            Self::Retryable => "retryable",
            Self::Conflicted => "conflicted",
            Self::Rejected => "rejected",
        }
    }
}

impl std::fmt::Display for DeliveryState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for DeliveryState {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "pending" => Ok(Self::Pending),
            "sending" => Ok(Self::Sending),
            "delivered" => Ok(Self::Delivered),
            "retryable" => Ok(Self::Retryable),
            "conflicted" => Ok(Self::Conflicted),
            "rejected" => Ok(Self::Rejected),
            _ => Err(format!("unknown delivery state {value:?}")),
        }
    }
}

/// The current durable state of one destination delivery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryRecord {
    pub id: String,
    pub scan_run_id: String,
    pub state: DeliveryState,
    pub destination_kind: String,
    pub destination_instance_id: String,
    pub destination_collection_id: String,
    pub destination_asset_id: Option<String>,
    pub stig_id: String,
    pub stig_revision: String,
    pub request_json: String,
    pub request_sha256: String,
    pub payload_json: String,
    pub payload_sha256: String,
    pub attempt_count: u32,
    pub last_error: Option<String>,
    pub remote_receipt_json: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub first_attempted_at: Option<String>,
    pub last_attempted_at: Option<String>,
    pub delivered_at: Option<String>,
    pub next_attempt_at: Option<String>,
    pub claimed_by: Option<String>,
    pub claim_token: Option<String>,
    pub claim_expires_at: Option<String>,
}

/// Immutable terminal record for one claimed delivery attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryReceipt {
    pub id: i64,
    pub delivery_id: String,
    pub attempt_number: u32,
    pub outcome: DeliveryState,
    pub recorded_at: String,
    pub error: Option<String>,
    pub remote_receipt_json: Option<String>,
}

/// The main database handle for AutomateSTIG.
pub struct Database {
    conn: Connection,
    // Retain Windows no-delete custody handles for the lifetime of SQLite's
    // path-based connection. On Unix these guards preserve existing behavior.
    _directory_custody: Option<SensitiveDirectoryGuard>,
    _database_custody: Option<std::fs::File>,
}

/// Narrow write capability used by the protected transition CLI.
///
/// The wrapped database handle is intentionally private and this type exposes
/// only append-only migration-run binding operations. Callers that need to
/// inspect any other retained state must use a separate read-only handle.
pub struct TransitionWriteDatabase {
    database: Database,
}

impl TransitionWriteDatabase {
    /// Re-read the complete immutable source run through the same protected
    /// handle immediately before inserting its destination binding.
    pub fn get_scan_run(&self, run_id: &str) -> StorageResult<ScanRunRecord> {
        self.database.get_scan_run(run_id)
    }

    pub fn create_migration_run_binding(
        &self,
        binding: &NewMigrationRunBinding,
    ) -> StorageResult<MigrationRunBindingRecord> {
        self.database.create_migration_run_binding(binding)
    }

    pub fn get_migration_run_binding(
        &self,
        run_id: &str,
    ) -> StorageResult<MigrationRunBindingRecord> {
        self.database.get_migration_run_binding(run_id)
    }
}

fn validate_required(label: &str, value: &str) -> StorageResult<()> {
    if value.trim().is_empty() {
        return Err(StorageError::InvalidData(format!(
            "{label} must not be empty"
        )));
    }
    Ok(())
}

fn validate_sha256(label: &str, value: &str) -> StorageResult<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(StorageError::InvalidData(format!(
            "{label} must be a 64-character hexadecimal SHA-256 digest"
        )));
    }
    Ok(())
}

fn validate_json(label: &str, value: &str) -> StorageResult<()> {
    serde_json::from_str::<serde_json::Value>(value)
        .map(|_| ())
        .map_err(|error| StorageError::InvalidData(format!("{label} is invalid JSON: {error}")))
}

fn sha256_hex(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

fn sha256_bytes_hex(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

fn parse_timestamp(label: &str, value: &str) -> StorageResult<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|error| StorageError::InvalidData(format!("{label} is invalid: {error}")))
}

fn format_timestamp(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Nanos, true)
}

/// Summary row for checklist listing (no full data).
#[derive(Debug, Clone)]
pub struct ChecklistSummaryRow {
    pub id: String,
    pub asset_hostname: String,
    pub stig_id: String,
    pub stig_title: String,
    pub stig_version: String,
    pub created_at: String,
    pub modified_at: String,
}

/// One retained evaluation-history row.
#[derive(Debug, Clone, Serialize)]
pub struct EvaluationHistoryRecord {
    pub id: i64,
    pub checklist_id: Option<String>,
    pub asset_hostname: String,
    pub stig_id: String,
    pub evaluated_at: String,
    pub total_rules: usize,
    pub open_count: usize,
    pub not_a_finding_count: usize,
    pub not_applicable_count: usize,
    pub not_reviewed_count: usize,
    pub source: String,
    pub details: Option<String>,
}

/// One retained row from the pre-library answer-file registry.
#[derive(Debug, Clone, Serialize)]
pub struct AnswerFileRegistryRecord {
    pub id: i64,
    pub name: String,
    pub stig_id: Option<String>,
    pub file_path: String,
    pub version: String,
    pub entry_count: usize,
    pub registered_at: String,
}

/// One immutable checklist audit event.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub id: i64,
    pub checklist_id: Option<String>,
    pub event_type: String,
    pub occurred_at: String,
    pub actor: String,
    pub details_json: Option<String>,
    pub checklist_snapshot: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_only_open_never_creates_or_mutates_the_database() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing.db");
        assert!(Database::open_read_only(&missing).is_err());
        assert!(!missing.exists());

        let path = directory.path().join("data.db");
        {
            let database = Database::open(&path).unwrap();
            database.set_config("preserved", "value").unwrap();
        }

        let database = Database::open_read_only(&path).unwrap();
        assert_eq!(database.schema_version().unwrap(), Some(SCHEMA_VERSION));
        assert_eq!(
            database.get_config("preserved").unwrap().as_deref(),
            Some("value")
        );
        assert!(database.set_config("forbidden", "value").is_err());
        assert!(database.get_config("forbidden").unwrap().is_none());
    }

    #[test]
    fn transition_write_open_requires_existing_current_schema_and_writes_only_bindings() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing-transition.db");
        assert!(Database::open_existing_for_transition_write(&missing).is_err());
        assert!(!missing.exists());

        let path = directory.path().join("transition.db");
        let run = make_scan_run("retained-transition-run");
        {
            let database = Database::open(&path).unwrap();
            database.save_completed_scan_run(&run).unwrap();
            database.set_config("must-remain", "preserved").unwrap();
        }

        let mapping_json = serde_json::json!({
            "schema": "automatestig.migration-run-binding.v1",
            "run_id": run.id,
            "destination_instance_id": "stigman-prod",
            "destination_collection_id": "44",
            "destination_asset_id": "901",
            "destination_assignment_id": "RHEL_9_STIG",
            "stig_id": run.stig_id,
            "stig_revision": run.stig_revision,
            "observed_stig_manager_version": "1.6.13",
            "observed_server_identity": "sha256:server-identity",
            "operator_source": "protected-cli"
        })
        .to_string();
        let binding = NewMigrationRunBinding {
            id: "binding-retained-transition-run".to_string(),
            run_id: run.id.clone(),
            destination_instance_id: "stigman-prod".to_string(),
            destination_collection_id: "44".to_string(),
            destination_asset_id: "901".to_string(),
            destination_assignment_id: "RHEL_9_STIG".to_string(),
            stig_id: run.stig_id.clone(),
            stig_revision: run.stig_revision.clone(),
            observed_stig_manager_version: "1.6.13".to_string(),
            observed_server_identity: "sha256:server-identity".to_string(),
            mapping_sha256: sha256_hex(&mapping_json),
            mapping_json,
            mapped_at: test_time("2026-08-10T12:00:00Z"),
            operator_source: "protected-cli".to_string(),
        };

        {
            let transition = Database::open_existing_for_transition_write(&path).unwrap();
            assert_eq!(
                transition.get_scan_run(&run.id).unwrap().result_sha256,
                sha256_hex(&run.result_json)
            );
            assert_eq!(
                transition
                    .create_migration_run_binding(&binding)
                    .unwrap()
                    .run_id,
                run.id
            );
            assert_eq!(
                transition
                    .get_migration_run_binding(&run.id)
                    .unwrap()
                    .mapping_sha256,
                binding.mapping_sha256
            );
        }

        let database = Database::open_read_only(&path).unwrap();
        assert_eq!(database.schema_version().unwrap(), Some(SCHEMA_VERSION));
        assert_eq!(
            database.get_config("must-remain").unwrap().as_deref(),
            Some("preserved")
        );
    }

    #[test]
    fn transition_write_open_fails_closed_for_older_and_newer_schemas() {
        for version in [SCHEMA_VERSION - 1, SCHEMA_VERSION + 1] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join(format!("schema-{version}.db"));
            {
                let database = Database::open(&path).unwrap();
                database
                    .conn
                    .execute("DELETE FROM schema_version", [])
                    .unwrap();
                database
                    .conn
                    .execute(
                        "INSERT INTO schema_version (version) VALUES (?1)",
                        params![version],
                    )
                    .unwrap();
            }

            let error = Database::open_existing_for_transition_write(&path)
                .err()
                .expect("mismatched schema must fail closed");
            assert!(error.to_string().contains("does not exactly match"));

            let connection = Connection::open_with_flags(
                &path,
                OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )
            .unwrap();
            let retained_version: i64 = connection
                .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(retained_version, version);
        }
    }

    #[test]
    fn transition_history_readers_preserve_source_and_registry_attribution() {
        let database = Database::in_memory().unwrap();
        database
            .conn
            .execute(
                "INSERT INTO evaluation_log
                 (checklist_id, asset_hostname, stig_id, evaluated_at, total_rules,
                  open_count, naf_count, na_count, nr_count, source, details)
                 VALUES (NULL, 'router-1', 'ROUTER_STIG', '2026-08-08T00:00:00Z',
                         4, 1, 2, 0, 1, 'legacy-import', 'preserve source')",
                [],
            )
            .unwrap();
        database
            .conn
            .execute(
                "INSERT INTO answer_file_registry
                 (name, stig_id, file_path, version, entry_count, registered_at)
                 VALUES ('site answers', 'ROUTER_STIG', '/preserved/site.yaml', '2', 3,
                         '2026-08-08T00:00:00Z')",
                [],
            )
            .unwrap();

        let history = database.list_evaluation_history().unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].source, "legacy-import");
        assert_eq!(history[0].details.as_deref(), Some("preserve source"));

        let registry = database.list_answer_file_registry().unwrap();
        assert_eq!(registry.len(), 1);
        assert_eq!(registry[0].name, "site answers");
        assert_eq!(registry[0].file_path, "/preserved/site.yaml");
    }

    #[cfg(unix)]
    #[test]
    fn database_open_rejects_symlinks_and_enforces_private_modes() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.db");
        std::fs::write(&target, b"do not replace").unwrap();
        let link = dir.path().join("linked.db");
        symlink(&target, &link).unwrap();
        assert!(matches!(
            Database::open(&link),
            Err(StorageError::UnsafePath(_))
        ));
        assert_eq!(std::fs::read(&target).unwrap(), b"do not replace");

        let database = dir.path().join("secure.db");
        Database::open(&database).unwrap();
        assert_eq!(
            std::fs::metadata(&database).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o022,
            0
        );
    }
    use automatestig_core::models::asset::Asset;
    use automatestig_core::models::checklist::{
        Checklist, ChecklistStigInfo, EvaluationOrigin, EvaluationProvenance,
    };
    use automatestig_core::models::finding::{Finding, FindingSource, FindingStatus};
    use automatestig_core::models::stig::Severity;

    fn test_time(value: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(value)
            .unwrap()
            .with_timezone(&Utc)
    }

    fn make_scan_run(id: &str) -> NewScanRun {
        NewScanRun {
            id: id.to_string(),
            checklist_id: Some(format!("checklist-{id}")),
            asset_hostname: "rhel9.example.test".to_string(),
            scanner_version: "0.3.0-test".to_string(),
            scan_source: "live_ssh".to_string(),
            stig_id: "RHEL_9_STIG".to_string(),
            stig_revision: "V2R4".to_string(),
            benchmark_sha256: "a".repeat(64),
            check_pack_sha256: "b".repeat(64),
            evaluation_plan_sha256: "c".repeat(64),
            evidence_sha256: "d".repeat(64),
            request_json: format!(r#"{{"run_id":"{id}","mode":"live_ssh"}}"#),
            result_json: format!(r#"{{"run_id":"{id}","open":2,"not_a_finding":7}}"#),
            completed_at: test_time("2026-08-08T12:00:00Z"),
        }
    }

    fn make_v2_scan_run(id: &str) -> NewScanRun {
        let mut run = make_scan_run(id);
        run.result_json = format!(
            r#"{{"schema":"automatestig.scanner-run.v2","run_id":"{id}","evidence":{{"sha256":"{}"}}}}"#,
            run.evidence_sha256
        );
        run
    }

    fn make_v3_scan_run(id: &str) -> NewScanRun {
        let mut run = make_v2_scan_run(id);
        run.result_json = run.result_json.replace(
            automatestig_core::selected_run_handoff::SCANNER_RUN_SCHEMA_V2,
            automatestig_core::selected_run_handoff::SCANNER_RUN_SCHEMA_V3,
        );
        run
    }

    fn make_scan_evidence(run: &NewScanRun, sealed_at: DateTime<Utc>) -> NewScanEvidenceArtifact {
        let ciphertext = vec![0xa5; 64];
        let wrapped_dek = vec![0x5a; 60];
        NewScanEvidenceArtifact {
            run_id: run.id.clone(),
            envelope_schema: "automatestig-adapter-evidence/v1".to_string(),
            evidence_sha256: run.evidence_sha256.clone(),
            plaintext_sha256: "e".repeat(64),
            ciphertext_sha256: sha256_bytes_hex(&ciphertext),
            algorithm: SCAN_EVIDENCE_ENCRYPTION_ALGORITHM.to_string(),
            key_id: "f".repeat(64),
            wrapped_dek_sha256: sha256_bytes_hex(&wrapped_dek),
            ciphertext,
            wrapped_dek,
            sealed_at,
            expires_at: sealed_at + chrono::Duration::days(30),
        }
    }

    fn make_scan_job(id: &str) -> NewScanJob {
        NewScanJob::new(
            id,
            format!(
                r#"{{"job_id":"{id}","profile_id":"rhel9","host":"router.example.test","password_present":true}}"#
            ),
        )
    }

    fn make_reconciliation_receipt(
        id: &str,
        run_id: &str,
        readback_at: DateTime<Utc>,
    ) -> NewReconciliationReceipt {
        let received_rule_ids_json = r#"["SV-1"]"#.to_string();
        let received_rule_set_sha256 = sha256_hex(&received_rule_ids_json);
        let independent_readback_sha256 = "6".repeat(64);
        let payload_sha256 = "5".repeat(64);
        let remote_url = "https://stigman.example.mil/".to_string();
        let receipt_json = serde_json::to_string(&serde_json::json!({
            "schema": "automatestig.receiver-reconciliation.v1",
            "run_id": run_id,
            "payload_sha256": payload_sha256,
            "destination_instance_id": "instance",
            "destination_collection_id": "7",
            "destination_asset_id": "41",
            "destination_assignment_id": "RHEL_9_STIG:V2R4",
            "stig_id": "RHEL_9_STIG",
            "stig_revision": "V2R4",
            "received_rule_set_sha256": received_rule_set_sha256,
            "independent_readback_sha256": independent_readback_sha256,
            "independent_readback_at": readback_at.to_rfc3339_opts(SecondsFormat::Millis, true),
            "remote_url": remote_url,
        }))
        .unwrap();
        NewReconciliationReceipt {
            id: id.to_string(),
            schema: "automatestig.receiver-reconciliation.v1".to_string(),
            run_id: run_id.to_string(),
            payload_sha256,
            destination_kind: "stig_manager".to_string(),
            destination_instance_id: "instance".to_string(),
            destination_collection_id: "7".to_string(),
            destination_asset_id: "41".to_string(),
            destination_assignment_id: "RHEL_9_STIG:V2R4".to_string(),
            stig_id: "RHEL_9_STIG".to_string(),
            stig_revision: "V2R4".to_string(),
            received_rule_ids_json,
            received_rule_set_sha256,
            independent_readback_sha256,
            independent_readback_at: readback_at,
            receipt_sha256: sha256_hex(&receipt_json),
            receipt_json,
            remote_url,
            producer_authentication: "unavailable".to_string(),
            signer_fingerprint: None,
            detached_signature: None,
            operator_confirmed: true,
        }
    }

    fn make_delivery(id: &str) -> NewPendingDelivery {
        NewPendingDelivery {
            id: id.to_string(),
            destination_kind: "stig_manager".to_string(),
            destination_instance_id: "staging".to_string(),
            destination_collection_id: "42".to_string(),
            destination_asset_id: None,
            request_json: format!(r#"{{"delivery_id":"{id}","collection_id":"42"}}"#),
            payload_json: format!(r#"{{"delivery_id":"{id}","reviews":9}}"#),
            not_before: None,
        }
    }

    #[test]
    fn retention_policy_is_atomic_and_bounded() {
        let db = Database::in_memory().unwrap();
        db.set_scanner_retention_policy(14, 45).unwrap();
        assert_eq!(
            db.get_config("scanner.evidence_retention_days").unwrap(),
            Some("14".to_string())
        );
        assert_eq!(
            db.get_config("scanner.operational_retention_days").unwrap(),
            Some("45".to_string())
        );
        db.set_scanner_retention_policy_dimensions(None, Some(60))
            .unwrap();
        assert_eq!(
            db.get_config("scanner.evidence_retention_days").unwrap(),
            Some("14".to_string()),
            "an environment-controlled dimension must preserve its ineffective stored value"
        );
        assert_eq!(
            db.get_config("scanner.operational_retention_days").unwrap(),
            Some("60".to_string())
        );
        assert!(matches!(
            db.set_scanner_retention_policy(0, 60),
            Err(StorageError::InvalidData(_))
        ));
        assert_eq!(
            db.get_config("scanner.evidence_retention_days").unwrap(),
            Some("14".to_string()),
            "an invalid update must not change either persisted dimension"
        );
        assert_eq!(
            db.get_config("scanner.operational_retention_days").unwrap(),
            Some("60".to_string())
        );
    }

    #[test]
    fn reconciliation_readback_time_is_bound_to_run_and_retention_window() {
        let db = Database::in_memory().unwrap();
        let run = make_scan_run("receipt-time-run");
        db.save_completed_scan_run(&run).unwrap();
        let imported_at = test_time("2026-08-20T12:00:00Z");

        let before_completion = make_reconciliation_receipt(
            "receipt-before-run",
            &run.id,
            test_time("2026-08-08T11:59:59Z"),
        );
        let error = db
            .import_reconciliation_receipt_at(&before_completion, 30, imported_at)
            .unwrap_err();
        assert!(
            matches!(error, StorageError::InvalidData(message) if message.contains("cannot predate"))
        );

        let stale = make_reconciliation_receipt(
            "receipt-stale",
            &run.id,
            test_time("2026-08-09T12:00:00Z"),
        );
        let error = db
            .import_reconciliation_receipt_at(&stale, 10, imported_at)
            .unwrap_err();
        assert!(
            matches!(error, StorageError::InvalidData(message) if message.contains("operational-retention window"))
        );

        let future = make_reconciliation_receipt(
            "receipt-future",
            &run.id,
            imported_at + chrono::Duration::minutes(6),
        );
        let error = db
            .import_reconciliation_receipt_at(&future, 30, imported_at)
            .unwrap_err();
        assert!(
            matches!(error, StorageError::InvalidData(message) if message.contains("too far in the future"))
        );

        let accepted = make_reconciliation_receipt(
            "receipt-accepted",
            &run.id,
            test_time("2026-08-20T11:55:00Z"),
        );
        let stored = db
            .import_reconciliation_receipt_at(&accepted, 30, imported_at)
            .unwrap();
        assert_eq!(stored.producer_authentication, "unavailable");
        assert!(stored.operator_confirmed);
        assert!(stored.signer_fingerprint.is_none());
    }

    fn save_test_pair(db: &Database, id: &str) -> (ScanRunRecord, DeliveryRecord) {
        db.save_completed_scan_run_with_pending_delivery(
            &make_scan_run(&format!("run-{id}")),
            &make_delivery(id),
        )
        .unwrap()
    }

    fn make_test_checklist() -> Checklist {
        let stig_info = ChecklistStigInfo {
            stig_id: "Test_STIG".to_string(),
            title: "Test STIG".to_string(),
            version: "1".to_string(),
            release: "1".to_string(),
            release_date: None,
            uuid: None,
            description: None,
            filename: None,
        };

        let mut cl = Checklist::new(Asset::new("testhost"), stig_info);
        let mut f = Finding::new_not_reviewed("V-1", "SV-1", "V-1", "Rule 1", Severity::High);
        f.status = FindingStatus::Open;
        cl.findings.push(f);
        cl
    }

    #[test]
    fn test_database_init() {
        let db = Database::in_memory().unwrap();
        let checklists = db.list_checklists().unwrap();
        assert!(checklists.is_empty());
        let version: usize = db
            .conn
            .query_row("SELECT version FROM schema_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION as usize);
    }

    #[test]
    fn scan_job_transitions_are_deterministic_append_only_and_terminal() {
        let db = Database::in_memory().unwrap();
        let queued_at = test_time("2026-08-08T12:00:00Z");
        let running_at = test_time("2026-08-08T12:01:00Z");
        let completed_at = test_time("2026-08-08T12:02:00Z");
        let input = make_scan_job("job-completed");

        let queued = db.create_scan_job_at(&input, queued_at).unwrap();
        assert_eq!(queued.state, ScanJobState::Queued);
        assert_eq!(
            queued.request_sha256,
            sha256_hex(&input.sanitized_request_json)
        );
        assert_eq!(queued.created_at, format_timestamp(queued_at));
        assert_eq!(queued.updated_at, format_timestamp(queued_at));
        assert!(queued.started_at.is_none());
        assert!(queued.finished_at.is_none());
        assert_eq!(
            db.list_scan_jobs(Some(ScanJobState::Queued)).unwrap(),
            vec![queued]
        );

        let running = db
            .transition_scan_job_at(
                "job-completed",
                ScanJobState::Running,
                None,
                None,
                running_at,
            )
            .unwrap();
        assert_eq!(running.state, ScanJobState::Running);
        assert_eq!(
            running.started_at.as_deref(),
            Some(format_timestamp(running_at).as_str())
        );
        assert!(running.finished_at.is_none());

        let run = make_scan_run("run-for-job");
        db.save_completed_scan_run(&run).unwrap();
        let completed = db
            .transition_scan_job_at(
                "job-completed",
                ScanJobState::Completed,
                Some("run-for-job"),
                None,
                completed_at,
            )
            .unwrap();
        assert_eq!(completed.state, ScanJobState::Completed);
        assert_eq!(completed.run_id.as_deref(), Some("run-for-job"));
        assert_eq!(
            completed.finished_at.as_deref(),
            Some(format_timestamp(completed_at).as_str())
        );
        assert!(completed.error.is_none());
        assert_eq!(db.get_scan_job("job-completed").unwrap(), completed);

        let history = db.list_scan_job_transitions("job-completed").unwrap();
        assert_eq!(
            history
                .iter()
                .map(|transition| transition.state)
                .collect::<Vec<_>>(),
            vec![
                ScanJobState::Queued,
                ScanJobState::Running,
                ScanJobState::Completed
            ]
        );
        assert_eq!(history[2].run_id.as_deref(), Some("run-for-job"));
        assert!(matches!(
            db.mark_scan_job_failed("job-completed", "cannot change terminal state"),
            Err(StorageError::InvalidScanJobState { .. })
        ));
        assert!(db
            .conn
            .execute(
                "UPDATE scan_jobs SET sanitized_request_json = '{}' WHERE id = 'job-completed'",
                [],
            )
            .is_err());
        assert!(db
            .conn
            .execute(
                "UPDATE scan_job_transitions SET state = 'failed' WHERE job_id = 'job-completed'",
                [],
            )
            .is_err());
        assert!(db
            .conn
            .execute(
                "DELETE FROM scan_job_transitions WHERE job_id = 'job-completed'",
                [],
            )
            .is_err());
        assert!(db
            .conn
            .execute("DELETE FROM scan_jobs WHERE id = 'job-completed'", [])
            .is_err());
    }

    #[test]
    fn scan_jobs_reject_credentials_mismatched_digests_and_invalid_transitions() {
        let db = Database::in_memory().unwrap();

        let mut wrong_digest = make_scan_job("wrong-digest");
        wrong_digest.request_sha256 = "f".repeat(64);
        assert!(matches!(
            db.create_scan_job(&wrong_digest),
            Err(StorageError::InvalidData(message)) if message.contains("does not match")
        ));

        let with_password = NewScanJob::new(
            "password-job",
            r#"{"host":"router.test","ssh_password":"plaintext"}"#,
        );
        assert!(matches!(
            db.create_scan_job(&with_password),
            Err(StorageError::InvalidData(message)) if message.contains("credential field")
        ));
        let with_private_key = NewScanJob::new(
            "key-job",
            r#"{"evidence":"-----BEGIN OPENSSH PRIVATE KEY----- secret"}"#,
        );
        assert!(matches!(
            db.create_scan_job(&with_private_key),
            Err(StorageError::InvalidData(message)) if message.contains("credential material")
        ));

        db.create_scan_job(&make_scan_job("invalid-transition"))
            .unwrap();
        assert!(matches!(
            db.mark_scan_job_completed("invalid-transition", "missing-run"),
            Err(StorageError::InvalidScanJobState { ref expected, .. }) if expected == "running"
        ));
        assert!(db
            .mark_scan_job_failed("invalid-transition", "Bearer plaintext-access-token")
            .is_err());
        let failed = db
            .mark_scan_job_failed(
                "invalid-transition",
                "SSH authentication failed; resubmit credentials",
            )
            .unwrap();
        assert_eq!(failed.state, ScanJobState::Failed);
        assert!(matches!(
            db.mark_scan_job_running("invalid-transition"),
            Err(StorageError::InvalidScanJobState { .. })
        ));
    }

    #[test]
    fn open_recovers_queued_and_running_scan_jobs_once_without_credentials() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("scan-job-restart.db");
        {
            let db = Database::open(&path).unwrap();
            db.create_scan_job(&make_scan_job("queued-before-restart"))
                .unwrap();
            db.create_scan_job(&make_scan_job("running-before-restart"))
                .unwrap();
            db.mark_scan_job_running("running-before-restart").unwrap();

            db.create_scan_job(&make_scan_job("completed-before-restart"))
                .unwrap();
            db.mark_scan_job_running("completed-before-restart")
                .unwrap();
            db.save_completed_scan_run(&make_scan_run("restart-run"))
                .unwrap();
            db.mark_scan_job_completed("completed-before-restart", "restart-run")
                .unwrap();
        }

        {
            let db = Database::open(&path).unwrap();
            for job_id in ["queued-before-restart", "running-before-restart"] {
                let failed = db.get_scan_job(job_id).unwrap();
                assert_eq!(failed.state, ScanJobState::Failed);
                assert_eq!(failed.error.as_deref(), Some(INTERRUPTED_SCAN_JOB_ERROR));
                assert!(failed
                    .error
                    .as_deref()
                    .unwrap()
                    .contains("resubmit credentials"));
                assert!(!failed.sanitized_request_json.contains("plaintext"));
            }
            assert_eq!(
                db.get_scan_job("completed-before-restart").unwrap().state,
                ScanJobState::Completed
            );
            assert_eq!(
                db.list_scan_job_transitions("queued-before-restart")
                    .unwrap()
                    .len(),
                2
            );
            assert_eq!(
                db.list_scan_job_transitions("running-before-restart")
                    .unwrap()
                    .len(),
                3
            );
        }

        let db = Database::open(&path).unwrap();
        assert_eq!(
            db.list_scan_job_transitions("queued-before-restart")
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            db.list_scan_job_transitions("running-before-restart")
                .unwrap()
                .len(),
            3
        );
    }

    #[test]
    fn encrypted_evidence_run_and_delivery_commit_atomically() {
        let db = Database::in_memory().unwrap();
        let run = make_v2_scan_run("evidence-run");
        let evidence = make_scan_evidence(&run, test_time("2026-08-08T12:00:00Z"));
        let delivery = make_delivery("evidence-delivery");
        let (stored_run, stored_evidence, stored_delivery) = db
            .save_completed_scan_run_with_evidence_and_pending_delivery(&run, &evidence, &delivery)
            .unwrap();

        assert_eq!(stored_run.id, run.id);
        assert_eq!(stored_delivery.scan_run_id, run.id);
        assert_eq!(stored_evidence.run_id, run.id);
        assert_eq!(stored_evidence.state, ScanEvidenceState::Retained);
        assert_eq!(
            stored_evidence.ciphertext_sha256,
            sha256_bytes_hex(&evidence.ciphertext)
        );
        let loaded = db
            .load_retained_scan_evidence_at(&run.id, test_time("2026-08-09T12:00:00Z"))
            .unwrap();
        assert_eq!(loaded.ciphertext, evidence.ciphertext);
        assert_eq!(loaded.wrapped_dek, evidence.wrapped_dek);

        let duplicate = make_v2_scan_run("rolled-back-run");
        let duplicate_evidence = make_scan_evidence(&duplicate, test_time("2026-08-08T12:00:00Z"));
        let error = db
            .save_completed_scan_run_with_evidence_and_pending_delivery(
                &duplicate,
                &duplicate_evidence,
                &delivery,
            )
            .unwrap_err();
        assert!(matches!(error, StorageError::Database(_)));
        assert!(matches!(
            db.get_scan_run(&duplicate.id),
            Err(StorageError::NotFound(_))
        ));
        assert!(matches!(
            db.get_scan_evidence_metadata(&duplicate.id),
            Err(StorageError::NotFound(_))
        ));
    }

    #[test]
    fn transition_custody_readers_are_exact_complete_and_non_mutating() {
        let db = Database::in_memory().unwrap();
        let run = make_v2_scan_run("custody-reader-run");
        let evidence = make_scan_evidence(&run, test_time("2026-08-08T12:00:00Z"));
        let expected_evidence_ciphertext = evidence.ciphertext.clone();
        let expected_evidence_wrapped_dek = evidence.wrapped_dek.clone();
        db.save_completed_scan_run_with_evidence(&run, &evidence)
            .unwrap();

        db.create_scan_job(&make_scan_job("custody-reader-job"))
            .unwrap();
        db.save_target_connection_profile(&NewTargetConnectionProfile {
            id: "custody-reader-profile".to_string(),
            scanner_profile_id: "rhel9".to_string(),
            adapter: "ssh".to_string(),
            endpoint: "router.example.test".to_string(),
            port: 22,
            credential_reference: Some("keychain:router".to_string()),
        })
        .unwrap();
        let checkpoint_ciphertext = vec![0x31; 64];
        let checkpoint_wrapped_dek = vec![0x42; 60];
        let checkpoint = NewScanOperationCheckpoint {
            job_id: "custody-reader-job".to_string(),
            profile_id: "rhel9".to_string(),
            plan_sha256: "1".repeat(64),
            device_fingerprint_sha256: "2".repeat(64),
            host_key_fingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            endpoint: "router.example.test".to_string(),
            port: 22,
            completed_operation_ids_json: r#"["show_config"]"#.to_string(),
            plaintext_sha256: "3".repeat(64),
            ciphertext_sha256: sha256_bytes_hex(&checkpoint_ciphertext),
            algorithm: SCAN_EVIDENCE_ENCRYPTION_ALGORITHM.to_string(),
            key_id: "4".repeat(64),
            wrapped_dek_sha256: sha256_bytes_hex(&checkpoint_wrapped_dek),
            ciphertext: checkpoint_ciphertext.clone(),
            wrapped_dek: checkpoint_wrapped_dek.clone(),
            expires_at: Utc::now() + chrono::Duration::days(1),
        };
        db.save_scan_operation_checkpoint(&checkpoint).unwrap();
        db.conn
            .execute(
                "UPDATE scan_operation_checkpoints
                 SET expires_at = '2020-01-01T00:00:00.000Z'
                 WHERE job_id = 'custody-reader-job'",
                [],
            )
            .unwrap();

        let receipt_json =
            r#"{"schema":"automatestig.receiver-reconciliation.v1","proof":"exact"}"#;
        let receipt_sha256 = sha256_hex(receipt_json);
        let rule_ids_json = r#"["SV-1"]"#;
        let detached_signature = vec![0x53; 64];
        db.conn
            .execute(
                "INSERT INTO reconciliation_receipts
                 (id, schema, run_id, payload_sha256, destination_kind,
                  destination_instance_id, destination_collection_id,
                  destination_asset_id, destination_assignment_id, stig_id, stig_revision,
                  received_rule_ids_json, received_rule_set_sha256,
                  independent_readback_sha256, independent_readback_at,
                  receipt_json, receipt_sha256, remote_url,
                  producer_authentication, signer_fingerprint, detached_signature,
                  operator_confirmed, imported_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                         ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23)",
                params![
                    "custody-reader-receipt",
                    "automatestig.receiver-reconciliation.v1",
                    run.id,
                    "5".repeat(64),
                    "stig_manager",
                    "instance",
                    "7",
                    "42",
                    "RHEL_9_STIG:V2R4",
                    run.stig_id,
                    run.stig_revision,
                    rule_ids_json,
                    sha256_hex(rule_ids_json),
                    "6".repeat(64),
                    "2026-08-08T12:05:00.000Z",
                    receipt_json,
                    receipt_sha256,
                    "https://stigman.example.mil/",
                    "trusted_detached_signature",
                    "7".repeat(64),
                    detached_signature,
                    false,
                    "2026-08-08T12:06:00.000Z",
                ],
            )
            .unwrap();
        db.conn
            .execute(
                "INSERT INTO operational_purge_tombstones
                 (run_id, request_sha256, result_sha256, evidence_sha256,
                  payload_sha256, destination_kind, destination_instance_id,
                  destination_collection_id, destination_asset_id,
                  destination_assignment_id, receipt_kind, receipt_id,
                  receipt_sha256, receipt_json, remote_url, purged_at)
                 VALUES ('prior-run', ?1, ?2, ?3, ?4, 'stig_manager', 'instance',
                         '7', '41', 'RHEL_9_STIG:V2R4', 'reconciliation_import',
                         'prior-receipt', ?5, ?6, 'https://stigman.example.mil/',
                         '2026-08-08T12:07:00.000Z')",
                params![
                    "8".repeat(64),
                    "9".repeat(64),
                    "a".repeat(64),
                    "b".repeat(64),
                    sha256_hex(r#"{"receipt":"preserved"}"#),
                    r#"{"receipt":"preserved"}"#,
                ],
            )
            .unwrap();

        let evidence_rows = db.list_scan_evidence_custody_records().unwrap();
        assert_eq!(evidence_rows.len(), 1);
        assert_eq!(
            evidence_rows[0].ciphertext.as_deref(),
            Some(expected_evidence_ciphertext.as_slice())
        );
        assert_eq!(
            evidence_rows[0].wrapped_dek.as_deref(),
            Some(expected_evidence_wrapped_dek.as_slice())
        );

        let checkpoint_rows = db.list_scan_operation_checkpoint_custody_records().unwrap();
        assert_eq!(checkpoint_rows.len(), 1);
        assert_eq!(checkpoint_rows[0].ciphertext, checkpoint_ciphertext);
        assert_eq!(checkpoint_rows[0].wrapped_dek, checkpoint_wrapped_dek);
        assert_eq!(
            checkpoint_rows[0].metadata.expires_at,
            "2020-01-01T00:00:00.000Z"
        );
        let checkpoint_still_present: bool = db
            .conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM scan_operation_checkpoints
                               WHERE job_id = 'custody-reader-job')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(checkpoint_still_present);

        let receipt_rows = db.list_reconciliation_receipt_custody_records().unwrap();
        assert_eq!(receipt_rows.len(), 1);
        assert_eq!(receipt_rows[0].receipt_json, receipt_json);
        assert_eq!(
            receipt_rows[0].detached_signature.as_deref(),
            Some(detached_signature.as_slice())
        );
        let tombstones = db.list_operational_purge_tombstones().unwrap();
        assert_eq!(tombstones.len(), 1);
        assert_eq!(tombstones[0].run_id, "prior-run");
        assert_eq!(tombstones[0].receipt_json, r#"{"receipt":"preserved"}"#);
        let profiles = db.list_target_connection_profiles_for_snapshot().unwrap();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].id, "custody-reader-profile");
        assert_eq!(
            profiles[0].credential_reference.as_deref(),
            Some("keychain:router")
        );
    }

    #[test]
    fn current_scanner_runs_cannot_bypass_atomic_evidence_storage() {
        let db = Database::in_memory().unwrap();
        for (schema, run_only, run_with_delivery) in [
            (
                "v2",
                make_v2_scan_run("v2-run-only-bypass"),
                make_v2_scan_run("v2-delivery-bypass"),
            ),
            (
                "v3",
                make_v3_scan_run("v3-run-only-bypass"),
                make_v3_scan_run("v3-delivery-bypass"),
            ),
        ] {
            assert!(
                matches!(
                    db.save_completed_scan_run(&run_only),
                    Err(StorageError::InvalidData(message))
                        if message.contains("encrypted replay evidence")
                ),
                "{schema} run-only insert bypassed encrypted evidence"
            );
            assert!(matches!(
                db.get_scan_run(&run_only.id),
                Err(StorageError::NotFound(_))
            ));
            assert!(
                matches!(
                    db.save_completed_scan_run_with_pending_delivery(
                        &run_with_delivery,
                        &make_delivery(&format!("{schema}-delivery-bypass"))
                    ),
                    Err(StorageError::InvalidData(message))
                        if message.contains("encrypted replay evidence")
                ),
                "{schema} delivery insert bypassed encrypted evidence"
            );
            assert!(matches!(
                db.get_scan_run(&run_with_delivery.id),
                Err(StorageError::NotFound(_))
            ));
        }
    }

    #[test]
    fn operational_sweep_accepts_only_structurally_verified_exact_noop_receipts() {
        let db = Database::in_memory().unwrap();
        for (suffix, reviews_sent) in [("invalid", 1u64), ("valid", 0u64)] {
            let run = make_scan_run(&format!("run-{suffix}"));
            let delivery = NewPendingDelivery {
                id: format!("delivery-{suffix}"),
                destination_kind: "stig_manager".to_string(),
                destination_instance_id: "instance-sha256".to_string(),
                destination_collection_id: "42".to_string(),
                destination_asset_id: Some("17".to_string()),
                request_json: format!(r#"{{"delivery":"{suffix}"}}"#),
                payload_json: serde_json::json!({
                    "target": {
                        "collection_id": "42",
                        "asset_id": "17",
                        "benchmark_id": "RHEL_9_STIG",
                        "revision": "V2R4"
                    },
                    "reviews": [{"rule_id": "SV-1_rule"}]
                })
                .to_string(),
                not_before: None,
            };
            db.save_completed_scan_run_with_pending_delivery(&run, &delivery)
                .unwrap();
            db.claim_delivery_at(
                &delivery.id,
                "retention-test",
                &format!("claim-{suffix}"),
                test_time("2026-08-08T12:01:00Z"),
                StdDuration::from_secs(60),
            )
            .unwrap();
            let receipt = serde_json::json!({
                "verification": "exact_noop",
                "remote_assignment_id": "RHEL_9_STIG:V2R4",
                "remote_url": "https://stigman.example.mil/",
                "destination_collection_id": "42",
                "destination_asset_id": "17",
                "stig_id": "RHEL_9_STIG",
                "stig_revision": "V2R4",
                "receipt": {
                    "collection_id": 42,
                    "asset_id": 17,
                    "benchmark_id": "RHEL_9_STIG",
                    "revision": "V2R4",
                    "reviews_considered": 1,
                    "reviews_sent": reviews_sent,
                    "unchanged": 1,
                    "inserted": 0,
                    "updated": 0
                }
            })
            .to_string();
            db.mark_delivery_delivered(&delivery.id, &format!("claim-{suffix}"), &receipt, None)
                .unwrap();
        }

        let purged = db
            .sweep_terminal_operational_history_at(test_time("2026-09-15T12:00:00Z"), 30, 10)
            .unwrap();
        assert_eq!(purged.len(), 1);
        assert_eq!(purged[0].run_id, "run-valid");
        assert_eq!(purged[0].receipt_kind, "verified_noop");
        assert_eq!(purged[0].destination_assignment_id, "RHEL_9_STIG:V2R4");
        assert!(matches!(
            db.get_scan_run("run-valid"),
            Err(StorageError::NotFound(_))
        ));
        assert!(db.get_scan_run("run-invalid").is_ok());
        assert!(db.get_delivery("delivery-invalid").is_ok());
    }

    #[test]
    fn encrypted_evidence_validates_bindings_hashes_and_retention_bounds() {
        let db = Database::in_memory().unwrap();
        let run = make_v2_scan_run("validated-evidence");
        let sealed_at = test_time("2026-08-08T12:00:00Z");

        let mut wrong_run = make_scan_evidence(&run, sealed_at);
        wrong_run.run_id = "somewhere-else".to_string();
        assert!(matches!(
            db.save_completed_scan_run_with_evidence(&run, &wrong_run),
            Err(StorageError::InvalidData(_))
        ));

        let mut tampered = make_scan_evidence(&run, sealed_at);
        tampered.ciphertext[0] ^= 0xff;
        assert!(matches!(
            db.save_completed_scan_run_with_evidence(&run, &tampered),
            Err(StorageError::InvalidData(_))
        ));

        let mut unbounded = make_scan_evidence(&run, sealed_at);
        unbounded.expires_at = sealed_at + chrono::Duration::days(366);
        assert!(matches!(
            db.save_completed_scan_run_with_evidence(&run, &unbounded),
            Err(StorageError::InvalidData(_))
        ));
        assert!(matches!(
            db.get_scan_run(&run.id),
            Err(StorageError::NotFound(_))
        ));
    }

    #[test]
    fn evidence_purge_is_one_way_and_preserves_run_metadata() {
        let db = Database::in_memory().unwrap();
        let run = make_v2_scan_run("purged-evidence");
        let evidence = make_scan_evidence(&run, test_time("2026-08-08T12:00:00Z"));
        db.save_completed_scan_run_with_evidence(&run, &evidence)
            .unwrap();

        let purged = db
            .purge_scan_evidence_at(
                &run.id,
                ScanEvidencePurgeReason::OperatorRequested,
                test_time("2026-08-09T12:00:00Z"),
            )
            .unwrap();
        assert_eq!(purged.state, ScanEvidenceState::Purged);
        assert_eq!(
            purged.purge_reason,
            Some(ScanEvidencePurgeReason::OperatorRequested)
        );
        assert!(db.get_scan_run(&run.id).is_ok());
        assert!(matches!(
            db.load_retained_scan_evidence_at(&run.id, test_time("2026-08-10T12:00:00Z")),
            Err(StorageError::NotFound(_))
        ));
        assert!(db
            .conn
            .execute(
                "UPDATE scan_run_evidence_artifacts SET state = 'retained' WHERE run_id = ?1",
                params![run.id]
            )
            .is_err());
        assert!(db
            .conn
            .execute(
                "DELETE FROM scan_run_evidence_artifacts WHERE run_id = ?1",
                params![run.id]
            )
            .is_err());

        let repeated = db
            .purge_scan_evidence_at(
                &run.id,
                ScanEvidencePurgeReason::RetentionExpired,
                test_time("2026-08-11T12:00:00Z"),
            )
            .unwrap();
        assert_eq!(repeated, purged);
    }

    #[test]
    fn evidence_purge_retries_busy_wal_cleanup_and_removes_old_blob_frames() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("evidence-purge.db");
        let writer = Database::open(&path).unwrap();
        writer
            .conn
            .busy_timeout(StdDuration::from_millis(10))
            .unwrap();
        let run = make_v2_scan_run("physical-purge");
        let mut evidence = make_scan_evidence(&run, test_time("2026-08-08T12:00:00Z"));
        evidence.ciphertext = (0..8_192)
            .map(|index| ((index * 73 + 19) % 251) as u8)
            .collect();
        evidence.ciphertext_sha256 = sha256_bytes_hex(&evidence.ciphertext);
        let ciphertext = evidence.ciphertext.clone();
        let wrapped_dek = evidence.wrapped_dek.clone();
        writer
            .save_completed_scan_run_with_evidence(&run, &evidence)
            .unwrap();

        // Opening a second handle checkpoints the original insert. Holding a
        // read snapshot then prevents the purge writer from truncating the WAL
        // until this independent reader releases its old view.
        let reader = Database::open(&path).unwrap();
        reader.conn.execute_batch("BEGIN DEFERRED").unwrap();
        let observed: Vec<u8> = reader
            .conn
            .query_row(
                "SELECT ciphertext FROM scan_run_evidence_artifacts WHERE run_id = ?1",
                params![run.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(observed, ciphertext);

        let first = writer.purge_scan_evidence_at(
            &run.id,
            ScanEvidencePurgeReason::OperatorRequested,
            test_time("2026-08-09T12:00:00Z"),
        );
        assert!(matches!(
            first,
            Err(StorageError::InvalidData(message))
                if message.contains("WAL cleanup is busy")
        ));
        assert_eq!(
            writer.get_scan_evidence_metadata(&run.id).unwrap().state,
            ScanEvidenceState::Purged
        );

        reader.conn.execute_batch("COMMIT").unwrap();
        writer
            .purge_scan_evidence_at(
                &run.id,
                ScanEvidencePurgeReason::OperatorRequested,
                test_time("2026-08-09T12:01:00Z"),
            )
            .unwrap();

        for candidate in [&path, &path.with_extension("db-wal")] {
            let Ok(bytes) = std::fs::read(candidate) else {
                continue;
            };
            assert!(!bytes
                .windows(ciphertext.len())
                .any(|window| window == ciphertext.as_slice()));
            assert!(!bytes
                .windows(wrapped_dek.len())
                .any(|window| window == wrapped_dek.as_slice()));
        }
    }

    #[test]
    fn expired_evidence_is_never_loaded_and_batch_purge_is_bounded() {
        let db = Database::in_memory().unwrap();
        for id in ["expired-a", "expired-b", "still-retained"] {
            let run = make_v2_scan_run(id);
            let mut evidence = make_scan_evidence(&run, test_time("2026-08-08T12:00:00Z"));
            if id == "still-retained" {
                evidence.expires_at = test_time("2026-09-07T12:00:00Z");
            } else {
                evidence.expires_at = test_time("2026-08-09T12:00:00Z");
            }
            db.save_completed_scan_run_with_evidence(&run, &evidence)
                .unwrap();
        }

        let first = db
            .purge_expired_scan_evidence_at(test_time("2026-08-10T12:00:00Z"), 1)
            .unwrap();
        assert_eq!(first.len(), 1);
        let second = db
            .purge_expired_scan_evidence_at(test_time("2026-08-10T12:00:00Z"), 10)
            .unwrap();
        assert_eq!(second.len(), 1);
        assert_eq!(
            db.get_scan_evidence_metadata("still-retained")
                .unwrap()
                .state,
            ScanEvidenceState::Retained
        );
        assert!(matches!(
            db.load_retained_scan_evidence_at("expired-a", test_time("2026-08-10T12:00:00Z")),
            Err(StorageError::NotFound(_))
        ));
        assert!(db.purge_expired_scan_evidence(0).is_err());
    }

    #[test]
    fn completed_run_and_pending_delivery_are_atomic_hashed_and_immutable() {
        let db = Database::in_memory().unwrap();
        let run_input = make_scan_run("run-1");
        let delivery_input = make_delivery("delivery-1");
        let (run, delivery) = db
            .save_completed_scan_run_with_pending_delivery(&run_input, &delivery_input)
            .unwrap();

        assert_eq!(run.request_sha256, sha256_hex(&run_input.request_json));
        assert_eq!(run.result_sha256, sha256_hex(&run_input.result_json));
        assert_eq!(
            delivery.request_sha256,
            sha256_hex(&delivery_input.request_json)
        );
        assert_eq!(
            delivery.payload_sha256,
            sha256_hex(&delivery_input.payload_json)
        );
        assert_eq!(delivery.state, DeliveryState::Pending);
        assert_eq!(delivery.stig_id, "RHEL_9_STIG");
        assert_eq!(delivery.stig_revision, "V2R4");
        assert_eq!(db.get_scan_run("run-1").unwrap(), run);
        assert_eq!(db.get_delivery("delivery-1").unwrap(), delivery);
        assert_eq!(db.list_scan_runs().unwrap(), vec![run]);
        assert_eq!(
            db.list_deliveries(Some(DeliveryState::Pending)).unwrap(),
            vec![delivery]
        );
        assert_eq!(db.list_deliveries_for_run("run-1").unwrap().len(), 1);

        assert!(db
            .conn
            .execute(
                "UPDATE scan_runs SET result_json = '{}' WHERE id = 'run-1'",
                [],
            )
            .is_err());
        assert!(db
            .conn
            .execute(
                "UPDATE delivery_outbox SET payload_json = '{}' WHERE id = 'delivery-1'",
                [],
            )
            .is_err());
        assert!(db
            .conn
            .execute("DELETE FROM scan_runs WHERE id = 'run-1'", [])
            .is_err());
        assert!(db
            .conn
            .execute("DELETE FROM delivery_outbox WHERE id = 'delivery-1'", [])
            .is_err());

        let second_run = make_scan_run("run-2");
        let duplicate_delivery = make_delivery("delivery-1");
        assert!(db
            .save_completed_scan_run_with_pending_delivery(&second_run, &duplicate_delivery)
            .is_err());
        assert!(matches!(
            db.get_scan_run("run-2"),
            Err(StorageError::NotFound(_))
        ));
    }

    #[test]
    fn incomplete_or_disconnected_run_can_be_retained_without_an_outbox_entry() {
        let db = Database::in_memory().unwrap();
        let input = make_scan_run("incomplete-run");

        let stored = db.save_completed_scan_run(&input).unwrap();

        assert_eq!(stored.id, "incomplete-run");
        assert_eq!(stored.result_sha256, sha256_hex(&input.result_json));
        assert!(db
            .list_deliveries_for_run("incomplete-run")
            .unwrap()
            .is_empty());
        assert!(db.save_completed_scan_run(&input).is_err());
    }

    #[test]
    fn explicit_claim_never_selects_a_different_delivery() {
        let db = Database::in_memory().unwrap();
        save_test_pair(&db, "first");
        save_test_pair(&db, "selected");

        let claimed = db
            .claim_delivery(
                "selected",
                "interactive-worker",
                "selected-token",
                StdDuration::from_secs(60),
            )
            .unwrap();

        assert_eq!(claimed.id, "selected");
        assert_eq!(claimed.state, DeliveryState::Sending);
        assert_eq!(
            db.get_delivery("first").unwrap().state,
            DeliveryState::Pending
        );
        assert!(db
            .claim_delivery(
                "selected",
                "second-worker",
                "second-token",
                StdDuration::from_secs(60),
            )
            .is_err());
    }

    #[test]
    fn explicit_claim_recovers_an_expired_sending_lease_without_stealing_an_active_one() {
        let db = Database::in_memory().unwrap();
        save_test_pair(&db, "crashed-delivery");
        let first_claim_at = test_time("2026-08-08T12:00:00Z");

        let first = db
            .claim_delivery_at(
                "crashed-delivery",
                "worker-that-crashes",
                "crashed-token",
                first_claim_at,
                StdDuration::from_secs(30),
            )
            .unwrap();
        assert_eq!(first.state, DeliveryState::Sending);
        assert_eq!(first.attempt_count, 1);

        let active_error = db
            .claim_delivery_at(
                "crashed-delivery",
                "impatient-worker",
                "impatient-token",
                first_claim_at + chrono::Duration::seconds(29),
                StdDuration::from_secs(30),
            )
            .unwrap_err();
        assert!(matches!(
            active_error,
            StorageError::InvalidDeliveryState { ref actual, .. }
                if actual == DeliveryState::Sending.as_str()
        ));
        assert_eq!(
            db.get_delivery("crashed-delivery")
                .unwrap()
                .claim_token
                .as_deref(),
            Some("crashed-token")
        );

        let recovered = db
            .claim_delivery_at(
                "crashed-delivery",
                "recovery-worker",
                "recovery-token",
                first_claim_at + chrono::Duration::seconds(31),
                StdDuration::from_secs(30),
            )
            .unwrap();
        assert_eq!(recovered.state, DeliveryState::Sending);
        assert_eq!(recovered.attempt_count, 2);
        assert_eq!(recovered.claimed_by.as_deref(), Some("recovery-worker"));
        assert_eq!(recovered.claim_token.as_deref(), Some("recovery-token"));

        let receipts = db.list_delivery_receipts("crashed-delivery").unwrap();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].attempt_number, 1);
        assert_eq!(receipts[0].outcome, DeliveryState::Retryable);
        assert_eq!(
            receipts[0].error.as_deref(),
            Some("delivery claim lease expired before completion")
        );
    }

    #[test]
    fn delivery_state_machine_records_receipts_and_manual_retries() {
        let db = Database::in_memory().unwrap();
        save_test_pair(&db, "a-delivered");
        save_test_pair(&db, "b-conflict");
        save_test_pair(&db, "c-rejected");
        let claim_time = test_time("2026-08-08T12:01:00Z");

        let sending = db
            .claim_next_delivery_at(
                "worker-a",
                "token-a",
                claim_time,
                StdDuration::from_secs(60),
            )
            .unwrap()
            .unwrap();
        assert_eq!(sending.id, "a-delivered");
        assert_eq!(sending.state, DeliveryState::Sending);
        assert_eq!(sending.attempt_count, 1);
        assert!(matches!(
            db.mark_delivery_delivered("a-delivered", "wrong-token", r#"{"ok":true}"#, None),
            Err(StorageError::DeliveryClaimLost(_))
        ));
        let with_asset = db
            .update_delivery_destination_asset_id("a-delivered", "token-a", "asset-17")
            .unwrap();
        assert_eq!(with_asset.destination_asset_id.as_deref(), Some("asset-17"));
        let delivered = db
            .mark_delivery_delivered(
                "a-delivered",
                "token-a",
                r#"{"status":201,"review_count":9}"#,
                None,
            )
            .unwrap();
        assert_eq!(delivered.state, DeliveryState::Delivered);
        assert!(delivered.delivered_at.is_some());

        let sending = db
            .claim_next_delivery_at(
                "worker-b",
                "token-b1",
                claim_time,
                StdDuration::from_secs(60),
            )
            .unwrap()
            .unwrap();
        assert_eq!(sending.id, "b-conflict");
        let retryable = db
            .mark_delivery_retryable(
                "b-conflict",
                "token-b1",
                "destination temporarily unavailable",
                Some(r#"{"status":503}"#),
                Some(test_time("2026-08-08T12:05:00Z")),
            )
            .unwrap();
        assert_eq!(retryable.state, DeliveryState::Retryable);
        assert_eq!(retryable.attempt_count, 1);
        assert_eq!(
            db.list_delivery_receipts("b-conflict").unwrap()[0].outcome,
            DeliveryState::Retryable
        );
        assert_eq!(
            db.retry_delivery("b-conflict", None).unwrap().state,
            DeliveryState::Pending
        );

        let sending = db
            .claim_next_delivery_at(
                "worker-b",
                "token-b2",
                claim_time,
                StdDuration::from_secs(60),
            )
            .unwrap()
            .unwrap();
        assert_eq!(sending.id, "b-conflict");
        let conflicted = db
            .mark_delivery_conflicted(
                "b-conflict",
                "token-b2",
                "remote review changed since scan",
                Some(r#"{"status":409,"remote_revision":"V2R5"}"#),
            )
            .unwrap();
        assert_eq!(conflicted.state, DeliveryState::Conflicted);
        assert_eq!(conflicted.attempt_count, 2);

        let sending = db
            .claim_next_delivery_at(
                "worker-c",
                "token-c",
                claim_time,
                StdDuration::from_secs(60),
            )
            .unwrap()
            .unwrap();
        assert_eq!(sending.id, "c-rejected");
        let rejected = db
            .mark_delivery_rejected(
                "c-rejected",
                "token-c",
                "destination rejected the exact STIG revision",
                Some(r#"{"status":422}"#),
            )
            .unwrap();
        assert_eq!(rejected.state, DeliveryState::Rejected);

        let receipts = db.list_delivery_receipts("b-conflict").unwrap();
        assert_eq!(receipts.len(), 2);
        assert_eq!(receipts[1].outcome, DeliveryState::Conflicted);
        assert!(db
            .conn
            .execute(
                "UPDATE delivery_receipts SET error = 'changed' WHERE delivery_id = 'b-conflict'",
                [],
            )
            .is_err());
        assert!(db
            .conn
            .execute(
                "DELETE FROM delivery_receipts WHERE delivery_id = 'b-conflict'",
                [],
            )
            .is_err());
        assert_eq!(
            db.list_deliveries(Some(DeliveryState::Delivered))
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            db.list_deliveries(Some(DeliveryState::Conflicted))
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            db.list_deliveries(Some(DeliveryState::Rejected))
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn expired_sending_claim_is_recovered_after_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("restart.db");
        let first_claim_at = test_time("2026-08-08T12:00:00Z");
        {
            let db = Database::open(&path).unwrap();
            save_test_pair(&db, "restart-delivery");
            let claimed = db
                .claim_next_delivery_at(
                    "worker-before-restart",
                    "old-token",
                    first_claim_at,
                    StdDuration::from_secs(30),
                )
                .unwrap()
                .unwrap();
            assert_eq!(claimed.state, DeliveryState::Sending);
        }

        let db = Database::open(&path).unwrap();
        let recovered = db
            .claim_next_delivery_at(
                "worker-after-restart",
                "new-token",
                test_time("2026-08-08T12:01:00Z"),
                StdDuration::from_secs(30),
            )
            .unwrap()
            .unwrap();
        assert_eq!(recovered.id, "restart-delivery");
        assert_eq!(recovered.state, DeliveryState::Sending);
        assert_eq!(recovered.attempt_count, 2);
        assert_eq!(recovered.claim_token.as_deref(), Some("new-token"));
        let receipts = db.list_delivery_receipts("restart-delivery").unwrap();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].attempt_number, 1);
        assert_eq!(receipts[0].outcome, DeliveryState::Retryable);
        assert!(receipts[0]
            .error
            .as_deref()
            .unwrap()
            .contains("lease expired"));
    }

    #[test]
    fn concurrent_connections_cannot_claim_the_same_delivery() {
        use std::sync::{Arc, Barrier};

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("concurrent.db");
        {
            let db = Database::open(&path).unwrap();
            save_test_pair(&db, "only-delivery");
        }
        let db_a = Database::open(&path).unwrap();
        let db_b = Database::open(&path).unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let fixed_now = test_time("2026-08-08T12:00:00Z");

        let handles = [(db_a, "worker-a", "token-a"), (db_b, "worker-b", "token-b")]
            .into_iter()
            .map(|(db, worker, token)| {
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    db.claim_next_delivery_at(worker, token, fixed_now, StdDuration::from_secs(60))
                        .unwrap()
                })
            })
            .collect::<Vec<_>>();
        let claims = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(claims.iter().filter(|claim| claim.is_some()).count(), 1);

        let db = Database::open(&path).unwrap();
        let stored = db.get_delivery("only-delivery").unwrap();
        assert_eq!(stored.state, DeliveryState::Sending);
        assert_eq!(stored.attempt_count, 1);
    }

    #[test]
    fn migrates_version_three_without_losing_legacy_data() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("version-three.db");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 CREATE TABLE schema_version (version INTEGER PRIMARY KEY);
                 INSERT INTO schema_version VALUES (3);
                 CREATE TABLE checklists (
                    id TEXT PRIMARY KEY, asset_hostname TEXT NOT NULL, stig_id TEXT NOT NULL,
                    stig_title TEXT NOT NULL, stig_version TEXT NOT NULL, data_json TEXT NOT NULL,
                    created_at TEXT NOT NULL, modified_at TEXT NOT NULL, generated_by TEXT NOT NULL
                 );
                 CREATE TABLE evaluation_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, checklist_id TEXT,
                    asset_hostname TEXT NOT NULL, stig_id TEXT NOT NULL, evaluated_at TEXT NOT NULL,
                    total_rules INTEGER NOT NULL, open_count INTEGER NOT NULL,
                    naf_count INTEGER NOT NULL, na_count INTEGER NOT NULL, nr_count INTEGER NOT NULL,
                    source TEXT NOT NULL, details TEXT,
                    FOREIGN KEY (checklist_id) REFERENCES checklists(id) ON DELETE SET NULL
                 );
                 CREATE TABLE answer_file_registry (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, stig_id TEXT,
                    file_path TEXT NOT NULL, version TEXT NOT NULL, entry_count INTEGER NOT NULL,
                    registered_at TEXT NOT NULL
                 );
                 CREATE TABLE app_config (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                 CREATE TABLE audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, checklist_id TEXT, event_type TEXT NOT NULL,
                    occurred_at TEXT NOT NULL, actor TEXT NOT NULL, details_json TEXT,
                    checklist_snapshot TEXT
                 );
                 INSERT INTO checklists VALUES
                    ('legacy-checklist', 'legacy-host', 'LEGACY_STIG', 'Legacy STIG', 'V1R2',
                     '{\"legacy\":true}', '2026-01-01T00:00:00Z', '2026-01-02T00:00:00Z', 'legacy');
                 INSERT INTO evaluation_log
                    (checklist_id, asset_hostname, stig_id, evaluated_at, total_rules, open_count,
                     naf_count, na_count, nr_count, source, details)
                    VALUES ('legacy-checklist', 'legacy-host', 'LEGACY_STIG',
                            '2026-01-02T00:00:00Z', 4, 1, 2, 0, 1, 'legacy-import', 'kept');
                 INSERT INTO answer_file_registry
                    (name, stig_id, file_path, version, entry_count, registered_at)
                    VALUES ('legacy answers', 'LEGACY_STIG', '/tmp/legacy.yaml', '1', 4,
                            '2026-01-01T00:00:00Z');
                 INSERT INTO app_config VALUES ('legacy.key', 'legacy-value');
                 INSERT INTO audit_log
                    (checklist_id, event_type, occurred_at, actor, details_json, checklist_snapshot)
                    VALUES ('legacy-checklist', 'legacy.event', '2026-01-02T00:00:00Z',
                            'legacy-user', '{\"kept\":true}', '{\"snapshot\":true}');",
            )
            .unwrap();
        drop(connection);

        let db = Database::open(&path).unwrap();
        let version: i64 = db
            .conn
            .query_row("SELECT version FROM schema_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        assert_eq!(db.list_checklists().unwrap()[0].id, "legacy-checklist");
        assert_eq!(
            db.get_config("legacy.key").unwrap().as_deref(),
            Some("legacy-value")
        );
        let evaluation: (String, String) = db
            .conn
            .query_row(
                "SELECT source, details FROM evaluation_log WHERE checklist_id = 'legacy-checklist'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            evaluation,
            ("legacy-import".to_string(), "kept".to_string())
        );
        let answer_name: String = db
            .conn
            .query_row("SELECT name FROM answer_file_registry", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(answer_name, "legacy answers");
        assert_eq!(db.list_audit_events().unwrap()[0].actor, "legacy-user");
        let scanner_tables: i64 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'table' AND name IN (
                    'scan_runs', 'scan_jobs', 'scan_job_transitions',
                    'delivery_outbox', 'delivery_receipts'
                 )",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(scanner_tables, 5);
        assert!(db.list_scan_runs().unwrap().is_empty());
        assert!(db.list_scan_jobs(None).unwrap().is_empty());
    }

    #[test]
    fn migrates_evaluation_log_to_retained_history() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("legacy.db");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE evaluation_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    checklist_id TEXT NOT NULL,
                    asset_hostname TEXT NOT NULL,
                    stig_id TEXT NOT NULL,
                    evaluated_at TEXT NOT NULL,
                    total_rules INTEGER NOT NULL,
                    open_count INTEGER NOT NULL,
                    naf_count INTEGER NOT NULL,
                    na_count INTEGER NOT NULL,
                    nr_count INTEGER NOT NULL,
                    source TEXT NOT NULL,
                    details TEXT,
                    FOREIGN KEY (checklist_id) REFERENCES checklists(id)
                 );",
            )
            .unwrap();
        drop(connection);

        let db = Database::open(&path).unwrap();
        let on_delete: String = db
            .conn
            .query_row(
                "SELECT on_delete FROM pragma_foreign_key_list('evaluation_log') LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(on_delete, "SET NULL");
        let not_null: i64 = db
            .conn
            .query_row(
                "SELECT [notnull] FROM pragma_table_info('evaluation_log') WHERE name = 'checklist_id'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(not_null, 0);
    }

    #[test]
    fn test_save_and_load_checklist() {
        let db = Database::in_memory().unwrap();
        let cl = make_test_checklist();
        let id = cl.id.to_string();

        db.save_checklist_with_audit(&cl, "checklist.saved", "test", None)
            .unwrap();

        let loaded = db.load_checklist(&id).unwrap();
        assert_eq!(loaded.asset.hostname, "testhost");
        assert_eq!(loaded.findings.len(), 1);
        assert_eq!(loaded.findings[0].status, FindingStatus::Open);
    }

    #[test]
    fn test_list_checklists() {
        let db = Database::in_memory().unwrap();

        db.save_checklist_with_audit(&make_test_checklist(), "checklist.saved", "test", None)
            .unwrap();
        db.save_checklist_with_audit(&make_test_checklist(), "checklist.saved", "test", None)
            .unwrap();

        let list = db.list_checklists().unwrap();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn test_delete_checklist() {
        let db = Database::in_memory().unwrap();
        let cl = make_test_checklist();
        let id = cl.id.to_string();

        db.save_evaluation(&cl, "test", None).unwrap();
        assert!(db.delete_checklist(&id).unwrap());
        assert!(db.load_checklist(&id).is_err());
        let evaluation_count: usize = db
            .conn
            .query_row("SELECT COUNT(*) FROM evaluation_log", [], |row| row.get(0))
            .unwrap();
        assert_eq!(evaluation_count, 1);
        let detached_id: Option<String> = db
            .conn
            .query_row("SELECT checklist_id FROM evaluation_log", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert!(detached_id.is_none());
        assert_eq!(db.count_audit_events(&id).unwrap(), 2);
    }

    #[test]
    fn incomplete_evaluation_is_audit_only_and_never_completed() {
        let db = Database::in_memory().unwrap();
        let mut checklist = make_test_checklist();
        checklist.findings[0].source = FindingSource::CollectionError;
        checklist.findings[0].status = FindingStatus::NotReviewed;
        checklist.evaluation_provenance = Some(EvaluationProvenance {
            origin: EvaluationOrigin::LiveSsh,
            collection_complete: false,
            collection_errors: vec!["show config: timeout".to_string()],
            evidence_sha256: None,
            claimed_hostname: Some("testhost".to_string()),
            collector_version: Some("test".to_string()),
            collected_at: Some("2026-01-01T00:00:00Z".to_string()),
            plan_sha256: Some("digest".to_string()),
            server_key_fingerprint: None,
            benchmark_sha256: None,
            check_pack_sha256: None,
            evaluation_plan_sha256: None,
            organization_policy: None,
            answer_file: None,
            answer_files: Vec::new(),
            unsafe_legacy_evidence: false,
        });

        assert!(matches!(
            db.save_evaluation(&checklist, "test", None),
            Err(StorageError::IncompleteEvaluation(_))
        ));
        db.record_incomplete_evaluation("test", r#"{"hostname":"testhost","reason":"timeout"}"#)
            .unwrap();

        assert!(db.list_checklists().unwrap().is_empty());
        let events = db.list_audit_events().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "evaluation.incomplete");
        assert!(events
            .iter()
            .all(|event| event.event_type != "evaluation.completed"));
    }

    #[test]
    fn test_evaluation_log() {
        let db = Database::in_memory().unwrap();
        let cl = make_test_checklist();

        db.save_evaluation(&cl, "test", Some("Test evaluation"))
            .unwrap();
        // No assertion needed — just verifying it doesn't error.
    }

    #[test]
    fn checklist_edit_and_audit_event_commit_together() {
        let db = Database::in_memory().unwrap();
        let mut cl = make_test_checklist();
        db.save_evaluation(&cl, "test", None).unwrap();
        cl.findings[0].comments = "reviewed".to_string();
        db.save_checklist_with_audit(
            &cl,
            "finding.updated",
            "test-user",
            Some(r#"{"vuln_id":"V-1"}"#),
        )
        .unwrap();

        assert_eq!(
            db.load_checklist(&cl.id.to_string()).unwrap().findings[0].comments,
            "reviewed"
        );
        assert_eq!(db.count_audit_events(&cl.id.to_string()).unwrap(), 2);
        assert_eq!(db.list_audit_events().unwrap().len(), 2);
        assert!(db.conn.execute("DELETE FROM audit_log", []).is_err());
    }

    #[test]
    fn test_config() {
        let db = Database::in_memory().unwrap();

        assert!(db.get_config("theme").unwrap().is_none());

        db.set_config("theme", "dark").unwrap();
        assert_eq!(db.get_config("theme").unwrap().as_deref(), Some("dark"));

        db.set_config("theme", "light").unwrap();
        assert_eq!(db.get_config("theme").unwrap().as_deref(), Some("light"));

        assert!(db.delete_config("theme").unwrap());
        assert!(db.get_config("theme").unwrap().is_none());
        assert!(!db.delete_config("theme").unwrap());
    }
}
