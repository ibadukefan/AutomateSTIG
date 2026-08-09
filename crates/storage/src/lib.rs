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

const SCHEMA_VERSION: i64 = 6;

/// Scanner replay evidence is deliberately short lived. Sites may choose a
/// shorter or longer period for new runs, but AutomateSTIG never accepts an
/// unbounded local retention value.
pub const DEFAULT_SCAN_EVIDENCE_RETENTION_DAYS: u32 = 30;
pub const MIN_SCAN_EVIDENCE_RETENTION_DAYS: u32 = 1;
pub const MAX_SCAN_EVIDENCE_RETENTION_DAYS: u32 = 365;
pub const SCAN_EVIDENCE_ENCRYPTION_ALGORITHM: &str = "AES-256-GCM+HKDF-SHA256-v1";
const MAX_ENCRYPTED_SCAN_EVIDENCE_BYTES: usize = 80 * 1024 * 1024;

const INTERRUPTED_SCAN_JOB_ERROR: &str = "Scan interrupted by an application restart. Credentials are never persisted; resubmit credentials and start a new scan.";

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

struct DeliveryFinish<'a> {
    outcome: DeliveryState,
    error: Option<&'a str>,
    remote_receipt_json: Option<&'a str>,
    destination_asset_id: Option<&'a str>,
    retry_at: Option<DateTime<Utc>>,
}

/// The main database handle for AutomateSTIG.
pub struct Database {
    conn: Connection,
}

impl Database {
    /// Open or create a database at the given path.
    pub fn open(path: &Path) -> StorageResult<Self> {
        secure_database_path(path)?;
        let conn = Connection::open(path)?;
        conn.busy_timeout(StdDuration::from_secs(5))?;
        let db = Self { conn };
        db.initialize()?;
        loop {
            if db.purge_expired_scan_evidence(1_000)?.len() < 1_000 {
                break;
            }
        }
        Ok(db)
    }

    /// Open an existing database for a transition report without changing it.
    ///
    /// Unlike [`Self::open`], this does not create a database, initialize a
    /// schema, run migrations, change permissions, or write SQLite pragmas.
    /// SQLite's `query_only` guard also prevents callers from accidentally
    /// reaching a mutation method through this handle.
    pub fn open_read_only(path: &Path) -> StorageResult<Self> {
        verify_existing_database_path(path)?;
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        conn.busy_timeout(StdDuration::from_secs(5))?;
        conn.pragma_update(None, "query_only", true)?;
        let db = Self { conn };
        if let Some(version) = db.schema_version()? {
            if version > SCHEMA_VERSION {
                return Err(StorageError::InvalidData(format!(
                    "database schema version {version} is newer than supported version {SCHEMA_VERSION}"
                )));
            }
        }
        Ok(db)
    }

    /// Create an in-memory database (for testing).
    pub fn in_memory() -> StorageResult<Self> {
        let conn = Connection::open_in_memory()?;
        conn.busy_timeout(StdDuration::from_secs(5))?;
        let db = Self { conn };
        db.initialize()?;
        Ok(db)
    }

    /// Return the newest declared schema version without changing the schema.
    pub fn schema_version(&self) -> StorageResult<Option<i64>> {
        self.conn
            .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
                row.get(0)
            })
            .map_err(Into::into)
    }

    /// Run several reads against one coherent SQLite snapshot.
    ///
    /// A read-only handle remains guarded by `PRAGMA query_only`; this helper
    /// only supplies snapshot consistency across the inventory queries.
    pub fn read_snapshot<T, E, F>(&self, reader: F) -> Result<T, E>
    where
        F: FnOnce(&Self) -> Result<T, E>,
        E: From<StorageError>,
    {
        self.conn
            .execute_batch("BEGIN DEFERRED TRANSACTION")
            .map_err(StorageError::from)
            .map_err(E::from)?;
        match reader(self) {
            Ok(value) => {
                self.conn
                    .execute_batch("COMMIT")
                    .map_err(StorageError::from)
                    .map_err(E::from)?;
                Ok(value)
            }
            Err(error) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(error)
            }
        }
    }

    /// Initialize the database schema.
    fn initialize(&self) -> StorageResult<()> {
        self.conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA foreign_keys = ON;
            PRAGMA synchronous = FULL;
            PRAGMA secure_delete = ON;

            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY
            );

            CREATE TABLE IF NOT EXISTS checklists (
                id TEXT PRIMARY KEY,
                asset_hostname TEXT NOT NULL,
                stig_id TEXT NOT NULL,
                stig_title TEXT NOT NULL,
                stig_version TEXT NOT NULL,
                data_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                modified_at TEXT NOT NULL,
                generated_by TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_checklists_hostname
                ON checklists(asset_hostname);
            CREATE INDEX IF NOT EXISTS idx_checklists_stig
                ON checklists(stig_id);

            CREATE TABLE IF NOT EXISTS evaluation_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                checklist_id TEXT,
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
                FOREIGN KEY (checklist_id) REFERENCES checklists(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS answer_file_registry (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                stig_id TEXT,
                file_path TEXT NOT NULL,
                version TEXT NOT NULL,
                entry_count INTEGER NOT NULL,
                registered_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS app_config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                checklist_id TEXT,
                event_type TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                actor TEXT NOT NULL,
                details_json TEXT,
                checklist_snapshot TEXT
            );

            CREATE TRIGGER IF NOT EXISTS audit_log_no_update
            BEFORE UPDATE ON audit_log
            BEGIN
                SELECT RAISE(ABORT, 'audit_log is append-only');
            END;

            CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
            BEFORE DELETE ON audit_log
            BEGIN
                SELECT RAISE(ABORT, 'audit_log is append-only');
            END;

            ",
        )?;
        let existing_version: Option<i64> =
            self.conn
                .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
                    row.get(0)
                })?;
        if existing_version.is_some_and(|version| version > SCHEMA_VERSION) {
            return Err(StorageError::InvalidData(format!(
                "database schema version {} is newer than supported version {SCHEMA_VERSION}",
                existing_version.unwrap_or_default()
            )));
        }
        self.migrate_evaluation_log_retention()?;
        self.migrate_scanner_delivery_schema()?;
        self.recover_interrupted_scan_jobs()?;
        Ok(())
    }

    fn migrate_evaluation_log_retention(&self) -> StorageResult<()> {
        let on_delete = self.conn.query_row(
            "SELECT on_delete FROM pragma_foreign_key_list('evaluation_log') LIMIT 1",
            [],
            |row| row.get::<_, String>(0),
        )?;
        let checklist_id_not_null: i64 = self.conn.query_row(
            "SELECT [notnull] FROM pragma_table_info('evaluation_log') WHERE name = 'checklist_id'",
            [],
            |row| row.get(0),
        )?;
        if on_delete.eq_ignore_ascii_case("SET NULL") && checklist_id_not_null == 0 {
            return Ok(());
        }

        let tx = self.conn.unchecked_transaction()?;
        tx.execute_batch(
            "ALTER TABLE evaluation_log RENAME TO evaluation_log_legacy;
             CREATE TABLE evaluation_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                checklist_id TEXT,
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
                FOREIGN KEY (checklist_id) REFERENCES checklists(id) ON DELETE SET NULL
             );
             INSERT INTO evaluation_log
                SELECT * FROM evaluation_log_legacy;
             DROP TABLE evaluation_log_legacy;",
        )?;
        tx.commit()?;
        Ok(())
    }

    fn migrate_scanner_delivery_schema(&self) -> StorageResult<()> {
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS scan_runs (
                id TEXT PRIMARY KEY,
                checklist_id TEXT,
                asset_hostname TEXT NOT NULL,
                scanner_version TEXT NOT NULL,
                scan_source TEXT NOT NULL,
                stig_id TEXT NOT NULL,
                stig_revision TEXT NOT NULL,
                benchmark_sha256 TEXT NOT NULL,
                check_pack_sha256 TEXT NOT NULL,
                evaluation_plan_sha256 TEXT NOT NULL,
                evidence_sha256 TEXT NOT NULL,
                request_json TEXT NOT NULL,
                request_sha256 TEXT NOT NULL,
                result_json TEXT NOT NULL,
                result_sha256 TEXT NOT NULL,
                completed_at TEXT NOT NULL,
                created_at TEXT NOT NULL
             );

             CREATE INDEX IF NOT EXISTS idx_scan_runs_asset_completed
                ON scan_runs(asset_hostname, completed_at DESC);
             CREATE INDEX IF NOT EXISTS idx_scan_runs_stig_revision
                ON scan_runs(stig_id, stig_revision);

             CREATE TRIGGER IF NOT EXISTS scan_runs_no_update
             BEFORE UPDATE ON scan_runs
             BEGIN
                SELECT RAISE(ABORT, 'scan_runs is immutable');
             END;

             CREATE TRIGGER IF NOT EXISTS scan_runs_no_delete
             BEFORE DELETE ON scan_runs
             BEGIN
                SELECT RAISE(ABORT, 'scan_runs is immutable');
             END;

             CREATE TABLE IF NOT EXISTS scan_run_evidence_artifacts (
                run_id TEXT PRIMARY KEY,
                state TEXT NOT NULL CHECK (state IN ('retained', 'purged')),
                envelope_schema TEXT NOT NULL,
                evidence_sha256 TEXT NOT NULL,
                plaintext_sha256 TEXT NOT NULL,
                ciphertext_sha256 TEXT NOT NULL,
                ciphertext_size INTEGER NOT NULL CHECK (ciphertext_size > 0),
                algorithm TEXT NOT NULL,
                key_id TEXT NOT NULL,
                wrapped_dek_sha256 TEXT NOT NULL,
                ciphertext BLOB,
                wrapped_dek BLOB,
                sealed_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                purged_at TEXT,
                purge_reason TEXT CHECK (
                    purge_reason IS NULL OR purge_reason IN (
                        'retention_expired', 'operator_requested'
                    )
                ),
                FOREIGN KEY (run_id) REFERENCES scan_runs(id) ON DELETE RESTRICT,
                CHECK (
                    (state = 'retained' AND ciphertext IS NOT NULL
                        AND wrapped_dek IS NOT NULL AND purged_at IS NULL
                        AND purge_reason IS NULL)
                    OR
                    (state = 'purged' AND ciphertext IS NULL
                        AND wrapped_dek IS NULL AND purged_at IS NOT NULL
                        AND purge_reason IS NOT NULL)
                )
             );

             CREATE INDEX IF NOT EXISTS idx_scan_evidence_expiry
                ON scan_run_evidence_artifacts(state, expires_at);

             CREATE TRIGGER IF NOT EXISTS scan_run_evidence_no_delete
             BEFORE DELETE ON scan_run_evidence_artifacts
             BEGIN
                SELECT RAISE(ABORT, 'scan evidence metadata is retained');
             END;

             CREATE TRIGGER IF NOT EXISTS scan_run_evidence_one_way_purge
             BEFORE UPDATE ON scan_run_evidence_artifacts
             WHEN NOT (
                OLD.state = 'retained' AND NEW.state = 'purged'
                AND OLD.run_id IS NEW.run_id
                AND OLD.envelope_schema IS NEW.envelope_schema
                AND OLD.evidence_sha256 IS NEW.evidence_sha256
                AND OLD.plaintext_sha256 IS NEW.plaintext_sha256
                AND OLD.ciphertext_sha256 IS NEW.ciphertext_sha256
                AND OLD.ciphertext_size IS NEW.ciphertext_size
                AND OLD.algorithm IS NEW.algorithm
                AND OLD.key_id IS NEW.key_id
                AND OLD.wrapped_dek_sha256 IS NEW.wrapped_dek_sha256
                AND OLD.sealed_at IS NEW.sealed_at
                AND OLD.expires_at IS NEW.expires_at
                AND NEW.ciphertext IS NULL
                AND NEW.wrapped_dek IS NULL
                AND NEW.purged_at IS NOT NULL
                AND NEW.purge_reason IN ('retention_expired', 'operator_requested')
             )
             BEGIN
                SELECT RAISE(ABORT, 'scan evidence supports only one-way purge');
             END;

             CREATE TABLE IF NOT EXISTS scan_jobs (
                id TEXT PRIMARY KEY,
                sanitized_request_json TEXT NOT NULL,
                request_sha256 TEXT NOT NULL,
                created_at TEXT NOT NULL
             );

             CREATE TRIGGER IF NOT EXISTS scan_jobs_no_update
             BEFORE UPDATE ON scan_jobs
             BEGIN
                SELECT RAISE(ABORT, 'scan_jobs requests are immutable');
             END;

             CREATE TRIGGER IF NOT EXISTS scan_jobs_no_delete
             BEFORE DELETE ON scan_jobs
             BEGIN
                SELECT RAISE(ABORT, 'scan_jobs are retained');
             END;

             CREATE TABLE IF NOT EXISTS scan_job_transitions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id TEXT NOT NULL,
                state TEXT NOT NULL CHECK (
                    state IN ('queued', 'running', 'completed', 'failed')
                ),
                occurred_at TEXT NOT NULL,
                run_id TEXT,
                error TEXT,
                FOREIGN KEY (job_id) REFERENCES scan_jobs(id) ON DELETE RESTRICT,
                FOREIGN KEY (run_id) REFERENCES scan_runs(id) ON DELETE RESTRICT,
                CHECK (
                    (state IN ('queued', 'running') AND run_id IS NULL AND error IS NULL)
                    OR (state = 'completed' AND run_id IS NOT NULL AND error IS NULL)
                    OR (state = 'failed' AND run_id IS NULL AND error IS NOT NULL)
                )
             );

             CREATE INDEX IF NOT EXISTS idx_scan_job_transitions_job
                ON scan_job_transitions(job_id, id);

             CREATE TRIGGER IF NOT EXISTS scan_job_transitions_no_update
             BEFORE UPDATE ON scan_job_transitions
             BEGIN
                SELECT RAISE(ABORT, 'scan_job_transitions are append-only');
             END;

             CREATE TRIGGER IF NOT EXISTS scan_job_transitions_no_delete
             BEFORE DELETE ON scan_job_transitions
             BEGIN
                SELECT RAISE(ABORT, 'scan_job_transitions are append-only');
             END;

             CREATE TRIGGER IF NOT EXISTS scan_job_transition_ordered
             BEFORE INSERT ON scan_job_transitions
             WHEN NEW.occurred_at < COALESCE(
                (SELECT occurred_at FROM scan_job_transitions
                 WHERE job_id = NEW.job_id ORDER BY id DESC LIMIT 1),
                NEW.occurred_at
             )
             BEGIN
                SELECT RAISE(ABORT, 'scan job transition timestamp moved backwards');
             END;

             CREATE TRIGGER IF NOT EXISTS scan_job_transition_valid
             BEFORE INSERT ON scan_job_transitions
             WHEN CASE NEW.state
                WHEN 'queued' THEN EXISTS (
                    SELECT 1 FROM scan_job_transitions WHERE job_id = NEW.job_id
                )
                WHEN 'running' THEN COALESCE(
                    (SELECT state FROM scan_job_transitions
                     WHERE job_id = NEW.job_id ORDER BY id DESC LIMIT 1), ''
                ) <> 'queued'
                WHEN 'completed' THEN COALESCE(
                    (SELECT state FROM scan_job_transitions
                     WHERE job_id = NEW.job_id ORDER BY id DESC LIMIT 1), ''
                ) <> 'running'
                WHEN 'failed' THEN COALESCE(
                    (SELECT state FROM scan_job_transitions
                     WHERE job_id = NEW.job_id ORDER BY id DESC LIMIT 1), ''
                ) NOT IN ('queued', 'running')
                ELSE 1
             END
             BEGIN
                SELECT RAISE(ABORT, 'invalid scan job state transition');
             END;

             CREATE TABLE IF NOT EXISTS delivery_outbox (
                id TEXT PRIMARY KEY,
                scan_run_id TEXT NOT NULL,
                state TEXT NOT NULL CHECK (
                    state IN ('pending', 'sending', 'delivered', 'retryable', 'conflicted', 'rejected')
                ),
                destination_kind TEXT NOT NULL,
                destination_instance_id TEXT NOT NULL,
                destination_collection_id TEXT NOT NULL,
                destination_asset_id TEXT,
                stig_id TEXT NOT NULL,
                stig_revision TEXT NOT NULL,
                request_json TEXT NOT NULL,
                request_sha256 TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL,
                attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
                last_error TEXT,
                remote_receipt_json TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                first_attempted_at TEXT,
                last_attempted_at TEXT,
                delivered_at TEXT,
                next_attempt_at TEXT,
                claimed_by TEXT,
                claim_token TEXT,
                claim_expires_at TEXT,
                FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id) ON DELETE RESTRICT,
                CHECK (
                    (state = 'sending' AND claimed_by IS NOT NULL AND claim_token IS NOT NULL
                        AND claim_expires_at IS NOT NULL AND attempt_count > 0)
                    OR
                    (state <> 'sending' AND claimed_by IS NULL AND claim_token IS NULL
                        AND claim_expires_at IS NULL)
                ),
                CHECK ((state = 'delivered' AND delivered_at IS NOT NULL) OR state <> 'delivered'),
                CHECK ((state = 'delivered' AND remote_receipt_json IS NOT NULL) OR state <> 'delivered'),
                CHECK ((state IN ('retryable', 'conflicted', 'rejected') AND last_error IS NOT NULL)
                    OR state NOT IN ('retryable', 'conflicted', 'rejected'))
             );

             CREATE INDEX IF NOT EXISTS idx_delivery_outbox_claimable
                ON delivery_outbox(state, next_attempt_at, created_at);
             CREATE INDEX IF NOT EXISTS idx_delivery_outbox_run
                ON delivery_outbox(scan_run_id, created_at);
             CREATE UNIQUE INDEX IF NOT EXISTS idx_delivery_outbox_claim_token
                ON delivery_outbox(claim_token) WHERE claim_token IS NOT NULL;

             CREATE TRIGGER IF NOT EXISTS delivery_outbox_no_delete
             BEFORE DELETE ON delivery_outbox
             BEGIN
                SELECT RAISE(ABORT, 'delivery_outbox is retained');
             END;

             CREATE TRIGGER IF NOT EXISTS delivery_outbox_request_immutable
             BEFORE UPDATE ON delivery_outbox
             WHEN OLD.id IS NOT NEW.id
                OR OLD.scan_run_id IS NOT NEW.scan_run_id
                OR OLD.destination_kind IS NOT NEW.destination_kind
                OR OLD.destination_instance_id IS NOT NEW.destination_instance_id
                OR OLD.destination_collection_id IS NOT NEW.destination_collection_id
                OR OLD.stig_id IS NOT NEW.stig_id
                OR OLD.stig_revision IS NOT NEW.stig_revision
                OR OLD.request_json IS NOT NEW.request_json
                OR OLD.request_sha256 IS NOT NEW.request_sha256
                OR OLD.payload_json IS NOT NEW.payload_json
                OR OLD.payload_sha256 IS NOT NEW.payload_sha256
                OR OLD.created_at IS NOT NEW.created_at
             BEGIN
                SELECT RAISE(ABORT, 'delivery request and payload are immutable');
             END;

             CREATE TRIGGER IF NOT EXISTS delivery_outbox_state_transition
             BEFORE UPDATE OF state ON delivery_outbox
             WHEN OLD.state <> NEW.state AND NOT (
                (OLD.state IN ('pending', 'retryable') AND NEW.state = 'sending')
                OR (OLD.state = 'sending' AND NEW.state IN ('delivered', 'retryable', 'conflicted', 'rejected'))
                OR (OLD.state IN ('retryable', 'conflicted', 'rejected') AND NEW.state = 'pending')
             )
             BEGIN
                SELECT RAISE(ABORT, 'invalid delivery state transition');
             END;

             CREATE TABLE IF NOT EXISTS delivery_receipts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                delivery_id TEXT NOT NULL,
                attempt_number INTEGER NOT NULL CHECK (attempt_number > 0),
                outcome TEXT NOT NULL CHECK (
                    outcome IN ('delivered', 'retryable', 'conflicted', 'rejected')
                ),
                recorded_at TEXT NOT NULL,
                error TEXT,
                remote_receipt_json TEXT,
                FOREIGN KEY (delivery_id) REFERENCES delivery_outbox(id) ON DELETE RESTRICT,
                UNIQUE (delivery_id, attempt_number)
             );

             CREATE INDEX IF NOT EXISTS idx_delivery_receipts_delivery
                ON delivery_receipts(delivery_id, attempt_number);

             CREATE TRIGGER IF NOT EXISTS delivery_receipts_no_update
             BEFORE UPDATE ON delivery_receipts
             BEGIN
                SELECT RAISE(ABORT, 'delivery_receipts is append-only');
             END;

             CREATE TRIGGER IF NOT EXISTS delivery_receipts_no_delete
             BEFORE DELETE ON delivery_receipts
             BEGIN
                SELECT RAISE(ABORT, 'delivery_receipts is append-only');
             END;",
        )?;
        tx.execute("DELETE FROM schema_version", [])?;
        tx.execute(
            "INSERT INTO schema_version (version) VALUES (?1)",
            params![SCHEMA_VERSION],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn recover_interrupted_scan_jobs(&self) -> StorageResult<()> {
        let now = format_timestamp(Utc::now());
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let interrupted = {
            let mut statement = tx.prepare(
                "SELECT transition.job_id
                 FROM scan_job_transitions AS transition
                 WHERE transition.id = (
                    SELECT MAX(latest.id) FROM scan_job_transitions AS latest
                    WHERE latest.job_id = transition.job_id
                 )
                 AND transition.state IN ('queued', 'running')
                 ORDER BY transition.job_id",
            )?;
            let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        for job_id in interrupted {
            tx.execute(
                "INSERT INTO scan_job_transitions
                 (job_id, state, occurred_at, run_id, error)
                 VALUES (?1, 'failed', ?2, NULL, ?3)",
                params![job_id, now, INTERRUPTED_SCAN_JOB_ERROR],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Persist a queued scanner job before any device I/O begins.
    ///
    /// The request must already be stripped of credentials. Storage performs a
    /// second defensive check for common secret fields/material and verifies
    /// its caller-supplied SHA-256 digest before committing the job.
    pub fn create_scan_job(&self, job: &NewScanJob) -> StorageResult<ScanJobRecord> {
        self.create_scan_job_at(job, Utc::now())
    }

    fn create_scan_job_at(
        &self,
        job: &NewScanJob,
        created_at: DateTime<Utc>,
    ) -> StorageResult<ScanJobRecord> {
        validate_new_scan_job(job)?;
        let created_at = format_timestamp(created_at);
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO scan_jobs
             (id, sanitized_request_json, request_sha256, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                job.id,
                job.sanitized_request_json,
                job.request_sha256,
                created_at
            ],
        )?;
        tx.execute(
            "INSERT INTO scan_job_transitions
             (job_id, state, occurred_at, run_id, error)
             VALUES (?1, 'queued', ?2, NULL, NULL)",
            params![job.id, created_at],
        )?;
        let stored = query_scan_job(&tx, &job.id)?;
        tx.commit()?;
        Ok(stored)
    }

    /// Get the derived current state of one durable scanner job.
    pub fn get_scan_job(&self, id: &str) -> StorageResult<ScanJobRecord> {
        query_scan_job(&self.conn, id)
    }

    /// List scanner jobs newest first, optionally filtering by current state.
    pub fn list_scan_jobs(&self, state: Option<ScanJobState>) -> StorageResult<Vec<ScanJobRecord>> {
        let sql = format!(
            "SELECT {SCAN_JOB_COLUMNS}
             FROM scan_jobs AS job
             JOIN scan_job_transitions AS current ON current.id = (
                SELECT MAX(latest.id) FROM scan_job_transitions AS latest
                WHERE latest.job_id = job.id
             )
             WHERE (?1 IS NULL OR current.state = ?1)
             ORDER BY job.created_at DESC, job.id ASC"
        );
        let state = state.map(ScanJobState::as_str);
        let mut statement = self.conn.prepare(&sql)?;
        let rows = statement.query_map(params![state], scan_job_from_row)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Append the transition from `queued` to `running`.
    pub fn mark_scan_job_running(&self, job_id: &str) -> StorageResult<ScanJobRecord> {
        self.transition_scan_job_at(job_id, ScanJobState::Running, None, None, Utc::now())
    }

    /// Append the terminal `completed` transition and bind its immutable run.
    pub fn mark_scan_job_completed(
        &self,
        job_id: &str,
        run_id: &str,
    ) -> StorageResult<ScanJobRecord> {
        validate_required("scan run id", run_id)?;
        self.transition_scan_job_at(
            job_id,
            ScanJobState::Completed,
            Some(run_id),
            None,
            Utc::now(),
        )
    }

    /// Append a terminal failure. The message must be actionable and sanitized.
    pub fn mark_scan_job_failed(
        &self,
        job_id: &str,
        sanitized_error: &str,
    ) -> StorageResult<ScanJobRecord> {
        validate_required("scan job error", sanitized_error)?;
        validate_sanitized_text("scan job error", sanitized_error)?;
        self.transition_scan_job_at(
            job_id,
            ScanJobState::Failed,
            None,
            Some(sanitized_error),
            Utc::now(),
        )
    }

    fn transition_scan_job_at(
        &self,
        job_id: &str,
        state: ScanJobState,
        run_id: Option<&str>,
        error: Option<&str>,
        occurred_at: DateTime<Utc>,
    ) -> StorageResult<ScanJobRecord> {
        validate_required("scan job id", job_id)?;
        let occurred_at = format_timestamp(occurred_at);
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let current = query_scan_job(&tx, job_id)?;
        let valid = match state {
            ScanJobState::Running => current.state == ScanJobState::Queued,
            ScanJobState::Completed => current.state == ScanJobState::Running,
            ScanJobState::Failed => {
                matches!(current.state, ScanJobState::Queued | ScanJobState::Running)
            }
            ScanJobState::Queued => false,
        };
        if !valid {
            let expected = match state {
                ScanJobState::Running => ScanJobState::Queued.to_string(),
                ScanJobState::Completed => ScanJobState::Running.to_string(),
                ScanJobState::Failed => "queued or running".to_string(),
                ScanJobState::Queued => "new job creation".to_string(),
            };
            return Err(StorageError::InvalidScanJobState {
                job_id: job_id.to_string(),
                expected,
                actual: current.state.to_string(),
            });
        }
        if let Some(run_id) = run_id {
            query_scan_run(&tx, run_id)?;
        }
        tx.execute(
            "INSERT INTO scan_job_transitions
             (job_id, state, occurred_at, run_id, error)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![job_id, state.as_str(), occurred_at, run_id, error],
        )?;
        let stored = query_scan_job(&tx, job_id)?;
        tx.commit()?;
        Ok(stored)
    }

    /// List the immutable transition history for one scanner job.
    pub fn list_scan_job_transitions(
        &self,
        job_id: &str,
    ) -> StorageResult<Vec<ScanJobTransitionRecord>> {
        validate_required("scan job id", job_id)?;
        query_scan_job(&self.conn, job_id)?;
        let mut statement = self.conn.prepare(
            "SELECT id, job_id, state, occurred_at, run_id, error
             FROM scan_job_transitions WHERE job_id = ?1 ORDER BY id ASC",
        )?;
        let rows = statement.query_map(params![job_id], scan_job_transition_from_row)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Atomically save one legacy immutable completed scan and its initial
    /// pending delivery. Scanner-run v2 callers must use the evidence-bearing
    /// API below. If either insert fails, neither record is committed.
    pub fn save_completed_scan_run_with_pending_delivery(
        &self,
        run: &NewScanRun,
        delivery: &NewPendingDelivery,
    ) -> StorageResult<(ScanRunRecord, DeliveryRecord)> {
        validate_scan_run_without_encrypted_evidence(run)?;
        validate_pending_delivery(delivery)?;

        let created_at = format_timestamp(Utc::now());
        let completed_at = format_timestamp(run.completed_at);
        let run_request_sha256 = sha256_hex(&run.request_json);
        let result_sha256 = sha256_hex(&run.result_json);
        let delivery_request_sha256 = sha256_hex(&delivery.request_json);
        let payload_sha256 = sha256_hex(&delivery.payload_json);
        let next_attempt_at = delivery.not_before.map(format_timestamp);

        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO scan_runs
             (id, checklist_id, asset_hostname, scanner_version, scan_source, stig_id,
              stig_revision, benchmark_sha256, check_pack_sha256, evaluation_plan_sha256,
              evidence_sha256, request_json, request_sha256, result_json, result_sha256,
              completed_at, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                     ?15, ?16, ?17)",
            params![
                run.id,
                run.checklist_id,
                run.asset_hostname,
                run.scanner_version,
                run.scan_source,
                run.stig_id,
                run.stig_revision,
                run.benchmark_sha256,
                run.check_pack_sha256,
                run.evaluation_plan_sha256,
                run.evidence_sha256,
                run.request_json,
                run_request_sha256,
                run.result_json,
                result_sha256,
                completed_at,
                created_at,
            ],
        )?;
        tx.execute(
            "INSERT INTO delivery_outbox
             (id, scan_run_id, state, destination_kind, destination_instance_id,
              destination_collection_id, destination_asset_id, stig_id, stig_revision,
              request_json, request_sha256, payload_json, payload_sha256, created_at,
              updated_at, next_attempt_at)
             VALUES (?1, ?2, 'pending', ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                     ?12, ?13, ?13, ?14)",
            params![
                delivery.id,
                run.id,
                delivery.destination_kind,
                delivery.destination_instance_id,
                delivery.destination_collection_id,
                delivery.destination_asset_id,
                run.stig_id,
                run.stig_revision,
                delivery.request_json,
                delivery_request_sha256,
                delivery.payload_json,
                payload_sha256,
                created_at,
                next_attempt_at,
            ],
        )?;

        let stored_run = query_scan_run(&tx, &run.id)?;
        let stored_delivery = query_delivery(&tx, &delivery.id)?;
        tx.commit()?;
        Ok((stored_run, stored_delivery))
    }

    /// Save a legacy immutable completed scanner attempt without a delivery.
    /// Scanner-run v2 callers must use the evidence-bearing API below so a run
    /// can never be committed without its encrypted replay artifact.
    pub fn save_completed_scan_run(&self, run: &NewScanRun) -> StorageResult<ScanRunRecord> {
        validate_scan_run_without_encrypted_evidence(run)?;

        let created_at = format_timestamp(Utc::now());
        let completed_at = format_timestamp(run.completed_at);
        let request_sha256 = sha256_hex(&run.request_json);
        let result_sha256 = sha256_hex(&run.result_json);
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO scan_runs
             (id, checklist_id, asset_hostname, scanner_version, scan_source, stig_id,
              stig_revision, benchmark_sha256, check_pack_sha256, evaluation_plan_sha256,
              evidence_sha256, request_json, request_sha256, result_json, result_sha256,
              completed_at, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                     ?15, ?16, ?17)",
            params![
                run.id,
                run.checklist_id,
                run.asset_hostname,
                run.scanner_version,
                run.scan_source,
                run.stig_id,
                run.stig_revision,
                run.benchmark_sha256,
                run.check_pack_sha256,
                run.evaluation_plan_sha256,
                run.evidence_sha256,
                run.request_json,
                request_sha256,
                run.result_json,
                result_sha256,
                completed_at,
                created_at,
            ],
        )?;
        let stored = query_scan_run(&tx, &run.id)?;
        tx.commit()?;
        Ok(stored)
    }

    /// Atomically save one immutable scanner run and its encrypted replay
    /// evidence. A failure in either insert leaves no partial run behind.
    pub fn save_completed_scan_run_with_evidence(
        &self,
        run: &NewScanRun,
        evidence: &NewScanEvidenceArtifact,
    ) -> StorageResult<(ScanRunRecord, ScanEvidenceArtifactMetadata)> {
        validate_scan_run(run)?;
        validate_scan_evidence(run, evidence)?;

        let created_at = format_timestamp(Utc::now());
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        insert_scan_run(&tx, run, &created_at)?;
        insert_scan_evidence(&tx, evidence)?;
        let stored_run = query_scan_run(&tx, &run.id)?;
        let stored_evidence = query_scan_evidence_metadata(&tx, &run.id)?;
        tx.commit()?;
        Ok((stored_run, stored_evidence))
    }

    /// Atomically save one immutable scanner run, its encrypted replay
    /// evidence, and the initial pending delivery. This is the only release
    /// path for complete connected scanner runs.
    pub fn save_completed_scan_run_with_evidence_and_pending_delivery(
        &self,
        run: &NewScanRun,
        evidence: &NewScanEvidenceArtifact,
        delivery: &NewPendingDelivery,
    ) -> StorageResult<(ScanRunRecord, ScanEvidenceArtifactMetadata, DeliveryRecord)> {
        validate_scan_run(run)?;
        validate_scan_evidence(run, evidence)?;
        validate_pending_delivery(delivery)?;

        let created_at = format_timestamp(Utc::now());
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        insert_scan_run(&tx, run, &created_at)?;
        insert_scan_evidence(&tx, evidence)?;
        insert_pending_delivery(&tx, run, delivery, &created_at)?;
        let stored_run = query_scan_run(&tx, &run.id)?;
        let stored_evidence = query_scan_evidence_metadata(&tx, &run.id)?;
        let stored_delivery = query_delivery(&tx, &delivery.id)?;
        tx.commit()?;
        Ok((stored_run, stored_evidence, stored_delivery))
    }

    /// Read non-secret evidence lifecycle metadata without loading ciphertext.
    pub fn get_scan_evidence_metadata(
        &self,
        run_id: &str,
    ) -> StorageResult<ScanEvidenceArtifactMetadata> {
        query_scan_evidence_metadata(&self.conn, run_id)
    }

    /// Load retained encrypted evidence, enforcing its expiry synchronously.
    /// Expired evidence is purged before this method returns an error, so a
    /// delayed background cleanup cannot extend the configured retention.
    pub fn load_retained_scan_evidence(
        &self,
        run_id: &str,
    ) -> StorageResult<RetainedScanEvidenceArtifact> {
        self.load_retained_scan_evidence_at(run_id, Utc::now())
    }

    fn load_retained_scan_evidence_at(
        &self,
        run_id: &str,
        now: DateTime<Utc>,
    ) -> StorageResult<RetainedScanEvidenceArtifact> {
        let metadata = query_scan_evidence_metadata(&self.conn, run_id)?;
        if metadata.state == ScanEvidenceState::Purged {
            return Err(StorageError::NotFound(format!(
                "Replay evidence for scan run {run_id} was purged"
            )));
        }
        let expires_at = parse_timestamp("scan evidence expires_at", &metadata.expires_at)?;
        if expires_at <= now {
            self.purge_scan_evidence_at(run_id, ScanEvidencePurgeReason::RetentionExpired, now)?;
            return Err(StorageError::NotFound(format!(
                "Replay evidence for scan run {run_id} expired"
            )));
        }
        query_retained_scan_evidence(&self.conn, run_id)
    }

    /// Irreversibly remove ciphertext and its wrapped data-encryption key while
    /// retaining immutable provenance hashes and purge metadata.
    pub fn purge_scan_evidence(
        &self,
        run_id: &str,
        reason: ScanEvidencePurgeReason,
    ) -> StorageResult<ScanEvidenceArtifactMetadata> {
        self.purge_scan_evidence_at(run_id, reason, Utc::now())
    }

    fn purge_scan_evidence_at(
        &self,
        run_id: &str,
        reason: ScanEvidencePurgeReason,
        now: DateTime<Utc>,
    ) -> StorageResult<ScanEvidenceArtifactMetadata> {
        validate_required("scan run id", run_id)?;
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let current = query_scan_evidence_metadata(&tx, run_id)?;
        if current.state == ScanEvidenceState::Purged {
            tx.commit()?;
            // A prior purge may have committed while an independent reader
            // prevented WAL truncation. Idempotent retries must retry the
            // physical cleanup as well as return the stable purge metadata.
            self.checkpoint_sensitive_deletions()?;
            return Ok(current);
        }
        tx.execute(
            "UPDATE scan_run_evidence_artifacts
             SET state = 'purged', ciphertext = NULL, wrapped_dek = NULL,
                 purged_at = ?2, purge_reason = ?3
             WHERE run_id = ?1 AND state = 'retained'",
            params![run_id, format_timestamp(now), reason.as_str()],
        )?;
        let stored = query_scan_evidence_metadata(&tx, run_id)?;
        tx.commit()?;
        self.checkpoint_sensitive_deletions()?;
        Ok(stored)
    }

    /// Purge a bounded batch of expired artifacts. The caller may repeat this
    /// at startup and periodically until an empty batch is returned.
    pub fn purge_expired_scan_evidence(
        &self,
        limit: usize,
    ) -> StorageResult<Vec<ScanEvidenceArtifactMetadata>> {
        self.purge_expired_scan_evidence_at(Utc::now(), limit)
    }

    fn purge_expired_scan_evidence_at(
        &self,
        now: DateTime<Utc>,
        limit: usize,
    ) -> StorageResult<Vec<ScanEvidenceArtifactMetadata>> {
        if !(1..=10_000).contains(&limit) {
            return Err(StorageError::InvalidData(
                "evidence purge batch limit must be between 1 and 10000".to_string(),
            ));
        }
        let now_text = format_timestamp(now);
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let run_ids = {
            let mut statement = tx.prepare(
                "SELECT run_id FROM scan_run_evidence_artifacts
                 WHERE state = 'retained' AND expires_at <= ?1
                 ORDER BY expires_at ASC, run_id ASC LIMIT ?2",
            )?;
            let rows = statement.query_map(params![now_text, limit as i64], |row| row.get(0))?;
            rows.collect::<Result<Vec<String>, _>>()?
        };
        let mut purged = Vec::with_capacity(run_ids.len());
        for run_id in &run_ids {
            tx.execute(
                "UPDATE scan_run_evidence_artifacts
                 SET state = 'purged', ciphertext = NULL, wrapped_dek = NULL,
                     purged_at = ?2, purge_reason = 'retention_expired'
                 WHERE run_id = ?1 AND state = 'retained'",
                params![run_id, now_text],
            )?;
            purged.push(query_scan_evidence_metadata(&tx, run_id)?);
        }
        tx.commit()?;
        // Run even for an empty batch so the periodic/startup sweep retries a
        // checkpoint which a long-lived reader may previously have blocked.
        self.checkpoint_sensitive_deletions()?;
        Ok(purged)
    }

    fn checkpoint_sensitive_deletions(&self) -> StorageResult<()> {
        // With a per-run wrapped DEK the row transition is already a
        // cryptographic purge. Truncating WAL frames prevents an ordinary
        // filesystem copy from retaining the pre-purge row as well.
        let (busy, _, _) = self
            .conn
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?;
        if busy != 0 {
            return Err(StorageError::InvalidData(
                "sensitive WAL cleanup is busy and must be retried".to_string(),
            ));
        }
        Ok(())
    }

    /// Get one immutable scanner run by ID.
    pub fn get_scan_run(&self, id: &str) -> StorageResult<ScanRunRecord> {
        query_scan_run(&self.conn, id)
    }

    /// List immutable scanner runs, newest completion first.
    pub fn list_scan_runs(&self) -> StorageResult<Vec<ScanRunRecord>> {
        let mut statement = self.conn.prepare(
            "SELECT id, checklist_id, asset_hostname, scanner_version, scan_source, stig_id,
                    stig_revision, benchmark_sha256, check_pack_sha256,
                    evaluation_plan_sha256, evidence_sha256, request_json, request_sha256,
                    result_json, result_sha256, completed_at, created_at
             FROM scan_runs ORDER BY completed_at DESC, id ASC",
        )?;
        let rows = statement.query_map([], scan_run_from_row)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Get the current durable state of one delivery.
    pub fn get_delivery(&self, id: &str) -> StorageResult<DeliveryRecord> {
        query_delivery(&self.conn, id)
    }

    /// List deliveries, optionally filtering by their current state.
    pub fn list_deliveries(
        &self,
        state: Option<DeliveryState>,
    ) -> StorageResult<Vec<DeliveryRecord>> {
        let sql = format!(
            "SELECT {DELIVERY_COLUMNS} FROM delivery_outbox
             WHERE (?1 IS NULL OR state = ?1)
             ORDER BY created_at ASC, id ASC"
        );
        let state = state.map(|value| value.as_str());
        let mut statement = self.conn.prepare(&sql)?;
        let rows = statement.query_map(params![state], delivery_from_row)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// List all deliveries created for one scan run.
    pub fn list_deliveries_for_run(&self, scan_run_id: &str) -> StorageResult<Vec<DeliveryRecord>> {
        let sql = format!(
            "SELECT {DELIVERY_COLUMNS} FROM delivery_outbox
             WHERE scan_run_id = ?1 ORDER BY created_at ASC, id ASC"
        );
        let mut statement = self.conn.prepare(&sql)?;
        let rows = statement.query_map(params![scan_run_id], delivery_from_row)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Claim the next due pending/retryable delivery with an expiring lease.
    pub fn claim_next_delivery(
        &self,
        worker_id: &str,
        claim_token: &str,
        lease_for: StdDuration,
    ) -> StorageResult<Option<DeliveryRecord>> {
        self.claim_next_delivery_at(worker_id, claim_token, Utc::now(), lease_for)
    }

    /// Claim one explicit due delivery. Interactive retry endpoints use this
    /// instead of claiming an unrelated queue head.
    pub fn claim_delivery(
        &self,
        delivery_id: &str,
        worker_id: &str,
        claim_token: &str,
        lease_for: StdDuration,
    ) -> StorageResult<DeliveryRecord> {
        self.claim_delivery_at(delivery_id, worker_id, claim_token, Utc::now(), lease_for)
    }

    /// Deterministic variant of [`Self::claim_delivery`]. Before claiming the
    /// selected delivery, this recovers every expired `sending` lease in the
    /// same immediate transaction so a worker crash cannot strand the request.
    pub fn claim_delivery_at(
        &self,
        delivery_id: &str,
        worker_id: &str,
        claim_token: &str,
        now: DateTime<Utc>,
        lease_for: StdDuration,
    ) -> StorageResult<DeliveryRecord> {
        validate_required("delivery_id", delivery_id)?;
        validate_required("worker_id", worker_id)?;
        validate_required("claim_token", claim_token)?;
        if lease_for.is_zero() {
            return Err(StorageError::InvalidData(
                "delivery lease must be longer than zero".to_string(),
            ));
        }
        let lease_delta = chrono::Duration::from_std(lease_for).map_err(|_| {
            StorageError::InvalidData("delivery lease is too large to represent".to_string())
        })?;
        let expires_at = now.checked_add_signed(lease_delta).ok_or_else(|| {
            StorageError::InvalidData("delivery lease expiration overflowed".to_string())
        })?;
        let now = format_timestamp(now);
        let expires_at = format_timestamp(expires_at);

        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        recover_expired_delivery_claims(&tx, &now)?;
        let current = query_delivery(&tx, delivery_id)?;
        if !matches!(
            current.state,
            DeliveryState::Pending | DeliveryState::Retryable
        ) {
            return Err(StorageError::InvalidDeliveryState {
                delivery_id: delivery_id.to_string(),
                expected: "pending or retryable".to_string(),
                actual: current.state.to_string(),
            });
        }
        if current
            .next_attempt_at
            .as_deref()
            .is_some_and(|not_before| not_before > now.as_str())
        {
            return Err(StorageError::InvalidDeliveryState {
                delivery_id: delivery_id.to_string(),
                expected: "due for delivery".to_string(),
                actual: format!(
                    "scheduled for {}",
                    current.next_attempt_at.unwrap_or_default()
                ),
            });
        }
        let updated = tx.execute(
            "UPDATE delivery_outbox
             SET state = 'sending', attempt_count = attempt_count + 1,
                 first_attempted_at = COALESCE(first_attempted_at, ?2),
                 last_attempted_at = ?2, updated_at = ?2, next_attempt_at = NULL,
                 claimed_by = ?3, claim_token = ?4, claim_expires_at = ?5
             WHERE id = ?1 AND state IN ('pending', 'retryable')
               AND (next_attempt_at IS NULL OR next_attempt_at <= ?2)",
            params![delivery_id, now, worker_id, claim_token, expires_at],
        )?;
        if updated != 1 {
            return Err(StorageError::DeliveryClaimLost(delivery_id.to_string()));
        }
        let delivery = query_delivery(&tx, delivery_id)?;
        tx.commit()?;
        Ok(delivery)
    }

    /// Deterministic variant of [`Self::claim_next_delivery`], useful to queue
    /// schedulers and restart recovery tests that operate from an explicit clock.
    pub fn claim_next_delivery_at(
        &self,
        worker_id: &str,
        claim_token: &str,
        now: DateTime<Utc>,
        lease_for: StdDuration,
    ) -> StorageResult<Option<DeliveryRecord>> {
        validate_required("worker_id", worker_id)?;
        validate_required("claim_token", claim_token)?;
        if lease_for.is_zero() {
            return Err(StorageError::InvalidData(
                "delivery lease must be longer than zero".to_string(),
            ));
        }
        let lease_delta = chrono::Duration::from_std(lease_for).map_err(|_| {
            StorageError::InvalidData("delivery lease is too large to represent".to_string())
        })?;
        let expires_at = now.checked_add_signed(lease_delta).ok_or_else(|| {
            StorageError::InvalidData("delivery lease expiration overflowed".to_string())
        })?;
        let now = format_timestamp(now);
        let expires_at = format_timestamp(expires_at);

        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        recover_expired_delivery_claims(&tx, &now)?;
        let candidate: Option<String> = tx
            .query_row(
                "SELECT id FROM delivery_outbox
                 WHERE state IN ('pending', 'retryable')
                   AND (next_attempt_at IS NULL OR next_attempt_at <= ?1)
                 ORDER BY COALESCE(next_attempt_at, created_at), created_at, id
                 LIMIT 1",
                params![now],
                |row| row.get(0),
            )
            .optional()?;

        let Some(delivery_id) = candidate else {
            tx.commit()?;
            return Ok(None);
        };
        let updated = tx.execute(
            "UPDATE delivery_outbox
             SET state = 'sending', attempt_count = attempt_count + 1,
                 first_attempted_at = COALESCE(first_attempted_at, ?2),
                 last_attempted_at = ?2, updated_at = ?2, next_attempt_at = NULL,
                 claimed_by = ?3, claim_token = ?4, claim_expires_at = ?5
             WHERE id = ?1 AND state IN ('pending', 'retryable')
               AND (next_attempt_at IS NULL OR next_attempt_at <= ?2)",
            params![delivery_id, now, worker_id, claim_token, expires_at],
        )?;
        if updated != 1 {
            return Err(StorageError::DeliveryClaimLost(delivery_id));
        }
        let delivery = query_delivery(&tx, &delivery_id)?;
        tx.commit()?;
        Ok(Some(delivery))
    }

    /// Persist an asset ID learned after a remote create call while retaining
    /// ownership checks for the active delivery claim.
    pub fn update_delivery_destination_asset_id(
        &self,
        delivery_id: &str,
        claim_token: &str,
        destination_asset_id: &str,
    ) -> StorageResult<DeliveryRecord> {
        validate_required("destination_asset_id", destination_asset_id)?;
        let now = format_timestamp(Utc::now());
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let current = query_delivery(&tx, delivery_id)?;
        ensure_active_claim(&current, claim_token)?;
        tx.execute(
            "UPDATE delivery_outbox
             SET destination_asset_id = ?2, updated_at = ?3
             WHERE id = ?1 AND state = 'sending' AND claim_token = ?4",
            params![delivery_id, destination_asset_id, now, claim_token],
        )?;
        let delivery = query_delivery(&tx, delivery_id)?;
        tx.commit()?;
        Ok(delivery)
    }

    /// Mark the active claim delivered and append its immutable remote receipt.
    pub fn mark_delivery_delivered(
        &self,
        delivery_id: &str,
        claim_token: &str,
        remote_receipt_json: &str,
        destination_asset_id: Option<&str>,
    ) -> StorageResult<DeliveryRecord> {
        self.finish_delivery(
            delivery_id,
            claim_token,
            DeliveryFinish {
                outcome: DeliveryState::Delivered,
                error: None,
                remote_receipt_json: Some(remote_receipt_json),
                destination_asset_id,
                retry_at: None,
            },
        )
    }

    /// Release the active claim after a transient failure and schedule retry.
    pub fn mark_delivery_retryable(
        &self,
        delivery_id: &str,
        claim_token: &str,
        error: &str,
        remote_receipt_json: Option<&str>,
        retry_at: Option<DateTime<Utc>>,
    ) -> StorageResult<DeliveryRecord> {
        self.finish_delivery(
            delivery_id,
            claim_token,
            DeliveryFinish {
                outcome: DeliveryState::Retryable,
                error: Some(error),
                remote_receipt_json,
                destination_asset_id: None,
                retry_at,
            },
        )
    }

    /// Mark the active claim as a remote-state conflict requiring review.
    pub fn mark_delivery_conflicted(
        &self,
        delivery_id: &str,
        claim_token: &str,
        error: &str,
        remote_receipt_json: Option<&str>,
    ) -> StorageResult<DeliveryRecord> {
        self.finish_delivery(
            delivery_id,
            claim_token,
            DeliveryFinish {
                outcome: DeliveryState::Conflicted,
                error: Some(error),
                remote_receipt_json,
                destination_asset_id: None,
                retry_at: None,
            },
        )
    }

    /// Mark the active claim rejected by the destination.
    pub fn mark_delivery_rejected(
        &self,
        delivery_id: &str,
        claim_token: &str,
        error: &str,
        remote_receipt_json: Option<&str>,
    ) -> StorageResult<DeliveryRecord> {
        self.finish_delivery(
            delivery_id,
            claim_token,
            DeliveryFinish {
                outcome: DeliveryState::Rejected,
                error: Some(error),
                remote_receipt_json,
                destination_asset_id: None,
                retry_at: None,
            },
        )
    }

    /// Explicitly move a retryable/conflicted/rejected delivery back to pending.
    pub fn retry_delivery(
        &self,
        delivery_id: &str,
        not_before: Option<DateTime<Utc>>,
    ) -> StorageResult<DeliveryRecord> {
        let now = format_timestamp(Utc::now());
        let not_before = not_before.map(format_timestamp);
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let current = query_delivery(&tx, delivery_id)?;
        if !matches!(
            current.state,
            DeliveryState::Retryable | DeliveryState::Conflicted | DeliveryState::Rejected
        ) {
            return Err(StorageError::InvalidDeliveryState {
                delivery_id: delivery_id.to_string(),
                expected: "retryable, conflicted, or rejected".to_string(),
                actual: current.state.to_string(),
            });
        }
        tx.execute(
            "UPDATE delivery_outbox
             SET state = 'pending', updated_at = ?2, next_attempt_at = ?3,
                 claimed_by = NULL, claim_token = NULL, claim_expires_at = NULL
             WHERE id = ?1",
            params![delivery_id, now, not_before],
        )?;
        let delivery = query_delivery(&tx, delivery_id)?;
        tx.commit()?;
        Ok(delivery)
    }

    /// List the immutable terminal receipts for a delivery, in attempt order.
    pub fn list_delivery_receipts(&self, delivery_id: &str) -> StorageResult<Vec<DeliveryReceipt>> {
        let mut statement = self.conn.prepare(
            "SELECT id, delivery_id, attempt_number, outcome, recorded_at, error,
                    remote_receipt_json
             FROM delivery_receipts WHERE delivery_id = ?1 ORDER BY attempt_number ASC",
        )?;
        let rows = statement.query_map(params![delivery_id], delivery_receipt_from_row)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    fn finish_delivery(
        &self,
        delivery_id: &str,
        claim_token: &str,
        finish: DeliveryFinish<'_>,
    ) -> StorageResult<DeliveryRecord> {
        let DeliveryFinish {
            outcome,
            error,
            remote_receipt_json,
            destination_asset_id,
            retry_at,
        } = finish;
        if !matches!(
            outcome,
            DeliveryState::Delivered
                | DeliveryState::Retryable
                | DeliveryState::Conflicted
                | DeliveryState::Rejected
        ) {
            return Err(StorageError::InvalidData(format!(
                "{outcome} is not a terminal attempt outcome"
            )));
        }
        if outcome == DeliveryState::Delivered && remote_receipt_json.is_none() {
            return Err(StorageError::InvalidData(
                "delivered state requires a remote receipt".to_string(),
            ));
        }
        if outcome != DeliveryState::Delivered {
            validate_required("delivery error", error.unwrap_or_default())?;
        }
        if let Some(receipt) = remote_receipt_json {
            validate_json("remote_receipt_json", receipt)?;
        }
        if let Some(asset_id) = destination_asset_id {
            validate_required("destination_asset_id", asset_id)?;
        }

        let now = format_timestamp(Utc::now());
        let retry_at = retry_at.map(format_timestamp);
        let delivered_at = (outcome == DeliveryState::Delivered).then(|| now.clone());
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let current = query_delivery(&tx, delivery_id)?;
        ensure_active_claim(&current, claim_token)?;
        let updated = tx.execute(
            "UPDATE delivery_outbox
             SET state = ?3,
                 destination_asset_id = COALESCE(?4, destination_asset_id),
                 last_error = ?5, remote_receipt_json = ?6, updated_at = ?7,
                 delivered_at = ?8, next_attempt_at = ?9,
                 claimed_by = NULL, claim_token = NULL, claim_expires_at = NULL
             WHERE id = ?1 AND state = 'sending' AND claim_token = ?2",
            params![
                delivery_id,
                claim_token,
                outcome.as_str(),
                destination_asset_id,
                error,
                remote_receipt_json,
                now,
                delivered_at,
                retry_at,
            ],
        )?;
        if updated != 1 {
            return Err(StorageError::DeliveryClaimLost(delivery_id.to_string()));
        }
        tx.execute(
            "INSERT INTO delivery_receipts
             (delivery_id, attempt_number, outcome, recorded_at, error, remote_receipt_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                delivery_id,
                current.attempt_count,
                outcome.as_str(),
                now,
                error,
                remote_receipt_json,
            ],
        )?;
        let delivery = query_delivery(&tx, delivery_id)?;
        tx.commit()?;
        Ok(delivery)
    }

    /// Atomically persist a completed evaluation and both history records.
    pub fn save_evaluation(
        &self,
        checklist: &Checklist,
        source: &str,
        details: Option<&str>,
    ) -> StorageResult<()> {
        if let Some(reason) = incomplete_evaluation_reason(checklist) {
            return Err(StorageError::IncompleteEvaluation(reason));
        }
        let data_json = serde_json::to_string(checklist)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        let tx = self.conn.unchecked_transaction()?;
        save_checklist_row(&tx, checklist, &data_json)?;
        insert_evaluation_log(&tx, checklist, source, details)?;
        insert_audit_event(
            &tx,
            Some(&checklist.id.to_string()),
            "evaluation.completed",
            source,
            details,
            Some(&data_json),
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Append an incomplete-attempt audit event without persisting a partial
    /// checklist or an evaluation-history row that could be mistaken for a
    /// completed result.
    pub fn record_incomplete_evaluation(
        &self,
        actor: &str,
        details_json: &str,
    ) -> StorageResult<()> {
        let tx = self.conn.unchecked_transaction()?;
        insert_audit_event(
            &tx,
            None,
            "evaluation.incomplete",
            actor,
            Some(details_json),
            None,
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Atomically update a checklist and append an immutable audit event.
    pub fn save_checklist_with_audit(
        &self,
        checklist: &Checklist,
        event_type: &str,
        actor: &str,
        details_json: Option<&str>,
    ) -> StorageResult<()> {
        let data_json = serde_json::to_string(checklist)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        let tx = self.conn.unchecked_transaction()?;
        save_checklist_row(&tx, checklist, &data_json)?;
        insert_audit_event(
            &tx,
            Some(&checklist.id.to_string()),
            event_type,
            actor,
            details_json,
            Some(&data_json),
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Load a checklist by ID.
    pub fn load_checklist(&self, id: &str) -> StorageResult<Checklist> {
        let data_json = self.load_checklist_json(id)?;

        serde_json::from_str(&data_json).map_err(|e| StorageError::Serialization(e.to_string()))
    }

    /// Load the exact retained checklist JSON without interpreting or
    /// rewriting finding attribution. Transition tooling uses this to preserve
    /// even a legacy row that the current model cannot deserialize.
    pub fn load_checklist_json(&self, id: &str) -> StorageResult<String> {
        self.conn
            .query_row(
                "SELECT data_json FROM checklists WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )
            .map_err(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => {
                    StorageError::NotFound(format!("Checklist {id}"))
                }
                other => other.into(),
            })
    }

    /// List all checklists (returns summary info, not full data).
    pub fn list_checklists(&self) -> StorageResult<Vec<ChecklistSummaryRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, asset_hostname, stig_id, stig_title, stig_version, created_at, modified_at
             FROM checklists ORDER BY modified_at DESC",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(ChecklistSummaryRow {
                id: row.get(0)?,
                asset_hostname: row.get(1)?,
                stig_id: row.get(2)?,
                stig_title: row.get(3)?,
                stig_version: row.get(4)?,
                created_at: row.get(5)?,
                modified_at: row.get(6)?,
            })
        })?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    /// Read retained evaluation history in append order for transition export.
    pub fn list_evaluation_history(&self) -> StorageResult<Vec<EvaluationHistoryRecord>> {
        let mut statement = self.conn.prepare(
            "SELECT id, checklist_id, asset_hostname, stig_id, evaluated_at, total_rules,
                    open_count, naf_count, na_count, nr_count, source, details
             FROM evaluation_log ORDER BY id ASC",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(EvaluationHistoryRecord {
                id: row.get(0)?,
                checklist_id: row.get(1)?,
                asset_hostname: row.get(2)?,
                stig_id: row.get(3)?,
                evaluated_at: row.get(4)?,
                total_rules: row.get(5)?,
                open_count: row.get(6)?,
                not_a_finding_count: row.get(7)?,
                not_applicable_count: row.get(8)?,
                not_reviewed_count: row.get(9)?,
                source: row.get(10)?,
                details: row.get(11)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Read the preserved legacy answer-file registry in append order.
    ///
    /// Current answer templates live in the library. These rows are retained
    /// only so a transition export does not silently lose historical paths and
    /// attribution from an older release.
    pub fn list_answer_file_registry(&self) -> StorageResult<Vec<AnswerFileRegistryRecord>> {
        let mut statement = self.conn.prepare(
            "SELECT id, name, stig_id, file_path, version, entry_count, registered_at
             FROM answer_file_registry ORDER BY id ASC",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(AnswerFileRegistryRecord {
                id: row.get(0)?,
                name: row.get(1)?,
                stig_id: row.get(2)?,
                file_path: row.get(3)?,
                version: row.get(4)?,
                entry_count: row.get(5)?,
                registered_at: row.get(6)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Delete a checklist by ID.
    pub fn delete_checklist(&self, id: &str) -> StorageResult<bool> {
        let snapshot = match self.conn.query_row(
            "SELECT data_json FROM checklists WHERE id = ?1",
            params![id],
            |row| row.get::<_, String>(0),
        ) {
            Ok(snapshot) => snapshot,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        let tx = self.conn.unchecked_transaction()?;
        insert_audit_event(
            &tx,
            Some(id),
            "checklist.deleted",
            "application",
            None,
            Some(&snapshot),
        )?;
        let affected = tx.execute("DELETE FROM checklists WHERE id = ?1", params![id])?;
        tx.commit()?;
        Ok(affected > 0)
    }

    /// Read the immutable audit trail in append order.
    pub fn list_audit_events(&self) -> StorageResult<Vec<AuditEvent>> {
        let mut statement = self.conn.prepare(
            "SELECT id, checklist_id, event_type, occurred_at, actor, details_json, checklist_snapshot
             FROM audit_log ORDER BY id ASC",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(AuditEvent {
                id: row.get(0)?,
                checklist_id: row.get(1)?,
                event_type: row.get(2)?,
                occurred_at: row.get(3)?,
                actor: row.get(4)?,
                details_json: row.get(5)?,
                checklist_snapshot: row.get(6)?,
            })
        })?;

        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Get or set an app configuration value.
    pub fn get_config(&self, key: &str) -> StorageResult<Option<String>> {
        let result = self.conn.query_row(
            "SELECT value FROM app_config WHERE key = ?1",
            params![key],
            |row| row.get(0),
        );

        match result {
            Ok(val) => Ok(Some(val)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(StorageError::Database(e)),
        }
    }

    pub fn set_config(&self, key: &str, value: &str) -> StorageResult<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO app_config (key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
        Ok(())
    }

    /// Delete an app configuration value, returning whether it existed.
    pub fn delete_config(&self, key: &str) -> StorageResult<bool> {
        let affected = self
            .conn
            .execute("DELETE FROM app_config WHERE key = ?1", params![key])?;
        Ok(affected > 0)
    }

    #[cfg(test)]
    fn count_audit_events(&self, checklist_id: &str) -> StorageResult<usize> {
        Ok(self.conn.query_row(
            "SELECT COUNT(*) FROM audit_log WHERE checklist_id = ?1",
            params![checklist_id],
            |row| row.get(0),
        )?)
    }
}

const SCAN_JOB_COLUMNS: &str = "job.id, current.state, job.sanitized_request_json,
     job.request_sha256, job.created_at, current.occurred_at,
     (SELECT started.occurred_at FROM scan_job_transitions AS started
      WHERE started.job_id = job.id AND started.state = 'running'
      ORDER BY started.id ASC LIMIT 1),
     CASE WHEN current.state IN ('completed', 'failed') THEN current.occurred_at ELSE NULL END,
     current.run_id, current.error";

const DELIVERY_COLUMNS: &str = "id, scan_run_id, state, destination_kind, destination_instance_id,
     destination_collection_id, destination_asset_id, stig_id, stig_revision,
     request_json, request_sha256, payload_json, payload_sha256, attempt_count,
     last_error, remote_receipt_json, created_at, updated_at, first_attempted_at,
     last_attempted_at, delivered_at, next_attempt_at, claimed_by, claim_token,
     claim_expires_at";

const SCAN_EVIDENCE_METADATA_COLUMNS: &str = "run_id, state, envelope_schema, evidence_sha256,
     plaintext_sha256, ciphertext_sha256, ciphertext_size, algorithm, key_id,
     wrapped_dek_sha256, sealed_at, expires_at, purged_at, purge_reason";

fn insert_scan_run(tx: &Transaction<'_>, run: &NewScanRun, created_at: &str) -> StorageResult<()> {
    tx.execute(
        "INSERT INTO scan_runs
         (id, checklist_id, asset_hostname, scanner_version, scan_source, stig_id,
          stig_revision, benchmark_sha256, check_pack_sha256, evaluation_plan_sha256,
          evidence_sha256, request_json, request_sha256, result_json, result_sha256,
          completed_at, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                 ?15, ?16, ?17)",
        params![
            run.id,
            run.checklist_id,
            run.asset_hostname,
            run.scanner_version,
            run.scan_source,
            run.stig_id,
            run.stig_revision,
            run.benchmark_sha256,
            run.check_pack_sha256,
            run.evaluation_plan_sha256,
            run.evidence_sha256,
            run.request_json,
            sha256_hex(&run.request_json),
            run.result_json,
            sha256_hex(&run.result_json),
            format_timestamp(run.completed_at),
            created_at,
        ],
    )?;
    Ok(())
}

fn insert_scan_evidence(
    tx: &Transaction<'_>,
    evidence: &NewScanEvidenceArtifact,
) -> StorageResult<()> {
    let ciphertext_size = u64::try_from(evidence.ciphertext.len()).map_err(|_| {
        StorageError::InvalidData("encrypted scan evidence size does not fit u64".to_string())
    })?;
    tx.execute(
        "INSERT INTO scan_run_evidence_artifacts
         (run_id, state, envelope_schema, evidence_sha256, plaintext_sha256,
          ciphertext_sha256, ciphertext_size, algorithm, key_id,
          wrapped_dek_sha256, ciphertext, wrapped_dek, sealed_at, expires_at,
          purged_at, purge_reason)
         VALUES (?1, 'retained', ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                 ?12, ?13, NULL, NULL)",
        params![
            evidence.run_id,
            evidence.envelope_schema,
            evidence.evidence_sha256,
            evidence.plaintext_sha256,
            evidence.ciphertext_sha256,
            ciphertext_size,
            evidence.algorithm,
            evidence.key_id,
            evidence.wrapped_dek_sha256,
            evidence.ciphertext,
            evidence.wrapped_dek,
            format_timestamp(evidence.sealed_at),
            format_timestamp(evidence.expires_at),
        ],
    )?;
    Ok(())
}

fn insert_pending_delivery(
    tx: &Transaction<'_>,
    run: &NewScanRun,
    delivery: &NewPendingDelivery,
    created_at: &str,
) -> StorageResult<()> {
    tx.execute(
        "INSERT INTO delivery_outbox
         (id, scan_run_id, state, destination_kind, destination_instance_id,
          destination_collection_id, destination_asset_id, stig_id, stig_revision,
          request_json, request_sha256, payload_json, payload_sha256, created_at,
          updated_at, next_attempt_at)
         VALUES (?1, ?2, 'pending', ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                 ?12, ?13, ?13, ?14)",
        params![
            delivery.id,
            run.id,
            delivery.destination_kind,
            delivery.destination_instance_id,
            delivery.destination_collection_id,
            delivery.destination_asset_id,
            run.stig_id,
            run.stig_revision,
            delivery.request_json,
            sha256_hex(&delivery.request_json),
            delivery.payload_json,
            sha256_hex(&delivery.payload_json),
            created_at,
            delivery.not_before.map(format_timestamp),
        ],
    )?;
    Ok(())
}

fn query_scan_job(conn: &Connection, id: &str) -> StorageResult<ScanJobRecord> {
    let sql = format!(
        "SELECT {SCAN_JOB_COLUMNS}
         FROM scan_jobs AS job
         JOIN scan_job_transitions AS current ON current.id = (
            SELECT MAX(latest.id) FROM scan_job_transitions AS latest
            WHERE latest.job_id = job.id
         )
         WHERE job.id = ?1"
    );
    conn.query_row(&sql, params![id], scan_job_from_row)
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => {
                StorageError::NotFound(format!("Scan job {id}"))
            }
            other => other.into(),
        })
}

fn scan_job_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ScanJobRecord> {
    Ok(ScanJobRecord {
        id: row.get(0)?,
        state: parse_scan_job_state(row.get(1)?, 1)?,
        sanitized_request_json: row.get(2)?,
        request_sha256: row.get(3)?,
        created_at: row.get(4)?,
        updated_at: row.get(5)?,
        started_at: row.get(6)?,
        finished_at: row.get(7)?,
        run_id: row.get(8)?,
        error: row.get(9)?,
    })
}

fn scan_job_transition_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<ScanJobTransitionRecord> {
    Ok(ScanJobTransitionRecord {
        id: row.get(0)?,
        job_id: row.get(1)?,
        state: parse_scan_job_state(row.get(2)?, 2)?,
        occurred_at: row.get(3)?,
        run_id: row.get(4)?,
        error: row.get(5)?,
    })
}

fn parse_scan_job_state(value: String, column: usize) -> rusqlite::Result<ScanJobState> {
    value.parse().map_err(|message: String| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                message,
            )),
        )
    })
}

fn query_scan_run(conn: &Connection, id: &str) -> StorageResult<ScanRunRecord> {
    conn.query_row(
        "SELECT id, checklist_id, asset_hostname, scanner_version, scan_source, stig_id,
                stig_revision, benchmark_sha256, check_pack_sha256,
                evaluation_plan_sha256, evidence_sha256, request_json, request_sha256,
                result_json, result_sha256, completed_at, created_at
         FROM scan_runs WHERE id = ?1",
        params![id],
        scan_run_from_row,
    )
    .map_err(|error| match error {
        rusqlite::Error::QueryReturnedNoRows => StorageError::NotFound(format!("Scan run {id}")),
        other => other.into(),
    })
}

fn scan_run_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ScanRunRecord> {
    Ok(ScanRunRecord {
        id: row.get(0)?,
        checklist_id: row.get(1)?,
        asset_hostname: row.get(2)?,
        scanner_version: row.get(3)?,
        scan_source: row.get(4)?,
        stig_id: row.get(5)?,
        stig_revision: row.get(6)?,
        benchmark_sha256: row.get(7)?,
        check_pack_sha256: row.get(8)?,
        evaluation_plan_sha256: row.get(9)?,
        evidence_sha256: row.get(10)?,
        request_json: row.get(11)?,
        request_sha256: row.get(12)?,
        result_json: row.get(13)?,
        result_sha256: row.get(14)?,
        completed_at: row.get(15)?,
        created_at: row.get(16)?,
    })
}

fn query_scan_evidence_metadata(
    conn: &Connection,
    run_id: &str,
) -> StorageResult<ScanEvidenceArtifactMetadata> {
    let sql = format!(
        "SELECT {SCAN_EVIDENCE_METADATA_COLUMNS}
         FROM scan_run_evidence_artifacts WHERE run_id = ?1"
    );
    conn.query_row(&sql, params![run_id], scan_evidence_metadata_from_row)
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => {
                StorageError::NotFound(format!("Replay evidence for scan run {run_id}"))
            }
            other => other.into(),
        })
}

fn query_retained_scan_evidence(
    conn: &Connection,
    run_id: &str,
) -> StorageResult<RetainedScanEvidenceArtifact> {
    let sql = format!(
        "SELECT {SCAN_EVIDENCE_METADATA_COLUMNS}, ciphertext, wrapped_dek
         FROM scan_run_evidence_artifacts
         WHERE run_id = ?1 AND state = 'retained'"
    );
    conn.query_row(&sql, params![run_id], |row| {
        Ok(RetainedScanEvidenceArtifact {
            metadata: scan_evidence_metadata_from_row(row)?,
            ciphertext: row.get(14)?,
            wrapped_dek: row.get(15)?,
        })
    })
    .map_err(|error| match error {
        rusqlite::Error::QueryReturnedNoRows => {
            StorageError::NotFound(format!("Retained replay evidence for scan run {run_id}"))
        }
        other => other.into(),
    })
}

fn scan_evidence_metadata_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<ScanEvidenceArtifactMetadata> {
    let ciphertext_size: i64 = row.get(6)?;
    let ciphertext_size = u64::try_from(ciphertext_size).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            6,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })?;
    Ok(ScanEvidenceArtifactMetadata {
        run_id: row.get(0)?,
        state: parse_scan_evidence_state(row.get(1)?, 1)?,
        envelope_schema: row.get(2)?,
        evidence_sha256: row.get(3)?,
        plaintext_sha256: row.get(4)?,
        ciphertext_sha256: row.get(5)?,
        ciphertext_size,
        algorithm: row.get(7)?,
        key_id: row.get(8)?,
        wrapped_dek_sha256: row.get(9)?,
        sealed_at: row.get(10)?,
        expires_at: row.get(11)?,
        purged_at: row.get(12)?,
        purge_reason: row
            .get::<_, Option<String>>(13)?
            .map(|value| parse_scan_evidence_purge_reason(value, 13))
            .transpose()?,
    })
}

fn parse_scan_evidence_state(value: String, column: usize) -> rusqlite::Result<ScanEvidenceState> {
    value.parse().map_err(|message: String| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                message,
            )),
        )
    })
}

fn parse_scan_evidence_purge_reason(
    value: String,
    column: usize,
) -> rusqlite::Result<ScanEvidencePurgeReason> {
    value.parse().map_err(|message: String| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                message,
            )),
        )
    })
}

fn query_delivery(conn: &Connection, id: &str) -> StorageResult<DeliveryRecord> {
    let sql = format!("SELECT {DELIVERY_COLUMNS} FROM delivery_outbox WHERE id = ?1");
    conn.query_row(&sql, params![id], delivery_from_row)
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => {
                StorageError::NotFound(format!("Delivery {id}"))
            }
            other => other.into(),
        })
}

fn delivery_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<DeliveryRecord> {
    let state = parse_delivery_state(row.get(2)?, 2)?;
    let attempt_count = parse_attempt_number(row.get(13)?, 13)?;
    Ok(DeliveryRecord {
        id: row.get(0)?,
        scan_run_id: row.get(1)?,
        state,
        destination_kind: row.get(3)?,
        destination_instance_id: row.get(4)?,
        destination_collection_id: row.get(5)?,
        destination_asset_id: row.get(6)?,
        stig_id: row.get(7)?,
        stig_revision: row.get(8)?,
        request_json: row.get(9)?,
        request_sha256: row.get(10)?,
        payload_json: row.get(11)?,
        payload_sha256: row.get(12)?,
        attempt_count,
        last_error: row.get(14)?,
        remote_receipt_json: row.get(15)?,
        created_at: row.get(16)?,
        updated_at: row.get(17)?,
        first_attempted_at: row.get(18)?,
        last_attempted_at: row.get(19)?,
        delivered_at: row.get(20)?,
        next_attempt_at: row.get(21)?,
        claimed_by: row.get(22)?,
        claim_token: row.get(23)?,
        claim_expires_at: row.get(24)?,
    })
}

fn delivery_receipt_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<DeliveryReceipt> {
    Ok(DeliveryReceipt {
        id: row.get(0)?,
        delivery_id: row.get(1)?,
        attempt_number: parse_attempt_number(row.get(2)?, 2)?,
        outcome: parse_delivery_state(row.get(3)?, 3)?,
        recorded_at: row.get(4)?,
        error: row.get(5)?,
        remote_receipt_json: row.get(6)?,
    })
}

fn parse_delivery_state(value: String, column: usize) -> rusqlite::Result<DeliveryState> {
    value.parse().map_err(|message: String| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                message,
            )),
        )
    })
}

fn parse_attempt_number(value: i64, column: usize) -> rusqlite::Result<u32> {
    u32::try_from(value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })
}

fn recover_expired_delivery_claims(conn: &Connection, now: &str) -> StorageResult<()> {
    let expired = {
        let mut statement = conn.prepare(
            "SELECT id, attempt_count FROM delivery_outbox
             WHERE state = 'sending' AND claim_expires_at <= ?1
             ORDER BY id",
        )?;
        let rows = statement.query_map(params![now], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        rows.collect::<Result<Vec<_>, _>>()?
    };
    if expired.is_empty() {
        return Ok(());
    }

    const LEASE_ERROR: &str = "delivery claim lease expired before completion";
    for (delivery_id, attempt_number) in &expired {
        conn.execute(
            "INSERT OR IGNORE INTO delivery_receipts
             (delivery_id, attempt_number, outcome, recorded_at, error, remote_receipt_json)
             VALUES (?1, ?2, 'retryable', ?3, ?4, NULL)",
            params![delivery_id, attempt_number, now, LEASE_ERROR],
        )?;
    }
    conn.execute(
        "UPDATE delivery_outbox
         SET state = 'retryable', updated_at = ?1, next_attempt_at = ?1,
             last_error = ?2, remote_receipt_json = NULL,
             claimed_by = NULL, claim_token = NULL, claim_expires_at = NULL
         WHERE state = 'sending' AND claim_expires_at <= ?1",
        params![now, LEASE_ERROR],
    )?;
    Ok(())
}

fn ensure_active_claim(delivery: &DeliveryRecord, claim_token: &str) -> StorageResult<()> {
    validate_required("claim_token", claim_token)?;
    if delivery.state != DeliveryState::Sending {
        return Err(StorageError::InvalidDeliveryState {
            delivery_id: delivery.id.clone(),
            expected: DeliveryState::Sending.to_string(),
            actual: delivery.state.to_string(),
        });
    }
    if delivery.claim_token.as_deref() != Some(claim_token) {
        return Err(StorageError::DeliveryClaimLost(delivery.id.clone()));
    }
    Ok(())
}

fn validate_new_scan_job(job: &NewScanJob) -> StorageResult<()> {
    validate_required("scan job id", &job.id)?;
    validate_sha256("scan job request_sha256", &job.request_sha256)?;
    let expected_sha256 = sha256_hex(&job.sanitized_request_json);
    if job.request_sha256 != expected_sha256 {
        return Err(StorageError::InvalidData(
            "scan job request_sha256 does not match sanitized_request_json".to_string(),
        ));
    }
    let request: serde_json::Value =
        serde_json::from_str(&job.sanitized_request_json).map_err(|error| {
            StorageError::InvalidData(format!(
                "scan job sanitized_request_json is invalid JSON: {error}"
            ))
        })?;
    if !request.is_object() {
        return Err(StorageError::InvalidData(
            "scan job sanitized_request_json must be a JSON object".to_string(),
        ));
    }
    validate_sanitized_json_value(&request, "$")
}

fn validate_sanitized_json_value(value: &serde_json::Value, path: &str) -> StorageResult<()> {
    match value {
        serde_json::Value::Object(fields) => {
            for (key, child) in fields {
                let normalized_key = key
                    .chars()
                    .filter(|character| character.is_ascii_alphanumeric())
                    .flat_map(char::to_lowercase)
                    .collect::<String>();
                let sensitive_key = [
                    "password",
                    "passphrase",
                    "secret",
                    "token",
                    "apikey",
                    "privatekey",
                    "authorization",
                    "cookie",
                    "credential",
                    "credentials",
                ]
                .iter()
                .any(|suffix| normalized_key.ends_with(suffix));
                if sensitive_key
                    && !matches!(child, serde_json::Value::Null | serde_json::Value::Bool(_))
                {
                    return Err(StorageError::InvalidData(format!(
                        "scan job sanitized_request_json contains credential field {path}.{key}"
                    )));
                }
                validate_sanitized_json_value(child, &format!("{path}.{key}"))?;
            }
        }
        serde_json::Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                validate_sanitized_json_value(child, &format!("{path}[{index}]"))?;
            }
        }
        serde_json::Value::String(text) => validate_sanitized_text(path, text)?,
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
    Ok(())
}

fn validate_sanitized_text(label: &str, value: &str) -> StorageResult<()> {
    if value.len() > 16_384 {
        return Err(StorageError::InvalidData(format!(
            "{label} is too long to persist safely"
        )));
    }
    let trimmed = value.trim();
    let lowercase = trimmed.to_ascii_lowercase();
    let contains_private_key = trimmed.contains("-----BEGIN ")
        && (trimmed.contains("PRIVATE KEY-----") || trimmed.contains("OPENSSH PRIVATE KEY-----"));
    let contains_authorization_value = lowercase.starts_with("bearer ")
        || lowercase.starts_with("basic ")
        || lowercase.contains("authorization: bearer ")
        || lowercase.contains("authorization: basic ");
    if contains_private_key || contains_authorization_value {
        return Err(StorageError::InvalidData(format!(
            "{label} contains credential material"
        )));
    }
    Ok(())
}

fn validate_scan_run(run: &NewScanRun) -> StorageResult<()> {
    validate_required("scan run id", &run.id)?;
    if let Some(checklist_id) = &run.checklist_id {
        validate_required("checklist_id", checklist_id)?;
    }
    validate_required("asset_hostname", &run.asset_hostname)?;
    validate_required("scanner_version", &run.scanner_version)?;
    validate_required("scan_source", &run.scan_source)?;
    validate_required("stig_id", &run.stig_id)?;
    validate_required("stig_revision", &run.stig_revision)?;
    validate_sha256("benchmark_sha256", &run.benchmark_sha256)?;
    validate_sha256("check_pack_sha256", &run.check_pack_sha256)?;
    validate_sha256("evaluation_plan_sha256", &run.evaluation_plan_sha256)?;
    validate_sha256("evidence_sha256", &run.evidence_sha256)?;
    validate_json("scan request_json", &run.request_json)?;
    validate_json("scan result_json", &run.result_json)
}

fn validate_scan_run_without_encrypted_evidence(run: &NewScanRun) -> StorageResult<()> {
    validate_scan_run(run)?;
    let result: serde_json::Value = serde_json::from_str(&run.result_json).map_err(|error| {
        StorageError::InvalidData(format!("scan result_json is invalid JSON: {error}"))
    })?;
    if result.get("schema").and_then(serde_json::Value::as_str)
        == Some("automatestig.scanner-run.v2")
    {
        return Err(StorageError::InvalidData(
            "scanner-run.v2 must be stored atomically with encrypted replay evidence".to_string(),
        ));
    }
    Ok(())
}

fn validate_scan_evidence(
    run: &NewScanRun,
    evidence: &NewScanEvidenceArtifact,
) -> StorageResult<()> {
    if evidence.run_id != run.id {
        return Err(StorageError::InvalidData(
            "encrypted evidence run_id does not match scan run".to_string(),
        ));
    }
    if evidence.evidence_sha256 != run.evidence_sha256 {
        return Err(StorageError::InvalidData(
            "encrypted evidence digest does not match scan run".to_string(),
        ));
    }
    validate_required("evidence envelope_schema", &evidence.envelope_schema)?;
    validate_sha256("evidence evidence_sha256", &evidence.evidence_sha256)?;
    validate_sha256("evidence plaintext_sha256", &evidence.plaintext_sha256)?;
    validate_sha256("evidence ciphertext_sha256", &evidence.ciphertext_sha256)?;
    validate_sha256("evidence key_id", &evidence.key_id)?;
    validate_sha256("evidence wrapped_dek_sha256", &evidence.wrapped_dek_sha256)?;
    if evidence.algorithm != SCAN_EVIDENCE_ENCRYPTION_ALGORITHM {
        return Err(StorageError::InvalidData(format!(
            "unsupported scan evidence encryption algorithm {:?}",
            evidence.algorithm
        )));
    }
    if evidence.ciphertext.len() < 28
        || evidence.ciphertext.len() > MAX_ENCRYPTED_SCAN_EVIDENCE_BYTES
    {
        return Err(StorageError::InvalidData(format!(
            "encrypted scan evidence must be between 28 and {MAX_ENCRYPTED_SCAN_EVIDENCE_BYTES} bytes"
        )));
    }
    if evidence.wrapped_dek.len() != 60 {
        return Err(StorageError::InvalidData(
            "wrapped scan evidence DEK must contain a 12-byte nonce, 32-byte key, and 16-byte tag"
                .to_string(),
        ));
    }
    if evidence.ciphertext_sha256 != sha256_bytes_hex(&evidence.ciphertext) {
        return Err(StorageError::InvalidData(
            "encrypted scan evidence ciphertext digest does not match its bytes".to_string(),
        ));
    }
    if evidence.wrapped_dek_sha256 != sha256_bytes_hex(&evidence.wrapped_dek) {
        return Err(StorageError::InvalidData(
            "encrypted scan evidence wrapped-DEK digest does not match its bytes".to_string(),
        ));
    }
    let retention = evidence
        .expires_at
        .signed_duration_since(evidence.sealed_at);
    if retention < chrono::Duration::days(i64::from(MIN_SCAN_EVIDENCE_RETENTION_DAYS))
        || retention > chrono::Duration::days(i64::from(MAX_SCAN_EVIDENCE_RETENTION_DAYS))
    {
        return Err(StorageError::InvalidData(format!(
            "scan evidence retention must be between {MIN_SCAN_EVIDENCE_RETENTION_DAYS} and {MAX_SCAN_EVIDENCE_RETENTION_DAYS} days"
        )));
    }

    let result: serde_json::Value = serde_json::from_str(&run.result_json).map_err(|error| {
        StorageError::InvalidData(format!("scan result_json is invalid JSON: {error}"))
    })?;
    if result.get("schema").and_then(serde_json::Value::as_str)
        != Some("automatestig.scanner-run.v2")
    {
        return Err(StorageError::InvalidData(
            "encrypted scanner evidence requires scanner-run.v2 result metadata".to_string(),
        ));
    }
    if result.get("evidence_envelope").is_some() {
        return Err(StorageError::InvalidData(
            "scanner-run.v2 must not embed a plaintext evidence envelope".to_string(),
        ));
    }
    Ok(())
}

fn validate_pending_delivery(delivery: &NewPendingDelivery) -> StorageResult<()> {
    validate_required("delivery id", &delivery.id)?;
    validate_required("destination_kind", &delivery.destination_kind)?;
    validate_required("destination_instance_id", &delivery.destination_instance_id)?;
    validate_required(
        "destination_collection_id",
        &delivery.destination_collection_id,
    )?;
    if let Some(asset_id) = &delivery.destination_asset_id {
        validate_required("destination_asset_id", asset_id)?;
    }
    validate_json("delivery request_json", &delivery.request_json)?;
    validate_json("delivery payload_json", &delivery.payload_json)
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

fn incomplete_evaluation_reason(checklist: &Checklist) -> Option<String> {
    if checklist.findings.iter().any(|finding| {
        finding.source == automatestig_core::models::finding::FindingSource::CollectionError
    }) {
        return Some("one or more findings have collection errors".to_string());
    }
    checklist
        .evaluation_provenance
        .as_ref()
        .and_then(|provenance| {
            (!provenance.collection_complete
                || !provenance.collection_errors.is_empty()
                || provenance.unsafe_legacy_evidence)
                .then(|| "collection provenance is incomplete or unsafe".to_string())
        })
}

fn secure_database_path(path: &Path) -> StorageResult<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    match std::fs::symlink_metadata(parent) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(StorageError::UnsafePath(format!(
                    "database parent must be a real directory: {}",
                    parent.display()
                )));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::{MetadataExt, PermissionsExt};
                if metadata.uid() != unsafe { libc::geteuid() } {
                    return Err(StorageError::UnsafePath(format!(
                        "database parent is not owned by the current user: {}",
                        parent.display()
                    )));
                }
                if parent.file_name().and_then(|name| name.to_str()) == Some(".automatestig") {
                    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
                } else if metadata.permissions().mode() & 0o022 != 0 {
                    return Err(StorageError::UnsafePath(format!(
                        "database parent is writable by group or other users: {}",
                        parent.display()
                    )));
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
            }
        }
        Err(error) => return Err(error.into()),
    }

    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(StorageError::UnsafePath(format!(
                    "database must be a regular non-symlink file: {}",
                    path.display()
                )));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::{MetadataExt, PermissionsExt};
                if metadata.uid() != unsafe { libc::geteuid() } {
                    return Err(StorageError::UnsafePath(format!(
                        "database is not owned by the current user: {}",
                        path.display()
                    )));
                }
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut options = std::fs::OpenOptions::new();
            options.read(true).write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
            }
            options.open(path)?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

/// Validate a database path without creating it or repairing its permissions.
fn verify_existing_database_path(path: &Path) -> StorageResult<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent_metadata = std::fs::symlink_metadata(parent)?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        return Err(StorageError::UnsafePath(format!(
            "database parent must be a real directory: {}",
            parent.display()
        )));
    }

    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(StorageError::UnsafePath(format!(
            "database must be a regular non-symlink file: {}",
            path.display()
        )));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let effective_user = unsafe { libc::geteuid() };
        if parent_metadata.uid() != effective_user {
            return Err(StorageError::UnsafePath(format!(
                "database parent is not owned by the current user: {}",
                parent.display()
            )));
        }
        if parent_metadata.permissions().mode() & 0o022 != 0 {
            return Err(StorageError::UnsafePath(format!(
                "database parent is writable by group or other users: {}",
                parent.display()
            )));
        }
        if metadata.uid() != effective_user {
            return Err(StorageError::UnsafePath(format!(
                "database is not owned by the current user: {}",
                path.display()
            )));
        }
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(StorageError::UnsafePath(format!(
                "database is writable by group or other users: {}",
                path.display()
            )));
        }
    }

    Ok(())
}

fn save_checklist_row(
    conn: &Connection,
    checklist: &Checklist,
    data_json: &str,
) -> rusqlite::Result<usize> {
    conn.execute(
        "INSERT INTO checklists
         (id, asset_hostname, stig_id, stig_title, stig_version, data_json, created_at, modified_at, generated_by)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT(id) DO UPDATE SET
            asset_hostname=excluded.asset_hostname,
            stig_id=excluded.stig_id,
            stig_title=excluded.stig_title,
            stig_version=excluded.stig_version,
            data_json=excluded.data_json,
            modified_at=excluded.modified_at,
            generated_by=excluded.generated_by",
        params![
            checklist.id.to_string(),
            checklist.asset.hostname,
            checklist.stig_info.stig_id,
            checklist.stig_info.title,
            format!("V{}R{}", checklist.stig_info.version, checklist.stig_info.release),
            data_json,
            checklist.created_at.to_rfc3339(),
            checklist.modified_at.to_rfc3339(),
            checklist.generated_by,
        ],
    )
}

fn insert_evaluation_log(
    conn: &Connection,
    checklist: &Checklist,
    source: &str,
    details: Option<&str>,
) -> rusqlite::Result<usize> {
    let summary = checklist.summary();
    conn.execute(
        "INSERT INTO evaluation_log
         (checklist_id, asset_hostname, stig_id, evaluated_at, total_rules, open_count, naf_count, na_count, nr_count, source, details)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            checklist.id.to_string(),
            checklist.asset.hostname,
            checklist.stig_info.stig_id,
            chrono::Utc::now().to_rfc3339(),
            summary.total,
            summary.open,
            summary.not_a_finding,
            summary.not_applicable,
            summary.not_reviewed,
            source,
            details,
        ],
    )
}

fn insert_audit_event(
    conn: &Connection,
    checklist_id: Option<&str>,
    event_type: &str,
    actor: &str,
    details_json: Option<&str>,
    checklist_snapshot: Option<&str>,
) -> rusqlite::Result<usize> {
    conn.execute(
        "INSERT INTO audit_log
         (checklist_id, event_type, occurred_at, actor, details_json, checklist_snapshot)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            checklist_id,
            event_type,
            chrono::Utc::now().to_rfc3339(),
            actor,
            details_json,
            checklist_snapshot,
        ],
    )
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
    fn scanner_run_v2_cannot_bypass_atomic_evidence_storage() {
        let db = Database::in_memory().unwrap();
        let run_only = make_v2_scan_run("v2-run-only-bypass");
        assert!(matches!(
            db.save_completed_scan_run(&run_only),
            Err(StorageError::InvalidData(message))
                if message.contains("encrypted replay evidence")
        ));
        assert!(matches!(
            db.get_scan_run(&run_only.id),
            Err(StorageError::NotFound(_))
        ));

        let run_with_delivery = make_v2_scan_run("v2-delivery-bypass");
        assert!(matches!(
            db.save_completed_scan_run_with_pending_delivery(
                &run_with_delivery,
                &make_delivery("v2-delivery-bypass")
            ),
            Err(StorageError::InvalidData(message))
                if message.contains("encrypted replay evidence")
        ));
        assert!(matches!(
            db.get_scan_run(&run_with_delivery.id),
            Err(StorageError::NotFound(_))
        ));
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
