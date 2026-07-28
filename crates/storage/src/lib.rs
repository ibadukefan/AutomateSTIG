//! SQLite storage layer for AutomateSTIG.
//!
//! Provides persistent storage for:
//! - Evaluation history and audit logs
//! - Cached checklists and findings
//! - User configuration and preferences
//! - STIG library index

use std::path::Path;

use rusqlite::{params, Connection};
use serde::Serialize;
use thiserror::Error;

use automatestig_core::models::checklist::Checklist;

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
}

pub type StorageResult<T> = std::result::Result<T, StorageError>;

/// The main database handle for AutomateSTIG.
pub struct Database {
    conn: Connection,
}

impl Database {
    /// Open or create a database at the given path.
    pub fn open(path: &Path) -> StorageResult<Self> {
        secure_database_path(path)?;
        let conn = Connection::open(path)?;
        let db = Self { conn };
        db.initialize()?;
        Ok(db)
    }

    /// Create an in-memory database (for testing).
    pub fn in_memory() -> StorageResult<Self> {
        let conn = Connection::open_in_memory()?;
        let db = Self { conn };
        db.initialize()?;
        Ok(db)
    }

    /// Initialize the database schema.
    fn initialize(&self) -> StorageResult<()> {
        self.conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA foreign_keys = ON;

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
        self.migrate_evaluation_log_retention()?;
        self.conn.execute_batch(
            "DELETE FROM schema_version;
             INSERT INTO schema_version (version) VALUES (3);",
        )?;
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
        let data_json: String = self
            .conn
            .query_row(
                "SELECT data_json FROM checklists WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )
            .map_err(|_| StorageError::NotFound(format!("Checklist {}", id)))?;

        serde_json::from_str(&data_json).map_err(|e| StorageError::Serialization(e.to_string()))
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

    #[cfg(test)]
    fn count_audit_events(&self, checklist_id: &str) -> StorageResult<usize> {
        Ok(self.conn.query_row(
            "SELECT COUNT(*) FROM audit_log WHERE checklist_id = ?1",
            params![checklist_id],
            |row| row.get(0),
        )?)
    }
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
        assert_eq!(version, 3);
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
    }
}
