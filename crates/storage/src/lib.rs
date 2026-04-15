//! SQLite storage layer for AutomateSTIG.
//!
//! Provides persistent storage for:
//! - Evaluation history and audit logs
//! - Cached checklists and findings
//! - User configuration and preferences
//! - STIG library index

use std::path::Path;

use rusqlite::{params, Connection};
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
}

pub type StorageResult<T> = std::result::Result<T, StorageError>;

/// The main database handle for AutomateSTIG.
pub struct Database {
    conn: Connection,
}

impl Database {
    /// Open or create a database at the given path.
    pub fn open(path: &Path) -> StorageResult<Self> {
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

            INSERT OR IGNORE INTO schema_version (version) VALUES (1);
            ",
        )?;
        Ok(())
    }

    /// Save a checklist to the database.
    pub fn save_checklist(&self, checklist: &Checklist) -> StorageResult<()> {
        let data_json = serde_json::to_string(checklist)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;

        self.conn.execute(
            "INSERT OR REPLACE INTO checklists
             (id, asset_hostname, stig_id, stig_title, stig_version, data_json, created_at, modified_at, generated_by)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
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
        )?;
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
        let affected = self
            .conn
            .execute("DELETE FROM checklists WHERE id = ?1", params![id])?;
        Ok(affected > 0)
    }

    /// Log an evaluation event.
    pub fn log_evaluation(
        &self,
        checklist: &Checklist,
        source: &str,
        details: Option<&str>,
    ) -> StorageResult<()> {
        let summary = checklist.summary();

        self.conn.execute(
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
        )?;
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use automatestig_core::models::asset::Asset;
    use automatestig_core::models::checklist::{Checklist, ChecklistStigInfo};
    use automatestig_core::models::finding::{Finding, FindingStatus};
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
    }

    #[test]
    fn test_save_and_load_checklist() {
        let db = Database::in_memory().unwrap();
        let cl = make_test_checklist();
        let id = cl.id.to_string();

        db.save_checklist(&cl).unwrap();

        let loaded = db.load_checklist(&id).unwrap();
        assert_eq!(loaded.asset.hostname, "testhost");
        assert_eq!(loaded.findings.len(), 1);
        assert_eq!(loaded.findings[0].status, FindingStatus::Open);
    }

    #[test]
    fn test_list_checklists() {
        let db = Database::in_memory().unwrap();

        db.save_checklist(&make_test_checklist()).unwrap();
        db.save_checklist(&make_test_checklist()).unwrap();

        let list = db.list_checklists().unwrap();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn test_delete_checklist() {
        let db = Database::in_memory().unwrap();
        let cl = make_test_checklist();
        let id = cl.id.to_string();

        db.save_checklist(&cl).unwrap();
        assert!(db.delete_checklist(&id).unwrap());
        assert!(db.load_checklist(&id).is_err());
    }

    #[test]
    fn test_evaluation_log() {
        let db = Database::in_memory().unwrap();
        let cl = make_test_checklist();

        db.save_checklist(&cl).unwrap();
        db.log_evaluation(&cl, "test", Some("Test evaluation")).unwrap();
        // No assertion needed — just verifying it doesn't error.
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
