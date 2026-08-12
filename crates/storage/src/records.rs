//! Checklist, evaluation-history, audit, and configuration records.

use super::*;

impl Database {
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

    /// Atomically persist the two bounded scanner retention controls.
    /// Existing evidence rows retain their immutable expiry; callers use these
    /// values for newly sealed replay/checkpoint data and the next operational
    /// history sweep.
    pub fn set_scanner_retention_policy(
        &self,
        evidence_days: u32,
        operational_days: u32,
    ) -> StorageResult<()> {
        self.set_scanner_retention_policy_dimensions(Some(evidence_days), Some(operational_days))
    }

    /// Atomically update only retention dimensions controlled by the local
    /// database. `None` preserves an ineffective stored value while a
    /// deployment environment override remains authoritative.
    pub fn set_scanner_retention_policy_dimensions(
        &self,
        evidence_days: Option<u32>,
        operational_days: Option<u32>,
    ) -> StorageResult<()> {
        if evidence_days.is_some_and(|days| {
            !(MIN_SCAN_EVIDENCE_RETENTION_DAYS..=MAX_SCAN_EVIDENCE_RETENTION_DAYS).contains(&days)
        }) {
            return Err(StorageError::InvalidData(format!(
                "evidence retention must be between {MIN_SCAN_EVIDENCE_RETENTION_DAYS} and {MAX_SCAN_EVIDENCE_RETENTION_DAYS} days"
            )));
        }
        if operational_days.is_some_and(|days| {
            !(MIN_OPERATIONAL_RETENTION_DAYS..=MAX_OPERATIONAL_RETENTION_DAYS).contains(&days)
        }) {
            return Err(StorageError::InvalidData(format!(
                "operational retention must be between {MIN_OPERATIONAL_RETENTION_DAYS} and {MAX_OPERATIONAL_RETENTION_DAYS} days"
            )));
        }
        let transaction = self.conn.unchecked_transaction()?;
        if let Some(evidence_days) = evidence_days {
            transaction.execute(
                "INSERT OR REPLACE INTO app_config (key, value) VALUES ('scanner.evidence_retention_days', ?1)",
                params![evidence_days.to_string()],
            )?;
        }
        if let Some(operational_days) = operational_days {
            transaction.execute(
                "INSERT OR REPLACE INTO app_config (key, value) VALUES ('scanner.operational_retention_days', ?1)",
                params![operational_days.to_string()],
            )?;
        }
        transaction.commit()?;
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
    pub(super) fn count_audit_events(&self, checklist_id: &str) -> StorageResult<usize> {
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
