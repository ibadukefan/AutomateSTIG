//! Durable scanner jobs, immutable runs, and encrypted replay evidence.

use super::delivery::{query_delivery, validate_pending_delivery};
use super::*;

impl Database {
    /// Persist a queued scanner job before any device I/O begins.
    ///
    /// The request must already be stripped of credentials. Storage performs a
    /// second defensive check for common secret fields/material and verifies
    /// its caller-supplied SHA-256 digest before committing the job.
    pub fn create_scan_job(&self, job: &NewScanJob) -> StorageResult<ScanJobRecord> {
        self.create_scan_job_at(job, Utc::now())
    }

    pub(super) fn create_scan_job_at(
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

    /// Bounded runtime page of scanner jobs. Transition/migration tooling may
    /// still use the complete reader above inside a controlled snapshot.
    pub fn list_scan_jobs_page(
        &self,
        state: Option<ScanJobState>,
        offset: usize,
        limit: usize,
    ) -> StorageResult<Vec<ScanJobRecord>> {
        validate_page(offset, limit)?;
        let sql = format!(
            "SELECT {SCAN_JOB_COLUMNS}
             FROM scan_jobs AS job
             JOIN scan_job_transitions AS current ON current.id = (
                SELECT MAX(latest.id) FROM scan_job_transitions AS latest
                WHERE latest.job_id = job.id
             )
             WHERE (?1 IS NULL OR current.state = ?1)
             ORDER BY job.created_at DESC, job.id ASC LIMIT ?2 OFFSET ?3"
        );
        let state = state.map(ScanJobState::as_str);
        let mut statement = self.conn.prepare(&sql)?;
        let rows = statement.query_map(
            params![state, limit as i64, offset as i64],
            scan_job_from_row,
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Append the transition from `queued` to `running`.
    pub fn mark_scan_job_running(&self, job_id: &str) -> StorageResult<ScanJobRecord> {
        self.transition_scan_job_at(job_id, ScanJobState::Running, None, None, Utc::now())
    }

    /// Resume a failed job only while its authenticated operation checkpoint is
    /// still retained. The database trigger independently enforces this gate.
    pub fn mark_scan_job_resuming(&self, job_id: &str) -> StorageResult<ScanJobRecord> {
        validate_required("scan job id", job_id)?;
        let now = format_timestamp(Utc::now());
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let current = query_scan_job(&tx, job_id)?;
        if current.state != ScanJobState::Failed {
            return Err(StorageError::InvalidScanJobState {
                job_id: job_id.to_string(),
                expected: "failed with a retained checkpoint".to_string(),
                actual: current.state.to_string(),
            });
        }
        let checkpoint_exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM scan_operation_checkpoints
                           WHERE job_id = ?1 AND expires_at > ?2)",
            params![job_id, now],
            |row| row.get(0),
        )?;
        if !checkpoint_exists {
            return Err(StorageError::InvalidScanJobState {
                job_id: job_id.to_string(),
                expected: "failed with a retained checkpoint".to_string(),
                actual: "failed without a resumable checkpoint".to_string(),
            });
        }
        tx.execute(
            "INSERT INTO scan_job_transitions
             (job_id, state, occurred_at, run_id, error)
             VALUES (?1, 'running', ?2, NULL, NULL)",
            params![job_id, now],
        )?;
        let stored = query_scan_job(&tx, job_id)?;
        tx.commit()?;
        Ok(stored)
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

    pub(super) fn transition_scan_job_at(
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

    /// Read every replay-evidence custody row exactly as stored for a
    /// controlled transition or backup snapshot.
    ///
    /// This is intentionally separate from the runtime loader: it never
    /// decrypts evidence, applies expiry, purges bytes, or changes database
    /// state. Retained rows include ciphertext and the wrapped DEK; purged rows
    /// retain metadata only. Callers must write the result only to a private,
    /// integrity-bound archive.
    pub fn list_scan_evidence_custody_records(
        &self,
    ) -> StorageResult<Vec<ScanEvidenceCustodyRecord>> {
        let sql = format!(
            "SELECT {SCAN_EVIDENCE_METADATA_COLUMNS}, ciphertext, wrapped_dek
             FROM scan_run_evidence_artifacts ORDER BY run_id ASC"
        );
        let mut statement = self.conn.prepare(&sql)?;
        let rows = statement.query_map([], |row| {
            Ok(ScanEvidenceCustodyRecord {
                metadata: scan_evidence_metadata_from_row(row)?,
                ciphertext: row.get(14)?,
                wrapped_dek: row.get(15)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
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

    pub(super) fn load_retained_scan_evidence_at(
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

    pub(super) fn purge_scan_evidence_at(
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

    pub(super) fn purge_expired_scan_evidence_at(
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

    /// Bounded runtime page of completed scanner runs.
    pub fn list_scan_runs_page(
        &self,
        offset: usize,
        limit: usize,
    ) -> StorageResult<Vec<ScanRunRecord>> {
        validate_page(offset, limit)?;
        let mut statement = self.conn.prepare(
            "SELECT id, checklist_id, asset_hostname, scanner_version, scan_source, stig_id,
                    stig_revision, benchmark_sha256, check_pack_sha256,
                    evaluation_plan_sha256, evidence_sha256, request_json, request_sha256,
                    result_json, result_sha256, completed_at, created_at
             FROM scan_runs ORDER BY completed_at DESC, id ASC LIMIT ?1 OFFSET ?2",
        )?;
        let rows = statement.query_map(params![limit as i64, offset as i64], scan_run_from_row)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Create or update one opt-in thin target connection profile.
    pub fn save_target_connection_profile(
        &self,
        profile: &NewTargetConnectionProfile,
    ) -> StorageResult<TargetConnectionProfileRecord> {
        validate_target_connection_profile(profile)?;
        let now = format_timestamp(Utc::now());
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM target_connection_profiles WHERE id = ?1)",
            params![profile.id],
            |row| row.get(0),
        )?;
        if !exists {
            let count: i64 = tx.query_row(
                "SELECT COUNT(*) FROM target_connection_profiles",
                [],
                |row| row.get(0),
            )?;
            if count >= MAX_TARGET_CONNECTION_PROFILES as i64 {
                return Err(StorageError::InvalidData(format!(
                    "target connection profile limit of {MAX_TARGET_CONNECTION_PROFILES} reached"
                )));
            }
        }
        tx.execute(
            "INSERT INTO target_connection_profiles
             (id, scanner_profile_id, adapter, endpoint, port, credential_reference,
              last_observed_fingerprint, recent_operational_state, observed_at,
              created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, NULL, NULL, ?7, ?7)
             ON CONFLICT(id) DO UPDATE SET
                scanner_profile_id = excluded.scanner_profile_id,
                adapter = excluded.adapter,
                endpoint = excluded.endpoint,
                port = excluded.port,
                credential_reference = excluded.credential_reference,
                last_observed_fingerprint = CASE
                    WHEN target_connection_profiles.scanner_profile_id = excluded.scanner_profile_id
                     AND target_connection_profiles.adapter = excluded.adapter
                     AND target_connection_profiles.endpoint = excluded.endpoint
                     AND target_connection_profiles.port = excluded.port
                    THEN target_connection_profiles.last_observed_fingerprint ELSE NULL END,
                recent_operational_state = CASE
                    WHEN target_connection_profiles.scanner_profile_id = excluded.scanner_profile_id
                     AND target_connection_profiles.adapter = excluded.adapter
                     AND target_connection_profiles.endpoint = excluded.endpoint
                     AND target_connection_profiles.port = excluded.port
                    THEN target_connection_profiles.recent_operational_state ELSE NULL END,
                observed_at = CASE
                    WHEN target_connection_profiles.scanner_profile_id = excluded.scanner_profile_id
                     AND target_connection_profiles.adapter = excluded.adapter
                     AND target_connection_profiles.endpoint = excluded.endpoint
                     AND target_connection_profiles.port = excluded.port
                    THEN target_connection_profiles.observed_at ELSE NULL END,
                updated_at = excluded.updated_at",
            params![
                profile.id,
                profile.scanner_profile_id,
                profile.adapter,
                profile.endpoint,
                i64::from(profile.port),
                profile.credential_reference,
                now,
            ],
        )?;
        let stored = query_target_connection_profile(&tx, &profile.id)?;
        tx.commit()?;
        Ok(stored)
    }

    pub fn list_target_connection_profiles(
        &self,
    ) -> StorageResult<Vec<TargetConnectionProfileRecord>> {
        let mut statement = self.conn.prepare(
            "SELECT id, scanner_profile_id, adapter, endpoint, port,
                    credential_reference, last_observed_fingerprint,
                    recent_operational_state, observed_at, created_at, updated_at
             FROM target_connection_profiles
             ORDER BY updated_at DESC, id ASC LIMIT ?1",
        )?;
        let rows = statement.query_map(
            params![MAX_TARGET_CONNECTION_PROFILES as i64],
            target_connection_profile_from_row,
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Read every thin target connection profile for a controlled transition
    /// or backup snapshot. Runtime callers should use the bounded list above.
    /// Credential references remain opaque provider labels; reusable
    /// credential material is rejected when profiles are written.
    pub fn list_target_connection_profiles_for_snapshot(
        &self,
    ) -> StorageResult<Vec<TargetConnectionProfileRecord>> {
        let mut statement = self.conn.prepare(
            "SELECT id, scanner_profile_id, adapter, endpoint, port,
                    credential_reference, last_observed_fingerprint,
                    recent_operational_state, observed_at, created_at, updated_at
             FROM target_connection_profiles
             ORDER BY updated_at DESC, id ASC",
        )?;
        let rows = statement.query_map([], target_connection_profile_from_row)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn get_target_connection_profile(
        &self,
        id: &str,
    ) -> StorageResult<TargetConnectionProfileRecord> {
        validate_identifier("target connection profile id", id)?;
        query_target_connection_profile(&self.conn, id)
    }

    pub fn delete_target_connection_profile(&self, id: &str) -> StorageResult<bool> {
        validate_identifier("target connection profile id", id)?;
        Ok(self.conn.execute(
            "DELETE FROM target_connection_profiles WHERE id = ?1",
            params![id],
        )? == 1)
    }

    pub fn record_target_connection_observation(
        &self,
        id: &str,
        fingerprint: &str,
        state: &str,
    ) -> StorageResult<TargetConnectionProfileRecord> {
        validate_identifier("target connection profile id", id)?;
        validate_fingerprint("target fingerprint", fingerprint)?;
        validate_operational_state(state)?;
        let now = format_timestamp(Utc::now());
        let changed = self.conn.execute(
            "UPDATE target_connection_profiles
             SET last_observed_fingerprint = ?2, recent_operational_state = ?3,
                 observed_at = ?4, updated_at = ?4 WHERE id = ?1",
            params![id, fingerprint, state, now],
        )?;
        if changed != 1 {
            return Err(StorageError::NotFound(format!(
                "Target connection profile {id}"
            )));
        }
        query_target_connection_profile(&self.conn, id)
    }

    pub fn update_target_connection_operational_state(
        &self,
        id: &str,
        state: &str,
    ) -> StorageResult<TargetConnectionProfileRecord> {
        validate_identifier("target connection profile id", id)?;
        validate_operational_state(state)?;
        let now = format_timestamp(Utc::now());
        let changed = self.conn.execute(
            "UPDATE target_connection_profiles
             SET recent_operational_state = ?2, observed_at = ?3, updated_at = ?3
             WHERE id = ?1 AND last_observed_fingerprint IS NOT NULL",
            params![id, state, now],
        )?;
        if changed != 1 {
            return Err(StorageError::NotFound(format!(
                "Observed target connection profile {id}"
            )));
        }
        query_target_connection_profile(&self.conn, id)
    }

    /// Insert or replace the encrypted successful-operation checkpoint while
    /// requiring every exact resume binding to remain unchanged.
    pub fn save_scan_operation_checkpoint(
        &self,
        checkpoint: &NewScanOperationCheckpoint,
    ) -> StorageResult<ScanOperationCheckpointMetadata> {
        validate_scan_operation_checkpoint(checkpoint)?;
        let now = format_timestamp(Utc::now());
        let expires_at = format_timestamp(checkpoint.expires_at);
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        query_scan_job(&tx, &checkpoint.job_id)?;
        let changed = tx.execute(
            "INSERT INTO scan_operation_checkpoints
             (job_id, profile_id, plan_sha256, device_fingerprint_sha256,
              host_key_fingerprint, endpoint, port, completed_operation_ids_json,
              plaintext_sha256, ciphertext_sha256, algorithm, key_id,
              wrapped_dek_sha256, ciphertext, wrapped_dek, created_at, updated_at,
              expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                     ?13, ?14, ?15, ?16, ?16, ?17)
             ON CONFLICT(job_id) DO UPDATE SET
                completed_operation_ids_json = excluded.completed_operation_ids_json,
                plaintext_sha256 = excluded.plaintext_sha256,
                ciphertext_sha256 = excluded.ciphertext_sha256,
                algorithm = excluded.algorithm,
                key_id = excluded.key_id,
                wrapped_dek_sha256 = excluded.wrapped_dek_sha256,
                ciphertext = excluded.ciphertext,
                wrapped_dek = excluded.wrapped_dek,
                updated_at = excluded.updated_at,
                expires_at = excluded.expires_at
             WHERE scan_operation_checkpoints.profile_id = excluded.profile_id
               AND scan_operation_checkpoints.plan_sha256 = excluded.plan_sha256
               AND scan_operation_checkpoints.device_fingerprint_sha256 = excluded.device_fingerprint_sha256
               AND scan_operation_checkpoints.host_key_fingerprint = excluded.host_key_fingerprint
               AND scan_operation_checkpoints.endpoint = excluded.endpoint
               AND scan_operation_checkpoints.port = excluded.port",
            params![
                checkpoint.job_id,
                checkpoint.profile_id,
                checkpoint.plan_sha256,
                checkpoint.device_fingerprint_sha256,
                checkpoint.host_key_fingerprint,
                checkpoint.endpoint,
                i64::from(checkpoint.port),
                checkpoint.completed_operation_ids_json,
                checkpoint.plaintext_sha256,
                checkpoint.ciphertext_sha256,
                checkpoint.algorithm,
                checkpoint.key_id,
                checkpoint.wrapped_dek_sha256,
                checkpoint.ciphertext,
                checkpoint.wrapped_dek,
                now,
                expires_at,
            ],
        )?;
        if changed != 1 {
            return Err(StorageError::InvalidData(
                "scan checkpoint resume bindings changed".to_string(),
            ));
        }
        let stored = query_scan_operation_checkpoint_metadata(&tx, &checkpoint.job_id)?;
        tx.commit()?;
        Ok(stored)
    }

    pub fn load_scan_operation_checkpoint(
        &self,
        job_id: &str,
    ) -> StorageResult<RetainedScanOperationCheckpoint> {
        validate_required("scan job id", job_id)?;
        let checkpoint = query_scan_operation_checkpoint(&self.conn, job_id)?;
        if parse_timestamp(
            "scan checkpoint expires_at",
            &checkpoint.metadata.expires_at,
        )? <= Utc::now()
        {
            self.conn.execute(
                "DELETE FROM scan_operation_checkpoints WHERE job_id = ?1",
                params![job_id],
            )?;
            return Err(StorageError::NotFound(format!(
                "Retained operation checkpoint for scan job {job_id} expired"
            )));
        }
        Ok(checkpoint)
    }

    /// Return only the non-secret checkpoint lifecycle/binding projection.
    ///
    /// Unlike [`Self::load_scan_operation_checkpoint`], this read does not
    /// decrypt bytes or delete an expired row. Runtime status APIs use it to
    /// report why a job is or is not resumable without touching checkpoint
    /// custody merely because an operator opened the queue.
    pub fn get_scan_operation_checkpoint_metadata(
        &self,
        job_id: &str,
    ) -> StorageResult<ScanOperationCheckpointMetadata> {
        validate_required("scan job id", job_id)?;
        query_scan_operation_checkpoint_metadata(&self.conn, job_id)
    }

    /// Read every encrypted operation checkpoint exactly as stored for a
    /// controlled transition or backup snapshot.
    ///
    /// This reader does not enforce expiry, delete rows, decrypt checkpoint
    /// evidence, or expose it through a serializable projection.
    pub fn list_scan_operation_checkpoint_custody_records(
        &self,
    ) -> StorageResult<Vec<ScanOperationCheckpointCustodyRecord>> {
        let sql = format!(
            "SELECT {SCAN_CHECKPOINT_METADATA_COLUMNS}, ciphertext, wrapped_dek
             FROM scan_operation_checkpoints ORDER BY job_id ASC"
        );
        let mut statement = self.conn.prepare(&sql)?;
        let rows = statement.query_map([], |row| {
            Ok(ScanOperationCheckpointCustodyRecord {
                metadata: scan_operation_checkpoint_metadata_from_row(row)?,
                ciphertext: row.get(16)?,
                wrapped_dek: row.get(17)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn delete_scan_operation_checkpoint(&self, job_id: &str) -> StorageResult<bool> {
        validate_required("scan job id", job_id)?;
        Ok(self.conn.execute(
            "DELETE FROM scan_operation_checkpoints WHERE job_id = ?1",
            params![job_id],
        )? == 1)
    }

    /// Append a receiver reconciliation receipt after strict run/destination
    /// binding has been validated by the API boundary.
    pub fn import_reconciliation_receipt(
        &self,
        receipt: &NewReconciliationReceipt,
        operational_retention_days: u32,
    ) -> StorageResult<ReconciliationReceiptRecord> {
        self.import_reconciliation_receipt_at(receipt, operational_retention_days, Utc::now())
    }

    pub(super) fn import_reconciliation_receipt_at(
        &self,
        receipt: &NewReconciliationReceipt,
        operational_retention_days: u32,
        imported_at: DateTime<Utc>,
    ) -> StorageResult<ReconciliationReceiptRecord> {
        validate_reconciliation_receipt_at(receipt, imported_at)?;
        if !(MIN_OPERATIONAL_RETENTION_DAYS..=MAX_OPERATIONAL_RETENTION_DAYS)
            .contains(&operational_retention_days)
        {
            return Err(StorageError::InvalidData(format!(
                "operational retention must be between {MIN_OPERATIONAL_RETENTION_DAYS} and {MAX_OPERATIONAL_RETENTION_DAYS} days"
            )));
        }
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let run = query_scan_run(&tx, &receipt.run_id)?;
        if run.stig_id != receipt.stig_id || run.stig_revision != receipt.stig_revision {
            return Err(StorageError::InvalidData(
                "reconciliation receipt STIG binding does not match the run".to_string(),
            ));
        }
        let run_completed_at = parse_timestamp("scan run completed_at", &run.completed_at)?;
        if receipt.independent_readback_at < run_completed_at {
            return Err(StorageError::InvalidData(
                "independent readback time cannot predate the immutable scan run completion time"
                    .to_string(),
            ));
        }
        let oldest_accepted =
            imported_at - chrono::Duration::days(i64::from(operational_retention_days));
        if receipt.independent_readback_at < oldest_accepted {
            return Err(StorageError::InvalidData(format!(
                "independent readback time is older than the effective {operational_retention_days}-day operational-retention window at import"
            )));
        }
        tx.execute(
            "INSERT INTO reconciliation_receipts
             (id, schema, run_id, payload_sha256, destination_kind,
              destination_instance_id, destination_collection_id,
              destination_asset_id, destination_assignment_id, stig_id, stig_revision,
              received_rule_ids_json, received_rule_set_sha256,
              independent_readback_sha256, independent_readback_at,
              receipt_json, receipt_sha256, remote_url,
              producer_authentication, signer_fingerprint, detached_signature,
              operator_confirmed, imported_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                     ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23)",
            params![
                receipt.id,
                receipt.schema,
                receipt.run_id,
                receipt.payload_sha256,
                receipt.destination_kind,
                receipt.destination_instance_id,
                receipt.destination_collection_id,
                receipt.destination_asset_id,
                receipt.destination_assignment_id,
                receipt.stig_id,
                receipt.stig_revision,
                receipt.received_rule_ids_json,
                receipt.received_rule_set_sha256,
                receipt.independent_readback_sha256,
                format_timestamp(receipt.independent_readback_at),
                receipt.receipt_json,
                receipt.receipt_sha256,
                receipt.remote_url,
                receipt.producer_authentication,
                receipt.signer_fingerprint,
                receipt.detached_signature,
                receipt.operator_confirmed,
                format_timestamp(imported_at),
            ],
        )?;
        let stored = query_reconciliation_receipt(&tx, &receipt.id)?;
        tx.commit()?;
        Ok(stored)
    }

    pub fn list_reconciliation_receipts_for_run(
        &self,
        run_id: &str,
    ) -> StorageResult<Vec<ReconciliationReceiptRecord>> {
        self.list_reconciliation_receipts_for_run_page(run_id, 0, MAX_OPERATIONAL_PAGE_SIZE)
    }

    /// Bounded receiver-reconciliation receipt history for a single run.
    /// The receipt payload itself remains append-only; callers must page
    /// rather than create an unbounded operational-history read.
    pub fn list_reconciliation_receipts_for_run_page(
        &self,
        run_id: &str,
        offset: usize,
        limit: usize,
    ) -> StorageResult<Vec<ReconciliationReceiptRecord>> {
        validate_required("scan run id", run_id)?;
        validate_page(offset, limit)?;
        query_scan_run(&self.conn, run_id)?;
        let mut statement = self.conn.prepare(
            "SELECT id, schema, run_id, payload_sha256, destination_kind,
                    destination_instance_id, destination_collection_id,
                    destination_asset_id, destination_assignment_id, stig_id, stig_revision,
                    received_rule_ids_json, received_rule_set_sha256,
                    independent_readback_sha256, independent_readback_at,
                    receipt_sha256, remote_url, producer_authentication,
                    signer_fingerprint, operator_confirmed, imported_at
             FROM reconciliation_receipts WHERE run_id = ?1
             ORDER BY imported_at ASC, id ASC LIMIT ?2 OFFSET ?3",
        )?;
        let rows = statement.query_map(
            params![run_id, limit as i64, offset as i64],
            reconciliation_receipt_from_row,
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Read every exact reconciliation receipt and detached signature for a
    /// controlled transition or backup snapshot.
    ///
    /// The runtime projection above remains bounded and metadata-only. This
    /// unbounded reader is for a database snapshot whose output is private and
    /// integrity-bound; it performs no mutation.
    pub fn list_reconciliation_receipt_custody_records(
        &self,
    ) -> StorageResult<Vec<ReconciliationReceiptCustodyRecord>> {
        let mut statement = self.conn.prepare(
            "SELECT id, schema, run_id, payload_sha256, destination_kind,
                    destination_instance_id, destination_collection_id,
                    destination_asset_id, destination_assignment_id, stig_id, stig_revision,
                    received_rule_ids_json, received_rule_set_sha256,
                    independent_readback_sha256, independent_readback_at,
                    receipt_sha256, remote_url, producer_authentication,
                    signer_fingerprint, operator_confirmed, imported_at,
                    receipt_json, detached_signature
             FROM reconciliation_receipts
             ORDER BY imported_at ASC, id ASC",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(ReconciliationReceiptCustodyRecord {
                record: reconciliation_receipt_from_row(row)?,
                receipt_json: row.get(21)?,
                detached_signature: row.get(22)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn list_operational_purge_tombstones_page(
        &self,
        offset: usize,
        limit: usize,
    ) -> StorageResult<Vec<OperationalPurgeTombstone>> {
        validate_page(offset, limit)?;
        let mut statement = self.conn.prepare(
            "SELECT id, run_id, request_sha256, result_sha256, evidence_sha256,
                    payload_sha256, destination_kind, destination_instance_id,
                    destination_collection_id, destination_asset_id,
                    destination_assignment_id, receipt_kind, receipt_id,
                    receipt_sha256, receipt_json, remote_url,
                    purged_at
             FROM operational_purge_tombstones
             ORDER BY purged_at DESC, id DESC LIMIT ?1 OFFSET ?2",
        )?;
        let rows = statement.query_map(
            params![limit as i64, offset as i64],
            operational_purge_tombstone_from_row,
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Read the complete append-only purge ledger for a controlled transition
    /// or backup snapshot. Runtime callers should continue to use the bounded
    /// page API.
    pub fn list_operational_purge_tombstones(
        &self,
    ) -> StorageResult<Vec<OperationalPurgeTombstone>> {
        let mut statement = self.conn.prepare(
            "SELECT id, run_id, request_sha256, result_sha256, evidence_sha256,
                    payload_sha256, destination_kind, destination_instance_id,
                    destination_collection_id, destination_asset_id,
                    destination_assignment_id, receipt_kind, receipt_id,
                    receipt_sha256, receipt_json, remote_url,
                    purged_at
             FROM operational_purge_tombstones
             ORDER BY purged_at ASC, id ASC",
        )?;
        let rows = statement.query_map([], operational_purge_tombstone_from_row)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Create one immutable retained-run destination mapping. A second mapping
    /// for the same run is rejected as ambiguous rather than overwritten.
    pub fn create_migration_run_binding(
        &self,
        binding: &NewMigrationRunBinding,
    ) -> StorageResult<MigrationRunBindingRecord> {
        validate_migration_run_binding(binding)?;
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let run = query_scan_run(&tx, &binding.run_id)?;
        if run.stig_id != binding.stig_id || run.stig_revision != binding.stig_revision {
            return Err(StorageError::InvalidData(
                "migration binding STIG/revision does not match the retained run".to_string(),
            ));
        }
        let duplicate: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM migration_run_bindings WHERE run_id = ?1)",
            params![binding.run_id],
            |row| row.get(0),
        )?;
        if duplicate {
            return Err(StorageError::InvalidData(format!(
                "retained scan run {} already has a migration binding; ambiguous remapping is forbidden",
                binding.run_id
            )));
        }
        tx.execute(
            "INSERT INTO migration_run_bindings
             (id, run_id, destination_instance_id, destination_collection_id,
              destination_asset_id, destination_assignment_id, stig_id,
              stig_revision, observed_stig_manager_version,
              observed_server_identity, mapping_json, mapping_sha256, mapped_at,
              operator_source, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                     ?13, ?14, ?15)",
            params![
                binding.id,
                binding.run_id,
                binding.destination_instance_id,
                binding.destination_collection_id,
                binding.destination_asset_id,
                binding.destination_assignment_id,
                binding.stig_id,
                binding.stig_revision,
                binding.observed_stig_manager_version,
                binding.observed_server_identity,
                binding.mapping_json,
                binding.mapping_sha256,
                format_timestamp(binding.mapped_at),
                binding.operator_source,
                format_timestamp(Utc::now()),
            ],
        )?;
        let stored = query_migration_run_binding(&tx, &binding.run_id)?;
        tx.commit()?;
        Ok(stored)
    }

    pub fn get_migration_run_binding(
        &self,
        run_id: &str,
    ) -> StorageResult<MigrationRunBindingRecord> {
        validate_required("retained scan run id", run_id)?;
        query_migration_run_binding(&self.conn, run_id)
    }

    /// Prune only terminal histories with a verified technical no-op receipt or
    /// an imported reconciliation receipt. Pending, sending, retryable, and
    /// conflicted deliveries are categorically ineligible.
    pub fn sweep_terminal_operational_history(
        &self,
        retention_days: u32,
        limit: usize,
    ) -> StorageResult<Vec<OperationalPurgeTombstone>> {
        self.sweep_terminal_operational_history_at(Utc::now(), retention_days, limit)
    }

    pub(super) fn sweep_terminal_operational_history_at(
        &self,
        now: DateTime<Utc>,
        retention_days: u32,
        limit: usize,
    ) -> StorageResult<Vec<OperationalPurgeTombstone>> {
        if !(MIN_OPERATIONAL_RETENTION_DAYS..=MAX_OPERATIONAL_RETENTION_DAYS)
            .contains(&retention_days)
        {
            return Err(StorageError::InvalidData(format!(
                "operational retention must be between {MIN_OPERATIONAL_RETENTION_DAYS} and {MAX_OPERATIONAL_RETENTION_DAYS} days"
            )));
        }
        validate_page(0, limit)?;
        let cutoff = format_timestamp(now - chrono::Duration::days(i64::from(retention_days)));
        let purged_at = format_timestamp(now);
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        // The schema's no-delete triggers permit this marker only while this
        // receipt-gated transaction is in progress. It is removed before the
        // transaction commits, so ordinary callers cannot delete history.
        tx.execute(
            "INSERT INTO app_config (key, value) VALUES ('scanner.operational_sweep_authorized', '1')
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [],
        )?;
        let run_ids = {
            let mut statement = tx.prepare(
                "SELECT run.id FROM scan_runs AS run
                 WHERE run.completed_at <= ?1
                   AND NOT EXISTS (
                     SELECT 1 FROM delivery_outbox AS blocked
                     WHERE blocked.scan_run_id = run.id
                       AND blocked.state IN ('pending', 'sending', 'retryable', 'conflicted')
                   )
                   AND (
                     EXISTS (
                       SELECT 1 FROM delivery_outbox AS delivered
                       WHERE delivered.scan_run_id = run.id
                         AND delivered.state = 'delivered'
                         AND delivered.remote_receipt_json IS NOT NULL
                         AND json_valid(delivered.remote_receipt_json)
                         AND json_extract(delivered.remote_receipt_json, '$.verification') = 'exact_noop'
                         AND json_type(delivered.remote_receipt_json, '$.remote_assignment_id') = 'text'
                         AND json_type(delivered.remote_receipt_json, '$.remote_url') = 'text'
                         AND json_extract(delivered.remote_receipt_json, '$.destination_collection_id') = delivered.destination_collection_id
                         AND json_extract(delivered.remote_receipt_json, '$.destination_asset_id') = delivered.destination_asset_id
                         AND json_extract(delivered.remote_receipt_json, '$.stig_id') = delivered.stig_id
                         AND json_extract(delivered.remote_receipt_json, '$.stig_revision') = delivered.stig_revision
                         AND json_extract(delivered.remote_receipt_json, '$.remote_assignment_id') = delivered.stig_id || ':' || delivered.stig_revision
                         AND json_valid(delivered.payload_json)
                         AND json_type(delivered.payload_json, '$.reviews') = 'array'
                         AND json_array_length(delivered.payload_json, '$.reviews') > 0
                         AND json_extract(delivered.remote_receipt_json, '$.receipt.reviews_sent') = 0
                         AND json_extract(delivered.remote_receipt_json, '$.receipt.inserted') = 0
                         AND json_extract(delivered.remote_receipt_json, '$.receipt.updated') = 0
                         AND json_extract(delivered.remote_receipt_json, '$.receipt.reviews_considered') = json_array_length(delivered.payload_json, '$.reviews')
                         AND json_extract(delivered.remote_receipt_json, '$.receipt.unchanged') = json_array_length(delivered.payload_json, '$.reviews')
                         AND CAST(json_extract(delivered.remote_receipt_json, '$.receipt.collection_id') AS TEXT) = delivered.destination_collection_id
                         AND CAST(json_extract(delivered.remote_receipt_json, '$.receipt.asset_id') AS TEXT) = delivered.destination_asset_id
                         AND json_extract(delivered.remote_receipt_json, '$.receipt.benchmark_id') = delivered.stig_id
                         AND json_extract(delivered.remote_receipt_json, '$.receipt.revision') = delivered.stig_revision
                     )
                     OR EXISTS (
                       SELECT 1 FROM reconciliation_receipts AS imported
                       WHERE imported.run_id = run.id
                     )
                   )
                 ORDER BY run.completed_at ASC, run.id ASC LIMIT ?2",
            )?;
            let rows = statement.query_map(params![cutoff, limit as i64], |row| row.get(0))?;
            rows.collect::<Result<Vec<String>, _>>()?
        };

        let mut tombstones = Vec::with_capacity(run_ids.len());
        for run_id in run_ids {
            let run = query_scan_run(&tx, &run_id)?;
            let imported = latest_reconciliation_receipt_for_run(&tx, &run_id).optional()?;
            let proof = if let Some(receipt) = imported {
                let receipt_json = tx.query_row(
                    "SELECT receipt_json FROM reconciliation_receipts WHERE id = ?1",
                    params![receipt.id],
                    |row| row.get(0),
                )?;
                PurgeProof {
                    payload_sha256: receipt.payload_sha256,
                    destination_kind: receipt.destination_kind,
                    destination_instance_id: receipt.destination_instance_id,
                    destination_collection_id: receipt.destination_collection_id,
                    destination_asset_id: receipt.destination_asset_id,
                    destination_assignment_id: receipt.destination_assignment_id,
                    receipt_kind: "reconciliation_import".to_string(),
                    receipt_id: receipt.id,
                    receipt_sha256: receipt.receipt_sha256,
                    receipt_json,
                    remote_url: receipt.remote_url,
                }
            } else {
                verified_noop_purge_proof(&tx, &run_id)?
            };
            validate_stig_manager_gui_base_url(&proof.remote_url)?;
            tx.execute(
                "INSERT INTO operational_purge_tombstones
                 (run_id, request_sha256, result_sha256, evidence_sha256,
                  payload_sha256, destination_kind, destination_instance_id,
                  destination_collection_id, destination_asset_id,
                  destination_assignment_id, receipt_kind, receipt_id,
                  receipt_sha256, receipt_json, remote_url,
                  purged_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                         ?12, ?13, ?14, ?15, ?16)",
                params![
                    run.id,
                    run.request_sha256,
                    run.result_sha256,
                    run.evidence_sha256,
                    proof.payload_sha256,
                    proof.destination_kind,
                    proof.destination_instance_id,
                    proof.destination_collection_id,
                    proof.destination_asset_id,
                    proof.destination_assignment_id,
                    proof.receipt_kind,
                    proof.receipt_id,
                    proof.receipt_sha256,
                    proof.receipt_json,
                    proof.remote_url,
                    purged_at,
                ],
            )?;
            tx.execute(
                "DELETE FROM delivery_receipts WHERE delivery_id IN
                    (SELECT id FROM delivery_outbox WHERE scan_run_id = ?1)",
                params![run_id],
            )?;
            tx.execute(
                "DELETE FROM delivery_outbox WHERE scan_run_id = ?1",
                params![run_id],
            )?;
            tx.execute(
                "DELETE FROM scan_job_transitions WHERE job_id IN
                    (SELECT id FROM scan_jobs WHERE id IN (
                        SELECT job_id FROM scan_job_transitions WHERE run_id = ?1
                    ))",
                params![run_id],
            )?;
            tx.execute(
                "DELETE FROM scan_jobs WHERE id NOT IN
                    (SELECT job_id FROM scan_job_transitions)",
                [],
            )?;
            tx.execute(
                "DELETE FROM scan_run_evidence_artifacts WHERE run_id = ?1",
                params![run_id],
            )?;
            tx.execute("DELETE FROM scan_runs WHERE id = ?1", params![run_id])?;
            tombstones.push(query_operational_purge_tombstone(&tx, &run_id)?);
        }
        tx.execute(
            "DELETE FROM app_config WHERE key = 'scanner.operational_sweep_authorized'",
            [],
        )?;
        tx.commit()?;
        if !tombstones.is_empty() {
            self.checkpoint_sensitive_deletions()?;
        }
        Ok(tombstones)
    }
}

const SCAN_JOB_COLUMNS: &str = "job.id, current.state, job.sanitized_request_json,
     job.request_sha256, job.created_at, current.occurred_at,
     (SELECT started.occurred_at FROM scan_job_transitions AS started
      WHERE started.job_id = job.id AND started.state = 'running'
      ORDER BY started.id ASC LIMIT 1),
     CASE WHEN current.state IN ('completed', 'failed') THEN current.occurred_at ELSE NULL END,
     current.run_id, current.error";

const SCAN_EVIDENCE_METADATA_COLUMNS: &str = "run_id, state, envelope_schema, evidence_sha256,
     plaintext_sha256, ciphertext_sha256, ciphertext_size, algorithm, key_id,
     wrapped_dek_sha256, sealed_at, expires_at, purged_at, purge_reason";

const TARGET_CONNECTION_PROFILE_COLUMNS: &str = "id, scanner_profile_id, adapter, endpoint,
     port, credential_reference, last_observed_fingerprint, recent_operational_state,
     observed_at, created_at, updated_at";

const SCAN_CHECKPOINT_METADATA_COLUMNS: &str = "job_id, profile_id, plan_sha256,
     device_fingerprint_sha256, host_key_fingerprint, endpoint, port,
     completed_operation_ids_json, plaintext_sha256, ciphertext_sha256, algorithm,
     key_id, wrapped_dek_sha256, created_at, updated_at, expires_at";

fn validate_page(offset: usize, limit: usize) -> StorageResult<()> {
    if limit == 0 || limit > MAX_OPERATIONAL_PAGE_SIZE {
        return Err(StorageError::InvalidData(format!(
            "page limit must be between 1 and {MAX_OPERATIONAL_PAGE_SIZE}"
        )));
    }
    if offset > i64::MAX as usize {
        return Err(StorageError::InvalidData(
            "page offset is too large".to_string(),
        ));
    }
    Ok(())
}

fn validate_identifier(label: &str, value: &str) -> StorageResult<()> {
    validate_required(label, value)?;
    if value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(StorageError::InvalidData(format!(
            "{label} must contain at most 128 letters, digits, dots, underscores, or hyphens"
        )));
    }
    Ok(())
}

fn validate_endpoint(value: &str) -> StorageResult<()> {
    validate_required("target endpoint", value)?;
    if value.len() > 253
        || value.chars().any(char::is_whitespace)
        || value.chars().any(char::is_control)
        || value.contains('/')
        || value.contains('@')
    {
        return Err(StorageError::InvalidData(
            "target endpoint must be a hostname or address without credentials, paths, or whitespace"
                .to_string(),
        ));
    }
    Ok(())
}

fn validate_credential_reference(value: &str) -> StorageResult<()> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > 256 || trimmed.chars().any(char::is_control) {
        return Err(StorageError::InvalidData(
            "credential reference must contain 1 through 256 visible characters".to_string(),
        ));
    }
    let lowercase = trimmed.to_ascii_lowercase();
    if lowercase.starts_with("bearer ")
        || lowercase.starts_with("basic ")
        || lowercase.contains("password=")
        || lowercase.contains("passphrase=")
        || lowercase.contains("secret=")
        || lowercase.contains("token=")
        || trimmed.contains("-----BEGIN ")
    {
        return Err(StorageError::InvalidData(
            "credential reference appears to contain credential material".to_string(),
        ));
    }
    if !trimmed.contains(':') {
        return Err(StorageError::InvalidData(
            "credential reference must use a provider-qualified label such as vault:device-reader"
                .to_string(),
        ));
    }
    Ok(())
}

fn validate_target_connection_profile(profile: &NewTargetConnectionProfile) -> StorageResult<()> {
    validate_identifier("target connection profile id", &profile.id)?;
    validate_identifier("scanner profile id", &profile.scanner_profile_id)?;
    validate_identifier("adapter", &profile.adapter)?;
    validate_endpoint(&profile.endpoint)?;
    if profile.port == 0 {
        return Err(StorageError::InvalidData(
            "target port must be between 1 and 65535".to_string(),
        ));
    }
    if let Some(reference) = profile.credential_reference.as_deref() {
        validate_credential_reference(reference)?;
    }
    Ok(())
}

fn validate_fingerprint(label: &str, value: &str) -> StorageResult<()> {
    if value.len() > 256
        || value.chars().any(char::is_control)
        || !automatestig_core::remote::is_openssh_sha256_fingerprint(value)
    {
        return Err(StorageError::InvalidData(format!(
            "{label} must be an OpenSSH SHA256 fingerprint"
        )));
    }
    Ok(())
}

fn validate_operational_state(value: &str) -> StorageResult<()> {
    if !matches!(
        value,
        "ready" | "running" | "completed" | "failed" | "interrupted"
    ) {
        return Err(StorageError::InvalidData(
            "recent operational state is not recognized".to_string(),
        ));
    }
    Ok(())
}

fn validate_scan_operation_checkpoint(
    checkpoint: &NewScanOperationCheckpoint,
) -> StorageResult<()> {
    validate_required("scan checkpoint job id", &checkpoint.job_id)?;
    validate_identifier("scan checkpoint profile id", &checkpoint.profile_id)?;
    validate_sha256("scan checkpoint plan_sha256", &checkpoint.plan_sha256)?;
    validate_sha256(
        "scan checkpoint device_fingerprint_sha256",
        &checkpoint.device_fingerprint_sha256,
    )?;
    validate_fingerprint(
        "scan checkpoint host key fingerprint",
        &checkpoint.host_key_fingerprint,
    )?;
    validate_endpoint(&checkpoint.endpoint)?;
    if checkpoint.port == 0 {
        return Err(StorageError::InvalidData(
            "scan checkpoint port must be between 1 and 65535".to_string(),
        ));
    }
    let operation_ids: Vec<String> = serde_json::from_str(&checkpoint.completed_operation_ids_json)
        .map_err(|error| {
            StorageError::InvalidData(format!("completed operation IDs are invalid JSON: {error}"))
        })?;
    if operation_ids.len() > 1024
        || operation_ids.iter().any(|id| {
            id.is_empty()
                || id.len() > 128
                || !id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
        || operation_ids
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len()
            != operation_ids.len()
        || serde_json::to_string(&operation_ids).ok().as_deref()
            != Some(checkpoint.completed_operation_ids_json.as_str())
    {
        return Err(StorageError::InvalidData(
            "completed operation IDs must be a canonical unique JSON array".to_string(),
        ));
    }
    for (label, digest) in [
        (
            "scan checkpoint plaintext_sha256",
            &checkpoint.plaintext_sha256,
        ),
        (
            "scan checkpoint ciphertext_sha256",
            &checkpoint.ciphertext_sha256,
        ),
        (
            "scan checkpoint wrapped_dek_sha256",
            &checkpoint.wrapped_dek_sha256,
        ),
        ("scan checkpoint key_id", &checkpoint.key_id),
    ] {
        validate_sha256(label, digest)?;
    }
    if checkpoint.algorithm != SCAN_EVIDENCE_ENCRYPTION_ALGORITHM {
        return Err(StorageError::InvalidData(
            "unsupported scan checkpoint encryption algorithm".to_string(),
        ));
    }
    if checkpoint.ciphertext.len() < 28
        || checkpoint.ciphertext.len() > MAX_ENCRYPTED_SCAN_CHECKPOINT_BYTES
        || checkpoint.wrapped_dek.len() != 60
        || checkpoint.ciphertext_sha256 != sha256_bytes_hex(&checkpoint.ciphertext)
        || checkpoint.wrapped_dek_sha256 != sha256_bytes_hex(&checkpoint.wrapped_dek)
    {
        return Err(StorageError::InvalidData(
            "scan checkpoint encrypted bytes or digests are invalid".to_string(),
        ));
    }
    let remaining = checkpoint.expires_at.signed_duration_since(Utc::now());
    if remaining <= chrono::Duration::zero()
        || remaining > chrono::Duration::days(i64::from(MAX_SCAN_EVIDENCE_RETENTION_DAYS))
    {
        return Err(StorageError::InvalidData(
            "scan checkpoint expiry must be in the future and within the evidence retention bound"
                .to_string(),
        ));
    }
    Ok(())
}

fn validate_stig_manager_gui_base_url(value: &str) -> StorageResult<()> {
    if value.len() > 2048
        || value.chars().any(char::is_control)
        || !value.starts_with("https://")
        || value.contains('@')
        || value.contains('?')
        || value.contains('#')
        || !value.ends_with('/')
        || value["https://".len()..]
            .split('/')
            .next()
            .is_none_or(str::is_empty)
    {
        return Err(StorageError::InvalidData(
            "STIG Manager remote_url must be a credential-free HTTPS GUI base URL ending in / with no query or fragment"
                .to_string(),
        ));
    }
    Ok(())
}

fn validate_reconciliation_receipt_at(
    receipt: &NewReconciliationReceipt,
    imported_at: DateTime<Utc>,
) -> StorageResult<()> {
    validate_identifier("reconciliation receipt id", &receipt.id)?;
    if receipt.schema != "automatestig.receiver-reconciliation.v1" {
        return Err(StorageError::InvalidData(
            "unsupported reconciliation receipt schema".to_string(),
        ));
    }
    validate_required("reconciliation run id", &receipt.run_id)?;
    for (label, value) in [
        ("receipt payload_sha256", &receipt.payload_sha256),
        (
            "receipt received_rule_set_sha256",
            &receipt.received_rule_set_sha256,
        ),
        (
            "receipt independent_readback_sha256",
            &receipt.independent_readback_sha256,
        ),
        ("receipt receipt_sha256", &receipt.receipt_sha256),
    ] {
        validate_sha256(label, value)?;
    }
    for (label, value) in [
        ("destination kind", &receipt.destination_kind),
        ("destination instance", &receipt.destination_instance_id),
        ("destination collection", &receipt.destination_collection_id),
        ("destination asset", &receipt.destination_asset_id),
        ("destination assignment", &receipt.destination_assignment_id),
        ("receipt STIG", &receipt.stig_id),
        ("receipt STIG revision", &receipt.stig_revision),
    ] {
        validate_required(label, value)?;
        validate_sanitized_text(label, value)?;
    }
    let rule_ids: Vec<String> =
        serde_json::from_str(&receipt.received_rule_ids_json).map_err(|error| {
            StorageError::InvalidData(format!("received rule IDs are invalid JSON: {error}"))
        })?;
    if rule_ids.is_empty()
        || rule_ids.len() > 10_000
        || !rule_ids.windows(2).all(|pair| pair[0] < pair[1])
        || rule_ids.iter().any(|id| id.is_empty() || id.len() > 256)
        || serde_json::to_string(&rule_ids).ok().as_deref()
            != Some(receipt.received_rule_ids_json.as_str())
        || sha256_hex(&receipt.received_rule_ids_json) != receipt.received_rule_set_sha256
    {
        return Err(StorageError::InvalidData(
            "received rule IDs must be a non-empty, sorted, unique canonical JSON array bound by SHA-256"
                .to_string(),
        ));
    }
    validate_json("reconciliation receipt_json", &receipt.receipt_json)?;
    if sha256_hex(&receipt.receipt_json) != receipt.receipt_sha256 {
        return Err(StorageError::InvalidData(
            "reconciliation receipt digest does not match receipt_json".to_string(),
        ));
    }
    let document: serde_json::Value = serde_json::from_str(&receipt.receipt_json)
        .map_err(|error| StorageError::InvalidData(error.to_string()))?;
    let exact = |field: &str, expected: &str| {
        document.get(field).and_then(serde_json::Value::as_str) == Some(expected)
    };
    if !exact("schema", &receipt.schema)
        || !exact("run_id", &receipt.run_id)
        || !exact("payload_sha256", &receipt.payload_sha256)
        || !exact("destination_instance_id", &receipt.destination_instance_id)
        || !exact(
            "destination_collection_id",
            &receipt.destination_collection_id,
        )
        || !exact("destination_asset_id", &receipt.destination_asset_id)
        || !exact(
            "destination_assignment_id",
            &receipt.destination_assignment_id,
        )
        || !exact("stig_id", &receipt.stig_id)
        || !exact("stig_revision", &receipt.stig_revision)
        || !exact(
            "received_rule_set_sha256",
            &receipt.received_rule_set_sha256,
        )
        || !exact(
            "independent_readback_sha256",
            &receipt.independent_readback_sha256,
        )
        || !exact("remote_url", &receipt.remote_url)
    {
        return Err(StorageError::InvalidData(
            "reconciliation receipt_json does not match its exact storage bindings".to_string(),
        ));
    }
    let document_readback_at = document
        .get("independent_readback_at")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc));
    if document_readback_at != Some(receipt.independent_readback_at) {
        return Err(StorageError::InvalidData(
            "reconciliation receipt_json independent_readback_at does not match its exact storage binding"
                .to_string(),
        ));
    }
    if receipt.independent_readback_at > imported_at + chrono::Duration::minutes(5) {
        return Err(StorageError::InvalidData(
            "independent readback time is too far in the future".to_string(),
        ));
    }
    validate_stig_manager_gui_base_url(&receipt.remote_url)?;
    if receipt.producer_authentication != "unavailable"
        || receipt.signer_fingerprint.is_some()
        || receipt.detached_signature.is_some()
        || !receipt.operator_confirmed
    {
        return Err(StorageError::InvalidData(
            "trusted reconciliation-receipt signature verification is unavailable; an unsigned digest-bound receipt requires explicit operator confirmation"
                .to_string(),
        ));
    }
    Ok(())
}

fn validate_migration_run_binding(binding: &NewMigrationRunBinding) -> StorageResult<()> {
    validate_identifier("migration binding id", &binding.id)?;
    validate_required("retained scan run id", &binding.run_id)?;
    for (label, value) in [
        ("destination instance", &binding.destination_instance_id),
        ("destination collection", &binding.destination_collection_id),
        ("destination asset", &binding.destination_asset_id),
        ("destination assignment", &binding.destination_assignment_id),
        ("STIG id", &binding.stig_id),
        ("STIG revision", &binding.stig_revision),
        (
            "observed STIG Manager version",
            &binding.observed_stig_manager_version,
        ),
        (
            "observed server identity",
            &binding.observed_server_identity,
        ),
        ("operator source", &binding.operator_source),
    ] {
        validate_required(label, value)?;
        validate_sanitized_text(label, value)?;
    }
    validate_json("migration mapping_json", &binding.mapping_json)?;
    validate_sha256("migration mapping_sha256", &binding.mapping_sha256)?;
    if sha256_hex(&binding.mapping_json) != binding.mapping_sha256 {
        return Err(StorageError::InvalidData(
            "migration mapping digest does not match mapping_json".to_string(),
        ));
    }
    let document: serde_json::Value = serde_json::from_str(&binding.mapping_json)
        .map_err(|error| StorageError::InvalidData(error.to_string()))?;
    let exact = |field: &str, expected: &str| {
        document.get(field).and_then(serde_json::Value::as_str) == Some(expected)
    };
    if !exact("schema", "automatestig.migration-run-binding.v1")
        || !exact("run_id", &binding.run_id)
        || !exact("destination_instance_id", &binding.destination_instance_id)
        || !exact(
            "destination_collection_id",
            &binding.destination_collection_id,
        )
        || !exact("destination_asset_id", &binding.destination_asset_id)
        || !exact(
            "destination_assignment_id",
            &binding.destination_assignment_id,
        )
        || !exact("stig_id", &binding.stig_id)
        || !exact("stig_revision", &binding.stig_revision)
        || !exact(
            "observed_stig_manager_version",
            &binding.observed_stig_manager_version,
        )
        || !exact(
            "observed_server_identity",
            &binding.observed_server_identity,
        )
        || !exact("operator_source", &binding.operator_source)
    {
        return Err(StorageError::InvalidData(
            "migration mapping_json does not match its exact retained-run bindings".to_string(),
        ));
    }
    if binding.mapped_at > Utc::now() + chrono::Duration::minutes(5) {
        return Err(StorageError::InvalidData(
            "migration mapping time is too far in the future".to_string(),
        ));
    }
    Ok(())
}

#[derive(Debug)]
struct PurgeProof {
    payload_sha256: String,
    destination_kind: String,
    destination_instance_id: String,
    destination_collection_id: String,
    destination_asset_id: String,
    destination_assignment_id: String,
    receipt_kind: String,
    receipt_id: String,
    receipt_sha256: String,
    receipt_json: String,
    remote_url: String,
}

fn verified_noop_purge_proof(conn: &Connection, run_id: &str) -> StorageResult<PurgeProof> {
    let row = conn
        .query_row(
            "SELECT id, payload_sha256, destination_kind, destination_instance_id,
                    destination_collection_id, destination_asset_id, stig_id,
                    stig_revision, payload_json, remote_receipt_json
             FROM delivery_outbox
             WHERE scan_run_id = ?1 AND state = 'delivered'
               AND remote_receipt_json IS NOT NULL
             ORDER BY delivered_at DESC, id ASC LIMIT 1",
            params![run_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                ))
            },
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => StorageError::InvalidData(
                "terminal run has no verified no-op or reconciliation receipt".to_string(),
            ),
            other => other.into(),
        })?;
    let receipt: serde_json::Value = serde_json::from_str(&row.9).map_err(|error| {
        StorageError::InvalidData(format!("verified no-op receipt is invalid JSON: {error}"))
    })?;
    if receipt
        .get("verification")
        .and_then(serde_json::Value::as_str)
        != Some("exact_noop")
    {
        return Err(StorageError::InvalidData(
            "delivered receipt does not prove an exact no-op".to_string(),
        ));
    }
    let destination_asset_id = row.5.as_deref().ok_or_else(|| {
        StorageError::InvalidData("verified no-op receipt has no destination asset".to_string())
    })?;
    let expected_assignment_id = format!("{}:{}", row.6, row.7);
    let root_exact = |field: &str, expected: &str| {
        receipt.get(field).and_then(serde_json::Value::as_str) == Some(expected)
    };
    if !root_exact("destination_collection_id", &row.4)
        || !root_exact("destination_asset_id", destination_asset_id)
        || !root_exact("stig_id", &row.6)
        || !root_exact("stig_revision", &row.7)
        || !root_exact("remote_assignment_id", &expected_assignment_id)
    {
        return Err(StorageError::InvalidData(
            "verified no-op receipt does not match its exact delivery destination".to_string(),
        ));
    }
    let payload: serde_json::Value = serde_json::from_str(&row.8).map_err(|error| {
        StorageError::InvalidData(format!("verified no-op payload is invalid JSON: {error}"))
    })?;
    let review_count = payload
        .get("reviews")
        .and_then(serde_json::Value::as_array)
        .map(Vec::len)
        .filter(|count| *count > 0)
        .ok_or_else(|| {
            StorageError::InvalidData(
                "verified no-op payload has no scanner-owned review array".to_string(),
            )
        })?;
    let typed = receipt.get("receipt").ok_or_else(|| {
        StorageError::InvalidData("verified no-op proof has no typed receipt".to_string())
    })?;
    let numeric_id_matches = |field: &str, expected: &str| {
        typed.get(field).is_some_and(|value| {
            value.as_str() == Some(expected)
                || value
                    .as_u64()
                    .is_some_and(|number| number.to_string() == expected)
        })
    };
    let count = |field: &str| typed.get(field).and_then(serde_json::Value::as_u64);
    if !numeric_id_matches("collection_id", &row.4)
        || !numeric_id_matches("asset_id", destination_asset_id)
        || typed
            .get("benchmark_id")
            .and_then(serde_json::Value::as_str)
            != Some(row.6.as_str())
        || typed.get("revision").and_then(serde_json::Value::as_str) != Some(row.7.as_str())
        || count("reviews_considered") != u64::try_from(review_count).ok()
        || count("unchanged") != u64::try_from(review_count).ok()
        || count("reviews_sent") != Some(0)
        || count("inserted") != Some(0)
        || count("updated") != Some(0)
    {
        return Err(StorageError::InvalidData(
            "verified no-op receipt counts or typed target do not prove zero remote writes"
                .to_string(),
        ));
    }
    let remote_url = receipt
        .get("remote_url")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            StorageError::InvalidData(
                "verified no-op receipt has no STIG Manager GUI base remote_url".to_string(),
            )
        })?
        .to_string();
    Ok(PurgeProof {
        payload_sha256: row.1,
        destination_kind: row.2,
        destination_instance_id: row.3,
        destination_collection_id: row.4,
        destination_asset_id: destination_asset_id.to_string(),
        destination_assignment_id: expected_assignment_id,
        receipt_kind: "verified_noop".to_string(),
        receipt_id: row.0,
        receipt_sha256: sha256_hex(&row.9),
        receipt_json: row.9,
        remote_url,
    })
}

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

fn query_target_connection_profile(
    conn: &Connection,
    id: &str,
) -> StorageResult<TargetConnectionProfileRecord> {
    let sql = format!(
        "SELECT {TARGET_CONNECTION_PROFILE_COLUMNS}
         FROM target_connection_profiles WHERE id = ?1"
    );
    conn.query_row(&sql, params![id], target_connection_profile_from_row)
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => {
                StorageError::NotFound(format!("Target connection profile {id}"))
            }
            other => other.into(),
        })
}

fn target_connection_profile_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<TargetConnectionProfileRecord> {
    let port: i64 = row.get(4)?;
    Ok(TargetConnectionProfileRecord {
        id: row.get(0)?,
        scanner_profile_id: row.get(1)?,
        adapter: row.get(2)?,
        endpoint: row.get(3)?,
        port: u16::try_from(port).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                4,
                rusqlite::types::Type::Integer,
                Box::new(error),
            )
        })?,
        credential_reference: row.get(5)?,
        last_observed_fingerprint: row.get(6)?,
        recent_operational_state: row.get(7)?,
        observed_at: row.get(8)?,
        created_at: row.get(9)?,
        updated_at: row.get(10)?,
    })
}

fn query_scan_operation_checkpoint_metadata(
    conn: &Connection,
    job_id: &str,
) -> StorageResult<ScanOperationCheckpointMetadata> {
    let sql = format!(
        "SELECT {SCAN_CHECKPOINT_METADATA_COLUMNS}
         FROM scan_operation_checkpoints WHERE job_id = ?1"
    );
    conn.query_row(
        &sql,
        params![job_id],
        scan_operation_checkpoint_metadata_from_row,
    )
    .map_err(|error| match error {
        rusqlite::Error::QueryReturnedNoRows => {
            StorageError::NotFound(format!("Operation checkpoint for scan job {job_id}"))
        }
        other => other.into(),
    })
}

fn query_scan_operation_checkpoint(
    conn: &Connection,
    job_id: &str,
) -> StorageResult<RetainedScanOperationCheckpoint> {
    let sql = format!(
        "SELECT {SCAN_CHECKPOINT_METADATA_COLUMNS}, ciphertext, wrapped_dek
         FROM scan_operation_checkpoints WHERE job_id = ?1"
    );
    conn.query_row(&sql, params![job_id], |row| {
        Ok(RetainedScanOperationCheckpoint {
            metadata: scan_operation_checkpoint_metadata_from_row(row)?,
            ciphertext: row.get(16)?,
            wrapped_dek: row.get(17)?,
        })
    })
    .map_err(|error| match error {
        rusqlite::Error::QueryReturnedNoRows => {
            StorageError::NotFound(format!("Operation checkpoint for scan job {job_id}"))
        }
        other => other.into(),
    })
}

fn scan_operation_checkpoint_metadata_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<ScanOperationCheckpointMetadata> {
    let port: i64 = row.get(6)?;
    let operation_ids_json: String = row.get(7)?;
    let completed_operation_ids = serde_json::from_str(&operation_ids_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(7, rusqlite::types::Type::Text, Box::new(error))
    })?;
    Ok(ScanOperationCheckpointMetadata {
        job_id: row.get(0)?,
        profile_id: row.get(1)?,
        plan_sha256: row.get(2)?,
        device_fingerprint_sha256: row.get(3)?,
        host_key_fingerprint: row.get(4)?,
        endpoint: row.get(5)?,
        port: u16::try_from(port).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                6,
                rusqlite::types::Type::Integer,
                Box::new(error),
            )
        })?,
        completed_operation_ids,
        plaintext_sha256: row.get(8)?,
        ciphertext_sha256: row.get(9)?,
        algorithm: row.get(10)?,
        key_id: row.get(11)?,
        wrapped_dek_sha256: row.get(12)?,
        created_at: row.get(13)?,
        updated_at: row.get(14)?,
        expires_at: row.get(15)?,
    })
}

fn query_reconciliation_receipt(
    conn: &Connection,
    id: &str,
) -> StorageResult<ReconciliationReceiptRecord> {
    conn.query_row(
        "SELECT id, schema, run_id, payload_sha256, destination_kind,
                destination_instance_id, destination_collection_id,
                destination_asset_id, destination_assignment_id, stig_id, stig_revision,
                received_rule_ids_json, received_rule_set_sha256,
                independent_readback_sha256, independent_readback_at,
                receipt_sha256, remote_url, producer_authentication,
                signer_fingerprint, operator_confirmed, imported_at
         FROM reconciliation_receipts WHERE id = ?1",
        params![id],
        reconciliation_receipt_from_row,
    )
    .map_err(|error| match error {
        rusqlite::Error::QueryReturnedNoRows => {
            StorageError::NotFound(format!("Reconciliation receipt {id}"))
        }
        other => other.into(),
    })
}

fn latest_reconciliation_receipt_for_run(
    conn: &Connection,
    run_id: &str,
) -> rusqlite::Result<ReconciliationReceiptRecord> {
    conn.query_row(
        "SELECT id, schema, run_id, payload_sha256, destination_kind,
                destination_instance_id, destination_collection_id,
                destination_asset_id, destination_assignment_id, stig_id, stig_revision,
                received_rule_ids_json, received_rule_set_sha256,
                independent_readback_sha256, independent_readback_at,
                receipt_sha256, remote_url, producer_authentication,
                signer_fingerprint, operator_confirmed, imported_at
         FROM reconciliation_receipts WHERE run_id = ?1
         ORDER BY imported_at DESC, id DESC LIMIT 1",
        params![run_id],
        reconciliation_receipt_from_row,
    )
}

fn reconciliation_receipt_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<ReconciliationReceiptRecord> {
    let received_rule_ids_json: String = row.get(11)?;
    let received_rule_ids = serde_json::from_str(&received_rule_ids_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(11, rusqlite::types::Type::Text, Box::new(error))
    })?;
    Ok(ReconciliationReceiptRecord {
        id: row.get(0)?,
        schema: row.get(1)?,
        run_id: row.get(2)?,
        payload_sha256: row.get(3)?,
        destination_kind: row.get(4)?,
        destination_instance_id: row.get(5)?,
        destination_collection_id: row.get(6)?,
        destination_asset_id: row.get(7)?,
        destination_assignment_id: row.get(8)?,
        stig_id: row.get(9)?,
        stig_revision: row.get(10)?,
        received_rule_ids,
        received_rule_set_sha256: row.get(12)?,
        independent_readback_sha256: row.get(13)?,
        independent_readback_at: row.get(14)?,
        receipt_sha256: row.get(15)?,
        remote_url: row.get(16)?,
        producer_authentication: row.get(17)?,
        signer_fingerprint: row.get(18)?,
        operator_confirmed: row.get(19)?,
        imported_at: row.get(20)?,
    })
}

fn query_operational_purge_tombstone(
    conn: &Connection,
    run_id: &str,
) -> StorageResult<OperationalPurgeTombstone> {
    conn.query_row(
        "SELECT id, run_id, request_sha256, result_sha256, evidence_sha256,
                payload_sha256, destination_kind, destination_instance_id,
                destination_collection_id, destination_asset_id,
                destination_assignment_id, receipt_kind, receipt_id,
                receipt_sha256, receipt_json, remote_url,
                purged_at
         FROM operational_purge_tombstones WHERE run_id = ?1",
        params![run_id],
        operational_purge_tombstone_from_row,
    )
    .map_err(Into::into)
}

fn operational_purge_tombstone_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<OperationalPurgeTombstone> {
    Ok(OperationalPurgeTombstone {
        id: row.get(0)?,
        run_id: row.get(1)?,
        request_sha256: row.get(2)?,
        result_sha256: row.get(3)?,
        evidence_sha256: row.get(4)?,
        payload_sha256: row.get(5)?,
        destination_kind: row.get(6)?,
        destination_instance_id: row.get(7)?,
        destination_collection_id: row.get(8)?,
        destination_asset_id: row.get(9)?,
        destination_assignment_id: row.get(10)?,
        receipt_kind: row.get(11)?,
        receipt_id: row.get(12)?,
        receipt_sha256: row.get(13)?,
        receipt_json: row.get(14)?,
        remote_url: row.get(15)?,
        purged_at: row.get(16)?,
    })
}

fn query_migration_run_binding(
    conn: &Connection,
    run_id: &str,
) -> StorageResult<MigrationRunBindingRecord> {
    conn.query_row(
        "SELECT id, run_id, destination_instance_id, destination_collection_id,
                destination_asset_id, destination_assignment_id, stig_id,
                stig_revision, observed_stig_manager_version,
                observed_server_identity, mapping_sha256, mapped_at,
                operator_source, created_at
         FROM migration_run_bindings WHERE run_id = ?1",
        params![run_id],
        |row| {
            Ok(MigrationRunBindingRecord {
                id: row.get(0)?,
                run_id: row.get(1)?,
                destination_instance_id: row.get(2)?,
                destination_collection_id: row.get(3)?,
                destination_asset_id: row.get(4)?,
                destination_assignment_id: row.get(5)?,
                stig_id: row.get(6)?,
                stig_revision: row.get(7)?,
                observed_stig_manager_version: row.get(8)?,
                observed_server_identity: row.get(9)?,
                mapping_sha256: row.get(10)?,
                mapped_at: row.get(11)?,
                operator_source: row.get(12)?,
                created_at: row.get(13)?,
            })
        },
    )
    .map_err(|error| match error {
        rusqlite::Error::QueryReturnedNoRows => {
            StorageError::NotFound(format!("Migration binding for scan run {run_id}"))
        }
        other => other.into(),
    })
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
    if matches!(
        result.get("schema").and_then(serde_json::Value::as_str),
        Some(automatestig_core::selected_run_handoff::SCANNER_RUN_SCHEMA_V2)
            | Some(automatestig_core::selected_run_handoff::SCANNER_RUN_SCHEMA_V3)
    ) {
        return Err(StorageError::InvalidData(
            "current scanner-run artifacts must be stored atomically with encrypted replay evidence"
                .to_string(),
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
    if !matches!(
        result.get("schema").and_then(serde_json::Value::as_str),
        Some(automatestig_core::selected_run_handoff::SCANNER_RUN_SCHEMA_V2)
            | Some(automatestig_core::selected_run_handoff::SCANNER_RUN_SCHEMA_V3)
    ) {
        return Err(StorageError::InvalidData(
            "encrypted scanner evidence requires the current scanner-run result metadata"
                .to_string(),
        ));
    }
    if result.get("evidence_envelope").is_some() {
        return Err(StorageError::InvalidData(
            "scanner-run result must not embed a plaintext evidence envelope".to_string(),
        ));
    }
    Ok(())
}
