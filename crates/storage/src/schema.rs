//! Database connection lifecycle, schema creation, and migrations.

use super::*;

impl Database {
    /// Open or create a database at the given path.
    pub fn open(path: &Path) -> StorageResult<Self> {
        let (directory_custody, database_custody) = secure_database_path(path)?;
        let conn = Connection::open(path)?;
        conn.busy_timeout(StdDuration::from_secs(5))?;
        let db = Self {
            conn,
            _directory_custody: Some(directory_custody),
            _database_custody: Some(database_custody),
        };
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
        let (directory_custody, database_custody) = verify_existing_database_path(
            path,
            automatestig_core::path_safety::SensitiveFileSharing::ReadOnly,
        )?;
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        conn.busy_timeout(StdDuration::from_secs(5))?;
        conn.pragma_update(None, "query_only", true)?;
        let db = Self {
            conn,
            _directory_custody: Some(directory_custody),
            _database_custody: Some(database_custody),
        };
        if let Some(version) = db.schema_version()? {
            if version > SCHEMA_VERSION {
                return Err(StorageError::InvalidData(format!(
                    "database schema version {version} is newer than supported version {SCHEMA_VERSION}"
                )));
            }
        }
        Ok(db)
    }

    /// Open an existing current-schema database with the narrow transition
    /// write capability.
    ///
    /// This path cannot create a database and deliberately performs no schema
    /// initialization, migration, permission repair, mutating pragma, restart
    /// recovery, evidence purge, or retention sweep. Both older and newer
    /// schemas fail closed. The returned type exposes only the immutable
    /// migration-run binding insert and its matching read.
    pub fn open_existing_for_transition_write(
        path: &Path,
    ) -> StorageResult<TransitionWriteDatabase> {
        let (directory_custody, database_custody) = verify_existing_database_path(
            path,
            automatestig_core::path_safety::SensitiveFileSharing::ReadWrite,
        )?;
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        conn.busy_timeout(StdDuration::from_secs(5))?;
        let database = Self {
            conn,
            _directory_custody: Some(directory_custody),
            _database_custody: Some(database_custody),
        };
        match database.schema_version()? {
            Some(version) if version == SCHEMA_VERSION => {}
            Some(version) => {
                return Err(StorageError::InvalidData(format!(
                    "database schema version {version} does not exactly match required transition-write version {SCHEMA_VERSION}"
                )))
            }
            None => {
                return Err(StorageError::InvalidData(format!(
                    "database has no declared schema version; transition-write requires version {SCHEMA_VERSION}"
                )))
            }
        }
        Ok(TransitionWriteDatabase { database })
    }

    /// Create an in-memory database (for testing).
    pub fn in_memory() -> StorageResult<Self> {
        let conn = Connection::open_in_memory()?;
        conn.busy_timeout(StdDuration::from_secs(5))?;
        let db = Self {
            conn,
            _directory_custody: None,
            _database_custody: None,
        };
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
             END;

             CREATE TABLE IF NOT EXISTS target_connection_profiles (
                id TEXT PRIMARY KEY,
                scanner_profile_id TEXT NOT NULL,
                adapter TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
                credential_reference TEXT,
                last_observed_fingerprint TEXT,
                recent_operational_state TEXT CHECK (
                    recent_operational_state IS NULL OR recent_operational_state IN (
                        'ready', 'running', 'completed', 'failed', 'interrupted'
                    )
                ),
                observed_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
             );

             CREATE INDEX IF NOT EXISTS idx_target_connection_profiles_recent
                ON target_connection_profiles(updated_at DESC, id ASC);

             CREATE TABLE IF NOT EXISTS scan_operation_checkpoints (
                job_id TEXT PRIMARY KEY,
                profile_id TEXT NOT NULL,
                plan_sha256 TEXT NOT NULL,
                device_fingerprint_sha256 TEXT NOT NULL,
                host_key_fingerprint TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
                completed_operation_ids_json TEXT NOT NULL,
                plaintext_sha256 TEXT NOT NULL,
                ciphertext_sha256 TEXT NOT NULL,
                algorithm TEXT NOT NULL,
                key_id TEXT NOT NULL,
                wrapped_dek_sha256 TEXT NOT NULL,
                ciphertext BLOB NOT NULL,
                wrapped_dek BLOB NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY (job_id) REFERENCES scan_jobs(id) ON DELETE CASCADE
             );

             CREATE INDEX IF NOT EXISTS idx_scan_operation_checkpoints_expiry
                ON scan_operation_checkpoints(expires_at, job_id);

             CREATE TABLE IF NOT EXISTS reconciliation_receipts (
                id TEXT PRIMARY KEY,
                schema TEXT NOT NULL,
                run_id TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL,
                destination_kind TEXT NOT NULL,
                destination_instance_id TEXT NOT NULL,
                destination_collection_id TEXT NOT NULL,
                destination_asset_id TEXT NOT NULL,
                destination_assignment_id TEXT NOT NULL,
                stig_id TEXT NOT NULL,
                stig_revision TEXT NOT NULL,
                received_rule_ids_json TEXT NOT NULL,
                received_rule_set_sha256 TEXT NOT NULL,
                independent_readback_sha256 TEXT NOT NULL,
                independent_readback_at TEXT NOT NULL,
                receipt_json TEXT NOT NULL,
                receipt_sha256 TEXT NOT NULL,
                remote_url TEXT NOT NULL,
                producer_authentication TEXT NOT NULL CHECK (
                    producer_authentication IN ('unavailable', 'trusted_detached_signature')
                ),
                signer_fingerprint TEXT,
                detached_signature BLOB,
                operator_confirmed INTEGER NOT NULL CHECK (operator_confirmed IN (0, 1)),
                imported_at TEXT NOT NULL,
                CHECK (
                    (producer_authentication = 'unavailable'
                        AND signer_fingerprint IS NULL AND detached_signature IS NULL
                        AND operator_confirmed = 1)
                    OR
                    (producer_authentication = 'trusted_detached_signature'
                        AND signer_fingerprint IS NOT NULL AND detached_signature IS NOT NULL)
                )
             );

             CREATE UNIQUE INDEX IF NOT EXISTS idx_reconciliation_receipts_run_digest
                ON reconciliation_receipts(run_id, receipt_sha256);

             CREATE TRIGGER IF NOT EXISTS reconciliation_receipts_no_update
             BEFORE UPDATE ON reconciliation_receipts
             BEGIN
                SELECT RAISE(ABORT, 'reconciliation receipts are append-only');
             END;

             CREATE TRIGGER IF NOT EXISTS reconciliation_receipts_no_delete
             BEFORE DELETE ON reconciliation_receipts
             BEGIN
                SELECT RAISE(ABORT, 'reconciliation receipts are append-only');
             END;

             CREATE TABLE IF NOT EXISTS operational_purge_tombstones (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL UNIQUE,
                request_sha256 TEXT NOT NULL,
                result_sha256 TEXT NOT NULL,
                evidence_sha256 TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL,
                destination_kind TEXT NOT NULL,
                destination_instance_id TEXT NOT NULL,
                destination_collection_id TEXT NOT NULL,
                destination_asset_id TEXT NOT NULL,
                destination_assignment_id TEXT NOT NULL,
                receipt_kind TEXT NOT NULL CHECK (
                    receipt_kind IN ('verified_noop', 'reconciliation_import')
                ),
                receipt_id TEXT NOT NULL,
                receipt_sha256 TEXT NOT NULL,
                receipt_json TEXT NOT NULL,
                remote_url TEXT NOT NULL,
                purged_at TEXT NOT NULL
             );

             CREATE TRIGGER IF NOT EXISTS operational_purge_tombstones_no_update
             BEFORE UPDATE ON operational_purge_tombstones
             BEGIN
                SELECT RAISE(ABORT, 'operational purge tombstones are append-only');
             END;

             CREATE TRIGGER IF NOT EXISTS operational_purge_tombstones_no_delete
             BEFORE DELETE ON operational_purge_tombstones
             BEGIN
                SELECT RAISE(ABORT, 'operational purge tombstones are append-only');
             END;

             CREATE TABLE IF NOT EXISTS migration_run_bindings (
                id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL UNIQUE,
                destination_instance_id TEXT NOT NULL,
                destination_collection_id TEXT NOT NULL,
                destination_asset_id TEXT NOT NULL,
                destination_assignment_id TEXT NOT NULL,
                stig_id TEXT NOT NULL,
                stig_revision TEXT NOT NULL,
                observed_stig_manager_version TEXT NOT NULL,
                observed_server_identity TEXT NOT NULL,
                mapping_json TEXT NOT NULL,
                mapping_sha256 TEXT NOT NULL,
                mapped_at TEXT NOT NULL,
                operator_source TEXT NOT NULL,
                created_at TEXT NOT NULL
             );

             CREATE TRIGGER IF NOT EXISTS migration_run_bindings_no_update
             BEFORE UPDATE ON migration_run_bindings
             BEGIN
                SELECT RAISE(ABORT, 'migration run bindings are append-only');
             END;

             CREATE TRIGGER IF NOT EXISTS migration_run_bindings_no_delete
             BEFORE DELETE ON migration_run_bindings
             BEGIN
                SELECT RAISE(ABORT, 'migration run bindings are append-only');
             END;

             -- Operational history may be removed only inside the
             -- receipt-gated sweeper transaction. A scoped marker is set and
             -- cleared by storage in that same transaction; direct SQL and
             -- normal application paths remain append-only.
             DROP TRIGGER IF EXISTS scan_runs_no_delete;
             CREATE TRIGGER scan_runs_no_delete
             BEFORE DELETE ON scan_runs
             WHEN NOT EXISTS (SELECT 1 FROM app_config WHERE key = 'scanner.operational_sweep_authorized' AND value = '1')
             BEGIN SELECT RAISE(ABORT, 'scan runs are retained'); END;
             DROP TRIGGER IF EXISTS scan_run_evidence_no_delete;
             CREATE TRIGGER scan_run_evidence_no_delete
             BEFORE DELETE ON scan_run_evidence_artifacts
             WHEN NOT EXISTS (SELECT 1 FROM app_config WHERE key = 'scanner.operational_sweep_authorized' AND value = '1')
             BEGIN SELECT RAISE(ABORT, 'scan evidence metadata is retained'); END;
             DROP TRIGGER IF EXISTS scan_jobs_no_delete;
             CREATE TRIGGER scan_jobs_no_delete
             BEFORE DELETE ON scan_jobs
             WHEN NOT EXISTS (SELECT 1 FROM app_config WHERE key = 'scanner.operational_sweep_authorized' AND value = '1')
             BEGIN SELECT RAISE(ABORT, 'scan jobs are retained'); END;
             DROP TRIGGER IF EXISTS scan_job_transitions_no_delete;
             CREATE TRIGGER scan_job_transitions_no_delete
             BEFORE DELETE ON scan_job_transitions
             WHEN NOT EXISTS (SELECT 1 FROM app_config WHERE key = 'scanner.operational_sweep_authorized' AND value = '1')
             BEGIN SELECT RAISE(ABORT, 'scan job transitions are retained'); END;
             DROP TRIGGER IF EXISTS delivery_outbox_no_delete;
             CREATE TRIGGER delivery_outbox_no_delete
             BEFORE DELETE ON delivery_outbox
             WHEN NOT EXISTS (SELECT 1 FROM app_config WHERE key = 'scanner.operational_sweep_authorized' AND value = '1')
             BEGIN SELECT RAISE(ABORT, 'delivery outbox is retained'); END;
             DROP TRIGGER IF EXISTS delivery_receipts_no_delete;
             CREATE TRIGGER delivery_receipts_no_delete
             BEFORE DELETE ON delivery_receipts
             WHEN NOT EXISTS (SELECT 1 FROM app_config WHERE key = 'scanner.operational_sweep_authorized' AND value = '1')
             BEGIN SELECT RAISE(ABORT, 'delivery receipts are retained'); END;

             DROP TRIGGER IF EXISTS scan_job_transition_valid;
             CREATE TRIGGER scan_job_transition_valid
             BEFORE INSERT ON scan_job_transitions
             WHEN CASE NEW.state
                WHEN 'queued' THEN EXISTS (
                    SELECT 1 FROM scan_job_transitions WHERE job_id = NEW.job_id
                )
                WHEN 'running' THEN NOT (
                    COALESCE(
                        (SELECT state FROM scan_job_transitions
                         WHERE job_id = NEW.job_id ORDER BY id DESC LIMIT 1), ''
                    ) = 'queued'
                    OR (
                        COALESCE(
                            (SELECT state FROM scan_job_transitions
                             WHERE job_id = NEW.job_id ORDER BY id DESC LIMIT 1), ''
                        ) = 'failed'
                        AND EXISTS (
                            SELECT 1 FROM scan_operation_checkpoints
                            WHERE job_id = NEW.job_id
                        )
                    )
                )
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
}

fn secure_database_path(
    path: &Path,
) -> StorageResult<(
    automatestig_core::path_safety::SensitiveDirectoryGuard,
    std::fs::File,
)> {
    use automatestig_core::path_safety::{
        configure_no_follow, open_sensitive_file_with_sharing, validate_open_sensitive_file,
        validate_sensitive_directory, SensitiveFilePolicy, SensitiveFileSharing,
    };

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
    let directory_custody = validate_sensitive_directory(parent, "database parent")
        .map_err(|error| StorageError::UnsafePath(error.to_string()))?;

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
            configure_no_follow(&mut options);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
            }
            let file = options.open(path)?;
            validate_open_sensitive_file(&file, path, "database", SensitiveFilePolicy::Private)
                .map_err(|error| StorageError::UnsafePath(error.to_string()))?;
        }
        Err(error) => return Err(error.into()),
    }
    let database_custody = open_sensitive_file_with_sharing(
        path,
        "database",
        SensitiveFilePolicy::Private,
        SensitiveFileSharing::ReadWrite,
    )
    .map_err(|error| StorageError::UnsafePath(error.to_string()))?;
    Ok((directory_custody, database_custody))
}

/// Validate a database path without creating it or repairing its permissions.
fn verify_existing_database_path(
    path: &Path,
    sharing: automatestig_core::path_safety::SensitiveFileSharing,
) -> StorageResult<(
    automatestig_core::path_safety::SensitiveDirectoryGuard,
    std::fs::File,
)> {
    use automatestig_core::path_safety::{
        open_sensitive_file_with_sharing, validate_sensitive_directory, SensitiveFilePolicy,
    };

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

    let directory_custody = validate_sensitive_directory(parent, "database parent")
        .map_err(|error| StorageError::UnsafePath(error.to_string()))?;
    #[cfg(windows)]
    let policy = SensitiveFilePolicy::IntegrityProtected;
    #[cfg(not(windows))]
    let policy = SensitiveFilePolicy::UntrustedInput;
    let database_custody = open_sensitive_file_with_sharing(path, "database", policy, sharing)
        .map_err(|error| StorageError::UnsafePath(error.to_string()))?;
    Ok((directory_custody, database_custody))
}
