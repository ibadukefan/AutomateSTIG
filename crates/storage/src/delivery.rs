//! Durable delivery outbox, leases, state transitions, and receipts.

use super::*;

struct DeliveryFinish<'a> {
    outcome: DeliveryState,
    error: Option<&'a str>,
    remote_receipt_json: Option<&'a str>,
    destination_asset_id: Option<&'a str>,
    retry_at: Option<DateTime<Utc>>,
}

impl Database {
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

    /// Bounded runtime page of delivery rows.
    pub fn list_deliveries_page(
        &self,
        state: Option<DeliveryState>,
        offset: usize,
        limit: usize,
    ) -> StorageResult<Vec<DeliveryRecord>> {
        validate_delivery_page(offset, limit)?;
        let sql = format!(
            "SELECT {DELIVERY_COLUMNS} FROM delivery_outbox
             WHERE (?1 IS NULL OR state = ?1)
             ORDER BY created_at ASC, id ASC LIMIT ?2 OFFSET ?3"
        );
        let state = state.map(DeliveryState::as_str);
        let mut statement = self.conn.prepare(&sql)?;
        let rows = statement.query_map(
            params![state, limit as i64, offset as i64],
            delivery_from_row,
        )?;
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

    pub fn list_delivery_receipts_page(
        &self,
        delivery_id: &str,
        offset: usize,
        limit: usize,
    ) -> StorageResult<Vec<DeliveryReceipt>> {
        validate_required("delivery_id", delivery_id)?;
        validate_delivery_page(offset, limit)?;
        let mut statement = self.conn.prepare(
            "SELECT id, delivery_id, attempt_number, outcome, recorded_at, error,
                    remote_receipt_json
             FROM delivery_receipts WHERE delivery_id = ?1
             ORDER BY attempt_number ASC LIMIT ?2 OFFSET ?3",
        )?;
        let rows = statement.query_map(
            params![delivery_id, limit as i64, offset as i64],
            delivery_receipt_from_row,
        )?;
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
}

fn validate_delivery_page(offset: usize, limit: usize) -> StorageResult<()> {
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

const DELIVERY_COLUMNS: &str = "id, scan_run_id, state, destination_kind, destination_instance_id,
     destination_collection_id, destination_asset_id, stig_id, stig_revision,
     request_json, request_sha256, payload_json, payload_sha256, attempt_count,
     last_error, remote_receipt_json, created_at, updated_at, first_attempted_at,
     last_attempted_at, delivered_at, next_attempt_at, claimed_by, claim_token,
     claim_expires_at";

pub(super) fn query_delivery(conn: &Connection, id: &str) -> StorageResult<DeliveryRecord> {
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

pub(super) fn validate_pending_delivery(delivery: &NewPendingDelivery) -> StorageResult<()> {
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
