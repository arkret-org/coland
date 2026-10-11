mod queue_authority;

pub(crate) use queue_authority::enqueue_mls_welcome_in_connection;

use super::{
    AsyncConnection, AsyncPgConnection, BTreeMap, BTreeSet, BigInt, Bool, DeviceInventoryRecord,
    DeviceInventoryStore, DeviceKeyStore, DeviceMessageBatchCommitOutcome,
    DeviceMessageBatchInspection, DeviceMessageBatchRecord, DeviceMessageIntentRecord,
    DeviceMessageRecord, DeviceMessageStore, DeviceRevocationGateSelector,
    DeviceRevocationGateStatus, Integer, JsonPayloadRow, Jsonb, MaxSeqRow, Nullable,
    OneTimeKeyStore, OptionalExtension, PersistenceError, PersistenceResult, PgPool,
    PgTransactionError, QueryableByName, RecipientDeliveryRecord, RecipientQueueSelector,
    RunQueryDsl, Text, Timestamptz, Utc, Uuid, Value, async_trait, fresh_device_message_ack_token,
    pg_conn, sql_query, sql_types,
};
pub struct PgDeviceMessageStore {
    pub pool: PgPool,
}
#[derive(QueryableByName)]
struct DeviceMessageRow {
    #[diesel(sql_type = Text)]
    idempotency_key: String,
    #[diesel(sql_type = Text)]
    sender: String,
    #[diesel(sql_type = Text)]
    recipient: String,
    #[diesel(sql_type = Text)]
    device_id: String,
    #[diesel(sql_type = Jsonb)]
    recipient_device_authorization: Value,
    #[diesel(sql_type = BigInt)]
    position: i64,
    #[diesel(sql_type = Jsonb)]
    content: Value,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<Utc>,
}
impl TryFrom<DeviceMessageRow> for DeviceMessageRecord {
    type Error = PersistenceError;
    fn try_from(row: DeviceMessageRow) -> PersistenceResult<Self> {
        let record = Self {
            idempotency_key: row.idempotency_key,
            sender: row.sender,
            recipient: row.recipient,
            device_id: row.device_id,
            recipient_device_authorization: serde_json::from_value(
                row.recipient_device_authorization,
            )
            .map_err(PersistenceError::database)?,
            position: row.position,
            envelope: serde_json::from_value(row.content).map_err(|error| {
                PersistenceError::SchemaViolation(format!(
                    "queued DeviceMessage is not a closed envelope: {error}"
                ))
            })?,
        };
        record
            .validate_binding()
            .map_err(|error| PersistenceError::SchemaViolation(error.into()))?;
        if record.envelope.sent_at != row.created_at {
            return Err(PersistenceError::SchemaViolation(
                "queued DeviceMessage sent_at differs from its enqueue time".into(),
            ));
        }
        Ok(record)
    }
}
#[derive(QueryableByName)]
struct DeviceMessageAckTokenRow {
    #[diesel(sql_type = Text)]
    recipient: String,
    #[diesel(sql_type = Text)]
    device_id: String,
    #[diesel(sql_type = BigInt)]
    queue_position: i64,
    #[diesel(sql_type = Jsonb)]
    recipient_device_authorization: Value,
    #[diesel(sql_type = Timestamptz)]
    expires_at: chrono::DateTime<Utc>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    consumed_at: Option<chrono::DateTime<Utc>>,
}
#[derive(QueryableByName)]
struct DeviceMessageTxnRow {
    #[diesel(sql_type = Text)]
    request_digest: String,
    #[diesel(sql_type = Jsonb)]
    outcome: Value,
}
#[derive(QueryableByName)]
struct DeviceMessageIntentRow {
    #[diesel(sql_type = Text)]
    intent_digest: String,
    #[diesel(sql_type = Bool)]
    delivered: bool,
}
#[derive(QueryableByName)]
struct DeviceMessageSnapshotRow {
    #[diesel(sql_type = Text)]
    device_id: String,
    #[diesel(sql_type = Timestamptz)]
    updated_at: chrono::DateTime<Utc>,
}
#[async_trait]
impl DeviceMessageStore for PgDeviceMessageStore {
    async fn append(
        &self,
        device_revocation_gate: Option<&DeviceRevocationGateSelector>,
        message: DeviceMessageRecord,
        per_device_queue_capacity: usize,
    ) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            queue_authority::validate_recipient(&message)?;
            let mut selectors = vec![&message.recipient_device_authorization];
            selectors.extend(device_revocation_gate);
            crate::device_revocations::lock_artifact_devices_in_transaction(conn, &selectors).await?;
            crate::ensure_gate_allowed_in_transaction(conn, &message.recipient_device_authorization).await?;
            if let Some(selector) = device_revocation_gate {
                crate::ensure_gate_allowed_in_transaction(conn, selector).await?;
            }
            queue_authority::lock_delivery_order_in_transaction(conn).await?;
            if !queue_authority::human_queue_has_capacity_in_transaction(
                conn,
                &message,
                per_device_queue_capacity,
            )
            .await?
            {
                return Err(PersistenceError::Conflict(format!(
                    "{}: recipient queue is at capacity",
                    coland_storage::ConflictCode::RecipientQueueAtCapacity
                ))
                .into());
            }
            sql_query(
                "INSERT INTO device_messages \
             (id, idempotency_key, sender, recipient, device_id, position, content, created_at, recipient_device_authorization) \
             VALUES ($1, $2, $3, $4, $5, nextval('public.recipient_delivery_position_seq'), $6, $7, $8) \
             ON CONFLICT (recipient, device_id, position) DO NOTHING",
            )
            .bind::<sql_types::Uuid, _>(Uuid::new_v4())
            .bind::<Text, _>(&message.idempotency_key)
            .bind::<Text, _>(&message.sender)
            .bind::<Text, _>(&message.recipient)
            .bind::<Text, _>(&message.device_id)
            .bind::<Jsonb, _>(serde_json::to_value(&message.envelope).map_err(PersistenceError::database)?)
            .bind::<Timestamptz, _>(message.envelope.sent_at)
            .bind::<Jsonb, _>(serde_json::to_value(&message.recipient_device_authorization).map_err(PersistenceError::database)?)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
            Ok::<(), PgTransactionError>(())
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn inspect_batch(
        &self,
        request_key: &str,
        request_digest: &str,
        items: &[DeviceMessageIntentRecord],
    ) -> PersistenceResult<DeviceMessageBatchInspection> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let existing_request = sql_query(
            "SELECT request_digest, outcome FROM device_message_txns \
             WHERE key = $1 AND expires_at > NOW()",
        )
        .bind::<Text, _>(request_key)
        .get_result::<DeviceMessageTxnRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        if let Some(existing) = existing_request {
            return if existing.request_digest == request_digest {
                let outcome = serde_json::from_value(existing.outcome).map_err(|error| {
                    PersistenceError::Internal(format!(
                        "device message request outcome deserialize: {error}"
                    ))
                })?;
                Ok(DeviceMessageBatchInspection::Duplicate(outcome))
            } else {
                Ok(DeviceMessageBatchInspection::RequestConflict)
            };
        }
        let mut batch_digests = BTreeMap::new();
        let mut existing_message_outcomes = BTreeMap::new();
        for item in items {
            if let Some(digest) =
                batch_digests.insert(item.message_key.clone(), item.intent_digest.clone())
                && digest != item.intent_digest
            {
                return Ok(DeviceMessageBatchInspection::MessageConflict {
                    message_key: item.message_key.clone(),
                });
            }
            let existing = sql_query(
                "SELECT intent_digest, delivered FROM device_message_idempotency \
                 WHERE message_key = $1 AND expires_at > NOW()",
            )
            .bind::<Text, _>(&item.message_key)
            .get_result::<DeviceMessageIntentRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?;
            if let Some(existing) = existing {
                if existing.intent_digest != item.intent_digest {
                    return Ok(DeviceMessageBatchInspection::MessageConflict {
                        message_key: item.message_key.clone(),
                    });
                }
                existing_message_outcomes.insert(item.message_key.clone(), existing.delivered);
            }
        }
        Ok(DeviceMessageBatchInspection::Fresh {
            existing_message_outcomes,
        })
    }

    async fn commit_batch(
        &self,
        batch: DeviceMessageBatchRecord,
    ) -> PersistenceResult<DeviceMessageBatchCommitOutcome> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            let mut selectors = Vec::new();
            selectors.extend(batch.device_revocation_gate.as_ref());
            for item in &batch.items {
                if let Some(message) = &item.message {
                    queue_authority::validate_recipient(message)?;
                    selectors.push(&message.recipient_device_authorization);
                }
            }
            // Device locks always precede the shared idempotency ledger lock.
            crate::device_revocations::lock_artifact_devices_in_transaction(conn, &selectors).await?;
            sql_query(
                "LOCK TABLE device_message_txns, device_message_idempotency \
                 IN SHARE ROW EXCLUSIVE MODE",
            )
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
            sql_query("DELETE FROM device_message_txns WHERE expires_at <= NOW()")
                .execute(&mut *conn)
                .await
                .map_err(PersistenceError::database)?;
            sql_query("DELETE FROM device_message_idempotency WHERE expires_at <= NOW()")
                .execute(&mut *conn)
                .await
                .map_err(PersistenceError::database)?;

            let existing_request = sql_query(
                "SELECT request_digest, outcome FROM device_message_txns WHERE key = $1",
            )
            .bind::<Text, _>(&batch.request_key)
            .get_result::<DeviceMessageTxnRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?;
            if let Some(existing) = existing_request {
                return if existing.request_digest == batch.request_digest {
                    let outcome = serde_json::from_value(existing.outcome).map_err(|error| {
                        PersistenceError::Internal(format!(
                            "device message request outcome deserialize: {error}"
                        ))
                    })?;
                    Ok(DeviceMessageBatchCommitOutcome::Duplicate(outcome))
                } else {
                    Ok(DeviceMessageBatchCommitOutcome::RequestConflict)
                };
            }

            if let Some(selector) = batch.device_revocation_gate.as_ref() {
            match crate::gate_status_in_transaction(conn, selector).await? {
                DeviceRevocationGateStatus::Revoked { .. } => {
                    return Ok(DeviceMessageBatchCommitOutcome::DeviceRevoked);
                }
                status => status.ensure_allowed()?,
            }
            }

            if let Some(guard) = batch.sender_agent_guard.as_ref() {
                match crate::authority_commit::check_agent_endpoint_current_in_connection(
                    conn,
                    &guard.pcr_realm_id,
                    &guard.agent_id,
                    &guard.authorization_ref,
                    &guard.verification_method,
                    chrono::Utc::now(),
                )
                .await
                {
                    Ok(()) => {}
                    Err(PersistenceError::Conflict(_)) => {
                        return Ok(DeviceMessageBatchCommitOutcome::SenderAgentUnauthorized);
                    }
                    Err(error) => return Err(error.into()),
                }
            }

            if let Some(expected) = &batch.target_snapshot_guard {
                // Device authorization mutations take ROW EXCLUSIVE on this
                // table. SHARE holds them off until the request ledger and all
                // queue rows commit, closing the read/enqueue revocation race.
                sql_query("LOCK TABLE devices IN SHARE MODE")
                    .execute(&mut *conn)
                    .await
                    .map_err(PersistenceError::database)?;
                let current = sql_query(
                    "SELECT device_id, updated_at FROM devices \
                     WHERE actor_id = $1 AND revoked_at IS NULL \
                     AND verification_state = 'verified' ORDER BY device_id",
                )
                .bind::<Text, _>(&expected.recipient)
                .load::<DeviceMessageSnapshotRow>(&mut *conn)
                .await
                .map_err(PersistenceError::database)?
                .into_iter()
                .map(|row| (row.device_id, row.updated_at))
                .collect::<Vec<_>>();
                if current != expected.devices {
                    return Ok(DeviceMessageBatchCommitOutcome::SnapshotConflict);
                }
            }

            queue_authority::lock_delivery_order_in_transaction(conn).await?;

            let mut batch_digests = BTreeMap::new();
            let mut fresh_message_keys = BTreeSet::new();
            for item in &batch.items {
                if let Some(digest) = batch_digests.insert(
                    item.message_key.clone(),
                    item.intent_digest.clone(),
                ) && digest != item.intent_digest
                {
                    return Ok(DeviceMessageBatchCommitOutcome::MessageConflict {
                        message_key: item.message_key.clone(),
                    });
                }
                let existing = sql_query(
                    "SELECT intent_digest, delivered FROM device_message_idempotency \
                     WHERE message_key = $1",
                )
                .bind::<Text, _>(&item.message_key)
                .get_result::<DeviceMessageIntentRow>(&mut *conn)
                .await
                .optional()
                .map_err(PersistenceError::database)?;
                match existing {
                    Some(existing) if existing.intent_digest != item.intent_digest => {
                        return Ok(DeviceMessageBatchCommitOutcome::MessageConflict {
                            message_key: item.message_key.clone(),
                        });
                    }
                    Some(_) => {}
                    None => {
                        fresh_message_keys.insert(item.message_key.clone());
                    }
                }
            }

            let mut outcomes = BTreeMap::new();
            for item in batch.items {
                if !fresh_message_keys.remove(&item.message_key) {
                    let existing = sql_query(
                        "SELECT intent_digest, delivered FROM device_message_idempotency \
                         WHERE message_key = $1",
                    )
                    .bind::<Text, _>(&item.message_key)
                    .get_result::<DeviceMessageIntentRow>(&mut *conn)
                    .await
                    .map_err(PersistenceError::database)?;
                    outcomes.insert(item.message_key, existing.delivered);
                    continue;
                }
                let delivered = item.message.is_some();
                sql_query(
                    "INSERT INTO device_message_idempotency \
                     (message_key, intent_digest, delivered, expires_at, created_at) \
                     VALUES ($1, $2, $3, $4, NOW())",
                )
                .bind::<Text, _>(&item.message_key)
                .bind::<Text, _>(&item.intent_digest)
                .bind::<Bool, _>(delivered)
                .bind::<Timestamptz, _>(item.idempotency_expires_at)
                .execute(&mut *conn)
                .await
                .map_err(PersistenceError::database)?;
                outcomes.insert(item.message_key, delivered);
                let Some(message) = item.message else {
                    continue;
                };
                queue_authority::validate_recipient(&message)?;
                crate::ensure_gate_allowed_in_transaction(conn, &message.recipient_device_authorization).await?;
                if !queue_authority::human_queue_has_capacity_in_transaction(
                    conn,
                    &message,
                    batch.per_device_queue_capacity,
                )
                .await?
                {
                    // This may follow earlier queue and idempotency writes in
                    // the same batch. Refuse through the transaction error
                    // path so none of those writes can commit.
                    return Err(PersistenceError::Conflict(format!(
                        "{}: recipient queue is at capacity",
                        coland_storage::ConflictCode::RecipientQueueAtCapacity
                    ))
                    .into());
                }
                sql_query(
                    "INSERT INTO device_messages \
                     (id, idempotency_key, sender, recipient, device_id, position, content, created_at, recipient_device_authorization) \
                     VALUES ($1, $2, $3, $4, $5, nextval('public.recipient_delivery_position_seq'), $6, $7, $8)",
                )
                .bind::<sql_types::Uuid, _>(Uuid::new_v4())
                .bind::<Text, _>(&message.idempotency_key)
                .bind::<Text, _>(&message.sender)
                .bind::<Text, _>(&message.recipient)
                .bind::<Text, _>(&message.device_id)
                .bind::<Jsonb, _>(serde_json::to_value(&message.envelope).map_err(PersistenceError::database)?)
                .bind::<Timestamptz, _>(message.envelope.sent_at)
            .bind::<Jsonb, _>(serde_json::to_value(&message.recipient_device_authorization).map_err(PersistenceError::database)?)
                .execute(&mut *conn)
                .await
                .map_err(PersistenceError::database)?;
            }
            sql_query(
                "INSERT INTO device_message_txns \
                 (key, request_digest, outcome, expires_at, created_at) \
                 VALUES ($1, $2, $3, $4, NOW())",
            )
            .bind::<Text, _>(&batch.request_key)
            .bind::<Text, _>(&batch.request_digest)
            .bind::<Jsonb, _>(
                serde_json::to_value(&outcomes).map_err(|error| {
                    PersistenceError::Internal(format!(
                        "device message request outcome serialize: {error}"
                    ))
                })?,
            )
            .bind::<Timestamptz, _>(batch.idempotency_expires_at)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
            Ok(DeviceMessageBatchCommitOutcome::Stored(outcomes))
        })
        .await
        .map_err(PgTransactionError::into_persistence)
        .or_else(|error| {
            if error.conflict_code() == Some(coland_storage::ConflictCode::RecipientQueueAtCapacity) {
                Ok(DeviceMessageBatchCommitOutcome::QueueAtCapacity)
            } else {
                Err(error)
            }
        })
    }

    async fn issue_ack_token(
        &self,
        recipient: &str,
        device_id: &str,
        queue_position: i64,
    ) -> PersistenceResult<Option<String>> {
        queue_authority::issue_ack_token(&self.pool, recipient, device_id, queue_position).await
    }
    async fn ack_with_token(
        &self,
        recipient: &str,
        device_id: &str,
        ack_token: &str,
    ) -> PersistenceResult<Option<usize>> {
        queue_authority::ack_with_token(&self.pool, recipient, device_id, ack_token).await
    }
    async fn list_after(
        &self,
        recipient: &str,
        device_id: &str,
        queue_position: i64,
        limit: usize,
    ) -> PersistenceResult<Vec<DeviceMessageRecord>> {
        queue_authority::list_after(&self.pool, recipient, device_id, queue_position, limit).await
    }

    async fn list_recipient_deliveries(
        &self,
        selector: &RecipientQueueSelector,
        queue_position: i64,
        limit: usize,
    ) -> PersistenceResult<Vec<RecipientDeliveryRecord>> {
        queue_authority::list_recipient_deliveries(&self.pool, selector, queue_position, limit)
            .await
    }

    async fn issue_recipient_ack_token(
        &self,
        selector: &RecipientQueueSelector,
        queue_position: i64,
    ) -> PersistenceResult<Option<String>> {
        queue_authority::issue_recipient_ack_token(&self.pool, selector, queue_position).await
    }

    async fn ack_recipient_with_token(
        &self,
        selector: &RecipientQueueSelector,
        ack_token: &str,
    ) -> PersistenceResult<Option<usize>> {
        queue_authority::ack_recipient_with_token(&self.pool, selector, ack_token).await
    }

    async fn lost_watermark(
        &self,
        recipient: &str,
        device_id: &str,
    ) -> PersistenceResult<Option<i64>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT lost_through AS max_seq \
             FROM device_message_lost_watermarks \
             WHERE recipient = $1 AND device_id = $2",
        )
        .bind::<Text, _>(recipient)
        .bind::<Text, _>(device_id)
        .get_result::<MaxSeqRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.and_then(|row| row.max_seq))
        .map_err(PersistenceError::database)
    }
}
// ── G3.S1: in-memory MLS lifecycle stores ─────────────────────────────

pub struct PgDeviceInventoryStore {
    pub pool: PgPool,
}
#[async_trait]
impl DeviceInventoryStore for PgDeviceInventoryStore {
    async fn get(
        &self,
        actor: &str,
        device_id: &str,
    ) -> PersistenceResult<Option<DeviceInventoryRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT actor_id AS actor, device_id, payload, verification_state, created_at, updated_at, revoked_at \
             FROM devices WHERE actor_id = $1 AND device_id = $2 AND revoked_at IS NULL",
        )
            .bind::<Text, _>(actor)
            .bind::<Text, _>(device_id)
            .get_result::<DeviceRow>(&mut *conn).await
            .optional()
            .map(|row| row.map(DeviceInventoryRecord::from))
            .map_err(PersistenceError::database)
    }

    async fn put_metadata(
        &self,
        record: &coland_storage::DeviceInventoryMetadata,
    ) -> PersistenceResult<()> {
        let mut payload = serde_json::json!({"device_id": record.device_id});
        let object = payload.as_object_mut().expect("metadata is an object");
        if let Some(value) = &record.display_name {
            object.insert("display_name".into(), serde_json::json!(value));
        }
        if let Some(value) = record.last_seen_at {
            object.insert("last_seen_at".into(), serde_json::json!(value));
        }
        if let Some(value) = record.last_key_upload_at {
            object.insert("last_key_upload_at".into(), serde_json::json!(value));
        }
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("INSERT INTO devices(id,actor_id,device_id,payload,verification_state,created_at,updated_at) VALUES($1,$2,$3,$4,'unverified',$5,$5) ON CONFLICT(actor_id,device_id) DO UPDATE SET payload=devices.payload || EXCLUDED.payload,updated_at=GREATEST(devices.updated_at,EXCLUDED.updated_at)")
            .bind::<sql_types::Uuid,_>(Uuid::now_v7()).bind::<Text,_>(&record.actor)
            .bind::<Text,_>(&record.device_id).bind::<Jsonb,_>(payload).bind::<Timestamptz,_>(record.updated_at)
            .execute(&mut *conn).await.map_err(PersistenceError::database)?;
        Ok(())
    }

    async fn revoke_actor(
        &self,
        actor: &str,
        revoked_at: chrono::DateTime<Utc>,
    ) -> PersistenceResult<usize> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("UPDATE devices SET revoked_at=$2,updated_at=GREATEST(updated_at,$2) WHERE actor_id=$1 AND revoked_at IS NULL")
            .bind::<Text,_>(actor).bind::<Timestamptz,_>(revoked_at).execute(&mut *conn).await.map_err(PersistenceError::database)
    }

    async fn put_if_absent(&self, record: &DeviceInventoryRecord) -> PersistenceResult<bool> {
        if record.verification_state != "unverified"
            || record.payload.get("device_authorize_event_id").is_some()
        {
            return Err(PersistenceError::SchemaViolation(
                "device placeholder cannot carry authorization".into(),
            ));
        }
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "INSERT INTO devices (id, actor_id, device_id, payload, verification_state, created_at, updated_at, revoked_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             ON CONFLICT (actor_id, device_id) DO NOTHING",
        )
        .bind::<diesel::sql_types::Uuid, _>(uuid::Uuid::now_v7())
        .bind::<Text, _>(&record.actor)
        .bind::<Text, _>(&record.device_id)
        .bind::<Jsonb, _>(&record.payload)
        .bind::<Text, _>(&record.verification_state)
        .bind::<Timestamptz, _>(record.created_at)
        .bind::<Timestamptz, _>(record.updated_at)
        .bind::<Nullable<Timestamptz>, _>(record.revoked_at)
        .execute(&mut *conn)
        .await
        .map(|affected| affected > 0)
        .map_err(PersistenceError::database)
    }

    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<DeviceInventoryRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows = sql_query(
            "SELECT actor_id AS actor, device_id, payload, verification_state, created_at, updated_at, revoked_at \
             FROM devices WHERE actor_id = $1 AND revoked_at IS NULL ORDER BY device_id",
        )
        .bind::<Text, _>(actor)
        .load::<DeviceRow>(&mut *conn).await
        .map_err(PersistenceError::database)?;
        Ok(rows.into_iter().map(DeviceInventoryRecord::from).collect())
    }

    async fn list_for_actor_including_revoked(
        &self,
        actor: &str,
    ) -> PersistenceResult<Vec<DeviceInventoryRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows = sql_query(
            "SELECT actor_id AS actor, device_id, payload, verification_state, created_at, updated_at, revoked_at \
             FROM devices WHERE actor_id = $1 ORDER BY device_id",
        )
        .bind::<Text, _>(actor)
        .load::<DeviceRow>(&mut *conn).await
        .map_err(PersistenceError::database)?;
        Ok(rows.into_iter().map(DeviceInventoryRecord::from).collect())
    }

    async fn list(&self) -> PersistenceResult<Vec<DeviceInventoryRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows = sql_query(
            "SELECT actor_id AS actor, device_id, payload, verification_state, created_at, updated_at, revoked_at \
             FROM devices WHERE revoked_at IS NULL ORDER BY actor_id, device_id",
        )
        .load::<DeviceRow>(&mut *conn).await
        .map_err(PersistenceError::database)?;
        Ok(rows.into_iter().map(DeviceInventoryRecord::from).collect())
    }
}
#[derive(QueryableByName)]
struct DeviceRow {
    #[diesel(sql_type = Text)]
    actor: String,
    #[diesel(sql_type = Text)]
    device_id: String,
    #[diesel(sql_type = Jsonb)]
    payload: Value,
    #[diesel(sql_type = Text)]
    verification_state: String,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    updated_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    revoked_at: Option<chrono::DateTime<chrono::Utc>>,
}
impl From<DeviceRow> for DeviceInventoryRecord {
    fn from(row: DeviceRow) -> Self {
        let display_name = row
            .payload
            .get("display_name")
            .and_then(|value| value.as_str())
            .map(ToOwned::to_owned);
        Self {
            actor: row.actor,
            device_id: row.device_id,
            display_name,
            verification_state: row.verification_state,
            payload: row.payload,
            created_at: row.created_at,
            updated_at: row.updated_at,
            revoked_at: row.revoked_at,
        }
    }
}

/// PostgreSQL-backed device key bundle store (`keys/upload`).
mod key_material;
pub use key_material::{PgDeviceKeyStore, PgOneTimeKeyStore};
