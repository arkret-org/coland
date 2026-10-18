//! Queue reads, acknowledgements and writes retain the recipient's original
//! authorization. No artifact can be relabelled by a later same-device login.
use arkret_models_collaboration::device_messages::{DeviceMessageEnvelope, RecipientDelivery};
use arkret_wire::{MlsWelcomeDelivery, MlsWelcomeRecipientEndpoint};

use super::*;

#[derive(QueryableByName)]
struct ExistingWelcomeRow {
    #[diesel(sql_type = Jsonb)]
    delivery_json: Value,
}

#[derive(QueryableByName)]
struct AgentWelcomeAuthorizationRow {
    #[diesel(sql_type = Text)]
    authorized_event_ref: String,
}

#[derive(QueryableByName)]
struct QueueDeliveryRow {
    #[diesel(sql_type = BigInt)]
    position: i64,
    #[diesel(sql_type = Text)]
    delivery_kind: String,
    #[diesel(sql_type = Jsonb)]
    delivery_json: Value,
}

#[derive(QueryableByName)]
struct OutstandingCountRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

#[derive(QueryableByName)]
struct AgentAckTokenRow {
    #[diesel(sql_type = Text)]
    agent_id: String,
    #[diesel(sql_type = Text)]
    verification_method: String,
    #[diesel(sql_type = Text)]
    authorization_event_ref: String,
    #[diesel(sql_type = BigInt)]
    queue_position: i64,
    #[diesel(sql_type = Timestamptz)]
    expires_at: chrono::DateTime<Utc>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    consumed_at: Option<chrono::DateTime<Utc>>,
}

/// The sequence alone does not order commit visibility: a later sequence
/// value can commit first and make an earlier value invisible past a cursor.
/// Serialize both queue writers until their surrounding transactions commit.
pub(super) async fn lock_delivery_order_in_transaction(
    conn: &mut AsyncPgConnection,
) -> Result<(), PgTransactionError> {
    sql_query("LOCK TABLE device_messages, mls_welcome_deliveries IN SHARE ROW EXCLUSIVE MODE")
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Enqueue the original signed Welcome on the caller's accepted MLS Commit
/// transaction. The outbox row is also the recipient queue row: it gets the
/// same durable position sequence used by ordinary device messages.
/// Queue one Welcome for its exact recipient endpoint.
///
/// `recipient_queue_capacity` is the endpoint bound of a first admission; a
/// Welcome replicated with its accepted Commit passes `None`: it counts
/// toward the bound but is never refused by it (client-sync.md §10.1).
pub(crate) async fn enqueue_mls_welcome_in_connection(
    conn: &mut AsyncPgConnection,
    welcome: &MlsWelcomeDelivery,
    commit_event_pk: i64,
    queued_at: chrono::DateTime<Utc>,
    recipient_queue_capacity: Option<usize>,
) -> Result<(), PgTransactionError> {
    welcome.validate_shape().map_err(|error| {
        PersistenceError::SchemaViolation(format!("invalid MLS Welcome: {error}"))
    })?;
    let delivery_json = serde_json::to_value(welcome).map_err(PersistenceError::database)?;
    let existing = sql_query(
        "SELECT delivery_json FROM mls_welcome_deliveries WHERE welcome_id=$1 FOR UPDATE",
    )
    .bind::<Text, _>(welcome.welcome_id.as_str())
    .get_result::<ExistingWelcomeRow>(&mut *conn)
    .await
    .optional()?;
    if let Some(existing) = existing {
        if existing.delivery_json == delivery_json {
            return Ok(());
        }
        return Err(PersistenceError::Conflict(
            "welcome_id already binds different signed bytes".into(),
        )
        .into());
    }

    let (endpoint_kind, device_id, verification_method, authorization_event_ref, device_gate) =
        match &welcome.recipient_endpoint {
            MlsWelcomeRecipientEndpoint::Device { device_id } => {
                let account = welcome.recipient_actor_id.as_account_id().ok_or_else(|| {
                    PersistenceError::SchemaViolation(
                        "a device Welcome recipient is an Account actor".into(),
                    )
                })?;
                let Some(binding) = crate::device_revocations::local_device_binding_in_transaction(
                    conn,
                    account.principal_id.as_str(),
                    device_id.as_str(),
                )
                .await?
                .filter(|binding| binding.station_id == account.station_id) else {
                    return Err(PersistenceError::Conflict(
                        "Welcome recipient device has no accepted authorization".into(),
                    )
                    .into());
                };
                crate::device_revocations::lock_artifact_devices_in_transaction(conn, &[&binding])
                    .await?;
                crate::ensure_gate_allowed_in_transaction(conn, &binding).await?;
                let authorization_event_ref = binding.authorization_ref.event_id.to_string();
                let gate = serde_json::to_value(binding).map_err(PersistenceError::database)?;
                (
                    "device",
                    Some(device_id.as_str().to_owned()),
                    None,
                    authorization_event_ref,
                    Some(gate),
                )
            }
            MlsWelcomeRecipientEndpoint::AgentRuntime {
                verification_method,
            } => {
                let row = sql_query(
                    "SELECT authorized_event_ref FROM agent_principals \
                     WHERE id=$1 AND state='active' AND authorized_verification_method=$2 \
                       AND authorized_event_ref IS NOT NULL AND authorized_key_event IS NOT NULL \
                     FOR SHARE",
                )
                .bind::<Text, _>(
                    welcome
                        .recipient_actor_id
                        .signing_principal_id()
                        .to_string(),
                )
                .bind::<Text, _>(verification_method.as_str())
                .get_result::<AgentWelcomeAuthorizationRow>(&mut *conn)
                .await
                .optional()?;
                let Some(row) = row else {
                    return Err(PersistenceError::Conflict(
                        "Welcome Agent endpoint has no accepted key authorization".into(),
                    )
                    .into());
                };
                (
                    "agent_runtime",
                    None,
                    Some(verification_method.as_str().to_owned()),
                    row.authorized_event_ref,
                    None,
                )
            }
        };
    lock_delivery_order_in_transaction(conn).await?;
    // The first lookup is an exact-retry fast path. Another Commit may have
    // inserted the same Welcome while this transaction waited for the queue
    // lock; recheck under that lock before attempting the unique insert.
    let concurrent = sql_query(
        "SELECT delivery_json FROM mls_welcome_deliveries WHERE welcome_id=$1 FOR UPDATE",
    )
    .bind::<Text, _>(welcome.welcome_id.as_str())
    .get_result::<ExistingWelcomeRow>(&mut *conn)
    .await
    .optional()?;
    if let Some(concurrent) = concurrent {
        if concurrent.delivery_json == delivery_json {
            return Ok(());
        }
        return Err(PersistenceError::Conflict(
            "welcome_id already binds different signed bytes".into(),
        )
        .into());
    }
    // encryption-and-audit.md §2.6: a claim serves exactly one accepted
    // Commit; another Welcome naming it is a reuse, never a second delivery.
    if sql_query(
        "SELECT EXISTS(SELECT 1 FROM mls_welcome_deliveries WHERE keypackage_claim_ref=$1) \
         AS present",
    )
    .bind::<Text, _>(welcome.keypackage_claim_ref.as_str())
    .get_result::<crate::query_rows::ExistsRow>(&mut *conn)
    .await?
    .present
    {
        return Err(PersistenceError::Conflict(format!(
            "{}: the KeyPackage claim already serves another accepted Welcome",
            coland_storage::ConflictCode::DuplicateConflict
        ))
        .into());
    }
    let Some(recipient_queue_capacity) = recipient_queue_capacity else {
        return insert_mls_welcome(
            conn,
            welcome,
            commit_event_pk,
            queued_at,
            endpoint_kind,
            device_id,
            verification_method,
            authorization_event_ref,
            device_gate,
            delivery_json,
        )
        .await;
    };
    if recipient_queue_capacity == 0 {
        return Err(PersistenceError::SchemaViolation(
            "MLS Welcome transaction omitted recipient queue capacity".into(),
        )
        .into());
    }
    let outstanding = match endpoint_kind {
        "device" => {
            sql_query(
                "SELECT ((SELECT COUNT(*) FROM device_messages \
               WHERE recipient=$1 AND device_id=$2 AND recipient_device_authorization=$4) + \
               (SELECT COUNT(*) FROM mls_welcome_deliveries \
               WHERE recipient=$1 AND recipient_endpoint_kind='device' \
                 AND recipient_device_id=$2 AND recipient_authorization_event_ref=$3 \
                 AND recipient_device_authorization=$4 AND state='queued')) AS count",
            )
            .bind::<Text, _>(
                welcome
                    .recipient_actor_id
                    .signing_principal_id()
                    .to_string(),
            )
            .bind::<Text, _>(device_id.as_deref().unwrap_or_default())
            .bind::<Text, _>(&authorization_event_ref)
            .bind::<Jsonb, _>(device_gate.as_ref().expect("device branch has gate"))
            .get_result::<OutstandingCountRow>(&mut *conn)
            .await?
        }
        "agent_runtime" => {
            sql_query(
                "SELECT COUNT(*) AS count FROM mls_welcome_deliveries \
             WHERE recipient=$1 AND recipient_endpoint_kind='agent_runtime' \
               AND recipient_verification_method=$2 AND recipient_authorization_event_ref=$3 \
               AND state='queued'",
            )
            .bind::<Text, _>(
                welcome
                    .recipient_actor_id
                    .signing_principal_id()
                    .to_string(),
            )
            .bind::<Text, _>(verification_method.as_deref().unwrap_or_default())
            .bind::<Text, _>(&authorization_event_ref)
            .get_result::<OutstandingCountRow>(&mut *conn)
            .await?
        }
        _ => unreachable!("validated Welcome endpoint kind"),
    };
    if outstanding.count >= i64::try_from(recipient_queue_capacity).unwrap_or(i64::MAX) {
        return Err(PersistenceError::Conflict(format!(
            "{}: recipient queue is at capacity",
            coland_storage::ConflictCode::RecipientQueueAtCapacity
        ))
        .into());
    }
    insert_mls_welcome(
        conn,
        welcome,
        commit_event_pk,
        queued_at,
        endpoint_kind,
        device_id,
        verification_method,
        authorization_event_ref,
        device_gate,
        delivery_json,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn insert_mls_welcome(
    conn: &mut AsyncPgConnection,
    welcome: &MlsWelcomeDelivery,
    commit_event_pk: i64,
    queued_at: chrono::DateTime<Utc>,
    endpoint_kind: &str,
    device_id: Option<String>,
    verification_method: Option<String>,
    authorization_event_ref: String,
    device_gate: Option<Value>,
    delivery_json: Value,
) -> Result<(), PgTransactionError> {
    sql_query(
        "INSERT INTO mls_welcome_deliveries \
         (welcome_id, realm_id, commit_event_pk, recipient, recipient_endpoint_kind, \
          recipient_device_id, recipient_verification_method, recipient_authorization_event_ref, \
          recipient_device_authorization, keypackage_claim_ref, delivery_json, state, queued_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'queued',$12)",
    )
    .bind::<Text, _>(welcome.welcome_id.as_str())
    .bind::<Text, _>(welcome.realm_id.as_str())
    .bind::<BigInt, _>(commit_event_pk)
    .bind::<Text, _>(
        welcome
            .recipient_actor_id
            .signing_principal_id()
            .to_string(),
    )
    .bind::<Text, _>(endpoint_kind)
    .bind::<Nullable<Text>, _>(device_id)
    .bind::<Nullable<Text>, _>(verification_method)
    .bind::<Text, _>(authorization_event_ref)
    .bind::<Nullable<Jsonb>, _>(device_gate)
    .bind::<Text, _>(welcome.keypackage_claim_ref.as_str())
    .bind::<Jsonb, _>(delivery_json)
    .bind::<Timestamptz, _>(queued_at)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

pub(super) fn validate_recipient(message: &DeviceMessageRecord) -> PersistenceResult<()> {
    message
        .validate_binding()
        .map_err(|error| PersistenceError::SchemaViolation(error.into()))
}

/// Caller holds the shared queue writer lock. Count both delivery branches
/// for the exact current human endpoint before inserting a DeviceMessage.
pub(super) async fn human_queue_has_capacity_in_transaction(
    conn: &mut AsyncPgConnection,
    message: &DeviceMessageRecord,
    capacity: usize,
) -> PersistenceResult<bool> {
    if capacity == 0 {
        return Ok(true);
    }
    let binding = serde_json::to_value(&message.recipient_device_authorization)
        .map_err(PersistenceError::database)?;
    let row = sql_query(
        "SELECT ((SELECT COUNT(*) FROM device_messages \
             WHERE recipient=$1 AND device_id=$2 AND recipient_device_authorization=$3) + \
             (SELECT COUNT(*) FROM mls_welcome_deliveries \
             WHERE recipient=$1 AND recipient_endpoint_kind='device' \
               AND recipient_device_id=$2 AND recipient_device_authorization=$3 \
               AND state='queued')) AS count",
    )
    .bind::<Text, _>(&message.recipient)
    .bind::<Text, _>(&message.device_id)
    .bind::<Jsonb, _>(binding)
    .get_result::<OutstandingCountRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(row.count < i64::try_from(capacity).unwrap_or(i64::MAX))
}

pub(super) async fn current_binding(
    conn: &mut diesel_async::AsyncPgConnection,
    recipient: &str,
    device_id: &str,
) -> PersistenceResult<Option<Value>> {
    let Some(binding) =
        crate::device_revocations::local_device_binding_in_transaction(conn, recipient, device_id)
            .await?
    else {
        return Ok(None);
    };
    if crate::gate_status_in_transaction(conn, &binding).await?
        != DeviceRevocationGateStatus::Active
    {
        return Ok(None);
    }
    serde_json::to_value(binding)
        .map(Some)
        .map_err(PersistenceError::database)
}

pub(super) async fn issue_ack_token(
    pool: &PgPool,
    recipient: &str,
    device_id: &str,
    queue_position: i64,
) -> PersistenceResult<Option<String>> {
    if queue_position <= 0 {
        return Ok(None);
    }
    let mut conn = pg_conn(pool).await.map_err(PersistenceError::database)?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        let Some(binding) = current_binding(conn, recipient, device_id).await? else { return Ok(None); };
        // A cursor from an older instance cannot mint an acknowledgement for
        // the replacement instance. Bind to an actually delivered queue row.
        let exists = sql_query("SELECT EXISTS(\
            SELECT 1 FROM device_messages WHERE recipient=$1 AND device_id=$2 AND position=$3 AND recipient_device_authorization=$4 \
            UNION ALL \
            SELECT 1 FROM mls_welcome_deliveries WHERE recipient=$1 AND recipient_endpoint_kind='device' \
              AND recipient_device_id=$2 AND position=$3 AND recipient_device_authorization=$4 AND state='queued'\
        ) AS present")
            .bind::<Text,_>(recipient).bind::<Text,_>(device_id).bind::<BigInt,_>(queue_position).bind::<Jsonb,_>(&binding)
            .get_result::<crate::ExistsRow>(conn).await?;
        if !exists.present { return Ok(None); }
        let token = fresh_device_message_ack_token();
        sql_query("INSERT INTO device_message_ack_tokens(ack_token,recipient,device_id,recipient_device_authorization,queue_position,issued_at,expires_at,consumed_at) VALUES($1,$2,$3,$4,$5,NOW(),$6,NULL)")
            .bind::<Text,_>(&token).bind::<Text,_>(recipient).bind::<Text,_>(device_id).bind::<Jsonb,_>(&binding)
            .bind::<BigInt,_>(queue_position).bind::<Timestamptz,_>(Utc::now()+chrono::Duration::hours(24)).execute(conn).await?;
        Ok(Some(token))
    }).await.map_err(PgTransactionError::into_persistence)
}

pub(super) async fn ack_with_token(
    pool: &PgPool,
    recipient: &str,
    device_id: &str,
    ack_token: &str,
) -> PersistenceResult<Option<usize>> {
    let mut conn = pg_conn(pool).await.map_err(PersistenceError::database)?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        let Some(binding) = current_binding(conn, recipient, device_id).await? else { return Ok(None); };
        let token = sql_query("SELECT recipient,device_id,recipient_device_authorization,queue_position,expires_at,consumed_at FROM device_message_ack_tokens WHERE ack_token=$1 AND effective_scope IS NULL FOR UPDATE")
            .bind::<Text,_>(ack_token).get_result::<DeviceMessageAckTokenRow>(conn).await.optional()?;
        let Some(token) = token else { return Ok(None); };
        if token.recipient != recipient || token.device_id != device_id || token.recipient_device_authorization != binding || token.expires_at <= Utc::now() { return Ok(None); }
        if token.consumed_at.is_some() { return Ok(Some(0)); }
        let count = sql_query("DELETE FROM device_messages WHERE recipient=$1 AND device_id=$2 AND position<=$3 AND recipient_device_authorization=$4")
            .bind::<Text,_>(recipient).bind::<Text,_>(device_id).bind::<BigInt,_>(token.queue_position).bind::<Jsonb,_>(&binding).execute(conn).await?;
        let welcome_count = sql_query("UPDATE mls_welcome_deliveries SET state='delivered', delivered_at=NOW() \
            WHERE recipient=$1 AND recipient_endpoint_kind='device' AND recipient_device_id=$2 \
              AND position<=$3 AND recipient_device_authorization=$4 AND state='queued'")
            .bind::<Text,_>(recipient).bind::<Text,_>(device_id).bind::<BigInt,_>(token.queue_position)
            .bind::<Jsonb,_>(&binding)
            .execute(conn).await?;
        sql_query("UPDATE device_message_ack_tokens SET consumed_at=NOW() WHERE ack_token=$1 AND consumed_at IS NULL").bind::<Text,_>(ack_token).execute(conn).await?;
        Ok(Some(count + welcome_count))
    }).await.map_err(PgTransactionError::into_persistence)
}

pub(super) async fn list_after(
    pool: &PgPool,
    recipient: &str,
    device_id: &str,
    position: i64,
    limit: usize,
) -> PersistenceResult<Vec<DeviceMessageRecord>> {
    let mut conn = pg_conn(pool).await.map_err(PersistenceError::database)?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        let Some(binding) = current_binding(conn, recipient, device_id).await? else { return Ok(vec![]); };
        let rows = sql_query("SELECT idempotency_key,sender,recipient,device_id,recipient_device_authorization,position,content,created_at FROM device_messages WHERE recipient=$1 AND device_id=$2 AND position>$3 AND recipient_device_authorization=$4 ORDER BY position ASC LIMIT $5")
            .bind::<Text,_>(recipient).bind::<Text,_>(device_id).bind::<BigInt,_>(position).bind::<Jsonb,_>(binding).bind::<BigInt,_>(limit.min(1001) as i64)
            .load::<DeviceMessageRow>(conn).await?;
        rows.into_iter().map(DeviceMessageRecord::try_from).collect::<PersistenceResult<Vec<_>>>().map_err(Into::into)
    }).await.map_err(PgTransactionError::into_persistence)
}

async fn current_agent_authorization(
    conn: &mut AsyncPgConnection,
    agent_id: &str,
    verification_method: &str,
) -> PersistenceResult<Option<String>> {
    sql_query(
        "SELECT authorized_event_ref FROM agent_principals \
         WHERE id=$1 AND state='active' AND authorized_verification_method=$2 \
           AND authorized_event_ref IS NOT NULL AND authorized_key_event IS NOT NULL \
         FOR SHARE",
    )
    .bind::<Text, _>(agent_id)
    .bind::<Text, _>(verification_method)
    .get_result::<AgentWelcomeAuthorizationRow>(&mut *conn)
    .await
    .optional()
    .map(|row| row.map(|row| row.authorized_event_ref))
    .map_err(PersistenceError::database)
}

fn decode_delivery(
    row: QueueDeliveryRow,
    selector: &RecipientQueueSelector,
) -> PersistenceResult<RecipientDeliveryRecord> {
    let delivery = match row.delivery_kind.as_str() {
        "device_message" => {
            let RecipientQueueSelector::HumanDevice {
                recipient,
                device_id,
            } = selector
            else {
                return Err(PersistenceError::SchemaViolation(
                    "Agent queue contained a human DeviceMessage".into(),
                ));
            };
            let message: DeviceMessageEnvelope =
                serde_json::from_value(row.delivery_json).map_err(PersistenceError::database)?;
            if message.recipient_account_id.principal_id.as_str() != recipient
                || message.recipient_device_id.as_str() != device_id
            {
                return Err(PersistenceError::SchemaViolation(
                    "DeviceMessage queue row differs from its signed recipient".into(),
                ));
            }
            RecipientDelivery::DeviceMessage {
                device_message: message,
            }
        }
        "mls_welcome" => {
            let welcome: MlsWelcomeDelivery =
                serde_json::from_value(row.delivery_json).map_err(PersistenceError::database)?;
            welcome.validate_shape().map_err(|error| {
                PersistenceError::SchemaViolation(format!("invalid queued Welcome: {error}"))
            })?;
            let bound = match (selector, &welcome.recipient_endpoint) {
                (
                    RecipientQueueSelector::HumanDevice {
                        recipient,
                        device_id,
                    },
                    MlsWelcomeRecipientEndpoint::Device {
                        device_id: welcome_device,
                    },
                ) => {
                    welcome
                        .recipient_actor_id
                        .signing_principal_id()
                        .to_string()
                        == *recipient
                        && welcome_device.as_str() == device_id
                }
                (
                    RecipientQueueSelector::AgentRuntime {
                        agent_id,
                        verification_method,
                        ..
                    },
                    MlsWelcomeRecipientEndpoint::AgentRuntime {
                        verification_method: welcome_method,
                    },
                ) => {
                    welcome
                        .recipient_actor_id
                        .signing_principal_id()
                        .to_string()
                        == *agent_id
                        && welcome_method.as_str() == verification_method
                }
                _ => false,
            };
            if !bound {
                return Err(PersistenceError::SchemaViolation(
                    "Welcome queue row differs from its recipient endpoint".into(),
                ));
            }
            RecipientDelivery::MlsWelcome {
                mls_welcome: welcome,
            }
        }
        _ => {
            return Err(PersistenceError::SchemaViolation(
                "unknown recipient delivery kind".into(),
            ));
        }
    };
    Ok(RecipientDeliveryRecord {
        position: row.position,
        delivery,
    })
}

pub(super) async fn list_recipient_deliveries(
    pool: &PgPool,
    selector: &RecipientQueueSelector,
    position: i64,
    limit: usize,
) -> PersistenceResult<Vec<RecipientDeliveryRecord>> {
    let mut conn = pg_conn(pool).await.map_err(PersistenceError::database)?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        let rows = match selector {
            RecipientQueueSelector::HumanDevice { recipient, device_id } => {
                let Some(binding) = current_binding(conn, recipient, device_id).await? else {
                    return Ok(Vec::new());
                };
                sql_query(
                    "SELECT position, 'device_message'::text AS delivery_kind, content AS delivery_json \
                       FROM device_messages WHERE recipient=$1 AND device_id=$2 \
                        AND recipient_device_authorization=$3 AND position>$4 \
                     UNION ALL \
                     SELECT position, 'mls_welcome'::text AS delivery_kind, delivery_json \
                       FROM mls_welcome_deliveries WHERE recipient=$1 \
                        AND recipient_endpoint_kind='device' AND recipient_device_id=$2 \
                        AND recipient_device_authorization=$3 AND state='queued' AND position>$4 \
                     ORDER BY position ASC LIMIT $5",
                )
                .bind::<Text, _>(recipient)
                .bind::<Text, _>(device_id)
                .bind::<Jsonb, _>(binding)
                .bind::<BigInt, _>(position)
                .bind::<BigInt, _>(limit.min(1001) as i64)
                .load::<QueueDeliveryRow>(conn)
                .await?
            }
            RecipientQueueSelector::AgentRuntime {
                agent_id,
                verification_method,
                authorization_event_ref,
            } => {
                if current_agent_authorization(conn, agent_id, verification_method).await?
                    .as_deref()
                    != Some(authorization_event_ref.as_str())
                {
                    return Ok(Vec::new());
                }
                sql_query(
                    "SELECT position, 'mls_welcome'::text AS delivery_kind, delivery_json \
                       FROM mls_welcome_deliveries WHERE recipient=$1 \
                        AND recipient_endpoint_kind='agent_runtime' \
                        AND recipient_verification_method=$2 AND recipient_authorization_event_ref=$3 \
                        AND state='queued' AND position>$4 ORDER BY position ASC LIMIT $5",
                )
                .bind::<Text, _>(agent_id)
                .bind::<Text, _>(verification_method)
                .bind::<Text, _>(authorization_event_ref)
                .bind::<BigInt, _>(position)
                .bind::<BigInt, _>(limit.min(1001) as i64)
                .load::<QueueDeliveryRow>(conn)
                .await?
            }
        };
        rows.into_iter()
            .map(|row| decode_delivery(row, selector).map_err(Into::into))
            .collect()
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}

pub(super) async fn issue_recipient_ack_token(
    pool: &PgPool,
    selector: &RecipientQueueSelector,
    queue_position: i64,
) -> PersistenceResult<Option<String>> {
    if queue_position <= 0 {
        return Ok(None);
    }
    match selector {
        RecipientQueueSelector::HumanDevice {
            recipient,
            device_id,
        } => issue_ack_token(pool, recipient, device_id, queue_position).await,
        RecipientQueueSelector::AgentRuntime {
            agent_id,
            verification_method,
            authorization_event_ref,
        } => {
            let mut conn = pg_conn(pool).await.map_err(PersistenceError::database)?;
            conn.transaction::<_, PgTransactionError, _>(async move |conn| {
                if current_agent_authorization(conn, agent_id, verification_method).await?
                    .as_deref()
                    != Some(authorization_event_ref.as_str())
                {
                    return Ok(None);
                }
                let exists = sql_query(
                    "SELECT EXISTS(SELECT 1 FROM mls_welcome_deliveries \
                     WHERE recipient=$1 AND recipient_endpoint_kind='agent_runtime' \
                       AND recipient_verification_method=$2 AND recipient_authorization_event_ref=$3 \
                       AND position=$4 AND state='queued') AS present",
                )
                .bind::<Text, _>(agent_id)
                .bind::<Text, _>(verification_method)
                .bind::<Text, _>(authorization_event_ref)
                .bind::<BigInt, _>(queue_position)
                .get_result::<crate::ExistsRow>(conn)
                .await?;
                if !exists.present {
                    return Ok(None);
                }
                let token = fresh_device_message_ack_token();
                sql_query(
                    "INSERT INTO agent_recipient_delivery_ack_tokens \
                     (ack_token, agent_id, verification_method, authorization_event_ref, \
                      queue_position, issued_at, expires_at, consumed_at) \
                     VALUES ($1,$2,$3,$4,$5,NOW(),$6,NULL)",
                )
                .bind::<Text, _>(&token)
                .bind::<Text, _>(agent_id)
                .bind::<Text, _>(verification_method)
                .bind::<Text, _>(authorization_event_ref)
                .bind::<BigInt, _>(queue_position)
                .bind::<Timestamptz, _>(Utc::now() + chrono::Duration::hours(24))
                .execute(conn)
                .await?;
                Ok(Some(token))
            })
            .await
            .map_err(PgTransactionError::into_persistence)
        }
    }
}

pub(super) async fn ack_recipient_with_token(
    pool: &PgPool,
    selector: &RecipientQueueSelector,
    ack_token: &str,
) -> PersistenceResult<Option<usize>> {
    match selector {
        RecipientQueueSelector::HumanDevice {
            recipient,
            device_id,
        } => ack_with_token(pool, recipient, device_id, ack_token).await,
        RecipientQueueSelector::AgentRuntime {
            agent_id,
            verification_method,
            authorization_event_ref,
        } => {
            let mut conn = pg_conn(pool).await.map_err(PersistenceError::database)?;
            conn.transaction::<_, PgTransactionError, _>(async move |conn| {
                if current_agent_authorization(conn, agent_id, verification_method).await?
                    .as_deref()
                    != Some(authorization_event_ref.as_str())
                {
                    return Ok(None);
                }
                let token = sql_query(
                    "SELECT agent_id, verification_method, authorization_event_ref, \
                            queue_position, expires_at, consumed_at \
                     FROM agent_recipient_delivery_ack_tokens WHERE ack_token=$1 FOR UPDATE",
                )
                .bind::<Text, _>(ack_token)
                .get_result::<AgentAckTokenRow>(conn)
                .await
                .optional()?;
                let Some(token) = token else {
                    return Ok(None);
                };
                if token.agent_id != *agent_id
                    || token.verification_method != *verification_method
                    || token.authorization_event_ref != *authorization_event_ref
                    || token.expires_at <= Utc::now()
                {
                    return Ok(None);
                }
                if token.consumed_at.is_some() {
                    return Ok(Some(0));
                }
                let count = sql_query(
                    "UPDATE mls_welcome_deliveries SET state='delivered', delivered_at=NOW() \
                     WHERE recipient=$1 AND recipient_endpoint_kind='agent_runtime' \
                       AND recipient_verification_method=$2 AND recipient_authorization_event_ref=$3 \
                       AND position<=$4 AND state='queued'",
                )
                .bind::<Text, _>(agent_id)
                .bind::<Text, _>(verification_method)
                .bind::<Text, _>(authorization_event_ref)
                .bind::<BigInt, _>(token.queue_position)
                .execute(conn)
                .await?;
                sql_query(
                    "UPDATE agent_recipient_delivery_ack_tokens SET consumed_at=NOW() \
                     WHERE ack_token=$1 AND consumed_at IS NULL",
                )
                .bind::<Text, _>(ack_token)
                .execute(conn)
                .await?;
                Ok(Some(count))
            })
            .await
            .map_err(PgTransactionError::into_persistence)
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn welcome_row(endpoint: Value) -> QueueDeliveryRow {
        QueueDeliveryRow {
            position: 7,
            delivery_kind: "mls_welcome".to_owned(),
            delivery_json: json!({
                "welcome_id": "ak:mls_welcome_delivery:0199aaaa-aaaa-7aaa-8aaa-aaaaaaaaaaaa",
                "realm_id": "ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5",
                "effective_scope": {"kind":"realm", "realm_id":"ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5"},
                "commit_event_ref": "ak:event:AQJmSg1s9QyzppFeJL40dN92YVHZeLdBBt3UWHa9XNOD",
                "recipient_actor_id": {"kind":"service", "service_id":"ak:did_core:webvh:z6mkfixturestationb"},
                "recipient_endpoint": endpoint,
                "keypackage_claim_ref": "ak:keypackage_claim:0199cccc-cccc-7ccc-8ccc-cccccccccccc",
                "ciphertext_b64": "AQIDBA",
                "producer_proof": {
                    "context": "ak.mls_welcome_delivery_signature.v1",
                    "signature_algorithm": "Ed25519",
                    "verification_method": "did:webvh:z6mkfixturealice:alice.example#device-fixture",
                    "signed_digest": "sha256:f51a607977aa5ba077764b06209d77c0231822b23a59be07cdb44f11f6582a29",
                    "created_at": "2026-09-20T00:00:00.000Z",
                    "sig": "R_RF4nAmz0yEIvqPt7BLemCd4npd36B5p5wyhSB8gXy2AL2AHTZHypwUsIsbqL5mZ3uesmfoOdcO8vbShWzNDw"
                }
            }),
        }
    }

    #[test]
    fn human_queue_rejects_welcome_for_another_device() {
        let row = welcome_row(
            json!({"kind":"device", "device_id":"ak:device:0199bbbb-bbbb-7bbb-8bbb-bbbbbbbbbbbb"}),
        );
        let selector = RecipientQueueSelector::HumanDevice {
            recipient: "ak:did_core:webvh:z6mkfixturestationb".to_owned(),
            device_id: "ak:device:0199dddd-dddd-7ddd-8ddd-dddddddddddd".to_owned(),
        };
        assert!(decode_delivery(row, &selector).is_err());
    }

    #[test]
    fn agent_queue_rejects_welcome_for_another_method() {
        let row = welcome_row(
            json!({"kind":"agent_runtime", "verification_method":"did:webvh:z6mkfixturealice:alice.example#device-fixture"}),
        );
        let selector = RecipientQueueSelector::AgentRuntime {
            agent_id: "ak:did_core:webvh:z6mkfixturestationb".to_owned(),
            verification_method: "did:webvh:z6mkfixturealice:alice.example#different".to_owned(),
            authorization_event_ref: "ak:event:AQJmSg1s9QyzppFeJL40dN92YVHZeLdBBt3UWHa9XNOD"
                .to_owned(),
        };
        assert!(decode_delivery(row, &selector).is_err());
    }
}
