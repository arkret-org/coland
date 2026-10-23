use diesel_async::AsyncConnection;

use super::{
    BigInt, Jsonb, OptionalExtension, PersistenceError, PersistenceResult, PgPool, QueryableByName,
    RunQueryDsl, SIGNAL_RELAY_MAX_PER_REALM, SignalRelayRecord, SignalRelayStore, Text,
    Timestamptz, Uuid, Value, async_trait, pg_conn, sql_query, sql_types,
};
use crate::PgTransactionError;

/// PostgreSQL-backed live Signal relay (`sync/signal.md` §4).
///
/// Nothing here is durable protocol state: rows are retained only until
/// `expires_at`, and every stored column outside `envelope` is a copy of the
/// envelope's own AAD-bound header.
pub struct PgSignalRelayStore {
    pub pool: PgPool,
}

#[derive(QueryableByName)]
struct SignalRelayPositionRow {
    #[diesel(sql_type = BigInt)]
    next_position: i64,
}

#[derive(QueryableByName)]
struct SignalRelayRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = BigInt)]
    position: i64,
    #[diesel(sql_type = Jsonb)]
    scope_ref: Value,
    #[diesel(sql_type = Text)]
    sender_actor_id: String,
    #[diesel(sql_type = sql_types::Nullable<Text>)]
    sender_device_id: Option<String>,
    #[diesel(sql_type = Text)]
    signal_class: String,
    #[diesel(sql_type = Text)]
    envelope_digest: String,
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
    #[diesel(sql_type = Timestamptz)]
    sent_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    expires_at: chrono::DateTime<chrono::Utc>,
}

impl TryFrom<SignalRelayRow> for SignalRelayRecord {
    type Error = PersistenceError;

    fn try_from(row: SignalRelayRow) -> PersistenceResult<Self> {
        Ok(Self {
            realm_id: row.realm_id,
            scope_ref: serde_json::from_value(row.scope_ref).map_err(|error| {
                PersistenceError::SchemaViolation(format!(
                    "stored signal scope_ref is invalid: {error}"
                ))
            })?,
            sender_actor_id: row.sender_actor_id.to_string(),
            sender_device_id: row.sender_device_id,
            signal_class: serde_json::from_value(Value::String(row.signal_class)).map_err(
                |error| {
                    PersistenceError::SchemaViolation(format!(
                        "stored signal_class is invalid: {error}"
                    ))
                },
            )?,
            envelope_digest: row.envelope_digest,
            sent_at: row.sent_at,
            expires_at: row.expires_at,
            envelope: serde_json::from_value(row.envelope).map_err(|error| {
                PersistenceError::SchemaViolation(format!(
                    "stored signal envelope is invalid: {error}"
                ))
            })?,
            position: row.position.max(0) as u64,
        })
    }
}

#[derive(QueryableByName)]
struct SignalRelayWatermarkRow {
    #[diesel(sql_type = BigInt)]
    delivered_through: i64,
}

/// Row shape for existence-only probes. The probe selects a constant rather
/// than projecting a payload column it would immediately discard, and the
/// marker is read back so no field goes unused.
#[derive(QueryableByName)]
struct SignalRelayExistsRow {
    #[diesel(sql_type = BigInt)]
    present: i64,
}

const SIGNAL_RELAY_COLUMNS: &str = "realm_id, position, scope_ref, sender_actor_id, \
     sender_device_id, signal_class, envelope_digest, envelope, sent_at, expires_at";

#[async_trait]
impl SignalRelayStore for PgSignalRelayStore {
    async fn append(&self, record: SignalRelayRecord) -> PersistenceResult<bool> {
        let envelope = serde_json::to_value(&record.envelope).map_err(|error| {
            PersistenceError::Internal(format!("failed to encode signal envelope: {error}"))
        })?;
        let scope_ref = serde_json::to_value(&record.scope_ref).map_err(|error| {
            PersistenceError::Internal(format!("failed to encode signal scope_ref: {error}"))
        })?;
        let signal_class = serde_json::to_value(record.signal_class)
            .ok()
            .and_then(|value| value.as_str().map(ToOwned::to_owned))
            .ok_or_else(|| {
                PersistenceError::Internal("failed to encode signal_class".to_owned())
            })?;
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        // The existing per-Realm allocator serializes duplicate checks and
        // insertion across Station processes. Allocation and retention share
        // the same transaction, so a failed append cannot burn progress.
        sql_query("INSERT INTO signal_relay_position (realm_id,next_position,updated_at) VALUES ($1,0,NOW()) ON CONFLICT DO NOTHING")
            .bind::<Text,_>(&record.realm_id).execute(&mut *conn).await?;
        sql_query("SELECT next_position FROM signal_relay_position WHERE realm_id=$1 FOR UPDATE")
            .bind::<Text,_>(&record.realm_id).get_result::<SignalRelayPositionRow>(&mut *conn).await?;
        let seen=sql_query("SELECT 1::bigint AS present FROM signal_relay WHERE realm_id=$1 AND envelope_digest=$2 LIMIT 1")
            .bind::<Text,_>(&record.realm_id).bind::<Text,_>(&record.envelope_digest)
            .get_result::<SignalRelayExistsRow>(&mut *conn).await.optional()?;
        if seen.is_some_and(|row|row.present==1) {return Ok(false);}
        let position_row = sql_query(
            "UPDATE signal_relay_position SET next_position=next_position+1,updated_at=NOW() WHERE realm_id=$1 \
             RETURNING next_position",
        )
        .bind::<Text, _>(&record.realm_id)
        .get_result::<SignalRelayPositionRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        let position = position_row.next_position;

        sql_query(
            "INSERT INTO signal_relay \
             (id, realm_id, position, scope_ref, sender_actor_id, sender_device_id, \
              signal_class, envelope_digest, envelope, sent_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind::<sql_types::Uuid, _>(Uuid::now_v7())
        .bind::<Text, _>(&record.realm_id)
        .bind::<BigInt, _>(position)
        .bind::<Jsonb, _>(&scope_ref)
        .bind::<Text, _>(&record.sender_actor_id)
        .bind::<sql_types::Nullable<Text>, _>(record.sender_device_id.as_deref())
        .bind::<Text, _>(&signal_class)
        .bind::<Text, _>(&record.envelope_digest)
        .bind::<Jsonb, _>(&envelope)
        .bind::<Timestamptz, _>(record.sent_at)
        .bind::<Timestamptz, _>(record.expires_at)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;

        sql_query("DELETE FROM signal_relay WHERE realm_id = $1 AND position <= $2 - $3")
            .bind::<Text, _>(&record.realm_id)
            .bind::<BigInt, _>(position)
            .bind::<BigInt, _>(SIGNAL_RELAY_MAX_PER_REALM as i64)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
        Ok(true)
        }).await.map_err(PgTransactionError::into_persistence)
    }

    async fn list_for_realm(&self, realm_id: &str) -> PersistenceResult<Vec<SignalRelayRecord>> {
        let mut conn = crate::pg_db(&self.pool);
        let rows = sql_query(format!(
            "SELECT {SIGNAL_RELAY_COLUMNS} FROM signal_relay \
             WHERE realm_id = $1 AND expires_at > NOW() \
             ORDER BY position ASC"
        ))
        .bind::<Text, _>(realm_id)
        .load::<SignalRelayRow>(&mut conn)
        .await
        .map_err(PersistenceError::database)?;
        rows.into_iter().map(SignalRelayRecord::try_from).collect()
    }

    async fn prune_expired(&self) -> PersistenceResult<usize> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query("DELETE FROM signal_relay WHERE expires_at <= NOW()")
            .execute(&mut conn)
            .await
            .map_err(PersistenceError::database)
    }

    async fn delivered_through(
        &self,
        actor: &str,
        device: &str,
        realm_id: &str,
    ) -> PersistenceResult<u64> {
        let mut conn = crate::pg_db(&self.pool);
        let row = sql_query(
            "SELECT delivered_through FROM signal_relay_watermark \
             WHERE actor_id = $1 AND device_id = $2 AND realm_id = $3",
        )
        .bind::<Text, _>(actor)
        .bind::<Text, _>(device)
        .bind::<Text, _>(realm_id)
        .get_result::<SignalRelayWatermarkRow>(&mut conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        Ok(row.map(|r| r.delivered_through.max(0) as u64).unwrap_or(0))
    }

    async fn advance(
        &self,
        actor: &str,
        device: &str,
        realm_id: &str,
        position: u64,
    ) -> PersistenceResult<()> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query(
            "INSERT INTO signal_relay_watermark \
             (actor_id, device_id, realm_id, delivered_through, updated_at) \
             VALUES ($1, $2, $3, $4, NOW()) \
             ON CONFLICT (actor_id, device_id, realm_id) DO UPDATE SET \
                delivered_through = GREATEST(signal_relay_watermark.delivered_through, EXCLUDED.delivered_through), \
                updated_at = NOW()",
        )
        .bind::<Text, _>(actor)
        .bind::<Text, _>(device)
        .bind::<Text, _>(realm_id)
        .bind::<BigInt, _>(position as i64)
        .execute(&mut conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }
}
