use coland_storage::AccountPk;
use diesel_async::AsyncConnection;

use super::{
    BigInt, Jsonb, Nullable, OptionalExtension, PersistenceError, PersistenceResult, PgPool,
    QueryableByName, RunQueryDsl, SessionRecord, SessionStore, Text, Timestamptz, Value,
    async_trait, decode_session_agent_payload, encode_session_payload, pg_conn, sql_query,
};
use crate::PgTransactionError;
pub struct PgSessionStore {
    pub pool: PgPool,
}
#[async_trait]
impl SessionStore for PgSessionStore {
    async fn get(&self, token: &str) -> PersistenceResult<Option<SessionRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT id AS token_hash, account_pk, actor_id AS actor, device_id, audience, session_public_key, payload, expires_at, created_at, revoked_at \
             FROM sessions WHERE id = $1",
        )
        .bind::<Text, _>(token)
        .get_result::<SessionRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(SessionRecord::try_from)
        .transpose()
    }

    async fn put(&self, record: &SessionRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        // Use the same lock order as revocation cleanup: instance, then artifact.
        // An existing token keeps its original instance even after reauthorization.
        let current_binding = if record.agent_session.is_none() {
            let principal = arkret_wire::DidCoreId::new(record.actor.clone()).map_err(|e| PersistenceError::SchemaViolation(e.to_string()))?;
            let station = arkret_wire::DidCoreId::new(record.audience.clone()).map_err(|e| PersistenceError::SchemaViolation(e.to_string()))?;
            crate::device_revocations::current_device_binding_in_transaction(conn,&principal,&station,&record.device_id).await?
        } else { None };
        let existing = sql_query("SELECT payload FROM sessions WHERE id=$1 FOR UPDATE").bind::<Text,_>(&record.token_hash)
            .get_result::<crate::JsonPayloadRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
        let mut payload = encode_session_payload(record);
        if existing.is_none()
            && let Some(binding) = current_binding {
                crate::ensure_gate_allowed_in_transaction(conn,&binding).await?;
                payload["device_authorization"] = serde_json::to_value(binding).map_err(PersistenceError::database)?;
            }
        let affected = sql_query(
            "INSERT INTO sessions (id, account_pk, actor_id, device_id, audience, session_public_key, payload, expires_at, revoked_at, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW()) \
             ON CONFLICT (id) DO UPDATE SET account_pk = EXCLUDED.account_pk, actor_id = EXCLUDED.actor_id, device_id = EXCLUDED.device_id, \
             audience = EXCLUDED.audience, session_public_key = EXCLUDED.session_public_key, \
             payload = EXCLUDED.payload - 'device_authorization' || CASE WHEN sessions.payload ? 'device_authorization' THEN jsonb_build_object('device_authorization',sessions.payload->'device_authorization') ELSE '{}'::jsonb END, expires_at = EXCLUDED.expires_at, revoked_at = COALESCE(sessions.revoked_at,EXCLUDED.revoked_at), updated_at = NOW() \
             WHERE sessions.account_pk=EXCLUDED.account_pk AND sessions.actor_id=EXCLUDED.actor_id AND sessions.device_id=EXCLUDED.device_id AND sessions.audience=EXCLUDED.audience AND sessions.session_public_key IS NOT DISTINCT FROM EXCLUDED.session_public_key",
        )
        .bind::<Text, _>(&record.token_hash)
        .bind::<BigInt, _>(record.account_pk.get())
        .bind::<Text, _>(&record.actor)
        .bind::<Text, _>(&record.device_id)
        .bind::<Text, _>(&record.audience)
        .bind::<Nullable<Text>, _>(record.session_public_key.as_deref())
        .bind::<Jsonb, _>(&payload)
        .bind::<Timestamptz, _>(record.expires_at)
        .bind::<Nullable<Timestamptz>, _>(record.revoked_at)
        .bind::<Timestamptz, _>(record.created_at)
        .execute(&mut *conn).await.map_err(PgTransactionError::from)?;
        if affected != 1 {
            return Err(PersistenceError::Conflict("session token cannot change its authenticated holder".into()).into());
        }
        Ok(())
        }).await.map_err(PgTransactionError::into_persistence)
    }

    async fn device_authorization(
        &self,
        token: &str,
    ) -> PersistenceResult<Option<coland_storage::DeviceRevocationGateSelector>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let row = sql_query("SELECT payload FROM sessions WHERE id=$1")
            .bind::<Text, _>(token)
            .get_result::<crate::JsonPayloadRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?;
        row.and_then(|row| row.payload.get("device_authorization").cloned())
            .map(serde_json::from_value)
            .transpose()
            .map_err(|e| {
                PersistenceError::SchemaViolation(format!(
                    "invalid persisted session authorization binding: {e}"
                ))
            })
    }

    async fn delete(&self, token: &str) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("DELETE FROM sessions WHERE id = $1")
            .bind::<Text, _>(token)
            .execute(&mut *conn)
            .await
            .map(|_| ())
            .map_err(PersistenceError::database)
    }

    async fn cleanup_expired(&self) -> PersistenceResult<usize> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("DELETE FROM sessions WHERE expires_at <= NOW()")
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<SessionRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT id AS token_hash, account_pk, actor_id AS actor, device_id, audience, session_public_key, payload, expires_at, created_at, revoked_at \
             FROM sessions",
        )
        .load::<SessionRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?
        .into_iter()
        .map(SessionRecord::try_from)
        .collect()
    }
}
#[derive(QueryableByName)]
struct SessionRow {
    #[diesel(sql_type = Text)]
    token_hash: String,
    #[diesel(sql_type = BigInt)]
    account_pk: i64,
    #[diesel(sql_type = Text)]
    actor: String,
    #[diesel(sql_type = Text)]
    device_id: String,
    #[diesel(sql_type = Text)]
    audience: String,
    #[diesel(sql_type = Nullable<Text>)]
    session_public_key: Option<String>,
    #[diesel(sql_type = Jsonb)]
    payload: Value,
    #[diesel(sql_type = Timestamptz)]
    expires_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    revoked_at: Option<chrono::DateTime<chrono::Utc>>,
}
impl TryFrom<SessionRow> for SessionRecord {
    type Error = PersistenceError;

    fn try_from(row: SessionRow) -> Result<Self, Self::Error> {
        Ok(Self {
            token_hash: row.token_hash,
            account_pk: AccountPk(row.account_pk),
            actor: row.actor,
            device_id: row.device_id,
            audience: row.audience,
            session_public_key: row.session_public_key,
            agent_session: decode_session_agent_payload(&row.payload),
            expires_at: row.expires_at,
            created_at: row.created_at,
            revoked_at: row.revoked_at,
        })
    }
}
