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
        let mut conn = crate::pg_db(&self.pool);
        sql_query(
            "SELECT id AS token_hash, account_pk, actor_id AS actor, device_id, audience, session_public_key, payload, expires_at, created_at, revoked_at \
             FROM sessions WHERE id = $1",
        )
        .bind::<Text, _>(token)
        .get_result::<SessionRow>(&mut conn)
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
        if record.agent_session.is_none() {
            let owner = sql_query("SELECT jsonb_build_object('principal_id',principal_id,'station_id',station_id) AS payload FROM accounts WHERE pk=$1")
                .bind::<BigInt,_>(record.account_pk.get()).get_result::<crate::JsonPayloadRow>(&mut *conn).await?;
            let account: arkret_wire::AccountId = serde_json::from_value(owner.payload).map_err(PersistenceError::database)?;
            if account.principal_id.as_str() != record.actor {
                return Err(PersistenceError::SchemaViolation("session Account and Human principal disagree".into()).into());
            }
            crate::pcr_private_authority::require_active_account_owner(conn,&account).await?;
        }
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
        let mut conn = crate::pg_db(&self.pool);
        let row = sql_query("SELECT payload FROM sessions WHERE id=$1")
            .bind::<Text, _>(token)
            .get_result::<crate::JsonPayloadRow>(&mut conn)
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

    async fn revoke_account(
        &self,
        account: &arkret_wire::AccountId,
        device_id: Option<&str>,
        revoked_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<usize> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query("UPDATE sessions s SET revoked_at=$4,updated_at=GREATEST(s.updated_at,$4) FROM accounts a WHERE s.account_pk=a.pk AND a.principal_id=$1 AND a.station_id=$2 AND s.actor_id=$1 AND ($3::text IS NULL OR s.device_id=$3) AND s.revoked_at IS NULL")
            .bind::<Text,_>(account.principal_id.as_str())
            .bind::<Text,_>(account.station_id.as_str())
            .bind::<Nullable<Text>,_>(device_id)
            .bind::<Timestamptz,_>(revoked_at)
            .execute(&mut conn).await.map_err(PersistenceError::database)
    }

    async fn delete(&self, token: &str) -> PersistenceResult<()> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query("DELETE FROM sessions WHERE id = $1")
            .bind::<Text, _>(token)
            .execute(&mut conn)
            .await
            .map(|_| ())
            .map_err(PersistenceError::database)
    }

    async fn cleanup_expired(&self) -> PersistenceResult<usize> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query("DELETE FROM sessions WHERE expires_at <= NOW()")
            .execute(&mut conn)
            .await
            .map_err(PersistenceError::database)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<SessionRecord>> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query(
            "SELECT id AS token_hash, account_pk, actor_id AS actor, device_id, audience, session_public_key, payload, expires_at, created_at, revoked_at \
             FROM sessions",
        )
        .load::<SessionRow>(&mut conn)
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

#[cfg(test)]
mod account_revocation_tests {
    use super::*;
    use crate::{AccountRecord, AccountStore as _, PgAccountStore};

    #[tokio::test]
    async fn account_revocation_preserves_same_principal_foreign_account_and_other_device() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let accounts = PgAccountStore { pool: pool.clone() };
        let sessions = PgSessionStore { pool };
        let principal =
            arkret_wire::DidCoreId::new("ak:did_core:web:session-holder.example").unwrap();
        let account = |station: &str| {
            arkret_wire::AccountId::new(
                principal.clone(),
                arkret_wire::DidCoreId::new(station).unwrap(),
            )
        };
        let home = account("ak:did_core:web:session-home.example");
        let foreign = account("ak:did_core:web:session-foreign.example");
        let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let profile = |account: &arkret_wire::AccountId| AccountRecord {
            pk: AccountPk(0),
            principal_id: account.principal_id.clone(),
            station_id: account.station_id.clone(),
            localpart: String::new(),
            display_name: None,
            biography: None,
            avatar_blob_ref: None,
            created_at: at,
        };
        let home_pk = accounts.put(&profile(&home)).await.unwrap();
        let foreign_pk = accounts.put(&profile(&foreign)).await.unwrap();
        assert_ne!(home_pk, foreign_pk);
        let first_device = arkret_identifiers::new_prefixed_uuid7("ak:device:");
        let other_device = arkret_identifiers::new_prefixed_uuid7("ak:device:");
        // These real cache rows provide no authority. Same principal, Device
        // and local audience deliberately cannot stand in for AccountId.
        for (token, account_pk, device) in [
            ("home-first", home_pk, &first_device),
            ("foreign-first", foreign_pk, &first_device),
            ("home-other", home_pk, &other_device),
        ] {
            sessions
                .put(&SessionRecord {
                    token_hash: arkret_canonical::sha256_digest(token.as_bytes()),
                    account_pk,
                    actor: principal.to_string(),
                    device_id: device.clone(),
                    audience: home.station_id.to_string(),
                    session_public_key: None,
                    agent_session: None,
                    expires_at: at + chrono::Duration::hours(1),
                    created_at: at,
                    revoked_at: None,
                })
                .await
                .unwrap();
        }
        assert_eq!(
            sessions
                .revoke_account(&home, Some(&first_device), at)
                .await
                .unwrap(),
            1
        );
        let get = |token: &str| arkret_canonical::sha256_digest(token.as_bytes());
        assert_eq!(
            sessions
                .get(&get("home-first"))
                .await
                .unwrap()
                .unwrap()
                .revoked_at,
            Some(at)
        );
        assert!(
            sessions
                .get(&get("foreign-first"))
                .await
                .unwrap()
                .unwrap()
                .revoked_at
                .is_none()
        );
        assert!(
            sessions
                .get(&get("home-other"))
                .await
                .unwrap()
                .unwrap()
                .revoked_at
                .is_none()
        );
        assert_eq!(sessions.revoke_account(&home, None, at).await.unwrap(), 1);
        assert_eq!(sessions.revoke_account(&home, None, at).await.unwrap(), 0);
        assert!(
            sessions
                .get(&get("foreign-first"))
                .await
                .unwrap()
                .unwrap()
                .revoked_at
                .is_none()
        );
    }
}
