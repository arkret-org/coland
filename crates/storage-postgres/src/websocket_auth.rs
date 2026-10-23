use arkret_wire::WebOrigin;
use coland_storage::{
    WebsocketAuthChallengeRecord, WebsocketAuthReplayRecord, WebsocketAuthStore,
    WebsocketConnectionLease,
};
use diesel::sql_types::Bool;
use diesel_async::AsyncConnection;

use super::{
    ExistsRow, OptionalExtension, PersistenceError, PersistenceResult, PgPool, QueryableByName,
    RunQueryDsl, Text, Timestamptz, Utc, async_trait, pg_conn, sql_query,
};
use crate::PgTransactionError;

/// Sentinel that rolls the consume transaction back when the challenge half
/// was already taken. It never escapes this module.
const CHALLENGE_ALREADY_CONSUMED: &str = "websocket challenge already consumed";

/// Durable `ak.profile.binding.websocket.v1` challenge store + replay ledger.
///
/// §3.1 requires one consistent state across instances, so both tables are
/// plain Pg rows and the consume step is a single transaction: the ledger
/// insert and the challenge update either both land or neither does.
pub struct PgWebsocketAuthStore {
    pub pool: PgPool,
}

#[derive(QueryableByName)]
struct WebsocketChallengeRow {
    #[diesel(sql_type = Text)]
    connection_id: String,
    #[diesel(sql_type = Text)]
    nonce: String,
    #[diesel(sql_type = Text)]
    canonical_origin: String,
    #[diesel(sql_type = Text)]
    canonical_base_url: String,
    #[diesel(sql_type = Timestamptz)]
    issued_at: chrono::DateTime<Utc>,
    #[diesel(sql_type = Timestamptz)]
    expires_at: chrono::DateTime<Utc>,
    #[diesel(sql_type = Bool)]
    consumed: bool,
    #[diesel(sql_type = Timestamptz)]
    retain_until: chrono::DateTime<Utc>,
}

impl TryFrom<WebsocketChallengeRow> for WebsocketAuthChallengeRecord {
    type Error = PersistenceError;

    fn try_from(row: WebsocketChallengeRow) -> Result<Self, Self::Error> {
        Ok(Self {
            connection_id: row.connection_id,
            nonce: row.nonce,
            canonical_origin: WebOrigin::new(row.canonical_origin).map_err(|error| {
                PersistenceError::SchemaViolation(format!(
                    "stored websocket canonical_origin is invalid: {error}"
                ))
            })?,
            canonical_base_url: row.canonical_base_url,
            issued_at: row.issued_at,
            expires_at: row.expires_at,
            consumed: row.consumed,
            retain_until: row.retain_until,
        })
    }
}

#[async_trait]
impl WebsocketAuthStore for PgWebsocketAuthStore {
    async fn reserve_connection(
        &self,
        lease: &WebsocketConnectionLease,
    ) -> PersistenceResult<bool> {
        if lease.expires_at <= Utc::now()
            || lease.expires_at > Utc::now() + chrono::Duration::seconds(31)
        {
            return Err(PersistenceError::SchemaViolation(
                "socket lease must expire within thirty seconds".to_owned(),
            ));
        }
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            // All grants for this exact holder serialize at this shared lock.
            // No pool connection is held for the lifetime of a physical socket.
            sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
                .bind::<Text,_>(&lease.device_binding).execute(&mut *conn).await?;
            sql_query("DELETE FROM websocket_connection_leases WHERE device_binding=$1 AND expires_at<=clock_timestamp()")
                .bind::<Text,_>(&lease.device_binding).execute(&mut *conn).await?;
            let allowed = sql_query(
                "SELECT NOT EXISTS(SELECT 1 FROM websocket_connection_leases WHERE connection_id=$1 AND device_binding<>$3) \
                 AND (SELECT count(*) FROM websocket_connection_leases WHERE session_binding=$2 AND connection_id<>$1 AND expires_at>clock_timestamp())<2 \
                 AND (SELECT count(*) FROM websocket_connection_leases WHERE device_binding=$3 AND connection_id<>$1 AND expires_at>clock_timestamp())<4 AS present",
            ).bind::<Text,_>(&lease.connection_id).bind::<Text,_>(&lease.session_binding).bind::<Text,_>(&lease.device_binding)
                .get_result::<ExistsRow>(&mut *conn).await?.present;
            if !allowed { return Ok(false); }
            let written = sql_query(
                "INSERT INTO websocket_connection_leases(connection_id,session_binding,device_binding,expires_at) \
                 SELECT $1,$2,$3,$4 WHERE $4>clock_timestamp() \
                 ON CONFLICT(connection_id) DO UPDATE SET session_binding=EXCLUDED.session_binding,expires_at=EXCLUDED.expires_at \
                 WHERE websocket_connection_leases.device_binding=EXCLUDED.device_binding",
            ).bind::<Text,_>(&lease.connection_id).bind::<Text,_>(&lease.session_binding).bind::<Text,_>(&lease.device_binding)
                .bind::<Timestamptz,_>(lease.expires_at).execute(&mut *conn).await?;
            Ok(written == 1)
        }).await.map_err(PgTransactionError::into_persistence)
    }

    async fn release_connection(&self, connection_id: &str) -> PersistenceResult<()> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query("DELETE FROM websocket_connection_leases WHERE connection_id=$1")
            .bind::<Text, _>(connection_id)
            .execute(&mut conn)
            .await
            .map_err(PersistenceError::database)?;
        Ok(())
    }
    async fn prepare_challenge(
        &self,
        record: &WebsocketAuthChallengeRecord,
    ) -> PersistenceResult<()> {
        let mut conn = crate::pg_db(&self.pool);
        let inserted = sql_query(
            "INSERT INTO websocket_auth_challenges (connection_id, nonce, canonical_origin, \
             canonical_base_url, issued_at, expires_at, consumed, retain_until) \
             VALUES ($1, $2, $3, $4, $5, $6, false, $7) ON CONFLICT DO NOTHING",
        )
        .bind::<Text, _>(&record.connection_id)
        .bind::<Text, _>(&record.nonce)
        .bind::<Text, _>(record.canonical_origin.as_str())
        .bind::<Text, _>(&record.canonical_base_url)
        .bind::<Timestamptz, _>(record.issued_at)
        .bind::<Timestamptz, _>(record.expires_at)
        .bind::<Timestamptz, _>(record.retain_until)
        .execute(&mut conn)
        .await
        .map_err(PersistenceError::database)?;
        if inserted == 0 {
            return Err(PersistenceError::Conflict(
                "websocket challenge already exists for this connection and nonce".to_owned(),
            ));
        }
        Ok(())
    }

    async fn get_challenge(
        &self,
        connection_id: &str,
        nonce: &str,
    ) -> PersistenceResult<Option<WebsocketAuthChallengeRecord>> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query(
            "SELECT connection_id, nonce, canonical_origin, canonical_base_url, issued_at, \
             expires_at, consumed, retain_until FROM websocket_auth_challenges \
             WHERE connection_id = $1 AND nonce = $2",
        )
        .bind::<Text, _>(connection_id)
        .bind::<Text, _>(nonce)
        .get_result::<WebsocketChallengeRow>(&mut conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(WebsocketAuthChallengeRecord::try_from)
        .transpose()
    }

    async fn replay_ledger_contains(
        &self,
        cnf_jkt: &str,
        jti: &str,
        proof_context: &str,
    ) -> PersistenceResult<bool> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query(
            "SELECT EXISTS(SELECT 1 FROM websocket_auth_replay_ledger \
             WHERE cnf_jkt = $1 AND jti = $2 AND proof_context = $3) AS present",
        )
        .bind::<Text, _>(cnf_jkt)
        .bind::<Text, _>(jti)
        .bind::<Text, _>(proof_context)
        .get_result::<ExistsRow>(&mut conn)
        .await
        .map(|row| row.present)
        .map_err(PersistenceError::database)
    }

    async fn consume_challenge(
        &self,
        connection_id: &str,
        nonce: &str,
        replay: &WebsocketAuthReplayRecord,
    ) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let connection_id = connection_id.to_owned();
        let nonce = nonce.to_owned();
        let replay = replay.clone();
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            // Ledger first: a second use of the same proof is refused before
            // the challenge row is touched, so a failed attempt can never
            // consume the challenge.
            let ledger = sql_query(
                "INSERT INTO websocket_auth_replay_ledger (cnf_jkt, jti, proof_context, \
                 consumed_at, retain_until) VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
            )
            .bind::<Text, _>(&replay.cnf_jkt)
            .bind::<Text, _>(&replay.jti)
            .bind::<Text, _>(&replay.proof_context)
            .bind::<Timestamptz, _>(replay.consumed_at)
            .bind::<Timestamptz, _>(replay.retain_until)
            .execute(&mut *conn)
            .await?;
            if ledger == 0 {
                return Ok(false);
            }
            let consumed = sql_query(
                "UPDATE websocket_auth_challenges SET consumed = true \
                 WHERE connection_id = $1 AND nonce = $2 AND consumed = false \
                 AND expires_at > clock_timestamp()",
            )
            .bind::<Text, _>(&connection_id)
            .bind::<Text, _>(&nonce)
            .execute(&mut *conn)
            .await?;
            if consumed == 0 {
                // Roll the ledger insert back with the transaction: the proof
                // was never actually accepted.
                return Err(PgTransactionError::Storage(PersistenceError::Conflict(
                    CHALLENGE_ALREADY_CONSUMED.to_owned(),
                )));
            }
            Ok(true)
        })
        .await
        .or_else(|error| match error.into_persistence() {
            PersistenceError::Conflict(reason) if reason == CHALLENGE_ALREADY_CONSUMED => Ok(false),
            other => Err(other),
        })
    }

    async fn prune_expired(&self, now: chrono::DateTime<Utc>) -> PersistenceResult<usize> {
        let mut conn = crate::pg_db(&self.pool);
        let challenges =
            sql_query("DELETE FROM websocket_auth_challenges WHERE retain_until <= $1")
                .bind::<Timestamptz, _>(now)
                .execute(&mut conn)
                .await
                .map_err(PersistenceError::database)?;
        let ledger = sql_query("DELETE FROM websocket_auth_replay_ledger WHERE retain_until <= $1")
            .bind::<Timestamptz, _>(now)
            .execute(&mut conn)
            .await
            .map_err(PersistenceError::database)?;
        let leases = sql_query("DELETE FROM websocket_connection_leases WHERE expires_at <= $1")
            .bind::<Timestamptz, _>(now)
            .execute(&mut conn)
            .await
            .map_err(PersistenceError::database)?;
        Ok(challenges + ledger + leases)
    }
}
