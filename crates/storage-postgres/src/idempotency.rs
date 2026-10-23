use super::{
    IdempotencyRecord, IdempotencyStore, Integer, Jsonb, OptionalExtension, PersistenceError,
    PersistenceResult, PgPool, QueryableByName, RunQueryDsl, Text, Timestamptz, Utc, Value,
    async_trait, pg_conn, sql_query,
};
pub struct PgIdempotencyStore {
    pub pool: PgPool,
}

/// Write one idempotency reservation on a caller-owned connection.
///
/// The Event commit unit of work calls this inside its single transaction so a
/// rolled-back commit never leaves a reservation that would replay a response
/// for an Event that was never committed.
pub(crate) async fn record_idempotency_in_connection(
    conn: &mut diesel_async::AsyncPgConnection,
    record: &IdempotencyRecord,
) -> PersistenceResult<()> {
    let actor_key = actor_key(&record.authenticated_actor)?;
    let actor_value = actor_value(&record.authenticated_actor)?;
    // First-writer-wins under a concurrent race: the earliest row stays,
    // and a racer's later read returns it as a Replay.
    sql_query(
        "INSERT INTO idempotency_keys \
         (actor_key, authenticated_actor, operation_id, idempotency_key, request_hash, response_status, \
          response_body, created_at, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
         ON CONFLICT (actor_key, operation_id, idempotency_key) DO NOTHING",
    )
    .bind::<Text, _>(&actor_key)
    .bind::<Jsonb, _>(&actor_value)
    .bind::<Text, _>(&record.operation_id)
    .bind::<Text, _>(&record.idempotency_key)
    .bind::<Text, _>(&record.request_hash)
    .bind::<Integer, _>(record.response_status)
    .bind::<Jsonb, _>(&record.response_body)
    .bind::<Timestamptz, _>(record.created_at)
    .bind::<Timestamptz, _>(record.expires_at)
    .execute(conn)
    .await
    .map(|_| ())
    .map_err(PersistenceError::database)
}
/// Compare under the unique row lock, in the accepting transaction. A
/// conflicting retry identity must roll back the Event and every MLS effect.
pub(crate) async fn record_native_mls_idempotency_in_connection(
    conn: &mut diesel_async::AsyncPgConnection,
    record: &IdempotencyRecord,
) -> PersistenceResult<()> {
    record_idempotency_in_connection(conn, record).await?;
    let stored = sql_query(
        "SELECT authenticated_actor,operation_id,idempotency_key,request_hash,response_status,response_body,created_at,expires_at \
         FROM idempotency_keys WHERE actor_key=$1 AND operation_id=$2 AND idempotency_key=$3 FOR UPDATE",
    ).bind::<Text,_>(actor_key(&record.authenticated_actor)?)
        .bind::<Text,_>(&record.operation_id).bind::<Text,_>(&record.idempotency_key)
        .get_result::<IdempotencyRow>(conn).await.map_err(PersistenceError::database)?;
    if stored.request_hash != record.request_hash {
        return Err(PersistenceError::Conflict(
            "duplicate_conflict: native MLS retry key binds a different complete unit".into(),
        ));
    }
    Ok(())
}

/// A completed command cannot be replaced by a later worker's response.
pub(crate) async fn record_exact_idempotency_in_connection(
    conn: &mut diesel_async::AsyncPgConnection,
    record: &IdempotencyRecord,
) -> PersistenceResult<()> {
    record_idempotency_in_connection(conn, record).await?;
    let stored = sql_query("SELECT authenticated_actor,operation_id,idempotency_key,request_hash,response_status,response_body,created_at,expires_at FROM idempotency_keys WHERE actor_key=$1 AND operation_id=$2 AND idempotency_key=$3 FOR UPDATE")
        .bind::<Text,_>(actor_key(&record.authenticated_actor)?)
        .bind::<Text,_>(&record.operation_id).bind::<Text,_>(&record.idempotency_key)
        .get_result::<IdempotencyRow>(conn).await.map_err(PersistenceError::database)?;
    if stored.request_hash != record.request_hash
        || stored.response_status != record.response_status
        || stored.response_body != record.response_body
    {
        return Err(PersistenceError::Conflict(
            "duplicate_conflict: accepted command response changed".into(),
        ));
    }
    Ok(())
}

#[derive(QueryableByName)]
struct IdempotencyRow {
    #[diesel(sql_type = Jsonb)]
    authenticated_actor: Value,
    #[diesel(sql_type = Text)]
    operation_id: String,
    #[diesel(sql_type = Text)]
    idempotency_key: String,
    #[diesel(sql_type = Text)]
    request_hash: String,
    #[diesel(sql_type = Integer)]
    response_status: i32,
    #[diesel(sql_type = Jsonb)]
    response_body: Value,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<Utc>,
    #[diesel(sql_type = Timestamptz)]
    expires_at: chrono::DateTime<Utc>,
}

impl TryFrom<IdempotencyRow> for IdempotencyRecord {
    type Error = PersistenceError;

    fn try_from(row: IdempotencyRow) -> Result<Self, Self::Error> {
        Ok(Self {
            authenticated_actor: serde_json::from_value(row.authenticated_actor).map_err(
                |error| {
                    PersistenceError::SchemaViolation(format!(
                        "stored authenticated ActorId is invalid: {error}"
                    ))
                },
            )?,
            operation_id: row.operation_id,
            idempotency_key: row.idempotency_key,
            request_hash: row.request_hash,
            response_status: row.response_status,
            response_body: row.response_body,
            created_at: row.created_at,
            expires_at: row.expires_at,
        })
    }
}

fn actor_key(actor: &arkret_wire::ActorId) -> PersistenceResult<String> {
    actor.canonical_key().map_err(|error| {
        PersistenceError::SchemaViolation(format!("authenticated ActorId is invalid: {error}"))
    })
}

fn actor_value(actor: &arkret_wire::ActorId) -> PersistenceResult<Value> {
    serde_json::to_value(actor).map_err(|error| {
        PersistenceError::SchemaViolation(format!("authenticated ActorId encode failed: {error}"))
    })
}
#[async_trait]
impl IdempotencyStore for PgIdempotencyStore {
    async fn record_with_lookup(
        &self,
        response: &IdempotencyRecord,
        lookup: &IdempotencyRecord,
    ) -> PersistenceResult<IdempotencyRecord> {
        use diesel_async::AsyncConnection as _;
        let response = response.clone();
        let lookup = lookup.clone();
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, super::PgTransactionError, _>(async move |conn| {
            let lookup_actor = actor_key(&lookup.authenticated_actor)?;
            let lock = format!("{}:{}:{}", lookup_actor, lookup.operation_id, lookup.idempotency_key);
            sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind::<Text, _>(lock).execute(&mut *conn).await?;
            record_idempotency_in_connection(conn, &lookup).await?;
            record_idempotency_in_connection(conn, &response).await?;
            let mut landed = None;
            for candidate in [&lookup, &response] {
                let stored: IdempotencyRecord = sql_query(
                    "SELECT authenticated_actor,operation_id,idempotency_key,request_hash,response_status, \
                     response_body,created_at,expires_at FROM idempotency_keys \
                     WHERE actor_key=$1 AND operation_id=$2 AND idempotency_key=$3",
                ).bind::<Text, _>(actor_key(&candidate.authenticated_actor)?)
                    .bind::<Text, _>(&candidate.operation_id)
                    .bind::<Text, _>(&candidate.idempotency_key)
                    .get_result::<IdempotencyRow>(&mut *conn).await?.try_into()?;
                if stored.request_hash != candidate.request_hash {
                    return Err(PersistenceError::Conflict(
                        "duplicate_conflict: receipt request or resource binds different bytes".into(),
                    ).into());
                }
                landed = Some(stored);
            }
            Ok(landed.expect("response record was read"))
        }).await.map_err(super::PgTransactionError::into_persistence)
    }

    async fn get(
        &self,
        authenticated_actor: &arkret_wire::ActorId,
        operation_id: &str,
        idempotency_key: &str,
    ) -> PersistenceResult<Option<IdempotencyRecord>> {
        let mut conn = crate::pg_db(&self.pool);
        let actor_key = actor_key(authenticated_actor)?;
        Ok(sql_query(
            "SELECT authenticated_actor, operation_id, idempotency_key, request_hash, response_status, \
             response_body, created_at, expires_at \
             FROM idempotency_keys WHERE actor_key = $1 AND operation_id = $2 AND idempotency_key = $3",
        )
        .bind::<Text, _>(&actor_key)
        .bind::<Text, _>(operation_id)
        .bind::<Text, _>(idempotency_key)
        .get_result::<IdempotencyRow>(&mut conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(IdempotencyRecord::try_from)
        .transpose()?)
    }

    async fn record(&self, record: &IdempotencyRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        record_idempotency_in_connection(&mut conn, record).await
    }

    async fn complete_reservation(
        &self,
        expected: &IdempotencyRecord,
        completed: &IdempotencyRecord,
    ) -> PersistenceResult<bool> {
        if expected.authenticated_actor != completed.authenticated_actor
            || expected.operation_id != completed.operation_id
            || expected.idempotency_key != completed.idempotency_key
        {
            return Ok(false);
        }
        let mut conn = crate::pg_db(&self.pool);
        let actor_key = actor_key(&expected.authenticated_actor)?;
        sql_query(
            "UPDATE idempotency_keys SET request_hash = $9, response_status = $10, \
             response_body = $11, created_at = $12, expires_at = $13 \
             WHERE actor_key = $1 AND operation_id = $2 AND idempotency_key = $3 \
             AND request_hash = $4 AND response_status = $5 AND response_body = $6 \
             AND created_at = $7 AND expires_at = $8",
        )
        .bind::<Text, _>(&actor_key)
        .bind::<Text, _>(&expected.operation_id)
        .bind::<Text, _>(&expected.idempotency_key)
        .bind::<Text, _>(&expected.request_hash)
        .bind::<Integer, _>(expected.response_status)
        .bind::<Jsonb, _>(&expected.response_body)
        .bind::<Timestamptz, _>(expected.created_at)
        .bind::<Timestamptz, _>(expected.expires_at)
        .bind::<Text, _>(&completed.request_hash)
        .bind::<Integer, _>(completed.response_status)
        .bind::<Jsonb, _>(&completed.response_body)
        .bind::<Timestamptz, _>(completed.created_at)
        .bind::<Timestamptz, _>(completed.expires_at)
        .execute(&mut conn)
        .await
        .map(|affected| affected == 1)
        .map_err(PersistenceError::database)
    }

    async fn prune_expired(&self, now: chrono::DateTime<Utc>) -> PersistenceResult<usize> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query("DELETE FROM idempotency_keys WHERE expires_at <= $1")
            .bind::<Timestamptz, _>(now)
            .execute(&mut conn)
            .await
            .map_err(PersistenceError::database)
    }
}
