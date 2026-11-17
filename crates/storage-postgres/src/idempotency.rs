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
    record_idempotency_with_source_in_connection(conn, record, None).await
}

async fn record_idempotency_with_source_in_connection(
    conn: &mut diesel_async::AsyncPgConnection,
    record: &IdempotencyRecord,
    source_event_pk: Option<i64>,
) -> PersistenceResult<()> {
    let actor_key = actor_key(&record.authenticated_actor)?;
    let actor_value = actor_value(&record.authenticated_actor)?;
    // First-writer-wins under a concurrent race: the earliest row stays,
    // and a racer's later read returns it as a Replay.
    sql_query(
        "INSERT INTO idempotency_keys \
         (actor_key, authenticated_actor, operation_id, idempotency_key, request_hash, response_status, \
          response_body, created_at, expires_at, source_event_pk) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
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
    .bind::<diesel::sql_types::Nullable<diesel::sql_types::BigInt>, _>(source_event_pk)
    .execute(conn)
    .await
    .map(|_| ())
    .map_err(crate::persistence_query_error)
}
/// Compare under the unique row lock, in the accepting transaction. A
/// conflicting retry identity must roll back the Event and every MLS effect.
pub(crate) async fn record_native_mls_idempotency_in_connection(
    conn: &mut diesel_async::AsyncPgConnection,
    record: &IdempotencyRecord,
    event: &arkret_wire::Event,
) -> PersistenceResult<()> {
    require_mls_source_identity(record, event)?;
    #[derive(diesel::QueryableByName)]
    struct Source {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        pk: i64,
    }
    let token = crate::ids::parse_event_id(event.event_id.as_str())
        .ok_or_else(|| PersistenceError::SchemaViolation("invalid MLS source Event ID".into()))?;
    let source = sql_query("SELECT pk FROM canonical_events WHERE id=$1 AND envelope=$2 AND kind='ak.mls.commit' AND state IN ('committed','rejected')")
        .bind::<diesel::sql_types::Binary,_>(token.to_vec())
        .bind::<Jsonb,_>(serde_json::to_value(event).map_err(PersistenceError::database)?)
        .get_result::<Source>(conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(|| PersistenceError::Conflict("failed_precondition: MLS result has no exact terminal source Event".into()))?;
    record_idempotency_with_source_in_connection(conn, record, Some(source.pk)).await?;
    require_mls_idempotency_in_connection(conn, record, event)
        .await
        .map(|_| ())
}

fn require_mls_source_identity(
    record: &IdempotencyRecord,
    event: &arkret_wire::Event,
) -> PersistenceResult<()> {
    if event.kind != arkret_wire::EventKind::MlsCommit
        || &record.authenticated_actor != event.actual_signer()
        || record.operation_id != arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1
    {
        return Err(PersistenceError::SchemaViolation(
            "MLS result namespace differs from its exact source Event".into(),
        ));
    }
    Ok(())
}

/// Read the winning complete unit without creating a new identity for an
/// Event already accepted under a different retry key.
pub(crate) async fn require_mls_idempotency_in_connection(
    conn: &mut diesel_async::AsyncPgConnection,
    record: &IdempotencyRecord,
    event: &arkret_wire::Event,
) -> PersistenceResult<IdempotencyRecord> {
    require_mls_source_identity(record, event)?;
    let token = crate::ids::parse_event_id(event.event_id.as_str())
        .ok_or_else(|| PersistenceError::SchemaViolation("invalid MLS source Event ID".into()))?;
    let stored = sql_query(
        "SELECT k.authenticated_actor,k.operation_id,k.idempotency_key,k.request_hash,k.response_status,k.response_body,k.created_at,k.expires_at \
         FROM idempotency_keys k JOIN canonical_events e ON e.pk=k.source_event_pk WHERE k.actor_key=$1 AND k.operation_id=$2 AND k.idempotency_key=$3 AND e.id=$4 AND e.envelope=$5 AND e.kind='ak.mls.commit' FOR UPDATE OF k",
    ).bind::<Text,_>(actor_key(&record.authenticated_actor)?)
        .bind::<Text,_>(&record.operation_id).bind::<Text,_>(&record.idempotency_key)
        .bind::<diesel::sql_types::Binary,_>(token.to_vec())
        .bind::<Jsonb,_>(serde_json::to_value(event).map_err(PersistenceError::database)?)
        .get_result::<IdempotencyRow>(conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(|| PersistenceError::Conflict("duplicate_conflict: MLS Event has another complete retry unit".into()))?;
    if stored.request_hash != record.request_hash {
        return Err(PersistenceError::Conflict(
            "duplicate_conflict: native MLS retry key binds a different complete unit".into(),
        ));
    }
    stored.try_into()
}

/// A completed command cannot be replaced by a later worker's response.
pub(crate) async fn record_exact_idempotency_in_connection(
    conn: &mut diesel_async::AsyncPgConnection,
    record: &IdempotencyRecord,
) -> PersistenceResult<()> {
    // Accepted Contact and backup units retain their real source/outcome
    // separately. A terminal owner suppresses only this optional private copy.
    // Reuse the derived NOWAIT gate before any idempotency row lock; a true
    // result holds Account SHARE through this transaction and the exact read.
    if let Some(owner) = record.authenticated_actor.as_account_id() {
        #[derive(QueryableByName)]
        struct Allowed {
            #[diesel(sql_type = diesel::sql_types::Bool)]
            allowed: bool,
        }
        let row = sql_query("SELECT lock_account_private_projection($1,$2) AS allowed")
            .bind::<Text, _>(owner.principal_id.as_str())
            .bind::<Text, _>(owner.station_id.as_str())
            .get_result::<Allowed>(&mut *conn)
            .await
            .map_err(crate::persistence_query_error)?;
        if !row.allowed {
            return Ok(());
        }
    }
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
pub(crate) async fn preparation_record(
    conn: &mut diesel_async::AsyncPgConnection,
    record: &IdempotencyRecord,
) -> PersistenceResult<Option<IdempotencyRecord>> {
    sql_query("SELECT authenticated_actor,operation_id,idempotency_key,request_hash,response_status,response_body,created_at,expires_at FROM idempotency_keys WHERE actor_key=$1 AND operation_id=$2 AND idempotency_key=$3 FOR UPDATE")
        .bind::<Text,_>(actor_key(&record.authenticated_actor)?)
        .bind::<Text,_>(&record.operation_id).bind::<Text,_>(&record.idempotency_key)
        .get_result::<IdempotencyRow>(&mut *conn).await.optional()
        .map_err(crate::persistence_query_error)?
        .map(IdempotencyRecord::try_from).transpose()
}

#[async_trait]
impl IdempotencyStore for PgIdempotencyStore {
    async fn record_preparation(
        &self,
        primary: &IdempotencyRecord,
        context: Option<&IdempotencyRecord>,
    ) -> PersistenceResult<IdempotencyRecord> {
        use diesel_async::AsyncConnection as _;
        let owner = primary.authenticated_actor.as_account_id().ok_or_else(|| {
            PersistenceError::SchemaViolation(
                "private preparation requires an Account owner".into(),
            )
        })?;
        if context.is_some_and(|context| {
            context.authenticated_actor != primary.authenticated_actor
                || context.operation_id != primary.operation_id
                || context.request_hash != primary.request_hash
                || context.idempotency_key == primary.idempotency_key
        }) {
            return Err(PersistenceError::SchemaViolation(
                "private preparation context differs from its primary scope".into(),
            ));
        }
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, super::PgTransactionError, _>(async |conn| {
            crate::pcr_private_authority::require_active_account_owner(conn, owner).await?;
            // At most the actual primary and one context identity. Sort their
            // advisory locks before the first row, including absence, so two
            // preparations cannot take each other's alias in reverse order.
            let mut identities = std::collections::BTreeSet::new();
            for record in std::iter::once(primary).chain(context) {
                identities.insert(
                    arkret_canonical::canonical_json_string(&(
                        &record.authenticated_actor,
                        &record.operation_id,
                        &record.idempotency_key,
                    ))
                    .map_err(PersistenceError::database)?,
                );
            }
            for identity in identities {
                sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
                    .bind::<Text, _>(identity)
                    .execute(&mut *conn)
                    .await?;
            }
            if let Some(original) = preparation_record(conn, primary).await? {
                if original.request_hash != primary.request_hash {
                    return Err(PersistenceError::Conflict(
                        "duplicate_conflict: private preparation request changed".into(),
                    )
                    .into());
                }
                return Ok(original);
            }
            record_idempotency_in_connection(conn, primary).await?;
            let original = preparation_record(conn, primary).await?.ok_or_else(|| {
                PersistenceError::Internal("private preparation primary was not stored".into())
            })?;
            // Other generic writers still obey the table's first-writer rule.
            // A winner with different generated bytes owns its own context.
            if original.request_hash != primary.request_hash {
                return Err(PersistenceError::Conflict(
                    "duplicate_conflict: private preparation request changed".into(),
                )
                .into());
            }
            if original.response_status != primary.response_status
                || original.response_body != primary.response_body
            {
                return Ok(original);
            }
            if let Some(context) = context {
                record_idempotency_in_connection(conn, context).await?;
                let stored = preparation_record(conn, context).await?.ok_or_else(|| {
                    PersistenceError::Internal("private preparation context was not stored".into())
                })?;
                if stored.request_hash != context.request_hash
                    || stored.response_status != context.response_status
                    || stored.response_body != context.response_body
                {
                    return Err(PersistenceError::Conflict(
                        "duplicate_conflict: private preparation context is occupied".into(),
                    )
                    .into());
                }
            }
            Ok(original)
        })
        .await
        .map_err(super::PgTransactionError::into_persistence)
    }

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
        use diesel_async::AsyncConnection as _;
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, super::PgTransactionError, _>(async |conn| {
            // A standalone new private reservation must not report success
            // when the owner has already closed. No private row precedes this
            // typed gate. Accepted UOW mirrors use the separate derived path.
            if let Some(owner) = record.authenticated_actor.as_account_id() {
                crate::pcr_private_authority::require_active_account_owner(conn, owner).await?;
            }
            record_idempotency_in_connection(conn, record)
                .await
                .map_err(Into::into)
        })
        .await
        .map_err(super::PgTransactionError::into_persistence)
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
        .map_err(crate::persistence_query_error)
    }

    async fn prune_expired(&self, now: chrono::DateTime<Utc>) -> PersistenceResult<usize> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query("DELETE FROM idempotency_keys WHERE expires_at <= $1 AND source_event_pk IS NULL")
            .bind::<Timestamptz, _>(now)
            .execute(&mut conn)
            .await
            .map_err(PersistenceError::database)
    }
}

#[cfg(test)]
#[path = "idempotency/preparation_tests.rs"]
mod preparation_tests;
