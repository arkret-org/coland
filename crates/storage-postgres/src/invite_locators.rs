use super::{
    AsyncConnection, BigInt, Bool, InviteLocatorInsertOutcome, InviteLocatorRecord,
    InviteLocatorRotateMutation, InviteLocatorStore, Jsonb, Nullable, OptionalExtension,
    PersistenceError, PersistenceResult, PgPool, PgTransactionError, QueryableByName, RunQueryDsl,
    Text, Timestamptz, Utc, Value, async_trait, pg_conn, sql_query,
};

pub struct PgInviteLocatorStore {
    pub pool: PgPool,
}

#[derive(QueryableByName)]
struct CountResult {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

#[derive(QueryableByName)]
struct LocatorRow {
    #[diesel(sql_type = Jsonb)]
    record_payload: Value,
    #[diesel(sql_type = Bool)]
    one_time_use: bool,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    revoked_at: Option<chrono::DateTime<Utc>>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    consumed_at: Option<chrono::DateTime<Utc>>,
}

fn decode(mut row: LocatorRow) -> PersistenceResult<InviteLocatorRecord> {
    let mut record: InviteLocatorRecord = serde_json::from_value(row.record_payload.take())
        .map_err(|error| PersistenceError::Internal(format!("invite locator decode: {error}")))?;
    record.one_time_use = row.one_time_use;
    record.revoked_at = row.revoked_at;
    record.consumed_at = row.consumed_at;
    Ok(record)
}

fn payload(record: &InviteLocatorRecord) -> PersistenceResult<Value> {
    serde_json::to_value(record)
        .map_err(|error| PersistenceError::Internal(format!("invite locator encode: {error}")))
}

#[async_trait]
impl InviteLocatorStore for PgInviteLocatorStore {
    async fn insert(
        &self,
        record: &InviteLocatorRecord,
        active_limit: usize,
        now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<InviteLocatorInsertOutcome> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let record = record.clone();
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            sql_query("SELECT pg_advisory_xact_lock(hashtext($1))")
                .bind::<Text, _>(&record.subject_id)
                .execute(conn)
                .await?;
            let count = sql_query(
                "SELECT COUNT(*)::bigint AS count FROM invite_locators WHERE subject_id = $1 AND expires_at > $2 AND revoked_at IS NULL AND consumed_at IS NULL",
            )
            .bind::<Text, _>(&record.subject_id)
            .bind::<Timestamptz, _>(now)
            .get_result::<CountResult>(conn)
            .await?;
            if count.count >= active_limit as i64 {
                return Ok(InviteLocatorInsertOutcome::ActiveLimitReached);
            }
            let payload = payload(&record)?;
            sql_query("INSERT INTO invite_locators (locator_id, token_digest, subject_id, recipient_id, issued_at, expires_at, one_time_use, record_payload) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)")
                .bind::<Text, _>(&record.locator_id)
                .bind::<Text, _>(&record.token_digest)
                .bind::<Text, _>(&record.subject_id)
                .bind::<Text, _>(&record.recipient_id)
                .bind::<Timestamptz, _>(record.issued_at)
                .bind::<Timestamptz, _>(record.expires_at)
                .bind::<Bool, _>(record.one_time_use)
                .bind::<Jsonb, _>(&payload)
                .execute(conn).await?;
            Ok(InviteLocatorInsertOutcome::Inserted)
        }).await.map_err(PgTransactionError::into_persistence)
    }

    async fn resolve_and_consume(
        &self,
        token_digest: &str,
        now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<Option<InviteLocatorRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let token_digest = token_digest.to_owned();
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            let row = sql_query("SELECT record_payload, one_time_use, revoked_at, consumed_at FROM invite_locators WHERE token_digest = $1 AND expires_at > $2 AND revoked_at IS NULL AND consumed_at IS NULL FOR UPDATE")
                .bind::<Text, _>(&token_digest).bind::<Timestamptz, _>(now)
                .get_result::<LocatorRow>(conn).await.optional()?;
            let Some(mut record) = row.map(decode).transpose()? else { return Ok(None); };
            if record.one_time_use {
                sql_query("UPDATE invite_locators SET consumed_at = $2 WHERE token_digest = $1")
                    .bind::<Text, _>(&token_digest).bind::<Timestamptz, _>(now).execute(conn).await?;
                record.consumed_at = Some(now);
            }
            Ok(Some(record))
        }).await.map_err(PgTransactionError::into_persistence)
    }

    async fn rotate(
        &self,
        subject_id: &str,
        old_locator_id: &str,
        mutation: &InviteLocatorRotateMutation,
        now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<Option<InviteLocatorRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let subject_id = subject_id.to_owned();
        let old_locator_id = old_locator_id.to_owned();
        let mutation = mutation.clone();
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            let old = sql_query("SELECT record_payload, one_time_use, revoked_at, consumed_at FROM invite_locators WHERE locator_id = $1 AND subject_id = $2 AND expires_at > $3 AND revoked_at IS NULL AND consumed_at IS NULL FOR UPDATE")
                .bind::<Text, _>(&old_locator_id).bind::<Text, _>(&subject_id).bind::<Timestamptz, _>(now)
                .get_result::<LocatorRow>(conn).await.optional()?;
            let Some(old) = old.map(decode).transpose()? else { return Ok(None); };
            let replacement = mutation.apply_to(&old);
            sql_query("UPDATE invite_locators SET revoked_at = $2 WHERE locator_id = $1")
                .bind::<Text, _>(&old_locator_id).bind::<Timestamptz, _>(now).execute(conn).await?;
            let replacement_payload = payload(&replacement)?;
            sql_query("INSERT INTO invite_locators (locator_id, token_digest, subject_id, recipient_id, issued_at, expires_at, one_time_use, record_payload) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)")
                .bind::<Text, _>(&replacement.locator_id).bind::<Text, _>(&replacement.token_digest)
                .bind::<Text, _>(&replacement.subject_id).bind::<Text, _>(&replacement.recipient_id)
                .bind::<Timestamptz, _>(replacement.issued_at).bind::<Timestamptz, _>(replacement.expires_at)
                .bind::<Bool, _>(replacement.one_time_use).bind::<Jsonb, _>(&replacement_payload)
                .execute(conn).await?;
            Ok(Some(replacement))
        }).await.map_err(PgTransactionError::into_persistence)
    }

    async fn revoke(
        &self,
        subject_id: &str,
        locator_id: &str,
        now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<Option<InviteLocatorRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let row = sql_query("UPDATE invite_locators SET revoked_at = COALESCE(revoked_at, $3) WHERE locator_id = $1 AND subject_id = $2 AND consumed_at IS NULL RETURNING record_payload, one_time_use, revoked_at, consumed_at")
            .bind::<Text, _>(locator_id).bind::<Text, _>(subject_id).bind::<Timestamptz, _>(now)
            .get_result::<LocatorRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
        row.map(decode).transpose()
    }
}
