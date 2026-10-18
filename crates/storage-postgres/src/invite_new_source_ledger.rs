use arkret_wire::AccountId;
use arkret_wire::receive_policy::EffectiveNewSourceQuota;
use diesel::OptionalExtension as _;
use diesel_async::AsyncConnection;

use super::{
    BigInt, InviteNewSourceLedgerStore, NewSourceAdmission, PersistenceError, PersistenceResult,
    PgPool, PgTransactionError, QueryableByName, RunQueryDsl, Text, Timestamptz, Utc, async_trait,
    pg_conn, sql_query,
};

pub struct PgInviteNewSourceLedgerStore {
    pub pool: PgPool,
}

/// This read never creates or rotates a key, including on denied first contact.
pub(crate) async fn source_digest_in_connection(
    conn: &mut diesel_async::AsyncPgConnection,
    holder: &AccountId,
    source: &arkret_wire::DidCoreId,
) -> PersistenceResult<String> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    #[derive(QueryableByName)]
    struct Key {
        #[diesel(sql_type=diesel::sql_types::Binary)]
        key_bytes: Vec<u8>,
    }
    let key=sql_query("SELECT k.key_bytes FROM invite_new_source_hmac_keys k JOIN accounts a ON a.pk=k.account_pk WHERE a.principal_id=$1 AND a.station_id=$2")
        .bind::<Text,_>(holder.principal_id.as_str()).bind::<Text,_>(holder.station_id.as_str())
        .get_result::<Key>(conn).await.optional().map_err(PersistenceError::database)?
        .filter(|key|key.key_bytes.len()==32)
        .ok_or_else(|| PersistenceError::Conflict("temporarily_unavailable: immutable holder quota key is missing".into()))?;
    let material = format!(
        "coland-invite-new-source-ledger-v1\0{}\0{}\0{source}",
        holder.principal_id, holder.station_id
    );
    let mut mac = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(&key.key_bytes)
        .map_err(|_| PersistenceError::SchemaViolation("holder quota key is invalid".into()))?;
    mac.update(material.as_bytes());
    Ok(mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

#[derive(QueryableByName)]
struct CountsRow {
    #[diesel(sql_type = BigInt)]
    rate: i64,
    #[diesel(sql_type = BigInt)]
    total: i64,
}

#[derive(QueryableByName)]
struct SeenRow {
    #[diesel(sql_type = BigInt)]
    seen: i64,
}

#[async_trait]
impl InviteNewSourceLedgerStore for PgInviteNewSourceLedgerStore {
    async fn source_digest(
        &self,
        holder: &AccountId,
        source: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<String> {
        let mut conn = pg_conn(&self.pool).await?;
        source_digest_in_connection(&mut conn, holder, source).await
    }
    async fn admit_new_source(
        &self,
        holder: &AccountId,
        source_digest: &str,
        now: chrono::DateTime<Utc>,
        quota: &EffectiveNewSourceQuota,
    ) -> PersistenceResult<NewSourceAdmission> {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async |conn| {
            crate::pcr_private_authority::lock_holder(conn, holder, Some(&holder.station_id))
                .await?;
            admit_in_connection(conn, holder, source_digest, now, quota)
                .await
                .map_err(Into::into)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn delete_for_holder(&self, holder: &AccountId) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "WITH holder AS (SELECT pk FROM accounts WHERE principal_id=$1 AND station_id=$2), \
             erased_ledger AS (DELETE FROM invite_new_source_ledgers WHERE account_pk IN (SELECT pk FROM holder)) \
             DELETE FROM invite_new_source_hmac_keys WHERE account_pk IN (SELECT pk FROM holder)",
        )
        .bind::<Text, _>(holder.principal_id.as_str())
        .bind::<Text, _>(holder.station_id.as_str())
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn retained_source_count(&self, holder: &AccountId) -> PersistenceResult<usize> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let row = sql_query(
            "SELECT count(*) AS seen FROM invite_new_source_ledgers l \
             JOIN accounts a ON a.pk = l.account_pk \
             WHERE a.principal_id = $1 AND a.station_id = $2",
        )
        .bind::<Text, _>(holder.principal_id.as_str())
        .bind::<Text, _>(holder.station_id.as_str())
        .get_result::<SeenRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        Ok(usize::try_from(row.seen).unwrap_or(usize::MAX))
    }
}

/// Caller holds the holder PCR authority lock. Denials and retained-source
/// retries never prune, charge or renew a source's original admission instant.
pub(crate) async fn admit_in_connection(
    conn: &mut diesel_async::AsyncPgConnection,
    holder: &AccountId,
    source_digest: &str,
    now: chrono::DateTime<Utc>,
    quota: &EffectiveNewSourceQuota,
) -> PersistenceResult<NewSourceAdmission> {
    let lock = format!(
        "invite-new-source-ledger:{}:{}",
        holder.principal_id, holder.station_id
    );
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind::<Text, _>(lock)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    let retained = now - chrono::Duration::seconds(quota.retention_seconds as i64);
    let window = now - chrono::Duration::seconds(quota.window_seconds as i64);
    let seen=sql_query("SELECT count(*) AS seen FROM invite_new_source_ledgers l JOIN accounts a ON a.pk=l.account_pk WHERE a.principal_id=$1 AND a.station_id=$2 AND l.source_digest=$3 AND l.first_admitted_at>$4")
        .bind::<Text,_>(holder.principal_id.as_str()).bind::<Text,_>(holder.station_id.as_str()).bind::<Text,_>(source_digest).bind::<Timestamptz,_>(retained)
        .get_result::<SeenRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    if seen.seen > 0 {
        return Ok(NewSourceAdmission::Seen);
    }
    let count=sql_query("SELECT count(*) FILTER(WHERE l.first_admitted_at>$3) AS rate,count(*) FILTER(WHERE l.first_admitted_at>$4) AS total FROM invite_new_source_ledgers l JOIN accounts a ON a.pk=l.account_pk WHERE a.principal_id=$1 AND a.station_id=$2")
        .bind::<Text,_>(holder.principal_id.as_str()).bind::<Text,_>(holder.station_id.as_str()).bind::<Timestamptz,_>(window).bind::<Timestamptz,_>(retained)
        .get_result::<CountsRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    if count.rate >= quota.new_sources_per_window as i64
        || count.total >= quota.new_sources_per_retention as i64
    {
        return Ok(NewSourceAdmission::Denied);
    }
    sql_query("DELETE FROM invite_new_source_ledgers l USING accounts a WHERE l.account_pk=a.pk AND a.principal_id=$1 AND a.station_id=$2 AND l.first_admitted_at<=$3")
        .bind::<Text,_>(holder.principal_id.as_str()).bind::<Text,_>(holder.station_id.as_str()).bind::<Timestamptz,_>(retained).execute(&mut *conn).await.map_err(PersistenceError::database)?;
    let written=sql_query("INSERT INTO invite_new_source_ledgers(account_pk,source_digest,first_admitted_at) SELECT pk,$3,$4 FROM accounts WHERE principal_id=$1 AND station_id=$2 ON CONFLICT(account_pk,source_digest) DO NOTHING")
        .bind::<Text,_>(holder.principal_id.as_str()).bind::<Text,_>(holder.station_id.as_str()).bind::<Text,_>(source_digest).bind::<Timestamptz,_>(now).execute(&mut *conn).await.map_err(PersistenceError::database)?;
    if written != 1 {
        return Err(PersistenceError::Conflict(
            "holder quota account is unavailable".into(),
        ));
    }
    Ok(NewSourceAdmission::Admitted)
}
