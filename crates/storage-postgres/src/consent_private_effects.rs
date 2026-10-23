//! Durable publication intents belong to the same native PCR private unit.
use arkret_wire::{AccountId, RealmId};
use coland_storage::PersistenceResult;
use diesel::sql_query;
use diesel::sql_types::{Jsonb, Text};
use diesel_async::AsyncPgConnection;
use horme::RunQueryDsl;
pub(crate) async fn mark_pending(
    conn: &mut AsyncPgConnection,
    holder: &AccountId,
    realm: &RealmId,
) -> PersistenceResult<()> {
    sql_query("INSERT INTO consent_private_effect_jobs(holder_account_id,realm_id,sequence) VALUES($1,$2,1) ON CONFLICT(holder_account_id) DO UPDATE SET realm_id=EXCLUDED.realm_id,sequence=consent_private_effect_jobs.sequence+1")
        .bind::<Jsonb,_>(serde_json::to_value(holder).map_err(coland_storage::PersistenceError::database)?).bind::<Text,_>(realm.as_str()).execute(conn).await.map_err(coland_storage::PersistenceError::database)?;
    Ok(())
}

use arkret_models_collaboration::consent_private::ConsentPrivateEffectsPublishRequest;
use arkret_wire::DidCoreId;
use coland_storage::{PersistenceError, PrivateEffectsPublication};
use diesel::sql_types::BigInt;
use diesel_async::AsyncConnection as _;
use horme::OptionalExtension as _;

use crate::{PgPool, PgTransactionError, pg_conn};
#[derive(diesel::QueryableByName)]
struct Holder {
    #[diesel(sql_type=Jsonb)]
    holder_account_id: serde_json::Value,
}
#[derive(diesel::QueryableByName)]
struct Sequence {
    #[diesel(sql_type=BigInt)]
    sequence: i64,
}
pub(crate) async fn pending(
    pool: &PgPool,
    issuer: &DidCoreId,
) -> PersistenceResult<Vec<AccountId>> {
    let mut conn = pg_conn(pool).await?;
    let rows=sql_query("SELECT j.holder_account_id FROM consent_private_effect_jobs j JOIN realm_authorities a ON a.realm_id=j.realm_id WHERE a.service_id=$1 AND NOT EXISTS(SELECT 1 FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk WHERE c.realm_id=a.realm_id AND c.governance_generation=a.generation AND e.kind='ak.realm.governance_station.change') ORDER BY j.realm_id LIMIT 32")
        .bind::<Text,_>(issuer.as_str()).get_results::<Holder>(&mut conn).await.map_err(PersistenceError::database)?;
    rows.into_iter()
        .map(|row| {
            serde_json::from_value(row.holder_account_id).map_err(PersistenceError::database)
        })
        .collect()
}
pub(crate) async fn prepare(
    pool: &PgPool,
    holder: &AccountId,
    issuer: &DidCoreId,
    nonce: String,
) -> PersistenceResult<Option<PrivateEffectsPublication>> {
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_,PgTransactionError,_>(async |conn| {
        let cut=crate::pcr_private_authority::lock_holder(conn,holder,Some(issuer)).await?;
        crate::pcr_private_authority::require_transferable(conn,&cut.realm_id).await?;
        let job=sql_query("SELECT sequence FROM consent_private_effect_jobs WHERE holder_account_id=$1 AND realm_id=$2")
            .bind::<Jsonb,_>(serde_json::to_value(holder).map_err(PersistenceError::database)?).bind::<Text,_>(cut.realm_id.as_str())
            .get_result::<Sequence>(&mut *conn).await.optional()?;
        let Some(job)=job else {return Ok(None)};
        crate::consent_current::records_in_connection(conn,holder,&cut.realm_id).await?;
        let effects=crate::consent_private_commands::effects(conn,holder).await?;
        let now=arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let request=ConsentPrivateEffectsPublishRequest{holder_account_id:holder.clone(),realm_id:cut.realm_id,governance_generation:cut.generation,nonce,effective_stream_head:cut.head,evaluated_at:now,expires_at:now+chrono::Duration::seconds(30),effects};
        request.validate_for_authority(issuer,&holder.station_id,&request.realm_id,issuer,cut.generation,now).map_err(|e|PersistenceError::SchemaViolation(e.to_string()))?;
        Ok(Some(PrivateEffectsPublication{sequence:u64::try_from(job.sequence).map_err(PersistenceError::database)?,request}))
    }).await.map_err(PgTransactionError::into_persistence)
}
pub(crate) async fn acknowledge(
    pool: &PgPool,
    holder: &AccountId,
    issuer: &DidCoreId,
    sequence: u64,
) -> PersistenceResult<()> {
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async |conn| {
        crate::pcr_private_authority::lock_holder(conn, holder, Some(issuer)).await?;
        sql_query(
            "DELETE FROM consent_private_effect_jobs WHERE holder_account_id=$1 AND sequence=$2",
        )
        .bind::<Jsonb, _>(serde_json::to_value(holder).map_err(PersistenceError::database)?)
        .bind::<BigInt, _>(i64::try_from(sequence).map_err(PersistenceError::database)?)
        .execute(&mut *conn)
        .await?;
        Ok(())
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}

/// Native cells already own their durable account journal. Draining this job
/// sends a wakeup without constructing remote nonce or authority-cut state.
pub(crate) async fn drain_native(
    pool: &PgPool,
    holder: &AccountId,
    issuer: &DidCoreId,
) -> PersistenceResult<Vec<coland_storage::AccountDataRecord>> {
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_,PgTransactionError,_>(async |conn| {
  let cut=crate::pcr_private_authority::lock_holder(conn,holder,Some(issuer)).await?;
  if holder.station_id != *issuer || !crate::pcr_private_authority::accepted_governance(conn,&cut.realm_id).await?.is_human() {return Err(crate::pcr_private_authority::refused("native effects require the Human account Station").into());}
        crate::pcr_private_authority::require_active_human_account(conn,holder).await?;
        crate::consent_current::records_in_connection(conn,holder,&cut.realm_id).await?;
  let job=sql_query("DELETE FROM consent_private_effect_jobs WHERE holder_account_id=$1 RETURNING sequence").bind::<Jsonb,_>(serde_json::to_value(holder).map_err(PersistenceError::database)?).get_result::<Sequence>(&mut *conn).await.optional()?;
  if job.is_none() {return Ok(Vec::new());}
  #[derive(diesel::QueryableByName)]
  struct NativeCell {
   #[diesel(sql_type=Text)] account_data_key:String,
   #[diesel(sql_type=BigInt)] revision:i64,
   #[diesel(sql_type=Jsonb)] payload:serde_json::Value,
   #[diesel(sql_type=diesel::sql_types::Timestamptz)] updated_at:chrono::DateTime<chrono::Utc>,
  }
  let actor=arkret_wire::ActorId::account(holder.clone()).to_string();
  let cells=sql_query("SELECT account_data_key,revision,payload,updated_at FROM account_datas WHERE actor_id=$1 AND account_data_key IN ($2,$3) AND NOT tombstone AND account_data_source_current(actor_id,account_data_key)")
   .bind::<Text,_>(&actor).bind::<Text,_>(arkret_wire::AccountDataKey::ACCOUNT_HOLDER_QUARANTINE).bind::<Text,_>(arkret_wire::AccountDataKey::ACCOUNT_INVITE_DELIVERY).get_results::<NativeCell>(&mut *conn).await?;
  cells.into_iter().map(|c|Ok(coland_storage::AccountDataRecord{actor:actor.clone(),account_data_key:c.account_data_key,revision:u64::try_from(c.revision).map_err(PersistenceError::database)?,payload:c.payload,tombstone:false,updated_at:c.updated_at})).collect::<PersistenceResult<Vec<_>>>().map_err(Into::into)
 }).await.map_err(PgTransactionError::into_persistence)
}
