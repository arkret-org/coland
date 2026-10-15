//! Durable reject-only high water for verified private proxy responses.
use arkret_models_collaboration::consent_private::*;
use coland_storage::{PersistenceError, PersistenceResult};
use diesel::sql_types::{BigInt, Jsonb, Text};
use diesel::{OptionalExtension as _, sql_query};
use diesel_async::{AsyncConnection as _, RunQueryDsl};
use serde_json::{Value, json};

use crate::{PgConsentCurrentStore, PgTransactionError, pg_conn};
fn unavailable(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!(
        "temporarily_unavailable: private proxy high water {detail}"
    ))
}
#[derive(diesel::QueryableByName)]
struct Cut {
    #[diesel(sql_type=Text)]
    realm_id: String,
    #[diesel(sql_type=BigInt)]
    governance_generation: i64,
    #[diesel(sql_type=BigInt)]
    head_stream_position: i64,
    #[diesel(sql_type=Text)]
    head_commit_id: String,
    #[diesel(sql_type=Jsonb)]
    cell_revisions: Value,
}
pub(crate) async fn observe(
    store: &PgConsentCurrentStore,
    request: &ConsentPrivateProxyRequest,
    outcome: &ConsentPrivateProxyOutcome,
) -> PersistenceResult<()> {
    outcome
        .validate_for_request(request, chrono::Utc::now())
        .map_err(unavailable)?;
    let holder =
        serde_json::to_value(&request.holder_account_id).map_err(PersistenceError::database)?;
    let generation = i64::try_from(outcome.governance_generation).map_err(unavailable)?;
    let position =
        i64::try_from(outcome.effective_stream_head.stream_position).map_err(unavailable)?;
    let summarize = |revision: u64, content: Value| -> PersistenceResult<Value> {
        Ok(
            json!({"revision":revision,"content_digest":arkret_canonical::canonical_sha256(&content).map_err(PersistenceError::database)?}),
        )
    };
    let mut revisions = serde_json::Map::new();
    if let ConsentPrivateCommandOutcome::Effects(effects) = &outcome.outcome {
        effects
            .body
            .validate_holder(&request.holder_account_id)
            .map_err(unavailable)?;
        revisions.insert(
            "holder_quarantine".into(),
            effects
                .body
                .holder_quarantine
                .as_ref()
                .map(|c| {
                    summarize(
                        c.revision,
                        serde_json::to_value(&c.content).map_err(PersistenceError::database)?,
                    )
                })
                .transpose()?
                .unwrap_or(Value::Null),
        );
        revisions.insert(
            "invite_delivery".into(),
            effects
                .body
                .invite_delivery
                .as_ref()
                .map(|c| {
                    summarize(
                        c.revision,
                        serde_json::to_value(&c.content).map_err(PersistenceError::database)?,
                    )
                })
                .transpose()?
                .unwrap_or(Value::Null),
        );
        revisions.insert(
            "invite_receive_policy".into(),
            effects
                .body
                .invite_receive_policy
                .as_ref()
                .map(|c| {
                    summarize(
                        c.revision,
                        serde_json::to_value(&c.content).map_err(PersistenceError::database)?,
                    )
                })
                .transpose()?
                .unwrap_or(Value::Null),
        );
    }
    if let ConsentPrivateCommandOutcome::InvitePolicy(policy) = &outcome.outcome {
        revisions.insert(
            "invite_receive_policy".into(),
            summarize(
                policy.body.revision,
                serde_json::to_value(&policy.body.content).map_err(PersistenceError::database)?,
            )?,
        );
    }
    let mut conn = pg_conn(&store.pool).await?;
    conn.transaction::<_,PgTransactionError,_>(async |conn| {
        let lock=format!("consent-private-host-cut:{}:{}",request.holder_account_id.principal_id,request.holder_account_id.station_id);
        sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))").bind::<Text,_>(lock).execute(&mut *conn).await?;
        let held=sql_query("SELECT realm_id,governance_generation,head_stream_position,head_commit_id,cell_revisions FROM consent_private_proxy_cuts WHERE holder_account_id=$1 FOR UPDATE")
            .bind::<Jsonb,_>(&holder).get_result::<Cut>(&mut *conn).await.optional()?;
        let mut cells=held.as_ref().map_or_else(||json!({}),|cut|cut.cell_revisions.clone());
        if let Some(held)=held {
            if held.realm_id!=outcome.realm_id.as_str() || generation<held.governance_generation || position<held.head_stream_position
                || (position==held.head_stream_position && held.head_commit_id!=outcome.effective_stream_head.commit_id.as_str()) {
                return Err(unavailable("rejects an obsolete or forked response").into());
            }
        }
        for (key,value) in revisions {
            if let Some(old)=cells.get(&key).filter(|v|!v.is_null()) {
                let previous=old.get("revision").and_then(Value::as_u64).ok_or_else(||unavailable("stored private-cell cut is incomplete"))?;
                if value.get("revision").and_then(Value::as_u64).is_none_or(|revision|revision<previous || (revision==previous && *old!=value)) {return Err(unavailable("rejects a private-cell revision rollback or content fork").into());}
            }
            cells[&key]=value;
        }
        sql_query("INSERT INTO consent_private_proxy_cuts(holder_account_id,realm_id,governance_generation,head_stream_position,head_commit_id,cell_revisions) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(holder_account_id) DO UPDATE SET realm_id=EXCLUDED.realm_id,governance_generation=EXCLUDED.governance_generation,head_stream_position=EXCLUDED.head_stream_position,head_commit_id=EXCLUDED.head_commit_id,cell_revisions=EXCLUDED.cell_revisions")
            .bind::<Jsonb,_>(&holder).bind::<Text,_>(outcome.realm_id.as_str()).bind::<BigInt,_>(generation).bind::<BigInt,_>(position)
            .bind::<Text,_>(outcome.effective_stream_head.commit_id.as_str()).bind::<Jsonb,_>(cells).execute(&mut *conn).await?;
        Ok(())
    }).await.map_err(PgTransactionError::into_persistence)
}
