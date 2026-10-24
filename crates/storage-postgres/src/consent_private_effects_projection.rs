//! Authority-verified hosting projection. This never accepts a business CAS.
use arkret_models_collaboration::consent_private::*;
use arkret_wire::{AccountDataKey, ActorId, CommitStreamHead, DidCoreId};
use coland_storage::{
    AccountDataRecord, CurrentRealmAuthority, PersistenceError, PersistenceResult,
    PrivateEffectsProjection,
};
use diesel::sql_query;
use diesel::sql_types::{BigInt, Bool, Jsonb, Nullable, Text, Timestamptz};
use diesel_async::{AsyncConnection as _, AsyncPgConnection};
use horme::{OptionalExtension as _, RunQueryDsl};
use serde_json::{Value, json};

use crate::{PgPool, PgTransactionError, pg_conn};
fn unavailable(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!(
        "temporarily_unavailable: private effect projection {detail}"
    ))
}
#[derive(diesel::QueryableByName)]
struct Authority {
    #[diesel(sql_type=BigInt)]
    generation: i64,
    #[diesel(sql_type=Text)]
    service_id: String,
    #[diesel(sql_type=Jsonb)]
    authority_ref: Value,
    #[diesel(sql_type=Nullable<Text>)]
    last_handoff_ref: Option<String>,
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
#[derive(diesel::QueryableByName)]
struct Cell {
    #[diesel(sql_type=BigInt)]
    revision: i64,
    #[diesel(sql_type=Jsonb)]
    content: Value,
    #[diesel(sql_type=Bool)]
    tombstone: bool,
}
#[derive(diesel::QueryableByName)]
struct Position {
    #[diesel(sql_type=BigInt)]
    position: i64,
}
fn cell_cut(revision: u64, content: &Value) -> PersistenceResult<Value> {
    Ok(
        json!({"revision":revision,"content_digest":arkret_canonical::canonical_sha256(content).map_err(PersistenceError::database)?}),
    )
}
fn require_cell(
    cells: &mut Value,
    key: &str,
    next: Option<(u64, &Value)>,
) -> PersistenceResult<()> {
    let previous = cells.get(key);
    match next {
        None => {
            if previous
                .and_then(|v| v.get("revision"))
                .and_then(Value::as_u64)
                .is_some()
            {
                return Err(unavailable(
                    "cannot erase a known private revision with null",
                ));
            }
            cells[key] = Value::Null;
        }
        Some((revision, content)) => {
            let next = cell_cut(revision, content)?;
            if let Some(old) = previous.filter(|v| !v.is_null()) {
                let previous = old["revision"]
                    .as_u64()
                    .ok_or_else(|| unavailable("stored private cut is incomplete"))?;
                if revision < previous || (revision == previous && *old != next) {
                    return Err(unavailable("private revision rollback or content fork"));
                }
            }
            cells[key] = next;
        }
    }
    Ok(())
}
async fn project_cell(
    conn: &mut AsyncPgConnection,
    actor: &str,
    key: &str,
    revision: u64,
    content: Value,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<Option<AccountDataRecord>> {
    let current=sql_query("SELECT revision,payload AS content,tombstone FROM account_datas WHERE actor_id=$1 AND account_data_key=$2 AND account_data_source_current(actor_id,account_data_key) FOR UPDATE")
        .bind::<Text,_>(actor).bind::<Text,_>(key).get_result::<Cell>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    let revision_i64 = i64::try_from(revision).map_err(PersistenceError::database)?;
    if let Some(current) = current {
        if current.revision > revision_i64
            || (current.revision == revision_i64
                && (current.tombstone || current.content != content))
        {
            return Err(unavailable(
                "accepted private cell conflicts with the hosting revision",
            ));
        }
        if current.revision == revision_i64 {
            return Ok(None);
        }
    }
    sql_query("INSERT INTO account_datas(id,actor_id,account_data_key,payload,revision,tombstone,updated_at) VALUES($1,$2,$3,$4,$5,FALSE,$6) ON CONFLICT(actor_id,account_data_key) DO UPDATE SET payload=EXCLUDED.payload,revision=EXCLUDED.revision,tombstone=FALSE,updated_at=EXCLUDED.updated_at")
        .bind::<diesel::sql_types::Uuid,_>(uuid::Uuid::now_v7()).bind::<Text,_>(actor).bind::<Text,_>(key).bind::<Jsonb,_>(&content).bind::<BigInt,_>(revision_i64).bind::<Timestamptz,_>(at)
        .execute(&mut *conn).await.map_err(PersistenceError::database)?;
    let position=sql_query("INSERT INTO account_data_changes(actor_id,account_data_key,revision,payload,tombstone,updated_at) VALUES($1,$2,$3,$4,FALSE,$5) RETURNING position")
        .bind::<Text,_>(actor).bind::<Text,_>(key).bind::<BigInt,_>(revision_i64).bind::<Jsonb,_>(&content).bind::<Timestamptz,_>(at).get_result::<Position>(&mut *conn).await.map_err(PersistenceError::database)?;
    sql_query("INSERT INTO account_data_change_retention(actor_id,latest_position,retained_through_position,updated_at) VALUES($1,$2,0,now()) ON CONFLICT(actor_id) DO UPDATE SET latest_position=GREATEST(account_data_change_retention.latest_position,EXCLUDED.latest_position),updated_at=EXCLUDED.updated_at")
        .bind::<Text,_>(actor).bind::<BigInt,_>(position.position).execute(&mut *conn).await.map_err(PersistenceError::database)?;
    Ok(Some(AccountDataRecord {
        actor: actor.to_owned(),
        account_data_key: key.to_owned(),
        revision,
        payload: content,
        tombstone: false,
        updated_at: at,
    }))
}
pub(crate) async fn project(
    pool: &PgPool,
    request: &ConsentPrivateEffectsPublishRequestBody,
    source: &DidCoreId,
    receiver: &DidCoreId,
    authority: &CurrentRealmAuthority,
    known_head: &CommitStreamHead,
) -> PersistenceResult<PrivateEffectsProjection> {
    let now = chrono::Utc::now();
    request
        .validate_for_authority(
            source,
            receiver,
            &authority.realm_id,
            &authority.service_id,
            authority.generation,
            now,
        )
        .map_err(unavailable)?;
    if known_head.stream_ref != request.effective_stream_head.stream_ref
        || known_head.stream_position != request.effective_stream_head.stream_position
        || known_head.commit_id != request.effective_stream_head.commit_id
    {
        return Err(unavailable(
            "publication does not cover the fresh known authority head",
        ));
    }
    let holder =
        serde_json::to_value(&request.holder_account_id).map_err(PersistenceError::database)?;
    let generation =
        i64::try_from(request.governance_generation).map_err(PersistenceError::database)?;
    let position = i64::try_from(request.effective_stream_head.stream_position)
        .map_err(PersistenceError::database)?;
    let digest = request.digest().map_err(unavailable)?;
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_,PgTransactionError,_>(async |conn| {
        crate::pcr_private_authority::require_transferable(conn,&request.realm_id).await?;
        let lock=format!("consent-private-host-cut:{}:{}",request.holder_account_id.principal_id,request.holder_account_id.station_id);
        sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))").bind::<Text,_>(lock).execute(&mut *conn).await?;
        let held=sql_query("SELECT generation,service_id,authority_ref,last_handoff_ref FROM realm_authorities WHERE realm_id=$1 FOR SHARE")
            .bind::<Text,_>(request.realm_id.as_str()).get_result::<Authority>(&mut *conn).await?;
        if held.generation>generation || (held.generation==generation && (held.service_id!=source.as_str() || held.authority_ref!=serde_json::to_value(&authority.authority_ref).map_err(PersistenceError::database)? || held.last_handoff_ref.as_deref()!=authority.last_handoff_ref.as_ref().map(|r|r.as_str()))) {
            return Err(unavailable("known governing authority rejects the verified publication chain").into());
        }
        #[derive(diesel::QueryableByName)] struct Recipient {#[diesel(sql_type=BigInt)] #[diesel(column_name=pk)] _pk:i64}
        let recipient=sql_query("SELECT a.pk FROM accounts a LEFT JOIN account_lifecycle l ON l.account_pk=a.pk WHERE a.principal_id=$1 AND a.station_id=$2 AND a.disabled_at IS NULL AND COALESCE(l.state NOT IN ('deactivated','erasure_pending'),TRUE) FOR SHARE OF a")
            .bind::<Text,_>(request.holder_account_id.principal_id.as_str()).bind::<Text,_>(request.holder_account_id.station_id.as_str()).get_result::<Recipient>(&mut *conn).await.optional()?;
        if recipient.is_none() {return Err(PersistenceError::NotFound("private effect recipient is unavailable".into()).into());}
        if !crate::pcr_private_authority::native_inception(conn,&request.realm_id).await? {return Err(unavailable("target is not an accepted PCR").into());}
        let existing=sql_query("SELECT realm_id,governance_generation,head_stream_position,head_commit_id,cell_revisions FROM consent_private_proxy_cuts WHERE holder_account_id=$1 FOR UPDATE")
            .bind::<Jsonb,_>(&holder).get_result::<Cut>(&mut *conn).await.optional()?;
        let mut cells=existing.as_ref().map_or_else(||json!({}),|row|row.cell_revisions.clone());
        if let Some(existing)=existing
            && (existing.realm_id!=request.realm_id.as_str() || existing.governance_generation>generation || existing.head_stream_position>position || (existing.head_stream_position==position && existing.head_commit_id!=request.effective_stream_head.commit_id.as_str())) {return Err(unavailable("known authority cut rejects rollback or fork").into());}
        #[derive(diesel::QueryableByName)] struct Fence {#[diesel(sql_type=Text)] request_digest:String,#[diesel(sql_type=Jsonb)] outcome:Value}
        let fence=sql_query("SELECT request_digest,outcome FROM consent_private_effect_fences WHERE holder_account_id=$1 AND governance_generation=$2 AND nonce=$3")
            .bind::<Jsonb,_>(&holder).bind::<BigInt,_>(generation).bind::<Text,_>(&request.nonce).get_result::<Fence>(&mut *conn).await.optional()?;
        if let Some(fence)=fence {
            if fence.request_digest!=digest {return Err(unavailable("publication nonce conflicts with its original request").into());}
            return Ok(PrivateEffectsProjection{outcome:serde_json::from_value(fence.outcome).map_err(PersistenceError::database)?,updates:Vec::new()});
        }
        let published=sql_query("SELECT realm_id,governance_generation,head_stream_position,head_commit_id,cell_revisions FROM consent_private_effect_cuts WHERE holder_account_id=$1 FOR UPDATE")
            .bind::<Jsonb,_>(&holder).get_result::<Cut>(&mut *conn).await.optional()?;
        let quarantine=request.effects.holder_quarantine.as_ref().map(|c|->PersistenceResult<_>{Ok((c.revision,serde_json::to_value(&c.content).map_err(PersistenceError::database)?))}).transpose()?;
        let delivery=request.effects.invite_delivery.as_ref().map(|c|->PersistenceResult<_>{Ok((c.revision,serde_json::to_value(&c.content).map_err(PersistenceError::database)?))}).transpose()?;
        let policy=request.effects.invite_receive_policy.as_ref().map(|c|->PersistenceResult<_>{Ok((c.revision,serde_json::to_value(&c.content).map_err(PersistenceError::database)?))}).transpose()?;
        require_cell(&mut cells,"holder_quarantine",quarantine.as_ref().map(|(r,c)|(*r,c)))?;
        require_cell(&mut cells,"invite_delivery",delivery.as_ref().map(|(r,c)|(*r,c)))?;
        require_cell(&mut cells,"invite_receive_policy",policy.as_ref().map(|(r,c)|(*r,c)))?;
        let actor=ActorId::account(request.holder_account_id.clone()).to_string();let mut updates=Vec::new();
        for (key,cell) in [(AccountDataKey::ACCOUNT_HOLDER_QUARANTINE,quarantine),(AccountDataKey::ACCOUNT_INVITE_DELIVERY,delivery)] {
            if let Some((revision,content))=cell {
                let at=content.get("updated_at").cloned().map(serde_json::from_value::<chrono::DateTime<chrono::Utc>>).transpose().map_err(PersistenceError::database)?.unwrap_or(request.evaluated_at);
                let previous_key=if key==AccountDataKey::ACCOUNT_HOLDER_QUARANTINE {"holder_quarantine"} else {"invite_delivery"};
                let published_revision=published.as_ref().and_then(|row|row.cell_revisions.get(previous_key)).and_then(|v|v.get("revision")).and_then(Value::as_u64);
                if let Some(update)=project_cell(conn,&actor,key,revision,content.clone(),at).await? {updates.push(update);} else if published_revision.is_none_or(|old|old<revision) {
                    updates.push(AccountDataRecord{actor:actor.clone(),account_data_key:key.to_owned(),revision,payload:content,tombstone:false,updated_at:at});
                }
            }
        }
        let mut changed=!updates.is_empty();
        if let Some((revision,content))=policy {
            let current=sql_query("SELECT p.revision,p.policy_payload AS content,FALSE AS tombstone FROM invite_receive_policies p JOIN accounts a ON a.pk=p.account_pk WHERE a.principal_id=$1 AND a.station_id=$2 FOR UPDATE OF p")
                .bind::<Text,_>(request.holder_account_id.principal_id.as_str()).bind::<Text,_>(request.holder_account_id.station_id.as_str()).get_result::<Cell>(&mut *conn).await.optional()?;
            let revision=i64::try_from(revision).map_err(PersistenceError::database)?;
            if let Some(current)=&current
                && (current.revision>revision || (current.revision==revision && current.content!=content)) {return Err(unavailable("policy revision rollback or content fork").into());}
            if current.is_none_or(|row|row.revision<revision) {
                let applied=sql_query("INSERT INTO invite_receive_policies(account_pk,revision,policy_payload,updated_at) SELECT pk,$3,$4,$5 FROM accounts WHERE principal_id=$1 AND station_id=$2 ON CONFLICT(account_pk) DO UPDATE SET revision=EXCLUDED.revision,policy_payload=EXCLUDED.policy_payload,updated_at=EXCLUDED.updated_at")
                    .bind::<Text,_>(request.holder_account_id.principal_id.as_str()).bind::<Text,_>(request.holder_account_id.station_id.as_str()).bind::<BigInt,_>(revision).bind::<Jsonb,_>(content).bind::<Timestamptz,_>(request.evaluated_at).execute(&mut *conn).await?;
                if applied!=1 {return Err(unavailable("hosting account is missing").into());}changed=true;
            }
        }
        sql_query("INSERT INTO consent_private_proxy_cuts(holder_account_id,realm_id,governance_generation,head_stream_position,head_commit_id,cell_revisions) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(holder_account_id) DO UPDATE SET realm_id=EXCLUDED.realm_id,governance_generation=EXCLUDED.governance_generation,head_stream_position=EXCLUDED.head_stream_position,head_commit_id=EXCLUDED.head_commit_id,cell_revisions=EXCLUDED.cell_revisions")
            .bind::<Jsonb,_>(&holder).bind::<Text,_>(request.realm_id.as_str()).bind::<BigInt,_>(generation).bind::<BigInt,_>(position).bind::<Text,_>(request.effective_stream_head.commit_id.as_str()).bind::<Jsonb,_>(cells).execute(&mut *conn).await?;
        sql_query("INSERT INTO consent_private_effect_cuts(holder_account_id,realm_id,governance_generation,head_stream_position,head_commit_id,cell_revisions) SELECT holder_account_id,realm_id,governance_generation,head_stream_position,head_commit_id,cell_revisions FROM consent_private_proxy_cuts WHERE holder_account_id=$1 ON CONFLICT(holder_account_id) DO UPDATE SET realm_id=EXCLUDED.realm_id,governance_generation=EXCLUDED.governance_generation,head_stream_position=EXCLUDED.head_stream_position,head_commit_id=EXCLUDED.head_commit_id,cell_revisions=EXCLUDED.cell_revisions")
            .bind::<Jsonb,_>(&holder).execute(&mut *conn).await?;
        let outcome=ConsentPrivateEffectsPublishResponseBody{request_digest:digest.clone(),status:if changed {ConsentPrivateEffectsPublishStatus::Applied}else{ConsentPrivateEffectsPublishStatus::Duplicate}};
        sql_query("DELETE FROM consent_private_effect_fences WHERE holder_account_id=$1 AND expires_at<$2").bind::<Jsonb,_>(&holder).bind::<Timestamptz,_>(now).execute(&mut *conn).await?;
        sql_query("INSERT INTO consent_private_effect_fences(holder_account_id,governance_generation,nonce,expires_at,request_digest,outcome) VALUES($1,$2,$3,$4,$5,$6)")
            .bind::<Jsonb,_>(&holder).bind::<BigInt,_>(generation).bind::<Text,_>(&request.nonce).bind::<Timestamptz,_>(request.expires_at).bind::<Text,_>(&digest).bind::<Jsonb,_>(serde_json::to_value(&outcome).map_err(PersistenceError::database)?).execute(&mut *conn).await?;
        Ok(PrivateEffectsProjection{outcome,updates})
    }).await.map_err(PgTransactionError::into_persistence)
}
