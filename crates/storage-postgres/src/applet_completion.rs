//! Original Realm creation tasks and current-governor material for retry delivery.
use arkret_models_integration::{AppletManagedActorAuthoringContext, RealmActorMaterialRequest};
use arkret_wire::{CommittedEventRef, DidCoreId, Event, Hash, RealmCommit};
use coland_storage::{
    AppletAuthoringCompletion, PersistenceError, PersistenceResult, RealmActorMaterialCaller,
    RealmActorMaterialSigner,
};
use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel::{QueryableByName, sql_query};
use diesel_async::AsyncPgConnection;
use horme::{OptionalExtension as _, RunQueryDsl};
use serde_json::{Value, json};

#[derive(QueryableByName)]
struct Row {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}
fn unavailable(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("temporarily_unavailable: {detail}"))
}
const FIELDS: &str = "jsonb_build_object('applet_id',applet_id,'realm_id',realm_id,'actor_id',actor_id,'creation_ref',creation_ref,'request_digest',request_digest,'source_id',source_id,'destination_id',destination_id,'endpoint',endpoint,'idempotency_key',idempotency_key,'context',context,'delivery_key_digest',delivery_key_digest)";
fn decode(row: Row) -> PersistenceResult<AppletAuthoringCompletion> {
    serde_json::from_value(row.value).map_err(PersistenceError::database)
}

pub(crate) async fn retain(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
    digest: &Hash,
    governor: &DidCoreId,
) -> PersistenceResult<()> {
    let creation = crate::realm_actor_control::creation(event)?
        .ok_or_else(|| unavailable("completion requires original creation"))?;
    let registration = crate::managed_message_actor::registration(conn, event).await?;
    let reference = CommittedEventRef {
        event_id: event.event_id.clone(),
        commit_id: commit.commit_id.clone(),
        stream_ref: commit.stream_ref.clone(),
        stream_position: commit.stream_position,
    };
    let inserted = sql_query("INSERT INTO applet_authoring_completions(applet_id,realm_id,actor_id,creation_ref,request_digest,source_id,destination_id,endpoint,idempotency_key,context,accepted_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,NULL,$10) ON CONFLICT DO NOTHING")
        .bind::<Text,_>(creation.applet_id.as_str()).bind::<Text,_>(event.realm_id.as_str())
        .bind::<Jsonb,_>(json!(creation.actor_id)).bind::<Jsonb,_>(json!(reference)).bind::<Text,_>(digest.as_str())
        .bind::<Text,_>(governor.as_str()).bind::<Text,_>(creation.service_id.as_str())
        .bind::<Text,_>(&registration.base_url).bind::<Text,_>(format!("creation:{}",event.event_id))
        .bind::<Timestamptz,_>(commit.committed_at).execute(&mut *conn).await.map_err(PersistenceError::database)?;
    if inserted != 1 {
        return Err(unavailable("creation completion identity already exists"));
    }
    Ok(())
}

pub(crate) async fn pending(
    conn: &mut AsyncPgConnection,
    limit: u32,
) -> PersistenceResult<Vec<AppletAuthoringCompletion>> {
    sql_query(format!("SELECT {FIELDS} AS value FROM applet_authoring_completions c WHERE delivered_at IS NULL AND (next_attempt_at IS NULL OR next_attempt_at<=clock_timestamp()) AND EXISTS(SELECT 1 FROM realm_authorities a WHERE a.realm_id=c.realm_id AND a.service_id=current_device_inventory_station()) AND EXISTS(SELECT 1 FROM realm_actor_current_results m WHERE m.realm_id=c.realm_id AND m.selector=jsonb_build_object('kind','realm_actor_manager','actor_id',c.actor_id) AND m.value->>'service_id'=c.destination_id) AND NOT EXISTS(SELECT 1 FROM realm_authorities a JOIN realm_commits rc ON rc.realm_id=a.realm_id AND rc.governance_generation=a.generation JOIN canonical_events e ON e.pk=rc.event_pk WHERE a.realm_id=c.realm_id AND e.kind='ak.realm.governance_station.change') ORDER BY next_attempt_at NULLS FIRST,accepted_at,applet_id,request_digest LIMIT $1"))
        .bind::<BigInt,_>(i64::from(limit.min(128))).load::<Row>(conn).await.map_err(PersistenceError::database)?
        .into_iter().map(decode).collect()
}

pub(crate) async fn prepare(
    conn: &mut AsyncPgConnection,
    expected: &AppletAuthoringCompletion,
    governor: &DidCoreId,
    delivery_key_digest: &Hash,
    sign: RealmActorMaterialSigner<'_>,
) -> PersistenceResult<AppletAuthoringCompletion> {
    crate::realm_actor_control::require_current_governor(conn, &expected.realm_id, governor)
        .await?;
    crate::realm_management_archive::require_unfrozen(conn, &expected.realm_id).await?;
    let row = sql_query(format!("SELECT {FIELDS} AS value FROM applet_authoring_completions WHERE applet_id=$1 AND request_digest=$2 AND delivered_at IS NULL FOR UPDATE"))
        .bind::<Text,_>(expected.applet_id.as_str()).bind::<Text,_>(expected.request_digest.as_str())
        .get_result::<Row>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(|| unavailable("creation completion is no longer pending"))?;
    let mut completion = decode(row)?;
    if completion.realm_id != expected.realm_id
        || completion.actor_id != expected.actor_id
        || completion.creation_ref != expected.creation_ref
        || completion.destination_id != expected.destination_id
    {
        return Err(unavailable("creation completion original changed"));
    }
    let request = RealmActorMaterialRequest::Event {
        actor_id: completion.actor_id.clone(),
        request_nonce: arkret_canonical::base64url_encode(rand::random::<[u8; 32]>()),
        target: completion.creation_ref.clone(),
    };
    let caller = RealmActorMaterialCaller::CreationCompletion {
        applet_id: completion.applet_id.clone(),
        request_digest: completion.request_digest.clone(),
        creation_ref: completion.creation_ref.clone(),
        service_id: completion.destination_id.clone(),
    };
    // Reprove the original and today's exact manager even for a cached body.
    let current =
        crate::realm_actor_material::read(conn, &request, &caller, governor, sign).await?;
    if let Some(context) = &completion.context {
        context.validate().map_err(unavailable)?;
        if context.material.actor_id != completion.actor_id
            || context.material.realm_id != completion.realm_id
            || context.material.requester_actor_id
                != arkret_wire::ActorId::service(completion.destination_id.clone())
            || json!(context.material.result) != json!(current.result)
        {
            return Err(unavailable(
                "cached completion differs from its original creation",
            ));
        }
    }
    sql_query("UPDATE applet_authoring_completions SET next_attempt_at=clock_timestamp()+INTERVAL '1 second' WHERE applet_id=$1 AND request_digest=$2 AND delivered_at IS NULL")
        .bind::<Text,_>(completion.applet_id.as_str()).bind::<Text,_>(completion.request_digest.as_str())
        .execute(&mut *conn).await.map_err(PersistenceError::database)?;
    let at = chrono::Utc::now();
    if completion.source_id == *governor
        && completion.delivery_key_digest.as_ref() == Some(delivery_key_digest)
        && completion.context.as_ref().is_some_and(|context| {
            context.material.expires_at > at + chrono::Duration::seconds(5)
                && context.material.governance_generation == current.governance_generation
                && context.material.authority_ref == current.authority_ref
        })
    {
        return Ok(completion);
    }
    completion.source_id = governor.clone();
    completion.delivery_key_digest = Some(delivery_key_digest.clone());
    completion.context = Some(AppletManagedActorAuthoringContext { material: current });
    completion.idempotency_key = arkret_canonical::canonical_sha256(&json!({
        "applet_id":completion.applet_id,"source_id":completion.source_id,"context":completion.context,
    })).map_err(unavailable)?;
    sql_query("UPDATE applet_authoring_completions SET source_id=$3,idempotency_key=$4,context=$5,delivery_key_digest=$6 WHERE applet_id=$1 AND request_digest=$2 AND delivered_at IS NULL")
        .bind::<Text,_>(completion.applet_id.as_str()).bind::<Text,_>(completion.request_digest.as_str())
        .bind::<Text,_>(completion.source_id.as_str()).bind::<Text,_>(&completion.idempotency_key)
        .bind::<Jsonb,_>(json!(completion.context)).bind::<Text,_>(delivery_key_digest.as_str()).execute(&mut *conn).await.map_err(PersistenceError::database)?;
    Ok(completion)
}

pub(crate) async fn acknowledge(
    conn: &mut AsyncPgConnection,
    applet: &arkret_wire::AppletId,
    digest: &Hash,
    idempotency_key: &str,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    let row = sql_query(format!("SELECT {FIELDS} AS value FROM applet_authoring_completions WHERE applet_id=$1 AND request_digest=$2"))
        .bind::<Text,_>(applet.as_str()).bind::<Text,_>(digest.as_str())
        .get_result::<Row>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(|| PersistenceError::NotFound("accepted creation completion is absent".into()))?;
    let completion = decode(row)?;
    crate::realm_actor_control::require_current_governor(
        conn,
        &completion.realm_id,
        &completion.source_id,
    )
    .await?;
    crate::realm_management_archive::require_unfrozen(conn, &completion.realm_id).await?;
    let (manager, _) = crate::realm_actor_control::current_source(
        conn,
        &completion.actor_id,
        serde_json::to_value(arkret_wire::CurrentSelector::RealmActorManager {
            actor_id: completion.actor_id.clone(),
        })
        .map_err(PersistenceError::database)?,
    )
    .await?;
    if manager["service_id"] != json!(completion.destination_id) {
        return Err(PersistenceError::NotFound(
            "creation completion manager no longer qualified".into(),
        ));
    }
    let updated = sql_query("UPDATE applet_authoring_completions SET delivered_at=COALESCE(delivered_at,$3) WHERE applet_id=$1 AND request_digest=$2 AND idempotency_key=$4")
        .bind::<Text,_>(applet.as_str()).bind::<Text,_>(digest.as_str())
        .bind::<Timestamptz,_>(at).bind::<Text,_>(idempotency_key).execute(&mut *conn).await.map_err(PersistenceError::database)?;
    if updated != 1 {
        return Err(PersistenceError::Conflict(
            "failed_precondition: creation completion delivery key changed".into(),
        ));
    }
    Ok(())
}
