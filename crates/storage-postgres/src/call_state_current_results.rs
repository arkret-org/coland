//! Call genesis admission and registered current at the accepting Commit cut.
use arkret_models_collaboration::events_payloads::call::{
    CallCreatePayload, CallStateCurrentValue,
};
use arkret_wire::{CallId, CommitStreamRef, Event, EventKind, RealmCommit, ScopeRef};
use coland_storage::{ConflictCode, PersistenceError, PersistenceResult};
use diesel::sql_query;
use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel_async::{AsyncPgConnection, RunQueryDsl};

fn invalid(detail: &str) -> PersistenceError {
    PersistenceError::SchemaViolation(detail.to_owned())
}

pub(crate) async fn commit_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
) -> PersistenceResult<()> {
    if event.kind != EventKind::CallCreate {
        return Ok(());
    }
    if !matches!(
        event.scope_ref,
        ScopeRef::Realm { .. } | ScopeRef::Circle { .. }
    ) || event.scope_ref.realm_id() != &event.realm_id
        || commit.realm_id != event.realm_id
        || commit.event_ref != event.event_id
        || commit.stream_ref
            != CommitStreamRef::from_scope(&event.scope_ref, None)
                .map_err(|_| invalid("Call create requires an exact ordinary scope stream"))?
    {
        return Err(invalid("Call create Event and Commit scope differ"));
    }
    let payload: CallCreatePayload = serde_json::from_value(serde_json::json!(&event.payload))
        .map_err(|_| invalid("Call create payload is invalid"))?;
    payload.validate().map_err(|_| {
        PersistenceError::Conflict(format!(
            "{}: Call genesis initial_state is not an initial lifecycle state",
            ConflictCode::CallStateTransitionInvalid
        ))
    })?;
    crate::realm_authorization_cut::authorize_capability_gated_event_in_connection(
        conn,
        event,
        commit.committed_at,
    )
    .await?;
    if !crate::moderation_report_current_results::scope_member_in_connection(
        conn,
        &event.realm_id,
        &event.scope_ref,
        &event.actor_id,
    )
    .await?
    {
        return Err(PersistenceError::Conflict(
            "capability_denied: Call creator lacks exact scope membership".to_owned(),
        ));
    }
    let call_id = CallId::from_event_id(&event.event_id);
    let value = serde_json::to_value(CallStateCurrentValue {
        from: None,
        to: payload.initial_state,
        failure_reason_code: None,
    })
    .map_err(PersistenceError::database)?;
    let stream = serde_json::to_value(&commit.stream_ref).map_err(PersistenceError::database)?;
    let position = i64::try_from(commit.stream_position)
        .map_err(|_| invalid("invalid Call stream position"))?;
    // Exact Event replays are handled before this writer by the authority UoW.
    // A duplicate genesis here must never overwrite a current Call state.
    sql_query("INSERT INTO call_state_current_results (realm_id,call_id,create_event_id,source_stream_ref,current_commit_id,current_stream_position,value,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(call_id.as_str())
        .bind::<Text,_>(event.event_id.as_str()).bind::<Jsonb,_>(&stream)
        .bind::<Text,_>(commit.commit_id.as_str()).bind::<BigInt,_>(position)
        .bind::<Jsonb,_>(&value).bind::<Timestamptz,_>(commit.committed_at)
        .execute(conn).await.map_err(PersistenceError::database)?;
    Ok(())
}
