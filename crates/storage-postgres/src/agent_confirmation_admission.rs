//! Immutable controller confirmations, distinct from detached grant votes.
use arkret_models_collaboration::events_payloads::agent::AgentActionApprovePayload;
use arkret_wire::{ActorId, Event, EventKind, RealmCommit};
use coland_storage::{PersistenceError, PersistenceResult};
use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};

#[derive(QueryableByName)]
struct Controller {
    #[diesel(sql_type=Jsonb)]
    controller_actor_id: serde_json::Value,
}
#[derive(QueryableByName)]
struct Confirmation {
    #[diesel(sql_type=Jsonb)]
    value: serde_json::Value,
}
fn invalid(detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!("failed_precondition: {detail}"))
}
fn required() -> PersistenceError {
    PersistenceError::Conflict(
        "approval_required: Agent confirmation is absent or no longer authorizes this exact Event"
            .into(),
    )
}
async fn controller(
    conn: &mut AsyncPgConnection,
    agent: &arkret_wire::DidCoreId,
) -> PersistenceResult<ActorId> {
    let row=sql_query("SELECT r.controller_actor_id FROM agent_principals a JOIN realm_authority_root_current_results r ON r.realm_id=a.principal_control_realm_id JOIN agent_status_current_results s ON s.realm_id=r.realm_id AND s.agent_id=a.id WHERE a.id=$1 AND s.value='\"active\"'::jsonb FOR SHARE OF a,r,s")
        .bind::<Text,_>(agent.as_str()).get_result::<Controller>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(||invalid("Agent controller authority is unavailable at the current PCR cut"))?;
    serde_json::from_value(row.controller_actor_id)
        .map_err(|_| invalid("Agent controller authority is invalid"))
}

pub(crate) async fn admit_confirmation(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
) -> PersistenceResult<()> {
    if event.kind != EventKind::AgentActionApprove {
        return Ok(());
    }
    let payload: AgentActionApprovePayload = serde_json::from_value(
        serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
    )
    .map_err(|e| PersistenceError::SchemaViolation(e.to_string()))?;
    if event.executed_by.is_some() || controller(conn, &payload.agent_id).await? != event.actor_id {
        return Err(invalid(
            "Agent confirmation must be signed by its current exact controller Actor",
        ));
    }
    if !payload.admits_commit_at(commit.committed_at) {
        return Err(invalid(
            "Agent confirmation covering committed_at is after expires_at",
        ));
    }
    crate::realm_authorization_cut::authorize_capability_gated_event_in_connection(
        conn,
        event,
        commit.committed_at,
    )
    .await?;
    Ok(())
}

pub(crate) async fn commit_confirmation(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
) -> PersistenceResult<()> {
    if event.kind != EventKind::AgentActionApprove {
        return Ok(());
    }
    let value = serde_json::to_value(&event.payload).map_err(PersistenceError::database)?;
    let payload: AgentActionApprovePayload = serde_json::from_value(value.clone())
        .map_err(|e| PersistenceError::SchemaViolation(e.to_string()))?;
    let inserted=sql_query("INSERT INTO agent_action_approval_current_results(realm_id,approval_id,controller_actor_key,approval_nonce,approved_event_id,current_event_id,current_commit_id,current_stream_position,value,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT DO NOTHING")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(&payload.approval_id).bind::<Text,_>(event.actor_id.to_string())
        .bind::<Text,_>(&payload.approval_nonce).bind::<Text,_>(payload.approved_event_id.as_str()).bind::<Text,_>(event.event_id.as_str())
        .bind::<Text,_>(commit.commit_id.as_str()).bind::<BigInt,_>(commit.stream_position as i64).bind::<Jsonb,_>(value)
        .bind::<Timestamptz,_>(commit.committed_at).execute(&mut *conn).await.map_err(PersistenceError::database)?;
    if inserted != 1 {
        return Err(invalid(
            "Agent confirmation identifier or controller nonce has already been allocated",
        ));
    }
    Ok(())
}

/// Unwired draft-publication implementation. A caller must first prove the
/// registered draft selection fact; executed_by alone is insufficient. Owner
/// 0228 retains this missing integration and its real conformance verification.
#[allow(dead_code)]
pub(crate) async fn require_publication(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
) -> PersistenceResult<()> {
    let Some(executor) = event
        .executed_by
        .as_ref()
        .filter(|executor| *executor != &event.actor_id)
    else {
        return Ok(());
    };
    let Some(agent) = executor.as_account_id() else {
        return Ok(());
    };
    #[derive(QueryableByName)]
    struct Present {
        #[diesel(sql_type=diesel::sql_types::Bool)]
        present: bool,
    }
    let present = sql_query("SELECT EXISTS(SELECT 1 FROM agent_principals WHERE id=$1) AS present")
        .bind::<Text, _>(agent.principal_id.as_str())
        .get_result::<Present>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    if !present.present {
        return Ok(());
    }
    if controller(conn, &agent.principal_id).await? != event.actor_id {
        return Err(required());
    }
    let rows=sql_query("SELECT a.value FROM agent_action_approval_current_results a JOIN realm_commits c ON c.commit_id=a.current_commit_id AND c.realm_id=a.realm_id AND c.stream_position=a.current_stream_position JOIN canonical_events e ON e.pk=c.event_pk WHERE a.realm_id=$1 AND a.approved_event_id=$2 AND a.controller_actor_key=$3 AND e.state='committed' AND e.envelope->>'kind'='ak.agent.action_approve' FOR SHARE OF a")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(event.event_id.as_str()).bind::<Text,_>(event.actor_id.to_string())
        .load::<Confirmation>(&mut *conn).await.map_err(PersistenceError::database)?;
    for row in rows {
        let payload: AgentActionApprovePayload =
            serde_json::from_value(row.value).map_err(|_| required())?;
        if payload.agent_id != agent.principal_id
            || payload.approved_event_id != event.event_id
            || !payload.admits_commit_at(commit.committed_at)
        {
            continue;
        }
        let action = arkret_wire::CapabilityActionId::from_wire(&payload.proposed_action)
            .ok_or_else(required)?;
        if !arkret_schema::capability_action_descriptor(action)
            .target_event_kinds
            .contains(&event.kind.as_str())
        {
            continue;
        }
        let target = &payload.target;
        let matches = match target.kind.as_str() {
            "realm" => target.realm_id.as_ref() == Some(&event.realm_id),
            "strand" | "space" | "message" | "object" => {
                target.object_ref.as_ref().is_some_and(|expected| {
                    [
                        "strand_id",
                        "space_id",
                        "message_id",
                        "target_ref",
                        "object_ref",
                    ]
                    .iter()
                    .any(|field| {
                        event
                            .payload
                            .get(*field)
                            .and_then(serde_json::Value::as_str)
                            == Some(expected.as_str())
                    })
                })
            }
            _ => false,
        };
        if matches {
            return Ok(());
        }
    }
    Err(required())
}
