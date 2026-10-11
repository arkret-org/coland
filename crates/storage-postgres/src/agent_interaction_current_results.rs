//! Whole-value Agent mode CAS and shared producer gates at the accepting cut.
use arkret_models_collaboration::agent_interaction::{
    AgentInteractionCurrentValue, AgentInteractionMode, AgentInteractionSetPayload,
};
use arkret_wire::{
    AccountId, ActorId, CommitStreamRef, CurrentRevision, Event, EventKind, RealmCommit, RealmId,
    ScopeRef,
};
use coland_storage::{PersistenceError, PersistenceResult};
use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::{Value, json};

#[derive(QueryableByName)]
pub(crate) struct ModeRow {
    #[diesel(sql_type = Text)]
    pub(crate) current_commit_id: String,
    #[diesel(sql_type = BigInt)]
    pub(crate) current_stream_position: i64,
    #[diesel(sql_type = Jsonb)]
    pub(crate) value: Value,
}
#[derive(QueryableByName)]
struct ValueRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}
#[derive(QueryableByName)]
struct PresentRow {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    present: bool,
}
fn denied(detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!("capability_denied: {detail}"))
}
fn precondition(detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!("failed_precondition: {detail}"))
}
fn invalid(error: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::SchemaViolation(error.to_string())
}

/// Current exact ownership and the joined generation that admitted this Agent.
pub(crate) async fn controller_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    agent: &AccountId,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<Option<AccountId>> {
    read_controller_in_connection(conn, realm, agent, at, true).await
}

/// The enclosing repeatable-read transaction fixes this visibility cut.
pub(crate) async fn controller_snapshot_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    agent: &AccountId,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<Option<AccountId>> {
    read_controller_in_connection(conn, realm, agent, at, false).await
}

async fn read_controller_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    agent: &AccountId,
    at: chrono::DateTime<chrono::Utc>,
    lock: bool,
) -> PersistenceResult<Option<AccountId>> {
    let row = sql_query(format!("SELECT e.envelope->'payload'->'agent_controller_binding' AS value FROM member_state_current_results a JOIN realm_commits c ON c.commit_id=a.current_commit_id AND c.stream_position=a.current_stream_position AND c.realm_id=a.realm_id JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' WHERE a.realm_id=$1 AND a.member_id=$2 AND a.membership='join' AND c.stream_ref=jsonb_build_object('kind','realm','realm_id',$1){}", if lock { " FOR SHARE OF a" } else { "" }))
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(ActorId::account(agent.clone()).to_string()).get_result::<ValueRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let Some(controller) = row.value.get("controller_account_id") else {
        return Ok(None);
    };
    let controller: AccountId = serde_json::from_value(controller.clone()).map_err(invalid)?;
    if controller.station_id != agent.station_id
        || row
            .value
            .get("controller_terminal_event_ref")
            .is_some_and(|v| !v.is_null())
    {
        return Ok(None);
    }
    let generation = row
        .value
        .get("controller_membership_generation_ref")
        .and_then(Value::as_str)
        .ok_or_else(|| precondition("Agent membership lacks controller generation"))?;
    let current = sql_query("SELECT EXISTS(SELECT 1 FROM member_state_current_results m JOIN realm_commits c ON c.commit_id=m.current_commit_id AND c.stream_position=m.current_stream_position AND c.realm_id=m.realm_id JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' WHERE m.realm_id=$1 AND m.member_id=$2 AND m.membership='join' AND e.envelope->>'event_id'=$3) AS present")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(ActorId::account(controller.clone()).to_string()).bind::<Text,_>(generation).get_result::<PresentRow>(&mut *conn).await.map_err(PersistenceError::database)?.present;
    if !current {
        return Ok(None);
    }
    let provision = sql_query(format!("SELECT p.value FROM agent_provisioning_current_results p JOIN pcr_genesis_units g ON g.realm_id=p.realm_id WHERE p.agent_id=$1 AND g.principal_id=$2 AND g.station_id=$3{}", if lock { " FOR SHARE OF p" } else { "" }))
        .bind::<Text,_>(agent.principal_id.as_str()).bind::<Text,_>(controller.principal_id.as_str()).bind::<Text,_>(controller.station_id.as_str()).get_result::<ValueRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    let Some(provision) = provision else {
        return Ok(None);
    };
    let provision: arkret_models_collaboration::events_payloads::agent::AgentProvisioningValue =
        serde_json::from_value(provision.value).map_err(invalid)?;
    if provision.controller_principal_id != controller.principal_id {
        return Ok(None);
    }
    if lock {
        crate::agent_current_results::lock_agent_producer_current(
            conn,
            &provision.principal_control_realm_id,
            &agent.principal_id,
        )
        .await?;
    }
    let active = sql_query("SELECT EXISTS(SELECT 1 FROM agent_status_current_results WHERE realm_id=$1 AND agent_id=$2 AND value='\"active\"'::jsonb) AS present")
        .bind::<Text,_>(provision.principal_control_realm_id.as_str()).bind::<Text,_>(agent.principal_id.as_str()).get_result::<PresentRow>(&mut *conn).await.map_err(PersistenceError::database)?.present;
    if !active {
        return Ok(None);
    }
    let rows = sql_query(format!("SELECT value FROM identity_accountability_current_results WHERE subject_id=$1 AND issuer_id=$2 ORDER BY realm_id,scope_set_digest{}", if lock { " FOR SHARE" } else { "" }))
        .bind::<Text,_>(agent.principal_id.as_str()).bind::<Text,_>(controller.principal_id.as_str()).get_results::<ValueRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let mut accountable = false;
    for row in rows {
        let value: arkret_models_collaboration::governance::accountability::AccountabilityProjection = serde_json::from_value(row.value).map_err(invalid)?;
        accountable |= value.verifies_at(at)
            && value
                .accountability_scope
                .scopes()
                .contains(&arkret_wire::AccountabilityScopeKind::AgentOperator);
    }
    Ok(accountable.then_some(controller))
}

pub(crate) async fn read_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    agent: &AccountId,
) -> PersistenceResult<Option<ModeRow>> {
    let key = arkret_wire::derive_agent_interaction_current_key(agent).map_err(invalid)?;
    // A projection cannot establish an already-public transition by itself.
    // Bind the whole value to the last accepted mode Event for this account.
    sql_query("SELECT r.current_commit_id,r.current_stream_position,r.value FROM agent_interaction_current_results r JOIN realm_commits c ON c.realm_id=r.realm_id AND c.commit_id=r.current_commit_id AND c.stream_position=r.current_stream_position JOIN canonical_events e ON e.pk=c.event_pk AND e.realm_id=c.realm_id AND e.state='committed' AND e.kind='ak.agent.interaction.set' WHERE r.realm_id=$1 AND r.current_key=$2 AND r.agent_account_id=$3 AND c.stream_ref=jsonb_build_object('kind','realm','realm_id',$1) AND e.scope_ref=c.stream_ref AND e.envelope->'payload'->'agent_account_id'=$3 AND r.value=jsonb_build_object('controller_account_id',e.envelope->'payload'->'controller_account_id','interaction_mode',e.envelope->'payload'->'interaction_mode') AND NOT EXISTS(SELECT 1 FROM realm_commits newer JOIN canonical_events ne ON ne.pk=newer.event_pk AND ne.realm_id=newer.realm_id AND ne.state='committed' AND ne.kind='ak.agent.interaction.set' WHERE newer.realm_id=$1 AND newer.stream_ref=c.stream_ref AND newer.stream_position>c.stream_position AND ne.envelope->'payload'->'agent_account_id'=$3)")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(key).bind::<Jsonb,_>(json!(agent)).get_result(&mut *conn).await.optional().map_err(PersistenceError::database)
}

pub(crate) async fn known_never_written(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    agent: &AccountId,
    head_position: u64,
) -> PersistenceResult<bool> {
    // A prefix with an unheld genesis or a gap cannot prove absence.
    let complete = sql_query("SELECT (COUNT(DISTINCT stream_position)=$2+1 AND MIN(stream_position)=0 AND MAX(stream_position)=$2) AS present FROM realm_commits WHERE realm_id=$1 AND stream_ref=jsonb_build_object('kind','realm','realm_id',$1)")
        .bind::<Text,_>(realm.as_str()).bind::<BigInt,_>(i64::try_from(head_position).map_err(invalid)?)
        .get_result::<PresentRow>(&mut *conn).await.map_err(PersistenceError::database)?.present;
    if !complete {
        return Ok(false);
    }
    Ok(!sql_query("SELECT EXISTS(SELECT 1 FROM canonical_events WHERE realm_id=$1 AND kind='ak.agent.interaction.set' AND state='committed' AND envelope->'payload'->'agent_account_id'=$2) AS present")
        .bind::<Text,_>(realm.as_str()).bind::<Jsonb,_>(json!(agent)).get_result::<PresentRow>(&mut *conn).await.map_err(PersistenceError::database)?.present)
}

pub(crate) async fn admit_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
) -> PersistenceResult<()> {
    if event.kind != EventKind::AgentInteractionSet {
        return Ok(());
    }
    let payload: AgentInteractionSetPayload =
        serde_json::from_value(json!(&event.payload)).map_err(invalid)?;
    if event.actor_id.as_account_id() != Some(&payload.controller_account_id)
        || event.executed_by.is_some()
        || event.applet_id.is_some()
        || event.producer_proof.is_none()
        || event.scope_ref
            != (ScopeRef::Realm {
                realm_id: event.realm_id.clone(),
            })
        || commit.stream_ref
            != (CommitStreamRef::Realm {
                realm_id: event.realm_id.clone(),
            })
    {
        return Err(denied(
            "Agent mode requires the exact controller device author",
        ));
    }
    crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &event.realm_id).await?;
    if controller_in_connection(
        conn,
        &event.realm_id,
        &payload.agent_account_id,
        commit.committed_at,
    )
    .await?
    .as_ref()
        != Some(&payload.controller_account_id)
    {
        return Err(denied(
            "Agent ownership or member generation is not current",
        ));
    }
    let prior = read_in_connection(conn, &event.realm_id, &payload.agent_account_id).await?;
    if prior.is_none()
        && !known_never_written(
            conn,
            &event.realm_id,
            &payload.agent_account_id,
            commit
                .stream_position
                .checked_sub(1)
                .ok_or_else(|| precondition("Agent mode needs an established Realm prefix"))?,
        )
        .await?
    {
        return Err(PersistenceError::Conflict(
            "revision_unavailable: Agent mode absence is not confirmed".into(),
        ));
    }
    let current = prior
        .as_ref()
        .map(|row| -> PersistenceResult<CurrentRevision> {
            Ok(CurrentRevision {
                commit_id: row.current_commit_id.parse().map_err(invalid)?,
                stream_position: u64::try_from(row.current_stream_position).map_err(invalid)?,
            })
        })
        .transpose()?;
    if current != payload.expected_revision {
        return Err(precondition(
            "Agent mode expected_revision differs from current",
        ));
    }
    if payload.interaction_mode == AgentInteractionMode::Public {
        let already_public = prior
            .as_ref()
            .map(|row| serde_json::from_value::<AgentInteractionCurrentValue>(row.value.clone()))
            .transpose()
            .map_err(invalid)?
            .is_some_and(|value| {
                value.controller_account_id == payload.controller_account_id
                    && value.interaction_mode == AgentInteractionMode::Public
            });
        if !already_public {
            crate::agent_management_admission::require_publish_in_connection(
                conn,
                &event.realm_id,
                &payload.controller_account_id,
                &payload.agent_account_id,
                commit.committed_at,
            )
            .await?;
        }
    }
    Ok(())
}

/// Install only a committed value; shared by authority writes and verified replicas.
pub(crate) async fn install_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    agent: &AccountId,
    revision: &CurrentRevision,
    value: &AgentInteractionCurrentValue,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    let key = arkret_wire::derive_agent_interaction_current_key(agent).map_err(invalid)?;
    sql_query("INSERT INTO agent_interaction_current_results (realm_id,current_key,agent_account_id,current_commit_id,current_stream_position,value,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(realm_id,current_key) DO UPDATE SET current_commit_id=EXCLUDED.current_commit_id,current_stream_position=EXCLUDED.current_stream_position,value=EXCLUDED.value,updated_at=EXCLUDED.updated_at")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(key).bind::<Jsonb,_>(json!(agent)).bind::<Text,_>(revision.commit_id.as_str()).bind::<BigInt,_>(i64::try_from(revision.stream_position).map_err(invalid)?).bind::<Jsonb,_>(json!(value)).bind::<Timestamptz,_>(at).execute(&mut *conn).await.map_err(PersistenceError::database)?;
    Ok(())
}
pub(crate) async fn project_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
) -> PersistenceResult<()> {
    if event.kind != EventKind::AgentInteractionSet {
        return Ok(());
    }
    let payload: AgentInteractionSetPayload =
        serde_json::from_value(json!(&event.payload)).map_err(invalid)?;
    install_in_connection(
        conn,
        &event.realm_id,
        &payload.agent_account_id,
        &CurrentRevision {
            commit_id: commit.commit_id.clone(),
            stream_position: commit.stream_position,
        },
        &AgentInteractionCurrentValue {
            controller_account_id: payload.controller_account_id,
            interaction_mode: payload.interaction_mode,
        },
        commit.committed_at,
    )
    .await
}

/// Public mode is necessary on ordinary shared writes, including delegated writers.
pub(crate) async fn require_shared_producer_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
) -> PersistenceResult<()> {
    if !matches!(
        event.scope_ref,
        ScopeRef::Realm { .. } | ScopeRef::Circle { .. }
    ) {
        return Ok(());
    }
    if matches!(event.kind, EventKind::MlsGenesis | EventKind::MlsCommit)
        || (matches!(
            event.kind,
            EventKind::StrandWatchSet | EventKind::ReadCursorAdvance
        ) && event.executed_by.is_none())
    {
        return Ok(());
    }
    if event.kind == EventKind::MemberState
        && event.executed_by.is_none()
        && serde_json::to_value(&event.payload)
            .ok()
            .and_then(|p| p.get("member_id").cloned())
            == Some(json!(event.actor_id))
    {
        return Ok(());
    }
    crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &event.realm_id).await?;
    // PCR governance is independent of collaboration mode.
    let governance = sql_query("SELECT EXISTS(SELECT 1 FROM realm_bootstrap_current_results WHERE realm_id=$1 AND result_family='realm_genesis' AND value->>'purpose' IN ('principal_control','agent_control')) AS present")
        .bind::<Text,_>(event.realm_id.as_str()).get_result::<PresentRow>(&mut *conn).await.map_err(PersistenceError::database)?.present;
    if governance {
        return Ok(());
    }
    for actor in std::iter::once(&event.actor_id).chain(event.executed_by.iter()) {
        let Some(agent) = actor.as_account_id() else {
            continue;
        };
        let is_agent =
            sql_query("SELECT (EXISTS(SELECT 1 FROM agent_principals WHERE id=$1) OR EXISTS(SELECT 1 FROM member_state_current_results m JOIN realm_commits c ON c.commit_id=m.current_commit_id JOIN canonical_events e ON e.pk=c.event_pk WHERE m.realm_id=$2 AND m.member_id=$3 AND e.envelope->'payload' ? 'agent_controller_binding')) AS present")
                .bind::<Text, _>(agent.principal_id.as_str())
                .bind::<Text, _>(event.realm_id.as_str())
                .bind::<Text, _>(actor.to_string())
                .get_result::<PresentRow>(&mut *conn)
                .await
                .map_err(PersistenceError::database)?
                .present;
        if !is_agent {
            continue;
        }
        // An independent owner Direct remains private and does not read group mode.
        let direct = sql_query("SELECT value FROM direct_conversation_binding_current_results WHERE realm_id=$1 FOR SHARE")
            .bind::<Text,_>(event.realm_id.as_str()).get_result::<ValueRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
        if let Some(direct) = direct {
            let value: arkret_models_collaboration::events_payloads::direct_conversation::DirectConversationBindingCurrentValue = serde_json::from_value(direct.value).map_err(invalid)?;
            value.binding_digest().map_err(invalid)?;
            if value.endorsements.as_slice().first().is_some_and(|entry| entry.value.unordered_participant_ids.iter().any(|a| a.as_account_id() == Some(agent)) && entry.value.authorization_basis.kind == arkret_models_collaboration::objects::direct_conversation::DirectConversationAuthorizationKind::AgentController) { continue; }
        }
        let Some(controller) =
            controller_in_connection(conn, &event.realm_id, agent, commit.committed_at).await?
        else {
            return Err(denied("shared Agent authority is unavailable"));
        };
        let Some(row) = read_in_connection(conn, &event.realm_id, agent).await? else {
            return Err(denied("shared Agent authority is unavailable"));
        };
        let value: AgentInteractionCurrentValue =
            serde_json::from_value(row.value).map_err(invalid)?;
        if value.controller_account_id != controller
            || value.interaction_mode != AgentInteractionMode::Public
        {
            return Err(denied("shared Agent authority is unavailable"));
        }
    }
    Ok(())
}

/// Read the agreed owner Direct binding without consulting group mode.
pub(crate) async fn owner_direct_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    agent: &AccountId,
    controller: &AccountId,
) -> PersistenceResult<bool> {
    let row = sql_query(
        "SELECT value FROM direct_conversation_binding_current_results WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm.as_str())
    .get_result::<ValueRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    let Some(row) = row else {
        return Ok(false);
    };
    let value: arkret_models_collaboration::events_payloads::direct_conversation::DirectConversationBindingCurrentValue = serde_json::from_value(row.value).map_err(invalid)?;
    value.binding_digest().map_err(invalid)?;
    Ok(value.endorsements.as_slice().first().is_some_and(|entry| {
        entry.value.authorization_basis.kind == arkret_models_collaboration::objects::direct_conversation::DirectConversationAuthorizationKind::AgentController
        && entry.value.unordered_participant_ids.len() == 2
        && entry.value.unordered_participant_ids.contains(&ActorId::account(agent.clone()))
        && entry.value.unordered_participant_ids.contains(&ActorId::account(controller.clone()))
    }))
}
