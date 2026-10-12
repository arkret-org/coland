//! Controller selection and target ceilings at the Event transaction cut.

use arkret_models_collaboration::governance::agent_participation::{
    AgentParticipationEntry, AgentParticipationPolicy, ParticipationBits,
};
use arkret_wire::{DidCoreId, Event, EventKind, RealmCommit};
use coland_storage::{PersistenceError, PersistenceResult};
use diesel::sql_types::{Array, Jsonb, Text};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::Value;

#[derive(QueryableByName)]
struct ValueRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

fn unresolved() -> PersistenceError {
    PersistenceError::Conflict(format!(
        "failed_precondition: {}",
        arkret_wire::ReasonCode::AGENT_PARTICIPATION_CEILING_UNRESOLVED
    ))
}

/// Selection replacement uses the exclusive form of this same per-Agent lock.
/// It also serializes inserting a more specific selection, including no-row
/// reads, which an ordinary row lock cannot protect.
pub(crate) async fn lock_selection(
    conn: &mut AsyncPgConnection,
    agent: &str,
    shared: bool,
) -> PersistenceResult<()> {
    let query = if shared {
        "SELECT pg_advisory_xact_lock_shared(hashtextextended($1, 0))"
    } else {
        "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))"
    };
    sql_query(query)
        .bind::<Text, _>(format!("agent-participation-current:{agent}"))
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    Ok(())
}

pub(crate) async fn require_current(
    conn: &mut AsyncPgConnection,
    event: &Event,
    _commit: &RealmCommit,
    target_station: &DidCoreId,
    deployment: ParticipationBits,
) -> PersistenceResult<()> {
    let mode = if event.executed_by.is_some() {
        "act_on_behalf"
    } else {
        match event.kind {
            EventKind::MessageCreate => "reply_message",
            EventKind::ReactionAdd => "reaction_add",
            EventKind::ReactionRemove => "reaction_remove",
            _ => return Ok(()),
        }
    };
    if event
        .human_device_producer()
        .map_err(|e| PersistenceError::SchemaViolation(e.to_string()))?
        .is_some()
    {
        return Ok(());
    }
    let Some(agent) = event.actual_signer().as_account_id() else {
        return Ok(());
    };
    if &agent.station_id != target_station {
        return Err(unresolved());
    }
    require_owner_current(conn, agent).await?;
    lock_selection(conn, agent.principal_id.as_str(), true).await?;

    let mut scopes = vec![format!("realm:{}", event.realm_id)];
    if let arkret_wire::ScopeRef::Circle { circle_id, .. } = &event.scope_ref {
        scopes.push(format!("circle:{}:{circle_id}", event.realm_id));
    }
    let message_id = match event.kind {
        EventKind::ReactionAdd | EventKind::ReactionRemove => {
            let payload: arkret_models_collaboration::events_payloads::reaction::ReactionPayload =
                serde_json::from_value(serde_json::json!(event.payload))
                    .map_err(|e| PersistenceError::SchemaViolation(e.to_string()))?;
            Some(
                arkret_wire::MessageId::new(payload.target_ref.as_str())
                    .map_err(|e| PersistenceError::SchemaViolation(e.to_string()))?,
            )
        }
        EventKind::MessageRevise | EventKind::MessageRedact => Some(
            arkret_wire::MessageId::new(
                event
                    .payload
                    .get("message_id")
                    .and_then(Value::as_str)
                    .ok_or_else(unresolved)?,
            )
            .map_err(|e| PersistenceError::SchemaViolation(e.to_string()))?,
        ),
        EventKind::PinAdd | EventKind::PinRemove => event
            .payload
            .get("target_ref")
            .and_then(Value::as_str)
            .and_then(|id| arkret_wire::MessageId::new(id).ok()),
        _ => None,
    };
    let strand_id = if let Some(message) = message_id {
        let target = crate::message_revision_current_results::locked_message_target(
            conn,
            &event.realm_id,
            &message,
        )
        .await
        .map_err(|error| match error {
            PersistenceError::NotFound(_) => PersistenceError::Conflict(
                "dependency_missing: the Message target is not materialized".into(),
            ),
            other => other,
        })?;
        if target.scope_ref != event.scope_ref {
            return Err(PersistenceError::Conflict(
                "failed_precondition: the Message target is outside the signed scope".into(),
            ));
        }
        Some(target.strand_id.to_string())
    } else {
        event
            .payload
            .get("strand_id")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| {
                event
                    .payload
                    .get("target_ref")
                    .and_then(Value::as_str)
                    .filter(|id| arkret_wire::StrandId::new(*id).is_ok())
                    .map(str::to_owned)
            })
    };
    if let Some(strand) = strand_id.as_deref() {
        let row = sql_query("SELECT s.value FROM strand_current_results s JOIN realm_commits c ON c.commit_id=s.current_commit_id AND c.realm_id=s.realm_id AND c.stream_position=s.current_stream_position WHERE s.realm_id=$1 AND s.strand_id=$2 FOR SHARE OF s")
            .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(strand)
            .get_result::<ValueRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?.ok_or_else(unresolved)?;
        if let Some(circle) = row.value.get("scope_circle_id").and_then(Value::as_str) {
            let key = format!("circle:{}:{circle}", event.realm_id);
            if !scopes.contains(&key) {
                scopes.push(key);
            }
        }
        scopes.push(format!("strand:{}:{strand}", event.realm_id));
    }
    let selections = sql_query("SELECT jsonb_build_object('target_scope',scope,'selection',jsonb_build_object('reply_message',reply_message,'reaction_add',reaction_add,'reaction_remove',reaction_remove,'accept_third_party_mention',accept_third_party_mention,'act_on_behalf',act_on_behalf),'version',version,'next_replace_input',jsonb_build_object('expected_version',version)) AS value FROM agent_participation WHERE agent_id=$1 AND scope_key=ANY($2) FOR SHARE")
        .bind::<Text,_>(agent.principal_id.as_str()).bind::<Array<Text>,_>(&scopes)
        .load::<ValueRow>(&mut *conn).await.map_err(PersistenceError::database)?
        .into_iter().map(|row| serde_json::from_value::<AgentParticipationEntry>(row.value).map_err(|_| unresolved()))
        .collect::<PersistenceResult<Vec<_>>>()?;
    let selected = scopes
        .iter()
        .rev()
        .find_map(|key| {
            selections
                .iter()
                .find(|entry| entry.scope.scope_key() == *key)
        })
        .ok_or_else(unresolved)?;
    let mut effective = deployment.intersect(selected.selection);
    for scope in &scopes {
        if let Some(ceiling) = governance_component(conn, event.realm_id.as_str(), scope).await? {
            effective = effective.intersect(ceiling);
        }
    }
    let allowed = match mode {
        "reply_message" => effective.reply_message,
        "reaction_add" => effective.reaction_add,
        "reaction_remove" => effective.reaction_remove,
        _ => effective.act_on_behalf,
    };
    if !allowed {
        return Err(PersistenceError::Conflict(format!(
            "failed_precondition: {}",
            match mode {
                "reply_message" => "agent_reply_not_permitted",
                "reaction_add" => "agent_reaction_add_not_permitted",
                "reaction_remove" => "agent_reaction_remove_not_permitted",
                _ => "agent_act_on_behalf_not_permitted",
            }
        )));
    }
    Ok(())
}

/// Fixed native reply preparation reads the same durable controller selection
/// and all ancestor ceilings without constructing a signed Message Event.
pub(crate) async fn require_native_reply_current(
    conn: &mut AsyncPgConnection,
    agent: &arkret_wire::AccountId,
    scope: &arkret_wire::ScopeRef,
    strand: &arkret_wire::StrandId,
    target_station: &DidCoreId,
    deployment: ParticipationBits,
) -> PersistenceResult<()> {
    if &agent.station_id != target_station {
        return Err(unresolved());
    }
    let realm = scope.realm_id_opt().ok_or_else(unresolved)?;
    require_owner_current(conn, agent).await?;
    lock_selection(conn, agent.principal_id.as_str(), true).await?;
    let mut scopes = vec![format!("realm:{realm}")];
    match scope {
        arkret_wire::ScopeRef::Realm { .. } => {}
        arkret_wire::ScopeRef::Circle { circle_id, .. } => {
            scopes.push(format!("circle:{realm}:{circle_id}"))
        }
        _ => return Err(unresolved()),
    }
    scopes.push(format!("strand:{realm}:{strand}"));
    let rows = sql_query("SELECT jsonb_build_object('target_scope',scope,'selection',jsonb_build_object('reply_message',reply_message,'reaction_add',reaction_add,'reaction_remove',reaction_remove,'accept_third_party_mention',accept_third_party_mention,'act_on_behalf',act_on_behalf),'version',version,'next_replace_input',jsonb_build_object('expected_version',version)) AS value FROM agent_participation WHERE agent_id=$1 AND scope_key=ANY($2) FOR SHARE")
        .bind::<Text,_>(agent.principal_id.as_str()).bind::<Array<Text>,_>(&scopes)
        .load::<ValueRow>(&mut *conn).await.map_err(PersistenceError::database)?
        .into_iter().map(|row| serde_json::from_value::<AgentParticipationEntry>(row.value).map_err(|_| unresolved()))
        .collect::<PersistenceResult<Vec<_>>>()?;
    let selected = scopes
        .iter()
        .rev()
        .find_map(|key| rows.iter().find(|entry| entry.scope.scope_key() == *key))
        .ok_or_else(unresolved)?;
    let mut effective = deployment.intersect(selected.selection);
    for scope in &scopes {
        if let Some(ceiling) = governance_component(conn, realm.as_str(), scope).await? {
            effective = effective.intersect(ceiling);
        }
    }
    if !effective.reply_message || !effective.accept_third_party_mention {
        return Err(unresolved());
    }
    Ok(())
}

/// Participation ownership comes from the owning Station's accepted provision
/// and Agent PCR, including private targets without shared Realm membership.
/// Shared membership and controller generation remain independent mode gates.
async fn require_owner_current(
    conn: &mut AsyncPgConnection,
    agent: &arkret_wire::AccountId,
) -> PersistenceResult<()> {
    let row = sql_query("SELECT p.value FROM agent_provisioning_current_results p JOIN pcr_genesis_units g ON g.realm_id=p.realm_id JOIN realm_commits c ON c.commit_id=p.current_commit_id AND c.realm_id=p.realm_id AND c.stream_position=p.current_stream_position WHERE p.agent_id=$1 AND g.station_id=$2 AND p.value->>'controller_principal_id'=g.principal_id FOR SHARE OF p")
        .bind::<Text,_>(agent.principal_id.as_str()).bind::<Text,_>(agent.station_id.as_str())
        .get_result::<ValueRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?.ok_or_else(unresolved)?;
    let provision: arkret_models_collaboration::events_payloads::agent::AgentProvisioningValue =
        serde_json::from_value(row.value).map_err(|_| unresolved())?;
    crate::agent_current_results::lock_agent_producer_current(
        conn,
        &provision.principal_control_realm_id,
        &agent.principal_id,
    )
    .await?;
    let row = sql_query("SELECT s.value FROM agent_status_current_results s JOIN realm_commits c ON c.commit_id=s.current_commit_id AND c.realm_id=s.realm_id AND c.stream_position=s.current_stream_position JOIN principal_resolutions r ON r.pcr_realm_id=s.realm_id AND r.principal_id=s.agent_id WHERE s.realm_id=$1 AND s.agent_id=$2 AND r.station_id=$3 FOR SHARE OF s")
        .bind::<Text,_>(provision.principal_control_realm_id.as_str()).bind::<Text,_>(agent.principal_id.as_str()).bind::<Text,_>(agent.station_id.as_str())
        .get_result::<ValueRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?.ok_or_else(unresolved)?;
    if row.value != Value::String("active".into()) {
        return Err(unresolved());
    }
    Ok(())
}

/// A present accepted current with an omitted component inherits its parent.
/// A Direct Conversation has a fixed genesis baseline and no policy-bundle
/// Event. Its accepted founding unit establishes an inherited Realm component.
/// Missing current, broken Commit coordinates and malformed declarations fail.
pub(crate) async fn governance_component(
    conn: &mut AsyncPgConnection,
    realm: &str,
    scope: &str,
) -> PersistenceResult<Option<ParticipationBits>> {
    let query = if scope.starts_with("realm:") {
        "SELECT s.value FROM realm_policy_bundle_current_results s JOIN realm_commits c ON c.commit_id=s.current_commit_id AND c.realm_id=s.realm_id AND c.stream_position=s.current_stream_position WHERE s.realm_id=$1 AND 'realm:'||s.realm_id=$2 FOR SHARE OF s"
    } else if scope.starts_with("circle:") {
        "SELECT s.value FROM circle_current_results s JOIN realm_commits c ON c.commit_id=s.current_commit_id AND c.realm_id=s.realm_id AND c.stream_position=s.current_stream_position WHERE s.realm_id=$1 AND 'circle:'||s.realm_id||':'||s.circle_id=$2 FOR SHARE OF s"
    } else if scope.starts_with("strand:") {
        "SELECT s.value FROM strand_current_results s JOIN realm_commits c ON c.commit_id=s.current_commit_id AND c.realm_id=s.realm_id AND c.stream_position=s.current_stream_position WHERE s.realm_id=$1 AND 'strand:'||s.realm_id||':'||s.strand_id=$2 FOR SHARE OF s"
    } else {
        return Err(unresolved());
    };
    let row = sql_query(query)
        .bind::<Text, _>(realm)
        .bind::<Text, _>(scope)
        .get_result::<ValueRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
    if let Some(row) = row {
        return component(&row.value);
    }
    if scope != format!("realm:{realm}") {
        return Err(unresolved());
    }
    // The source is the accepted profile-fixed genesis, not a guessed default
    // for a missing ordinary policy bundle. Require the exact four-Commit unit
    // and the genesis current's covering Commit before interpreting omission.
    let row = sql_query(
        "SELECT s.value FROM realm_bootstrap_current_results s \
         JOIN realm_commits c ON c.commit_id=s.current_commit_id \
           AND c.realm_id=s.realm_id AND c.stream_position=s.current_stream_position \
         JOIN direct_conversation_founding_slots f ON f.realm_id=s.realm_id \
         WHERE s.realm_id=$1 AND s.result_family='realm_genesis' \
           AND c.stream_position=0 AND jsonb_array_length(f.event_ids)=4 \
           AND f.event_ids->>0=c.commit_json->>'event_ref' \
           AND NOT EXISTS ( \
             SELECT 1 FROM jsonb_array_elements_text(f.event_ids) WITH ORDINALITY AS e(id,position) \
             WHERE NOT EXISTS (SELECT 1 FROM realm_commits u \
               WHERE u.realm_id=s.realm_id AND u.stream_position=e.position-1 \
                 AND u.commit_json->>'event_ref'=e.id)) \
         FOR SHARE OF s,c,f",
    )
    .bind::<Text, _>(realm)
    .get_result::<ValueRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(unresolved)?;
    let genesis: arkret_models_collaboration::events_payloads::realm::RealmGenesis =
        serde_json::from_value(row.value).map_err(|_| unresolved())?;
    genesis.validate().map_err(|_| unresolved())?;
    if genesis.purpose
        != arkret_models_collaboration::events_payloads::realm::RealmPurpose::DirectConversation
        || genesis.initial_join_rule != arkret_wire::JoinRule::Closed
        || genesis.initial_history_access != arkret_wire::HistoryAccess::SinceJoin
        || genesis.initial_discoverability != arkret_wire::Discoverability::InviteOnly
    {
        return Err(unresolved());
    }
    Ok(None)
}

pub(crate) fn component(value: &Value) -> PersistenceResult<Option<ParticipationBits>> {
    let Some(value) = value.get("agent_participation") else {
        return Ok(None);
    };
    let policy: AgentParticipationPolicy =
        serde_json::from_value(value.clone()).map_err(|_| unresolved())?;
    Ok(policy.agent)
}

pub(crate) async fn require_child_tightens(
    conn: &mut AsyncPgConnection,
    realm: &str,
    circle: Option<&str>,
    value: &Value,
) -> PersistenceResult<()> {
    let Some(child) = component(value)? else {
        return Ok(());
    };
    let mut parent = ParticipationBits::ALL;
    if let Some(bits) = governance_component(conn, realm, &format!("realm:{realm}")).await? {
        parent = parent.intersect(bits);
    }
    if let Some(circle) = circle
        && let Some(bits) =
            governance_component(conn, realm, &format!("circle:{realm}:{circle}")).await?
    {
        parent = parent.intersect(bits);
    }
    arkret_models_collaboration::governance::agent_participation::validate_agent_participation_tightens(parent, child)
        .map_err(|_| PersistenceError::Conflict(format!("failed_precondition: {}", arkret_wire::ReasonCode::AGENT_PARTICIPATION_CEILING_WIDEN)))
}
