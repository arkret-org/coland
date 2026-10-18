//! Immutable controller confirmations, distinct from detached grant votes.
use arkret_models_collaboration::events_payloads::agent::{
    AgentActionApprovePayload, AgentActionRequestPayload,
};
use arkret_wire::{AccountId, ActorId, Event, EventKind, RealmCommit};
use coland_storage::{PersistenceError, PersistenceResult};
use diesel::sql_types::{BigInt, Jsonb, Nullable, Text, Timestamptz};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};

#[derive(QueryableByName)]
struct Confirmation {
    #[diesel(sql_type=Jsonb)]
    value: serde_json::Value,
    #[diesel(sql_type=Timestamptz)]
    committed_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Jsonb)]
    controller_actor_id: serde_json::Value,
}

#[derive(QueryableByName)]
struct RequestSource {
    #[diesel(sql_type=Text)]
    controller_account_key: String,
    #[diesel(sql_type=Jsonb)]
    request: serde_json::Value,
    #[diesel(sql_type=Text)]
    workflow_state: String,
    #[diesel(sql_type=Nullable<Jsonb>)]
    source: Option<serde_json::Value>,
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
/// The Agent PCR root belongs to the Agent, not to its human controller.
/// Reuse the canonical accepted ownership closure, including its full Account,
/// native provision witness, lifecycle, accountability and DID/PCR binding.
async fn controller(
    conn: &mut AsyncPgConnection,
    agent: &arkret_wire::DidCoreId,
    expected: &AccountId,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<ActorId> {
    let agent_account = AccountId::new(agent.clone(), expected.station_id.clone());
    if crate::boxed_future(|| {
        crate::agent_interaction_current_results::owned_provenance_in_connection(
            conn,
            &agent_account,
            expected,
            at,
            true,
        )
    })
    .await?
    .is_none()
    {
        return Err(invalid(
            "Agent accepted current ownership source is unavailable",
        ));
    }
    Ok(ActorId::account(expected.clone()))
}

pub(crate) async fn admit_confirmation(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
    _prepared: Option<&coland_storage::EventApprovalCommit>,
) -> PersistenceResult<()> {
    if event.kind != EventKind::AgentActionApprove {
        return Ok(());
    }
    let payload: AgentActionApprovePayload = serde_json::from_value(
        serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
    )
    .map_err(|e| PersistenceError::SchemaViolation(e.to_string()))?;
    let expected = event
        .actor_id
        .as_account_id()
        .ok_or_else(|| invalid("Agent confirmation requires a full controller Account"))?;
    if event.executed_by.is_some()
        || event.applet_id.is_some()
        || event.producer_proof.is_none()
        || event.scope_ref
            != (arkret_wire::ScopeRef::Realm {
                realm_id: event.realm_id.clone(),
            })
        || commit.stream_ref
            != (arkret_wire::CommitStreamRef::Realm {
                realm_id: event.realm_id.clone(),
            })
        || controller(conn, &payload.agent_id, expected, commit.committed_at).await?
            != event.actor_id
    {
        return Err(invalid(
            "Agent confirmation must be signed by its current exact controller Actor",
        ));
    }
    if !payload.admits_commit_at(commit.committed_at) {
        return Err(invalid(
            "Agent confirmation covering committed_at is after expires_at",
        ));
    }
    // This registered controller proof class has no capability grant shortcut.
    // Lock and verify the same accepted ownership/member generation as mode writes.
    crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &event.realm_id).await?;
    let agent = AccountId::new(payload.agent_id.clone(), expected.station_id.clone());
    if crate::agent_interaction_current_results::controller_in_connection(
        conn,
        &event.realm_id,
        &agent,
        commit.committed_at,
    )
    .await?
    .as_ref()
        != Some(expected)
    {
        return Err(invalid(
            "Agent confirmation requires the current controller and Agent member generation",
        ));
    }
    require_confirmation_source(conn, event, &payload, expected).await?;
    Ok(())
}

/// The signed confirmation names immutable private input, never a caller-made
/// controller row. The complete approved Event digest is checked at publication.
async fn require_confirmation_source(
    conn: &mut AsyncPgConnection,
    event: &Event,
    payload: &AgentActionApprovePayload,
    owner: &AccountId,
) -> PersistenceResult<()> {
    let agent_actor = ActorId::account(AccountId::new(
        payload.agent_id.clone(),
        owner.station_id.clone(),
    ));
    if payload.target.realm_id.as_ref() != Some(&event.realm_id) {
        return Err(invalid("Agent confirmation target Realm differs"));
    }
    if let Some(request_id) = payload.request_id.as_deref() {
        let source = sql_query("SELECT r.controller_account_key,r.request,r.workflow_state,e.envelope AS source FROM agent_action_requests r LEFT JOIN actor_private_events e ON e.event_id=r.accepted_event_id AND e.kind='ak.agent.action_request' WHERE r.controller_account_key=$1 AND r.agent_id=$2 AND r.request_id=$3 FOR SHARE OF r")
            .bind::<Text,_>(owner.to_string()).bind::<Text,_>(payload.agent_id.as_str()).bind::<Text,_>(request_id)
            .get_result::<RequestSource>(&mut *conn).await.optional().map_err(PersistenceError::database)?
            .ok_or_else(|| invalid("Agent confirmation request source is unavailable"))?;
        let accepted: Event = serde_json::from_value(
            source
                .source
                .ok_or_else(|| invalid("Agent confirmation accepted request is unavailable"))?,
        )
        .map_err(PersistenceError::database)?;
        let request: AgentActionRequestPayload =
            serde_json::from_value(source.request.clone()).map_err(PersistenceError::database)?;
        if accepted.kind != EventKind::AgentActionRequest
            || accepted.actor_id != agent_actor
            || accepted.executed_by.is_some()
            || serde_json::json!(accepted.payload) != source.request
            || source.workflow_state != "requested"
            || request.request_id != request_id
            || request.agent_id != payload.agent_id
            || request.controller_account_id != *owner
            || request.proposed_action != payload.proposed_action
            || serde_json::json!(request.target) != serde_json::json!(payload.target)
            || payload
                .draft_id
                .as_ref()
                .is_some_and(|id| request.draft_id.as_ref() != Some(id))
        {
            return Err(invalid(
                "Agent confirmation differs from its immutable request",
            ));
        }
        return Ok(());
    }
    let draft = payload
        .draft_id
        .as_deref()
        .ok_or_else(|| invalid("Agent confirmation has no request or draft"))?;
    let source = confirmation_draft_source(conn, owner, &payload.agent_id, draft)
        .await?
        .ok_or_else(|| invalid("Agent confirmation consumed draft source is unavailable"))?;
    let accepted: Event =
        serde_json::from_value(source.source).map_err(PersistenceError::database)?;
    let proposed: arkret_models_collaboration::events_payloads::agent::AgentDraftProposePayload =
        serde_json::from_value(serde_json::json!(accepted.payload))
            .map_err(PersistenceError::database)?;
    if accepted.kind != EventKind::AgentDraftPropose
        || accepted.actor_id != agent_actor
        || accepted.executed_by.is_some()
        || proposed.agent_id != payload.agent_id
        || proposed.controller_account_id != *owner
        || proposed.draft_id != draft
        || proposed.proposed_action != payload.proposed_action
        || serde_json::json!(proposed.target) != serde_json::json!(payload.target)
        || payload.draft_content_digest.as_ref() != Some(&proposed.content_digest)
        || arkret_canonical::canonical_sha256(&accepted).map_err(PersistenceError::database)?
            != source.canonical_event_digest
    {
        return Err(invalid(
            "Agent confirmation differs from its immutable draft",
        ));
    }
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
        return Err(PersistenceError::Conflict(
            "approval_nonce_reused: Agent confirmation identifier or controller nonce has already been allocated".into(),
        ));
    }
    Ok(())
}

/// An accepted private action request selects its complete pre-signed Event.
/// Direct writes with no selection retain their own admission; attributed
/// Agent execution always requires its fresh controller confirmation.
/// Draft-only publication is selected by an immutable controller confirmation
/// and the accepted encrypted holder register, without exposing its plaintext.
pub(crate) async fn require_publication(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
) -> PersistenceResult<()> {
    if event.kind == EventKind::AgentActionApprove {
        return Ok(());
    }
    let actor = event.actor_id.as_account_id();
    let producer = event.actual_signer().as_account_id();
    let digest = arkret_canonical::canonical_sha256(event).map_err(PersistenceError::database)?;
    // The left join distinguishes a missing private source from no request.
    // Accepted private Events are immutable; only the workflow row is locked.
    let requests = sql_query("SELECT r.controller_account_key,r.request,r.workflow_state,e.envelope AS source FROM agent_action_requests r LEFT JOIN actor_private_events e ON e.event_id=r.accepted_event_id AND e.kind='ak.agent.action_request' WHERE (r.agent_id=$1 OR r.agent_id=$2) AND r.request->>'request_canonical_digest'=$3 FOR SHARE OF r")
        .bind::<Nullable<Text>,_>(actor.map(|account| account.principal_id.as_str()))
        .bind::<Nullable<Text>,_>(producer.map(|account| account.principal_id.as_str()))
        .bind::<Text,_>(&digest)
        .load::<RequestSource>(&mut *conn).await.map_err(PersistenceError::database)?;
    if requests.is_empty() {
        #[derive(QueryableByName)]
        struct Present {
            #[diesel(sql_type=diesel::sql_types::Bool)]
            present: bool,
        }
        let selected = sql_query("SELECT EXISTS(SELECT 1 FROM agent_action_approval_current_results WHERE realm_id=$1 AND approved_event_id=$2) AS present")
            .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(event.event_id.as_str())
            .get_result::<Present>(&mut *conn).await.map_err(PersistenceError::database)?;
        if selected.present {
            return crate::boxed_future(|| require_draft_publication(conn, event, commit)).await;
        }
        // Attribution cannot turn a reply grant or private participation bit
        // into a fresh controller approval for a new, unselected Event.
        if event.actual_signer() != &event.actor_id
            && let (Some(agent), Some(expected)) = (
                event.actual_signer().as_account_id(),
                event.actor_id.as_account_id(),
            )
            && crate::realm_authorization_cut::is_owned_agent_in_connection(
                conn,
                &event.realm_id,
                agent,
            )
            .await?
        {
            controller(conn, &agent.principal_id, expected, commit.committed_at).await?;
            return Err(required());
        }
        return Ok(());
    }
    for source in requests {
        let request: AgentActionRequestPayload =
            serde_json::from_value(source.request.clone()).map_err(|_| required())?;
        let accepted: Event =
            serde_json::from_value(source.source.ok_or_else(required)?).map_err(|_| required())?;
        // Agent identity belongs to the immutable private request, rather than
        // whichever actor happened to produce the selected publication.
        let Some(agent) = accepted.actor_id.as_account_id() else {
            continue;
        };
        if source.workflow_state != "requested"
            || request.agent_id != agent.principal_id
            || request.request_canonical_digest.as_str() != digest
            || accepted.kind != EventKind::AgentActionRequest
            || accepted.executed_by.is_some()
            || serde_json::to_value(&accepted.payload).map_err(PersistenceError::database)?
                != source.request
        {
            continue;
        }
        let current_controller = controller(
            conn,
            &agent.principal_id,
            &request.controller_account_id,
            commit.committed_at,
        )
        .await?;
        let Some(controller_account) = current_controller.as_account_id() else {
            continue;
        };
        let agent_actor = ActorId::account(agent.clone());
        let agent_owned = event.actor_id == agent_actor
            && (event.executed_by.is_none()
                || event.executed_by.as_ref() == Some(&current_controller));
        let controller_owned = event.actor_id == current_controller
            && event.executed_by.as_ref() == Some(&agent_actor);
        if agent.station_id != controller_account.station_id
            || source.controller_account_key != controller_account.to_string()
            || request.controller_account_id != *controller_account
            || !(agent_owned || controller_owned)
        {
            continue;
        }
        let rows=sql_query("SELECT a.value,c.committed_at,e.envelope->'actor_id' AS controller_actor_id FROM agent_action_approval_current_results a JOIN realm_commits c ON c.commit_id=a.current_commit_id AND c.realm_id=a.realm_id AND c.stream_position=a.current_stream_position JOIN canonical_events e ON e.pk=c.event_pk WHERE a.realm_id=$1 AND a.approved_event_id=$2 AND a.controller_actor_key=$3 AND e.state='committed' AND e.kind='ak.agent.action_approve' AND e.envelope->>'event_id'=a.current_event_id AND e.envelope->'payload'=a.value AND e.envelope->'actor_id'=$4 FOR SHARE OF a")
            .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(event.event_id.as_str()).bind::<Text,_>(current_controller.to_string())
            .bind::<Jsonb,_>(serde_json::to_value(&current_controller).map_err(PersistenceError::database)?)
            .load::<Confirmation>(&mut *conn).await.map_err(PersistenceError::database)?;
        for row in &rows {
            let payload: AgentActionApprovePayload =
                serde_json::from_value(row.value.clone()).map_err(|_| required())?;
            if payload.agent_id != agent.principal_id
                || payload.approved_event_id != event.event_id
                || !payload.admits_commit_at(commit.committed_at)
                || !payload.admits_commit_at(row.committed_at)
                || match payload.request_id.as_deref() {
                    Some(id) => id != request.request_id,
                    None => payload.draft_id.is_none() || payload.draft_id != request.draft_id,
                }
                || payload
                    .draft_id
                    .as_ref()
                    .is_some_and(|draft| request.draft_id.as_ref() != Some(draft))
                || payload.proposed_action != request.proposed_action
                || serde_json::to_value(&payload.target).map_err(PersistenceError::database)?
                    != serde_json::to_value(&request.target).map_err(PersistenceError::database)?
            {
                continue;
            }
            if confirmation_target_matches(&payload, event) {
                return Ok(());
            }
        }
    }
    Err(required())
}

fn confirmation_target_matches(payload: &AgentActionApprovePayload, event: &Event) -> bool {
    let Some(action) = arkret_wire::CapabilityActionId::from_wire(&payload.proposed_action) else {
        return false;
    };
    if !arkret_schema::capability_action_descriptor(action)
        .target_event_kinds
        .contains(&event.kind.as_str())
    {
        return false;
    }
    let target = &payload.target;
    if target
        .realm_id
        .as_ref()
        .is_some_and(|realm| realm != &event.realm_id)
        || target.operation_id.is_some()
        || target.account_data_key.is_some()
    {
        return false;
    }
    match target.kind.as_str() {
        "realm" => target.realm_id.as_ref() == Some(&event.realm_id),
        "strand" => target.object_ref.as_ref().is_some_and(|expected| {
            arkret_wire::StrandId::new(expected.as_str()).is_ok()
                && (event
                    .payload
                    .get("strand_id")
                    .and_then(serde_json::Value::as_str)
                    == Some(expected.as_str())
                    || (matches!(
                        event.kind,
                        EventKind::StrandArchive
                            | EventKind::StrandRestore
                            | EventKind::StrandStageSet
                            | EventKind::StrandTracksUpdate
                    ) && event
                        .payload
                        .get("target_ref")
                        .and_then(serde_json::Value::as_str)
                        == Some(expected.as_str()))
                    || (event.kind == EventKind::StrandCreate
                        && arkret_wire::StrandId::from_event_id(&event.event_id).as_str()
                            == expected.as_str()))
        }),
        "space" => target.object_ref.as_ref().is_some_and(|expected| {
            arkret_wire::SpaceId::new(expected.as_str()).is_ok()
                && (event
                    .payload
                    .get("space_id")
                    .and_then(serde_json::Value::as_str)
                    == Some(expected.as_str())
                    || (event.kind == EventKind::SpaceCreate
                        && arkret_wire::SpaceId::from_event_id(&event.event_id).as_str()
                            == expected.as_str()))
        }),
        "message" => target.object_ref.as_ref().is_some_and(|expected| {
            arkret_wire::MessageId::new(expected.as_str()).is_ok()
                && (event
                    .payload
                    .get("message_id")
                    .or_else(|| event.payload.get("target_ref"))
                    .and_then(serde_json::Value::as_str)
                    == Some(expected.as_str())
                    || (event.kind == EventKind::MessageCreate
                        && arkret_wire::MessageId::from_event_id(&event.event_id).as_str()
                            == expected.as_str()))
        }),
        "object" => target.object_ref.as_ref().is_some_and(|expected| {
            ["target_ref", "object_ref"].iter().any(|field| {
                event
                    .payload
                    .get(*field)
                    .and_then(serde_json::Value::as_str)
                    == Some(expected.as_str())
            })
        }),
        _ => false,
    }
}

#[derive(QueryableByName)]
struct DraftSource {
    #[diesel(sql_type = Jsonb)]
    source: serde_json::Value,
    #[diesel(sql_type = Text)]
    canonical_event_digest: String,
}

async fn confirmation_draft_source(
    conn: &mut AsyncPgConnection,
    owner: &AccountId,
    agent: &arkret_wire::DidCoreId,
    draft: &str,
) -> PersistenceResult<Option<DraftSource>> {
    let key =
        arkret_models_collaboration::events_payloads::account_data::agent_draft_account_data_key(
            agent, draft,
        )
        .map_err(|_| required())?;
    let source = sql_query("SELECT source.envelope AS source,p.canonical_event_digest FROM agent_draft_pending_intents p JOIN actor_private_events source ON source.event_id=p.accepted_event_id AND source.kind='ak.agent.draft.propose' JOIN actor_private_events consumed ON consumed.event_id=p.consumption->>'account_data_set_event_id' AND consumed.kind='ak.account_data.set' JOIN account_datas d ON d.actor_id=$1 AND d.account_data_key=$4 WHERE p.controller_account_key=$2 AND p.agent_id=$3 AND p.draft_id=$5 AND p.state='consumed' AND p.consumption->>'account_data_key'=$4 AND p.consumption->>'accepted_revision'='1' AND p.controller_account_id=$6 AND consumed.actor_id=$1 AND consumed.envelope->'payload'->>'key'=$4 AND consumed.envelope->'payload'->>'expected_server_revision'='0' AND consumed.envelope->'payload'->>'source_pending_event_id'=p.accepted_event_id AND consumed.envelope->'payload' ? 'encrypted_payload' AND NOT d.tombstone AND d.revision>=1 AND d.payload->>'schema'='ak.schema.account_data_encrypted_value.v1' FOR SHARE OF p,d")
            .bind::<Text,_>(ActorId::account(owner.clone()).to_string()).bind::<Text,_>(owner.to_string())
            .bind::<Text,_>(agent.as_str()).bind::<Text,_>(&key).bind::<Text,_>(draft).bind::<Jsonb,_>(serde_json::json!(owner))
            .get_result::<DraftSource>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    Ok(source)
}

/// The holder's signed confirmation selects a draft publication. Its encrypted
/// Account Data remains opaque: only accepted source coordinates are checked.
async fn require_draft_publication(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
) -> PersistenceResult<()> {
    let rows = sql_query("SELECT a.value,c.committed_at,e.envelope->'actor_id' AS controller_actor_id FROM agent_action_approval_current_results a JOIN realm_commits c ON c.commit_id=a.current_commit_id AND c.realm_id=a.realm_id AND c.stream_position=a.current_stream_position JOIN canonical_events e ON e.pk=c.event_pk WHERE a.realm_id=$1 AND a.approved_event_id=$2 AND e.state='committed' AND e.kind='ak.agent.action_approve' AND e.envelope->>'event_id'=a.current_event_id AND e.envelope->'payload'=a.value AND e.actor_id=a.controller_actor_key AND NOT (e.envelope ? 'executed_by') FOR SHARE OF a")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(event.event_id.as_str())
        .load::<Confirmation>(&mut *conn).await.map_err(PersistenceError::database)?;
    for confirmation in rows {
        let payload: AgentActionApprovePayload =
            serde_json::from_value(confirmation.value).map_err(|_| required())?;
        let Some(draft) = payload.draft_id.as_deref() else {
            continue;
        };
        if payload.request_id.is_some()
            || payload.approved_event_id != event.event_id
            || !payload.admits_commit_at(commit.committed_at)
            || !payload.admits_commit_at(confirmation.committed_at)
            || !confirmation_target_matches(&payload, event)
        {
            continue;
        }
        let confirmed_controller: ActorId =
            serde_json::from_value(confirmation.controller_actor_id).map_err(|_| required())?;
        let Some(expected) = confirmed_controller.as_account_id() else {
            continue;
        };
        let current_controller = crate::boxed_future(|| {
            controller(conn, &payload.agent_id, expected, commit.committed_at)
        })
        .await?;
        let Some(owner) = current_controller.as_account_id() else {
            continue;
        };
        let agent = ActorId::account(arkret_wire::AccountId::new(
            payload.agent_id.clone(),
            owner.station_id.clone(),
        ));
        let agent_owned = event.actor_id == agent
            && (event.executed_by.is_none()
                || event.executed_by.as_ref() == Some(&current_controller));
        let controller_owned =
            event.actor_id == current_controller && event.executed_by.as_ref() == Some(&agent);
        if !(agent_owned || controller_owned) {
            continue;
        }
        if confirmed_controller != current_controller {
            continue;
        }
        let source = confirmation_draft_source(conn, owner, &payload.agent_id, draft).await?;
        let Some(source) = source else {
            continue;
        };
        let accepted: Event = serde_json::from_value(source.source).map_err(|_| required())?;
        let proposed: arkret_models_collaboration::events_payloads::agent::AgentDraftProposePayload =
            serde_json::from_value(serde_json::json!(&accepted.payload)).map_err(|_| required())?;
        if accepted.actor_id == agent
            && accepted.executed_by.is_none()
            && proposed.agent_id == payload.agent_id
            && proposed.controller_account_id == *owner
            && proposed.draft_id == draft
            && arkret_canonical::canonical_sha256(&accepted).map_err(PersistenceError::database)?
                == source.canonical_event_digest
        {
            return Ok(());
        }
    }
    Err(required())
}

#[cfg(test)]
#[path = "agent_confirmation_admission/pg_tests.rs"]
mod pg_tests;
