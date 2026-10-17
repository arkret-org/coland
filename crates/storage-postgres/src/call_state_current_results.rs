//! Call genesis admission and registered current at the accepting Commit cut.
use arkret_models_collaboration::events_payloads::call::*;
use arkret_wire::{CallId, CommitStreamRef, Event, EventKind, RealmCommit, ScopeRef};
use coland_storage::{ConflictCode, PersistenceError, PersistenceResult};
use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};

fn invalid(detail: &str) -> PersistenceError {
    PersistenceError::SchemaViolation(detail.to_owned())
}

pub(crate) async fn commit_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
    prepared: Option<&coland_storage::EventApprovalCommit>,
    verified_media: Option<&arkret_signatures::media::VerifiedCallParticipant>,
) -> PersistenceResult<()> {
    if event.kind == EventKind::RealmMediaService {
        crate::realm_authorization_cut::authorize_capability_gated_event_with_approvals(
            conn, event, commit, prepared,
        )
        .await?;
        let payload: arkret_models_collaboration::events_payloads::RealmMediaServicePayload =
            serde_json::from_value(
                serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
            )
            .map_err(PersistenceError::database)?;
        payload
            .value
            .validate()
            .map_err(|e| invalid(&e.to_string()))?;
        sql_query("INSERT INTO realm_media_service_current_results(realm_id,source_stream_ref,current_commit_id,current_stream_position,value,updated_at) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(realm_id) DO UPDATE SET source_stream_ref=EXCLUDED.source_stream_ref,current_commit_id=EXCLUDED.current_commit_id,current_stream_position=EXCLUDED.current_stream_position,value=EXCLUDED.value,updated_at=EXCLUDED.updated_at")
            .bind::<Text,_>(event.realm_id.as_str()).bind::<Jsonb,_>(serde_json::to_value(&commit.stream_ref).map_err(PersistenceError::database)?)
            .bind::<Text,_>(commit.commit_id.as_str()).bind::<BigInt,_>(commit.stream_position as i64)
            .bind::<Jsonb,_>(serde_json::to_value(payload.value).map_err(PersistenceError::database)?)
            .bind::<Timestamptz,_>(commit.committed_at).execute(conn).await.map_err(PersistenceError::database)?;
        return Ok(());
    }
    if event.kind == EventKind::CallState {
        return commit_state(conn, event, commit, prepared, verified_media).await;
    }
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
    crate::realm_authorization_cut::authorize_capability_gated_event_with_approvals(
        conn, event, commit, prepared,
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

#[derive(QueryableByName)]
struct CurrentRow {
    #[diesel(sql_type=Jsonb)]
    value: serde_json::Value,
    #[diesel(sql_type=Jsonb)]
    source_stream_ref: serde_json::Value,
    #[diesel(sql_type=Text)]
    current_commit_id: String,
    #[diesel(sql_type=BigInt)]
    current_stream_position: i64,
}

fn conflict(message: &str) -> PersistenceError {
    PersistenceError::Conflict(format!("failed_precondition: {message}"))
}

pub(crate) async fn media_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &arkret_wire::RealmId,
) -> PersistenceResult<Option<arkret_models_collaboration::events_payloads::RealmMediaServiceValue>>
{
    #[derive(QueryableByName)]
    struct ValueRow {
        #[diesel(sql_type=Jsonb)]
        value: serde_json::Value,
    }
    sql_query("SELECT r.value FROM realm_media_service_current_results r WHERE r.realm_id=$1")
        .bind::<Text, _>(realm.as_str())
        .get_result::<ValueRow>(conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(|row| serde_json::from_value(row.value).map_err(PersistenceError::database))
        .transpose()
}

pub(crate) async fn read_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &arkret_wire::RealmId,
    call: &CallId,
    actor: &arkret_wire::ActorId,
) -> PersistenceResult<Option<coland_storage::CallCurrentCut>> {
    read_before_in_connection(conn, realm, call, actor, None).await
}

async fn read_before_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &arkret_wire::RealmId,
    call: &CallId,
    actor: &arkret_wire::ActorId,
    excluded: Option<&arkret_wire::EventId>,
) -> PersistenceResult<Option<coland_storage::CallCurrentCut>> {
    crate::realm_authorization_cut::lock_realm_authorization_cut(conn, realm).await?;
    let Some(row) = sql_query("SELECT r.value,r.source_stream_ref,r.current_commit_id,r.current_stream_position FROM call_state_current_results r WHERE r.realm_id=$1 AND r.call_id=$2")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(call.as_str()).get_result::<CurrentRow>(&mut *conn).await.optional().map_err(PersistenceError::database)? else { return Ok(None) };
    let stream: CommitStreamRef =
        serde_json::from_value(row.source_stream_ref).map_err(PersistenceError::database)?;
    let scope = match &stream {
        CommitStreamRef::Realm { realm_id } => ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        CommitStreamRef::Circle {
            realm_id,
            circle_id,
        } => ScopeRef::Circle {
            realm_id: realm_id.clone(),
            circle_id: circle_id.clone(),
        },
        _ => return Err(invalid("Call current uses a non-call stream")),
    };
    if !crate::moderation_report_current_results::scope_member_in_connection(
        conn, realm, &scope, actor,
    )
    .await?
    {
        return Ok(None);
    }
    #[derive(QueryableByName)]
    struct AxisRow {
        #[diesel(sql_type=Jsonb)]
        selector: serde_json::Value,
        #[diesel(sql_type=Jsonb)]
        value: serde_json::Value,
        #[diesel(sql_type=Jsonb)]
        source_stream_ref: serde_json::Value,
        #[diesel(sql_type=Text)]
        current_commit_id: String,
        #[diesel(sql_type=BigInt)]
        current_stream_position: i64,
    }
    let axes = sql_query("SELECT r.selector,r.value,r.source_stream_ref,r.current_commit_id,r.current_stream_position FROM call_component_current_results r WHERE r.realm_id=$1 AND r.call_id=$2")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(call.as_str()).get_results::<AxisRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let mut participants = Vec::new();
    let mut moderation = Vec::new();
    let mut focus = None;
    let mut roster_revision = None;
    let mut moderation_revision = None;
    let mut moderation_history = None;
    for axis in axes {
        let source: CommitStreamRef =
            serde_json::from_value(axis.source_stream_ref).map_err(PersistenceError::database)?;
        if source != stream {
            return Err(invalid("Call axis source stream differs"));
        }
        let revision = arkret_wire::CurrentRevision {
            commit_id: arkret_wire::RealmCommitId::new(axis.current_commit_id)
                .map_err(PersistenceError::database)?,
            stream_position: u64::try_from(axis.current_stream_position)
                .map_err(PersistenceError::database)?,
        };
        match axis.selector.get("kind").and_then(|v| v.as_str()) {
            Some("call_focus") => {
                focus =
                    Some(serde_json::from_value(axis.value).map_err(PersistenceError::database)?)
            }
            Some("call_roster") => {
                let value: CallRosterCurrentValue =
                    serde_json::from_value(axis.value).map_err(PersistenceError::database)?;
                value
                    .validate_sources(&stream, &revision)
                    .map_err(|e| invalid(&e.to_string()))?;
                participants = value
                    .active_participants()
                    .map_err(|e| invalid(&e.to_string()))?;
                roster_revision = Some(revision);
            }
            Some("call_moderation") => {
                let value: CallModerationCurrentValue =
                    serde_json::from_value(axis.value).map_err(PersistenceError::database)?;
                value
                    .validate_sources(&stream, &revision)
                    .map_err(|e| invalid(&e.to_string()))?;
                moderation = value
                    .effective_removals()
                    .map_err(|e| invalid(&e.to_string()))?;
                moderation_history = Some(value);
                moderation_revision = Some(revision);
            }
            _ => {}
        }
    }
    #[derive(QueryableByName)]
    struct HeadRow {
        #[diesel(sql_type=Jsonb)]
        commit_json: serde_json::Value,
    }
    let head=sql_query("SELECT commit_json FROM realm_commits WHERE realm_id=$1 AND stream_ref=$2 AND ($3::text IS NULL OR commit_json->>'event_ref'<>$3) ORDER BY stream_position DESC LIMIT 1")
        .bind::<Text,_>(realm.as_str()).bind::<Jsonb,_>(serde_json::to_value(&stream).map_err(PersistenceError::database)?)
        .bind::<diesel::sql_types::Nullable<Text>,_>(excluded.map(|e|e.as_str())).get_result::<HeadRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let head: RealmCommit =
        serde_json::from_value(head.commit_json).map_err(PersistenceError::database)?;
    if row.current_stream_position < 0
        || row.current_stream_position as u64 > head.stream_position
        || (row.current_stream_position as u64 == head.stream_position
            && row.current_commit_id != head.commit_id.as_str())
        || roster_revision
            .as_ref()
            .is_some_and(|r| r.stream_position > head.stream_position)
        || moderation_revision
            .as_ref()
            .is_some_and(|r| r.stream_position > head.stream_position)
    {
        return Err(conflict("Call current is ahead of its held namespace"));
    }

    #[derive(QueryableByName)]
    struct Generation {
        #[diesel(sql_type=BigInt)]
        generation: i64,
    }
    let generation = sql_query("SELECT generation FROM realm_authorities WHERE realm_id=$1")
        .bind::<Text, _>(realm.as_str())
        .get_result::<Generation>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?
        .generation;
    let current: CallStateCurrentValue =
        serde_json::from_value(row.value).map_err(PersistenceError::database)?;
    current.validate().map_err(|e| invalid(&e.to_string()))?;
    Ok(Some(coland_storage::CallCurrentCut {
        scope_ref: scope,
        head: arkret_wire::CommitStreamHead {
            stream_ref: stream,
            commit_id: head.commit_id,
            stream_position: head.stream_position,
        },
        generation: generation as u64,
        lifecycle: current.to,
        focus,
        participants,
        moderation,
        roster_revision,
        moderation_revision,
        moderation_history,
    }))
}

pub(crate) async fn write_axes(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
    payload: &CallStatePayload,
) -> PersistenceResult<()> {
    payload.validate().map_err(invalid)?;
    let call = &payload.call_id;
    for (kind, value) in [
        (
            "call_focus",
            payload.focus.as_ref().map(serde_json::to_value),
        ),
        (
            "call_roster",
            payload.roster_delta.as_ref().map(serde_json::to_value),
        ),
        (
            "call_moderation",
            payload.moderation_delta.as_ref().map(serde_json::to_value),
        ),
    ] {
        let Some(value) = value else { continue };
        let mut value = value.map_err(PersistenceError::database)?;
        let selector = serde_json::json!({"kind":kind,"call_id":call});
        #[derive(QueryableByName)]
        struct Old {
            #[diesel(sql_type=Jsonb)]
            value: serde_json::Value,
            #[diesel(sql_type=Jsonb)]
            source_stream_ref: serde_json::Value,
            #[diesel(sql_type=Text)]
            current_commit_id: String,
            #[diesel(sql_type=BigInt)]
            current_stream_position: i64,
        }
        let old=sql_query("SELECT value,source_stream_ref,current_commit_id,current_stream_position FROM call_component_current_results WHERE realm_id=$1 AND call_id=$2 AND selector=$3 FOR UPDATE")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(call.as_str()).bind::<Jsonb,_>(&selector)
        .get_result::<Old>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
        let stream =
            serde_json::to_value(&commit.stream_ref).map_err(PersistenceError::database)?;
        if old
            .as_ref()
            .is_some_and(|old| old.source_stream_ref != stream || old.current_stream_position < 0)
        {
            return Err(invalid("Call axis source or position differs"));
        }
        let rich = matches!(kind, "call_roster" | "call_moderation");
        if rich {
            let mut assertions = match &old {
                Some(old) => old
                    .value
                    .get("assertions")
                    .and_then(|a| a.as_array())
                    .cloned()
                    .ok_or_else(|| invalid("Call axis is not a complete assertion set"))?,
                None => Vec::new(),
            };
            let index = if kind == "call_roster" { 7 } else { 6 };
            let assertion = serde_json::json!({"tag_id":format!("{}:{}",event.event_id,index),"source_commit":commit,"value":value});
            if let Some(existing) = assertions
                .iter()
                .find(|a| a["tag_id"] == assertion["tag_id"])
            {
                if existing != &assertion {
                    return Err(invalid("Call assertion dot has a different carrier"));
                }
                continue;
            }
            if old
                .as_ref()
                .is_some_and(|o| o.current_stream_position as u64 >= commit.stream_position)
            {
                return Err(invalid(
                    "complete Call axis omitted an earlier accepted assertion",
                ));
            }
            assertions.push(assertion);
            assertions.sort_by(|a, b| a["tag_id"].as_str().cmp(&b["tag_id"].as_str()));
            value = serde_json::json!({"assertions":assertions});
        } else if let Some(old) = &old {
            if old.current_stream_position as u64 > commit.stream_position {
                continue;
            }
            if old.current_stream_position as u64 == commit.stream_position {
                if old.current_commit_id != commit.commit_id.as_str() || old.value != value {
                    return Err(invalid("Call axis forks its current position"));
                }
                continue;
            }
        }
        sql_query("INSERT INTO call_component_current_results(realm_id,call_id,selector,source_stream_ref,current_commit_id,current_stream_position,value,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(realm_id,call_id,selector) DO UPDATE SET source_stream_ref=EXCLUDED.source_stream_ref,current_commit_id=EXCLUDED.current_commit_id,current_stream_position=EXCLUDED.current_stream_position,value=EXCLUDED.value,updated_at=EXCLUDED.updated_at")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(call.as_str()).bind::<Jsonb,_>(selector)
        .bind::<Jsonb,_>(serde_json::to_value(&commit.stream_ref).map_err(PersistenceError::database)?)
        .bind::<Text,_>(commit.commit_id.as_str()).bind::<BigInt,_>(commit.stream_position as i64)
        .bind::<Jsonb,_>(value).bind::<Timestamptz,_>(commit.committed_at).execute(&mut *conn).await.map_err(PersistenceError::database)?;
    }
    Ok(())
}

async fn commit_state(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
    prepared: Option<&coland_storage::EventApprovalCommit>,
    verified: Option<&arkret_signatures::media::VerifiedCallParticipant>,
) -> PersistenceResult<()> {
    let payload: CallStatePayload = serde_json::from_value(
        serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
    )
    .map_err(PersistenceError::database)?;
    payload.validate().map_err(invalid)?;
    crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &event.realm_id).await?;
    let cut =
        crate::realm_authorization_cut::RealmAuthorizationCut::read_for_event(conn, event).await?;
    let mut actions = Vec::new();
    if payload.state_transition.is_some()
        || payload.focus.is_some()
        || payload.roster_delta.is_some()
    {
        actions.push(arkret_wire::CapabilityActionId::CALL_JOIN);
    }
    if payload.moderation_delta.is_some() {
        actions.push(arkret_wire::CapabilityActionId::CALL_MODERATE);
    }
    if payload.recording_transition.is_some() {
        actions.push(arkret_wire::CapabilityActionId::CALL_RECORD);
    }
    if payload.transcript_transition.is_some() {
        actions.push(arkret_wire::CapabilityActionId::CALL_TRANSCRIBE);
    }
    if payload.roster_delta.as_ref().is_some_and(|delta| matches!(delta,CallRosterDelta::Join {participant} if participant.media.as_ref().is_some_and(|m|m.screen==Some(true)))) {
        actions.push(arkret_wire::CapabilityActionId::CALL_SCREEN_SHARE);
    }
    cut.require_call_actions(conn, event, commit, prepared, &actions)
        .await?;
    let current = read_before_in_connection(
        conn,
        &event.realm_id,
        &payload.call_id,
        &event.actor_id,
        Some(&event.event_id),
    )
    .await?
    .ok_or_else(|| conflict("Call is not visible in exact scope"))?;
    if current.scope_ref != event.scope_ref
        || CommitStreamRef::from_scope(&event.scope_ref, None)
            .map_err(PersistenceError::database)?
            != commit.stream_ref
    {
        return Err(invalid("Call delta scope differs"));
    }
    if matches!(
        current.lifecycle,
        CallLifecycleState::Ended
            | CallLifecycleState::Missed
            | CallLifecycleState::Cancelled
            | CallLifecycleState::Failed
    ) {
        return Err(conflict("call_state_terminal"));
    }
    let media = media_in_connection(conn, &event.realm_id).await?;
    let focus = payload.focus.as_ref().or(current.focus.as_ref());
    if let Some(next) = &payload.focus {
        if let Some(old) = &current.focus {
            if old.session_focus.is_some() && old.session_focus != next.session_focus {
                return Err(conflict("session_focus_already_committed"));
            }
            let rank = |m: CallMode| match m {
                CallMode::P2p => 0,
                CallMode::Mesh => 1,
                CallMode::Sfu => 2,
                CallMode::Mcu => 3,
            };
            if rank(next.mode) < rank(old.mode) {
                return Err(conflict("call mode cannot downgrade"));
            }
        }
        if next.session_focus.as_ref().is_some_and(|id| {
            media
                .as_ref()
                .is_none_or(|m| !m.foci.iter().any(|f| f.focus_id.as_str() == id.as_str()))
        }) {
            return Err(conflict("focus_mismatch"));
        }
    }
    if let Some(delta) = &payload.roster_delta {
        match delta {
            CallRosterDelta::Join { participant } => {
                if current.participants.len() >= 1000
                    && !current.participants.iter().any(|(p, _)| {
                        p.actor_id == participant.actor_id && p.device_id == participant.device_id
                    })
                {
                    return Err(conflict("Call roster limit exceeded"));
                }
                if participant
                    .participant_binding
                    .as_ref()
                    .is_some_and(|b| b.expires_at <= commit.committed_at)
                {
                    return Err(conflict("participant_binding_invalid"));
                }
                let sfu = focus.is_some_and(|f| {
                    matches!(f.mode, CallMode::Sfu | CallMode::Mcu) || f.session_focus.is_some()
                });
                if sfu {
                    let service = &media
                        .as_ref()
                        .ok_or_else(|| conflict("media service current is missing"))?
                        .service_id;
                    if verified.is_none_or(|v| !v.binds(event, service))
                        || participant.focus_id.as_deref()
                            != focus.and_then(|f| f.session_focus.as_ref().map(|v| v.as_str()))
                    {
                        return Err(conflict("participant_binding_invalid"));
                    }
                } else {
                    return Err(conflict("verified P2P answer admission is unavailable"));
                }
            }
            CallRosterDelta::Leave {
                actor_id,
                device_id,
                expected_revision,
            } => {
                if !current
                    .participants
                    .iter()
                    .any(|(p, _)| &p.actor_id == actor_id && &p.device_id == device_id)
                {
                    return Err(conflict("active roster leg is absent"));
                }
                if current.roster_revision.as_ref() != Some(expected_revision) {
                    return Err(conflict("roster revision changed"));
                }
            }
        }
    }
    if let Some(CallModerationDelta::RestoreParticipant {
        actor_id,
        expected_revision,
        ..
    }) = &payload.moderation_delta
    {
        if current.moderation_revision.as_ref() != Some(expected_revision)
            || !current
                .moderation
                .iter()
                .any(|r| &r.actor_id == actor_id && r.action == CallParticipantRemovalAction::Ban)
        {
            return Err(conflict("active ban or moderation revision changed"));
        }
    }
    if payload.recording_transition.is_some() || payload.transcript_transition.is_some() {
        return Err(conflict(
            "capture current and stop-source admission are unavailable",
        ));
    }
    if let Some(t) = &payload.state_transition {
        use CallLifecycleState::*;
        let legal = match t.from {
            Scheduled => matches!(t.to, Ringing | Connecting | Cancelled | Missed | Failed),
            Ringing => matches!(t.to, Connecting | Active | Missed | Cancelled | Failed),
            Connecting => matches!(t.to, Active | Failed | Ended),
            Active => matches!(t.to, Ended | Failed),
            _ => false,
        };
        if t.from != current.lifecycle || !legal {
            return Err(conflict("call_state_transition_invalid"));
        }
        sql_query("UPDATE call_state_current_results SET current_commit_id=$3,current_stream_position=$4,value=$5,updated_at=$6 WHERE realm_id=$1 AND call_id=$2")
            .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(payload.call_id.as_str()).bind::<Text,_>(commit.commit_id.as_str()).bind::<BigInt,_>(commit.stream_position as i64)
            .bind::<Jsonb,_>(serde_json::to_value(t).map_err(PersistenceError::database)?).bind::<Timestamptz,_>(commit.committed_at).execute(&mut *conn).await.map_err(PersistenceError::database)?;
    }
    write_axes(conn, event, commit, &payload).await?;
    Ok(())
}

/// A final independent media permission cut. No prepared token is stored here.
pub(crate) async fn release_in_connection(
    conn: &mut AsyncPgConnection,
    request: &arkret_models_collaboration::objects::media::CallMediaTokenExchangeRequestBody,
    issuer: &arkret_wire::DidCoreId,
) -> PersistenceResult<bool> {
    let Some(cut) =
        read_in_connection(conn, &request.realm_id, &request.call_id, &request.actor_id).await?
    else {
        return Ok(false);
    };
    if matches!(
        cut.lifecycle,
        CallLifecycleState::Ended
            | CallLifecycleState::Failed
            | CallLifecycleState::Cancelled
            | CallLifecycleState::Missed
    ) {
        return Ok(false);
    };
    let Some(media) = media_in_connection(conn, &request.realm_id).await? else {
        return Ok(false);
    };
    if &media.service_id != issuer
        || !media
            .foci
            .iter()
            .any(|f| f.focus_id.as_str() == request.focus_id)
        || cut
            .focus
            .as_ref()
            .and_then(|f| f.session_focus.as_ref())
            .is_some_and(|f| f.as_str() != request.focus_id)
        || cut.moderation.iter().any(|r| {
            r.actor_id == request.actor_id && r.action == CallParticipantRemovalAction::Ban
        })
    {
        return Ok(false);
    };
    if let arkret_models_collaboration::call_invitation::CallMediaJoinContext::Refresh(context) =
        &request.join_context
    {
        let Some((participant, joined)) = cut.participants.iter().find(|(p, _)| {
            p.actor_id == request.actor_id
                && p.device_id == request.device_id.as_str()
                && p.participant_id.as_deref() == Some(context.participant_id.as_str())
                && p.focus_id.as_deref() == Some(request.focus_id.as_str())
        }) else {
            return Ok(false);
        };
        if cut.moderation_history.as_ref().is_some_and(|history| {
            history.assertions.iter().any(|assertion| {
                matches!(&assertion.value, CallModerationDelta::RemoveParticipant { removal }
                if removal.action == CallParticipantRemovalAction::Kick
                    && removal.actor_id == request.actor_id
                    && removal.device_id.as_deref() == Some(request.device_id.as_str())
                    && assertion.source_commit.stream_position > joined.stream_position)
            })
        }) {
            return Ok(false);
        }
        if participant.participant_binding.is_none()
            || !request.invitation_media().is_subset_of(
                &participant
                    .signed_media()
                    .map_err(|e| invalid(&e.to_string()))?,
            )
        {
            return Ok(false);
        }
    }
    let authorization = crate::realm_authorization_cut::RealmAuthorizationCut::read_accepted(
        conn,
        &request.realm_id,
        &request.actor_id,
    )
    .await?;
    let target: arkret_wire::WireResourceSelector = serde_json::from_value(match &cut.scope_ref {
        ScopeRef::Realm { realm_id } => serde_json::json!({"kind":"realm","realm_id":realm_id}),
        ScopeRef::Circle {
            realm_id,
            circle_id,
        } => serde_json::json!({"kind":"circle","realm_id":realm_id,"circle_id":circle_id}),
        _ => return Ok(false),
    })
    .map_err(PersistenceError::database)?;
    let mut actions = vec![arkret_wire::CapabilityActionId::CALL_JOIN];
    if request
        .desired_media
        .as_ref()
        .is_some_and(|m| m.screen == Some(true))
    {
        actions.push(arkret_wire::CapabilityActionId::CALL_SCREEN_SHARE);
    }
    let actor = authorization
        .bounded_actor_authorization_in_connection(conn, chrono::Utc::now())
        .await?;
    for action in actions {
        let requested = [action];
        let facts = coland_storage::OperationFacts::default();
        let evaluation = actor.evaluate(&requested, &target, &facts);
        let owner = actor.holds_realm_owner()
            && arkret_policy::owner_may_author_action(action).unwrap_or(false);
        let permits = match &evaluation {
            coland_storage::GrantEvaluation::Allowed(_) => {
                !evaluation.unreserved().is_empty() || owner
            }
            coland_storage::GrantEvaluation::Unnamed
            | coland_storage::GrantEvaluation::Unsatisfied => owner,
            _ => false,
        };
        if !permits {
            return Ok(false);
        };
    }
    Ok(true)
}
