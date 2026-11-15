//! Native capture admission. Result production never reopens capture permission.
use arkret_wire::{CurrentSelector, EventId, RealmId};
use serde_json::{Value, json};

use super::*;

mod key_source;
mod source_authority;
#[cfg(test)]
mod tests;

#[derive(QueryableByName)]
struct Axis {
    #[diesel(sql_type = Jsonb)]
    value: Value,
    #[diesel(sql_type = Jsonb)]
    source_stream_ref: Value,
    #[diesel(sql_type = Text)]
    current_commit_id: String,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
}

fn selector(
    kind: RecordingCaptureKind,
    artifact: bool,
    call: &CallId,
    segment: &CallRecordingId,
) -> CurrentSelector {
    let call_id = call.clone();
    let recording_id = segment.clone();
    match (kind, artifact) {
        (RecordingCaptureKind::Recording, false) => CurrentSelector::CallRecordingState {
            call_id,
            recording_id,
        },
        (RecordingCaptureKind::Recording, true) => CurrentSelector::CallRecordingArtifact {
            call_id,
            recording_id,
        },
        (RecordingCaptureKind::Transcript, false) => CurrentSelector::CallTranscriptState {
            call_id,
            recording_id,
        },
        (RecordingCaptureKind::Transcript, true) => CurrentSelector::CallTranscriptArtifact {
            call_id,
            recording_id,
        },
    }
}

async fn axis(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    selector: &CurrentSelector,
) -> PersistenceResult<Option<Axis>> {
    let call = match selector {
        CurrentSelector::CallRecordingState { call_id, .. }
        | CurrentSelector::CallRecordingArtifact { call_id, .. }
        | CurrentSelector::CallTranscriptState { call_id, .. }
        | CurrentSelector::CallTranscriptArtifact { call_id, .. } => call_id,
        _ => return Err(invalid("Not a capture current selector")),
    };
    sql_query("SELECT value,source_stream_ref,current_commit_id,current_stream_position FROM call_component_current_states WHERE realm_id=$1 AND call_id=$2 AND selector=$3 FOR UPDATE")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(call.as_str())
        .bind::<Jsonb,_>(serde_json::to_value(selector).map_err(PersistenceError::database)?)
        .get_result::<Axis>(&mut *conn).await.optional().map_err(PersistenceError::database)
}

async fn write(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
    call: &CallId,
    selector: &CurrentSelector,
    value: Value,
) -> PersistenceResult<()> {
    sql_query("INSERT INTO call_component_current_states(realm_id,call_id,selector,source_stream_ref,current_commit_id,current_stream_position,value,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(realm_id,call_id,selector) DO UPDATE SET source_stream_ref=EXCLUDED.source_stream_ref,current_commit_id=EXCLUDED.current_commit_id,current_stream_position=EXCLUDED.current_stream_position,value=EXCLUDED.value,updated_at=EXCLUDED.updated_at")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(call.as_str())
        .bind::<Jsonb,_>(serde_json::to_value(selector).map_err(PersistenceError::database)?)
        .bind::<Jsonb,_>(json!(commit.stream_ref)).bind::<Text,_>(commit.commit_id.as_str())
        .bind::<BigInt,_>(i64::try_from(commit.stream_position).map_err(PersistenceError::database)?)
        .bind::<Jsonb,_>(value).bind::<Timestamptz,_>(commit.committed_at)
        .execute(&mut *conn).await.map_err(PersistenceError::database)?;
    Ok(())
}

#[derive(QueryableByName)]
struct Source {
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
    #[diesel(sql_type = Jsonb)]
    commit_json: Value,
}

fn decode_source(
    source: Source,
    stream: &CommitStreamRef,
) -> PersistenceResult<(Event, RealmCommit)> {
    let event: Event =
        serde_json::from_value(source.envelope).map_err(PersistenceError::database)?;
    let commit: RealmCommit =
        serde_json::from_value(source.commit_json).map_err(PersistenceError::database)?;
    if commit.event_ref != event.event_id
        || commit.realm_id != event.realm_id
        || &commit.stream_ref != stream
        || CommitStreamRef::from_scope(&event.scope_ref, None)
            .map_err(PersistenceError::database)?
            != *stream
    {
        return Err(invalid(
            "Capture original Event and accepting Commit differ",
        ));
    }
    Ok((event, commit))
}

async fn original_start(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    call: &CallId,
    segment: &CallRecordingId,
    stream: &CommitStreamRef,
) -> PersistenceResult<(Event, CallRecordingStartPayload)> {
    let sources = sql_query("SELECT e.envelope,c.commit_json FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE e.realm_id=$1 AND e.state='committed' AND e.kind='ak.call.recording.start' AND e.envelope#>>'{payload,call_id}'=$2 AND e.envelope#>>'{payload,recording_id}'=$3")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(call.as_str()).bind::<Text,_>(segment.as_str())
        .load::<Source>(&mut *conn).await.map_err(PersistenceError::database)?;
    let [source]: [Source; 1] = sources
        .try_into()
        .map_err(|_| conflict("Capture has no unique retained original start"))?;
    let (event, _) = decode_source(source, stream)?;
    if event.kind != EventKind::CallRecordingStart {
        return Err(invalid("Capture original is not a start Event"));
    }
    let payload: CallRecordingStartPayload =
        serde_json::from_value(json!(event.payload)).map_err(PersistenceError::database)?;
    payload.validate().map_err(invalid)?;
    Ok((event, payload))
}

async fn stop_source(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    state: &Axis,
    call: &CallId,
    segment: &CallRecordingId,
    transcript: bool,
    stream: &CommitStreamRef,
) -> PersistenceResult<EventId> {
    if state.value != json!("stopped") || state.source_stream_ref != json!(stream) {
        return Err(conflict(
            "Capture result requires the exact native stopped state",
        ));
    }
    let source = sql_query("SELECT e.envelope,c.commit_json FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk WHERE c.realm_id=$1 AND c.commit_id=$2 AND c.stream_position=$3 AND e.state='committed'")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(&state.current_commit_id).bind::<BigInt,_>(state.current_stream_position)
        .get_result::<Source>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(|| conflict("Capture stop native history is unavailable"))?;
    let (event, _) = decode_source(source, stream)?;
    if event.kind != EventKind::CallState {
        return Err(invalid("Capture stop source is not CallState"));
    }
    let payload: CallStatePayload =
        serde_json::from_value(json!(event.payload)).map_err(PersistenceError::database)?;
    payload.validate().map_err(invalid)?;
    let matches = if transcript {
        payload.transcript_transition.as_ref().is_some_and(|t| {
            &t.recording_id == segment
                && t.from == CallTranscriptState::Transcribing
                && t.to == CallTranscriptState::Stopped
        })
    } else {
        payload.recording_transition.as_ref().is_some_and(|t| {
            &t.recording_id == segment
                && t.from == CallRecordingState::Recording
                && t.to == CallRecordingState::Stopped
        })
    };
    if &payload.call_id != call || !matches {
        return Err(invalid(
            "Capture stop belongs to another Call, segment or kind",
        ));
    }
    Ok(event.event_id)
}

fn retention(
    source: &CallRecordingRetention,
    next: &CallRecordingRetention,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    if next.retention_expires_at.is_some_and(|expiry| expiry <= at)
        || source
            .retention_expires_at
            .is_some_and(|old| next.retention_expires_at.is_none_or(|next| next < old))
        || (source.audit_lock == Some(true) && next.audit_lock != Some(true))
        || next.consent_confirmed == Some(false)
    {
        return Err(conflict(
            "Capture retention, legal hold or consent cannot be weakened",
        ));
    }
    Ok(())
}

fn retained_result(
    previous: &Value,
    next: Option<&CallRecordingRetention>,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    let source = previous
        .pointer("/details/artifact/retention")
        .or_else(|| previous.pointer("/details/retention"));
    if let Some(source) = source {
        let source: CallRecordingRetention =
            serde_json::from_value(source.clone()).map_err(PersistenceError::database)?;
        if let Some(next) = next {
            retention(&source, next, at)?;
        } else if source.audit_lock == Some(true) || source.retention_expires_at.is_some() {
            return Err(conflict(
                "Capture result cannot omit retained retention or hold obligations",
            ));
        }
    }
    Ok(())
}

pub(super) async fn start(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
    prepared: Option<&coland_storage::EventApprovalCommit>,
) -> PersistenceResult<()> {
    let payload: CallRecordingStartPayload =
        serde_json::from_value(json!(event.payload)).map_err(PersistenceError::database)?;
    payload.validate().map_err(invalid)?;
    crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &event.realm_id).await?;
    let cut =
        crate::realm_authorization_cut::RealmAuthorizationCut::read_for_event(conn, event).await?;
    let action = if payload.capture_kind == RecordingCaptureKind::Transcript {
        arkret_wire::CapabilityActionId::CALL_TRANSCRIBE
    } else {
        arkret_wire::CapabilityActionId::CALL_RECORD
    };
    cut.require_call_actions(conn, event, commit, prepared, &[action])
        .await?;
    let current = read_before_in_connection(
        conn,
        &event.realm_id,
        &payload.call_id,
        &event.actor_id,
        Some(&event.event_id),
    )
    .await?
    .ok_or_else(|| conflict("Capture Call is not visible"))?;
    if current.scope_ref != event.scope_ref
        || current.lifecycle != CallLifecycleState::Active
        || commit.event_ref != event.event_id
        || commit.realm_id != event.realm_id
        || CommitStreamRef::from_scope(&event.scope_ref, None)
            .map_err(PersistenceError::database)?
            != commit.stream_ref
    {
        return Err(conflict(
            "Capture requires the active Call's exact accepting stream",
        ));
    }
    let media = media_in_connection(conn, &event.realm_id)
        .await?
        .ok_or_else(|| conflict("Capture media service is unavailable"))?;
    if (payload.capture_kind == RecordingCaptureKind::Recording
        && media.recording_supported != Some(true))
        || current
            .focus
            .as_ref()
            .and_then(|f| f.session_focus.as_ref())
            .is_none_or(|focus| !media.foci.iter().any(|f| f.focus_id == *focus))
    {
        return Err(conflict(
            "Capture media policy or committed focus is unavailable",
        ));
    }
    retention(
        &payload.capture_metadata.retention,
        &payload.capture_metadata.retention,
        commit.committed_at,
    )?;
    if payload.capture_kind == RecordingCaptureKind::Recording {
        key_source::require_current(conn, event, commit, &payload).await?;
    }
    let occupied = sql_query("SELECT value,source_stream_ref,current_commit_id,current_stream_position FROM call_component_current_states WHERE realm_id=$1 AND call_id=$2 AND selector->>'recording_id'=$3 FOR UPDATE")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(payload.call_id.as_str()).bind::<Text,_>(payload.recording_id.as_str())
        .load::<Axis>(&mut *conn).await.map_err(PersistenceError::database)?;
    if !occupied.is_empty() {
        return Err(conflict("Capture segment identifier has already been used"));
    }
    let transcript = payload.capture_kind == RecordingCaptureKind::Transcript;
    let (opening, start_key) = if transcript {
        ("transcribing", "transcript_start_event_id")
    } else {
        ("recording", "recording_start_event_id")
    };
    write(
        conn,
        event,
        commit,
        &payload.call_id,
        &selector(
            payload.capture_kind,
            false,
            &payload.call_id,
            &payload.recording_id,
        ),
        json!(opening),
    )
    .await?;
    let mut details = json!(payload.capture_metadata);
    details[start_key] = json!(event.event_id);
    write(
        conn,
        event,
        commit,
        &payload.call_id,
        &selector(
            payload.capture_kind,
            true,
            &payload.call_id,
            &payload.recording_id,
        ),
        json!({"status":"pending","details":details}),
    )
    .await
}

pub(super) async fn transitions(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
    payload: &CallStatePayload,
    current: &coland_storage::CallCurrentCut,
) -> PersistenceResult<()> {
    if let Some(transition) = &payload.recording_transition {
        transition_recording(conn, event, commit, payload, transition, current).await?;
    }
    if let Some(transition) = &payload.transcript_transition {
        transition_transcript(conn, event, commit, payload, transition).await?;
    }
    Ok(())
}

async fn result_basis(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
    call: &CallId,
    segment: &CallRecordingId,
    transcript: bool,
    expected: &arkret_wire::RealmCommitId,
) -> PersistenceResult<(Event, CallRecordingStartPayload, EventId, Axis)> {
    let kind = if transcript {
        RecordingCaptureKind::Transcript
    } else {
        RecordingCaptureKind::Recording
    };
    let state = axis(conn, &event.realm_id, &selector(kind, false, call, segment))
        .await?
        .ok_or_else(|| conflict("Capture state is absent"))?;
    let result = axis(conn, &event.realm_id, &selector(kind, true, call, segment))
        .await?
        .ok_or_else(|| conflict("Capture result is absent"))?;
    if result.current_commit_id != expected.as_str()
        || result.source_stream_ref != json!(commit.stream_ref)
        || result.current_stream_position >= commit.stream_position as i64
        || state.current_stream_position >= commit.stream_position as i64
    {
        return Err(conflict("Capture result revision changed"));
    }
    let stop = stop_source(
        conn,
        &event.realm_id,
        &state,
        call,
        segment,
        transcript,
        &commit.stream_ref,
    )
    .await?;
    let (start, opening) =
        original_start(conn, &event.realm_id, call, segment, &commit.stream_ref).await?;
    if (opening.capture_kind == RecordingCaptureKind::Transcript) != transcript {
        return Err(invalid("Capture result kind differs from original start"));
    }
    Ok((start, opening, stop, result))
}

async fn stop(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
    call: &CallId,
    segment: &CallRecordingId,
    transcript: bool,
) -> PersistenceResult<()> {
    let kind = if transcript {
        RecordingCaptureKind::Transcript
    } else {
        RecordingCaptureKind::Recording
    };
    let key = selector(kind, false, call, segment);
    let current = axis(conn, &event.realm_id, &key)
        .await?
        .ok_or_else(|| conflict("Capture state is absent"))?;
    if current.value
        != json!(if transcript {
            "transcribing"
        } else {
            "recording"
        })
        || current.source_stream_ref != json!(commit.stream_ref)
        || current.current_stream_position >= commit.stream_position as i64
    {
        return Err(conflict(
            "Capture is already stopped or belongs to another stream",
        ));
    }
    let (_, opening) =
        original_start(conn, &event.realm_id, call, segment, &commit.stream_ref).await?;
    if (opening.capture_kind == RecordingCaptureKind::Transcript) != transcript {
        return Err(invalid("Capture stop kind differs"));
    }
    write(conn, event, commit, call, &key, json!("stopped")).await
}

async fn transition_recording(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
    payload: &CallStatePayload,
    transition: &CallRecordingTransition,
    current: &coland_storage::CallCurrentCut,
) -> PersistenceResult<()> {
    if transition.to == CallRecordingState::Stopped {
        return stop(
            conn,
            event,
            commit,
            &payload.call_id,
            &transition.recording_id,
            false,
        )
        .await;
    }
    let expected = transition
        .expected_commit_id
        .as_ref()
        .ok_or_else(|| invalid("Capture result has no expected commit"))?;
    let (start, opening, stop_id, old) = result_basis(
        conn,
        event,
        commit,
        &payload.call_id,
        &transition.recording_id,
        false,
        expected,
    )
    .await?;
    let details = transition
        .capture_metadata
        .as_ref()
        .ok_or_else(|| invalid("Recording result details are absent"))?;
    retained_result(
        &old.value,
        details
            .artifact
            .as_ref()
            .map(|artifact| &artifact.retention)
            .or(details.retention.as_ref()),
        commit.committed_at,
    )?;
    if transition.to == CallRecordingState::Ready {
        let artifact = details
            .artifact
            .as_ref()
            .ok_or_else(|| invalid("Recording artifact is absent"))?;
        validate_recording_artifact(
            conn, event, commit, &start, &opening, current, artifact, &old.value,
        )
        .await?;
        require_recording_initiator(conn, event, commit, &start, artifact).await?;
        require_recording_service_producer(conn, event, commit, &opening, artifact).await?;
    } else {
        if old.value.get("status") == Some(&json!("ready")) {
            return Err(conflict(
                "A recording failure cannot erase the published artifact and audit obligations",
            ));
        }
        if details.recording_stop_event_id.as_ref() != Some(&stop_id)
            || details
                .recording_start_event_id
                .as_ref()
                .is_some_and(|id| id != &start.event_id)
        {
            return Err(conflict(
                "Recording failure source differs from native capture",
            ));
        }
        if let Some(next) = &details.retention {
            retention(
                &opening.capture_metadata.retention,
                next,
                commit.committed_at,
            )?;
        } else if opening.capture_metadata.retention.audit_lock == Some(true)
            || opening
                .capture_metadata
                .retention
                .retention_expires_at
                .is_some()
        {
            return Err(conflict(
                "Recording failure must retain original retention and hold obligations",
            ));
        }
    }
    let status = if transition.to == CallRecordingState::Ready {
        "ready"
    } else {
        "failed"
    };
    write(
        conn,
        event,
        commit,
        &payload.call_id,
        &selector(
            RecordingCaptureKind::Recording,
            true,
            &payload.call_id,
            &transition.recording_id,
        ),
        json!({"status":status,"details":details}),
    )
    .await
}

async fn transition_transcript(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
    payload: &CallStatePayload,
    transition: &CallTranscriptTransition,
) -> PersistenceResult<()> {
    if transition.to == CallTranscriptState::Stopped {
        return stop(
            conn,
            event,
            commit,
            &payload.call_id,
            &transition.recording_id,
            true,
        )
        .await;
    }
    let expected = transition
        .expected_commit_id
        .as_ref()
        .ok_or_else(|| invalid("Transcript result has no expected commit"))?;
    let (start, opening, stop_id, old) = result_basis(
        conn,
        event,
        commit,
        &payload.call_id,
        &transition.recording_id,
        true,
        expected,
    )
    .await?;
    let details = transition
        .capture_metadata
        .as_ref()
        .ok_or_else(|| invalid("Transcript result details are absent"))?;
    retained_result(&old.value, details.retention.as_ref(), commit.committed_at)?;
    if details.transcript_start_event_id.as_ref() != Some(&start.event_id)
        || details
            .transcript_stop_event_id
            .as_ref()
            .is_some_and(|id| id != &stop_id)
    {
        return Err(conflict(
            "Transcript result source differs from native capture",
        ));
    }
    if transition.to == CallTranscriptState::Ready {
        // The existing transcript carrier does not bind encrypted bytes and
        // algorithm/context. A digest alone cannot prove that pipeline.
        return Err(conflict(
            "transcription_artifact_pipeline_bypassed: encrypted transcript provenance is unavailable",
        ));
    }
    if old.value.get("status") == Some(&json!("ready")) {
        return Err(conflict(
            "A transcript failure cannot erase a published artifact",
        ));
    }
    if let Some(next) = &details.retention {
        retention(
            &opening.capture_metadata.retention,
            next,
            commit.committed_at,
        )?;
    } else if opening.capture_metadata.retention.audit_lock == Some(true)
        || opening
            .capture_metadata
            .retention
            .retention_expires_at
            .is_some()
    {
        return Err(conflict(
            "Transcript failure must retain original retention and hold obligations",
        ));
    }
    write(
        conn,
        event,
        commit,
        &payload.call_id,
        &selector(
            RecordingCaptureKind::Transcript,
            true,
            &payload.call_id,
            &transition.recording_id,
        ),
        json!({"status":"failed","details":details}),
    )
    .await
}

async fn validate_recording_artifact(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
    start: &Event,
    opening: &CallRecordingStartPayload,
    current: &coland_storage::CallCurrentCut,
    artifact: &CallRecordingArtifact,
    previous: &Value,
) -> PersistenceResult<()> {
    artifact.validate().map_err(|e| invalid(&e.to_string()))?;
    artifact
        .encryption
        .validate_start_binding(&start.event_id, opening)
        .map_err(|e| conflict(&e.to_string()))?;
    let media = media_in_connection(conn, &event.realm_id)
        .await?
        .ok_or_else(|| conflict("Recording media service is unavailable"))?;
    if artifact.realm_id != event.realm_id
        || artifact.call_id != opening.call_id
        || artifact.recording_id != opening.recording_id
        || artifact.recording_start_event_id != start.event_id
        || artifact.produced_by != opening.recording_agent_id
        || artifact.encryption.context.media_service_id != media.service_id
        || media.recording_supported != Some(true)
        || current
            .focus
            .as_ref()
            .and_then(|f| f.session_focus.as_ref())
            .is_none_or(|focus| focus.as_str() != artifact.encryption.context.focus_id)
        || !media
            .foci
            .iter()
            .any(|focus| focus.focus_id.as_str() == artifact.encryption.context.focus_id)
        || artifact.created_at < start.created_at
        || artifact.created_at > commit.committed_at
    {
        return Err(conflict(
            "Recording artifact differs from original capture or current media policy",
        ));
    }
    retention(
        &opening.capture_metadata.retention,
        &artifact.retention,
        commit.committed_at,
    )?;
    if let Some(old) = previous.pointer("/details/artifact") {
        let old: CallRecordingArtifact =
            serde_json::from_value(old.clone()).map_err(PersistenceError::database)?;
        retention(&old.retention, &artifact.retention, commit.committed_at)?;
        if &old != artifact {
            return Err(conflict(
                "Ordinary recording result cannot rewrite the original Blob, encryption or audit obligations",
            ));
        }
    }
    if let Some(policy) = &artifact.retention_policy_id {
        let row = sql_query("SELECT value,source_stream_ref,current_commit_id,current_stream_position FROM (SELECT p.value,c.stream_ref AS source_stream_ref,p.current_commit_id,p.current_stream_position FROM policy_current_states p JOIN realm_commits c ON c.commit_id=p.current_commit_id AND c.realm_id=p.realm_id AND c.stream_position=p.current_stream_position WHERE p.realm_id=$1 AND p.policy_id=$2) p")
            .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(policy.as_str()).get_result::<Axis>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
        if row.is_none() {
            return Err(conflict(
                "Recording retention policy current is unavailable",
            ));
        }
    }
    let blob = crate::blobs::blob_for_delivery_in_connection(conn, &artifact.blob_ref)
        .await?
        .ok_or_else(|| conflict("Recording Blob has not entered the Arkret pipeline"))?;
    if blob.redacted
        || blob.realm_id.as_deref() != Some(event.realm_id.as_str())
        || blob.visibility != arkret_models_collaboration::objects::blob::BlobVisibility::RealmBound
        || blob.encryption.is_none()
        || blob.size_bytes < 0
        || blob.size_bytes as u64 != artifact.size_bytes
        || blob.media_type != "application/octet-stream"
        || artifact.blob_ref.as_str() != format!("ak:blob:sha256:{}", blob.sha256)
        || (blob.legal_hold && artifact.retention.audit_lock != Some(true))
    {
        return Err(conflict(
            "Recording artifact differs from its authenticated encrypted Blob",
        ));
    }
    let storage_stream = blob.encryption.is_some_and(|encryption| {
        matches!(
            encryption.scheme,
            arkret_models_collaboration::objects::blob::BlobStorageEncryptionScheme::StreamV1
        )
    });
    if !storage_stream {
        return Err(conflict(
            "Recording encryption algorithm differs from the stored ciphertext envelope",
        ));
    }
    // This checks public ciphertext metadata, never the E2EE plaintext or AEAD tag.
    Ok(())
}

async fn require_recording_service_producer(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
    opening: &CallRecordingStartPayload,
    artifact: &CallRecordingArtifact,
) -> PersistenceResult<()> {
    let fact = crate::agent_producer_signer_keys::producer_source_for_commit_in_connection(
        conn, event, commit,
    )
    .await?;
    let Some(arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact::Service(
        fact,
    )) = fact
    else {
        return Err(conflict(
            "Recording ready has no actual accepted Service producer source",
        ));
    };
    if fact.actor.signing_principal_id() != &artifact.produced_by
        || fact.actor.signing_principal_id() != &opening.recording_agent_id
    {
        return Err(conflict(
            "Recording ready producer Service differs from the original recorder",
        ));
    }
    // The UoW earned and retained this fact through the real installation,
    // current grant and signature gates before calling this materializer.
    // Ciphertext transport identity is not a second producer identity.
    Ok(())
}

async fn require_recording_initiator(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
    start: &Event,
    artifact: &CallRecordingArtifact,
) -> PersistenceResult<()> {
    let cited = source_authority::require_source(
        conn,
        start,
        &artifact.recording_initiator_capability_ref,
        commit.committed_at,
    )
    .await?;
    // The cited grant must already have been accepted when capture started;
    // acquiring a grant afterwards cannot retroactively invent provenance.
    let grant_event = artifact
        .recording_initiator_capability_ref
        .as_str()
        .replacen("ak:grant:", "ak:event:", 1);
    let existed = sql_query("SELECT e.envelope,c.commit_json FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk JOIN canonical_events s ON s.envelope->>'event_id'=$3 AND s.state='committed' JOIN realm_commits sc ON sc.event_pk=s.pk AND sc.realm_id=c.realm_id WHERE e.realm_id=$1 AND e.envelope->>'event_id'=$2 AND e.state='committed' AND c.committed_at<=sc.committed_at")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(grant_event).bind::<Text,_>(start.event_id.as_str())
        .get_result::<Source>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    if start.authorization_ref.as_ref().is_some_and(|reference| {
        reference.as_str() != artifact.recording_initiator_capability_ref.as_str()
    }) {
        return Err(conflict(
            "Recording initiator grant was not an accepted source of the original start",
        ));
    }
    let source = existed
        .ok_or_else(|| conflict("Recording initiator grant was not accepted before capture"))?;
    let source_event: Event =
        serde_json::from_value(source.envelope).map_err(PersistenceError::database)?;
    let source_commit: RealmCommit =
        serde_json::from_value(source.commit_json).map_err(PersistenceError::database)?;
    let original: arkret_models_collaboration::events_payloads::CapabilityGrantPayload =
        serde_json::from_value(json!(source_event.payload)).map_err(PersistenceError::database)?;
    let current_body = arkret_models_collaboration::events_payloads::CapabilityGrantCreateBody {
        schema: cited.schema.clone(),
        realm_id: cited.realm_id.clone(),
        issuer_id: cited.issuer_id.clone(),
        subject: cited.subject.clone(),
        actions: cited.actions.clone(),
        resources: cited.resources.clone(),
        constraints: cited.constraints.clone(),
        issued_at: cited.issued_at,
        issuer_authority_refs: cited.issuer_authority_refs.clone(),
    };
    if source_event.kind != EventKind::CapabilityGrant
        || source_event.realm_id != event.realm_id
        || source_commit.event_ref != source_event.event_id
        || source_commit.realm_id != event.realm_id
        || arkret_wire::GrantId::from_event_id(&source_event.event_id)
            != artifact.recording_initiator_capability_ref
        || source_event.actor_id != current_body.issuer_id
        || arkret_canonical::canonical_json_bytes(&original.grant)
            .map_err(PersistenceError::database)?
            != arkret_canonical::canonical_json_bytes(&current_body)
                .map_err(PersistenceError::database)?
    {
        return Err(conflict(
            "Recording initiator capability differs from its immutable accepted grant",
        ));
    }
    Ok(())
}
